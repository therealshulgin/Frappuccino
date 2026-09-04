package rs.readahead.washington.mobile.util.jobs

import timber.log.Timber
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Global concurrency cap for [ChunkUploadWorker].
 *
 * The cap is only global because WorkManager runs in the app's main process,
 * the one this singleton lives in : an `android:process` split would give
 * each process its own counter, so workers running in two processes at once
 * would no longer share one cap. State is lost at process death, which is
 * harmless since no workers run then either.
 *
 * WorkManager's default executor runs up to ~4 workers in parallel. On a slow
 * upload link (5G hotspot observed at ~700 kbps up 2026-05-10), 4 parallel
 * PUTs each get 1/4 of the bandwidth — a single 1 MB chunk that should take
 * ~5 s ends up taking 25+ s, multiplied across the queue. Capping concurrency
 * lets each upload have a meaningful share of the link without starving
 * WorkManager's other jobs (e.g. EnrollmentRetryWorker).
 *
 * The cap is adaptive rather than a hardcoded 2. Workers feed their
 * `uploadTimeMs` back via [reportUploadTime] (same signal the
 * [org.stream.crypto.capture.AdaptiveQualityManager] uses) and the limiter
 * keeps a rolling sample, adjusting the active cap up to [MAX_CAP] on fast
 * networks — a fibre or good wifi must not stay throttled by the 5G-friendly
 * cap of 2 — or down to [MIN_CAP] when uploads are slow, so a degraded link
 * doesn't get saturated. The semaphore always grants exactly the current cap
 * by releasing/acquiring "ghost" permits when the cap changes.
 */
object UploadConcurrencyLimiter {

    /** Lower bound. 1 = serial uploads, used on heavily congested links. */
    const val MIN_CAP = 1

    /**
     * Upper bound. Above 4-6 the gains plateau on residential fibre
     * (single TCP cwnd hits the BDP), and below that the WorkManager
     * default thread pool of ~4 caps us anyway.
     */
    const val MAX_CAP = 6

    /** Initial cap on first start. Matches the previous hardcoded Phase 3.10 default. */
    private const val INITIAL_CAP = 2

    /** Rolling window for upload-time samples (recent N chunks). */
    private const val SAMPLE_WINDOW = 8

    /**
     * Thresholds expressed against the default 5 s chunk interval.
     * Fast threshold = uploads consistently finish in less than 25 % of
     * a chunk interval → we can afford more parallelism. Slow = above
     * 70 % → we're pushing too much through the pipe.
     */
    private const val CHUNK_INTERVAL_MS = 5_000L
    private const val FAST_RATIO = 0.25
    private const val SLOW_RATIO = 0.70

    /** Samples before we accept an adjustment in either direction. */
    private const val ADJUST_HYSTERESIS = SAMPLE_WINDOW

    /**
     * How long a starting worker waits FIFO for a slot before giving up
     * and asking WorkManager to reschedule.
     *
     * Never lower this back toward the old 5 s. A short wait makes the
     * worker leave through `Result.retry()`, and WorkManager then applies
     * the EXPONENTIAL backoff meant for *network* failures (10->20->40->80 s,
     * set at enqueue time by `setBackoffCriteria` in
     * StreamRecordingService.scheduleUpload, not in [ChunkUploadWorker]).
     * The unlucky (oldest) chunk re-misses each shrinking opportunity and
     * its backoff keeps doubling : under a backlog with the cap shrunk to
     * 1-2, one chunk starved ~57 s while every other chunk drained, even
     * though the link was fine (its eventual PUT took 272 ms). That is the
     * post-stop drain starvation Phase 3.48 (2026-06-16) fixed by bumping
     * 5 s -> 45 s, diagnosed on-device (Seeker, logcat WM + queue tracker).
     *
     * The fair semaphore only orders waiters inside one acquire window, not
     * across retry+backoff cycles, so a long FIFO wait is what actually
     * prevents starvation : the worker stays queued on the semaphore
     * instead of leaving and re-arriving behind a doubled backoff. A slot
     * frees roughly every uploadMs (~5-15 s under load) so 45 s almost
     * always grants before timing out ; the timeout is only a floor for a
     * genuinely wedged link, where the EXPONENTIAL backoff then legitimately
     * kicks in. On a healthy link slots are free, so a worker acquires
     * immediately and this never adds latency (no regression to the nominal
     * path).
     *
     * The 45 s wait itself stays under the 120 s per-PUT ceiling ;
     * worst-case permit hold is acquire(<=45 s) + PUT(<=120 s) ~= 165 s,
     * well within WorkManager's ~10 min per-run budget. That 120 s is the
     * Rust transport's own PUT timeout, the chunk PUT under permit going
     * through Rust — not OkHttp's callTimeout, which happens to be 120 s
     * too but is no longer on this path.
     *
     * Trade-off : a waiting worker holds a WorkManager thread (default pool
     * ~4-8), so under cap=1 + a large backlog another job
     * (Enrollment/OrphanSweep) can wait up to ~45 s for a thread —
     * bounded, and both carry their own retry (OrphanSweep also self-gates
     * to empty while the service runs). The `acquireWait` metric below
     * measures this retention in the field.
     */
    private const val ACQUIRE_TIMEOUT_MS = 45_000L

    private val semaphore = Semaphore(INITIAL_CAP, /* fair = */ true)
    private val activeCap = AtomicInteger(INITIAL_CAP)

    /**
     * Number of workers currently inside [tryAcquire] (waiting
     * for or just granted a permit). Proxy for the pool-retention risk of
     * the longer [ACQUIRE_TIMEOUT_MS] ; surfaced in the `acquireWait` metric.
     */
    private val waiters = AtomicInteger(0)

    /**
     * Tracks permits we tried to reclaim during a shrink but couldn't
     * (all in-flight). Each subsequent [release] reclaims one toward
     * this debt until it hits zero, then resumes the normal release
     * path. Without this, `repeat(-delta) { tryAcquire() }` could no-op
     * when all permits were busy, leaving `availablePermits()`
     * permanently above [activeCap] until the next shrink — a silent
     * drift that defeats the cap on borderline networks (Blue CRIT-1
     * fix, Phase H2-B.13, 2026-05-18).
     *
     * AtomicInteger because [release] is called from arbitrary worker
     * threads and [maybeAdjustCap] from the reporter thread.
     */
    private val pendingShrink = AtomicInteger(0)

    // Ring buffer of recent uploadMs samples.
    private val samples = LongArray(SAMPLE_WINDOW) { -1L }
    private var samplesIdx = 0
    private val samplesLock = Any()

    fun tryAcquire(): Boolean {
        val concurrent = waiters.incrementAndGet()
        val startMs = System.currentTimeMillis()
        val granted = try {
            semaphore.tryAcquire(ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            // The worker thread was interrupted while waiting for a slot
            // (e.g. WorkManager stopping the worker, or a lost constraint).
            // With the 45 s wait this is more likely than under the old 5 s.
            // Restore the interrupt flag and report "no slot" so doWork()
            // takes the reschedule path cleanly instead of letting the
            // exception escape and fail the worker.
            Thread.currentThread().interrupt()
            false
        } finally {
            waiters.decrementAndGet()
        }
        // Field-test instrumentation for the starvation fix.
        // Silent on a healthy link (slot free immediately). When a worker
        // actually waited: waitMs = how long a pool thread was held (the
        // retention risk of the longer timeout) ; granted=false = no permit
        // obtained, either the 45 s timeout (residual starvation / wedged
        // link, would re-enter the exponential backoff) or an interrupt of
        // the worker thread (the InterruptedException branch above), waitMs
        // telling the two apart ; waiters = how many workers held a pool
        // thread at once. If `retry reason=concurrency_cap` vanishes from
        // the post-stop drain, the famine is gone.
        val waitMs = System.currentTimeMillis() - startMs
        if (waitMs >= 1_000L) {
            Timber.tag("StreamMetrics").i(
                "acquireWait ms=%d granted=%b waiters=%d cap=%d",
                waitMs, granted, concurrent, activeCap.get(),
            )
        }
        return granted
    }

    fun release() {
        // Consume any pending shrink before releasing.
        // CAS loop : if pendingShrink > 0, decrement and SKIP the
        // semaphore.release() so the permit count effectively drops.
        // Otherwise normal release. The CAS guarantees we never
        // over-consume (race between two concurrent releases).
        while (true) {
            val pending = pendingShrink.get()
            if (pending <= 0) {
                semaphore.release()
                return
            }
            if (pendingShrink.compareAndSet(pending, pending - 1)) {
                // Permit absorbed by the shrink, do NOT release back to
                // the semaphore. Drift fix : the absorbed permit makes
                // availablePermits() converge toward activeCap.
                Timber.v(
                    "[Phase H2-B.13] release absorbed by pendingShrink (was %d, now %d)",
                    pending, pending - 1,
                )
                return
            }
            // CAS lost, retry — another thread also tried to absorb.
        }
    }

    fun availablePermits(): Int = semaphore.availablePermits()

    fun currentCap(): Int = activeCap.get()

    /**
     * Workers call this after a successful PUT to feed the rolling
     * sample. Triggers a [maybeAdjustCap] check.
     */
    fun reportUploadTime(uploadMs: Long) {
        if (uploadMs < 0) return
        synchronized(samplesLock) {
            samples[samplesIdx] = uploadMs
            samplesIdx = (samplesIdx + 1) % SAMPLE_WINDOW
            maybeAdjustCap()
        }
    }

    /** Reset history (e.g. service start). */
    fun resetSamples() {
        synchronized(samplesLock) {
            for (i in samples.indices) samples[i] = -1L
            samplesIdx = 0
        }
    }

    /**
     * Network-recovery re-arm, called from the recording service's
     * `NetworkCallback.onAvailable` once the link has just (re)validated.
     *
     * Do not remove this as redundant with the adaptive cap. [maybeAdjustCap]
     * is the ONLY path that grows the cap, it needs [SAMPLE_WINDOW] fresh
     * samples, and a sample is only produced by a successful upload — so
     * cap=1 + WorkManager backoff starves exactly those successes : no
     * samples, no growth, and the cap stays down long after the link came
     * back. Field session 2026-06-23 (café) : a cellular start drove the cap
     * to 1, the link then went to excellent WiFi, and the cap stayed at 1 for
     * ~14 min (Phase 3.49).
     *
     * `onAvailable` already cancels the backed-off ENQUEUED workers and
     * reschedules them ; this re-arms the cap to [INITIAL_CAP] so those
     * rescheduled workers actually get parallelism, and wipes the rolling
     * window so the next decision is taken on fresh post-recovery samples,
     * not the stale slow ones that kept the median high.
     *
     * Monotonic upward only : never lowers an already-healthy cap (a
     * transient `onAvailable` on a fast link is a no-op beyond the sample
     * wipe). Grows via the same release-net-permits path [maybeAdjustCap]
     * uses (honouring [pendingShrink]) — never a raw `activeCap.set`, which
     * would drift `availablePermits()` (the H2-B.13 bug). Holds
     * [samplesLock] like every other cap mutation, so it is safe from the
     * worker thread `onAvailable` spawns for its recovery work ; the
     * callback does not run this inline.
     */
    fun bumpCapForRecovery() {
        synchronized(samplesLock) {
            val current = activeCap.get()
            if (current < INITIAL_CAP && activeCap.compareAndSet(current, INITIAL_CAP)) {
                val delta = INITIAL_CAP - current
                val absorbed = consumePendingShrinkUpTo(delta)
                val net = delta - absorbed
                if (net > 0) repeat(net) { semaphore.release() }
                Timber.tag("StreamMetrics").i(
                    "capReset reason=network_recovery from=%d to=%d", current, INITIAL_CAP
                )
            }
            // Always refresh the window so the post-recovery decision isn't
            // anchored on the stale congested samples (even when the cap was
            // already >= INITIAL_CAP).
            for (i in samples.indices) samples[i] = -1L
            samplesIdx = 0
        }
    }

    /**
     * Inspect the rolling median and decide whether to bump or drop the
     * cap by 1. We require the full window to be filled with valid
     * samples before any adjustment (hysteresis : no premature shrink
     * on the first slow chunk, no premature growth on the first burst).
     */
    private fun maybeAdjustCap() {
        val valid = samples.filter { it >= 0 }.sorted()
        if (valid.size < ADJUST_HYSTERESIS) return
        val median = valid[valid.size / 2]
        val ratio = median.toDouble() / CHUNK_INTERVAL_MS.toDouble()
        val current = activeCap.get()
        val target = when {
            ratio < FAST_RATIO && current < MAX_CAP -> current + 1
            ratio > SLOW_RATIO && current > MIN_CAP -> current - 1
            else -> current
        }
        if (target != current && activeCap.compareAndSet(current, target)) {
            val delta = target - current
            if (delta > 0) {
                // Growth : grant the new permits immediately. Also
                // reduce any leftover pendingShrink debt (if a recent
                // shrink hadn't fully reclaimed) before adding fresh
                // permits, so we don't double-count.
                val absorbed = consumePendingShrinkUpTo(delta)
                val net = delta - absorbed
                if (net > 0) repeat(net) { semaphore.release() }
            } else {
                // Shrink. Phase H2-B.13 — try to reclaim permits
                // non-blockingly, but if all permits are in-flight,
                // record the deficit in pendingShrink so the next
                // release() absorbs them. NEVER block : this path runs on
                // an upload worker thread that is still holding its own
                // permit (it releases only after this returns) and holds
                // samplesLock, so a blocking acquire could wait on permits
                // that nothing will free. And never silently leak.
                val toReclaim = -delta
                var reclaimed = 0
                repeat(toReclaim) {
                    if (semaphore.tryAcquire()) reclaimed++
                }
                val deficit = toReclaim - reclaimed
                if (deficit > 0) {
                    pendingShrink.addAndGet(deficit)
                    Timber.i(
                        "[Phase H2-B.13] shrink %d -> %d : reclaimed %d, deferred %d via pendingShrink",
                        current, target, reclaimed, deficit,
                    )
                }
            }
            Timber.i(
                "[Phase 3.21] cap %d -> %d (medianMs=%d, ratio=%.2f, pendingShrink=%d)",
                current, target, median, ratio, pendingShrink.get(),
            )
            // Wipe the window so the next decision is based on fresh
            // samples after the adjustment took effect.
            for (i in samples.indices) samples[i] = -1L
            samplesIdx = 0
        }
    }

    /**
     * Atomically consume up to [max] units from
     * [pendingShrink]. Returns the number actually consumed (0 if no
     * pending). Used by growth path so a debt absorbed before the
     * grow is netted against the new permits — keeps the math precise.
     */
    private fun consumePendingShrinkUpTo(max: Int): Int {
        while (true) {
            val pending = pendingShrink.get()
            if (pending <= 0) return 0
            val take = minOf(pending, max)
            if (pendingShrink.compareAndSet(pending, pending - take)) {
                return take
            }
        }
    }
}
