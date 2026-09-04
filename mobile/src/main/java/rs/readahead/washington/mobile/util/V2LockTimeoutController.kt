package rs.readahead.washington.mobile.util

import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import org.stream.crypto.upload.ChunkUploadQueue
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.data.sharedpref.Preferences
import rs.readahead.washington.mobile.service.StreamRecordingService
import rs.readahead.washington.mobile.util.jobs.UploadAuthHolder
import timber.log.Timber
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Pure-V2 lock-timeout controller: it owns both background timers, the
 * upload-JWT auto-clear and the ratchet inactivity auto-lock.
 *
 * Never re-wire this onto the Tella key/unlock infrastructure — `MainKey`,
 * `MainKeyStore`, `UnlockRegistry`, `PBEKeyWrapper`, `LifecycleMainKey`, the
 * Tella unlock activities. Phase 6.1.16 removed all of it from the repo: no
 * `LifecycleMainKey` class is declared anywhere any more, and the name now
 * survives only in prose, including the KDoc on [NO_TIMEOUT] below. The
 * V2 lock gate is 100 % ratchet-based
 * ([org.stream.crypto.upload.StreamUploadManager.isLocked] / `isUnlocked`),
 * so the Tella `MainKey` was dead weight; the JWT clear that used to hang off
 * `LifecycleMainKey`'s timer (wired in `MyApplication` as an
 * `addOnClearListener`) was the one load-bearing piece, and it lives here
 * now, on a dedicated [androidx.lifecycle.ProcessLifecycleOwner] observer
 * that knows nothing about Tella.
 *
 * `ON_PAUSE` arms two independent timers and `ON_RESUME` cancels both:
 *  - the JWT clear, from [Preferences.getLockTimeout] → [fire]:
 *      - `NO_TIMEOUT` (-1) → never auto-clear;
 *      - `0` (IMMEDIATE_SHUTDOWN, the default) → clear synchronously;
 *      - `> 0` → clear after `timeout` ms unless `ON_RESUME` cancels first.
 *  - the ratchet inactivity auto-lock, from [Preferences.getRatchetAutoLockMs]
 *    (15 min by default, `-1` or `0` disable it) → [fireRatchetLock].
 *
 * The JWT timeout is read straight from [Preferences.getLockTimeout], so the
 * legacy "temporary timeout" bumps (`BaseActivity.maybeChangeTemporaryTimeout`,
 * which only ever pushed into `LifecycleMainKey.timeout`) no longer delay the
 * JWT clear. That is intentional and benign in V2: **this** timer does not
 * wipe the ratchet, so clearing the JWT merely forces the next upload to
 * re-authenticate silently via `initServerSession`. It never strands footage
 * (see the [fire] gates) and never forces a re-PIN. The ratchet is locked by
 * the separate timer above — [fireRatchetLock] calls
 * `StreamUploadManager.lock()` once nothing is recording, encrypting or
 * draining — and by an explicit `lock()` / `panicWipe()`; those are what
 * force a re-PIN.
 */
class V2LockTimeoutController(
    lifecycle: Lifecycle,
    context: Context,
) : DefaultLifecycleObserver {

    private val appContext: Context = context.applicationContext

    private val executor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "v2-lock-timeout").apply { isDaemon = true }
    }

    @Volatile
    private var scheduled: ScheduledFuture<*>? = null

    // Phase 6 — separate timer for the ratchet inactivity auto-lock (re-PIN
    // on return), independent of the JWT-clear [scheduled] above so the
    // field-tuned JWT timing (lock_timeout default 0 + the 1.14/2.2.6/3.38-D
    // gates) is left untouched.
    @Volatile
    private var ratchetScheduled: ScheduledFuture<*>? = null

    // True between ON_PAUSE and ON_RESUME. [fireRatchetLock] checks it so a
    // fire that races a foregrounding (or a recording-deferred reschedule)
    // can't lock the ratchet once the user is back in the app.
    @Volatile
    private var backgrounded = false

    init {
        lifecycle.addObserver(this)
    }

    override fun onResume(owner: LifecycleOwner) {
        backgrounded = false
        cancel()
    }

    override fun onPause(owner: LifecycleOwner) {
        backgrounded = true
        schedule()
    }

    @Synchronized
    private fun schedule() {
        cancel()
        // JWT clear (existing, field-critical — unchanged).
        when (val timeout = Preferences.getLockTimeout()) {
            NO_TIMEOUT -> Unit // never auto-clear
            0L -> fire() // IMMEDIATE_SHUTDOWN — clear now (on the lifecycle thread, as before)
            else -> scheduled = executor.schedule({ fire() }, timeout, TimeUnit.MILLISECONDS)
        }
        // Ratchet inactivity auto-lock (Phase 6 — new). -1 / 0 = disabled.
        val ratchetMs = Preferences.getRatchetAutoLockMs()
        if (ratchetMs > 0L) {
            ratchetScheduled = executor.schedule({ fireRatchetLock() }, ratchetMs, TimeUnit.MILLISECONDS)
        }
    }

    @Synchronized
    private fun cancel() {
        scheduled?.cancel(false)
        scheduled = null
        ratchetScheduled?.cancel(false)
        ratchetScheduled = null
    }

    /**
     * Drop the upload JWT — unless a recording is live or tearing down, or
     * chunks are still queued for drain. Both gates are field-critical, and a
     * clear that slips past either one loses footage without anything
     * failing loudly. They come from the `MyApplication` `addOnClearListener`
     * (Phase 1.14 / 3.38-D / 3.35 / 3.41).
     *
     * Never clear the JWT while a recording session is live or tearing down.
     * Field forensics 2026-05-21, report `e0201e07`: the screen turned off
     * mid-recording, the lock timeout fired while the upload queue was
     * momentarily empty, the JWT was wiped, and the service then produced
     * ~318 more chunks that all looped on `no_auth_token` and were lost at
     * session end — a 39 % data loss on a 2 h session, unrecoverable because
     * the recording service has no re-auth path once the holder is cleared
     * out from under it. Gate on the SAME `isRunning || isShuttingDown`
     * window the upload workers use (see the `StreamRecordingService`
     * companion doc, Phase H2-B.16) rather than on a neighbouring condition
     * of your own, so the JWT survives the whole session plus teardown.
     *
     * Even when stopped, don't strand a post-stop drain: the JWT is
     * load-bearing for the drain, so skip the clear while any `.strm` chunks
     * are still queued. Once the queue is empty the holder is safe to drop.
     * The 24 h JWT exp and the 401 → clear + retry path still bound the
     * stale-JWT window in the "record, stop, leave the app forever" edge
     * case.
     */
    private fun fire() {
        if (StreamRecordingService.isRunning || StreamRecordingService.isShuttingDown) {
            Timber.d("Phase 1.14: skipping UploadAuthHolder.clear, recording session live/tearing down")
            rescheduleJwtClear()
            return
        }
        // A chunk can be finished encrypting but not yet
        // enqueued (its encryption Thread runs on after onDestroy's
        // bounded wait times out). It is invisible to the queue-pending
        // guard below, so clearing the JWT now strands it forever on
        // no_auth_token. Defer while any encryption is still in flight.
        val encrypting = StreamRecordingService.encryptionsInFlight()
        if (encrypting > 0) {
            Timber.d("Phase 2.2.6: skipping UploadAuthHolder.clear, %d chunk(s) still encrypting", encrypting)
            rescheduleJwtClear()
            return
        }
        val pending: Int = try {
            ChunkUploadQueue(appContext).getPendingCount()
        } catch (t: Throwable) {
            0 // fail-open: clear on error (no worse than the original 3.38-B behaviour)
        }
        if (pending == 0) {
            UploadAuthHolder.clear()
        } else {
            Timber.d("Phase 3.38-D: skipping UploadAuthHolder.clear, %d chunks pending drain", pending)
            rescheduleJwtClear()
        }
    }

    /**
     * Retry the JWT clear every [JWT_CLEAR_RETRY_MS] when [fire] defers it
     * because a recording / encryption / drain is in flight at background
     * time, instead of giving up.
     *
     * The retry is deliberately unbounded — no attempt counter, no maximum
     * delay — and its only exit is the user coming back: `onResume` clears
     * [backgrounded] and cancels the pending future. Do not add an attempt
     * cap for safety's sake, because that brings back the one-shot behaviour
     * it replaced, which left the bearer reachable in the JVM heap for the
     * full 24 h TTL in the "record, stop, background mid-drain" case
     * (confirmed by on-device heap dumps, 10.6 forensic 2026-06-13). The loop
     * stays harmless because every actual clear still goes through the gates
     * in [fire].
     */
    @Synchronized
    private fun rescheduleJwtClear() {
        if (!backgrounded) return
        scheduled = executor.schedule({ fire() }, JWT_CLEAR_RETRY_MS, TimeUnit.MILLISECONDS)
    }

    /**
     * **Never interrupts a recording.** The app recording in the background
     * with the screen off is how a witness captures testimony, not an edge
     * case, and wiping the ratchet mid-session would crash chunk encryption —
     * the same reason the explicit lock stops the service first. So when a
     * recording is live, tearing down or still encrypting, this defers rather
     * than gives up: it reschedules one more interval so the lock still lands
     * once the device is idle. The [backgrounded] guard stops a deferred fire
     * from locking after the user has returned to the foreground.
     *
     * Ratchet inactivity auto-lock (Phase 6). Fires after
     * [Preferences.getRatchetAutoLockMs] in the background and wipes the
     * ratchet from RAM ([StreamUploadManager.lock]), so the next return to
     * [rs.readahead.washington.mobile.views.activity.StreamActivity] forces a
     * re-PIN (its onResume → maybeLaunchPinUnlock → isLocked gate).
     */
    private fun fireRatchetLock() {
        if (!backgrounded) return
        // Defer the wipe while any chunk is still queued. The reportKeyring that
        // lock() wipes is load-bearing for the post-stop upload drain: EVERY
        // chunk's write-sig is signed with it, which makes it more load-bearing
        // than the JWT, which only the creation chunk uses. Without this guard a
        // wipe mid-drain strands every pending worker on no_report_keyring until
        // the user re-PINs. Both counters are needed and neither is redundant:
        // encryptionsInFlight() covers chunks not yet enqueued, getPendingCount
        // the enqueued-but-undrained ones. This mirrors the JWT clear's §3.3
        // drain-safe guard (see fire(), Phase 3.38-D) — Phase C review fix.
        val pending: Int = try {
            ChunkUploadQueue(appContext).getPendingCount()
        } catch (t: Throwable) {
            0 // fail-open: lock on error (matches fire()'s drain guard behaviour)
        }
        val busy = StreamRecordingService.isRunning ||
            StreamRecordingService.isShuttingDown ||
            StreamRecordingService.encryptionsInFlight() > 0 ||
            pending > 0
        if (busy) {
            synchronized(this) {
                if (!backgrounded) return
                val ms = Preferences.getRatchetAutoLockMs()
                if (ms > 0L) {
                    ratchetScheduled = executor.schedule({ fireRatchetLock() }, ms, TimeUnit.MILLISECONDS)
                }
            }
            Timber.d("Ratchet auto-lock deferred (recording/encryption/%d pending drain); rescheduled", pending)
            return
        }
        StreamUploadManager.getInstance(appContext).lock()
        Timber.tag("StreamMetrics").i("ratchetAutoLock fired (idle timeout)")
    }

    companion object {
        /** Matches `LifecycleMainKey.NO_TIMEOUT` — "never auto-clear". */
        const val NO_TIMEOUT: Long = -1L

        /** 10.6 forensic - retry interval for a deferred JWT clear (drain in flight). */
        const val JWT_CLEAR_RETRY_MS: Long = 10_000L
    }
}
