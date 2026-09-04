package org.stream.crypto.capture

import timber.log.Timber
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Watches how long each chunk takes to upload and moves the recording
 * quality up or down, so the upload pipeline stays caught up with the
 * capture pipeline.
 *
 * A tick is the ratio r = uploadTimeMs / chunkIntervalMs: above
 * [SLOW_THRESHOLD_RATIO] it counts as slow, below [FAST_THRESHOLD_RATIO]
 * as fast, and each kind resets the other's counter. It takes 3 slow ticks
 * to step down but 10 fast ticks to step up — roughly 15 s against 50 s at
 * a 5 s chunk interval. The asymmetry is deliberate: drop the quality
 * before the user notices the uploads piling up, but climb back only once
 * the network looks genuinely stable, never on a transient blip.
 *
 * Mid-band ticks (0.60..0.80) are fully neutral, no counter is touched.
 * That is not a detail. Back when a mid-band tick reset the counters, one
 * blip during a recovery (a single chunk uploading in 3.2 s on a wifi
 * burst) erased the accumulated fast streak, and on a network hovering
 * near the threshold the upgrade then never fired again — silently, stuck
 * at the lower quality (fixed 2026-05-10).
 *
 * A quality change is not free for the consumer: it rebuilds the encoder
 * in place. Nothing recorded is lost — the chunk in flight is finalized and
 * delivered early, and only the empty preallocated chunk is dropped — but
 * the picture hitches for about a frame while the GL output surface is
 * recreated. The camera is not rebound and the preview does not black out.
 * [RollingChunkRecorder.swapVideoConfig] owns that cost and describes it.
 *
 * Thread-safety: state lives in atomics, so [reportChunkUploadTime] and
 * [reset] are safe to call from any thread. [onQualityChange] is invoked
 * synchronously on the caller's thread, and that thread varies: an upload
 * worker thread on the [reportChunkUploadTime] path, the main looper on the
 * [setBacklog] one. So the callee must post back to the main thread before
 * touching the camera pipeline, which is what
 * `StreamRecordingService.applyQuality` does.
 */
class AdaptiveQualityManager(
    private val chunkIntervalMs: Long,
    private val onQualityChange: (StreamQuality) -> Unit,
    initialQuality: StreamQuality = StreamQuality.HD,
    /**
     * Debug calibration mode (2026-05-16). When `true`, all adaptive
     * transitions are short-circuited : [reportChunkUploadTime] and
     * [setBacklog] no-op, [currentQuality] stays pinned at the initial
     * value. Used by the fixed-bitrate calibration session where the
     * operator wants the encoder to keep producing chunks at a chosen
     * resolution + bitrate step regardless of network feedback.
     */
    private val forced: Boolean = false,
    /**
     * Moves the encoder between VBR and CBR when the upload backlog
     * crosses [BITRATE_MODE_CBR_THRESHOLD] (rising) or
     * [BITRATE_MODE_VBR_THRESHOLD] (falling), added 2026-05-17.
     *
     * Pass `null` when the consumer cannot move an encoder between VBR and
     * CBR at runtime. Mode adaptation is then disabled entirely and
     * silently: no partial degradation, no log. No production consumer
     * passes null today; the branch stays covered by the unit tests.
     *
     * The callback runs on the caller's thread, in practice the
     * notification refresher's main thread at ~1 Hz. The consumer is
     * responsible for triggering an encoder rebuild — same cost shape as
     * [onQualityChange], described in the class doc.
     */
    private val onBitrateModeChange: ((ChunkEncoderBundle.BitrateMode) -> Unit)? = null,
    initialBitrateMode: ChunkEncoderBundle.BitrateMode = ChunkEncoderBundle.BitrateMode.VBR,
    /**
     * User-configurable ceiling on the adaptive ladder: [stepUp] clamps to
     * it, and so do the initial value and [reset]. Default
     * [StreamQuality.FHD] means no cap. It bounds the top only — the ladder
     * still drops BELOW the cap as the network degrades, so this is a way
     * for a field user to bound per-chunk size and data usage on a metered
     * or flaky link, not a quality lock.
     *
     * Read once at recording start (the manager is rebuilt per session), so
     * changing the setting only takes effect on the NEXT recording — same
     * semantics as the debug-bitrate toggle.
     */
    private val maxQuality: StreamQuality = StreamQuality.FHD,
) {
    private val quality = AtomicReference(initialQuality.coerceAtMost(maxQuality))
    private val slowTicks = AtomicInteger(0)
    private val fastTicks = AtomicInteger(0)
    private val backlog = AtomicInteger(0)
    private val bitrateMode = AtomicReference(initialBitrateMode)

    @Volatile private var lastBitrateModeTransitionMs: Long = 0L

    /**
     * Timestamp of the last forced backlog downgrade, used as a cooldown so
     * a sustained-high backlog doesn't fire stepDown repeatedly, faster than
     * the new quality can settle — every rebound is another encoder swap,
     * at the cost described in the class doc. Volatile = visible across
     * threads.
     */
    @Volatile private var lastBacklogDowngradeMs: Long = 0L

    /**
     * Timestamp of the last hysteresis-driven quality transition (stepUp /
     * stepDown via fast_hyst or slow_hyst), used as an anti yo-yo cooldown
     * when the network sits on the borderline between FAST_THRESHOLD_RATIO
     * and SLOW_THRESHOLD_RATIO.
     *
     * Field-tested on the Seeker on 2026-05-18: over the 19:58→20:28
     * session, ~20 cycles of `fast_hyst 720→1080` followed by `slow_hyst
     * 1080→720` in 8 minutes, one every ~55 s. Sustained and reproducible,
     * not an isolated incident — that measurement is what makes the 60 s
     * cooldown a lower bound rather than a round number. The arithmetic
     * agrees: FAST_HYSTERESIS=10 + SLOW=3 at a 5 s chunk interval, so
     * ~50 s up + ~15 s down, a ~65 s cycle. The mid-band neutralization
     * does NOT cover this case and cannot replace the cooldown: the
     * steady-state ratio oscillates around 0.7, half the time below
     * FAST_THRESHOLD and half above SLOW_THRESHOLD, so it never lingers in
     * the mid-band long enough to neutralize anything.
     *
     * Volatile = visible across threads (set/read from any caller of
     * [reportChunkUploadTime] or [setBacklog]).
     */
    @Volatile private var lastQualityTransitionMs: Long = 0L

    /** Currently active quality. Read by the recording pipeline. */
    val currentQuality: StreamQuality
        get() = quality.get()

    /**
     * Current rate-control mode. Read by
     * [StreamRecordingService.buildHevcVideoConfigFor] so a quality-only
     * swap reuses the mode in effect ; toggled by the backlog ladder inside
     * [setBacklog].
     */
    val currentBitrateMode: ChunkEncoderBundle.BitrateMode
        get() = bitrateMode.get()

    /**
     * Current backlog snapshot, so observers (the ChunkUploadWorker metrics
     * line, the periodic snapshot) can put it in a structured log without
     * re-reading the filesystem.
     */
    fun getBacklog(): Int = backlog.get()

    /**
     * Current upload backlog in chunks, pushed by the recording service
     * from its notification refresher (1 Hz).
     *
     * Two rules ride on it. Above [BACKLOG_FREEZE_THRESHOLD] the manager
     * refuses any upgrade, even on a sustained fast streak: we are behind,
     * and heavier chunks would only grow the queue further. Downgrade stays
     * active.
     *
     * Past [FORCE_DOWNGRADE_BACKLOG] it forces a stepDown without waiting
     * for [SLOW_HYSTERESIS] consecutive SLOW ticks. That second downgrade
     * path is not a duplicate of the hysteresis, and the reason is a
     * livelock reproduced in-vivo on 2026-05-13: with the concurrency cap
     * at 1, uploads around 5 s and capture producing one chunk every 5 s,
     * the system settles into a STABLE equilibrium where the backlog never
     * drains. Worse, the workers that bounce off "concurrency cap, retry
     * deferred" report no uploadTime at all, so the SLOW-tick path is blind
     * and can never fire the downgrade — the signal stays stuck on whatever
     * the last successful upload produced. Driving the downgrade off the
     * backlog is what breaks the deadlock : smaller chunks → uploadMs <
     * chunkInterval → ratio < 1 → backlog drains → the cap can climb back
     * up.
     */
    fun setBacklog(count: Int) {
        backlog.set(count.coerceAtLeast(0))
        // Debug calibration : no forced downgrade — keep the user-pinned
        // quality even if uploads pile up. The operator is judging the
        // visual output, not the upload throughput.
        if (forced) return
        maybeAdjustBitrateMode(count)
        if (count > FORCE_DOWNGRADE_BACKLOG) {
            val now = System.currentTimeMillis()
            if (now - lastBacklogDowngradeMs >= FORCE_DOWNGRADE_COOLDOWN_MS) {
                val before = quality.get()
                // Suppress the stepDown's "slow_hyst" reason — we want
                // this transition tagged as "forced_backlog" instead.
                if (before != before.downgrade()
                    && quality.compareAndSet(before, before.downgrade())
                ) {
                    val after = quality.get()
                    slowTicks.set(0)
                    fastTicks.set(0)
                    lastBacklogDowngradeMs = now
                    // Share the timestamp with the hysteresis cooldown, so a
                    // forced_backlog followed within 60 s by a recovery-driven
                    // fast_hyst stepUp doesn't re-up too fast : the urgent
                    // downgrade means "the network is genuinely bad", and we
                    // want at least one transition cycle of observation before
                    // agreeing it has recovered.
                    lastQualityTransitionMs = now
                    Timber.tag("StreamMetrics").i(
                        "qualityTransition from=%s to=%s reason=forced_backlog backlog=%d",
                        before.displayLabel, after.displayLabel, count
                    )
                    onQualityChange(after)
                }
            }
        }
    }

    /**
     * Report that a chunk uploaded in [uploadTimeMs] milliseconds. Called
     * from [rs.readahead.washington.mobile.util.jobs.ChunkUploadWorker]
     * once per finished worker. May trigger [onQualityChange].
     */
    fun reportChunkUploadTime(uploadTimeMs: Long) {
        if (uploadTimeMs < 0) return
        // Debug calibration : ignore upload feedback. The pinned quality
        // and bitrate must persist for the full calibration clip.
        if (forced) return
        val ratio = uploadTimeMs.toDouble() / chunkIntervalMs.toDouble()

        when {
            ratio > SLOW_THRESHOLD_RATIO -> {
                fastTicks.set(0)
                val n = slowTicks.incrementAndGet()
                Timber.v(
                    "AdaptiveQuality: SLOW tick (uploadMs=%d, ratio=%.2f, slowTicks=%d/%d)",
                    uploadTimeMs, ratio, n, SLOW_HYSTERESIS
                )
                if (n >= SLOW_HYSTERESIS) {
                    stepDown()
                }
            }
            ratio < FAST_THRESHOLD_RATIO -> {
                slowTicks.set(0)
                val n = fastTicks.incrementAndGet()
                val pending = backlog.get()
                if (pending > BACKLOG_FREEZE_THRESHOLD) {
                    // Backlog gating. We're behind: do not upgrade even on
                    // a sustained fast streak. The 1080p chunks observed
                    // in-vivo 2026-05-10 during a wifi recovery grew the
                    // queue and made the catchup sluggish. Downgrade still
                    // works (slow path unchanged).
                    Timber.v(
                        "AdaptiveQuality: FAST tick (uploadMs=%d, ratio=%.2f, fastTicks=%d/%d) — gated, backlog=%d > %d",
                        uploadTimeMs, ratio, n, FAST_HYSTERESIS, pending, BACKLOG_FREEZE_THRESHOLD
                    )
                } else {
                    Timber.v(
                        "AdaptiveQuality: FAST tick (uploadMs=%d, ratio=%.2f, fastTicks=%d/%d, backlog=%d)",
                        uploadTimeMs, ratio, n, FAST_HYSTERESIS, pending
                    )
                    if (n >= FAST_HYSTERESIS) {
                        stepUp()
                    }
                }
            }
            else -> {
                // Mid-band: fully neutral, no counter mutation. See class
                // doc — preserves the in-flight fast streak across the
                // occasional mid-band blip during recovery.
                Timber.v(
                    "AdaptiveQuality: MID tick (uploadMs=%d, ratio=%.2f, slow=%d fast=%d unchanged)",
                    uploadTimeMs, ratio, slowTicks.get(), fastTicks.get()
                )
            }
        }
    }

    /** Reset state (ratchet, counters) — call at recording start. */
    fun reset(
        quality: StreamQuality = StreamQuality.HD,
        bitrateMode: ChunkEncoderBundle.BitrateMode = ChunkEncoderBundle.BitrateMode.VBR,
    ) {
        this.quality.set(quality.coerceAtMost(maxQuality))
        this.bitrateMode.set(bitrateMode)
        slowTicks.set(0)
        fastTicks.set(0)
        backlog.set(0)
        lastBitrateModeTransitionMs = 0L
        lastBacklogDowngradeMs = 0L
        lastQualityTransitionMs = 0L
    }

    /**
     * Network-recovery hint, called from the recording service's
     * `NetworkCallback.onAvailable` once the link has (re)validated. Clears
     * only the SLOW/FAST tick counters, so the post-recovery upload samples
     * decide the next transition from a clean slate instead of carrying the
     * SLOW streak accumulated during the bad-network spell.
     *
     * Deliberately conservative, and each of the three restrictions is
     * load-bearing. It does not force a step. It does not touch
     * [lastQualityTransitionMs], so the anti-yoyo cooldown stays armed and a
     * flapping link cannot resurrect the 2026-05-18 oscillation. It does not
     * touch the backlog: the existing hysteresis and
     * [BACKLOG_FREEZE_THRESHOLD] still govern any upgrade, so a recovery
     * that isn't real cannot bump the quality, and the [setBacklog] forced
     * downgrade still guards the downside.
     *
     * Pairs with `UploadConcurrencyLimiter.bumpCapForRecovery()` : without
     * that cap re-arm the rescheduled workers produce no fresh FAST samples,
     * and clearing the counters here buys nothing.
     *
     * No-op in [forced] calibration mode (the pinned quality must persist).
     * Safe from any thread (atomics).
     */
    fun onNetworkRecovered() {
        if (forced) return
        slowTicks.set(0)
        fastTicks.set(0)
        Timber.tag("StreamMetrics").i("qualityNetworkRecovered slowFast=reset")
    }

    /**
     * Inspected on every backlog tick (~1 Hz). Promotes VBR → CBR when
     * chunks pile up, so the encoder hard-caps and the queue can drain, and
     * reverts to VBR once the queue is essentially clear. Skipped entirely
     * when [onBitrateModeChange] is `null`.
     *
     * What CBR buys is measured, not theoretical : in 480p on the Seeker
     * (in-vivo 2026-05-17), a VBR encoder aimed at a 500 kbps target
     * actually floored around 1 Mbps where CBR delivered ~640 kbps, so
     * roughly half the bytes per chunk.
     *
     * The ladder is asymmetric, mirroring the quality manager's :
     *   - VBR → CBR at `backlog ≥ 3`, one notch below the quality stepDown
     *     at 6, so the milder mitigation is tried before the stepDown
     *     wastes the in-flight HD chunks.
     *   - CBR → VBR at `backlog ≤ 1`, once the queue has fully drained,
     *     before paying for another rebuild to restore visual quality.
     *     Conservative on purpose : each swap is a full encoder rebuild and
     *     we don't want to pay it twice over a 2-chunk blip.
     *   - `backlog = 2` is a no man's land : neither edge fires, the
     *     current mode persists.
     *   - 30 s cooldown between transitions, same as the quality downgrade,
     *     which keeps the mode stable across an emerging vs steady-state
     *     network signal.
     */
    private fun maybeAdjustBitrateMode(backlog: Int) {
        val cb = onBitrateModeChange ?: return
        val now = System.currentTimeMillis()
        if (now - lastBitrateModeTransitionMs < BITRATE_MODE_COOLDOWN_MS) return

        val current = bitrateMode.get()
        val target = when {
            current == ChunkEncoderBundle.BitrateMode.VBR
                && backlog >= BITRATE_MODE_CBR_THRESHOLD ->
                ChunkEncoderBundle.BitrateMode.CBR
            current == ChunkEncoderBundle.BitrateMode.CBR
                && backlog <= BITRATE_MODE_VBR_THRESHOLD ->
                ChunkEncoderBundle.BitrateMode.VBR
            else -> return
        }

        if (bitrateMode.compareAndSet(current, target)) {
            lastBitrateModeTransitionMs = now
            Timber.tag("StreamMetrics").i(
                "bitrateModeTransition from=%s to=%s backlog=%d",
                current.name, target.name, backlog
            )
            cb(target)
        }
    }

    private fun stepDown() {
        // Anti yo-yo cooldown : skip if the previous hysteresis transition
        // is too recent. Counters are PRESERVED (slowTicks keeps its
        // value), so the moment the cooldown elapses, if the pressure
        // persists, the very next SLOW tick fires the stepDown without
        // waiting another SLOW_HYSTERESIS window — reactive, but without
        // the oscillation.
        val now = System.currentTimeMillis()
        if (now - lastQualityTransitionMs < QUALITY_TRANSITION_COOLDOWN_MS) {
            Timber.v(
                "AdaptiveQuality: stepDown gated by anti yo-yo cooldown (%d ms left)",
                QUALITY_TRANSITION_COOLDOWN_MS - (now - lastQualityTransitionMs)
            )
            return
        }
        val current = quality.get()
        val next = current.downgrade()
        if (next != current && quality.compareAndSet(current, next)) {
            slowTicks.set(0)
            fastTicks.set(0)
            lastQualityTransitionMs = now
            // Structured transition event for post-hoc field analysis.
            // Reason="slow_hyst" when triggered by the 3-consecutive-SLOW
            // path ; the backlog-forced path logs its own
            // reason="forced_backlog" line in setBacklog.
            Timber.tag("StreamMetrics").i(
                "qualityTransition from=%s to=%s reason=slow_hyst backlog=%d",
                current.displayLabel, next.displayLabel, backlog.get()
            )
            onQualityChange(next)
        }
    }

    private fun stepUp() {
        // Anti yo-yo cooldown, same rationale as stepDown : counters
        // preserved, the transition fires on the first eligible FAST tick
        // once the cooldown has elapsed.
        val now = System.currentTimeMillis()
        if (now - lastQualityTransitionMs < QUALITY_TRANSITION_COOLDOWN_MS) {
            Timber.v(
                "AdaptiveQuality: stepUp gated by anti yo-yo cooldown (%d ms left)",
                QUALITY_TRANSITION_COOLDOWN_MS - (now - lastQualityTransitionMs)
            )
            return
        }
        val current = quality.get()
        // Clamp the upgrade to the user's max-quality cap. When already at
        // the cap, upgrade().coerceAtMost == current, so the guard below is
        // a no-op and the ladder never climbs past it.
        val next = current.upgrade().coerceAtMost(maxQuality)
        if (next != current && quality.compareAndSet(current, next)) {
            slowTicks.set(0)
            fastTicks.set(0)
            lastQualityTransitionMs = now
            Timber.tag("StreamMetrics").i(
                "qualityTransition from=%s to=%s reason=fast_hyst backlog=%d",
                current.displayLabel, next.displayLabel, backlog.get()
            )
            onQualityChange(next)
        }
    }

    companion object {
        const val SLOW_THRESHOLD_RATIO = 0.80
        const val FAST_THRESHOLD_RATIO = 0.60
        const val SLOW_HYSTERESIS = 3

        /**
         * Raised from 5 to 10 after in-vivo 2026-05-14, and 5 is not worth
         * going back to. At 5, after a stepDown HD → SD on a flaky but
         * recovering link, the FAST hysteresis cleared in ~25 s and the
         * quality flipped back up to HD just before the next dropout : the
         * chunks that then piled up during the dropout were 1.6 MB each
         * instead of the 900 kB they would have been in SD, and the
         * post-reconnect catchup was significantly slower for it. 10 means
         * ~50 s of sustained FAST signal before bumping up, which is closer
         * to "the network is genuinely stable" than "the last 5 chunks
         * happened to upload quickly".
         *
         * This is not interchangeable with the backlog freeze
         * ([BACKLOG_FREEZE_THRESHOLD]), which is what holds the floor at SD
         * while the queue is meaningfully backed up.
         */
        const val FAST_HYSTERESIS = 10

        /**
         * Pending blobs above this freeze upgrades. Picked at 5 = ~25 s of
         * capture lag at the default 5 s chunk interval. Below this, the
         * queue is treated as essentially caught up and upgrades are
         * allowed.
         */
        const val BACKLOG_FREEZE_THRESHOLD = 5

        /**
         * Lowered from 10 to 6 after in-vivo 2026-05-14. At 10 the
         * downgrade fired ~50 s after the network dropped — too late for a
         * meaningful catchup, since the queue was already filled with
         * full-bitrate HD chunks. 6 = 30 s of capture lag, clearly past a
         * transient hiccup but still recoverable. Raising it back "to avoid
         * spurious downgrades" brings the ~50 s back. The asymmetry with
         * FAST_HYSTERESIS = 10 (so ~50 s of stable network before any
         * upgrade back to HD) is what prevents quality yo-yo.
         */
        const val FORCE_DOWNGRADE_BACKLOG = 6

        /**
         * Minimum delay between two backlog-forced downgrades. Picked at
         * 30 s = enough for the encoder swap plus a few chunks at the new
         * bitrate, before we judge whether yet another downgrade is needed (e.g. HD → SD, still backed up, want
         * to consider further — but we floor at SD).
         */
        const val FORCE_DOWNGRADE_COOLDOWN_MS = 30_000L

        /**
         * Backlog at which a VBR encoder is rebuilt as CBR. Picked one step
         * below [FORCE_DOWNGRADE_BACKLOG] (= 6) so the milder mitigation
         * (cap bytes by mode) is attempted before the more disruptive
         * quality stepDown.
         */
        const val BITRATE_MODE_CBR_THRESHOLD = 3

        /**
         * Backlog at which CBR reverts to VBR. Conservative (0 or 1
         * pending) to avoid yo-yoing across a transient blip — the swap is
         * a full encoder rebuild and we don't want to pay it twice in a
         * row.
         */
        const val BITRATE_MODE_VBR_THRESHOLD = 1

        /**
         * Minimum delay between two bitrate-mode transitions. Mirrors
         * [FORCE_DOWNGRADE_COOLDOWN_MS] : long enough for the new mode to
         * settle through ~6 chunks before we judge whether the other
         * direction is warranted.
         */
        const val BITRATE_MODE_COOLDOWN_MS = 30_000L

        /**
         * Anti yo-yo cooldown between two hysteresis-driven
         * qualityTransitions. Applied to both stepUp (fast_hyst) and
         * stepDown (slow_hyst), and shared with the forced_backlog path so
         * a recovery-driven stepUp doesn't fire within 60 s of an urgent
         * downgrade.
         *
         * 60 s is a lower bound, not a round number : the Seeker field-test
         * of 2026-05-18 observed cycles of ~55 s, so anything under 60 s
         * fails to break the loop and re-opens that bug. It also happens to
         * be ~12 chunks at chunkInterval=5 s, a full FAST_HYSTERESIS window
         * of observation before any opposite transition is considered.
         *
         * NOT applied to the FORCE_DOWNGRADE path, which keeps its own 30 s
         * cooldown : an urgent stepDown must stay reactive even right after
         * a hysteresis transition. Unifying the two cooldowns would make an
         * urgent downgrade wait 60 s while the queue grows.
         */
        const val QUALITY_TRANSITION_COOLDOWN_MS = 60_000L
    }
}
