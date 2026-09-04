package org.stream.crypto.capture

import android.graphics.SurfaceTexture
import android.os.Handler
import android.os.HandlerThread
import android.view.Surface
import timber.log.Timber
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Produces a continuous sequence of standalone MP4 chunks (video + optional
 * audio) of [chunkIntervalMs] each. Camera, GL pipeline and PCM capture stay
 * live across chunk boundaries ; only the
 * [MediaMuxer][android.media.MediaMuxer] and
 * [MediaCodec][android.media.MediaCodec] encoders are recreated per chunk.
 *
 * **The rotation order is fixed** : `bundle.start()` (~5 ms) →
 * `pcm.setSink(new)` → `old.audio.signalEos()` → `gl.setOutputSurface(new)`.
 * Any other order costs audio (detaching the PCM sink before the EOS drops
 * what is still in flight — see [stop]) or frames. Everything else is done
 * ahead of the tick : the next chunk's `ChunkEncoderBundle` is built
 * `preallocLeadMs` early (codecs configured, encoder Surface obtained), which
 * leaves those four calls as the whole rotation, ~10 ms.
 *
 * **Rotation gap targets**
 *   - audio : 0 sample lost. The PCM stream is permanent ; the sink swap is
 *     an atomic `AtomicReference.set` between two consecutive
 *     `AudioRecord.read()` calls.
 *   - video : 1 frame worst case during the EGL window swap (1-5 ms on the
 *     GL thread, well below 1 frame at 30 fps).
 *
 * **Binding order** : the first chunk's encoder Surface is created in the
 * constructor so the GL pipeline has a target, and the pipeline is built and
 * started there too. The camera is therefore bound to [cameraSurfaceTexture]
 * BETWEEN construction and [start]. Starting GL lazily inside [start] instead
 * would leave the caller no correct ordering : binding before [start] would
 * find the SurfaceTexture not ready, binding after would race the first frames
 * being dropped. [start] itself boots PCM capture, the first chunk's encoders
 * and the rotation schedule — GL is already running by then. Every
 * [chunkIntervalMs] a finished chunk MP4 is delivered via [onChunkReady], and
 * [stop] delivers the in-flight one too so the consumer doesn't lose the tail.
 *
 * **Threading**
 *   - Internal rotation work runs on a dedicated `HandlerThread`
 *     ("RollingChunkRotate").
 *   - Old bundle teardown runs on a per-chunk one-shot thread so a slow muxer
 *     close (rare, but it happens on cold storage) doesn't delay the next
 *     rotation.
 *   - [onChunkReady] is therefore invoked **on the teardown thread** for
 *     rotation events and **on the calling thread of [stop]** for the final
 *     chunk. Implementations must not assume any specific thread.
 *
 * (Phase H2-B.4, 2026-05-16.)
 */
class RollingChunkRecorder(
    private val chunkDir: File,
    private val chunkIntervalMs: Long = 5_000L,
    private val preallocLeadMs: Long = 500L,
    initialVideoConfig: ChunkEncoderBundle.VideoConfig,
    private val audioConfig: ChunkEncoderBundle.AudioConfig?,
    private val orientationHintDegrees: Int = 0,
    private val onChunkReady: (File, Int) -> Unit,
    private val onError: (Exception) -> Unit,
) {
    init {
        require(chunkIntervalMs > preallocLeadMs + 200L) {
            "chunkIntervalMs ($chunkIntervalMs) must exceed preallocLeadMs ($preallocLeadMs) + 200ms"
        }
        chunkDir.mkdirs()
    }

    private data class PendingChunk(
        val bundle: ChunkEncoderBundle,
        val seq: Int,
        val file: File,
        val inputSurface: Surface,
    )

    private val rotateThread = HandlerThread("RollingChunkRotate").apply { start() }
    private val rotateHandler = Handler(rotateThread.looper)
    private val seqNum = AtomicInteger(0)
    @Volatile private var currentChunk: PendingChunk? = null
    @Volatile private var preallocatedNext: PendingChunk? = null
    private val running = AtomicBoolean(false)

    // [videoConfig] is swapped by [swapVideoConfig] (new resolution / bitrate /
    // mime) while the recorder stays live; makeChunk() reads it to configure the
    // next chunk's encoder. Written + read on the rotate handler thread →
    // @Volatile. [glPipeline] is built ONCE and reused for the whole recording:
    // a quality swap only repoints its OUTPUT surface in place (H2-B §Bugs #5),
    // it is no longer torn down + rebuilt, so the EGL context / OES texture /
    // camera SurfaceTexture / preview surface all persist across swaps.
    @Volatile private var videoConfig: ChunkEncoderBundle.VideoConfig = initialVideoConfig
    @Volatile private lateinit var glPipeline: GlVideoPipeline
    private val pcmThread: PcmCaptureThread?

    // Optional preview Surface attached to
    // the GL pipeline as a secondary draw target. Stored at recorder
    // level (not GL level) so it survives independently of chunk swaps:
    // the GL pipeline is no longer rebuilt on a quality swap, so the
    // preview stays attached throughout — it only needs re-feeding at
    // start() or if the SurfaceView surface itself is recreated.
    @Volatile private var previewSurface: Surface? = null

    // Actual camera buffer dimensions + the rotation needed to display in the
    // target orientation, forwarded to the GL pipeline as a
    // [GlVideoPipeline.setSourceTransform] call. The pipeline keeps its own
    // copy of the three values and that copy is what the draw loop reads ;
    // these fields are only the last values pushed through, nothing reads them
    // back today. (Phase H2-B.3, 2026-05-17 fix.)
    @Volatile private var sourceWidthPx: Int = 0
    @Volatile private var sourceHeightPx: Int = 0
    @Volatile private var sourceRotationDegrees: Int = 0

    // Guards the HEVC→H.264 fallback against re-entry. A
    // [android.media.MediaCodec.CodecException] from the HEVC drain thread
    // schedules a swap to `video/avc` ; if H.264 then throws too, a second
    // swap must NOT be scheduled — there is no further fallback codec, so the
    // re-entry would loop for ever instead of surfacing. The failure has to
    // reach the outer [onError]. One-shot : the flag stays true until the
    // recorder is destroyed.
    // It has to be an AtomicBoolean claimed by CAS and not a `var` : two
    // encoder drain threads can enter handleVideoCodecError at the same time,
    // and the old read-check-write let both of them launch a swap (TOCTOU,
    // closed by the N3 fix). (Phase H2-B.17, Blue MED-3 fix, 2026-05-19.)
    private val hevcFallbackAttempted = AtomicBoolean(false)

    // #2/N1 fail-closed rotation watchdog (all touched only on the rotate thread).
    // Count consecutive rotation failures; past MAX_ROTATION_FAILURES escalate an
    // unrecoverable capture (the service stops cleanly, finalizing+encrypting the
    // in-flight clear chunk) instead of letting it grow unbounded in the clear.
    private var consecutiveRotationFailures = 0
    @Volatile private var escalated = false

    init {
        // Build the very first chunk synchronously so the GL pipeline
        // has a target Surface to bind to.
        val first = makeChunk()
        currentChunk = first
        // GL pipeline is started up front so the camera can be bound
        // via [cameraSurfaceTexture] *before* [start] kicks off audio
        // capture and the first chunk's encoders. Doing it lazily in
        // start() forces the caller into a wrong ordering (bind camera
        // before start = SurfaceTexture not ready ; bind camera after
        // start = race with the first frames being dropped).
        glPipeline = GlVideoPipeline(
            initialOutputSurface = first.inputSurface,
            widthPx = videoConfig.widthPx,
            heightPx = videoConfig.heightPx,
        ).also { it.start() }
        pcmThread = audioConfig?.let {
            PcmCaptureThread(it.sampleRate, it.channelCount)
        }
    }

    /**
     * Hand this SurfaceTexture to the camera (e.g. CameraX
     * `Preview.setSurfaceProvider { request -> request.provideSurface(
     * Surface(surfaceTexture), executor, callback) }`). Available as soon as
     * the constructor has returned — the GL pipeline is built and started in
     * the init block. Bind the camera BEFORE [start] : binding after it races
     * the first frames.
     */
    fun cameraSurfaceTexture(): SurfaceTexture = glPipeline.cameraSurfaceTexture()

    fun start() {
        if (!running.compareAndSet(false, true)) error("Already started")
        // GL pipeline was already started in the constructor (so the
        // caller could bind the camera SurfaceTexture). Here we only
        // boot audio capture + the first chunk's encoders.
        pcmThread?.start()
        val first = currentChunk ?: error("first chunk missing")
        pcmThread?.setSink(first.bundle.audioEncoder)
        first.bundle.start()
        // Apply a preview Surface that was attached
        // before [start] (typical : the caller wires the SurfaceView's
        // SurfaceHolder.Callback to [setPreviewSurface] *before* calling
        // [start]). The GL pipeline is already running so the call is
        // honored ; without this re-apply, the stored Surface would
        // never be sent to GL.
        previewSurface?.let {
            try { glPipeline.setPreviewOutputSurface(it) } catch (e: Exception) {
                Timber.w(e, "start: preview attach failed")
            }
        }
        Timber.tag("StreamMetrics").i(
            "rollingStart seq=%d chunkMs=%d preallocLeadMs=%d",
            first.seq, chunkIntervalMs, preallocLeadMs
        )
        rotateHandler.postDelayed({ preallocateNext() }, chunkIntervalMs - preallocLeadMs)
        rotateHandler.postDelayed({ rotateChunk() }, chunkIntervalMs)
    }

    /**
     * Attach (or detach) an on-screen preview Surface, drawn by the GL
     * pipeline as a second target alongside the encoder Surface.
     *
     * The reference is held here, at recorder level, and not inside the GL
     * pipeline, because the caller's Surface arrives on its own schedule : it
     * can be handed over before [start], which replays it, and the Activity
     * lifecycle can destroy and recreate the SurfaceView at any time. A quality
     * swap does not disturb it — [swapVideoConfig] repoints the output surface
     * in place and the preview stays attached throughout.
     *
     * Safe to call before [start] — the surface is stored and attached when
     * [start] runs — or any time after. Pass `null` to detach (e.g. when the
     * SurfaceView surface is destroyed by the Activity lifecycle).
     * (Phase H2-B.3, 2026-05-17.)
     */
    fun setPreviewSurface(surface: Surface?) {
        previewSurface = surface
        if (running.get()) {
            try {
                glPipeline.setPreviewOutputSurface(surface)
            } catch (e: Exception) {
                Timber.w(e, "setPreviewSurface: GL forward failed")
            }
        }
        // If !running, the surface is captured in [previewSurface] and
        // attached at the next start().
    }

    /**
     * Declare the camera buffer dimensions — as actually negotiated by
     * CameraX, typically landscape even on a phone held in portrait — and the
     * CCW rotation in degrees needed to bring that buffer to the target
     * display orientation. Typical for portrait phones with landscape-mounted
     * rear cams : `setSourceTransform(1280, 720, 90)`. Mixing the convention
     * up gives the squish/rotated-video class of bug. It shows on screen right
     * away : the preview is letterboxed from this same triplet and frames
     * exactly what is being recorded (WYSIWYG, H2-B.20), so there is no need to
     * wait for an archive playback to catch it.
     *
     * The GL pipeline keeps its own copy of the transform, and
     * [swapVideoConfig] repoints its output surface in place without touching
     * that copy, so nothing has to be re-applied after a swap.
     * (Phase H2-B.3, 2026-05-17.)
     */
    fun setSourceTransform(bufferWidthPx: Int, bufferHeightPx: Int, rotationDegrees: Int) {
        sourceWidthPx = bufferWidthPx
        sourceHeightPx = bufferHeightPx
        sourceRotationDegrees = rotationDegrees
        try {
            glPipeline.setSourceTransform(bufferWidthPx, bufferHeightPx, rotationDegrees)
        } catch (_: UninitializedPropertyAccessException) {
            // Called before the init block has built glPipeline. The values
            // land in the fields above, but nothing replays them : a transform
            // pushed this early never reaches GL.
        } catch (e: Exception) {
            Timber.w(e, "setSourceTransform: GL forward failed")
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        rotateHandler.removeCallbacksAndMessages(null)

        val curr = currentChunk
        val preall = preallocatedNext
        currentChunk = null
        preallocatedNext = null

        // GL pipeline first (avoid EGL_BAD_SURFACE on encoder shutdown).
        try { glPipeline.stop() } catch (e: Exception) {
            Timber.w(e, "stop: glPipeline failed")
        }
        // Signal EOS first, drain (bundle.stop() waits for the audio encoder
        // to consume up to the EOS marker), THEN detach the PCM sink. The
        // historic order detached it (`pcmThread.setSink(null)`) BEFORE
        // signaling EOS, which silently dropped 500-1000 ms of audio samples
        // already buffered in flight, because the sink=null path in
        // PcmCaptureThread discards reads. For a témoignage parlé that is the
        // last sentence said, often the one that matters ("I am being
        // detained").
        //
        // What makes this order safe : after EOS, MediaCodec drops the
        // remaining PCM frames itself, so nothing has to be re-routed while
        // the drain finishes. (Phase H2-B.14, 2026-05-18 ; Blue HIGH-1 + R2
        // stop(), drainAudioThenDetach.)
        try {
            curr?.bundle?.audioEncoder?.signalEos()
        } catch (e: Exception) {
            Timber.w(e, "stop: audio signalEos failed")
        }
        // Drain + close current bundle (audio drain reads PCM samples
        // up to the EOS just signaled, video drain reads via encoder
        // input surface EOS implied by bundle.stop()).
        if (curr != null) {
            try { curr.bundle.stop() } catch (e: Exception) {
                Timber.w(e, "stop: current bundle.stop failed")
            }
            // Mirror the rotation-path chunkReady metric so the final
            // chunk delivered at session end shows up alongside the
            // others in field logs.
            Timber.tag("StreamMetrics").i(
                "chunkReady seq=%d sizeBytes=%d final=true",
                curr.seq, curr.file.length()
            )
            try { onChunkReady(curr.file, curr.seq) } catch (e: Exception) {
                Timber.w(e, "stop: onChunkReady (final) failed")
            }
        }
        // Detach AFTER drain. The PCM thread is still
        // pushing reads at this point but the encoder is EOS'd, so
        // MediaCodec drops them at dequeueInputBuffer. Detaching here
        // stops the futile pushes for the remaining stop sequence.
        try { pcmThread?.setSink(null) } catch (e: Exception) {
            Timber.w(e, "stop: pcm setSink(null) failed")
        }
        // Discard preallocated chunk (never recorded into). The bundle's
        // stop() handles "configured but not started" cleanly.
        preall?.let {
            try { it.bundle.stop() } catch (e: Exception) {
                Timber.w(e, "stop: preallocated bundle.stop failed")
            }
        }
        try { pcmThread?.stop() } catch (e: Exception) {
            Timber.w(e, "stop: pcmThread failed")
        }
        rotateThread.quitSafely()
        Timber.tag("StreamMetrics").i("rollingStop done")
    }

    /**
     * Swap to a new video config (resolution, bitrate, mime) mid-recording.
     *
     * Mechanically this is a [rotateChunk] with new dimensions : start the new
     * chunk's encoder, switch the PCM sink atomically, EOS the old audio, then
     * repoint the GL pipeline's OUTPUT surface at the new encoder IN PLACE via
     * [GlVideoPipeline.setOutputSurface] (now carrying the new dims). The EGL
     * context, the GL program, the OES texture, the on-screen preview surface
     * AND the camera-facing SurfaceTexture all survive — so the live preview
     * keeps rendering throughout (no teardown, no forensic black-scrub) and the
     * camera never needs re-binding. The camera's config (resolution, ultra-
     * wide zoom, AE FPS floor) persists from the single startCamera bind.
     *
     * This replaced the original teardown+rebuild (glPipeline.stop() → new
     * GlVideoPipeline → caller rebinds the camera), which blacked out the
     * preview on every adaptive quality change (field-test Berlin 2026-06-16)
     * and zoomed the FOV via the camera rebind. Bonus : the audio handoff is
     * now the lossless [rotateChunk] ordering (setSink-then-EOS) instead of the
     * old EOS-then-rebuild gap (~200-500 ms). (Phase H2-B.5, 2026-05-16 ;
     * rewritten under H2-B §Bugs #5, 2026-06-19.)
     *
     * The currently-recording chunk is finalized + delivered via [onChunkReady]
     * on a background thread (mirrors [rotateChunk]); the stale preallocated
     * chunk (configured for the OLD dims) is discarded there too.
     *
     * Runs on the rotate handler thread so it serializes with any in-flight
     * [rotateChunk] or [preallocateNext]. The caller blocks until the swap is
     * complete. Cost : 1 chunk delivered early (the one in flight) + a ~1-frame
     * hitch while the GL output surface is recreated (no black, no rebind).
     */
    fun swapVideoConfig(newConfig: ChunkEncoderBundle.VideoConfig) {
        check(running.get()) { "swapVideoConfig called before start() or after stop()" }
        val latch = CountDownLatch(1)
        val errRef = AtomicReference<Exception?>(null)
        rotateHandler.post {
            val swapStartNs = System.nanoTime()
            var swapNext: PendingChunk? = null
            try {
                // Cancel the pending periodic prealloc/rotation; we rebuild the
                // chunk cadence around the new config at the end of this swap.
                rotateHandler.removeCallbacksAndMessages(null)

                val old = currentChunk
                val preall = preallocatedNext

                // 1. Adopt the new config FIRST so makeChunk() configures the
                //    new encoder at the new dims/bitrate/mime.
                videoConfig = newConfig
                val next = makeChunk()
                swapNext = next

                // 2-5. Same four calls, in the same order, as rotateChunk() —
                //      the proven, black-free, audit-hardened one (H2-B.14 /
                //      Blue HIGH-1). Reordering them costs audio. Only two
                //      things differ from a plain rotation : the new dims are
                //      handed to setOutputSurface, and `next` is a FRESH
                //      makeChunk() rather than the preallocated chunk — that
                //      one's codecs were configured for the OLD dims / bitrate
                //      / mime, so reusing it would encode the new content at
                //      the old resolution. The GL pipeline, the preview and the
                //      camera SurfaceTexture are untouched, so there is no
                //      preview black-out.
                next.bundle.start()
                pcmThread?.setSink(next.bundle.audioEncoder)
                old?.bundle?.audioEncoder?.signalEos()
                glPipeline.setOutputSurface(
                    next.inputSurface, newConfig.widthPx, newConfig.heightPx
                )

                // 6. Bookkeep. The rotation cadence is re-armed in `finally`.
                currentChunk = next
                preallocatedNext = null
                consecutiveRotationFailures = 0

                val swapElapsedMs = (System.nanoTime() - swapStartNs) / 1_000_000L
                Timber.tag("StreamMetrics").i(
                    "rollingSwapConfig newSeq=%d w=%d h=%d kbps=%d swapMs=%d",
                    next.seq, newConfig.widthPx, newConfig.heightPx,
                    newConfig.bitrateBps / 1000, swapElapsedMs
                )

                // 7. Drain the old chunk + discard the stale preallocated chunk
                //    in the background (mirrors rotateChunk's drain thread) so
                //    the swap returns fast and the GL surface switch isn't held
                //    up by the old encoder's EOS flush. signalEndOfInputStream
                //    on the old video encoder is done by bundle.stop().
                Thread({
                    if (old != null) {
                        try { old.bundle.stop() } catch (e: Exception) {
                            Timber.w(e, "swapVideoConfig: old bundle.stop failed seq=%d", old.seq)
                        }
                        Timber.tag("StreamMetrics").i(
                            "chunkReady seq=%d sizeBytes=%d swap=true",
                            old.seq, old.file.length()
                        )
                        try { onChunkReady(old.file, old.seq) } catch (e: Exception) {
                            Timber.w(e, "swapVideoConfig: onChunkReady (transition) failed")
                        }
                    }
                    // The preallocated chunk's codecs were configured for the
                    // OLD dims/bitrate. bundle.stop() handles "configured but
                    // not started" cleanly.
                    preall?.let {
                        try { it.bundle.stop() } catch (e: Exception) {
                            Timber.w(e, "swapVideoConfig: preallocated bundle.stop failed")
                        }
                    }
                }, "RollingChunkSwapDrain-${old?.seq ?: -1}").start()
            } catch (e: Exception) {
                errRef.set(e)
                Timber.e(e, "swapVideoConfig failed")
                // Forfeit the broken `next`; `old` stays current and is delivered
                // by the next normal rotation (the finally re-arms the cadence).
                try { swapNext?.bundle?.stop() } catch (ex: Exception) {
                    Timber.w(ex, "swapVideoConfig recover: next.bundle.stop failed")
                }
                preallocatedNext = null
            } finally {
                // #2: re-arm the rotation cadence in ALL cases (never freeze). The
                // swap cancelled the pending cadence at the top; restore it for both
                // success and failure — unless the backstop escalated.
                if (running.get() && !escalated) {
                    rotateHandler.postDelayed({ preallocateNext() }, chunkIntervalMs - preallocLeadMs)
                    rotateHandler.postDelayed({ rotateChunk() }, chunkIntervalMs)
                }
                latch.countDown()
            }
        }
        latch.await()
        errRef.get()?.let { throw it }
    }

    private fun makeChunk(): PendingChunk {
        val seq = seqNum.incrementAndGet()
        val file = File(chunkDir, "chunk-%03d.mp4".format(seq))
        val bundle = ChunkEncoderBundle(
            outputFile = file,
            videoConfig = videoConfig,
            audioConfig = audioConfig,
            orientationHintDegrees = orientationHintDegrees,
            // (Blue MED-3 fix, 2026-05-19) — wire the
            // encoder drain thread to the recorder's H.264 fallback
            // path. The bundle propagates this through to the
            // [HevcMediaCodecEncoder]. See [handleVideoCodecError] for
            // the swap orchestration + the `hevcFallbackAttempted`
            // one-shot guard.
            onCodecError = ::handleVideoCodecError,
        )
        val surface = bundle.createVideoInputSurface()
        return PendingChunk(bundle, seq, file, surface)
    }

    /**
     * Runtime HEVC→H.264 fallback orchestrator. Invoked from the HEVC drain
     * thread when MediaCodec emits a
     * [android.media.MediaCodec.CodecException] (covered by the dispatcher in
     * [HevcMediaCodecEncoder.drainLoop]).
     *
     * Why this path exists : the H2-B.6 pre-emptive fallback only catches
     * devices where HEVC is *absent* at codec-list query time. Devices where
     * the HEVC encoder is *listed but flaky at runtime* — some older Mediatek
     * Helio P/G chipsets, some Samsung A-series with stale C2 vendor blobs —
     * silently corrupt or stall mid-stream instead. The field rate is low
     * (~0 % in dogfooding on Seeker and OnePlus 13 as of 2026-05-19), but
     * unhandled the cost is a whole témoignage : every subsequent chunk fails
     * the same way, the queue fills with 0-byte MP4s, and the operator only
     * discovers there is no recorded video at archive playback. Handled, the
     * recorder falls back after the first failed chunk and the operator keeps
     * a usable recording, at the cost of one forfeited chunk + ~500 ms of
     * transition (same shape as an adaptive quality swap).
     *
     * Runs on the encoder's drain thread and must not block, hence the
     * one-shot worker thread that carries the swap. That thread is
     * deliberately NOT a `rotateHandler.post` : [swapVideoConfig] posts to
     * rotateHandler itself and then blocks on a CountDownLatch, so calling it
     * from rotateHandler would leave it waiting on its own thread — deadlock.
     * The swap repoints the GL output surface in place (no rebuild), tears
     * down the broken bundle and re-arms the rotation cadence.
     *
     * Three exits come before it. Two of them propagate to the outer [onError]
     * because there is no third codec to try : a fallback already attempted
     * (the H.264 encoder threw as well, the recorder is wedged), or a current
     * mime that is no longer `video/hevc`. The third one is silent by design :
     * a concurrent drain thread has already claimed the one-shot via CAS (the
     * N3 guard), so this call returns without [onError] — the swap it would
     * have started is already under way.
     * (Phase H2-B.17, Blue MED-3 fix, 2026-05-19.)
     */
    private fun handleVideoCodecError(e: android.media.MediaCodec.CodecException) {
        val currentMime = videoConfig.mime
        Timber.tag("StreamMetrics").w(
            "hevcCodecError mime=%s diag=%s recoverable=%b transient=%b attemptedFallback=%b",
            currentMime,
            e.diagnosticInfo,
            try { e.isRecoverable } catch (_: Throwable) { false },
            try { e.isTransient } catch (_: Throwable) { false },
            hevcFallbackAttempted.get(),
        )
        if (hevcFallbackAttempted.get()) {
            Timber.e(e, "Phase H2-B.17: H.264 fallback also failed, surfacing to outer onError")
            try { onError(e) } catch (cb: Exception) {
                Timber.w(cb, "outer onError callback threw")
            }
            return
        }
        if (currentMime != "video/hevc") {
            // Either we're already on H.264 (shouldn't happen — see
            // hevcFallbackAttempted guard, but defensive) or some
            // future mime was wired in. No further fallback exists.
            Timber.e(
                e,
                "Phase H2-B.17: CodecException on non-HEVC mime=%s, surfacing to outer onError",
                currentMime,
            )
            try { onError(e) } catch (cb: Exception) {
                Timber.w(cb, "outer onError callback threw")
            }
            return
        }
        // N3: claim the one-shot fallback atomically. If a concurrent drain
        // thread already claimed it, don't launch a second swap.
        if (!hevcFallbackAttempted.compareAndSet(false, true)) {
            Timber.d("Phase H2-B.17: H.264 fallback already claimed concurrently — skip")
            return
        }
        // Compute the H.264 fallback config. Same dims/fps/keyframe
        // interval, same bitrate. H.264 is universally supported on
        // every Android device (mandatory for video playback in the
        // CTS suite since API 16), so the fallback can't itself fail
        // the codec-pickup step.
        val fallbackConfig = videoConfig.copy(mime = "video/avc")
        Timber.tag("StreamMetrics").i(
            "hevcFallbackScheduled fromMime=%s toMime=%s w=%d h=%d kbps=%d",
            currentMime, fallbackConfig.mime,
            fallbackConfig.widthPx, fallbackConfig.heightPx,
            fallbackConfig.bitrateBps / 1000,
        )
        // Kick off the swap on a fresh daemon thread,
        // NOT via rotateHandler.post. swapVideoConfig() internally
        // posts to rotateHandler and blocks on a CountDownLatch ; if
        // we called it from rotateHandler ourselves, the inner post
        // would queue behind us → deadlock waiting for our own thread.
        // The drain thread (our caller) must also not block here, so
        // we spin a one-shot worker. Same shape as a manual
        // `swapVideoConfig` from the app side.
        Thread({
            if (!running.get()) {
                Timber.d("Phase H2-B.17: recorder stopped before fallback ran, skip")
                return@Thread
            }
            try {
                swapVideoConfig(fallbackConfig)
            } catch (swapEx: Exception) {
                Timber.e(swapEx, "Phase H2-B.17: H.264 fallback swap threw — surfacing to outer onError")
                try { onError(swapEx) } catch (cb: Exception) {
                    Timber.w(cb, "outer onError callback threw")
                }
            }
        }, "hevc-fallback-swap").apply { isDaemon = true; start() }
    }

    private fun preallocateNext() {
        if (!running.get()) return
        if (preallocatedNext != null) return // idempotent
        try {
            val pc = makeChunk()
            preallocatedNext = pc
            Timber.tag("StreamMetrics").i("preallocateNext seq=%d", pc.seq)
        } catch (e: Exception) {
            Timber.e(e, "preallocateNext failed")
            onError(e)
        }
    }

    private fun rotateChunk() {
        if (!running.get()) return
        val old = currentChunk ?: return
        val next = preallocatedNext ?: run {
            // Preallocation didn't run (e.g. preallocLeadMs too tight or
            // exception). Allocate synchronously — costs ~30-50 ms.
            Timber.w("rotateChunk : preallocated missing, allocating synchronously")
            try {
                makeChunk()
            } catch (e: Exception) {
                // Can't build `next`; `old` keeps recording. Record the failure
                // and re-arm the cadence so a later tick retries (mirrors the main
                // finally), then bail — never freeze.
                Timber.e(e, "rotateChunk : synchronous makeChunk failed")
                onRotationFailure(old, null, e)
                if (running.get() && !escalated) {
                    rotateHandler.postDelayed({ rotateChunk() }, chunkIntervalMs)
                }
                return
            }
        }

        val rotateStartNs = System.nanoTime()
        try {
            // 1. Boot the new bundle (codecs configured during makeChunk(),
            //    here we just start them — ~5 ms).
            next.bundle.start()
            // 2. Swap the PCM sink atomically. From this point on, every
            //    AudioRecord.read() block goes to the new AAC session
            //    instead of the old one.
            pcmThread?.setSink(next.bundle.audioEncoder)
            // 3. Tell the old AAC session to flush + exit. Its drain
            //    thread will close the audio track once it sees EOS.
            old.bundle.audioEncoder?.signalEos()
            // 4. Swap the GL output surface — the next camera frame lands
            //    on the new HEVC encoder's Surface, not the old one.
            //    Blocks until the swap is complete on the GL thread. Same
            //    dims (a rotation keeps the resolution; only swapVideoConfig
            //    passes new dims).
            glPipeline.setOutputSurface(
                next.inputSurface, videoConfig.widthPx, videoConfig.heightPx
            )

            // 5. Bookkeep. The cadence is re-armed in `finally` (never frozen).
            currentChunk = next
            preallocatedNext = null
            consecutiveRotationFailures = 0

            val rotateElapsedMs = (System.nanoTime() - rotateStartNs) / 1_000_000L
            Timber.tag("StreamMetrics").i(
                "chunkRotate oldSeq=%d newSeq=%d rotateMs=%d",
                old.seq, next.seq, rotateElapsedMs
            )

            // 6. Drain old bundle in background. signalEndOfInputStream
            //    on the old video encoder is done by bundle.stop(); its
            //    drain thread sees EOS and exits.
            Thread({
                try {
                    old.bundle.stop()
                } catch (e: Exception) {
                    Timber.w(e, "old bundle.stop failed seq=%d", old.seq)
                }
                Timber.tag("StreamMetrics").i(
                    "chunkReady seq=%d sizeBytes=%d",
                    old.seq, old.file.length()
                )
                try {
                    onChunkReady(old.file, old.seq)
                } catch (e: Exception) {
                    Timber.w(e, "onChunkReady cb failed seq=%d", old.seq)
                }
            }, "RollingChunkDrain-${old.seq}").start()
        } catch (e: Exception) {
            // N1/#2: forfeit the broken `next`, keep `old` recording (it is
            // delivered by the retry's success or the backstop's clean stop),
            // count the failure, and escalate past MAX_ROTATION_FAILURES.
            Timber.e(e, "rotateChunk failed")
            onRotationFailure(old, next, e)
        } finally {
            // #2: re-arm the rotation cadence in ALL cases so a single throw can
            // never freeze it (which would strand `old` growing in the clear). On
            // success this is the normal next cycle; on failure it retries a fresh
            // rotation with `old` still current — unless the backstop escalated.
            if (running.get() && !escalated) {
                rotateHandler.postDelayed({ preallocateNext() }, chunkIntervalMs - preallocLeadMs)
                rotateHandler.postDelayed({ rotateChunk() }, chunkIntervalMs)
            }
        }
    }

    /**
     * Fail-closed recovery from a rotation/swap failure (N1/#2). Forfeits the
     * broken [next] bundle so the retry rebuilds fresh, keeps [old] recording
     * (bounded — delivered by the next successful rotation), counts the failure,
     * and past [MAX_ROTATION_FAILURES] escalates an unrecoverable capture so the
     * service stops cleanly (finalizing+encrypting [old]) rather than let it grow
     * unbounded in the clear. Runs on the rotate thread.
     */
    private fun onRotationFailure(old: PendingChunk, next: PendingChunk?, e: Exception) {
        try { next?.bundle?.stop() } catch (ex: Exception) {
            Timber.w(ex, "onRotationFailure: next.bundle.stop failed")
        }
        preallocatedNext = null
        consecutiveRotationFailures++
        Timber.tag("StreamMetrics").w(
            "rotateChunkRecover fail#%d oldSeq=%d", consecutiveRotationFailures, old.seq
        )
        try { onError(e) } catch (cb: Exception) { Timber.w(cb, "onError callback threw") }
        if (consecutiveRotationFailures >= MAX_ROTATION_FAILURES && !escalated) {
            escalated = true
            Timber.e(
                "rotateChunk: %d consecutive failures — escalating unrecoverable capture",
                consecutiveRotationFailures
            )
            try {
                onError(
                    CaptureUnrecoverableException(
                        "rotation failed ${consecutiveRotationFailures}x: ${e.message}"
                    )
                )
            } catch (cb: Exception) { Timber.w(cb, "onError(escalation) callback threw") }
        }
    }
}

/** Max consecutive rotation failures before the recorder escalates a fail-closed
 *  stop instead of retrying (and letting the clear chunk grow unbounded). */
private const val MAX_ROTATION_FAILURES = 3

/** Signals to the host service that capture cannot recover and must be stopped
 *  cleanly (the in-flight clear chunk is finalized+encrypted via onChunkReady). */
class CaptureUnrecoverableException(message: String) : RuntimeException(message)
