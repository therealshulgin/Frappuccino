package org.stream.crypto.capture

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.MediaFormat
import android.view.Surface
import timber.log.Timber
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Standalone HEVC/H.264 encoder driven by a camera-fed [Surface].
 *
 * The reason this class exists at all: CameraX's
 * [androidx.camera.video.Recorder] does not expose codec selection, and
 * it treats `setTargetVideoEncodingBitRate` as a soft hint the codec is
 * free to ignore (confirmed empirically 2026-05-16 across the Mediatek
 * Seeker and the Snapdragon 8 Elite OnePlus 13). Going back to CameraX to
 * "simplify" would take HEVC and bitrate control with it, and with them
 * the whole adaptive quality ladder (VBR/CBR, upload backlog).
 * MediaCodec honours the requested bitrate far more reliably —
 * typically within ±10 %.
 *
 * This encoder does NOT own a `MediaMuxer`. It delegates track-add and
 * sample-write to the [ChunkEncoderBundle.MuxerSink] it is constructed
 * with, so audio and video can share a single MP4 file; that sink also
 * handles the `muxer.start()` synchronization and the shared A/V
 * timestamp anchor. [stop] therefore releases the codec and the input
 * Surface but never closes the muxer — the bundle does that, once both
 * encoders have stopped.
 *
 * Call order is [createInputSurface] → [start] → [stop].
 * `createInputSurface` returns the Surface the caller hands to the GL
 * wedge, which renders camera frames onto it; nothing reaches the sink
 * before [start] boots the drain thread.
 *
 * Two capability assumptions: `video/hevc` is supported on virtually
 * every Android SoC since ~2018, and where it is not, the caller
 * re-constructs with mime = "video/avc" (see [pickBestVideoMime]) ; and
 * `COLOR_FormatSurface` is the canonical cross-OEM input path, which is
 * what spares us manual YUV420 plumbing.
 *
 * @param mime "video/hevc" (HEVC/H.265) or "video/avc" (H.264 fallback).
 * @param frameRate target capture frame rate, used to schedule the
 *   keyframe interval; the actual fps is governed by the camera feeding
 *   the input Surface.
 *
 * The muxer moved out to the bundle in H2-B.2.
 */
class HevcMediaCodecEncoder(
    private val sink: ChunkEncoderBundle.MuxerSink,
    private val mime: String,
    private val widthPx: Int,
    private val heightPx: Int,
    private val bitrateBps: Int,
    private val frameRate: Int = 30,
    /**
     * Keyframe (IDR) interval in seconds. Smaller = more seekable
     * but inflates bitrate noticeably (each IDR is ~10-30× the size
     * of an inter-frame at the same resolution).
     *
     * In single-chunk tests this defaults to 1 s for fine-grained
     * seeking. In rolling chunk mode the caller should pass
     * `chunkIntervalSec` so that each chunk naturally contains
     * exactly one IDR (the new encoder always emits an IDR for its
     * first frame, and the next scheduled IDR falls outside the
     * chunk window) — measured ~30 % bitrate reduction at 720p
     * 5 s chunks on Seeker Mediatek (2026-05-16).
     */
    private val keyframeIntervalSec: Int = 1,
    /**
     * Rate-control mode (Phase H2-B adaptive, 2026-05-17). VBR default
     * preserves visual quality ; CBR caps bitrate hard. The
     * [AdaptiveQualityManager] toggles this based on upload backlog —
     * see [ChunkEncoderBundle.BitrateMode] for trade-offs.
     */
    private val bitrateMode: ChunkEncoderBundle.BitrateMode =
        ChunkEncoderBundle.BitrateMode.VBR,
    /**
     * Runtime codec-error callback, invoked when MediaCodec emits a
     * [MediaCodec.CodecException] (transient hardware encoder failure,
     * input format rejection mid-stream, etc.). This is the recorder's
     * hook to schedule an HEVC→H.264 fallback swap.
     *
     * Three invariants, none of them visible from the signature :
     *   - It runs ON the drain thread, so the implementer must not block
     *     on anything that needs that thread. Calling [stop] synchronously
     *     makes the drain thread join itself: the join burns its full 2 s
     *     timeout, and the whole teardown is late by that much. Post to a
     *     handler instead.
     *   - It fires at most once per encoder lifecycle — the drain loop
     *     exits right after invoking it.
     *   - `null` means errors are logged only, which is the behaviour the
     *     standalone encoder tests and ad-hoc consumers rely on.
     *
     * Added with the H.264 fallback path (H2-B.17, Blue MED-3 fix,
     * 2026-05-19).
     */
    private val onCodecError: ((MediaCodec.CodecException) -> Unit)? = null,
) {
    private var codec: MediaCodec? = null
    private var inputSurface: Surface? = null
    private var trackIndex: Int = -1
    private val running = AtomicBoolean(false)
    private var drainThread: Thread? = null

    /**
     * Resolved encoder bitrate range for diagnostics. Populated at
     * [createInputSurface] time. Useful to log alongside the requested
     * [bitrateBps] when calibrating per-device floors.
     */
    var encoderBitrateRange: android.util.Range<Int>? = null
        private set

    /** Real codec component name (e.g. "c2.qti.hevc.encoder"). */
    var componentName: String? = null
        private set

    init {
        require(mime == "video/hevc" || mime == "video/avc") {
            "Unsupported mime $mime — only video/hevc and video/avc are wired."
        }
        require(widthPx > 0 && heightPx > 0) { "Bad resolution $widthPx×$heightPx" }
        require(bitrateBps in 50_000..50_000_000) { "Bitrate $bitrateBps out of bounds" }
    }

    /**
     * Configures the encoder and returns the Surface the camera pipeline
     * writes its frames into.
     *
     * It throws IllegalStateException for two different reasons. Either
     * no encoder at all — hardware or software — supports [mime] : a
     * software encoder IS accepted here (see [pickEncoder]), the
     * hardware/software sorting happens upstream in [pickBestVideoMime],
     * so this one is rare. Or `configure()` rejects these dimensions and
     * this bitrate, which is the ~5 % residual described in
     * [pickBestVideoMime] and the case you will actually meet.
     *
     * Either way the caller has to act — re-construct with
     * mime = "video/avc", or surface the error to the operator. Nothing
     * downstream turns this throw into an H.264 fallback; [onCodecError]
     * never sees it.
     */
    fun createInputSurface(): Surface {
        check(codec == null) { "createInputSurface called twice" }

        val info = pickEncoder(mime)
            ?: throw IllegalStateException("No encoder for mime=$mime on this device")
        val caps = info.getCapabilitiesForType(mime)
        encoderBitrateRange = caps.videoCapabilities.bitrateRange
        componentName = info.name
        Timber.tag("StreamMetrics").i(
            "hevcEncoderInit mime=%s component=%s bitrateRange=[%d,%d] requestedBps=%d mode=%s",
            mime, info.name,
            encoderBitrateRange?.lower ?: -1, encoderBitrateRange?.upper ?: -1,
            bitrateBps, bitrateMode.name
        )

        val format = MediaFormat.createVideoFormat(mime, widthPx, heightPx).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, bitrateBps)
            // Phase H2-B (adaptive VBR↔CBR, 2026-05-17) — rate-control
            // strategy toggled by [AdaptiveQualityManager] based on
            // upload backlog. VBR default preserves visual quality on
            // good links ; CBR kicks in when chunks pile up so the
            // encoder hard-caps at `bitrateBps` and degrades quality
            // instead of inflating bytes. KEY_BITRATE_MODE is config-
            // time only, so a mode change forces a swapVideoConfig
            // (full encoder rebuild, 1 chunk forfeit).
            val bitrateModeValue = when (bitrateMode) {
                ChunkEncoderBundle.BitrateMode.VBR ->
                    MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR
                ChunkEncoderBundle.BitrateMode.CBR ->
                    MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR
            }
            setInteger(MediaFormat.KEY_BITRATE_MODE, bitrateModeValue)
            setInteger(MediaFormat.KEY_FRAME_RATE, frameRate)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, keyframeIntervalSec)
            // Discourage B-frames : a handful of older Mediatek encoders
            // (Helio G7x-) crash or produce out-of-order timestamps when
            // B-frames are enabled. Latency-mode = no B-frames.
            setInteger(MediaFormat.KEY_LATENCY, 1)
        }

        val c = MediaCodec.createByCodecName(info.name)
        try {
            c.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        } catch (e: Exception) {
            c.release()
            throw IllegalStateException(
                "Encoder configure failed for $mime $widthPx×$heightPx @ $bitrateBps bps", e
            )
        }
        val surface = c.createInputSurface()
        codec = c
        inputSurface = surface
        return surface
    }

    /**
     * Starts the encoder and the background drain thread. The drain
     * thread will, on its first format-changed event, call
     * `sink.onTrackReady(format)` and then push every encoded sample
     * via `sink.writeSample(trackIdx, buf, info)`.
     */
    fun start() {
        val c = codec ?: error("createInputSurface() must be called first")
        check(!running.get()) { "Already started" }

        c.start()
        running.set(true)

        drainThread = Thread({ drainLoop() }, "HevcEncoderDrain").apply {
            isDaemon = true
            // #20 belt-and-suspenders: keep any stray exception on this daemon
            // thread from reaching Android's default handler (which kills the
            // whole process). Log loudly (surfaces the bug, never masks it) —
            // the drain simply stops; the recorder's error path handles recovery.
            setUncaughtExceptionHandler { t, ex ->
                Timber.e(ex, "%s uncaught exception — swallowed to avoid process kill", t.name)
            }
            start()
        }
        Timber.tag("StreamMetrics").i("hevcEncoderStart mime=%s", mime)
    }

    /**
     * Signals end-of-stream, waits for the drain loop to finish, then
     * releases the codec + input Surface. The bundle owns the muxer
     * and is responsible for closing it after both encoders have
     * stopped.
     */
    fun stop() {
        val c = codec ?: return
        if (!running.getAndSet(false)) {
            // Configured (via createInputSurface) but never started —
            // happens when the rolling recorder pre-allocates the next
            // chunk's encoder and then has to discard it (e.g. caller
            // stops mid-window). Release codec + surface so the kernel
            // BufferQueue and the codec's hardware slot are returned.
            try { c.release() } catch (e: Exception) {
                Timber.w(e, "codec.release (not started) failed")
            }
            try { inputSurface?.release() } catch (e: Exception) {
                Timber.w(e, "surface.release (not started) failed")
            }
            codec = null
            inputSurface = null
            return
        }
        try {
            c.signalEndOfInputStream()
        } catch (e: Exception) {
            Timber.w(e, "signalEndOfInputStream failed")
        }
        try {
            drainThread?.join(2000)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        try {
            c.stop()
        } catch (e: Exception) { Timber.w(e, "codec.stop failed") }
        try {
            c.release()
        } catch (e: Exception) { Timber.w(e, "codec.release failed") }
        try {
            inputSurface?.release()
        } catch (e: Exception) { Timber.w(e, "surface.release failed") }
        codec = null
        inputSurface = null
        trackIndex = -1
        Timber.tag("StreamMetrics").i("hevcEncoderStop done")
    }

    /**
     * Output buffer drain loop, on a dedicated daemon thread until
     * end-of-stream has been observed.
     *
     * Do not merge the two catch branches. It is the most tempting
     * cleanup in this file and it kills the fallback: a
     * [MediaCodec.CodecException] is a transient hardware/codec failure
     * we can recover from by swapping to H.264, so it invokes
     * [onCodecError] exactly once and then bails out of the loop, which
     * is how the recorder gets its chance to schedule that swap ; a plain
     * [IllegalStateException] means the codec moved to an error state for
     * less recoverable reasons, and is logged before terminating the
     * drain. Treat them alike and, on a capricious vendor HEVC blob,
     * every following chunk fails the same way — the operator finds out
     * only when playing the archive back.
     *
     * (H2-B.17, Blue MED-3 fix, 2026-05-19.)
     */
    private fun drainLoop() {
        val bufferInfo = MediaCodec.BufferInfo()
        val c = codec ?: return
        var eosSeen = false
        // Guard against firing the callback twice if
        // multiple sequential ops throw CodecException before the loop
        // exits (rare but legal — e.g. dequeue throws, then a follow-up
        // op on a half-dead codec also throws). The recorder's swap
        // path is idempotent in practice but we avoid the spam.
        var codecErrorReported = false
        // WP-F4 (audit 2026-06-28, L-9) — once-per-drain flag so we surface (not
        // silently swallow) the case where the codec hands back read-only output
        // buffers and the plaintext scrub below cannot run. One line per encoder
        // session, not per frame.
        var plaintextScrubUnavailableLogged = false
        while (!eosSeen) {
            val idx = try {
                c.dequeueOutputBuffer(bufferInfo, 10_000) // 10ms timeout
            } catch (e: MediaCodec.CodecException) {
                Timber.w(
                    e,
                    "Phase H2-B.17: CodecException in dequeueOutputBuffer (mime=%s comp=%s) — bail drain",
                    mime, componentName
                )
                if (!codecErrorReported) {
                    codecErrorReported = true
                    try { onCodecError?.invoke(e) } catch (cb: Exception) {
                        Timber.w(cb, "onCodecError callback threw")
                    }
                }
                break
            } catch (e: IllegalStateException) {
                Timber.w(e, "dequeueOutputBuffer threw, stopping drain")
                break
            }
            when {
                idx == MediaCodec.INFO_TRY_AGAIN_LATER -> {
                    // nothing ready — loop until EOS flushes through.
                }
                idx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                    // #20: a second format change (OEM contract violation) must
                    // not throw a bare ISE off this daemon thread (process kill).
                    // Honour the drain's documented ISE contract: log + break.
                    if (trackIndex >= 0) {
                        Timber.w(
                            "HevcEncoder: format changed twice (trackIndex=%d) — stopping drain",
                            trackIndex
                        )
                        break
                    }
                    val format = try {
                        c.outputFormat
                    } catch (e: MediaCodec.CodecException) {
                        Timber.w(e, "Phase H2-B.17: CodecException reading outputFormat")
                        if (!codecErrorReported) {
                            codecErrorReported = true
                            try { onCodecError?.invoke(e) } catch (cb: Exception) {
                                Timber.w(cb, "onCodecError callback threw")
                            }
                        }
                        break
                    }
                    trackIndex = try {
                        sink.onTrackReady(format)
                    } catch (e: IllegalStateException) {
                        Timber.w(e, "HevcEncoder: onTrackReady threw — stopping drain")
                        break
                    }
                    Timber.d(
                        "HevcEncoder: track ready idx=%d format=%s",
                        trackIndex, format
                    )
                }
                idx >= 0 -> {
                    val outBuf: ByteBuffer? = try {
                        c.getOutputBuffer(idx)
                    } catch (e: MediaCodec.CodecException) {
                        Timber.w(e, "Phase H2-B.17: CodecException in getOutputBuffer")
                        if (!codecErrorReported) {
                            codecErrorReported = true
                            try { onCodecError?.invoke(e) } catch (cb: Exception) {
                                Timber.w(cb, "onCodecError callback threw")
                            }
                        }
                        break
                    }
                    // #20: a null output buffer (OEM contract violation) — log +
                    // break instead of `error()` (a bare ISE that, off this daemon
                    // thread, would reach Android's handler and kill the process).
                    if (outBuf == null) {
                        Timber.w("HevcEncoder: getOutputBuffer(%d) returned null — stopping drain", idx)
                        break
                    }
                    if ((bufferInfo.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG) != 0) {
                        // CSD already consumed via getOutputFormat — drop.
                        bufferInfo.size = 0
                    }
                    if (bufferInfo.size > 0 && trackIndex >= 0) {
                        outBuf.position(bufferInfo.offset)
                        outBuf.limit(bufferInfo.offset + bufferInfo.size)
                        sink.writeSample(trackIndex, outBuf, bufferInfo)
                        // The codec output buffer still holds the compressed,
                        // not-yet-encrypted HEVC bitstream we just muxed, and it
                        // goes straight back into the codec's reusable pool. Zero
                        // that region first, so a stale plaintext frame cannot sit
                        // in a recycled buffer awaiting a heap or VRAM dump.
                        //
                        // This achieves less than it looks: getOutputBuffer() is
                        // read-only by the MediaCodec contract, so on a compliant
                        // device the scrub is a no-op and wipe returns false. That
                        // used to be SILENT — we believed the frame was wiped when
                        // it was not — hence the one-line-per-session trace below.
                        // The residual is bounded: the codec overwrites that pool
                        // buffer with the next frame, nothing is written at rest.
                        //
                        // Forensic #3 ; honesty fix WP-F4
                        // (audit 2026-06-28, L-9), residual filed as WP-G.
                        outBuf.position(bufferInfo.offset)
                        outBuf.limit(bufferInfo.offset + bufferInfo.size)
                        val scrubbed = org.stream.crypto.SecureWipe.wipe(outBuf)
                        if (!scrubbed && !plaintextScrubUnavailableLogged) {
                            plaintextScrubUnavailableLogged = true
                            Timber.i(
                                "HevcEncoder: codec output buffer is read-only — in-place plaintext scrub (forensic #3) unavailable on this device; relying on codec pool reuse (WP-F4/WP-G residual)"
                            )
                        }
                    }
                    try {
                        c.releaseOutputBuffer(idx, false)
                    } catch (e: MediaCodec.CodecException) {
                        Timber.w(e, "Phase H2-B.17: CodecException in releaseOutputBuffer")
                        if (!codecErrorReported) {
                            codecErrorReported = true
                            try { onCodecError?.invoke(e) } catch (cb: Exception) {
                                Timber.w(cb, "onCodecError callback threw")
                            }
                        }
                        break
                    }
                    if ((bufferInfo.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
                        eosSeen = true
                    }
                }
                else -> {
                    Timber.v("dequeueOutputBuffer unexpected idx=%d", idx)
                }
            }
        }
    }

    companion object {
        /**
         * Returns the first encoder supporting [mime] whose name is not
         * prefixed `c2.android.` — a name-based proxy for "hardware", the
         * vendor implementations met in the field being `c2.qti.*`,
         * `c2.mtk.*` and `c2.exynos.*` — else any encoder supporting
         * [mime], else null. Note the middle term: when a software encoder
         * is all the device has, it is returned rather than null.
         */
        fun pickEncoder(mime: String): MediaCodecInfo? {
            val list = MediaCodecList(MediaCodecList.REGULAR_CODECS)
            val candidates = list.codecInfos.filter { info ->
                info.isEncoder && info.supportedTypes.any { it.equals(mime, ignoreCase = true) }
            }
            // Hardware encoders first (vendor prefix), then software.
            val hardware = candidates.firstOrNull { !it.name.startsWith("c2.android.") }
            return hardware ?: candidates.firstOrNull()
        }

        /** Is a HEVC encoder present whose name is not `c2.android.*`? */
        fun hasHevcHardwareEncoder(): Boolean {
            val info = pickEncoder("video/hevc") ?: return false
            return !info.name.startsWith("c2.android.")
        }

        /** Same name-based probe as [hasHevcHardwareEncoder], for AV1. */
        fun hasAv1HardwareEncoder(): Boolean {
            val info = pickEncoder("video/av01") ?: return false
            return !info.name.startsWith("c2.android.")
        }

        /**
         * Pre-emptive HEVC → H.264 fallback. Returns `video/hevc` when
         * the device lists a HEVC encoder whose name is not prefixed
         * `c2.android.`, otherwise `video/avc`. That prefix is a proxy
         * for "hardware" — nothing here calls
         * `MediaCodecInfo.isHardwareAccelerated()`. Use it when
         * configuring a [ChunkEncoderBundle.VideoConfig] so the caller
         * doesn't have to know whether the SoC supports HEVC.
         *
         * This is a [MediaCodecList] query at boot, not a `configure()`
         * attempt, so it is a probe and not a guarantee: a device can
         * list HEVC and still fail `configure()` at unusual dimensions or
         * bitrate — an estimated ~5 % of real cases. Nothing retries H.264
         * for those, and that is a known gap rather than a covered case.
         * They come back as the IllegalStateException [createInputSurface]
         * throws on the calling thread: at boot it leaves the recorder's
         * constructor, later it counts as an ordinary rotation failure.
         * [onCodecError], and with it the HEVC→H.264 swap, only ever fires
         * for a [MediaCodec.CodecException] raised on the drain thread.
         * (StreamRecordingService's `buildHevcVideoConfigFor` is already
         * written expecting a runtime fallback that does not exist yet.)
         *
         * The runtime fallback that does exist (H2-B.17) covers the other
         * residual: encoders that configure fine and fail mid-stream.
         *
         * (Phase H2-B.6, 2026-05-16.)
         */
        fun pickBestVideoMime(): String =
            if (hasHevcHardwareEncoder()) "video/hevc" else "video/avc"
    }
}
