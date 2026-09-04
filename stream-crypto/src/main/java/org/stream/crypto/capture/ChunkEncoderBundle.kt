package org.stream.crypto.capture

import android.media.MediaCodec
import android.media.MediaFormat
import android.media.MediaMuxer
import android.view.Surface
import timber.log.Timber
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

/**
 * Owns the [MediaMuxer] and coordinates the video and (optional) audio
 * encoders so that both write into a single output MP4 through the same
 * [MuxerSink].
 *
 * Two ordering rules come from outside this class, and neither is visible
 * in the bodies below :
 *
 *   - `MediaMuxer.start()` must come after ALL tracks have been added.
 *     That is what the pending-track count is for. Start on the first
 *     track that reports its format and you break the other one —
 *     whichever it happens to be, nothing here fixes that order — because
 *     its `addTrack()` then lands after `start()` and throws. Writers that
 *     arrive before the start are unblocked once it fires.
 *   - The caller must stop the GL pipeline BEFORE [stop], otherwise the
 *     encoder Surface is invalidated under a live EGL context
 *     (EGL_BAD_SURFACE) and the capture goes down.
 *
 * The sink also anchors the first presentation timestamp it observes at 0
 * and shifts every later sample of both tracks by that same offset. That
 * single anchor is what keeps two independent encoders in sync — see the
 * note next to `anchorUs` for why it preserves the real audio-vs-video
 * offset rather than correcting it.
 *
 * Pass `audioConfig = null` for video-only output; the calibration grid
 * does, audio adds no signal there.
 *
 * (Phase H2-B.2, 2026-05-16.)
 */
class ChunkEncoderBundle(
    private val outputFile: File,
    private val videoConfig: VideoConfig,
    private val audioConfig: AudioConfig? = null,
    /**
     * Rotation hint written into the MP4 composition matrix
     * (0, 90, 180, or 270 degrees clockwise at playback). Players
     * (VLC, ffmpeg, Android MediaPlayer) honour this to rotate the
     * frame on display — the bytes encoded on disk stay in the
     * sensor's native orientation (typically 1280×720 landscape on
     * Android phones).
     *
     * Leave it at 0. Every call site passes 0 today and that is not an
     * oversight : on the device this was established on — in vivo on the
     * Mediatek Seeker, 2026-05-17, see the "no rotation in MVP" note in
     * [GlVideoPipeline] — the GL pipeline already delivers the frame in
     * the target orientation, so a non-zero hint here would rotate the
     * picture a second time at playback. That is a per-SoC property and
     * not a law: where the camera's transform matrix does not carry the
     * rotation, a non-zero hint here plus an MVP rotation in GL is the fix
     * instead. The reasoning, and the `rotationCrosscheck` log that tells
     * you which of the two a given device needs, live in
     * StreamRecordingService.kt:977-988 — read that output before changing
     * this value.
     *
     * If a device ever does need one, it derives from
     * `CameraCharacteristics.SENSOR_ORIENTATION` minus the current
     * `Display.getRotation()`. (H2-B.4, H2-B.7-bis.)
     */
    private val orientationHintDegrees: Int = 0,
    /**
     * Blue MED-3 fix (2026-05-19) — propagated to
     * [HevcMediaCodecEncoder] so a [android.media.MediaCodec.CodecException]
     * caught on the drain thread reaches the recorder and triggers an
     * HEVC→H.264 fallback swap. See [HevcMediaCodecEncoder.onCodecError]
     * for invocation invariants. `null` (default) preserves the
     * pre-fix log-only behaviour for standalone bundle tests.
     */
    private val onCodecError: ((android.media.MediaCodec.CodecException) -> Unit)? = null,
) {
    init {
        require(orientationHintDegrees in setOf(0, 90, 180, 270)) {
            "orientationHintDegrees must be 0/90/180/270 (got $orientationHintDegrees)"
        }
    }

    /**
     * Encoder rate-control strategy. VBR (default) is quality-preserving :
     * the encoder grows its output when scenes get complex. CBR caps the
     * output hard at `bitrateBps`, padding with stuffing bits on static
     * scenes — which is what you want when the uplink is the bottleneck
     * (cellular, sub-800 kbps).
     *
     * `KEY_BITRATE_MODE` is config-time only on `MediaCodec` : the mode
     * cannot be flipped on a live encoder. That is why
     * [AdaptiveQualityManager] switches mid-stream through a
     * swapVideoConfig call, which is a full encoder rebuild — same cost
     * shape as a resolution swap, 1 chunk forfeit + ~130 ms transition.
     *
     * (Phase H2-B, adaptive VBR↔CBR, 2026-05-17.)
     */
    enum class BitrateMode { VBR, CBR }

    data class VideoConfig(
        val mime: String,
        val widthPx: Int,
        val heightPx: Int,
        val bitrateBps: Int,
        val frameRate: Int = 30,
        /**
         * Keyframe (IDR) interval in seconds passed through to
         * [HevcMediaCodecEncoder]. In rolling-chunk mode, set this
         * to the chunk duration so each chunk naturally contains
         * exactly one IDR (the start-of-encoder IDR). See the
         * encoder class for rationale.
         */
        val keyframeIntervalSec: Int = 1,
        /**
         * Rate-control mode (VBR default). See [BitrateMode] for
         * trade-offs. Wired adaptively to backlog by
         * [AdaptiveQualityManager] : CBR kicks in when chunks pile up,
         * reverts to VBR once the queue drains.
         */
        val bitrateMode: BitrateMode = BitrateMode.VBR,
    )

    data class AudioConfig(
        val sampleRate: Int = 48_000,
        val channelCount: Int = 1,
        val bitrateBps: Int = 96_000,
    )

    /**
     * Sink callback interface implemented by the bundle. Encoders call
     * [onTrackReady] when their output format is available and
     * [writeSample] for each output buffer. The sink owns muxer
     * synchronization + timestamp anchoring.
     */
    interface MuxerSink {
        /** Encoder has its output format. Returns the trackIndex to use. */
        fun onTrackReady(format: MediaFormat): Int

        /** Write one encoded sample. Blocks until `muxer.start()` if needed. */
        fun writeSample(trackIdx: Int, buf: ByteBuffer, info: MediaCodec.BufferInfo)
    }

    private val muxer = MediaMuxer(
        outputFile.absolutePath,
        MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4,
    ).apply {
        // setOrientationHint must be called *before* start() — and
        // before any addTrack(), per the Android docs. We do it here
        // so the MuxerSink's later muxer.start() picks it up.
        if (orientationHintDegrees != 0) {
            setOrientationHint(orientationHintDegrees)
        }
    }
    private val muxerLock = Object()
    private var muxerStarted: Boolean = false
    private val expectedTrackCount: Int = if (audioConfig != null) 2 else 1
    private val pendingTracks = AtomicInteger(expectedTrackCount)
    // Shared presentation-timestamp anchor across both tracks. The
    // video encoder emits `SurfaceTexture.timestamp` (CLOCK_BOOTTIME),
    // and the audio encoder emits `SystemClock.elapsedRealtimeNanos`
    // (also CLOCK_BOOTTIME). One common anchor normalizes both to a
    // shared zero, preserving the *real* audio-vs-video start offset
    // — typically audio fires first by 50-500 ms because the camera
    // HAL takes longer to bind than AudioRecord.startRecording().
    private var anchorUs: Long = -1L
    // Per-chunk A/V start skew tripwire. Logging only, no behaviour
    // change: the recorder already guarantees intra-chunk sync (absolute
    // CLOCK_BOOTTIME PTS on both tracks + the shared anchor above), so
    // this only turns "is the next chunk synced?" into an objective field
    // datum. [anchorTrackIdx] records which track set [anchorUs], so the
    // first sample of the *other* track can be measured against it.
    // A quality swap is the one place samples get dropped, so this is the
    // number to watch right after one: a large magnitude means a desynced
    // chunk, and that is a regression alarm.
    private var anchorTrackIdx: Int = -1
    private var videoTrackIdx: Int = -1
    private var audioTrackIdx: Int = -1
    private var skewLogged: Boolean = false

    private val sink = object : MuxerSink {
        override fun onTrackReady(format: MediaFormat): Int {
            synchronized(muxerLock) {
                val idx = muxer.addTrack(format)
                // Label the track (audio/video) for the chunkStartSkew
                // tripwire in writeSample. Both addTrack calls complete
                // before muxer.start(), so both indices are known before
                // any writeSample gets past the muxerStarted wait.
                when {
                    format.getString(MediaFormat.KEY_MIME).orEmpty()
                        .startsWith("audio/") -> audioTrackIdx = idx
                    format.getString(MediaFormat.KEY_MIME).orEmpty()
                        .startsWith("video/") -> videoTrackIdx = idx
                }
                val remaining = pendingTracks.decrementAndGet()
                if (remaining == 0) {
                    muxer.start()
                    muxerStarted = true
                    muxerLock.notifyAll()
                    Timber.tag("StreamMetrics").i(
                        "muxerStarted out=%s tracks=%d", outputFile.name, expectedTrackCount
                    )
                }
                return idx
            }
        }

        override fun writeSample(
            trackIdx: Int,
            buf: ByteBuffer,
            info: MediaCodec.BufferInfo,
        ) {
            synchronized(muxerLock) {
                // N2: bound the wait for muxer.start(). If the OTHER track never
                // presents its format (e.g. its drain thread died — see #20), then
                // pendingTracks never reaches 0, muxer.start() never fires, and an
                // unbounded wait() here would block this drain thread FOREVER →
                // back-pressure wedges the GL pipeline and the whole capture. Fail
                // closed: drop this sample after the deadline instead of hanging.
                val deadlineNs = System.nanoTime() + MUXER_START_TIMEOUT_MS * 1_000_000L
                while (!muxerStarted) {
                    val remainingMs = (deadlineNs - System.nanoTime()) / 1_000_000L
                    if (remainingMs <= 0L) {
                        Timber.e(
                            "muxer never started within %dms (out=%s) — dropping sample (fail-closed)",
                            MUXER_START_TIMEOUT_MS, outputFile.name
                        )
                        return
                    }
                    try {
                        muxerLock.wait(remainingMs)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return
                    }
                }
                if (anchorUs < 0L) {
                    anchorUs = info.presentationTimeUs
                    anchorTrackIdx = trackIdx
                    Timber.tag("StreamMetrics").i(
                        "muxerAnchor trackIdx=%d anchorUs=%d", trackIdx, anchorUs
                    )
                } else if (!skewLogged && trackIdx != anchorTrackIdx) {
                    // Sync tripwire — first sample of the OTHER
                    // track. (presentationTimeUs - anchorUs) is the real
                    // absolute-time gap between this chunk's first audio
                    // sample and first video frame. ~0 ms = tight lip-sync;
                    // a large magnitude flags a desynced chunk (watch after
                    // a quality swap). Signed: audio leading video = negative.
                    skewLogged = true
                    val audioMinusVideoUs = when (anchorTrackIdx) {
                        videoTrackIdx -> info.presentationTimeUs - anchorUs
                        audioTrackIdx -> anchorUs - info.presentationTimeUs
                        else -> info.presentationTimeUs - anchorUs
                    }
                    Timber.tag("StreamMetrics").i(
                        "chunkStartSkew out=%s audioMinusVideoMs=%d anchorTrack=%d",
                        outputFile.name, audioMinusVideoUs / 1000L, anchorTrackIdx
                    )
                }
                val adjusted = MediaCodec.BufferInfo().apply {
                    set(
                        info.offset,
                        info.size,
                        info.presentationTimeUs - anchorUs,
                        info.flags,
                    )
                }
                try {
                    muxer.writeSampleData(trackIdx, buf, adjusted)
                } catch (e: Exception) {
                    Timber.w(e, "muxer.writeSampleData failed track=%d", trackIdx)
                }
            }
        }
    }

    val videoEncoder = HevcMediaCodecEncoder(
        sink = sink,
        mime = videoConfig.mime,
        widthPx = videoConfig.widthPx,
        heightPx = videoConfig.heightPx,
        bitrateBps = videoConfig.bitrateBps,
        frameRate = videoConfig.frameRate,
        keyframeIntervalSec = videoConfig.keyframeIntervalSec,
        bitrateMode = videoConfig.bitrateMode,
        // Blue MED-3 (2026-05-19) — propagate runtime
        // codec errors up to the recorder so it can swap to H.264.
        onCodecError = onCodecError,
    )

    /**
     * AAC encoder session for this chunk. The bundle does NOT own audio
     * capture : this session is fed PCM frames through the [PcmSink]
     * contract by an externally owned [PcmCaptureThread], and it stays
     * silent until the caller wires it up with
     * `pcmCapture.setSink(bundle.audioEncoder)`.
     *
     * Forget that wiring and the chunk does not merely come out silent, it
     * can be lost whole. With an [AudioConfig] the muxer waits for two
     * tracks : if the AAC encoder never reports an output format — which
     * is what an encoder starved of PCM does — `muxer.start()` never
     * fires, every video sample is dropped at the 3 s fail-closed deadline
     * in `writeSample`, and [stop] then deletes the 0-byte MP4. The video
     * goes with it.
     *
     * The [stop] contract applies either way : send `signalEos()` so the
     * audio drain has an end of stream to exit on. It does also exit on a
     * codec error, and [AacEncoderSession.stop] bounds its join at 2 s,
     * but neither of those is a path you want to rely on.
     */
    val audioEncoder: AacEncoderSession? = audioConfig?.let {
        AacEncoderSession(
            sink = sink,
            sampleRate = it.sampleRate,
            channelCount = it.channelCount,
            bitrateBps = it.bitrateBps,
        )
    }

    /**
     * Returns the Surface obtained from the video encoder's
     * `MediaCodec.createInputSurface()`. Hand it to the GL wedge.
     * Must be called exactly once, before [start].
     */
    fun createVideoInputSurface(): Surface = videoEncoder.createInputSurface()

    /**
     * Starts both encoders + their drain threads. Caller is responsible
     * for routing a [PcmCaptureThread] to [audioEncoder] (typically
     * just before or after this call) — the bundle does NOT own audio
     * capture.
     */
    fun start() {
        videoEncoder.start()
        audioEncoder?.start()
        Timber.tag("StreamMetrics").i(
            "bundleStart out=%s audio=%s", outputFile.name, audioConfig != null
        )
    }

    /**
     * Stops both encoders and closes the muxer. Two preconditions, neither
     * of them checked here nor visible in the body :
     *
     *   1. Stop the GL pipeline first. Otherwise the encoder Surface is
     *      invalidated under a live EGL context (EGL_BAD_SURFACE) and the
     *      capture goes down.
     *   2. Signal EOS to the audio encoder first, typically
     *      `bundle.audioEncoder?.signalEos()` right after detaching the
     *      PcmCaptureThread sink. Without it the audio drain thread has no
     *      end of stream to exit on : the chunk loses its audio tail, and
     *      the teardown falls back on a bounded join before releasing the
     *      codec under a thread that is still running.
     */
    fun stop() {
        videoEncoder.stop()
        audioEncoder?.stop()
        // Capture muxerStarted BEFORE the stop block below resets it : it
        // is how we recognise a preallocated chunk that was discarded
        // without ever writing a sample — the normal outcome of a quality
        // swap — and clean up its output file.
        //
        // The Android fact behind that cleanup : it is the MediaMuxer
        // CONSTRUCTOR that touches the output file on disk, not start().
        // An abandoned bundle therefore leaves a 0-byte MP4 behind, and
        // they pile up swap after swap.
        //
        // Nothing sweeps them on a TTL : OrphanSweepWorker (48 h) only
        // walks filesDir/stream_chunk_queue and only ever finds .strm
        // there. The real net is CaptureScratchCleaner.purgeOrphanChunks,
        // which secure-deletes any orphan .mp4 whatever its size (F-01),
        // at service start, at onDestroy and on panicWipe. The delete
        // below is the first line of that defence, keeping the files from
        // accumulating between two passes of the cleaner. A discarded
        // preallocated chunk never reaches the upload path in any case —
        // not through a size filter, but because onChunkReady is never
        // called for it, so it is never STRM-encrypted.
        // (Phase H2-B.11, 2026-05-18 ; Blue Team B-H3.)
        var wasMuxerStarted = false
        synchronized(muxerLock) {
            wasMuxerStarted = muxerStarted
            if (muxerStarted) {
                try {
                    muxer.stop()
                } catch (e: Exception) {
                    Timber.w(e, "muxer.stop failed")
                }
                muxerStarted = false
            }
            try {
                muxer.release()
            } catch (e: Exception) {
                Timber.w(e, "muxer.release failed")
            }
        }
        // If the muxer never started, the output file is either 0 bytes
        // (no addTrack got far enough) or a few header bytes (rare,
        // depends on MuxerImpl). Scope our delete to length == 0 to be
        // defensive — never delete a partially valid MP4.
        if (!wasMuxerStarted) {
            try {
                if (outputFile.exists() && outputFile.length() == 0L) {
                    val deleted = outputFile.delete()
                    Timber.tag("StreamMetrics").i(
                        "preallocOrphanDeleted out=%s deleted=%b",
                        outputFile.name, deleted
                    )
                }
            } catch (e: Exception) {
                Timber.w(e, "preallocOrphan delete failed for %s", outputFile.name)
            }
        }
        Timber.tag("StreamMetrics").i("bundleStop out=%s", outputFile.name)
    }
}

// N2: max time writeSample blocks waiting for muxer.start() before dropping the
// sample (fail-closed) rather than hanging the drain thread forever. Well above
// the normal sub-second track-format handshake, well below "forever".
private const val MUXER_START_TIMEOUT_MS = 3000L
