package org.stream.crypto.capture

import android.annotation.SuppressLint
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.SystemClock
import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Continuous PCM capture, decoupled from the AAC encoder. Owns the
 * [AudioRecord], reads PCM frames in a tight loop, and pushes each
 * (bytes, length, ptsNs) tuple to the currently registered [PcmSink].
 *
 * The sink reference is atomic and can be swapped at any time without
 * pausing capture. That is not an elegance, it is the mechanism that
 * makes chunk rotation lossless on the audio side : the rolling recorder
 * points the sink at a fresh [AacEncoderSession] when it wants to cut a
 * new chunk, and PCM samples never stop flowing — no AudioRecord
 * start/stop hole at each cut.
 *
 * Each buffer is tagged with the wall-clock of its FIRST sample, in
 * `CLOCK_BOOTTIME` nanoseconds, the same clock domain as
 * `SurfaceTexture.timestamp` from CameraX. That shared domain is the
 * audio/video sync anchor of the whole pipeline.
 *
 * No EOS is ever sent automatically — neither by [setSink] when it
 * replaces a sink, nor by [stop]. The caller owes the outgoing sink its
 * EOS, and the order matters. Swapping to another sink loses nothing,
 * since capture never stops and the frames go to the new sink. Detaching
 * with `setSink(null)` is the destructive move: the read loop's
 * `sinkRef.get()?.onPcm(...)` simply discards the read when the sink is
 * null, with no log and no exception. So EOS the outgoing sink and let it
 * drain BEFORE detaching it — `RollingChunkRecorder.stop` documents what
 * the reverse order used to cost.
 *
 * Requires the `RECORD_AUDIO` runtime permission ; [start] carries a
 * `@SuppressLint("MissingPermission")`, so nothing here will remind you.
 *
 * (Phase H2-B.4, 2026-05-16.)
 */
class PcmCaptureThread(
    private val sampleRate: Int = 48_000,
    private val channelCount: Int = 1,
) {
    private val running = AtomicBoolean(false)
    private val sinkRef = AtomicReference<PcmSink?>(null)
    private var audioRecord: AudioRecord? = null
    private var thread: Thread? = null
    private var bufferSize: Int = 0

    init {
        require(channelCount == 1 || channelCount == 2) { "Bad channelCount $channelCount" }
        require(sampleRate in 8_000..96_000) { "Bad sampleRate $sampleRate" }
    }

    /**
     * Replaces the current sink atomically. The previous sink (if any)
     * stops receiving PCM frames from the very next read; the new sink
     * starts receiving them immediately. Pass `null` to detach (e.g.
     * during teardown).
     */
    fun setSink(sink: PcmSink?) {
        sinkRef.set(sink)
    }

    @SuppressLint("MissingPermission")
    fun start() {
        check(!running.get()) { "Already started" }

        val channelConfig = if (channelCount == 1) {
            AudioFormat.CHANNEL_IN_MONO
        } else {
            AudioFormat.CHANNEL_IN_STEREO
        }
        val pcm = AudioFormat.ENCODING_PCM_16BIT
        val minBuf = AudioRecord.getMinBufferSize(sampleRate, channelConfig, pcm)
        require(minBuf > 0) { "AudioRecord.getMinBufferSize=$minBuf (unsupported config?)" }
        bufferSize = minBuf * 2

        val ar = AudioRecord(
            MediaRecorder.AudioSource.VOICE_RECOGNITION,
            sampleRate,
            channelConfig,
            pcm,
            bufferSize,
        )
        check(ar.state == AudioRecord.STATE_INITIALIZED) {
            "AudioRecord init failed (state=${ar.state})"
        }
        audioRecord = ar

        ar.startRecording()
        running.set(true)

        thread = Thread({ runLoop() }, "PcmCaptureThread").apply {
            isDaemon = true
            start()
        }
        Timber.tag("StreamMetrics").i(
            "pcmCaptureStart sr=%d ch=%d bufSize=%d",
            sampleRate, channelCount, bufferSize
        )
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        try {
            thread?.join(2000)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        try { audioRecord?.stop() } catch (e: Exception) {
            Timber.w(e, "audioRecord.stop failed")
        }
        try { audioRecord?.release() } catch (e: Exception) {
            Timber.w(e, "audioRecord.release failed")
        }
        audioRecord = null
        sinkRef.set(null)
        Timber.tag("StreamMetrics").i("pcmCaptureStop done")
    }

    private fun runLoop() {
        val ar = audioRecord ?: return
        val bytesPerFrame = 2 * channelCount
        val readBuf = ByteArray(bufferSize.coerceAtMost(8192))

        while (running.get()) {
            val n = try {
                ar.read(readBuf, 0, readBuf.size)
            } catch (e: Exception) {
                Timber.w(e, "AudioRecord.read threw")
                break
            }
            // Wall-clock right after read() returns approximates the
            // wall-clock of the *last* sample in the buffer; subtract
            // the buffer duration to get the *first* sample's PTS in
            // `CLOCK_BOOTTIME` nanos — same domain as the camera-side
            // SurfaceTexture timestamps.
            val nowNs = SystemClock.elapsedRealtimeNanos()
            if (n <= 0) {
                if (n < 0) Timber.w("AudioRecord.read returned %d", n)
                continue
            }
            val framesInBuffer = (n / bytesPerFrame).toLong()
            val bufferDurationNs = framesInBuffer * 1_000_000_000L / sampleRate
            val firstSampleNs = nowNs - bufferDurationNs
            // Sink consumes the buffer synchronously via
            // MediaCodec.queueInputBuffer (which copies into the codec's
            // own buffer) — safe to reuse readBuf on the next loop.
            sinkRef.get()?.onPcm(readBuf, 0, n, firstSampleNs)
        }
    }
}

/**
 * Consumer of PCM frames coming out of [PcmCaptureThread]. Implementations
 * MUST consume the buffer synchronously (copy out anything they need
 * before returning) — the producer reuses the same backing array on
 * the next loop iteration.
 */
interface PcmSink {
    /**
     * Receive one PCM buffer.
     *
     * @param buf backing byte array. Do NOT retain a reference; copy
     *   anything needed before returning.
     * @param offset start offset within [buf].
     * @param length number of bytes to consume from [buf].
     * @param ptsBootNs wall-clock of the first sample of this buffer,
     *   in `CLOCK_BOOTTIME` nanoseconds.
     */
    fun onPcm(buf: ByteArray, offset: Int, length: Int, ptsBootNs: Long)

    /**
     * Signal end-of-stream. The implementation is expected to flush
     * its encoder and release resources. After this returns, no more
     * [onPcm] calls will happen on this sink.
     */
    fun signalEos()
}
