package org.stream.crypto.capture

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AAC encoder bound to one chunk's [ChunkEncoderBundle]. It consumes PCM
 * frames through the [PcmSink] contract and pushes encoded AAC samples to
 * the bundle's [ChunkEncoderBundle.MuxerSink].
 *
 * It deliberately does NOT own an [android.media.AudioRecord]. A single
 * [PcmCaptureThread] drives a succession of these sessions back-to-back,
 * one per chunk, without ever stopping audio capture. Giving each session
 * its own AudioRecord would look tidier and would put a start/stop at
 * every chunk boundary — an audible hole at every rotation.
 *
 * The PTS handed to [onPcm] is the wall-clock of the buffer's first
 * sample in `CLOCK_BOOTTIME`, the same clock domain as CameraX's
 * `SurfaceTexture.timestamp` on the video side. That shared domain is the
 * A/V sync anchor of the whole pipeline.
 *
 * Threading : [onPcm] runs on the PcmCaptureThread's thread and the codec
 * drain on a dedicated thread, while [start], [signalEos] and [stop] are
 * called by the orchestrator from any thread. [onPcm], [signalEos] and
 * [stop]'s codec teardown are serialized on [codecLock] so a PCM frame
 * delivered during teardown can never touch a released codec — the
 * orchestrator swaps the PcmSink and stops the old session while the
 * capture loop may still hold the old sink reference. [start] is still
 * expected to happen-before any [onPcm]. What publishes `codec` — a plain
 * non-volatile `var`, written by [start] outside the lock — is the
 * `running` AtomicBoolean: [start] assigns `codec` before
 * `running.set(true)`, and an AtomicBoolean carries the same memory
 * barrier as a volatile, so an [onPcm] that observes `running == true`
 * observes the codec with it. Do not drop the `running.get()` check at the
 * top of [onPcm] on the grounds that [codecLock] covers everything: the
 * lock orders the codec calls, that check is what makes `codec` visible.
 *
 * [stop] releases the codec but does NOT close the muxer — the bundle
 * owns it and closes it once both encoders have stopped. That split is
 * structural rather than a convention waiting to be tidied up: this class
 * never holds a muxer it could close, only the narrow
 * [ChunkEncoderBundle.MuxerSink].
 *
 * (Phase H2-B.4, 2026-05-16 ; codecLock serialization H2-B.19,
 * 2026-05-23.)
 */
class AacEncoderSession(
    private val sink: ChunkEncoderBundle.MuxerSink,
    private val sampleRate: Int = 48_000,
    private val channelCount: Int = 1,
    private val bitrateBps: Int = 96_000,
) : PcmSink {
    private val running = AtomicBoolean(false)
    private var codec: MediaCodec? = null
    private var trackIndex: Int = -1
    private var drainThread: Thread? = null

    // Serializes codec access between the capture thread (onPcm /
    // signalEos) and stop()'s teardown. It looks removable — every method
    // below already null-checks `codec` before touching it — and it is
    // not. Without it, PcmCaptureThread.runLoop can deliver a PCM frame
    // to onPcm on a session whose codec.stop()/release() is concurrently
    // in flight: the orchestrator swaps the PcmSink + stops the old
    // session while runLoop has already captured the old sink reference.
    // Result, seen 3× in field 2026-05-20/22 (all with
    // AacEncoderSession.onPcm on top of the stack): IllegalStateException
    // "Invalid to call during stop()" on the JVM, and a SIGSEGV
    // (use-after-free in MediaCodec native) that takes the whole recording
    // process down mid-capture. A Java try/catch can't catch the native
    // segfault, so the only robust fix is to never touch the codec
    // concurrently with its release. (Phase H2-B.19, 2026-05-23.)
    private val codecLock = Any()

    init {
        require(channelCount == 1 || channelCount == 2) { "Bad channelCount $channelCount" }
        require(sampleRate in 8_000..96_000) { "Bad sampleRate $sampleRate" }
        require(bitrateBps in 16_000..256_000) { "Bad bitrateBps $bitrateBps" }
    }

    fun start() {
        check(!running.get()) { "Already started" }

        val mime = MediaFormat.MIMETYPE_AUDIO_AAC
        val fmt = MediaFormat.createAudioFormat(mime, sampleRate, channelCount).apply {
            setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
            setInteger(MediaFormat.KEY_BIT_RATE, bitrateBps)
            setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 16 * 1024)
        }
        val c = MediaCodec.createEncoderByType(mime)
        try {
            c.configure(fmt, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        } catch (e: Exception) {
            c.release()
            throw IllegalStateException(
                "AAC encoder configure failed @ $sampleRate Hz $channelCount ch $bitrateBps bps", e
            )
        }
        codec = c
        c.start()
        running.set(true)

        drainThread = Thread({ drainLoop() }, "AacEncoderDrain").apply {
            isDaemon = true
            // #20 belt-and-suspenders: a stray exception on this daemon thread
            // would otherwise reach Android's default handler and kill the whole
            // process. Log loudly (surfaces the bug) and let the drain stop.
            setUncaughtExceptionHandler { t, ex ->
                Timber.e(ex, "%s uncaught exception — swallowed to avoid process kill", t.name)
            }
            start()
        }
        Timber.tag("StreamMetrics").i(
            "aacSessionStart sr=%d ch=%d bps=%d",
            sampleRate, channelCount, bitrateBps
        )
    }

    override fun onPcm(buf: ByteArray, offset: Int, length: Int, ptsBootNs: Long) {
        // Hold codecLock for the whole codec interaction so stop() can't
        // release the codec from under us. That is where the safety comes
        // from: stop() nulls `codec` under this same lock, and every path
        // below re-checks it. If we grab the lock after stop() began we see
        // running=false, or a null codec, and bail; if we grab it first,
        // stop() blocks until we finish, then releases. Either way the codec
        // is alive throughout.
        //
        // stop() lowers running=false BEFORE taking the lock. That order is
        // not the safety property, but keep it anyway: it spares a whole
        // onPcm from running for nothing during teardown, and it is the
        // idempotence guard against a second stop().
        //
        // getInputBuffer is try/catch-guarded too — it was the exact throw
        // site (AacEncoderSession.kt:96) in field. (Phase H2-B.19.)
        synchronized(codecLock) {
            if (!running.get()) return
            val c = codec ?: return
            val idx = try {
                c.dequeueInputBuffer(10_000L)
            } catch (e: IllegalStateException) {
                Timber.w(e, "aac dequeueInputBuffer threw")
                return
            }
            if (idx < 0) return
            val inBuf = try {
                c.getInputBuffer(idx)
            } catch (e: IllegalStateException) {
                Timber.w(e, "aac getInputBuffer threw")
                return
            } ?: return
            inBuf.clear()
            inBuf.put(buf, offset, length)
            val ptsUs = ptsBootNs / 1000L
            try {
                c.queueInputBuffer(idx, 0, length, ptsUs, 0)
            } catch (e: Exception) {
                Timber.w(e, "aac queueInputBuffer threw")
            }
        }
    }

    override fun signalEos() {
        // Phase H2-B.19 — same codecLock as onPcm: signalEos also feeds
        // an input buffer, so it must not race onPcm (two threads doing
        // dequeue/queueInputBuffer concurrently corrupts MediaCodec
        // state) nor stop()'s release.
        synchronized(codecLock) {
            val c = codec ?: return
            try {
                val idx = c.dequeueInputBuffer(50_000L)
                if (idx >= 0) {
                    c.queueInputBuffer(idx, 0, 0, 0L, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                } else {
                    Timber.w("aac EOS: no input buffer available")
                }
            } catch (e: Exception) {
                Timber.w(e, "aac EOS signal failed")
            }
        }
    }

    /**
     * Joins the drain thread + releases the codec. Caller MUST have
     * delivered an EOS via [signalEos] beforehand, otherwise the drain
     * thread will block on dequeueOutputBuffer until it times out.
     */
    fun stop() {
        if (!running.getAndSet(false)) return
        // running=false is now visible to onPcm. Join the drain thread
        // first (it exits on EOS or its own IllegalStateException). The
        // drain thread does NOT take codecLock, so joining here cannot
        // deadlock against an onPcm that currently holds the lock.
        try { drainThread?.join(2000) } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        // Phase H2-B.19 — release under codecLock so an in-flight onPcm /
        // signalEos on the capture thread finishes before the codec is
        // torn down. Closes the use-after-free that crashed the app in
        // field (IllegalStateException + SIGSEGV at onPcm).
        synchronized(codecLock) {
            try { codec?.stop() } catch (e: Exception) {
                Timber.w(e, "aac codec.stop failed")
            }
            try { codec?.release() } catch (e: Exception) {
                Timber.w(e, "aac codec.release failed")
            }
            codec = null
            trackIndex = -1
        }
        Timber.tag("StreamMetrics").i("aacSessionStop done")
    }

    private fun drainLoop() {
        val c = codec ?: return
        val info = MediaCodec.BufferInfo()
        var eosSeen = false
        while (!eosSeen) {
            val idx = try {
                c.dequeueOutputBuffer(info, 10_000L)
            } catch (e: IllegalStateException) {
                Timber.w(e, "aac dequeueOutputBuffer threw")
                break
            }
            when {
                idx == MediaCodec.INFO_TRY_AGAIN_LATER -> { /* loop */ }
                idx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                    // #20: log + break instead of a bare ISE off this daemon thread.
                    if (trackIndex >= 0) {
                        Timber.w("aac: format changed twice — stopping drain")
                        break
                    }
                    trackIndex = try {
                        sink.onTrackReady(c.outputFormat)
                    } catch (e: IllegalStateException) {
                        Timber.w(e, "aac onTrackReady/outputFormat threw — stopping drain")
                        break
                    }
                    Timber.d("AacSession: track ready idx=%d", trackIndex)
                }
                idx >= 0 -> {
                    try {
                        val outBuf = c.getOutputBuffer(idx)
                        if (outBuf == null) {
                            Timber.w("aac getOutputBuffer null at idx=%d", idx)
                        } else {
                            if ((info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG) != 0) {
                                info.size = 0
                            }
                            if (info.size > 0 && trackIndex >= 0) {
                                outBuf.position(info.offset)
                                outBuf.limit(info.offset + info.size)
                                sink.writeSample(trackIndex, outBuf, info)
                            }
                        }
                        c.releaseOutputBuffer(idx, false)
                        if ((info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
                            eosSeen = true
                        }
                    } catch (e: IllegalStateException) {
                        // #20: getOutputBuffer / writeSample / releaseOutputBuffer
                        // can throw ISE if the codec/muxer moved to an error state —
                        // stop the drain gracefully instead of killing the process.
                        Timber.w(e, "aac drain op threw (idx=%d) — stopping drain", idx)
                        break
                    }
                }
                else -> {
                    Timber.v("aac dequeueOutputBuffer unexpected idx=%d", idx)
                }
            }
        }
    }
}
