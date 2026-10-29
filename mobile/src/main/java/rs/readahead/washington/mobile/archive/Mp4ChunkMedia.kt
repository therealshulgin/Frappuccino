package rs.readahead.washington.mobile.archive

import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import android.os.Build
import org.stream.crypto.SecureWipe
import timber.log.Timber
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer

/**
 * The Android side of the joined export ([JoinedExportRun.Media]): reads a
 * decrypted chunk with [MediaExtractor] and writes the joined video with
 * [MediaMuxer], sample by sample, without re-encoding. [JoinPlanner] decides
 * what joins and by how much each chunk is shifted; this class only reads and
 * writes.
 *
 * The muxer writes to a private file given by path: `MediaMuxer(FileDescriptor)`
 * needs API 26 and the app supports API 21. The caller copies the finished
 * file out and secure-deletes it.
 *
 * Nothing about the phone is added on purpose: no location, and the
 * orientation hint keeps its default of 0, as in the chunks. Each track is
 * declared from scratch with its MIME, its dimensions or audio layout and its
 * codec configuration, and nothing else from the chunk's own track format.
 * The platform muxer still writes, in any MP4 it produces, the Android
 * version of the phone that exports (`com.android.version`, in a metadata
 * box) and creation and modification times that are those of the export,
 * not of the recording. [finish] clears both in place once the muxer has
 * stopped, before the file is copied out ([Mp4MetadataScrub]): the times
 * are set to 0 and the metadata boxes become `free` boxes of zeros, at the
 * same sizes and places, so no sample moves. A file the scrub does not
 * recognise fails the export rather than leave the app half cleared. What
 * stays: a language code and a handler name on each track, the layout of the
 * file as the exporting phone's muxer writes it, and the size of the cleared
 * metadata box, which depends on the length of that phone's Android version
 * string ([Mp4MetadataScrub] says more). A chunk exported as recorded is not
 * muxed and keeps what its recorder wrote.
 *
 * The samples are plaintext of the testimony. They pass through one heap
 * buffer per video, wiped when the video is finished or abandoned, and when
 * a larger one replaces it. What the platform's extractor and muxer keep in
 * native memory while they work is out of the app's reach.
 *
 * @param scrub clears what the muxer wrote about the export from the
 *   finished private file, in place; throws for a file it cannot clear.
 */
internal class Mp4ChunkMedia(
    private val scrub: (File) -> Unit = Mp4MetadataScrub::scrub,
) : JoinedExportRun.Media<Mp4ChunkMedia.Video> {

    /** A joined video being written to the private [file]. [videoTrack] and
     *  [audioTrack] are the muxer's track indices, -1 for a track the video
     *  does not have. */
    class Video internal constructor(
        internal val muxer: MediaMuxer,
        internal val file: File,
        internal val videoTrack: Int,
        internal val audioTrack: Int,
    ) {
        internal val clock = PartClock()
        internal var buffer: ByteBuffer = ByteBuffer.allocate(INITIAL_BUFFER_BYTES)

        internal fun wipeBuffer() {
            SecureWipe.wipe(buffer.array())
        }
    }

    /** The extractor's indices of the video and the audio track, -1 when
     *  absent. */
    private class Layout(val video: Int, val audio: Int)

    override fun probe(chunk: File): ChunkProbe {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(chunk.path)
            val layout = layoutOf(extractor) ?: return ChunkProbe.UNREADABLE
            val videoTimes = TrackTimes.Builder()
            val audioTimes = TrackTimes.Builder()
            select(extractor, layout)
            while (true) {
                val track = extractor.sampleTrackIndex
                if (track < 0) break
                val sync = extractor.sampleFlags and MediaExtractor.SAMPLE_FLAG_SYNC != 0
                when (track) {
                    layout.video -> videoTimes.add(extractor.sampleTime, sync)
                    layout.audio -> audioTimes.add(extractor.sampleTime, sync)
                }
                if (!extractor.advance()) break
            }
            return ChunkProbe(
                readable = true,
                video = if (layout.video >= 0) {
                    ProbedTrack(videoFormat(extractor.getTrackFormat(layout.video)), videoTimes.build())
                } else {
                    null
                },
                audio = if (layout.audio >= 0) {
                    ProbedTrack(audioFormat(extractor.getTrackFormat(layout.audio)), audioTimes.build())
                } else {
                    null
                },
            )
        } catch (e: Exception) {
            // Not an MP4 the extractor can read: the chunk is exported as
            // recorded. The exception is not logged: its message may name
            // the private file.
            Timber.w("Mp4ChunkMedia: chunk not readable for a join, exported as recorded")
            return ChunkProbe.UNREADABLE
        } finally {
            extractor.release()
        }
    }

    override fun open(file: File, first: ChunkProbe): Video {
        // The planner never joins a codec this muxer does not write. Checked
        // again here because the failure differs: an exception fails the
        // export and its cleanup runs, while a platform muxer older than
        // Android 7.0, handed HEVC, may fail natively instead and take the
        // process down before any cleanup.
        for (track in listOfNotNull(first.video, first.audio)) {
            if (!JoinPlanner.muxerWrites(track.format.mime, Build.VERSION.SDK_INT)) {
                throw IOException("codec not written by this phone's muxer")
            }
        }
        val muxer = MediaMuxer(file.path, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        try {
            val videoTrack = first.video?.let { muxer.addTrack(toMediaFormat(it.format, video = true)) } ?: -1
            val audioTrack = first.audio?.let { muxer.addTrack(toMediaFormat(it.format, video = false)) } ?: -1
            muxer.start()
            return Video(muxer, file, videoTrack, audioTrack)
        } catch (e: Exception) {
            releaseQuietly(muxer)
            throw e
        }
    }

    override fun append(video: Video, chunk: File, offsetUs: Long) {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(chunk.path)
            val layout = layoutOf(extractor) ?: throw IOException("chunk no longer readable")
            select(extractor, layout)
            val info = MediaCodec.BufferInfo()
            while (true) {
                val track = extractor.sampleTrackIndex
                if (track < 0) break
                val isVideo = track == layout.video
                val muxerTrack = if (isVideo) video.videoTrack else video.audioTrack
                if (muxerTrack < 0) throw IOException("track missing from the video")
                val size = readSample(video, extractor)
                val timeUs = extractor.sampleTime + offsetUs
                // The planner checked the order before this chunk was placed;
                // a sample out of order now means the file is not the one it
                // read, and the export stops rather than write it.
                if (!video.clock.admit(isVideo, timeUs)) throw IOException("sample out of order")
                val sync = extractor.sampleFlags and MediaExtractor.SAMPLE_FLAG_SYNC != 0
                info.set(0, size, timeUs, if (sync) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0)
                video.muxer.writeSampleData(muxerTrack, video.buffer, info)
                if (!extractor.advance()) break
            }
        } finally {
            extractor.release()
        }
    }

    override fun finish(video: Video) {
        try {
            video.muxer.stop()
        } finally {
            releaseQuietly(video.muxer)
            video.wipeBuffer()
        }
        // Only after stop(): the muxer writes the movie box, and with it the
        // dates and its metadata, as it finishes the file.
        scrub(video.file)
    }

    override fun abandon(video: Video) {
        try {
            video.muxer.stop()
        } catch (_: Exception) {
            // A video abandoned half-way may not stop cleanly; its file is
            // secure-deleted by the caller either way.
        }
        releaseQuietly(video.muxer)
        video.wipeBuffer()
    }

    /** Read the current sample into the video's buffer, growing it when the
     *  sample does not fit; returns the sample's size. */
    private fun readSample(video: Video, extractor: MediaExtractor): Int {
        while (true) {
            val buffer = video.buffer
            buffer.clear()
            // A buffer too small makes the read throw, without consuming the
            // sample: it is read again once the buffer is larger.
            val size = try {
                extractor.readSampleData(buffer, 0)
            } catch (e: IllegalArgumentException) {
                TOO_SMALL
            }
            if (size >= 0) {
                buffer.position(0)
                buffer.limit(size)
                return size
            }
            if (size != TOO_SMALL) throw IOException("sample not readable")
            if (buffer.capacity() >= MAX_BUFFER_BYTES) throw IOException("sample too large")
            video.wipeBuffer()
            video.buffer = ByteBuffer.allocate(minOf(buffer.capacity() * 2, MAX_BUFFER_BYTES))
        }
    }

    private fun releaseQuietly(muxer: MediaMuxer) {
        try {
            muxer.release()
        } catch (_: Exception) {
            // release() stops a started muxer first, which can throw again
            // after a failed stop; nothing more can be done with it.
        }
    }

    companion object {
        private const val INITIAL_BUFFER_BYTES = 1024 * 1024
        private const val MAX_BUFFER_BYTES = 64 * 1024 * 1024
        private const val TOO_SMALL = -2

        /** The video and audio tracks of the extractor's file, or null when
         *  it holds anything else than at most one of each, or neither. */
        private fun layoutOf(extractor: MediaExtractor): Layout? {
            var video = -1
            var audio = -1
            for (i in 0 until extractor.trackCount) {
                val mime = extractor.getTrackFormat(i).getString(MediaFormat.KEY_MIME).orEmpty()
                when {
                    mime.startsWith("video/") && video < 0 -> video = i
                    mime.startsWith("audio/") && audio < 0 -> audio = i
                    else -> return null
                }
            }
            return if (video < 0 && audio < 0) null else Layout(video, audio)
        }

        private fun select(extractor: MediaExtractor, layout: Layout) {
            if (layout.video >= 0) extractor.selectTrack(layout.video)
            if (layout.audio >= 0) extractor.selectTrack(layout.audio)
        }

        private fun videoFormat(f: MediaFormat) = TrackFormat(
            mime = f.getString(MediaFormat.KEY_MIME).orEmpty(),
            csd = csdOf(f),
            width = intOf(f, MediaFormat.KEY_WIDTH),
            height = intOf(f, MediaFormat.KEY_HEIGHT),
        )

        private fun audioFormat(f: MediaFormat) = TrackFormat(
            mime = f.getString(MediaFormat.KEY_MIME).orEmpty(),
            csd = csdOf(f),
            sampleRate = intOf(f, MediaFormat.KEY_SAMPLE_RATE),
            channels = intOf(f, MediaFormat.KEY_CHANNEL_COUNT),
        )

        private fun intOf(f: MediaFormat, key: String): Int = if (f.containsKey(key)) f.getInteger(key) else 0

        /** The codec configuration buffers `csd-0`, `csd-1`, ... in order. */
        private fun csdOf(f: MediaFormat): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            while (true) {
                val buffer = f.getByteBuffer("csd-${out.size}") ?: break
                val view = buffer.duplicate()
                out.add(ByteArray(view.remaining()).also { view.get(it) })
            }
            return out
        }

        /** The muxer's track format for [format]: only what the track needs
         *  to be decoded. */
        private fun toMediaFormat(format: TrackFormat, video: Boolean): MediaFormat {
            val f = if (video) {
                MediaFormat.createVideoFormat(format.mime, format.width, format.height)
            } else {
                MediaFormat.createAudioFormat(format.mime, format.sampleRate, format.channels)
            }
            format.csd.forEachIndexed { i, bytes -> f.setByteBuffer("csd-$i", ByteBuffer.wrap(bytes)) }
            return f
        }
    }
}
