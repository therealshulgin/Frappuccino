package rs.readahead.washington.mobile.archive

import java.util.EnumMap
import java.util.TreeSet

/**
 * The format of one track of a chunk, as compared between chunks.
 *
 * [csd] holds the codec configuration buffers (`csd-0`, `csd-1`, ...) in
 * order: the parameter sets of the video codec (`avcC` or `hvcC` in the MP4),
 * the audio specific config of AAC. They describe how the stream is encoded,
 * not what it shows. [width] and [height] are 0 for audio, [sampleRate] and
 * [channels] are 0 for video.
 */
class TrackFormat(
    val mime: String,
    val csd: List<ByteArray>,
    val width: Int = 0,
    val height: Int = 0,
    val sampleRate: Int = 0,
    val channels: Int = 0,
) {
    /** Same MIME, same dimensions or audio layout, and every codec
     *  configuration buffer identical byte for byte. */
    fun sameAs(other: TrackFormat): Boolean =
        mime == other.mime &&
            width == other.width &&
            height == other.height &&
            sampleRate == other.sampleRate &&
            channels == other.channels &&
            csd.size == other.csd.size &&
            csd.indices.all { csd[it].contentEquals(other.csd[it]) }
}

/**
 * The sample times of one track of a chunk, in the order the file stores
 * them (decode order), in microseconds of the chunk's own clock.
 *
 * @property lastDeltaUs the gap between the last two samples, null when the
 *   track holds a single sample.
 * @property startsWithSync the first sample is a sync sample (a key frame).
 */
data class TrackTimes(
    val firstUs: Long,
    val lastUs: Long,
    val count: Int,
    val strictlyIncreasing: Boolean,
    val lastDeltaUs: Long?,
    val startsWithSync: Boolean,
) {
    /** Collects the times of one track while a chunk is read. */
    class Builder {
        private var first = 0L
        private var last = 0L
        private var count = 0
        private var increasing = true
        private var lastDelta: Long? = null
        private var startsWithSync = false

        fun add(timeUs: Long, sync: Boolean) {
            if (count == 0) {
                first = timeUs
                startsWithSync = sync
            } else {
                if (timeUs <= last) increasing = false
                lastDelta = timeUs - last
            }
            last = timeUs
            count++
        }

        /** The times collected, or null when the track held no sample. */
        fun build(): TrackTimes? =
            if (count == 0) null else TrackTimes(first, last, count, increasing, lastDelta, startsWithSync)
    }
}

/** One track of a chunk: its format, and its times (null when the track
 *  holds no sample). */
class ProbedTrack(val format: TrackFormat, val times: TrackTimes?)

/**
 * What one decrypted chunk holds, read before it is written.
 *
 * [readable] is false when the chunk could not be read as an MP4 with at most
 * one video track, at most one audio track and nothing else. Such a chunk is
 * never joined and never dropped: it is exported as recorded, as a video of
 * its own.
 */
class ChunkProbe(val readable: Boolean, val video: ProbedTrack?, val audio: ProbedTrack?) {
    companion object {
        val UNREADABLE = ChunkProbe(readable = false, video = null, audio = null)
    }
}

/** Why a new video starts after the first one. */
enum class Cut {
    /** The seq jumps over a chunk the verification found missing on the
     *  relay ([ExportPlan.Joined.missingSeqs]). */
    MISSING,

    /** The previous chunk was excluded because it does not decrypt. */
    EXCLUDED,

    /**
     * The seq jumps, and no chunk in between is known to be missing. The
     * recorder can skip a number at a change of quality, with no video lost:
     * the chunk it had prepared for the old settings is dropped before it
     * records anything. A chunk lost at capture, or one that is not verified
     * and so not exported, leaves the same jump. Nothing here tells these
     * apart, so the jump still cuts the video, and the wording claims no loss.
     */
    NUMBERING,

    /** The codec, its configuration, the dimensions or the audio format
     *  changed: a change of quality, or a fall-back from HEVC to H.264
     *  part-way through a recording. One file holds one format per track. */
    FORMAT,

    /** The chunk is in a codec the platform muxer of this phone does not
     *  write ([JoinPlanner.muxerWrites]): it is a video of its own, as
     *  recorded. */
    CODEC,

    /** The open video reached [JoinPlanner.MAX_PART_BYTES], or the phone
     *  would not have the free space to copy it out once joined. */
    SIZE,

    /** The chunks follow each other in the same format, and still cannot be
     *  joined safely: one of them cannot be read for a join, or the shifted
     *  times would not be strictly increasing. */
    OTHER,
}

/** Where a chunk goes, as decided by [JoinPlanner.place]. */
sealed class JoinPlacement {
    /** Append the chunk to the open video, every sample shifted by [offsetUs]. */
    data class Join(val offsetUs: Long) : JoinPlacement()

    /** Close the open video, if any, and start a new one with this chunk,
     *  unshifted. [cut] is why, null for the first video. */
    data class NewVideo(val cut: Cut?) : JoinPlacement()

    /** Close the open video, if any; this chunk is a video of its own,
     *  copied as recorded. [cut] is why, null for the first video. */
    data class AsRecorded(val cut: Cut?) : JoinPlacement()
}

/**
 * Decides how the verified chunks of one report join into videos. No Android
 * and no I/O here, so every rule is testable on a plain JVM; [Mp4ChunkMedia]
 * reads the chunks and writes what this class decides.
 *
 * A chunk is a self-contained MP4 of about five seconds. It joins the open
 * video only when joining can neither lose nor invent anything:
 * - same format: same video MIME, codec configuration identical byte for
 *   byte, same dimensions, same audio format, and the same tracks present.
 *   A muxer writes one format per track, so a change starts a new video.
 * - contiguous: its seq is the previous chunk's plus one, AND the previous
 *   chunk was written. A missing chunk, or one excluded because it does not
 *   decrypt, starts a new video: a joined video never hides a gap.
 * - joinable on its own: every track it holds is in a codec the platform
 *   muxer of this phone writes ([muxerWrites], from [sdkInt]) and has
 *   samples, at times that are not negative, not beyond [MAX_CHUNK_US] and
 *   strictly increasing, and its video starts on a key frame. Anything else
 *   is exported as recorded.
 * - in order: once shifted, its first sample on each track comes strictly
 *   after the last sample written on that track.
 * - small enough: the open video stays within [MAX_PART_BYTES], and the
 *   phone keeps the room to copy it out (see [place]).
 *
 * The shift is anchored on the audio clock. The first chunk of a video is
 * not shifted; each next chunk is shifted by the previous chunk's shift plus
 * the previous chunk's audio length: the time of its last audio sample plus
 * one audio frame. The chunks were recorded back to back and each one
 * restarts its clock at zero; the audio is continuous across chunks and runs
 * a little longer than the video in each of them, so the audio clock is the
 * one to follow. A chunk without audio uses its video length the same way, in
 * a video that has no audio either (the tracks present are part of the
 * format).
 *
 * The audio length does not come from the track's declared duration: the
 * last sample's time plus one frame is what the samples themselves say.
 *
 * Each cut is counted once, under one reason ([cuts]): the first that holds
 * in the order [Cut.EXCLUDED], [Cut.MISSING], [Cut.FORMAT], [Cut.NUMBERING],
 * then [Cut.CODEC], [Cut.SIZE] or [Cut.OTHER]. A change of quality changes
 * the format and can skip a number at once: it counts as [Cut.FORMAT],
 * unless a chunk in the jump is known to be missing.
 *
 * [place] commits its decision: the caller writes the chunk as placed, or
 * the whole export fails.
 *
 * @param sdkInt the Android version of the phone that writes the videos,
 *   which decides the codecs its muxer writes.
 * @param missingSeqs the seqs the verification found missing on the relay
 *   (the report's verdict). Only these make a jump a [Cut.MISSING].
 */
class JoinPlanner(private val sdkInt: Int, missingSeqs: Set<Int>) {

    private val missing = TreeSet(missingSeqs)

    /** Videos started so far. */
    var videos = 0
        private set

    private val cutCounts = EnumMap<Cut, Int>(Cut::class.java)

    /** The cuts so far, by reason; a reason that never cut is absent. */
    val cuts: Map<Cut, Int> get() = cutCounts.toMap()

    private var lastSeq: Int? = null
    private var lastWritten = false

    /** The last chunk placed, null when it could not be read: a chunk copied
     *  as recorded still tells whether the format changed after it. */
    private var lastReadable: ChunkProbe? = null

    /** The video the next chunk may join, null when there is none or when
     *  the last video is a chunk copied as recorded. */
    private var open: Open? = null

    private class Open(
        var nextOffsetUs: Long,
        var lastVideoUs: Long,
        var lastAudioUs: Long,
        var bytes: Long,
    )

    /** How a chunk stands to the one placed or excluded before it. */
    private enum class Link { FIRST, CONTIGUOUS, AFTER_EXCLUDED, OVER_MISSING, OVER_NUMBER, BACKWARDS }

    /** The chunk [seq] was not written: it does not decrypt. The next chunk
     *  starts a new video. */
    fun excluded(seq: Int) {
        lastSeq = seq
        lastWritten = false
    }

    /**
     * Where the chunk [seq], described by [probe], goes. [chunkBytes] is the
     * size of its decrypted file; [freeBytes] is the free space left where
     * the open video is written, with the chunk already decrypted there.
     *
     * The chunk joins only while the open video stays within
     * [MAX_PART_BYTES], and while [freeBytes] still covers, once the chunk
     * is joined, a copy of the whole video plus one more chunk and
     * [SPACE_MARGIN_BYTES]: the destination is often on the same storage,
     * and the video is copied out there while the next chunk sits decrypted
     * beside it. Otherwise the video is closed and copied out, which frees
     * its private file. At worst each chunk is a video of its own.
     */
    fun place(seq: Int, probe: ChunkProbe, chunkBytes: Long, freeBytes: Long): JoinPlacement {
        require(chunkBytes >= 0) { "negative chunk size" }
        val link = link(seq)
        val previous = lastReadable
        lastSeq = seq
        lastWritten = true
        lastReadable = if (probe.readable) probe else null
        val current = open
        val formatChanged = previous != null && probe.readable && !sameFormat(previous, probe)

        if (!joinable(probe, sdkInt)) {
            open = null
            val otherwise = if (probe.readable && !tracksWritable(probe, sdkInt)) Cut.CODEC else Cut.OTHER
            return JoinPlacement.AsRecorded(newVideo(reason(link, formatChanged, otherwise)))
        }
        // After a chunk copied as recorded, or out of order.
        var otherwise = Cut.OTHER
        if (current != null && link == Link.CONTIGUOUS && !formatChanged) {
            val offset = current.nextOffsetUs
            val inOrder = inOrder(current, probe, offset)
            val fits = fits(current, chunkBytes, freeBytes)
            if (inOrder && fits) {
                advance(current, probe, offset)
                current.bytes += chunkBytes
                return JoinPlacement.Join(offset)
            }
            if (inOrder) otherwise = Cut.SIZE
        }
        val cut = newVideo(reason(link, formatChanged, otherwise))
        open = Open(
            nextOffsetUs = 0L,
            lastVideoUs = Long.MIN_VALUE,
            lastAudioUs = Long.MIN_VALUE,
            bytes = chunkBytes,
        ).also { advance(it, probe, 0L) }
        return JoinPlacement.NewVideo(cut)
    }

    private fun link(seq: Int): Link {
        val previous = lastSeq ?: return Link.FIRST
        return when {
            !lastWritten -> Link.AFTER_EXCLUDED
            seq <= previous -> Link.BACKWARDS
            seq == previous + 1 -> Link.CONTIGUOUS
            // A seq in the jump that the verification found missing.
            missing.ceiling(previous + 1)?.let { it < seq } == true -> Link.OVER_MISSING
            else -> Link.OVER_NUMBER
        }
    }

    /** The reason a new video starts, in the order the class documents;
     *  [otherwise] when none of the others holds. */
    private fun reason(link: Link, formatChanged: Boolean, otherwise: Cut): Cut = when {
        link == Link.AFTER_EXCLUDED -> Cut.EXCLUDED
        link == Link.OVER_MISSING -> Cut.MISSING
        formatChanged -> Cut.FORMAT
        link == Link.OVER_NUMBER -> Cut.NUMBERING
        else -> otherwise
    }

    /** Counts a new video and the cut that starts it; returns the cut, null
     *  for the first video, which follows nothing. */
    private fun newVideo(reason: Cut): Cut? {
        val cut = if (videos == 0) null else reason
        if (cut != null) cutCounts[cut] = (cutCounts[cut] ?: 0) + 1
        videos++
        return cut
    }

    private fun advance(video: Open, probe: ChunkProbe, offset: Long) {
        probe.video?.times?.let { video.lastVideoUs = offset + it.lastUs }
        probe.audio?.times?.let { video.lastAudioUs = offset + it.lastUs }
        video.nextOffsetUs = offset + lengthUs(probe)
    }

    private fun sameFormat(a: ChunkProbe, b: ChunkProbe): Boolean =
        sameTrack(a.video?.format, b.video?.format) && sameTrack(a.audio?.format, b.audio?.format)

    private fun sameTrack(a: TrackFormat?, b: TrackFormat?): Boolean =
        if (a == null || b == null) a == null && b == null else a.sameAs(b)

    private fun inOrder(open: Open, probe: ChunkProbe, offset: Long): Boolean {
        val video = probe.video?.times
        val audio = probe.audio?.times
        return (video == null || offset + video.firstUs > open.lastVideoUs) &&
            (audio == null || offset + audio.firstUs > open.lastAudioUs)
    }

    /** Whether the open video can take [chunkBytes] more (see [place]). */
    private fun fits(open: Open, chunkBytes: Long, freeBytes: Long): Boolean {
        val joined = open.bytes + chunkBytes
        return joined <= MAX_PART_BYTES && freeBytes - SPACE_MARGIN_BYTES - chunkBytes >= joined
    }

    companion object {
        /** The longest chunk clock accepted for a join. A chunk lasts about
         *  five seconds; a time past a day says the file is not what the
         *  recorder writes, and it is exported as recorded instead. The
         *  bound also caps how far one chunk can move the shift. */
        const val MAX_CHUNK_US = 24L * 60 * 60 * 1_000_000

        /**
         * The largest joined video, counted as the sum of its chunks' sizes:
         * 3 GiB. The platform muxer offers no way to ask for 64-bit offsets,
         * so the file must stay under 4 GiB, which is also the largest file
         * a FAT32 card or key holds. The rest covers the index the muxer
         * writes at the end.
         */
        const val MAX_PART_BYTES = 3L shl 30

        /** Free space kept beyond what joining and copying out need: the
         *  index the muxer writes when the video is finished, and samples it
         *  still holds in memory. */
        const val SPACE_MARGIN_BYTES = 32L shl 20

        /** Android 7.0 (`Build.VERSION_CODES.N`): the platform muxer writes
         *  HEVC into an MP4 from this version on. */
        private const val SDK_MUXER_HEVC = 24

        /** Samples per AAC frame (AAC-LC, what the recorder writes). */
        private const val AAC_FRAME_SAMPLES = 1024L
        private const val MIME_AAC = "audio/mp4a-latm"
        private const val MIME_AVC = "video/avc"
        private const val MIME_HEVC = "video/hevc"

        /**
         * Whether the platform muxer of a phone at [sdkInt] writes [mime]
         * into an MP4: H.264 and AAC on every version the app supports, HEVC
         * from Android 7.0 (API 24), as the `MediaMuxer` documentation lists
         * them. No other codec is joined: the recorder writes these three,
         * and anything else is exported as recorded rather than handed to a
         * muxer that may not take it.
         */
        fun muxerWrites(mime: String, sdkInt: Int): Boolean = when (mime) {
            MIME_AVC, MIME_AAC -> true
            MIME_HEVC -> sdkInt >= SDK_MUXER_HEVC
            else -> false
        }

        private fun tracksWritable(probe: ChunkProbe, sdkInt: Int): Boolean =
            listOfNotNull(probe.video, probe.audio).all { muxerWrites(it.format.mime, sdkInt) }

        /** Whether [probe] can take part in a join at all, on a phone at
         *  [sdkInt]. */
        fun joinable(probe: ChunkProbe, sdkInt: Int): Boolean {
            if (!probe.readable) return false
            if (probe.video == null && probe.audio == null) return false
            if (!tracksWritable(probe, sdkInt)) return false
            val video = probe.video
            if (video != null && (!usable(video.times) || video.times?.startsWithSync != true)) return false
            val audio = probe.audio
            return audio == null || usable(audio.times)
        }

        private fun usable(times: TrackTimes?): Boolean =
            times != null &&
                times.count > 0 &&
                times.strictlyIncreasing &&
                times.firstUs >= 0 &&
                times.lastUs <= MAX_CHUNK_US

        /**
         * The length of a joinable chunk on the clock its next chunk is
         * placed on: the audio's end when it has audio, the video's end
         * otherwise. A length that cannot be told (a single video sample, an
         * audio codec with no known frame size and a single sample) counts
         * the last sample only; the order check then refuses a next chunk
         * that would land on the same time.
         */
        fun lengthUs(probe: ChunkProbe): Long {
            val audio = probe.audio
            val audioTimes = audio?.times
            if (audio != null && audioTimes != null) {
                return audioTimes.lastUs + audioFrameUs(audio.format, audioTimes)
            }
            val videoTimes = probe.video?.times ?: return 0L
            return videoTimes.lastUs + (videoTimes.lastDeltaUs ?: 0L)
        }

        /** One audio frame: 1024 samples at the track's rate for AAC, the
         *  gap between the last two samples for any other codec. */
        private fun audioFrameUs(format: TrackFormat, times: TrackTimes): Long =
            if (format.mime == MIME_AAC && format.sampleRate > 0) {
                AAC_FRAME_SAMPLES * 1_000_000L / format.sampleRate
            } else {
                times.lastDeltaUs ?: 0L
            }
    }
}

/**
 * The last time written on each track of the open video. The writer checks
 * every sample against it, so a sample that would not come strictly after
 * the previous one on its track stops the export instead of being written
 * into an invalid file.
 */
class PartClock {
    private var lastVideoUs = Long.MIN_VALUE
    private var lastAudioUs = Long.MIN_VALUE

    /** Records [timeUs] on the video or the audio track and returns true,
     *  or returns false, recording nothing, when it is not strictly later
     *  than the last time recorded on that track. */
    fun admit(video: Boolean, timeUs: Long): Boolean {
        val last = if (video) lastVideoUs else lastAudioUs
        if (timeUs <= last) return false
        if (video) lastVideoUs = timeUs else lastAudioUs = timeUs
        return true
    }
}
