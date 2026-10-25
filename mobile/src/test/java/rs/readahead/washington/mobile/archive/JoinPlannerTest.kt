package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The join rules: chunks join only when they share their format byte for
 * byte, follow each other with nothing missing, stay in order once shifted,
 * are in a codec this phone's muxer writes, and keep the video small enough
 * to copy out; the shift follows the audio clock. Each cut is counted under
 * the reason that is known, never a harsher one.
 */
class JoinPlannerTest {

    private val avc = byteArrayOf(0x67, 0x42, 0x00, 0x1f)
    private val avcPps = byteArrayOf(0x68, 0xce.toByte(), 0x3c, 0x80.toByte())
    private val hevc = byteArrayOf(0x40, 0x01, 0x0c, 0x01)
    private val aacConfig = byteArrayOf(0x11, 0x88.toByte())

    private fun h264(width: Int = 720, height: Int = 1280, sps: ByteArray = avc) =
        TrackFormat("video/avc", listOf(sps, avcPps), width = width, height = height)

    private fun hevcFormat() = TrackFormat("video/hevc", listOf(hevc), width = 720, height = 1280)

    private fun aac(rate: Int = 48_000, channels: Int = 1) =
        TrackFormat("audio/mp4a-latm", listOf(aacConfig), sampleRate = rate, channels = channels)

    /** A planner on a phone whose muxer writes every codec the recorder
     *  uses, with [missing] seqs found missing by the verification. */
    private fun planner(sdkInt: Int = SDK_ANY, missing: Set<Int> = emptySet()) = JoinPlanner(sdkInt, missing)

    /** Place a chunk of [bytes] with [free] bytes free. */
    private fun JoinPlanner.at(seq: Int, probe: ChunkProbe, bytes: Long = CHUNK_BYTES, free: Long = Long.MAX_VALUE) =
        place(seq, probe, bytes, free)

    /** Times from [first] to [last] every [step] µs. */
    private fun times(first: Long, last: Long, step: Long, sync: Boolean = true): TrackTimes {
        val b = TrackTimes.Builder()
        var t = first
        var i = 0
        while (t <= last) {
            b.add(t, sync && i == 0)
            t += step
            i++
        }
        return checkNotNull(b.build())
    }

    /** A chunk shaped like the recorder's: video at 30 fps over [videoUs],
     *  AAC 48 kHz frames over [audioUs], a little longer. */
    private fun chunk(
        video: TrackFormat? = h264(),
        audio: TrackFormat? = aac(),
        videoFirstUs: Long = 0,
        videoUs: Long = 4_900_000,
        audioUs: Long = 5_000_000,
    ) = ChunkProbe(
        readable = true,
        video = video?.let { ProbedTrack(it, times(videoFirstUs, videoUs, 33_333)) },
        audio = audio?.let { ProbedTrack(it, times(0, audioUs, AAC_FRAME_US)) },
    )

    private fun audioLength(probe: ChunkProbe): Long = checkNotNull(probe.audio?.times).lastUs + AAC_FRAME_US

    @Test
    fun `contiguous chunks of the same format join into one video`() {
        val planner = planner()
        val chunks = List(3) { chunk() }

        val placements = chunks.mapIndexed { i, c -> planner.at(i + 1, c) }

        assertEquals(JoinPlacement.NewVideo(null), placements[0])
        assertTrue(placements.drop(1).all { it is JoinPlacement.Join })
        assertEquals(1, planner.videos)
        assertEquals(emptyMap<Cut, Int>(), planner.cuts)
    }

    @Test
    fun `a change of codec starts a new video`() {
        val planner = planner()
        planner.at(1, chunk(video = hevcFormat()))
        planner.at(2, chunk(video = hevcFormat()))

        // The fall-back from HEVC to H.264 part-way through a recording.
        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(3, chunk(video = h264())))
        assertTrue(planner.at(4, chunk(video = h264())) is JoinPlacement.Join)
        assertEquals(2, planner.videos)
        assertEquals(mapOf(Cut.FORMAT to 1), planner.cuts)
    }

    @Test
    fun `codec configurations that differ by one byte start a new video`() {
        val planner = planner()
        planner.at(1, chunk())
        val other = avc.copyOf().also { it[3] = 0x20 }

        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(2, chunk(video = h264(sps = other))))
    }

    @Test
    fun `other dimensions or another audio format start a new video`() {
        val planner = planner()
        planner.at(1, chunk())

        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(2, chunk(video = h264(width = 1280, height = 720))))
        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(3, chunk(video = h264(width = 1280, height = 720), audio = aac(rate = 44_100))))
        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(4, chunk(video = h264(width = 1280, height = 720), audio = null)))
        assertEquals(4, planner.videos)
        assertEquals(mapOf(Cut.FORMAT to 3), planner.cuts)
    }

    @Test
    fun `a jump over a chunk the verification found missing is a missing cut`() {
        val planner = planner(missing = setOf(3))
        planner.at(1, chunk())
        planner.at(2, chunk())

        assertEquals(JoinPlacement.NewVideo(Cut.MISSING), planner.at(4, chunk()))
        assertEquals(2, planner.videos)
        assertEquals(mapOf(Cut.MISSING to 1), planner.cuts)
    }

    @Test
    fun `a jump with no chunk known to be missing still cuts, and claims no loss`() {
        // The recorder skips a number at a change of quality without losing
        // anything; a seq missing elsewhere in the report says nothing about
        // this jump.
        val planner = planner(missing = setOf(1, 9))
        planner.at(2, chunk())
        planner.at(3, chunk())

        assertEquals(JoinPlacement.NewVideo(Cut.NUMBERING), planner.at(5, chunk()))
        assertTrue(planner.at(6, chunk()) is JoinPlacement.Join)
        assertEquals(mapOf(Cut.NUMBERING to 1), planner.cuts)
    }

    @Test
    fun `a change of quality that skips a number counts as a change of format`() {
        val planner = planner()
        planner.at(1, chunk())

        // What the recorder does at a change of quality: other dimensions,
        // and a seq skipped.
        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(3, chunk(video = h264(width = 1080, height = 1920))))
        assertEquals(mapOf(Cut.FORMAT to 1), planner.cuts)
    }

    @Test
    fun `a change of format over a chunk known to be missing counts the missing chunk`() {
        val planner = planner(missing = setOf(2))
        planner.at(1, chunk(video = hevcFormat()))

        assertEquals(JoinPlacement.NewVideo(Cut.MISSING), planner.at(3, chunk(video = h264())))
        assertEquals(mapOf(Cut.MISSING to 1), planner.cuts)
    }

    @Test
    fun `a chunk that does not decrypt cuts the video, even with its seq in place`() {
        val planner = planner()
        planner.at(1, chunk())
        planner.excluded(2)

        assertEquals(JoinPlacement.NewVideo(Cut.EXCLUDED), planner.at(3, chunk()))
        assertTrue(planner.at(4, chunk()) is JoinPlacement.Join)
        assertEquals(2, planner.videos)
        assertEquals(mapOf(Cut.EXCLUDED to 1), planner.cuts)
    }

    @Test
    fun `the first video follows nothing, whatever came before it`() {
        val planner = planner()
        planner.excluded(1)

        assertEquals(JoinPlacement.NewVideo(null), planner.at(2, chunk()))
        assertEquals(emptyMap<Cut, Int>(), planner.cuts)
    }

    @Test
    fun `a seq that does not move forward never joins`() {
        val planner = planner()
        planner.at(2, chunk())

        assertEquals(JoinPlacement.NewVideo(Cut.OTHER), planner.at(2, chunk()))
        assertEquals(JoinPlacement.NewVideo(Cut.OTHER), planner.at(1, chunk()))
    }

    @Test
    fun `the muxer writes H264 and AAC everywhere, HEVC from Android 7`() {
        for (sdk in listOf(21, 23, 24, 34)) {
            assertTrue(JoinPlanner.muxerWrites("video/avc", sdk))
            assertTrue(JoinPlanner.muxerWrites("audio/mp4a-latm", sdk))
            assertFalse(JoinPlanner.muxerWrites("video/mp4v-es", sdk))
            assertFalse(JoinPlanner.muxerWrites("audio/3gpp", sdk))
            assertFalse(JoinPlanner.muxerWrites("", sdk))
        }
        assertFalse(JoinPlanner.muxerWrites("video/hevc", 21))
        assertFalse(JoinPlanner.muxerWrites("video/hevc", 23))
        assertTrue(JoinPlanner.muxerWrites("video/hevc", 24))
        assertTrue(JoinPlanner.muxerWrites("video/hevc", 34))
    }

    @Test
    fun `before Android 7, HEVC chunks are exported as recorded, never joined`() {
        val planner = planner(sdkInt = 23)

        assertEquals(JoinPlacement.AsRecorded(null), planner.at(1, chunk(video = hevcFormat())))
        assertEquals(JoinPlacement.AsRecorded(Cut.CODEC), planner.at(2, chunk(video = hevcFormat())))
        // The fall-back to H.264 is still told apart, after a chunk copied
        // as recorded, and H.264 joins.
        assertEquals(JoinPlacement.NewVideo(Cut.FORMAT), planner.at(3, chunk(video = h264())))
        assertTrue(planner.at(4, chunk(video = h264())) is JoinPlacement.Join)
        assertEquals(3, planner.videos)
        assertEquals(mapOf(Cut.CODEC to 1, Cut.FORMAT to 1), planner.cuts)
        assertFalse(JoinPlanner.joinable(chunk(video = hevcFormat()), 23))
        assertTrue(JoinPlanner.joinable(chunk(video = hevcFormat()), 24))
    }

    @Test
    fun `from Android 7, HEVC chunks join`() {
        val planner = planner(sdkInt = 24)

        assertEquals(JoinPlacement.NewVideo(null), planner.at(1, chunk(video = hevcFormat())))
        assertTrue(planner.at(2, chunk(video = hevcFormat())) is JoinPlacement.Join)
    }

    @Test
    fun `a video stops growing at the size bound`() {
        val planner = planner()
        val gib = 1L shl 30

        val placements = (1..5).map { planner.at(it, chunk(), bytes = gib) }

        // Three chunks of 1 GiB make 3 GiB, the bound; the fourth starts a
        // new video, which the fifth joins.
        assertEquals(JoinPlacement.NewVideo(null), placements[0])
        assertTrue(placements[1] is JoinPlacement.Join)
        assertTrue(placements[2] is JoinPlacement.Join)
        assertEquals(JoinPlacement.NewVideo(Cut.SIZE), placements[3])
        assertTrue(placements[4] is JoinPlacement.Join)
        assertEquals(mapOf(Cut.SIZE to 1), planner.cuts)
        assertEquals(3 * gib, JoinPlanner.MAX_PART_BYTES)
    }

    @Test
    fun `a video stops growing before the phone could not copy it out`() {
        val planner = planner()
        val mib = 1L shl 20
        val chunkBytes = 100 * mib
        // Joining a second chunk needs the joined 200 MiB, one more chunk and
        // the margin free; a third, 300 MiB more. 400 MiB holds the first.
        val free = 400 * mib
        assertTrue(200 * mib + chunkBytes + JoinPlanner.SPACE_MARGIN_BYTES <= free)
        assertTrue(300 * mib + chunkBytes + JoinPlanner.SPACE_MARGIN_BYTES > free)

        val placements = (1..4).map { planner.at(it, chunk(), bytes = chunkBytes, free = free) }

        assertEquals(JoinPlacement.NewVideo(null), placements[0])
        assertTrue(placements[1] is JoinPlacement.Join)
        assertEquals(JoinPlacement.NewVideo(Cut.SIZE), placements[2])
        assertTrue(placements[3] is JoinPlacement.Join)
    }

    @Test
    fun `with no free space, each chunk is a video of its own and none is dropped`() {
        val planner = planner()

        val placements = (1..3).map { planner.at(it, chunk(), free = 0L) }

        assertEquals(
            listOf(JoinPlacement.NewVideo(null), JoinPlacement.NewVideo(Cut.SIZE), JoinPlacement.NewVideo(Cut.SIZE)),
            placements,
        )
        assertEquals(3, planner.videos)
    }

    @Test
    fun `each chunk is shifted by the audio length of the ones before it`() {
        val planner = planner()
        // Audio runs a little longer than the video in each chunk, by a
        // different amount each time; the first chunk's video starts late.
        val chunks = listOf(
            chunk(videoFirstUs = 900_000, videoUs = 4_880_000, audioUs = 4_970_000),
            chunk(videoUs = 4_900_000, audioUs = 5_010_000),
            chunk(videoUs = 4_920_000, audioUs = 5_000_000),
        )

        val offsets = chunks.mapIndexed { i, c ->
            when (val p = planner.at(i + 1, c)) {
                is JoinPlacement.NewVideo -> 0L
                is JoinPlacement.Join -> p.offsetUs
                is JoinPlacement.AsRecorded -> error("not joinable: $p")
            }
        }

        assertEquals(
            listOf(0L, audioLength(chunks[0]), audioLength(chunks[0]) + audioLength(chunks[1])),
            offsets,
        )
        // The shifted samples stay strictly increasing on both tracks.
        for (i in 1 until chunks.size) {
            val prev = chunks[i - 1]
            val next = chunks[i]
            assertTrue(offsets[i] + next.video!!.times!!.firstUs > offsets[i - 1] + prev.video!!.times!!.lastUs)
            assertTrue(offsets[i] + next.audio!!.times!!.firstUs > offsets[i - 1] + prev.audio!!.times!!.lastUs)
        }
    }

    @Test
    fun `the audio length is the last sample plus one AAC frame`() {
        val probe = chunk(audioUs = 5_000_000)
        assertEquals(probe.audio!!.times!!.lastUs + 1024L * 1_000_000 / 48_000, JoinPlanner.lengthUs(probe))
    }

    @Test
    fun `a chunk without audio is measured by its video`() {
        val planner = planner()
        val first = chunk(audio = null, videoUs = 4_900_000)
        val second = chunk(audio = null)

        planner.at(1, first)
        val placed = planner.at(2, second)

        val video = first.video!!.times!!
        assertEquals(JoinPlacement.Join(video.lastUs + video.lastDeltaUs!!), placed)
    }

    @Test
    fun `video running past the audio breaks the order and starts a new video`() {
        val planner = planner()
        planner.at(1, chunk(videoUs = 5_100_000, audioUs = 5_000_000))

        // Shifted by the audio length, the next video would start before the
        // last video sample written: never written out of order.
        assertEquals(JoinPlacement.NewVideo(Cut.OTHER), planner.at(2, chunk()))
        assertEquals(mapOf(Cut.OTHER to 1), planner.cuts)
    }

    @Test
    fun `a chunk that cannot be read is exported as recorded, never joined`() {
        val planner = planner()
        planner.at(1, chunk())

        assertEquals(JoinPlacement.AsRecorded(Cut.OTHER), planner.at(2, ChunkProbe.UNREADABLE))
        // Nothing joins a chunk copied as recorded.
        assertEquals(JoinPlacement.NewVideo(Cut.OTHER), planner.at(3, chunk()))
        assertEquals(3, planner.videos)
        assertEquals(mapOf(Cut.OTHER to 2), planner.cuts)
    }

    @Test
    fun `a chunk that is not joinable on its own is exported as recorded`() {
        val noKeyFrame = ChunkProbe(
            readable = true,
            video = ProbedTrack(h264(), times(0, 4_900_000, 33_333, sync = false)),
            audio = ProbedTrack(aac(), times(0, 5_000_000, AAC_FRAME_US)),
        )
        val outOfOrder = ChunkProbe(
            readable = true,
            video = ProbedTrack(h264(), TrackTimes.Builder().apply { add(0, true); add(66_666, false); add(33_333, false) }.build()),
            audio = ProbedTrack(aac(), times(0, 5_000_000, AAC_FRAME_US)),
        )
        val negative = chunk(videoFirstUs = -10_000)
        val noSamples = ChunkProbe(readable = true, video = ProbedTrack(h264(), null), audio = null)
        val tooLong = ChunkProbe(
            readable = true,
            video = ProbedTrack(h264(), times(0, 4_900_000, 33_333)),
            audio = ProbedTrack(aac(), TrackTimes.Builder().apply { add(0, true); add(JoinPlanner.MAX_CHUNK_US + 1, false) }.build()),
        )
        val otherCodec = chunk(video = TrackFormat("video/mp4v-es", emptyList(), width = 720, height = 1280))

        for (probe in listOf(noKeyFrame, outOfOrder, negative, noSamples, tooLong, otherCodec, ChunkProbe.UNREADABLE)) {
            assertFalse(JoinPlanner.joinable(probe, SDK_ANY))
            assertTrue(planner().at(1, probe) is JoinPlacement.AsRecorded)
        }
        assertTrue(JoinPlanner.joinable(chunk(), SDK_ANY))
    }

    @Test
    fun `an unreadable chunk after a jump counts the jump`() {
        val planner = planner(missing = setOf(3))
        planner.at(1, chunk())

        assertEquals(JoinPlacement.AsRecorded(Cut.MISSING), planner.at(5, ChunkProbe.UNREADABLE))
        assertEquals(JoinPlacement.AsRecorded(Cut.NUMBERING), planner.at(7, ChunkProbe.UNREADABLE))
    }

    @Test
    fun `the clock refuses a sample that is not strictly later on its track`() {
        val clock = PartClock()
        assertTrue(clock.admit(video = true, timeUs = 0))
        assertTrue(clock.admit(video = false, timeUs = 0))
        assertTrue(clock.admit(video = true, timeUs = 33_333))
        assertFalse(clock.admit(video = true, timeUs = 33_333))
        assertFalse(clock.admit(video = true, timeUs = 10))
        // The tracks are independent, and a refused time is not recorded.
        assertTrue(clock.admit(video = false, timeUs = 21_333))
        assertTrue(clock.admit(video = true, timeUs = 33_334))
    }

    @Test
    fun `the builder records order, first sync and the last gap`() {
        val b = TrackTimes.Builder()
        assertEquals(null, b.build())
        b.add(100, sync = true)
        assertEquals(TrackTimes(100, 100, 1, true, null, true), b.build())
        b.add(200, sync = false)
        b.add(250, sync = false)
        assertEquals(TrackTimes(100, 250, 3, true, 50, true), b.build())
        b.add(250, sync = false)
        assertFalse(checkNotNull(b.build()).strictlyIncreasing)
    }

    private companion object {
        const val AAC_FRAME_US = 1024L * 1_000_000 / 48_000

        /** A version whose muxer writes H.264, HEVC and AAC. */
        const val SDK_ANY = 34

        /** A chunk of about five seconds at a few Mbit/s. */
        const val CHUNK_BYTES = 3L shl 20
    }
}
