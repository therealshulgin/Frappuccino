package rs.readahead.washington.mobile.archive

import android.content.Context
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMetadataRetriever
import android.media.MediaMuxer
import android.os.Build
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.util.zip.CRC32

/**
 * The joined export on the platform's own extractor and muxer: chunks of one
 * format become one valid MP4 holding every sample, at strictly increasing
 * times on each track, as long as the chunks' audio together; a change of
 * codec or a gap makes two files. The dates and the Android version the
 * muxer writes about the export are cleared ([Mp4MetadataScrub]) without
 * moving a sample.
 *
 * Runs the export loop ([JoinedExportRun]) with [Mp4ChunkMedia], on plain
 * files: "decrypting" is a copy, and the destination is a directory. The
 * chunks are synthetic, in `androidTest/assets/join/`: 160x288 at 30 fps,
 * about one second each, AAC 48 kHz mono, one key frame first and no B-frame,
 * like the recorder's. Made with ffmpeg (libx264 / libx265):
 * ```
 * ffmpeg -f lavfi -i testsrc=size=160x288:rate=30:duration=6 \
 *        -f lavfi -i sine=frequency=440:sample_rate=48000:duration=6 \
 *        -ss K -t 1 -map 0:v -map 1:a \
 *        -c:v libx264 -preset veryfast -bf 0 -g 30 -keyint_min 30 -sc_threshold 0 -pix_fmt yuv420p -crf 38 \
 *        -threads 1 -map_metadata -1 -fflags +bitexact -flags:v +bitexact -flags:a +bitexact \
 *        -use_editlist 0 -avoid_negative_ts make_zero -c:a aac -b:a 32k -ac 1 -ar 48000 h264-N.mp4
 * ```
 * with K = 0, 1, 2 for `h264-1..3`; the HEVC chunks take K = 3, 4, a 660 Hz
 * tone, and `-c:v libx265 -x265-params bframes=0:keyint=30:min-keyint=30:scenecut=0:pools=none:frame-threads=1
 * -tag:v hvc1` in place of the libx264 options. Same settings, same codec
 * configuration byte for byte, as in a real recording.
 *
 * [joinDirectory] joins real chunks on request, see there.
 *
 * Run:
 * ```
 * ./gradlew :mobile:connectedDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=rs.readahead.washington.mobile.archive.Mp4JoinInstrumentedTest
 * ```
 */
@RunWith(AndroidJUnit4::class)
class Mp4JoinInstrumentedTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        val context: Context = ApplicationProvider.getApplicationContext()
        root = File(context.cacheDir, TEST_ROOT)
        root.deleteRecursively()
        assertTrue(root.mkdirs())
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun threeH264ChunksJoinIntoOneValidVideo() {
        val chunks = listOf(1 to asset("h264-1.mp4"), 2 to asset("h264-2.mp4"), 3 to asset("h264-3.mp4"))

        val (outcome, videos) = join(chunks)

        assertEquals(1, outcome.videos)
        assertEquals(listOf("prise-01.mp4"), videos.map { it.name })
        val out = read(videos.single())
        val inputs = chunks.map { read(it.second) }
        assertEquals("video/avc", out.videoMime)
        assertEquals(inputs.sumOf { it.video.size }, out.video.size)
        assertEquals(inputs.sumOf { it.audio.size }, out.audio.size)
        assertStrictlyIncreasing(out.video)
        assertStrictlyIncreasing(out.audio)
        // Each chunk lands where the audio before it ends, to within the
        // audio track's time unit (1/48000 s), which the file stores.
        val lengths = inputs.map { it.audio.last() + AAC_FRAME_US }
        assertEquals((lengths.dropLast(1).sum() + inputs.last().audio.last()).toDouble(), out.audio.last().toDouble(), 21.0)
        assertEquals(lengths.sum().toDouble(), out.durationUs.toDouble(), 50_000.0)
        assertEquals(0L, out.video.first())
        // Nothing about the phone added: no location, no rotation.
        val retriever = MediaMetadataRetriever()
        try {
            retriever.setDataSource(videos.single().path)
            assertNull(retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_LOCATION))
            assertEquals("0", retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION))
        } finally {
            retriever.release()
        }
        // Nor anything about the export: no date, no Android version.
        assertCleared(videos.single(), tracks = 2)
    }

    /**
     * What the platform muxer writes about the export is there before the
     * scrub, and gone after it, while every sample stays where it was: the
     * same file, the same size, changed only inside the date fields and the
     * metadata boxes, and read back by the platform's extractor with the
     * same tracks and the same samples, byte for byte, at the same times.
     */
    @Test
    fun theScrubClearsTheExportAndMovesNoSample() {
        val sets = mutableListOf(listOf(asset("h264-1.mp4"), asset("h264-2.mp4"), asset("h264-3.mp4")))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) sets.add(listOf(asset("hevc-1.mp4"), asset("hevc-2.mp4")))
        for ((n, files) in sets.withIndex()) {
            val (_, joined) = join(
                files.mapIndexed { i, f -> i + 1 to f },
                out = File(root, "reference-$n"),
                media = Mp4ChunkMedia(scrub = {}),
            )
            val reference = joined.single()
            val before = reference.readBytes()
            val found = Mp4MetadataScrub.inspect(reference)
            // The muxer did write them: without this, the rest checks nothing.
            assertTrue("no export date in the reference", found.dates.any { it.value != 0L })
            assertTrue("no metadata box in the reference", found.metadata.isNotEmpty())
            assertTrue("no Android version in the reference", contains(before, ANDROID_VERSION_KEY))
            val scrubbed = File(root, "scrubbed-$n.mp4")
            reference.copyTo(scrubbed)

            Mp4MetadataScrub.scrub(scrubbed)

            val after = scrubbed.readBytes()
            assertEquals(before.size, after.size)
            val cleared = found.dates.map { it.offset until it.offset + it.width } +
                found.metadata.map { it.offset + 4 until it.end }
            for (i in before.indices) {
                if (before[i] != after[i]) {
                    assertTrue("byte $i changed out of a date or a metadata box", cleared.any { i.toLong() in it })
                }
            }
            assertCleared(scrubbed, tracks = 2)
            assertEquals(formats(reference), formats(scrubbed))
            val expected = samples(reference)
            assertEquals(files.sumOf { samples(it).size }, expected.size)
            assertEquals(expected, samples(scrubbed))
        }
    }

    /** A video the scrub refuses never reaches the destination, and its
     *  private file is deleted, as after any failed write. */
    @Test
    fun aVideoTheScrubRefusesFailsTheExport() {
        val out = File(root, "out")
        try {
            join(
                listOf(1 to asset("h264-1.mp4"), 2 to asset("h264-2.mp4")),
                out = out,
                media = Mp4ChunkMedia(scrub = { throw Mp4MetadataScrub.Unexpected("refused") }),
            )
            fail("a video the scrub refuses must fail the export")
        } catch (_: Mp4MetadataScrub.Unexpected) {
        }
        assertEquals(emptyList<String>(), out.list().orEmpty().toList())
        assertEquals(emptyList<String>(), File(root, "work").list().orEmpty().toList())
    }

    /**
     * From Android 7.0 the HEVC chunks join, then the H.264 ones; before, the
     * platform muxer does not write HEVC, and each HEVC chunk is exported as
     * recorded while the H.264 ones still join.
     */
    @Test
    fun hevcThenH264MakeTwoVideos() {
        val chunks = listOf(
            1 to asset("hevc-1.mp4"), 2 to asset("hevc-2.mp4"),
            3 to asset("h264-1.mp4"), 4 to asset("h264-2.mp4"), 5 to asset("h264-3.mp4"),
        )

        val (outcome, videos) = join(chunks)

        val hevcJoins = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
        val hevcVideos = if (hevcJoins) 1 else 2
        assertEquals(hevcVideos + 1, outcome.videos)
        assertEquals(
            if (hevcJoins) mapOf(Cut.FORMAT to 1) else mapOf(Cut.CODEC to 1, Cut.FORMAT to 1),
            outcome.cuts,
        )
        assertEquals((1..hevcVideos + 1).map { "prise-01-partie-%02d.mp4".format(it) }, videos.map { it.name })
        val read = videos.map { read(it) }
        assertTrue(read.dropLast(1).all { it.videoMime == "video/hevc" })
        assertEquals("video/avc", read.last().videoMime)
        assertEquals(chunks.take(2).sumOf { read(it.second).video.size }, read.dropLast(1).sumOf { it.video.size })
        assertEquals(chunks.drop(2).sumOf { read(it.second).video.size }, read.last().video.size)
        for (v in read) {
            assertStrictlyIncreasing(v.video)
            assertStrictlyIncreasing(v.audio)
        }
    }

    @Test
    fun aMissingSeqMakesTwoVideos() {
        val chunks = listOf(1 to asset("h264-1.mp4"), 2 to asset("h264-2.mp4"), 4 to asset("h264-3.mp4"))

        val (outcome, videos) = join(chunks, missingSeqs = setOf(3))

        assertEquals(2, outcome.videos)
        assertEquals(mapOf(Cut.MISSING to 1), outcome.cuts)
        val inputs = chunks.map { read(it.second) }
        assertEquals(inputs[0].video.size + inputs[1].video.size, read(videos[0]).video.size)
        assertEquals(inputs[2].video.size, read(videos[1]).video.size)
    }

    /** A jump the verification does not list as missing still cuts the
     *  video, and is not counted as a missing chunk. */
    @Test
    fun aSkippedSeqMakesTwoVideosWithoutClaimingALoss() {
        val chunks = listOf(1 to asset("h264-1.mp4"), 2 to asset("h264-2.mp4"), 4 to asset("h264-3.mp4"))

        val (outcome, videos) = join(chunks)

        assertEquals(2, videos.size)
        assertEquals(mapOf(Cut.NUMBERING to 1), outcome.cuts)
    }

    /**
     * The first chunk of a recording starts its video later than its audio,
     * and still ends it before its audio. The muxer writes that delay as an
     * edit list; read back, the joined video keeps it rather than pulling the
     * pictures ahead of the sound.
     */
    @Test
    fun aLateVideoStartIsKept() {
        val late = File(root, "late.mp4")
        remux(asset("h264-1.mp4"), late, videoDelayUs = LATE_US)
        val delayedFrames = read(late).video.size
        assertTrue(delayedFrames in 1 until read(asset("h264-1.mp4")).video.size)
        val delayed = read(late)
        assertEquals(LATE_US.toDouble(), delayed.video.first().toDouble(), 1_000.0)

        val (_, videos) = join(listOf(1 to late, 2 to asset("h264-2.mp4")))

        val out = read(videos.single())
        assertEquals(delayed.video.first(), out.video.first())
        assertEquals(0L, out.audio.first())
        assertStrictlyIncreasing(out.video)
    }

    /**
     * Joins the `part-*.mp4` files of the directory given as the
     * instrumentation argument `joinDir`, a directory the app can read, and
     * writes the result to `joined/` in the app's cache, kept after the
     * test. Skipped without the argument.
     *
     * The number of each name is taken as the chunk's seq, and it is not
     * one: an export numbers its raw chunks in reading order from 1, so a
     * chunk the relay did not hold, or a number the recorder skipped, leaves
     * no hole in the names; only a chunk excluded from that export does. This
     * test therefore joins across jumps the app's export would cut at, and
     * its result can hold fewer videos than the app's export of the same
     * report. It checks what the muxer makes of real chunks, not where the
     * export cuts.
     * ```
     * ./gradlew :mobile:connectedDebugAndroidTest \
     *     -Pandroid.testInstrumentationRunnerArguments.class=rs.readahead.washington.mobile.archive.Mp4JoinInstrumentedTest#joinDirectory \
     *     -Pandroid.testInstrumentationRunnerArguments.joinDir=/path/on/the/device
     * ```
     */
    @Test
    fun joinDirectory() {
        val dir = InstrumentationRegistry.getArguments().getString(ARG_JOIN_DIR)
        assumeTrue("no $ARG_JOIN_DIR argument", !dir.isNullOrEmpty())
        val chunks = File(checkNotNull(dir)).listFiles().orEmpty()
            .mapNotNull { f -> PART_NAME.matchEntire(f.name)?.let { it.groupValues[1].toInt() to f } }
            .sortedBy { it.first }
        assumeTrue("no part-NNNN.mp4 in $dir", chunks.isNotEmpty())
        val context: Context = ApplicationProvider.getApplicationContext()
        val out = File(context.cacheDir, "joined").apply { deleteRecursively(); mkdirs() }

        val (outcome, videos) = join(chunks, out)

        Log.i(TAG, "joined ${chunks.size} chunks into $outcome")
        for (v in videos) {
            val r = read(v)
            Log.i(TAG, "${v.path}: ${r.videoMime}, ${r.video.size} video / ${r.audio.size} audio samples, ${r.durationUs} us")
            assertStrictlyIncreasing(r.video)
            assertStrictlyIncreasing(r.audio)
        }
        assertEquals(outcome.videos, videos.size)
    }

    // ---- helpers ----

    private fun asset(name: String): File {
        val target = File(root, "asset-$name")
        if (!target.exists()) {
            InstrumentationRegistry.getInstrumentation().context.assets.open("join/$name").use { input ->
                target.outputStream().use { input.copyTo(it) }
            }
        }
        return target
    }

    /** Run the export loop on [chunks] (seq → file) into [out]; returns the
     *  outcome and the videos written, in name order. */
    private fun join(
        chunks: List<Pair<Int, File>>,
        out: File = File(root, "out"),
        missingSeqs: Set<Int> = emptySet(),
        media: Mp4ChunkMedia = Mp4ChunkMedia(),
    ): Pair<ExportOutcome, List<File>> {
        out.mkdirs()
        val sources = chunks.associate { (seq, file) -> "%06d.strm".format(seq) to file }
        val plan = ExportPlan.planJoined(
            sources.keys.toList(), missingSeqs, otsMatched = false, includeRaw = false, ordinal = 1,
        )
        val work = File(root, "work").apply { mkdirs() }
        val destination = object : JoinedExportRun.Destination<File> {
            override fun create(item: ExportPlan.Item): File = File(out, item.targetName)
            override fun createVideo(name: String): File = File(out, name)
            override fun copy(plain: File, target: File): Long = plain.copyTo(target, overwrite = true).length()
            override fun writeTimestamp(item: ExportPlan.Item, target: File) = error("no timestamp here")
        }
        val outcome = JoinedExportRun(
            decrypt = { sealed, plain -> sealed.copyTo(plain, overwrite = true) },
            secureDelete = { it.delete() },
            media = media,
            destination = destination,
            sdkInt = Build.VERSION.SDK_INT,
        ).run(plan, sources, File(work, "chunk.tmp"), File(work, "video.tmp"), isActive = { true }) { _, _ -> }
        assertTrue("private files left behind", work.list().orEmpty().isEmpty())
        return outcome to out.listFiles().orEmpty().filter { it.name.startsWith("prise-") }.sortedBy { it.name }
    }

    /** [file] holds no date and no metadata box, as the walk of the scrub
     *  reads it, and not the Android version tag anywhere in its bytes. */
    private fun assertCleared(file: File, tracks: Int) {
        val found = Mp4MetadataScrub.inspect(file)
        // Two dates in the movie header, and in each track's track and media
        // headers.
        assertEquals(2 * (1 + 2 * tracks), found.dates.size)
        assertTrue("a date left", found.dates.all { it.value == 0L })
        assertEquals(emptyList<String>(), found.metadata.map { it.type })
        assertFalse("Android version left", contains(file.readBytes(), ANDROID_VERSION_KEY))
    }

    private fun contains(bytes: ByteArray, text: String): Boolean {
        val needle = text.toByteArray(Charsets.ISO_8859_1)
        return (0..bytes.size - needle.size).any { i -> needle.indices.all { bytes[i + it] == needle[it] } }
    }

    /** What the platform's extractor reads of each track of [file]. */
    private fun formats(file: File): List<String> {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(file.path)
            return (0 until extractor.trackCount).map { i ->
                val f = extractor.getTrackFormat(i)
                buildString {
                    append(f.getString(MediaFormat.KEY_MIME))
                    for (key in INT_KEYS) if (f.containsKey(key)) append(" $key=${f.getInteger(key)}")
                    if (f.containsKey(MediaFormat.KEY_DURATION)) append(" duration=${f.getLong(MediaFormat.KEY_DURATION)}")
                    if (f.containsKey(MediaFormat.KEY_LANGUAGE)) append(" language=${f.getString(MediaFormat.KEY_LANGUAGE)}")
                    var n = 0
                    while (true) {
                        val csd = f.getByteBuffer("csd-$n")?.duplicate() ?: break
                        val bytes = ByteArray(csd.remaining()).also { csd.get(it) }
                        append(" csd-$n=").append(bytes.joinToString("") { "%02x".format(it) })
                        n++
                    }
                }
            }
        } finally {
            extractor.release()
        }
    }

    private data class Sample(val track: Int, val timeUs: Long, val flags: Int, val size: Int, val crc: Long)

    /** Every sample of [file], in the order the platform's extractor reads
     *  them: track, time, flags, size and a checksum of the bytes. */
    private fun samples(file: File): List<Sample> {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(file.path)
            for (i in 0 until extractor.trackCount) extractor.selectTrack(i)
            val buffer = ByteBuffer.allocate(1 shl 20)
            val crc = CRC32()
            val out = ArrayList<Sample>()
            while (extractor.sampleTrackIndex >= 0) {
                val size = extractor.readSampleData(buffer, 0)
                crc.reset()
                crc.update(buffer.array(), buffer.arrayOffset(), size)
                out.add(Sample(extractor.sampleTrackIndex, extractor.sampleTime, extractor.sampleFlags, size, crc.value))
                if (!extractor.advance()) break
            }
            return out
        } finally {
            extractor.release()
        }
    }

    private class Read(val videoMime: String?, val video: List<Long>, val audio: List<Long>, val durationUs: Long)

    /** The sample times of [file]'s video and audio tracks, as the platform
     *  reads them, and its longest track duration. */
    private fun read(file: File): Read {
        val extractor = MediaExtractor()
        try {
            extractor.setDataSource(file.path)
            var videoTrack = -1
            var audioTrack = -1
            var videoMime: String? = null
            var duration = 0L
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                val mime = f.getString(MediaFormat.KEY_MIME).orEmpty()
                if (mime.startsWith("video/")) {
                    videoTrack = i
                    videoMime = mime
                }
                if (mime.startsWith("audio/")) audioTrack = i
                if (f.containsKey(MediaFormat.KEY_DURATION)) duration = maxOf(duration, f.getLong(MediaFormat.KEY_DURATION))
                extractor.selectTrack(i)
            }
            val video = ArrayList<Long>()
            val audio = ArrayList<Long>()
            while (extractor.sampleTrackIndex >= 0) {
                when (extractor.sampleTrackIndex) {
                    videoTrack -> video.add(extractor.sampleTime)
                    audioTrack -> audio.add(extractor.sampleTime)
                }
                if (!extractor.advance()) break
            }
            return Read(videoMime, video, audio, duration)
        } finally {
            extractor.release()
        }
    }

    private fun assertStrictlyIncreasing(times: List<Long>) {
        assertTrue("no samples", times.isNotEmpty())
        for (i in 1 until times.size) {
            assertTrue("time ${times[i]} after ${times[i - 1]} at $i", times[i] > times[i - 1])
        }
    }

    /** Remux [source] into [target] with its video [videoDelayUs] later,
     *  as the platform muxer writes a recording whose video starts late,
     *  dropping the frames that would then run past the last audio sample. */
    private fun remux(source: File, target: File, videoDelayUs: Long) {
        val audioEndUs = read(source).audio.last()
        val extractor = MediaExtractor()
        val muxer = MediaMuxer(target.path, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        try {
            extractor.setDataSource(source.path)
            val tracks = IntArray(extractor.trackCount)
            val isVideo = BooleanArray(extractor.trackCount)
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                isVideo[i] = f.getString(MediaFormat.KEY_MIME).orEmpty().startsWith("video/")
                tracks[i] = muxer.addTrack(f)
                extractor.selectTrack(i)
            }
            muxer.start()
            val buffer = ByteBuffer.allocate(1 shl 20)
            val info = MediaCodec.BufferInfo()
            while (true) {
                val track = extractor.sampleTrackIndex
                if (track < 0) break
                val size = extractor.readSampleData(buffer, 0)
                val time = extractor.sampleTime + if (isVideo[track]) videoDelayUs else 0L
                val flags = if (extractor.sampleFlags and MediaExtractor.SAMPLE_FLAG_SYNC != 0) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0
                if (!isVideo[track] || time < audioEndUs) {
                    info.set(0, size, time, flags)
                    muxer.writeSampleData(tracks[track], buffer, info)
                }
                if (!extractor.advance()) break
            }
            muxer.stop()
        } finally {
            muxer.release()
            extractor.release()
        }
    }

    private companion object {
        const val TEST_ROOT = "mp4-join-test"
        const val TAG = "Mp4JoinTest"
        const val ARG_JOIN_DIR = "joinDir"
        const val AAC_FRAME_US = 1024L * 1_000_000 / 48_000
        const val LATE_US = 300_000L
        val PART_NAME = Regex("""part-(\d+)\.mp4""")
        const val ANDROID_VERSION_KEY = "com.android.version"
        val INT_KEYS = listOf(
            MediaFormat.KEY_WIDTH, MediaFormat.KEY_HEIGHT, MediaFormat.KEY_SAMPLE_RATE, MediaFormat.KEY_CHANNEL_COUNT,
        )
    }
}
