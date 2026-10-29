package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.frappuccino.FfiException
import java.io.File
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException

/**
 * The nominal export's loop: the chunks become as few videos as the join
 * rules allow, named after the report; the chunks as recorded and the
 * timestamp proof go to their subfolder only when asked for; an object that
 * does not decrypt is excluded, counted, and cuts the video; and no private
 * plaintext outlives the export, whatever happens to it.
 *
 * The media side is a fake: a "video" is a text file listing the chunks
 * appended to it and their shift, which is what the loop decides. The
 * muxing itself is tested on a device (`Mp4JoinInstrumentedTest`).
 */
class JoinedExportRunTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var enc: File
    private lateinit var plainDir: File
    private lateinit var dest: File

    private fun layout() {
        enc = tmp.newFolder("enc")
        plainDir = tmp.newFolder("plain")
        dest = tmp.newFolder("dest")
    }

    private val chunkPlain: File get() = File(plainDir, "export.tmp")
    private val videoPlain: File get() = File(plainDir, "export-video.tmp")
    private val rawDir: File get() = File(dest, RescueNames.EXPORT_RAW_FOLDER_NAME)

    private val avc = TrackFormat("video/avc", listOf(byteArrayOf(1, 2, 3)), width = 720, height = 1280)
    private val hevc = TrackFormat("video/hevc", listOf(byteArrayOf(4, 5, 6)), width = 720, height = 1280)
    private val aac = TrackFormat("audio/mp4a-latm", listOf(byteArrayOf(0x11, 0x88.toByte())), sampleRate = 48_000, channels = 1)

    private fun probe(video: TrackFormat): ChunkProbe {
        val v = TrackTimes.Builder().apply { add(0, true); add(4_900_000, false) }.build()
        val a = TrackTimes.Builder().apply { add(0, true); add(4_992_000, false) }.build()
        return ChunkProbe(readable = true, video = ProbedTrack(video, v), audio = ProbedTrack(aac, a))
    }

    private class FakeVideo(val file: File) {
        var finished = false
        var abandoned = false
    }

    private inner class Fakes(
        /** Plaintext of a chunk → what it holds; anything else is unreadable. */
        val probes: Map<String, ChunkProbe> = emptyMap(),
        val undecryptable: Set<String> = emptySet(),
        val refusedTargets: Set<String> = emptySet(),
        val shortTargets: Set<String> = emptySet(),
        val failAppend: Boolean = false,
        val failFinish: Boolean = false,
    ) {
        val secureDeleted = ArrayList<File>()
        val videos = ArrayList<FakeVideo>()

        val media = object : JoinedExportRun.Media<FakeVideo> {
            override fun probe(chunk: File): ChunkProbe = probes[chunk.readText()] ?: ChunkProbe.UNREADABLE

            override fun open(file: File, first: ChunkProbe): FakeVideo {
                check(!file.exists()) { "a private video left behind" }
                file.writeText("")
                return FakeVideo(file).also { videos.add(it) }
            }

            override fun append(video: FakeVideo, chunk: File, offsetUs: Long) {
                if (failAppend) throw IllegalStateException("muxer failed")
                video.file.appendText("${chunk.readText()}@$offsetUs\n")
            }

            override fun finish(video: FakeVideo) {
                video.finished = true
                if (failFinish) throw IOException("video not cleared")
            }

            override fun abandon(video: FakeVideo) {
                video.abandoned = true
            }
        }

        val destination = object : JoinedExportRun.Destination<File> {
            override fun create(item: ExportPlan.Item): File {
                val dir = if (item.inRawFolder) rawDir.apply { mkdirs() } else dest
                return File(dir, item.targetName).apply { check(createNewFile()) { "created twice" } }
            }

            override fun createVideo(name: String): File =
                File(dest, name).apply { check(createNewFile()) { "created twice" } }

            override fun copy(plain: File, target: File): Long {
                if (target.name in refusedTargets) throw IOException("export destination refused")
                plain.copyTo(target, overwrite = true)
                return if (target.name in shortTargets) plain.length() - 1 else plain.length()
            }

            override fun writeTimestamp(item: ExportPlan.Item, target: File) = target.writeText(item.kind.name)
        }

        fun run(
            plan: ExportPlan.Joined,
            sources: Map<String, File>,
            isActive: () -> Boolean = { true },
            sdkInt: Int = SDK_ANY,
            freeSpace: (File) -> Long = { Long.MAX_VALUE },
            onItem: (Int, Int) -> Unit = { _, _ -> },
        ): ExportOutcome = JoinedExportRun(
            decrypt = { sealed, out ->
                if (sealed.name in undecryptable) {
                    out.writeText("partial plaintext of ${sealed.name}")
                    throw FfiException.InvalidBlob("not a STRM for this identity")
                }
                sealed.copyTo(out, overwrite = true)
            },
            secureDelete = { secureDeleted.add(it); it.delete() },
            media = media,
            destination = destination,
            sdkInt = sdkInt,
            freeSpace = freeSpace,
        ).run(plan, sources, chunkPlain, videoPlain, isActive, onItem)
    }

    /** Encrypted sources whose "plaintext" is their own name. */
    private fun sources(vararg names: String): Map<String, File> =
        names.associateWith { File(enc, it).apply { writeText(it) } }

    private fun plan(
        sources: Map<String, File>,
        otsMatched: Boolean = false,
        includeRaw: Boolean = false,
        missingSeqs: Set<Int> = emptySet(),
    ) = ExportPlan.planJoined(sources.keys.toList(), missingSeqs, otsMatched, includeRaw, ordinal = 3)

    private fun exported(dir: File = dest): Set<String> = dir.list()?.toSet().orEmpty()

    private fun noPrivatePlaintextLeft() {
        assertFalse("private chunk left behind", chunkPlain.exists())
        assertFalse("private video left behind", videoPlain.exists())
    }

    @Test
    fun `chunks of one format make one video named after the report`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm", "000003.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(avc), "000002.strm" to probe(avc), "000003.strm" to probe(avc)))

        val outcome = fakes.run(plan(sources), sources)

        assertEquals(ExportOutcome(written = 2, undecryptable = 0, timestampLeftOut = false, videos = 1), outcome)
        assertEquals(setOf("metadata.json", "prise-03.mp4"), exported())
        val length = JoinPlanner.lengthUs(probe(avc))
        assertEquals(
            listOf("000001.strm@0", "000002.strm@$length", "000003.strm@${2 * length}"),
            File(dest, "prise-03.mp4").readLines(),
        )
        assertTrue(fakes.videos.single().finished)
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a change of codec makes numbered parts, and the outcome says why`() {
        layout()
        val sources = sources("000001.strm", "000002.strm", "000003.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(hevc), "000002.strm" to probe(hevc), "000003.strm" to probe(avc)))

        val outcome = fakes.run(plan(sources), sources)

        assertEquals(2, outcome.videos)
        assertEquals(mapOf(Cut.FORMAT to 1), outcome.cuts)
        assertEquals(setOf("prise-03-partie-01.mp4", "prise-03-partie-02.mp4"), exported())
        assertEquals(listOf("000003.strm@0"), File(dest, "prise-03-partie-02.mp4").readLines())
        noPrivatePlaintextLeft()
    }

    @Test
    fun `before Android 7, an HEVC report still exports, its HEVC chunks as recorded`() {
        layout()
        val sources = sources("000001.strm", "000002.strm", "000003.strm", "000004.strm")
        val fakes = Fakes(
            probes = mapOf(
                "000001.strm" to probe(hevc), "000002.strm" to probe(hevc),
                "000003.strm" to probe(avc), "000004.strm" to probe(avc),
            ),
        )

        val outcome = fakes.run(plan(sources), sources, sdkInt = 23)

        assertEquals(3, outcome.videos)
        assertEquals(mapOf(Cut.CODEC to 1, Cut.FORMAT to 1), outcome.cuts)
        // The HEVC chunks never reach the muxer: the only video opened is
        // the H.264 one.
        assertEquals(1, fakes.videos.size)
        assertEquals("000001.strm", File(dest, "prise-03-partie-01.mp4").readText())
        assertEquals("000002.strm", File(dest, "prise-03-partie-02.mp4").readText())
        assertEquals(
            listOf("000003.strm@0", "000004.strm@${JoinPlanner.lengthUs(probe(avc))}"),
            File(dest, "prise-03-partie-03.mp4").readLines(),
        )
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a jump is a missing cut only over a seq the verdict lists as missing`() {
        layout()
        val sources = sources("000001.strm", "000003.strm", "000005.strm")
        val fakes = Fakes(probes = sources.keys.associateWith { probe(avc) })

        val outcome = fakes.run(plan(sources, missingSeqs = setOf(4)), sources)

        // 2 is not in the verdict's missing seqs: the recorder may have
        // skipped it. 4 is.
        assertEquals(3, outcome.videos)
        assertEquals(mapOf(Cut.NUMBERING to 1, Cut.MISSING to 1), outcome.cuts)
    }

    @Test
    fun `short of space, each video is closed and copied out and the export goes on`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm", "000003.strm")
        val fakes = Fakes(probes = sources.keys.associateWith { probe(avc) })

        val outcome = fakes.run(plan(sources), sources, freeSpace = { 0L })

        assertEquals(3, outcome.videos)
        assertEquals(mapOf(Cut.SIZE to 2), outcome.cuts)
        assertEquals(
            setOf("metadata.json", "prise-03-partie-01.mp4", "prise-03-partie-02.mp4", "prise-03-partie-03.mp4"),
            exported(),
        )
        assertTrue(fakes.videos.all { it.finished })
        noPrivatePlaintextLeft()
    }

    @Test
    fun `the free space is asked of the private video's storage`() {
        layout()
        val sources = sources("000001.strm", "000002.strm")
        val asked = ArrayList<File>()

        Fakes(probes = sources.keys.associateWith { probe(avc) })
            .run(plan(sources), sources, freeSpace = { asked.add(it); Long.MAX_VALUE })

        assertEquals(listOf(videoPlain, videoPlain), asked)
    }

    @Test
    fun `without the raw chunks, no chunk as recorded and no timestamp proof leave the app`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")

        val outcome = Fakes(probes = mapOf("000001.strm" to probe(avc))).run(plan(sources, otsMatched = true), sources)

        assertFalse(outcome.timestampLeftOut)
        assertEquals(setOf("metadata.json", "prise-03.mp4"), exported())
        assertFalse(rawDir.exists())
    }

    @Test
    fun `with the raw chunks, the subfolder holds them and the matching proof`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(avc), "000002.strm" to probe(avc)))

        val outcome = fakes.run(plan(sources, otsMatched = true, includeRaw = true), sources)

        assertEquals(ExportOutcome(written = 6, undecryptable = 0, timestampLeftOut = false, videos = 1), outcome)
        assertEquals(setOf("metadata.json", "prise-03.mp4", RescueNames.EXPORT_RAW_FOLDER_NAME), exported())
        assertEquals(setOf("part-0001.mp4", "part-0002.mp4", "timestamp.ots", "timestamp.otssalt"), exported(rawDir))
        assertEquals("000002.strm", File(rawDir, "part-0002.mp4").readText())
    }

    @Test
    fun `a chunk that does not decrypt is excluded, counted, and cuts the video`() {
        layout()
        val sources = sources("000001.strm", "000002.strm", "000003.strm")
        val fakes = Fakes(
            probes = mapOf("000001.strm" to probe(avc), "000003.strm" to probe(avc)),
            undecryptable = setOf("000002.strm"),
        )

        val outcome = fakes.run(plan(sources, otsMatched = true, includeRaw = true), sources)

        assertEquals(1, outcome.undecryptable)
        assertEquals(2, outcome.videos)
        assertEquals(mapOf(Cut.EXCLUDED to 1), outcome.cuts)
        // The proof commits to every verified chunk, and one is missing.
        assertTrue(outcome.timestampLeftOut)
        assertEquals(setOf("prise-03-partie-01.mp4", "prise-03-partie-02.mp4", RescueNames.EXPORT_RAW_FOLDER_NAME), exported())
        assertEquals(setOf("part-0001.mp4", "part-0003.mp4"), exported(rawDir))
        for (f in dest.walkTopDown().filter { it.isFile }) assertFalse(f.readText().contains("partial plaintext"))
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a chunk that cannot be read for a join is a video of its own, as recorded`() {
        layout()
        val sources = sources("000001.strm", "000002.strm", "000003.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(avc), "000003.strm" to probe(avc)))

        val outcome = fakes.run(plan(sources), sources)

        assertEquals(3, outcome.videos)
        assertEquals(mapOf(Cut.OTHER to 2), outcome.cuts)
        assertEquals("000002.strm", File(dest, "prise-03-partie-02.mp4").readText())
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a single chunk that cannot be read is still the report's one video`() {
        layout()
        val sources = sources("000001.strm")

        val outcome = Fakes().run(plan(sources), sources)

        assertEquals(1, outcome.videos)
        assertEquals("000001.strm", File(dest, "prise-03.mp4").readText())
        noPrivatePlaintextLeft()
    }

    @Test
    fun `every private plaintext file is secure-deleted`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(hevc), "000002.strm" to probe(avc)))

        fakes.run(plan(sources), sources)

        assertTrue(fakes.secureDeleted.count { it == chunkPlain } >= 3)
        assertTrue(fakes.secureDeleted.count { it == videoPlain } >= 2)
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a destination that refuses a video fails the export and leaves no private plaintext`() {
        layout()
        val sources = sources("000001.strm", "000002.strm")
        val fakes = Fakes(
            probes = mapOf("000001.strm" to probe(hevc), "000002.strm" to probe(avc)),
            refusedTargets = setOf("prise-03-partie-01.mp4"),
        )

        try {
            fakes.run(plan(sources), sources)
            fail("a refused destination must fail the export")
        } catch (_: IOException) {
        }
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a copy cut short fails the export`() {
        layout()
        val sources = sources("000001.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(avc)), shortTargets = setOf("prise-03.mp4"))

        try {
            fakes.run(plan(sources), sources)
            fail("a short copy must fail the export")
        } catch (_: IOException) {
        }
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a failure writing the video fails the export and releases it`() {
        layout()
        val sources = sources("000001.strm")
        val fakes = Fakes(probes = mapOf("000001.strm" to probe(avc)), failAppend = true)

        try {
            fakes.run(plan(sources), sources)
            fail("a muxer failure must fail the export")
        } catch (_: IllegalStateException) {
        }
        assertTrue(fakes.videos.single().abandoned)
        noPrivatePlaintextLeft()
    }

    /** The joined video's metadata scrub refusing the file, for one: the
     *  video never reaches the destination. */
    @Test
    fun `a video its media cannot finish fails the export before any copy`() {
        layout()
        val sources = sources("000001.strm", "000002.strm")
        val fakes = Fakes(probes = sources.keys.associateWith { probe(avc) }, failFinish = true)

        try {
            fakes.run(plan(sources), sources)
            fail("a video that cannot be finished must fail the export")
        } catch (_: IOException) {
        }
        assertEquals(emptySet<String>(), exported())
        assertTrue(fakes.videos.single().finished)
        noPrivatePlaintextLeft()
    }

    @Test
    fun `a cancellation after a chunk stops the export and releases the open video`() {
        layout()
        val sources = sources("000001.strm", "000002.strm", "000003.strm")
        val fakes = Fakes(probes = sources.keys.associateWith { probe(avc) })
        var checks = 0

        try {
            // Active for the first chunk's checks, then cancelled.
            fakes.run(plan(sources), sources, isActive = { ++checks <= 2 })
            fail("a cancellation must stop the export")
        } catch (_: CancellationException) {
        }
        assertTrue(fakes.videos.single().abandoned)
        assertEquals(emptySet<String>(), exported())
        noPrivatePlaintextLeft()
    }

    @Test
    fun `the progress counts every object and timestamp file`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm")
        val progress = ArrayList<Pair<Int, Int>>()

        Fakes(probes = mapOf("000001.strm" to probe(avc)), undecryptable = setOf("000002.strm"))
            .run(plan(sources, otsMatched = true, includeRaw = true), sources) { done, total -> progress.add(done to total) }

        assertEquals(listOf(1 to 5, 2 to 5, 3 to 5, 4 to 5, 5 to 5), progress)
    }

    @Test
    fun `nothing decrypts, nothing is written and the outcome says so`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")

        val outcome = Fakes(undecryptable = sources.keys).run(plan(sources), sources)

        assertTrue(outcome.nothingWritten)
        assertEquals(0, outcome.videos)
        assertEquals(emptySet<String>(), exported())
        noPrivatePlaintextLeft()
    }

    private companion object {
        /** A version whose muxer writes H.264, HEVC and AAC. */
        const val SDK_ANY = 34
    }
}
