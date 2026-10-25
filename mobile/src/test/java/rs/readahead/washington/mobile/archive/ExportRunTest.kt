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
 * An object that does not decrypt is excluded from the export and counted;
 * the rest of the report is exported, and nothing of the excluded object
 * stays, neither in the private directory nor at the destination. A write to
 * the destination, or a failure that is not the object's own, still fails the
 * export.
 */
class ExportRunTest {

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

    private val plain: File get() = File(plainDir, "export.tmp")

    /**
     * Decrypts by copying. A name in [undecryptable] writes a partial
     * plaintext then throws what [failure] gives, the worst a failed
     * decryption could leave behind.
     */
    private inner class Fakes(
        val undecryptable: Set<String> = emptySet(),
        val failure: () -> Exception = { FfiException.InvalidBlob("not a STRM for this identity") },
        val refusedTargets: Set<String> = emptySet(),
        val shortTargets: Set<String> = emptySet(),
    ) {
        val secureDeleted = ArrayList<File>()

        val destination = object : ExportRun.Destination<File> {
            override fun create(item: ExportPlan.Item): File =
                File(dest, item.targetName).apply { check(createNewFile()) { "created twice" } }

            override fun copy(plain: File, target: File): Long {
                if (target.name in refusedTargets) throw IOException("export destination refused")
                plain.copyTo(target, overwrite = true)
                // A copy cut short, as when the private file is erased in
                // place while it is being read.
                return if (target.name in shortTargets) plain.length() - 1 else plain.length()
            }

            override fun writeTimestamp(item: ExportPlan.Item, target: File) = target.writeText(item.kind.name)
        }

        fun run(
            plan: List<ExportPlan.Item>,
            sources: Map<String, File>,
            isActive: () -> Boolean = { true },
            onItem: (Int, Int) -> Unit = { _, _ -> },
        ): ExportOutcome = ExportRun(
            decrypt = { sealed, out ->
                if (sealed.name in undecryptable) {
                    out.writeText("partial plaintext of ${sealed.name}")
                    throw failure()
                }
                sealed.copyTo(out, overwrite = true)
            },
            secureDelete = { secureDeleted.add(it); it.delete() },
            destination = destination,
        ).run(plan, sources, plain, isActive, onItem)
    }

    private fun sources(vararg names: String): Map<String, File> =
        names.associateWith { File(enc, it).apply { writeText("content of $it") } }

    private fun exported(): Set<String> = dest.list()?.toSet().orEmpty()

    @Test
    fun `an object that does not decrypt is excluded and counted, the rest is exported`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm", "000003.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val fakes = Fakes(undecryptable = setOf("000002.strm"))

        val outcome = fakes.run(plan, sources)

        assertEquals(ExportOutcome(written = 3, undecryptable = 1, timestampLeftOut = false), outcome)
        // The plan's names are kept: the excluded chunk leaves a gap.
        assertEquals(setOf("metadata.json", "part-0001.mp4", "part-0003.mp4"), exported())
        assertEquals("content of 000003.strm", File(dest, "part-0003.mp4").readText())
    }

    @Test
    fun `the excluded object leaves no plaintext, privately or at the destination`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val fakes = Fakes(undecryptable = setOf("000001.strm"))

        fakes.run(plan, sources)

        assertFalse("private plaintext left behind", plain.exists())
        assertEquals(listOf(plain, plain), fakes.secureDeleted)
        assertFalse("a file was created for the excluded object", File(dest, "part-0001.mp4").exists())
        for (f in dest.listFiles().orEmpty()) assertFalse(f.readText().contains("partial plaintext"))
    }

    @Test
    fun `every planned item counts in the progress, written or excluded`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val progress = ArrayList<Pair<Int, Int>>()

        Fakes(undecryptable = setOf("000001.strm")).run(plan, sources) { done, total -> progress.add(done to total) }

        assertEquals(listOf(1 to 3, 2 to 3, 3 to 3), progress)
    }

    @Test
    fun `nothing decrypts, nothing is written and the outcome says so`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)

        val outcome = Fakes(undecryptable = sources.keys).run(plan, sources)

        assertEquals(ExportOutcome(written = 0, undecryptable = 2, timestampLeftOut = false), outcome)
        assertTrue(outcome.nothingWritten)
        assertEquals(emptySet<String>(), exported())
        assertFalse(plain.exists())
    }

    @Test
    fun `an excluded chunk takes the timestamp proof and its salt out with it`() {
        layout()
        val sources = sources("000000.strm", "000001.strm", "000002.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = true)

        val outcome = Fakes(undecryptable = setOf("000002.strm")).run(plan, sources)

        assertEquals(ExportOutcome(written = 2, undecryptable = 1, timestampLeftOut = true), outcome)
        assertEquals(setOf("metadata.json", "part-0001.mp4"), exported())
    }

    @Test
    fun `an excluded metadata object keeps the timestamp proof, which commits to the chunks only`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = true)

        val outcome = Fakes(undecryptable = setOf("000000.strm")).run(plan, sources)

        assertEquals(ExportOutcome(written = 3, undecryptable = 1, timestampLeftOut = false), outcome)
        assertEquals(setOf("part-0001.mp4", "timestamp.ots", "timestamp.otssalt"), exported())
    }

    @Test
    fun `the timestamp items are written after the recordings, wherever the plan lists them`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = true)
        val reordered = plan.filter { it.sourceName == null } + plan.filter { it.sourceName != null }

        val outcome = Fakes(undecryptable = setOf("000001.strm")).run(reordered, sources)

        assertTrue(outcome.timestampLeftOut)
        assertEquals(setOf("metadata.json"), exported())
    }

    @Test
    fun `a write to the destination fails the export, and the private copy still goes`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val fakes = Fakes(refusedTargets = setOf("part-0001.mp4"))

        try {
            fakes.run(plan, sources)
            fail("a refused write must fail the export")
        } catch (e: IOException) {
            assertEquals("export destination refused", e.message)
        }
        assertFalse(plain.exists())
        assertEquals(listOf(plain, plain), fakes.secureDeleted)
    }

    @Test
    fun `a local I-O error is not an object that does not decrypt`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val fakes = Fakes(undecryptable = setOf("000001.strm"), failure = { FfiException.Io("disk full") })

        try {
            fakes.run(plan, sources)
            fail("a local I/O error must fail the export")
        } catch (e: FfiException.Io) {
            // expected
        }
        assertFalse(plain.exists())
    }

    @Test
    fun `a cancellation stops the export`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        var calls = 0

        try {
            Fakes().run(plan, sources, isActive = { calls++ == 0 })
            fail("a cancelled export must stop")
        } catch (e: CancellationException) {
            // expected
        }
        assertEquals(setOf("metadata.json"), exported())
    }

    @Test
    fun `a cancellation seen during the last copy still stops the export`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val copies = plan.count { it.kind == ExportPlan.Kind.VIDEO || it.kind == ExportPlan.Kind.METADATA }
        var checks = 0
        // Active for every check before each item and after every copy but
        // the last: the cancellation lands while the last file is copied.
        val activeChecks = 2 * copies - 1

        try {
            Fakes().run(plan, sources, isActive = { checks++ < activeChecks })
            fail("a cancellation during the last copy must stop the export")
        } catch (e: CancellationException) {
            // expected: the caller removes the folder
        }
        assertFalse(plain.exists())
    }

    @Test
    fun `a copy shorter than its private file fails the export`() {
        layout()
        val sources = sources("000000.strm", "000001.strm")
        val plan = ExportPlan.plan(sources.keys.toList(), otsMatched = false)
        val video = plan.first { it.kind == ExportPlan.Kind.VIDEO }.targetName

        try {
            Fakes(shortTargets = setOf(video)).run(plan, sources)
            fail("a truncated copy must fail the export")
        } catch (e: IOException) {
            // expected
        }
        assertFalse(plain.exists())
    }
}
