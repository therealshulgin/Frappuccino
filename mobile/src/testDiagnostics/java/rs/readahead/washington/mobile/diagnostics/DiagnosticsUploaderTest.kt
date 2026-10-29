package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.util.Random
import java.util.zip.GZIPInputStream

class DiagnosticsUploaderTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val store by lazy { SpillStore(File(tmp.root, "diag"), { d -> File(d.parentFile, "gone").takeIf { d.renameTo(it) } }, maxFileBytes = 64) }
    private val sent = ArrayList<Pair<String, String>>() // body text, install id

    private fun uploader(status: (Int) -> Int, logcat: String = "", id: () -> String = { "a".repeat(32) }) =
        DiagnosticsUploader(
            store = store,
            installId = id,
            profile = { "build.model=Test" },
            logcat = { logcat },
            send = { body, installId ->
                sent += gunzip(body) to installId
                status(sent.size)
            },
        )

    private fun gunzip(b: ByteArray) = GZIPInputStream(b.inputStream()).readBytes().toString(Charsets.UTF_8)

    private fun fill(vararg lines: String) = assertTrue(store.write(lines.toList(), store.generation))

    private fun files() = (store.dir.listFiles() ?: emptyArray()).map { it.name }.sorted()

    @Test
    fun `one body holds the profile, then the spill files oldest first, then the logcat`() {
        fill("x".repeat(40), "y".repeat(40)) // two files
        assertTrue(uploader({ 204 }, logcat = "logcat line\n").run())
        assertEquals(1, sent.size)
        val body = sent[0].first
        val profile = body.indexOf("### device profile\nbuild.model=Test")
        val first = body.indexOf("### app log spill-000001.log")
        val second = body.indexOf("### app log spill-000002.log")
        val logcat = body.indexOf("### logcat\nlogcat line")
        assertTrue(body, profile == 0 && first > profile && second > first && logcat > second)
        assertEquals("a".repeat(32), sent[0].second)
    }

    @Test
    fun `a 2xx deletes the files sent`() {
        fill("x".repeat(40))
        assertTrue(uploader({ 200 }).run())
        assertEquals(emptyList<String>(), files())
    }

    @Test
    fun `400 and 413 delete them too, so a refused body is not resent forever`() {
        for (code in listOf(400, 413)) {
            fill("x".repeat(40))
            assertTrue(uploader({ code }).run())
            assertEquals("after $code", emptyList<String>(), files())
        }
    }

    @Test
    fun `429, 5xx, other statuses and IOException keep the files and ask for a retry`() {
        for (code in listOf(429, 500, 503, 404)) {
            fill("x".repeat(40))
            assertFalse("status $code", uploader({ code }).run())
            assertTrue("status $code", files().isNotEmpty())
        }
        val before = files()
        val failing = DiagnosticsUploader(store, { "a".repeat(32) }, { "" }, { "" }, { _, _ -> throw IOException("down") })
        assertFalse(failing.run())
        assertTrue(files().containsAll(before))
    }

    @Test
    fun `nothing to send sends nothing`() {
        assertTrue(uploader({ 204 }).run())
        assertEquals(0, sent.size)
    }

    @Test
    fun `a wipe before the id is read ends the pass without sending`() {
        fill("x".repeat(40))
        // A logcat capture is taken after the wipe too: without the check
        // before each request, it would leave under the fresh id.
        val u = uploader({ 204 }, logcat = "logcat line\n", id = { store.detach(); "b".repeat(32) })
        assertTrue(u.run())
        assertEquals(0, sent.size)
    }

    @Test
    fun `a wipe between two requests stops the second one and deletes nothing more`() {
        val big = SpillStore(File(tmp.root, "diag2"), { d -> File(d.parentFile, "gone2").takeIf { d.renameTo(it) } }, maxFileBytes = 1000)
        val rnd = Random(1)
        val alnum = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        // Three files of one barely compressible 600-character line each: one
        // part fits in a 700-byte body, two do not.
        val lines = (1..3).map { (1..600).map { alnum[rnd.nextInt(alnum.size)] }.joinToString("") }
        assertTrue(big.write(lines, big.generation))
        val u = DiagnosticsUploader(
            store = big,
            installId = { "a".repeat(32) },
            profile = { "p" },
            logcat = { "" },
            send = { _, _ ->
                sent += "" to ""
                big.detach()
                204
            },
            maxRequestBytes = 700,
        )
        assertTrue(u.run())
        assertEquals(1, sent.size)
        // The first request's file is not deleted either: the deletion is
        // refused once the generation moved, and the files went with the wipe.
        assertEquals(3, File(tmp.root, "gone2").listFiles()!!.size)
    }

    @Test
    fun `bodies stay within the limit, split by part, every part sent once`() {
        val max = 4096
        val rnd = Random(7)
        val parts = (1..6).map { i ->
            val text = (1..60).joinToString("\n") { "p$i " + ByteArray(24).also(rnd::nextBytes).joinToString("") { b -> "%02x".format(b) } }
            DiagnosticsUploader.Part("part$i", text.toByteArray(), File("f$i"))
        }
        val requests = DiagnosticsUploader.plan("### device profile\np\n".toByteArray(), parts, max)
        assertTrue(requests.size > 1)
        for (r in requests) assertTrue("body of ${r.body.size} bytes", r.body.size <= max)
        assertEquals(parts.map { it.file }, requests.flatMap { it.files })
        for (r in requests) assertTrue(gunzip(r.body).startsWith("### device profile\np\n"))
    }

    @Test
    fun `a part too large on its own is cut to its most recent lines`() {
        val max = 2048
        val rnd = Random(3)
        val text = (1..400).joinToString("\n") { "line$it " + ByteArray(16).also(rnd::nextBytes).joinToString("") { b -> "%02x".format(b) } }
        val requests = DiagnosticsUploader.plan("h\n".toByteArray(), listOf(DiagnosticsUploader.Part("big", text.toByteArray(), File("big"))), max)
        assertEquals(1, requests.size)
        assertTrue(requests[0].body.size <= max)
        val body = gunzip(requests[0].body)
        assertTrue(body.contains("[cut: the first "))
        assertTrue(body.contains("line400 "))
        assertFalse(body.contains("line1 "))
    }

    @Test
    fun `the relay's statuses map to what happens to the files`() {
        assertEquals(DiagnosticsUploader.Outcome.SENT, DiagnosticsUploader.outcomeOf(204))
        assertEquals(DiagnosticsUploader.Outcome.REFUSED, DiagnosticsUploader.outcomeOf(400))
        assertEquals(DiagnosticsUploader.Outcome.REFUSED, DiagnosticsUploader.outcomeOf(413))
        assertEquals(DiagnosticsUploader.Outcome.RETRY, DiagnosticsUploader.outcomeOf(429))
        assertEquals(DiagnosticsUploader.Outcome.RETRY, DiagnosticsUploader.outcomeOf(507))
    }
}
