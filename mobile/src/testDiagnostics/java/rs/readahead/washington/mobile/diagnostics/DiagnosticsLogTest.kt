package rs.readahead.washington.mobile.diagnostics

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import timber.log.Timber
import java.io.File
import java.util.concurrent.Executor

/** The writer, the Timber tree and the crash recorder, against a real store. */
class DiagnosticsLogTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** Runs the writer's task only when told to: "off the calling thread". */
    private class ManualExecutor : Executor {
        val tasks = ArrayList<Runnable>()
        override fun execute(command: Runnable) { tasks += command }
        fun runAll() { while (tasks.isNotEmpty()) tasks.removeAt(0).run() }
    }

    private val executor = ManualExecutor()
    private val store by lazy { SpillStore(File(tmp.root, "diag"), { it }) }
    private val trees = ArrayList<Timber.Tree>()

    private fun log(capacity: Int = 16) = DiagnosticsLog(store, executor, capacity)

    private fun stored(): String =
        (store.dir.listFiles() ?: emptyArray()).sortedBy { it.name }.joinToString("") { it.readText() }

    private fun plant(tree: Timber.Tree) { Timber.plant(tree); trees += tree }

    @After
    fun uproot() { trees.forEach(Timber::uproot) }

    @Test
    fun `the caller only queues, the writer formats, redacts and stores`() {
        val log = log()
        assertTrue(log.submit(Entry(0L, 4, "Tag", "main", "session 0123456789abcdef0123456789abcdef open")))
        assertEquals("", stored())
        executor.runAll()
        assertEquals("1970-01-01T00:00:00.000Z I/Tag [main]: session <hex> open\n", stored())
    }

    @Test
    fun `a full queue drops the entry and the count is written`() {
        val log = log(capacity = 2)
        assertTrue(log.submit(Entry(0L, 3, "T", "t", "a")))
        assertTrue(log.submit(Entry(0L, 3, "T", "t", "b")))
        assertFalse(log.submit(Entry(0L, 3, "T", "t", "c")))
        assertEquals(1L, log.droppedCount)
        executor.runAll()
        val text = stored()
        assertTrue(text, text.contains("W/FrappDiag: 1 log entries dropped (queue full)"))
        assertTrue(text.contains("D/T [t]: a") && text.contains("D/T [t]: b") && !text.contains("D/T [t]: c"))
    }

    @Test
    fun `a message with the recovery phrase across its lines is dropped whole`() {
        val log = log()
        log.submit(Entry(0L, 4, "T", "t", "first abaisser\nabandon\nabdiquer last"))
        log.submit(Entry(0L, 4, "T", "t", "kept"))
        executor.runAll()
        assertEquals("1970-01-01T00:00:00.000Z I/T [t]: kept\n", stored())
    }

    @Test
    fun `after the wipe nothing queued or submitted is stored`() {
        val log = log()
        log.submit(Entry(0L, 4, "T", "t", "before"))
        log.stopForWipe()
        store.detach()
        assertFalse(log.submit(Entry(0L, 4, "T", "t", "after")))
        executor.runAll()
        log.writeNow(Entry(0L, 7, "CRASH", "t", "late"))
        assertFalse(store.dir.exists())
    }

    @Test
    fun `a batch drained before the wipe and written after it lands nowhere`() {
        val log = log()
        log.submit(Entry(0L, 4, "T", "t", "before"))
        // The writer has read the generation and is about to write when the
        // wipe renames the directory: that is the store's generation check.
        val gen = store.generation
        store.detach()
        assertFalse(store.write(listOf("before"), gen))
        assertFalse(store.dir.exists())
    }

    @Test
    fun `the tree stores every priority, verbose and debug included, with the tag`() {
        val log = log()
        plant(DiagnosticsTree(log))
        Timber.tag("Cam").v("verbose line")
        Timber.tag("Cam").d("debug line")
        Timber.tag("Cam").e(IllegalStateException("boom"), "error line")
        executor.runAll()
        val text = stored()
        assertTrue(text, text.contains("V/Cam ["))
        assertTrue(text.contains("D/Cam [") && text.contains("debug line"))
        assertTrue(text.contains("E/Cam [") && text.contains("java.lang.IllegalStateException: boom"))
    }

    @Test
    fun `an untagged call is tagged with the calling class`() {
        val log = log()
        plant(DiagnosticsTree(log))
        Timber.i("untagged")
        executor.runAll()
        assertTrue(stored(), stored().contains("I/DiagnosticsLogTest [") && stored().contains("untagged"))
    }

    @Test
    fun `the tree ignores its own tag`() {
        val log = log()
        plant(DiagnosticsTree(log))
        Timber.tag(DiagnosticsTree.OWN_TAG).w("from the diagnostics code")
        executor.runAll()
        assertEquals("", stored())
    }

    @Test
    fun `a crash is written on the crashing thread, then handed on`() {
        val log = log()
        log.submit(Entry(0L, 4, "T", "t", "queued before the crash"))
        var handedOn: Throwable? = null
        val previous = Thread.UncaughtExceptionHandler { _, e -> handedOn = e }
        val crash = RuntimeException("fatal 0123456789abcdef0123")
        CrashRecorder(log, previous).uncaughtException(Thread.currentThread(), crash)
        // Written without the writer thread having run.
        val text = stored()
        assertTrue(text, text.contains("queued before the crash"))
        assertTrue(text.contains("A/CRASH [") && text.contains("FATAL EXCEPTION"))
        assertTrue(text.contains("java.lang.RuntimeException: fatal <hex>"))
        assertSame(crash, handedOn)
    }
}
