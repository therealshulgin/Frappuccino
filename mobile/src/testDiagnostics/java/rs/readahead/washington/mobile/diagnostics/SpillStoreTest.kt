package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SpillStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun store(maxFileBytes: Long = 100, maxFiles: Int = 4, maxFileCount: Int = 256): SpillStore {
        val dir = File(tmp.root, "diag")
        return SpillStore(
            dir, { d -> File(d.parentFile, d.name + ".wipe-1").takeIf { d.renameTo(it) } },
            maxFileBytes, maxFiles, maxFileCount,
        )
    }

    private fun line(n: Int) = "line-%03d-".format(n) + "x".repeat(10) // 19 bytes + newline

    @Test
    fun `a file is closed when the next line would take it past the limit`() {
        val s = store(maxFileBytes = 100)
        assertTrue(s.write((1..5).map(::line), s.generation)) // 5 x 20 = 100 bytes: fits
        assertEquals(1, s.dir.listFiles()!!.size)
        s.write(listOf(line(6)), s.generation)
        val files = s.dir.listFiles()!!.sortedBy { it.name }
        assertEquals(listOf("spill-000001.log", "spill-000002.log"), files.map { it.name })
        assertEquals(100L, files[0].length())
        assertTrue(files.all { it.length() <= 100 })
    }

    @Test
    fun `at most maxFiles times maxFileBytes is kept, the oldest files dropped`() {
        val s = store(maxFileBytes = 20, maxFiles = 4)
        s.write((1..10).map(::line), s.generation) // one line per file
        val names = s.dir.listFiles()!!.map { it.name }.sorted()
        assertEquals(listOf("spill-000007.log", "spill-000008.log", "spill-000009.log", "spill-000010.log"), names)
        assertEquals(line(10) + "\n", File(s.dir, "spill-000010.log").readText())
    }

    @Test
    fun `a relay that keeps failing does not cost the oldest lines while there is room`() {
        val s = store(maxFileBytes = 100, maxFiles = 4) // 400 bytes in all
        s.write(listOf(line(1)), s.generation)
        // Each failed pass closes the current file and deletes nothing; the
        // next line opens another one.
        for (n in 2..7) {
            s.closeForUpload(s.generation)
            s.write(listOf(line(n)), s.generation)
        }
        assertEquals(7, s.dir.listFiles()!!.size) // 140 bytes
        assertEquals(line(1) + "\n", File(s.dir, "spill-000001.log").readText())
    }

    @Test
    fun `many small files are capped by number too`() {
        val s = store(maxFileBytes = 100, maxFiles = 4, maxFileCount = 3)
        for (n in 1..5) {
            s.write(listOf(line(n)), s.generation)
            s.closeForUpload(s.generation)
        }
        s.write(listOf(line(6)), s.generation)
        val names = s.dir.listFiles()!!.map { it.name }.sorted()
        assertEquals(listOf("spill-000004.log", "spill-000005.log", "spill-000006.log"), names)
    }

    @Test
    fun `the file being written is kept even when it alone is over the bound`() {
        val s = store(maxFileBytes = 20, maxFiles = 1)
        val long = "y".repeat(50)
        assertTrue(s.write(listOf(long), s.generation))
        assertEquals(long + "\n", File(s.dir, "spill-000001.log").readText())
    }

    @Test
    fun `an upload gets the closed files, oldest first, and the current one is closed for it`() {
        val s = store(maxFileBytes = 40)
        s.write((1..3).map(::line), s.generation)
        val closed = s.closeForUpload(s.generation)
        assertEquals(listOf("spill-000001.log", "spill-000002.log"), closed.map { it.name })
        // The next line starts a new file, never appended to one being sent.
        s.write(listOf(line(4)), s.generation)
        assertEquals(line(3) + "\n", closed[1].readText())
        assertTrue(File(s.dir, "spill-000003.log").exists())
    }

    @Test
    fun `an upload on an empty store creates nothing`() {
        val s = store()
        assertEquals(emptyList<File>(), s.closeForUpload(s.generation))
        assertFalse(s.dir.exists())
    }

    @Test
    fun `sent files are deleted, the current one is not`() {
        val s = store(maxFileBytes = 40)
        s.write((1..3).map(::line), s.generation)
        val closed = s.closeForUpload(s.generation)
        s.write(listOf(line(4)), s.generation)
        assertTrue(s.delete(closed + File(s.dir, "spill-000003.log"), s.generation))
        assertEquals(listOf("spill-000003.log"), s.dir.listFiles()!!.map { it.name })
    }

    @Test
    fun `the wipe renames the directory and stale writes and deletions do nothing`() {
        val s = store()
        val before = s.generation
        s.write(listOf(line(1)), before)
        val closed = s.closeForUpload(before)
        val moved = s.detach()
        assertEquals("diag.wipe-1", moved!!.name)
        assertFalse(s.dir.exists())
        // A write prepared before the wipe lands nowhere.
        assertFalse(s.write(listOf(line(2)), before))
        assertFalse(s.dir.exists())
        // After the wipe, a new line goes to a fresh directory, numbered from 1.
        assertTrue(s.write(listOf(line(3)), s.generation))
        assertEquals(listOf("spill-000001.log"), s.dir.listFiles()!!.map { it.name })
        // Deleting by the old names would hit the fresh file: refused.
        assertFalse(s.delete(closed, before))
        assertTrue(File(s.dir, "spill-000001.log").exists())
        assertEquals(emptyList<File>(), s.closeForUpload(before))
    }

    @Test
    fun `a wipe with nothing on disk returns nothing`() {
        assertNull(store().detach())
    }

    @Test
    fun `numbering resumes after a restart`() {
        val first = store(maxFileBytes = 40)
        first.write((1..3).map(::line), first.generation)
        // A new process continues the highest file, then rotates past it.
        val second = store(maxFileBytes = 40)
        second.write((4..5).map(::line), second.generation)
        assertEquals(line(3) + "\n" + line(4) + "\n", File(second.dir, "spill-000002.log").readText())
        assertEquals(line(5) + "\n", File(second.dir, "spill-000003.log").readText())
    }
}
