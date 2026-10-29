package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * What a production build removes from a phone that ran a pre-release test
 * build. Main source set on purpose: it runs in both channels, and in a
 * production build this is the only code of the diagnostics that does
 * anything.
 */
class DiagnosticsLeftoversTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun dataDir(): Pair<File, File> {
        val filesDir = File(tmp.root, "files").apply { mkdirs() }
        val prefsDir = File(tmp.root, "shared_prefs")
        return filesDir to prefsDir
    }

    @Test
    fun `what a test build left is taken out of reach and handed over for erasing`() {
        val (filesDir, prefsDir) = dataDir()
        val diag = File(filesDir, "diag").apply { mkdirs() }
        File(diag, "spill-000001.log").writeText("line\n")
        // An erase that a process death interrupted.
        val interrupted = File(filesDir, "diag.wipe-123").apply { mkdirs() }
        File(interrupted, "spill-000009.log").writeText("older\n")
        prefsDir.mkdirs()
        val prefs = File(prefsDir, "frappuccino_diag.xml").apply { writeText("<map/>") }
        val backup = File(prefsDir, "frappuccino_diag.xml.bak").apply { writeText("<map/>") }
        // Not the test build's: they stay.
        val otherPrefs = File(prefsDir, "frappuccino_other.xml").apply { writeText("<map/>") }
        val otherDir = File(filesDir, "diagnostics-notes").apply { mkdirs() }

        val dirs = DiagnosticsLeftovers.detach(filesDir)

        assertFalse("the log directory is still under its name", diag.exists())
        assertFalse("the install id is still there", prefs.exists())
        assertFalse(backup.exists())
        assertTrue(otherPrefs.exists())
        assertTrue(otherDir.exists())
        assertEquals(2, dirs.size)
        assertEquals(interrupted, dirs[0])
        assertTrue(dirs[1].name, dirs[1].name.startsWith("diag.wipe-"))
        assertEquals("line\n", File(dirs[1], "spill-000001.log").readText())
    }

    @Test
    fun `a phone that never ran a test build is left as it was`() {
        val (filesDir, _) = dataDir()
        assertEquals(emptyList<File>(), DiagnosticsLeftovers.detach(filesDir))
        assertEquals(listOf("files"), tmp.root.list()!!.toList())
        assertEquals(0, filesDir.list()!!.size)
    }

    @Test
    fun `the preferences file is the one the test build writes`() {
        val (filesDir, prefsDir) = dataDir()
        assertEquals(
            listOf(File(prefsDir, "${DiagnosticsNames.PREFS}.xml"), File(prefsDir, "${DiagnosticsNames.PREFS}.xml.bak")),
            DiagnosticsLeftovers.prefsFiles(filesDir),
        )
        assertEquals("frappuccino_diag", DiagnosticsNames.PREFS)
    }
}
