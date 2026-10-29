package rs.readahead.washington.mobile.diagnostics

import org.stream.crypto.SecureDirWiper
import java.io.File

/**
 * What a pre-release test build's diagnostics leave on a phone, taken away by
 * the production build that replaces it: the production facade
 * (src/diagnosticsOff/java) calls [detach] at each start. Nothing in a
 * production build reads or erases these files otherwise, and its emergency
 * wipe does not know them, so without this a phone updated from a test build
 * would keep the test build's log for good.
 *
 * Main source set, and plain JVM, so that a unit test holds it in every
 * build, production versions included.
 */
internal object DiagnosticsLeftovers {

    /**
     * Take what a test build left out of reach, now: the log directory is
     * renamed aside and the install id's preferences file deleted. Returns the
     * directories for the caller to erase in the background: those of an
     * erase that a process death interrupted, then the one just renamed.
     * Creates nothing when there is nothing to remove.
     *
     * The preferences file is deleted as a file: a production build never
     * opens it, so no copy of it is held in memory to outlive the file.
     */
    fun detach(filesDir: File): List<File> {
        // Listed before the rename: afterwards the directory just renamed would
        // be listed too, and erased twice at once.
        val interrupted = SecureDirWiper.leftovers(filesDir, listOf(DiagnosticsNames.DIR))
        val moved = SecureDirWiper.detach(File(filesDir, DiagnosticsNames.DIR))
        for (f in prefsFiles(filesDir)) f.delete()
        return interrupted + listOfNotNull(moved)
    }

    /**
     * The install id's preferences file, and the backup copy Android keeps
     * beside it while it writes the file (left behind if the process died
     * then).
     */
    fun prefsFiles(filesDir: File): List<File> {
        val dataDir = filesDir.parentFile ?: return emptyList()
        val dir = File(dataDir, "shared_prefs")
        val name = "${DiagnosticsNames.PREFS}.xml"
        return listOf(File(dir, name), File(dir, "$name.bak"))
    }
}
