package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The emergency wipe's file steps: every rescue directory is renamed before
 * anything is erased, and the erase takes the plaintext of every root before
 * any ciphertext.
 */
class ArchiveLocalDataTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun `the panic rename is synchronous, erases nothing, and can run twice`() {
        val noBackup = tmp.newFolder("no_backup")
        val cache = tmp.newFolder("cache")
        val view = File(noBackup, "archive_view")
        File(view, "tok/enc").mkdirs()
        File(view, "tok/enc/o000001.bin").writeText("cipher")
        val recovery = File(cache, "archive_recovery")
        recovery.mkdirs()
        File(recovery, "clear.mp4").writeText("clear")

        val trash = ArchiveLocalData.renameForPanic(view, recovery)
        // The names the data had are gone as soon as the call returns ...
        assertFalse(view.exists())
        assertFalse(recovery.exists())
        assertEquals(2, trash.size)
        assertTrue(ArchivePurgeRules.isTrashOf("archive_view", trash[0].name))
        assertTrue(ArchivePurgeRules.isTrashOf("archive_recovery", trash[1].name))
        // ... and nothing was erased yet.
        assertTrue(File(trash[0], "tok/enc/o000001.bin").isFile)
        assertTrue(File(trash[1], "clear.mp4").isFile)

        // A second call renames nothing more and leaves the trash alone.
        assertEquals(emptyList<File>(), ArchiveLocalData.renameForPanic(view, recovery))
        assertTrue(trash.all { it.isDirectory })
    }

    @Test
    fun `the panic split puts every report's plain directory with the plaintext`() {
        // The whole view directory, renamed: one report as is, one already
        // renamed by its own purge.
        val view = tmp.newFolder("archive_view.trash-a")
        for (sub in listOf("tok1/enc", "tok1/plain", "tok1/unverifiable", "tok2.trash-b/plain")) {
            File(view, sub).mkdirs()
        }
        // One report purged on its own (a root that is a report directory).
        val oneReport = tmp.newFolder("tok3.trash-c")
        File(oneReport, "plain").mkdirs()
        File(oneReport, "enc").mkdirs()
        // The decrypt buffer of earlier versions: plaintext as a whole.
        val recovery = tmp.newFolder("archive_recovery.trash-d")
        File(recovery, "report").mkdirs()

        val (plain, rest) = ArchivePurgeRules.panicSplit(listOf(view, oneReport, recovery)) {
            it == recovery
        }

        assertEquals(
            setOf(File(view, "tok1/plain"), File(view, "tok2.trash-b/plain"), File(oneReport, "plain"), recovery),
            plain.toSet(),
        )
        assertEquals(listOf(view, oneReport), rest)
    }

    @Test
    fun `the erase takes the plaintext of every root before any ciphertext`() {
        val view = tmp.newFolder("archive_view.trash-a")
        File(view, "tok/enc").mkdirs()
        File(view, "tok/plain").mkdirs()
        File(view, "tok/enc/o000001.bin").writeText("cipher")
        File(view, "tok/enc/o000002.bin").writeText("cipher")
        File(view, "tok/plain/export.tmp").writeText("clear")
        // The decrypt buffer of earlier versions: plaintext in directories
        // named after reports, never under a `plain` directory.
        val recovery = tmp.newFolder("archive_recovery.trash-b")
        File(recovery, "report").mkdirs()
        File(recovery, "report/000001.mp4").writeText("clear")

        val erased = ArrayList<File>()
        ArchiveLocalData.eraseTrees(
            listOf(view, recovery),
            delete = { erased.add(it); it.delete() },
            pause = { true },
        )

        val isPlain = { f: File -> f.parentFile?.name == "plain" || f.path.startsWith(recovery.path) }
        assertEquals(4, erased.size)
        val lastPlain = erased.indexOfLast(isPlain)
        val firstCipher = erased.indexOfFirst { !isPlain(it) }
        assertTrue("plaintext erased after ciphertext: $erased", lastPlain < firstCipher)
        // Every tree is gone, directories included.
        assertFalse(view.exists())
        assertFalse(recovery.exists())
    }
}
