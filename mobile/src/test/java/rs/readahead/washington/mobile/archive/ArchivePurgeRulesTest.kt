package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ArchivePurgeRulesTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun `the last one alive purges`() {
        // No screen, no batch: purge.
        assertTrue(ArchivePurgeRules.shouldPurge(attachedScreens = 0, batchRunning = false))
        // A batch still running purges itself when it ends.
        assertFalse(ArchivePurgeRules.shouldPurge(attachedScreens = 0, batchRunning = true))
        // A screen still attached (the rescue screen under the player).
        assertFalse(ArchivePurgeRules.shouldPurge(attachedScreens = 1, batchRunning = false))
        assertFalse(ArchivePurgeRules.shouldPurge(attachedScreens = 2, batchRunning = true))
    }

    @Test
    fun `a counter that went below zero still purges`() {
        assertTrue(ArchivePurgeRules.shouldPurge(attachedScreens = -1, batchRunning = false))
    }

    @Test
    fun `trash names are recognised and nothing else is`() {
        val token = RescueNames.newToken()
        val trash = ArchivePurgeRules.trashName("archive_view", token)
        assertEquals("archive_view.trash-$token", trash)
        assertTrue(ArchivePurgeRules.isTrashOf("archive_view", trash))
        assertFalse(ArchivePurgeRules.isTrashOf("archive_view", "archive_view"))
        assertFalse(ArchivePurgeRules.isTrashOf("archive_view", "archive_viewer.trash-$token"))
        assertFalse(ArchivePurgeRules.isTrashOf("archive_recovery", trash))
    }

    @Test
    fun `the background timer purges under a screen left in the background`() {
        // A screen left behind Home stays attached for the life of the
        // process: under the last-one-alive rule the timer purged nothing.
        assertTrue(ArchivePurgeRules.shouldPurgeOnBackgroundTimer(attachedScreens = 1, batchRunning = false))
        assertTrue(ArchivePurgeRules.shouldPurgeOnBackgroundTimer(attachedScreens = 2, batchRunning = false))
        assertTrue(ArchivePurgeRules.shouldPurgeOnBackgroundTimer(attachedScreens = 0, batchRunning = false))
        // A batch running: no purge now, the timer comes back after it.
        assertFalse(ArchivePurgeRules.shouldPurgeOnBackgroundTimer(attachedScreens = 1, batchRunning = true))
        assertFalse(ArchivePurgeRules.shouldPurgeOnBackgroundTimer(attachedScreens = 0, batchRunning = true))
    }

    @Test
    fun `plaintext is erased first across every root, the old decrypt buffer included`() {
        val view = tmp.newFolder("archive_view.trash-a")
        val enc = File(view, "tok/enc").apply { mkdirs() }
        val plain = File(view, "tok/plain").apply { mkdirs() }
        File(enc, "o000001.bin").writeText("cipher")
        File(plain, "p000000-x.mp4").writeText("clear")
        val recovery = tmp.newFolder("archive_recovery.trash-b")
        File(recovery, "some-report").mkdirs()
        File(recovery, "some-report/000001.mp4").writeText("clear")

        val order = ArchivePurgeRules.eraseOrder(listOf(view, recovery)) { root ->
            ArchivePurgeRules.isTrashOf("archive_recovery", root.name)
        }
        val firstCipher = order.indexOfFirst { it.parentFile?.name == "enc" }
        val plaintext = order.filter { it.parentFile?.name == "plain" || it.path.startsWith(recovery.path) }
        assertEquals(3, order.size)
        assertEquals(2, plaintext.size)
        assertTrue(plaintext.all { order.indexOf(it) < firstCipher })
    }
}
