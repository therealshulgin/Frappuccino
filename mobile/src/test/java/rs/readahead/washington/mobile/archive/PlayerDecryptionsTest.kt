package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The player's decryption record across a trip to the background: every
 * chunk of the window is decrypted again on return, whether its decryption
 * was still queued or still running when the screen was hidden.
 */
class PlayerDecryptionsTest {

    private fun out(index: Int) = File("plain", RescueNames.newPlainFileName(index))

    @Test
    fun `chunks still queued when the screen was hidden are decrypted again on return`() {
        val d = PlayerDecryptions()
        // Opening the player schedules the window: 0 runs, 1 and 2 queue.
        val g0 = d.claim(0)!!
        assertNotNull(d.claim(1))
        assertNotNull(d.claim(2))
        assertTrue(d.finish(0, g0, out(0)))
        // Screen hidden: the decrypt thread is shut down, 1 and 2 never run
        // and never release their claims themselves.
        d.wipe()
        // Back on screen: the whole window is claimed again.
        assertNotNull(d.claim(0))
        assertNotNull(d.claim(1))
        assertNotNull(d.claim(2))
    }

    @Test
    fun `the chunk still decrypting when the screen was hidden is decrypted again on return`() {
        val d = PlayerDecryptions()
        val stale = d.claim(0)!!
        d.wipe()
        // Back on screen before the old decryption returned (a native call a
        // shutdown does not interrupt).
        val fresh = d.claim(0)
        assertNotNull(fresh)
        // The old decryption ends: its output is not the window's, and it
        // leaves the new claim alone.
        assertFalse(d.finish(0, stale, out(0)))
        assertNull(d.claim(0))
        // The new one is recorded.
        val written = out(0)
        assertTrue(d.finish(0, fresh!!, written))
        assertEquals(written, d.ready(0))
    }

    @Test
    fun `one decryption at a time per chunk within a generation`() {
        val d = PlayerDecryptions()
        val g = d.claim(3)!!
        assertNull(d.claim(3))
        assertTrue(d.finish(3, g, out(3)))
        // Decrypted: not claimed again until it leaves the window.
        assertNull(d.claim(3))
        assertNotNull(d.remove(3))
        assertNotNull(d.claim(3))
    }

    @Test
    fun `a failed decryption releases its claim`() {
        val d = PlayerDecryptions()
        val g = d.claim(1)!!
        assertFalse(d.finish(1, g, null))
        assertNotNull(d.claim(1))
    }

    @Test
    fun `a wipe hands back every decrypted copy for erasure`() {
        val d = PlayerDecryptions()
        val a = out(0)
        val b = out(1)
        d.finish(0, d.claim(0)!!, a)
        d.finish(1, d.claim(1)!!, b)
        assertEquals(setOf(a, b), d.wipe().toSet())
        assertEquals(emptySet<Int>(), d.decryptedIndices())
    }
}
