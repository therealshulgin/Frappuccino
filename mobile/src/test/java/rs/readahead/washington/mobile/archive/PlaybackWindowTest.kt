package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PlaybackWindowTest {

    @Test
    fun `the window is the current chunk and a few after it`() {
        val w = PlaybackWindow(size = 10, ahead = 2)
        assertEquals(listOf(0, 1, 2), w.wanted())
        assertTrue(w.advance())
        assertEquals(listOf(1, 2, 3), w.wanted())
    }

    @Test
    fun `the window shrinks at the end of the report`() {
        val w = PlaybackWindow(size = 3, ahead = 2)
        w.advance()
        w.advance()
        assertEquals(listOf(2), w.wanted())
        assertFalse(w.advance())
        assertEquals(2, w.current)
    }

    @Test
    fun `watched chunks are erased as soon as playback leaves them`() {
        val w = PlaybackWindow(size = 10, ahead = 2)
        w.advance()
        assertEquals(listOf(0), w.toErase(listOf(0, 1, 2)))
        w.advance()
        assertEquals(listOf(0, 1), w.toErase(listOf(2, 1, 0, 3)))
    }

    @Test
    fun `going back erases what got out of the window ahead`() {
        val w = PlaybackWindow(size = 10, ahead = 1)
        repeat(5) { w.advance() }
        assertTrue(w.back())
        assertEquals(listOf(4, 5), w.wanted())
        assertEquals(listOf(6), w.toErase(listOf(4, 5, 6)))
    }

    @Test
    fun `an empty report wants nothing and cannot move`() {
        val w = PlaybackWindow(size = 0)
        assertEquals(emptyList<Int>(), w.wanted())
        assertFalse(w.advance())
        assertFalse(w.back())
        assertFalse(w.hasNext)
        assertFalse(w.hasPrevious)
    }

    @Test
    fun `no lookahead keeps exactly one chunk in clear`() {
        val w = PlaybackWindow(size = 4, ahead = 0)
        assertEquals(listOf(0), w.wanted())
        w.advance()
        assertEquals(listOf(0, 2), w.toErase(listOf(0, 1, 2)))
    }
}
