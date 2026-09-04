package org.stream.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

/**
 * Pins the [SecureWipe.wipe] ByteBuffer contract that the HEVC encoder depends
 * on: the call reports whether the bytes were ACTUALLY overwritten, so a
 * read-only codec output buffer — which cannot be scrubbed in place — comes
 * back `false` instead of a silent no-op (WP-F4, audit 2026-06-28, L-9). The
 * `assertFalse` on the read-only buffer is therefore not an edge case to
 * relax: it is what keeps the silent no-op from coming back.
 *
 * Pure JVM (SecureRandom + nio ByteBuffer), no Android framework — which is why
 * it lives in the plain `src/test` set: `gradlew :stream-crypto:testDebugUnitTest`
 * replays it without a device. Note that nothing in CI runs the Gradle test
 * tasks today (the workflows cover Rust, the server and semgrep), so this guard
 * only fires when someone runs it by hand.
 */
class SecureWipeTest {

    @Test
    fun wipe_writableHeapBuffer_returnsTrue_andZeroesRegion() {
        val buf = ByteBuffer.allocate(64)
        for (i in 0 until 64) buf.put(i, 0x5A.toByte())
        buf.position(0); buf.limit(64)

        val wiped = SecureWipe.wipe(buf)

        assertTrue("writable buffer must report a real wipe", wiped)
        // The zero pass is last, so the region must end all-zero.
        for (i in 0 until 64) assertEquals("byte $i", 0, buf.get(i).toInt())
        // Position/limit restored for the caller.
        assertEquals(0, buf.position())
        assertEquals(64, buf.limit())
    }

    @Test
    fun wipe_directWritableBuffer_returnsTrue_andZeroed() {
        val buf = ByteBuffer.allocateDirect(48)
        for (i in 0 until 48) buf.put(i, 0xFF.toByte())
        buf.position(0); buf.limit(48)

        val wiped = SecureWipe.wipe(buf)

        assertTrue(wiped)
        for (i in 0 until 48) assertEquals(0, buf.get(i).toInt())
    }

    @Test
    fun wipe_readOnlyBuffer_returnsFalse_andLeavesBytesUntouched() {
        val backing = ByteBuffer.allocate(32)
        val known = ByteArray(32) { (it + 1).toByte() }
        for (i in 0 until 32) backing.put(i, known[i])
        val ro = backing.asReadOnlyBuffer()
        ro.position(0); ro.limit(32)

        val wiped = SecureWipe.wipe(ro)

        assertFalse("read-only buffer cannot be scrubbed → must report false", wiped)
        // The underlying bytes are untouched: the no-op did not somehow mutate.
        val after = ByteArray(32) { backing.get(it) }
        assertArrayEquals(known, after)
    }

    @Test
    fun wipe_nullBuffer_returnsFalse() {
        assertFalse(SecureWipe.wipe(null as ByteBuffer?))
    }

    @Test
    fun wipe_emptyRegion_returnsFalse() {
        val buf = ByteBuffer.allocate(16)
        buf.position(8); buf.limit(8) // zero-length [8,8)
        assertFalse(SecureWipe.wipe(buf))
    }

    @Test
    fun wipe_onlyScrubsPositionToLimitSubRegion() {
        val buf = ByteBuffer.allocate(10)
        for (i in 0 until 10) buf.put(i, (i + 1).toByte()) // 1..10
        buf.position(2); buf.limit(7) // scrub indices [2,7)

        val wiped = SecureWipe.wipe(buf)

        assertTrue(wiped)
        // Position/limit restored for the caller.
        assertEquals(2, buf.position())
        assertEquals(7, buf.limit())
        // Absolute get(int) is bounded by limit, not capacity — widen it to
        // inspect the whole backing now that we've asserted it was restored.
        buf.limit(10)
        // Outside the scrubbed sub-region is untouched.
        assertEquals(1, buf.get(0).toInt())
        assertEquals(2, buf.get(1).toInt())
        assertEquals(8, buf.get(7).toInt())
        assertEquals(10, buf.get(9).toInt())
        // Inside the sub-region is zeroed.
        for (i in 2 until 7) assertEquals("byte $i", 0, buf.get(i).toInt())
    }
}
