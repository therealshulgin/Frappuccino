package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.frappuccino.FfiException
import kotlin.coroutines.cancellation.CancellationException

/**
 * The mapping of the FFI errors onto the retry rules. The generated exception
 * classes are plain Kotlin: building one loads no native code.
 */
class RescueFailuresTest {

    @Test
    fun `a 429 is a rate limit carrying the relay's hint`() {
        assertEquals(Failure.RateLimited(0), RescueFailures.classify(FfiException.RateLimited(0uL)))
        assertEquals(Failure.RateLimited(90), RescueFailures.classify(FfiException.RateLimited(90uL)))
        assertEquals(FailureReason.RATE_LIMITED, RescueFailures.reason(FfiException.RateLimited(0uL)))
    }

    @Test
    fun `an absurd retry-after does not overflow`() {
        val f = RescueFailures.classify(FfiException.RateLimited(ULong.MAX_VALUE))
        assertEquals(Failure.RateLimited(Long.MAX_VALUE), f)
    }

    @Test
    fun `network and io failures are transient`() {
        assertEquals(Failure.Transient, RescueFailures.classify(FfiException.Network("reset")))
        assertEquals(Failure.Transient, RescueFailures.classify(FfiException.Io("cut")))
        assertEquals(FailureReason.NETWORK, RescueFailures.reason(FfiException.Network("reset")))
        assertEquals(FailureReason.STORAGE, RescueFailures.reason(FfiException.Io("cut")))
    }

    @Test
    fun `everything else is permanent`() {
        assertEquals(Failure.Permanent, RescueFailures.classify(FfiException.ReportRefused("closure first")))
        assertEquals(Failure.Permanent, RescueFailures.classify(IllegalStateException("destroyed")))
        assertEquals(FailureReason.REFUSED, RescueFailures.reason(FfiException.ReportRefused("x")))
        assertEquals(FailureReason.OTHER, RescueFailures.reason(IllegalStateException("destroyed")))
    }

    @Test
    fun `a listing the relay served unreadable is an anomaly, never retried`() {
        // Rust raises InvalidBlob for a malformed listing or one over its size
        // cap. Classified permanent, it stopped the whole enumeration at that
        // index, while the CLI goes on past it.
        assertEquals(Failure.Unreadable, RescueFailures.classify(FfiException.InvalidBlob("listing too large")))
        assertTrue(RescueFailures.isUnreadable(FfiException.InvalidBlob("x")))
        assertFalse(RescueFailures.isUnreadable(FfiException.Network("reset")))
        assertFalse(RescueFailures.isUnreadable(FfiException.ReportRefused("x")))
        assertNull(RescueRetryPolicy().nextWaitMillis(Failure.Unreadable, 0, 0))
    }

    @Test
    fun `an object that does not decrypt is told from a failure that may pass`() {
        assertTrue(RescueFailures.isUndecryptable(FfiException.InvalidBlob("not a STRM")))
        assertTrue(RescueFailures.isUndecryptable(FfiException.WrongPin()))
        assertTrue(RescueFailures.isUndecryptable(FfiException.Internal("x")))
        assertFalse(RescueFailures.isUndecryptable(FfiException.Io("disk full")))
        assertFalse(RescueFailures.isUndecryptable(FfiException.Network("reset")))
        assertFalse(RescueFailures.isUndecryptable(FfiException.RateLimited(0uL)))
        assertFalse(RescueFailures.isUndecryptable(CancellationException("cancelled")))
        assertFalse(RescueFailures.isUndecryptable(IllegalStateException("ArchiveSession is closed")))
    }
}
