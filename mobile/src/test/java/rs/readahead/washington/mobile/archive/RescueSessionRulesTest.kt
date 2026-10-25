package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.frappuccino.NoPointer
import uniffi.frappuccino.ReportCheck
import uniffi.frappuccino.ReportScheme

/**
 * A batch that never starts: the search the screen showed as running is
 * ended, and nothing else is touched.
 */
class RescueSessionRulesTest {

    @Test
    fun `a search that never started does not stay running`() {
        assertEquals(
            RescueSession.EnumerationState.INCOMPLETE,
            RescueSession.stateAfterFailedStart(isEnumeration = true, current = RescueSession.EnumerationState.RUNNING),
        )
    }

    @Test
    fun `a verification or an export that never started leaves the search's state alone`() {
        for (state in RescueSession.EnumerationState.values()) {
            assertNull(state.name, RescueSession.stateAfterFailedStart(isEnumeration = false, current = state))
        }
        // A search already over is not reopened either.
        assertNull(RescueSession.stateAfterFailedStart(true, RescueSession.EnumerationState.COMPLETE))
        assertNull(RescueSession.stateAfterFailedStart(true, RescueSession.EnumerationState.NOT_STARTED))
    }

    @Test
    fun `failing a started search ends it as incomplete`() {
        RescueSession.reset()
        RescueSession.markEnumerationStarting()
        RescueSession.failStartedEnumeration(isEnumeration = true)
        val e = RescueSession.snapshot().enumeration
        assertEquals(RescueSession.EnumerationState.INCOMPLETE, e.state)
        assertEquals(FailureReason.OTHER, e.failure)
        RescueSession.reset()
    }

    /** A report handle with no native object behind it, which remembers
     *  whether it was destroyed. */
    private class FakeCheck : ReportCheck(NoPointer) {
        var destroyed = false
        override fun destroy() {
            destroyed = true
            super.destroy()
        }
    }

    @Test
    fun `a report probed across a reset is destroyed, never added to the emptied session`() {
        RescueSession.reset()
        val gen = RescueSession.beginEnumeration()
        // The emergency wipe resets the session while the probe is in flight.
        RescueSession.reset()
        val late = FakeCheck()
        assertNull(RescueSession.addEntry(gen, late, ReportScheme.CHAIN, 1L, 3))
        assertTrue(late.destroyed)
        assertEquals(0, RescueSession.snapshot().entries.size)

        // The current generation still adds.
        val now = RescueSession.beginEnumeration()
        val kept = FakeCheck()
        assertNotNull(RescueSession.addEntry(now, kept, ReportScheme.CHAIN, 2L, 3))
        assertFalse(kept.destroyed)
        RescueSession.reset()
        assertTrue(kept.destroyed)
    }

    @Test
    fun `an enumeration's late writes are dropped once the session was reset`() {
        RescueSession.reset()
        val gen = RescueSession.beginEnumeration()
        RescueSession.reset()
        RescueSession.noteUnreadableListing(gen)
        RescueSession.setProbed(gen, 7)
        RescueSession.endEnumeration(gen, RescueSession.EnumerationState.CANCELLED, null)
        val e = RescueSession.snapshot().enumeration
        assertEquals(RescueSession.EnumerationState.NOT_STARTED, e.state)
        assertEquals(0, e.probed)
        assertEquals(0, e.unreadableListings)
    }
}
