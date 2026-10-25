package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.frappuccino.ClosureState

/**
 * What the rescue screen says about the relay's records. "No directory on the
 * relay" is said only when the relay said so.
 */
class RescueAnomaliesTest {

    private fun view(
        state: RescueSession.EnumerationState,
        directory: RescueSession.DirectoryState,
        closure: ClosureState? = null,
        unmatched: Int = 0,
        unreadable: Int = 0,
        failure: FailureReason? = null,
    ) = RescueSession.EnumerationView(
        state = state,
        probed = 0,
        found = 0,
        rateLimitedUntil = 0L,
        directory = directory,
        directoryClosure = closure,
        unmatchedEntries = unmatched,
        unreadableListings = unreadable,
        probesLongTail = false,
        failure = failure,
    )

    @Test
    fun `a directory that could not be reached is not called absent`() {
        // The relay never answered (network, or a cancelled search): nothing
        // is known about the directory.
        for (state in listOf(
            RescueSession.EnumerationState.INCOMPLETE,
            RescueSession.EnumerationState.CANCELLED,
        )) {
            val anomalies = RescueAnomalies.of(
                view(state, RescueSession.DirectoryState.UNKNOWN, failure = FailureReason.NETWORK),
            )
            assertFalse(state.name, RescueAnomaly.DirectoryAbsent in anomalies)
        }
    }

    @Test
    fun `a directory the relay says it does not have is called absent once the search ends`() {
        assertEquals(
            listOf(RescueAnomaly.DirectoryAbsent),
            RescueAnomalies.of(view(RescueSession.EnumerationState.COMPLETE, RescueSession.DirectoryState.ABSENT)),
        )
        assertEquals(
            emptyList<RescueAnomaly>(),
            RescueAnomalies.of(view(RescueSession.EnumerationState.RUNNING, RescueSession.DirectoryState.ABSENT)),
        )
    }

    @Test
    fun `a directory that was read is never called absent, even when the search stopped after it`() {
        val anomalies = RescueAnomalies.of(
            view(
                RescueSession.EnumerationState.INCOMPLETE,
                RescueSession.DirectoryState.LISTED,
                closure = ClosureState.VALID,
                failure = FailureReason.OTHER,
            ),
        )
        assertEquals(listOf(RescueAnomaly.DirectoryClosed), anomalies)
    }

    @Test
    fun `the directory's closure is told by its checked state`() {
        fun closureOf(c: ClosureState) = RescueAnomalies.of(
            view(RescueSession.EnumerationState.COMPLETE, RescueSession.DirectoryState.LISTED, closure = c),
        )
        assertEquals(listOf(RescueAnomaly.DirectoryClosed), closureOf(ClosureState.VALID))
        assertEquals(listOf(RescueAnomaly.DirectoryClosureInvalid), closureOf(ClosureState.INVALID))
        assertEquals(listOf(RescueAnomaly.DirectoryClosureUnchecked), closureOf(ClosureState.UNCHECKED))
    }

    @Test
    fun `unreadable listings are shown, and an unreadable directory too`() {
        val anomalies = RescueAnomalies.of(
            view(
                RescueSession.EnumerationState.COMPLETE,
                RescueSession.DirectoryState.UNREADABLE,
                unmatched = 2,
                unreadable = 3,
            ),
        )
        assertTrue(RescueAnomaly.DirectoryUnreadable in anomalies)
        assertTrue(RescueAnomaly.Unmatched(2) in anomalies)
        assertTrue(RescueAnomaly.UnreadableListings(3) in anomalies)
        assertFalse(RescueAnomaly.DirectoryAbsent in anomalies)
    }

    @Test
    fun `nothing is shown before a search`() {
        assertEquals(
            emptyList<RescueAnomaly>(),
            RescueAnomalies.of(view(RescueSession.EnumerationState.NOT_STARTED, RescueSession.DirectoryState.ABSENT)),
        )
    }
}
