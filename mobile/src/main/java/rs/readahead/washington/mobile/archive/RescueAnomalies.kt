package rs.readahead.washington.mobile.archive

import uniffi.frappuccino.ClosureState

/**
 * An anomaly the rescue screen shows above the list: something about the
 * relay's records that the witness should know before trusting the list.
 */
sealed class RescueAnomaly {
    /** A valid closure is recorded on the directory: whoever held the
     *  device's state closed it (R1b). */
    object DirectoryClosed : RescueAnomaly()

    /** A closure that does not verify is recorded on the directory. */
    object DirectoryClosureInvalid : RescueAnomaly()

    /** A closure is recorded on the directory, and checking it failed. */
    object DirectoryClosureUnchecked : RescueAnomaly()

    /** The relay answered that it has no directory for this phrase. */
    object DirectoryAbsent : RescueAnomaly()

    /** The relay served a directory listing that could not be read. */
    object DirectoryUnreadable : RescueAnomaly()

    data class Unmatched(val count: Int) : RescueAnomaly()

    /** Report listings the relay served unreadable. */
    data class UnreadableListings(val count: Int) : RescueAnomaly()
}

/**
 * Which anomalies an enumeration shows. Kept apart from Android so the rules
 * are testable.
 *
 * "No directory on the relay" is a statement about the relay's answer, and it
 * is made only when the relay gave that answer. A directory that could not be
 * reached (network, a rate limit that never lifted, a cancelled search) is
 * not absent: nothing is known about it, and nothing is said.
 */
object RescueAnomalies {

    fun of(view: RescueSession.EnumerationView): List<RescueAnomaly> {
        if (view.state == RescueSession.EnumerationState.NOT_STARTED) return emptyList()
        val out = ArrayList<RescueAnomaly>()
        when (view.directoryClosure) {
            null, ClosureState.ABSENT -> Unit
            ClosureState.VALID -> out.add(RescueAnomaly.DirectoryClosed)
            ClosureState.INVALID -> out.add(RescueAnomaly.DirectoryClosureInvalid)
            ClosureState.UNCHECKED -> out.add(RescueAnomaly.DirectoryClosureUnchecked)
        }
        when (view.directory) {
            RescueSession.DirectoryState.ABSENT ->
                if (view.state != RescueSession.EnumerationState.RUNNING) out.add(RescueAnomaly.DirectoryAbsent)
            RescueSession.DirectoryState.UNREADABLE -> out.add(RescueAnomaly.DirectoryUnreadable)
            RescueSession.DirectoryState.LISTED, RescueSession.DirectoryState.UNKNOWN -> Unit
        }
        if (view.unmatchedEntries > 0) out.add(RescueAnomaly.Unmatched(view.unmatchedEntries))
        if (view.unreadableListings > 0) out.add(RescueAnomaly.UnreadableListings(view.unreadableListings))
        return out
    }
}
