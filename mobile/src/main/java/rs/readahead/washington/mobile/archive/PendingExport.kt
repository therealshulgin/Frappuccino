package rs.readahead.washington.mobile.archive

/**
 * The export waiting for the system folder picker: which report (its
 * position in the list), and whether it is the section kept apart as not
 * verifiable. Nothing secret, so it may go in the screen's saved instance
 * state, and it must: the picker's answer goes to whichever instance of the
 * rescue screen exists when it comes back, and a change of configuration
 * while the picker is shown (dark mode, language, font size, window size)
 * recreates the screen. Held in a plain field, the pending export would be
 * lost and the witness's export dropped without a word.
 */
data class PendingExport(val ordinal: Int, val unverifiable: Boolean) {

    /** What the screen does with the picker's answer. */
    sealed class Answer {
        data class Start(val ordinal: Int, val unverifiable: Boolean) : Answer()

        /** The witness left the picker without choosing a folder. */
        object Cancelled : Answer()

        /** A folder was chosen, but the export it was for is not known any
         *  more: the screen says the export did not start. */
        object Lost : Answer()
    }

    companion object {
        const val KEY_ORDINAL = "archive.pendingExport.ordinal"
        const val KEY_UNVERIFIABLE = "archive.pendingExport.unverifiable"

        /** The answer to give when the picker returns; [folderChosen] is
         *  whether it returned a folder. */
        fun answer(pending: PendingExport?, folderChosen: Boolean): Answer = when {
            !folderChosen -> Answer.Cancelled
            pending == null || pending.ordinal <= 0 -> Answer.Lost
            else -> Answer.Start(pending.ordinal, pending.unverifiable)
        }

        /** The pending export saved as [ordinal] and [unverifiable], or null
         *  when [ordinal] says there was none (positions start at 1). */
        fun fromSaved(ordinal: Int, unverifiable: Boolean): PendingExport? =
            if (ordinal > 0) PendingExport(ordinal, unverifiable) else null
    }
}
