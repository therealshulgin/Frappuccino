package rs.readahead.washington.mobile.archive

/**
 * The export waiting for the system folder picker: which report (its
 * position in the list), whether it is the section kept apart as not
 * verifiable, and whether the chunks as recorded go with the joined videos.
 * Nothing secret, so it may go in the screen's saved instance state, and it
 * must: the picker's answer goes to whichever instance of the rescue screen
 * exists when it comes back, and a change of configuration while the picker
 * is shown (dark mode, language, font size, window size) recreates the
 * screen. Held in a plain field, the pending export would be lost and the
 * witness's export dropped without a word, or started without the choice the
 * witness made in the dialog.
 */
data class PendingExport(val ordinal: Int, val unverifiable: Boolean, val includeRaw: Boolean = false) {

    /** What the screen does with the picker's answer. */
    sealed class Answer {
        data class Start(val ordinal: Int, val unverifiable: Boolean, val includeRaw: Boolean = false) : Answer()

        /** The witness left the picker without choosing a folder. */
        object Cancelled : Answer()

        /** A folder was chosen, but the export it was for is not known any
         *  more: the screen says the export did not start. */
        object Lost : Answer()
    }

    companion object {
        const val KEY_ORDINAL = "archive.pendingExport.ordinal"
        const val KEY_UNVERIFIABLE = "archive.pendingExport.unverifiable"
        const val KEY_INCLUDE_RAW = "archive.pendingExport.includeRaw"

        /** The answer to give when the picker returns; [folderChosen] is
         *  whether it returned a folder. */
        fun answer(pending: PendingExport?, folderChosen: Boolean): Answer = when {
            !folderChosen -> Answer.Cancelled
            pending == null || pending.ordinal <= 0 -> Answer.Lost
            else -> Answer.Start(pending.ordinal, pending.unverifiable, pending.includeRaw)
        }

        /** The pending export saved as [ordinal], [unverifiable] and
         *  [includeRaw], or null when [ordinal] says there was none
         *  (positions start at 1). */
        fun fromSaved(ordinal: Int, unverifiable: Boolean, includeRaw: Boolean = false): PendingExport? =
            if (ordinal > 0) PendingExport(ordinal, unverifiable, includeRaw) else null
    }
}
