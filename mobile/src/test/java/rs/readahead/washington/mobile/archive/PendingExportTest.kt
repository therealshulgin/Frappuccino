package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * The folder picker's answer: a chosen folder starts the export it was asked
 * for, and one whose export is not known any more is said so, never dropped
 * in silence.
 */
class PendingExportTest {

    @Test
    fun `a chosen folder starts the pending export`() {
        assertEquals(
            PendingExport.Answer.Start(3, unverifiable = true),
            PendingExport.answer(PendingExport(3, unverifiable = true), folderChosen = true),
        )
    }

    @Test
    fun `the raw chunks option goes through the picker`() {
        assertEquals(
            PendingExport.Answer.Start(2, unverifiable = false, includeRaw = true),
            PendingExport.answer(PendingExport(2, unverifiable = false, includeRaw = true), folderChosen = true),
        )
        assertEquals(PendingExport(2, false, includeRaw = true), PendingExport.fromSaved(2, false, includeRaw = true))
        // Unchecked unless the witness checked it.
        assertFalse(PendingExport(2, false).includeRaw)
    }

    @Test
    fun `a chosen folder with no pending export is reported, not ignored`() {
        assertSame(PendingExport.Answer.Lost, PendingExport.answer(null, folderChosen = true))
        assertSame(PendingExport.Answer.Lost, PendingExport.answer(PendingExport(0, false), folderChosen = true))
    }

    @Test
    fun `leaving the picker is a cancel`() {
        assertSame(PendingExport.Answer.Cancelled, PendingExport.answer(PendingExport(2, false), folderChosen = false))
        assertSame(PendingExport.Answer.Cancelled, PendingExport.answer(null, folderChosen = false))
    }

    @Test
    fun `the saved values give the pending export back`() {
        assertEquals(PendingExport(5, false), PendingExport.fromSaved(5, false))
        assertEquals(PendingExport(1, true), PendingExport.fromSaved(1, true))
        assertNull(PendingExport.fromSaved(0, true))
    }
}
