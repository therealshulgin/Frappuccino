package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LegacyMigrationPlanTest {

    @Test
    fun legacy_blob_names_are_parsed_from_the_end() {
        assertEquals(
            LegacyMigrationPlan.Blob("0123abcd", 0),
            LegacyMigrationPlan.parseBlob("0123abcd_000000.strm"),
        )
        // The old session-id format had underscores of its own.
        assertEquals(
            LegacyMigrationPlan.Blob("ab12_1715000000_ff00", 17),
            LegacyMigrationPlan.parseBlob("ab12_1715000000_ff00_000017.strm"),
        )
        assertNull(LegacyMigrationPlan.parseBlob("0123abcd_17.strm"))
        assertNull(LegacyMigrationPlan.parseBlob("0123abcd_000017.strm.part"))
        assertNull(LegacyMigrationPlan.parseBlob("_000017.strm"))
        assertNull(LegacyMigrationPlan.parseBlob("a/b_000017.strm"))
    }

    @Test
    fun staged_directory_entries_carry_their_index() {
        assertEquals(0, LegacyMigrationPlan.parseDirectoryEntry("0000000000"))
        assertEquals(42, LegacyMigrationPlan.parseDirectoryEntry("0000000042"))
        assertNull(LegacyMigrationPlan.parseDirectoryEntry("42"))
        assertNull(LegacyMigrationPlan.parseDirectoryEntry("9999999999"))
        assertNull(LegacyMigrationPlan.parseDirectoryEntry("00000000ab"))
    }

    @Test
    fun received_proofs_name_their_session() {
        assertEquals("0123abcd", LegacyMigrationPlan.parseProof("0123abcd.ots"))
        assertNull(LegacyMigrationPlan.parseProof("0123abcd.ticket"))
        assertNull(LegacyMigrationPlan.parseProof(".ots"))
    }

    @Test
    fun the_chained_scheme_starts_past_every_legacy_index() {
        assertEquals(0, LegacyMigrationPlan.firstChainIndex(0, emptyList()))
        assertEquals(5, LegacyMigrationPlan.firstChainIndex(5, listOf(1, 4)))
        // A mapping ahead of the counter wins: no legacy index is reused.
        assertEquals(10, LegacyMigrationPlan.firstChainIndex(3, listOf(1, 9)))
        assertEquals(3, LegacyMigrationPlan.firstChainIndex(3, listOf(-1)))
        assertEquals(0, LegacyMigrationPlan.firstChainIndex(-4, emptyList()))
    }

    @Test
    fun only_sessions_with_a_pending_blob_get_an_index() {
        val blobs = listOf("0123abcd_000001.strm", "0123abcd_000002.strm", "not-a-blob")
        assertEquals(setOf("0123abcd"), LegacyMigrationPlan.sessionsNeedingIndex(blobs))
        // A session known only through a received proof is not in the set:
        // giving it an index would file the proof in a report of its own.
        val withProofOnly = blobs + "fedc9876.ots"
        assertEquals(setOf("0123abcd"), LegacyMigrationPlan.sessionsNeedingIndex(withProofOnly))
    }

    @Test
    fun every_legacy_index_gets_a_closure() {
        assertEquals(listOf(0, 1, 2), LegacyMigrationPlan.indicesToClose(3).toList())
        assertEquals(emptyList<Int>(), LegacyMigrationPlan.indicesToClose(0).toList())
    }
}
