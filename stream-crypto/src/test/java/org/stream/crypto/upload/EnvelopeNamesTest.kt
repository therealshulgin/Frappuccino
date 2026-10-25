package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The local envelope names are what keeps one job per object and makes a
 * retried seal overwrite its own leftovers: a name must parse back to exactly
 * what built it, and the chained and legacy families must never be confused.
 */
class EnvelopeNamesTest {

    private val sid = "0123456789abcdef0123456789abcdef"

    @Test
    fun chained_names_round_trip() {
        val chunk = EnvelopeNames.chunk(sid, 42)
        assertEquals("${sid}_c000042.fqe", chunk)
        assertEquals(EnvelopeNames.Parsed(EnvelopeNames.Role.OBJECT, null, sid, 42), EnvelopeNames.parse(chunk))
        assertEquals(
            EnvelopeNames.Parsed(EnvelopeNames.Role.DIRECTORY_ENTRY, null, sid, null),
            EnvelopeNames.parse(EnvelopeNames.directoryEntry(sid)),
        )
        assertEquals(
            EnvelopeNames.Parsed(EnvelopeNames.Role.CLOSURE, null, sid, null),
            EnvelopeNames.parse(EnvelopeNames.closure(sid)),
        )
        assertEquals(
            EnvelopeNames.Parsed(EnvelopeNames.Role.TIMESTAMP_PROOF, null, sid, null),
            EnvelopeNames.parse(EnvelopeNames.timestampProof(sid)),
        )
    }

    @Test
    fun legacy_names_round_trip_even_with_underscores_in_the_session_id() {
        val oldSid = "ab12_1715000000_ff00"
        val name = EnvelopeNames.legacyObject(7, oldSid, 3)
        assertEquals("L7_${oldSid}_000003.fqe", name)
        assertEquals(EnvelopeNames.Parsed(EnvelopeNames.Role.OBJECT, 7, oldSid, 3), EnvelopeNames.parse(name))
        assertEquals(
            EnvelopeNames.Parsed(EnvelopeNames.Role.DIRECTORY_ENTRY, 7, null, null),
            EnvelopeNames.parse(EnvelopeNames.legacyDirectoryEntry(7)),
        )
        assertEquals(
            EnvelopeNames.Parsed(EnvelopeNames.Role.CLOSURE, 0, null, null),
            EnvelopeNames.parse(EnvelopeNames.legacyClosure(0)),
        )
        assertEquals(
            EnvelopeNames.Parsed(EnvelopeNames.Role.TIMESTAMP_PROOF, 12, null, null),
            EnvelopeNames.parse(EnvelopeNames.legacyTimestampProof(12)),
        )
    }

    @Test
    fun the_two_families_never_overlap() {
        // A chained session id is lowercase hex: it can never take the
        // uppercase `L<i>` form of a legacy name.
        assertFalse(EnvelopeNames.isSessionId("L12"))
        val legacy = EnvelopeNames.parse("L12_d.fqe")
        assertEquals(12, legacy?.legacyIndex)
        assertTrue(legacy!!.isLegacy)
        assertFalse(EnvelopeNames.parse(EnvelopeNames.directoryEntry(sid))!!.isLegacy)
    }

    @Test
    fun foreign_or_damaged_names_are_rejected() {
        assertNull(EnvelopeNames.parse("${sid}_c000042.strm"))
        assertNull(EnvelopeNames.parse("${sid}_c42.fqe"))
        assertNull(EnvelopeNames.parse("${sid}_x.fqe"))
        assertNull(EnvelopeNames.parse("${sid}_c000042.fqe.part"))
        assertNull(EnvelopeNames.parse("${sid.uppercase()}_d.fqe"))
        assertNull(EnvelopeNames.parse("_d.fqe"))
        assertNull(EnvelopeNames.parse("L1_.fqe"))
        assertNull(EnvelopeNames.parse("L01_d.fqe"))
        assertNull(EnvelopeNames.parse("L1_a/b_000001.fqe"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun a_seq_beyond_the_writer_bound_is_refused() {
        EnvelopeNames.chunk(sid, EnvelopeNames.MAX_SEQ + 1)
    }

    @Test
    fun only_report_creators_may_need_the_bearer() {
        assertTrue(EnvelopeNames.mayNeedJwt(EnvelopeNames.chunk(sid, 0)))
        assertTrue(EnvelopeNames.mayNeedJwt(EnvelopeNames.directoryEntry(sid)))
        assertTrue(EnvelopeNames.mayNeedJwt(EnvelopeNames.legacyObject(3, "old", 0)))
        assertTrue(EnvelopeNames.mayNeedJwt(EnvelopeNames.legacyDirectoryEntry(3)))
        assertFalse(EnvelopeNames.mayNeedJwt(EnvelopeNames.chunk(sid, 1)))
        assertFalse(EnvelopeNames.mayNeedJwt(EnvelopeNames.closure(sid)))
        assertFalse(EnvelopeNames.mayNeedJwt(EnvelopeNames.timestampProof(sid)))
        assertFalse(EnvelopeNames.mayNeedJwt("garbage"))
    }

    @Test
    fun session_objects_are_told_apart() {
        val other = "fedcba9876543210fedcba9876543210"
        assertTrue(EnvelopeNames.isObjectOfSession(EnvelopeNames.chunk(sid, 0), sid))
        assertTrue(EnvelopeNames.isObjectOfSession(EnvelopeNames.chunk(sid, 9), sid))
        assertFalse(EnvelopeNames.isObjectOfSession(EnvelopeNames.chunk(other, 9), sid))
        assertFalse(EnvelopeNames.isObjectOfSession(EnvelopeNames.directoryEntry(sid), sid))
        assertFalse(EnvelopeNames.isObjectOfSession(EnvelopeNames.legacyObject(1, sid, 9), sid))
    }
}
