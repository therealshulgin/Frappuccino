package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Test
import org.stream.crypto.upload.TimestampTicketPolicy.Outcome
import uniffi.frappuccino.FfiException

class TimestampTicketPolicyTest {

    @Test
    fun a_transient_read_error_keeps_the_ticket() {
        assertEquals(Outcome.RETRY, TimestampTicketPolicy.forReadFailure(FfiException.Io("EIO")))
        assertEquals(Outcome.RETRY, TimestampTicketPolicy.forReadFailure(FfiException.NoQueueKey()))
        assertEquals(Outcome.RETRY, TimestampTicketPolicy.forReadFailure(IllegalStateException("x")))
    }

    @Test
    fun only_an_unreadable_ticket_is_dropped() {
        assertEquals(Outcome.DROP_TICKET, TimestampTicketPolicy.forReadFailure(FfiException.WrongPin()))
        assertEquals(Outcome.DROP_TICKET, TimestampTicketPolicy.forReadFailure(FfiException.InvalidBlob("bad")))
    }

    @Test
    fun a_legacy_job_waits_for_the_migration_to_count_it() {
        assertEquals(Outcome.RETRY, TimestampTicketPolicy.forLegacyJob(migrationNeeded = true))
        assertEquals(Outcome.FAIL, TimestampTicketPolicy.forLegacyJob(migrationNeeded = false))
    }
}
