package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.stream.crypto.upload.UploadOutcomePolicy.Action
import org.stream.crypto.upload.UploadOutcomePolicy.Kind

/**
 * The send table (design §7.5), row by row. The rows that matter most are the
 * ones that must NOT delete: an envelope cannot be signed again, so anything
 * other than 2xx and the two moot cases must keep it.
 */
class UploadOutcomePolicyTest {

    private fun decide(
        kind: Kind,
        code: Int,
        detail: String? = null,
        legacyClosure: Boolean = false,
        peers: Boolean = false,
        creation: Boolean = false,
    ) = UploadOutcomePolicy.decide(kind, legacyClosure, code, detail, peers, creation)

    @Test
    fun success_deletes_for_every_kind() {
        for (kind in Kind.values()) {
            assertEquals(Action.DELETE, decide(kind, 200))
            assertEquals(Action.DELETE, decide(kind, 204))
        }
    }

    @Test
    fun transient_answers_retry() {
        for (kind in Kind.values()) {
            for (code in listOf(429, 500, 502, 503, 507)) {
                assertEquals("$kind $code", Action.RETRY, decide(kind, code))
            }
            assertEquals(Action.RETRY, decide(kind, 0, "network"))
            assertEquals(Action.RETRY, decide(kind, 0, "timeout"))
            assertEquals(Action.RETRY, decide(kind, 0, UploadOutcomePolicy.Tag.NO_QUEUE_KEY))
            assertEquals(Action.RETRY, decide(kind, 0, UploadOutcomePolicy.Tag.ENVELOPE_IO))
            assertEquals(Action.RETRY, decide(kind, 0, UploadOutcomePolicy.Tag.NO_BEARER))
            assertEquals(Action.RETRY, decide(kind, 0, null))
        }
    }

    @Test
    fun a_401_drops_the_bearer_only_after_a_creation_request() {
        assertEquals(Action.RETRY_AFTER_AUTH_REFUSED, decide(Kind.OBJECT, 401, creation = true))
        assertEquals(Action.RETRY, decide(Kind.OBJECT, 401, creation = false))
    }

    @Test
    fun local_tags_without_a_response() {
        assertEquals(Action.ALREADY_GONE, decide(Kind.OBJECT, 0, UploadOutcomePolicy.Tag.FILE_MISSING))
        assertEquals(Action.FAIL, decide(Kind.OBJECT, 0, UploadOutcomePolicy.Tag.ENVELOPE_CORRUPT))
        assertEquals(Action.FAIL, decide(Kind.CLOSURE, 0, UploadOutcomePolicy.Tag.ENVELOPE_CORRUPT))
    }

    @Test
    fun a_425_asks_for_creation_except_on_a_closure() {
        assertEquals(Action.RETRY_WITH_CREATION, decide(Kind.OBJECT, 425))
        assertEquals(Action.RETRY_WITH_CREATION, decide(Kind.DIRECTORY_ENTRY, 425))
        assertEquals(Action.RETRY_WITH_CREATION, decide(Kind.TIMESTAMP_PROOF, 425))
    }

    @Test
    fun a_425_on_a_chained_closure_waits_while_its_report_has_objects_queued() {
        assertEquals(Action.RETRY, decide(Kind.CLOSURE, 425, peers = true))
        assertEquals(Action.ABANDON_CLOSURE, decide(Kind.CLOSURE, 425, peers = false))
    }

    @Test
    fun a_425_on_a_drained_legacy_closure_is_dropped() {
        assertEquals(Action.DROP_LEGACY_CLOSURE, decide(Kind.CLOSURE, 425, legacyClosure = true))
        assertEquals(Action.DROP_LEGACY_CLOSURE, decide(Kind.CLOSURE, 425, legacyClosure = true, peers = true))
    }

    @Test
    fun a_404_on_the_close_route_is_never_given_up() {
        assertEquals(Action.RETRY_CLOSE_ROUTE, decide(Kind.CLOSURE, 404))
        assertEquals(Action.RETRY_CLOSE_ROUTE, decide(Kind.CLOSURE, 404, legacyClosure = true))
        assertEquals(Action.FAIL, decide(Kind.OBJECT, 404))
    }

    @Test
    fun only_the_closure_refusal_on_the_directory_gets_its_own_alert() {
        val closed = UploadOutcomePolicy.Tag.REPORT_CLOSED
        assertEquals(Action.FAIL_DIRECTORY_CLOSED, decide(Kind.DIRECTORY_ENTRY, 409, closed))
        assertEquals(Action.FAIL_DIRECTORY_CLOSED, decide(Kind.TIMESTAMP_PROOF, 409, closed))
        // A 409 without the tag is a write-once conflict or a key that does
        // not match the record: the generic refusal, not "directory closed".
        assertEquals(Action.FAIL, decide(Kind.DIRECTORY_ENTRY, 409))
        assertEquals(Action.FAIL, decide(Kind.TIMESTAMP_PROOF, 409))
        // A closed report refusing an object or a closure is a plain refusal.
        assertEquals(Action.FAIL, decide(Kind.OBJECT, 409, closed))
        assertEquals(Action.FAIL, decide(Kind.CLOSURE, 409, closed))
        assertEquals(Action.FAIL, decide(Kind.OBJECT, 409))
        assertEquals(Action.FAIL, decide(Kind.CLOSURE, 409))
    }

    @Test
    fun the_closure_tag_only_counts_with_a_409() {
        val closed = UploadOutcomePolicy.Tag.REPORT_CLOSED
        assertEquals(Action.FAIL, decide(Kind.DIRECTORY_ENTRY, 400, closed))
        assertEquals(Action.DELETE, decide(Kind.DIRECTORY_ENTRY, 204, closed))
        assertEquals(Action.RETRY, decide(Kind.DIRECTORY_ENTRY, 0, closed))
    }

    @Test
    fun a_closure_whose_creator_landed_during_its_425_is_retried() {
        // The creator was queued when the closure went out, and was accepted
        // then removed before the closure's 425 came back.
        val peers = UploadOutcomePolicy.closurePeersQueued(queuedBeforeSend = true) { false }
        assertEquals(Action.RETRY, decide(Kind.CLOSURE, 425, peers = peers))
        // Nothing queued before nor after: nothing can create the report.
        val none = UploadOutcomePolicy.closurePeersQueued(queuedBeforeSend = false) { false }
        assertEquals(Action.ABANDON_CLOSURE, decide(Kind.CLOSURE, 425, peers = none))
        assertTrue(UploadOutcomePolicy.closurePeersQueued(false) { true })
    }

    @Test
    fun other_client_errors_fail_without_deleting() {
        for (code in listOf(400, 403, 410, 413, 422)) {
            for (kind in Kind.values()) {
                val action = decide(kind, code)
                assertEquals("$kind $code", Action.FAIL, action)
            }
        }
    }

    @Test
    fun only_two_outcomes_ever_delete() {
        val deleting = setOf(Action.DELETE, Action.DROP_LEGACY_CLOSURE)
        for (kind in Kind.values()) {
            for (code in (0..599)) {
                for (legacy in listOf(false, true)) {
                    for (peers in listOf(false, true)) {
                        val action = decide(kind, code, "x", legacy, peers)
                        if (action in deleting) {
                            val ok = code in 200..299 ||
                                (kind == Kind.CLOSURE && legacy && code == 425)
                            assertTrue("$kind $code legacy=$legacy peers=$peers -> $action", ok)
                        }
                    }
                }
            }
        }
    }

    @Test
    fun creation_mode_needs_a_bearer_a_signature_and_a_reason() {
        val c = UploadOutcomePolicy::useCreation
        assertTrue(c(Kind.OBJECT, true, true, true, false))
        assertTrue(c(Kind.OBJECT, true, true, false, true))
        assertTrue(c(Kind.DIRECTORY_ENTRY, true, true, true, false))
        // Without a bearer the send goes out plain first.
        assertFalse(c(Kind.OBJECT, true, false, true, true))
        // No creation signature, nothing to create with.
        assertFalse(c(Kind.OBJECT, false, true, true, true))
        // An ordinary chunk with no 425 behind it goes plain.
        assertFalse(c(Kind.OBJECT, true, true, false, false))
        // A closure never creates a report.
        assertFalse(c(Kind.CLOSURE, true, true, true, true))
    }

    @Test
    fun a_legacy_closure_waits_for_its_report_to_drain() {
        assertFalse(UploadOutcomePolicy.legacyClosureReady(peersQueued = true))
        assertTrue(UploadOutcomePolicy.legacyClosureReady(peersQueued = false))
    }
}
