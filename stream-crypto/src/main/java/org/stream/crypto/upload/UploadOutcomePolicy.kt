package org.stream.crypto.upload

/**
 * What the envelope worker does with the answer to one send, and how it sends.
 * The table it implements is the contract between the device and the relay, so
 * a row changed here changes what happens to a witness's footage: read the
 * row's comment before touching it.
 *
 * The rule behind every row: an envelope is signed once, when it is produced,
 * and the key that signed it is gone once its report is closed. Nothing can
 * re-sign it, so an envelope is never deleted unless the relay holds it (2xx)
 * or holding it is pointless (a legacy closure for a report the relay never
 * knew). Every other outcome either retries or moves the envelope to the failed
 * directory, where it stays, counted and shown, until the emergency wipe.
 *
 * Pure JVM: unit-tested without the native library.
 */
object UploadOutcomePolicy {

    /** What the envelope carries (the trailer's kind). */
    enum class Kind { OBJECT, DIRECTORY_ENTRY, CLOSURE, TIMESTAMP_PROOF }

    enum class Action {
        /** The relay holds it: securely delete the envelope. */
        DELETE,

        /** The envelope is not there any more (a concurrent worker sent it). */
        ALREADY_GONE,

        /** Transient (network, 5xx, 507, 429, a local I/O hiccup): retry. */
        RETRY,

        /** 401 on a creation request: the bearer was refused. Drop it, retry. */
        RETRY_AFTER_AUTH_REFUSED,

        /**
         * 425 on an object, a directory entry or a proof: the report does not
         * exist yet. Remember it, and retry in creation mode as soon as a bearer
         * is available.
         */
        RETRY_WITH_CREATION,

        /**
         * 404 on a closure: the relay does not have the closure route yet (it is
         * deployed before the app, but a rollback is possible). Retry with
         * backoff, never give up: the closure is what freezes the report.
         */
        RETRY_CLOSE_ROUTE,

        /** Refused for good: failed directory + in-app alert. */
        FAIL,

        /**
         * 409 on a directory entry or a timestamp proof whose body is the
         * relay's closure refusal (tag [Tag.REPORT_CLOSED]): the relay says the
         * directory is closed. This app never closes its directory, so the
         * witness gets an alert of its own; the refusal says the directory is
         * closed, not who closed it. Any other 409 on these kinds (a
         * write-once conflict, a key that does not match the record) is a plain
         * [FAIL]. Failed directory either way.
         */
        FAIL_DIRECTORY_CLOSED,

        /**
         * 425 on a chained closure while nothing else of the report was queued,
         * neither when the closure was sent nor when its answer came back (see
         * [closurePeersQueued]): the report was never created, so there is
         * nothing to close and nothing left that could create it. Failed
         * directory + alert.
         */
        ABANDON_CLOSURE,

        /**
         * 425 on a legacy closure (sent only once the report's queue drained):
         * the relay never knew the report, there is nothing to freeze. Delete.
         */
        DROP_LEGACY_CLOSURE,
    }

    /**
     * Tags of `upload_send_envelope` (its `error_detail`). All but one come
     * with `http_status == 0`, when no response came back. The exception is
     * [REPORT_CLOSED], which comes WITH a response.
     */
    object Tag {
        const val FILE_MISSING = "file_missing"
        const val ENVELOPE_CORRUPT = "envelope_corrupt"
        const val ENVELOPE_IO = "envelope_io"
        const val NO_QUEUE_KEY = "no_queue_key"
        const val NO_BEARER = "no_bearer"
        const val NO_CREATE_SIG = "no_create_sig"

        /**
         * A 409 whose body is exactly the relay's closure refusal
         * (`{"detail":"Report closed"}`): the report is closed and refuses this
         * name. Set by Rust from the response body; the write-once conflict,
         * the other 409, carries no tag. Not a local failure.
         */
        const val REPORT_CLOSED = "report_closed"
    }

    /**
     * @param kind what the envelope carries.
     * @param legacyClosure the trailer's `needs_drain` (a legacy closure).
     * @param httpStatus 0 when no HTTP response came back.
     * @param errorDetail the outcome's tag: one of the local tags when
     *   [httpStatus] is 0, [Tag.REPORT_CLOSED] or null with a response.
     * @param peersQueued whether another envelope of the same report is still
     *   in the queue (the failed directory does not count).
     * @param usedCreation whether this request carried the creation headers.
     */
    fun decide(
        kind: Kind,
        legacyClosure: Boolean,
        httpStatus: Int,
        errorDetail: String?,
        peersQueued: Boolean,
        usedCreation: Boolean,
    ): Action {
        if (httpStatus in 200..299) return Action.DELETE
        if (httpStatus == 0) {
            return when (errorDetail) {
                Tag.FILE_MISSING -> Action.ALREADY_GONE
                // Damaged, or does not verify under its own key: never retried,
                // never re-signed (nothing could re-sign it anyway).
                Tag.ENVELOPE_CORRUPT -> Action.FAIL
                // Everything else without a response is local or network and
                // transient; the file stays where it is.
                else -> Action.RETRY
            }
        }
        return when (httpStatus) {
            401 -> if (usedCreation) Action.RETRY_AFTER_AUTH_REFUSED else Action.RETRY
            425 -> when (kind) {
                Kind.CLOSURE -> when {
                    legacyClosure -> Action.DROP_LEGACY_CLOSURE
                    peersQueued -> Action.RETRY
                    else -> Action.ABANDON_CLOSURE
                }
                else -> Action.RETRY_WITH_CREATION
            }
            404 -> if (kind == Kind.CLOSURE) Action.RETRY_CLOSE_ROUTE else Action.FAIL
            409 -> when {
                (kind == Kind.DIRECTORY_ENTRY || kind == Kind.TIMESTAMP_PROOF) &&
                    errorDetail == Tag.REPORT_CLOSED -> Action.FAIL_DIRECTORY_CLOSED
                else -> Action.FAIL
            }
            // Rate limit or creation budget: both clear on their own.
            429 -> Action.RETRY
            else -> when {
                httpStatus in 400..499 -> Action.FAIL
                // 5xx and 507 (relay storage full) are the relay's problem.
                httpStatus >= 500 -> Action.RETRY
                // 1xx/3xx never come back from these routes; if one does, keep
                // the envelope rather than guess.
                else -> Action.RETRY
            }
        }
    }

    /**
     * Whether to send with the creation headers (the envelope's create-sig and
     * the upload bearer). Only when a bearer is held: without one the send goes
     * out plain first, and a 425 is what tells the queue the report needs
     * creating. With one, only for an envelope that may have to create its
     * report: the report's first object, a directory entry, or one the relay
     * already answered 425 for. A closure never creates anything.
     */
    fun useCreation(
        kind: Kind,
        hasCreateSig: Boolean,
        bearerHeld: Boolean,
        mayCreate: Boolean,
        markedNotCreated: Boolean,
    ): Boolean {
        if (kind == Kind.CLOSURE || !hasCreateSig || !bearerHeld) return false
        return mayCreate || markedNotCreated
    }

    /**
     * Whether a legacy closure may be sent now: only once nothing else of its
     * report is queued, because the relay refuses every new object after a
     * closure and a legacy closure lists none.
     */
    fun legacyClosureReady(peersQueued: Boolean): Boolean = !peersQueued

    /**
     * The `peersQueued` of a chained closure's 425: whether another envelope of
     * its report was in the queue when the closure was sent ([queuedBeforeSend],
     * sampled before the request) or still is now ([queuedNow], read only if
     * needed).
     *
     * Reading the queue only after the answer is not enough. The relay answers
     * 425 when it has no record yet, and the envelope that creates the record
     * can be accepted, then removed from the queue, while the closure's answer
     * is still on its way back: "nothing queued now" would then abandon a
     * closure whose report exists. An envelope leaves the queue only once the
     * relay holds it (the record then exists) or once it is refused for good,
     * so "nothing queued before the send either" is what proves that nothing
     * left can create the report.
     */
    fun closurePeersQueued(queuedBeforeSend: Boolean, queuedNow: () -> Boolean): Boolean =
        queuedBeforeSend || queuedNow()
}
