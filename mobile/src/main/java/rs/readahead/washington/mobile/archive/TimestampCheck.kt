package rs.readahead.washington.mobile.archive

import uniffi.frappuccino.OtsStatus
import java.io.File
import java.security.MessageDigest

/**
 * The timestamp check of a verified report, on the phone: does the decrypted
 * proof commit to the report's VERIFIED chunks? The phone only says whether
 * the proof is about these recordings; the Bitcoin anchoring is checked on a
 * desktop with the CLI.
 *
 * The proof is opt-in and auxiliary, and its check never fails the report:
 * the testimony stays readable and exportable whatever the proof says. An
 * object that verified but does not decrypt (the proof, the metadata, a
 * chunk) makes the check conclude MISMATCH, as in the desktop CLI: a
 * verified signature says who stored an object, not that it decrypts, and the
 * directory's key, which signs the proofs, is held by whoever extracted the
 * device's state. A failure that may pass (local I/O, the relay, a rate
 * limit) and a cancellation are rethrown instead; the report is then
 * verified again later.
 *
 * The native calls are passed in, so the rules are testable on a plain JVM.
 *
 * @param decrypt decrypts the STRM file `input` to `output`.
 * @param hashPlaintext SHA-256 of the plaintext of the STRM file `input`,
 *   through the scratch file `scratch`, which it secure-deletes.
 * @param commitment the salted commitment over the chunk hashes, the salt
 *   derived from the recording id.
 * @param proofStatus compares a decrypted proof with a commitment.
 */
internal class TimestampCheck(
    private val decrypt: (input: File, output: File) -> Unit,
    private val hashPlaintext: (input: File, scratch: File) -> ByteArray,
    private val commitment: (hashes: List<ByteArray>, recordingId: ByteArray) -> ByteArray,
    private val proofStatus: (proof: File, commitment: ByteArray) -> OtsStatus,
    private val secureDelete: (File) -> Unit,
    private val wipe: (ByteArray) -> Unit,
    private val undecryptable: (Throwable) -> Boolean = RescueFailures::isUndecryptable,
) {
    /**
     * What the check concluded. [proof] and [recordingId] are set on
     * [OtsStatus.MATCH] only: the caller keeps them for the export (the
     * proof, and the recording id its salt is derived from) and wipes
     * [recordingId] when it is done with it.
     */
    class Outcome(val status: OtsStatus, val proof: File?, val recordingId: ByteArray?)

    /**
     * Check a proof stored encrypted (a chained report's, fetched from the
     * directory): decrypt [sealed] into [proof], then compare. [sealed] is
     * deleted whatever happens; [proof] is secure-deleted unless it matched.
     *
     * @param metadata the report's VERIFIED metadata object (seq 0), still
     *   encrypted, or null when it has none.
     * @param chunks the report's VERIFIED chunks, in reading order.
     * @param scratchDir a private directory for the short-lived plaintext.
     */
    fun checkSealed(sealed: File, proof: File, metadata: File?, chunks: List<File>, scratchDir: File): Outcome {
        val decrypted = try {
            undecryptableAsFalse { decrypt(sealed, proof) }
        } catch (e: Exception) {
            secureDelete(proof)
            throw e
        } finally {
            sealed.delete()
        }
        if (!decrypted) {
            secureDelete(proof)
            return Outcome(OtsStatus.MISMATCH, null, null)
        }
        return compare(proof, ownsProof = true, metadata, chunks, scratchDir)
    }

    /**
     * Check a proof stored as is (a legacy report's own `.ots` object, kept
     * with the report's verified objects). [proof] is never deleted here.
     */
    fun checkStored(proof: File, metadata: File?, chunks: List<File>, scratchDir: File): Outcome =
        compare(proof, ownsProof = false, metadata, chunks, scratchDir)

    private fun compare(
        proof: File,
        ownsProof: Boolean,
        metadata: File?,
        chunks: List<File>,
        scratchDir: File,
    ): Outcome {
        var keep = false
        var recordingId: ByteArray? = null
        try {
            // No verified metadata object, no session id in it, or a metadata
            // object that does not decrypt: the commitment cannot be
            // recomputed, so the proof matches nothing.
            recordingId = metadata?.let { recordingId(it, scratchDir) }
                ?: return Outcome(OtsStatus.MISMATCH, null, null)
            // The recorder committed to the chunks it recorded (seq >= 1, in
            // seq order). The commitment is recomputed from the VERIFIED
            // chunks only, so a chunk missing or excluded here makes it
            // differ, and so does one that does not decrypt.
            val hashes = ArrayList<ByteArray>(chunks.size)
            for (chunk in chunks) {
                var hash: ByteArray? = null
                val hashed = undecryptableAsFalse { hash = hashPlaintext(chunk, File(scratchDir, HASH_SCRATCH)) }
                val h = hash
                if (!hashed || h == null) return Outcome(OtsStatus.MISMATCH, null, null)
                hashes.add(h)
            }
            val result = proofStatus(proof, commitment(hashes, recordingId))
            if (result == OtsStatus.MATCH) {
                keep = true
                return Outcome(OtsStatus.MATCH, proof, recordingId)
            }
            return Outcome(result, null, null)
        } finally {
            if (!keep) {
                recordingId?.let(wipe)
                if (ownsProof) secureDelete(proof)
            }
        }
    }

    /**
     * `SHA-256(sessionId)[..16]`, the recording id the recorder derived the
     * timestamp salt from. The session id is read from the decrypted
     * [metadata] object as bytes, never as a `String`. Null without a session
     * id, or when the object does not decrypt.
     */
    private fun recordingId(metadata: File, scratchDir: File): ByteArray? {
        val plain = File(scratchDir, METADATA_SCRATCH)
        var json: ByteArray? = null
        var sessionId: ByteArray? = null
        try {
            if (!undecryptableAsFalse { decrypt(metadata, plain) }) return null
            json = plain.readBytes()
            sessionId = SessionIdReader.sessionIdBytes(json) ?: return null
            return MessageDigest.getInstance("SHA-256").digest(sessionId).copyOf(RECORDING_ID_BYTES)
        } finally {
            json?.let(wipe)
            sessionId?.let(wipe)
            secureDelete(plain)
        }
    }

    /** Run [block]: true when it returned, false when the object it decrypts
     *  does not decrypt; any other failure is rethrown. */
    private inline fun undecryptableAsFalse(block: () -> Unit): Boolean = try {
        block()
        true
    } catch (e: Exception) {
        if (!undecryptable(e)) throw e
        false
    }

    private companion object {
        const val HASH_SCRATCH = "hash.tmp"
        const val METADATA_SCRATCH = "metadata.tmp"
        const val RECORDING_ID_BYTES = 16
    }
}
