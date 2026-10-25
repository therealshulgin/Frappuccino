package org.stream.crypto.upload

import org.stream.crypto.ArchiveIdentity
import uniffi.frappuccino.BlobMetadata
import uniffi.frappuccino.ReportCheck
import uniffi.frappuccino.RescuePlanner
import uniffi.frappuccino.RescueTarget
import uniffi.frappuccino.ReportRescue as FfiReportRescue
import uniffi.frappuccino.StreamServerClient as FfiServerClient
import java.io.File

/**
 * The rescue context: a relay client plus everything the phrase derives for
 * finding and checking the witness's reports.
 *
 * Reads carry no bearer and consume no ratchet slot, and that is not a missing
 * authentication waiting to be fixed: the phrase-derived `report_id` IS the
 * capability (`GET /api/v2/archive/reports/{report_id}/…`). The relay stores
 * `report_id → report_pk` and never the identity, so a seizure of its disk
 * reveals no `identity → report` link. Bolting a bearer onto these reads would
 * recreate exactly that link, and would put ratchet slots back into a path that
 * spends none.
 *
 * The [FfiReportRescue] held here is secret material, like the decrypt
 * identity: it holds the phrase-derived legacy keyring and the links of the
 * report key chain, from which the witness's report keys derive. [close]
 * destroys it, and nothing else may keep a reference to it.
 *
 * The verification itself lives in Rust ([ReportCheck]): every key and id is
 * re-derived from the phrase, every stored object is hashed while it is written
 * to disk, and what does not verify is deleted. Kotlin only orchestrates the
 * calls and decides where a kept file goes; it never receives a hash it could
 * substitute.
 *
 * Threading: every call blocks on the network or the disk. Call from a
 * background thread or coroutine (`Dispatchers.IO`). A
 * [uniffi.frappuccino.FfiException.RateLimited] means: wait, then repeat the
 * same call.
 */
class ArchiveSession private constructor(
    private val client: FfiServerClient,
    private val rescue: FfiReportRescue,
) : AutoCloseable {

    @Volatile
    private var closed = false

    /** The directory's listing, or null when the relay has no directory for
     *  this phrase. */
    fun openDirectory(): ReportCheck? = live().openDirectory(client)

    /** The enumeration plan. [directory] is the result of [openDirectory]
     *  (null when absent): a closed or missing directory makes the plan probe
     *  a longer tail. */
    fun planner(directory: ReportCheck?): RescuePlanner = live().planner(directory)

    /** The listing of the report [target] re-derives; null on 404, which is a
     *  hole in the enumeration, never the end of it. */
    fun openReport(target: RescueTarget): ReportCheck? = live().openReport(client, target)

    /**
     * Decrypt a STRM file that a [ReportCheck] kept. The plaintext never
     * crosses into the JVM: Rust writes it to [output], which the caller
     * secure-deletes once read. Call only on a file whose status is
     * `VERIFIED`; decryption is not a verification (the STRM header is
     * sealed to the public identity, so anyone can produce one).
     */
    fun decryptToFile(input: File, output: File, identity: ArchiveIdentity): BlobMetadata {
        live()
        return uniffi.frappuccino.strmDecryptToFile(input.path, output.path, identity.inner)
    }

    /**
     * SHA-256 of the plaintext of the verified STRM file [input], computed in
     * Rust. The plaintext transits through [scratch], which is secure-deleted
     * before this returns, whatever happens.
     */
    fun plaintextHash(input: File, scratch: File, identity: ArchiveIdentity): ByteArray {
        try {
            decryptToFile(input, scratch, identity)
            return uniffi.frappuccino.provenanceHashPlaintextFile(scratch.path)
        } finally {
            secureDelete(scratch)
        }
    }

    /** Destroy the phrase-derived rescue material and the relay client.
     *  Idempotent. A call in flight on another thread completes first: the
     *  generated bindings defer the release until it returns. */
    override fun close() {
        if (closed) return
        closed = true
        try {
            rescue.destroy()
        } catch (_: Exception) {
        }
        try {
            client.destroy()
        } catch (_: Exception) {
        }
    }

    private fun live(): FfiReportRescue {
        check(!closed) { "ArchiveSession is closed" }
        return rescue
    }

    companion object {
        /**
         * Build a rescue context for [serverUrl] from the phrase.
         *
         * Like [ArchiveIdentity.fromMnemonic], this does not wipe its
         * arguments: the caller wipes [mnemonic] and [passphrase] right after
         * the call. The phrase is checked (words and checksum) first, so a
         * mistyped phrase fails here instead of finding nothing.
         *
         * @throws uniffi.frappuccino.FfiException on an invalid phrase or an
         *   unusable relay URL.
         */
        fun open(serverUrl: String, mnemonic: ByteArray, passphrase: ByteArray = ByteArray(0)): ArchiveSession {
            val rescue = FfiReportRescue.fromMnemonic(mnemonic, passphrase)
            val client = try {
                FfiServerClient(serverUrl)
            } catch (e: Exception) {
                rescue.destroy()
                throw e
            }
            return ArchiveSession(client, rescue)
        }

        /** Overwrite then unlink [file]; a plain delete if the overwrite fails,
         *  including when the native library cannot be loaded (an erase must
         *  still remove the file). No-op on a missing file. */
        fun secureDelete(file: File) {
            try {
                uniffi.frappuccino.secureDeleteFile(file.path)
            } catch (_: Exception) {
                file.delete()
            } catch (_: LinkageError) {
                file.delete()
            }
        }
    }
}
