package rs.readahead.washington.mobile.archive

import java.io.File
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException

/**
 * What an export wrote.
 *
 * @property written files written to the destination.
 * @property undecryptable objects excluded because they do not decrypt.
 * @property timestampLeftOut the timestamp proof and its salt were planned,
 *   and excluded because a chunk they commit to was.
 */
data class ExportOutcome(val written: Int, val undecryptable: Int, val timestampLeftOut: Boolean) {

    /** Every recording planned was excluded: the export holds nothing. */
    val nothingWritten: Boolean get() = written == 0 && undecryptable > 0
}

/**
 * The loop of one export ([ExportPlan]): which planned files are written, and
 * what becomes of an object that does not decrypt. Kept apart from Android and
 * from the FFI, which are passed in, so the rule is testable on a plain JVM.
 *
 * An object that does not decrypt is excluded from the export and counted,
 * and the rest of the report is exported. A verified signature says who
 * stored an object, not that it decrypts (see [TimestampCheck]); one such
 * object must not cost the witness the others. Each object is decrypted to a
 * private file BEFORE its file is created at the destination, so an excluded
 * one leaves nothing there, and the private file is secure-deleted after each
 * object, whatever happened to it.
 *
 * Anything else stops the export and is rethrown, for the caller to remove
 * the folder: a write to the destination, a copy shorter than its private
 * file, a local I/O error (the private copy could not be written), a
 * cancellation, any error that does not say the object itself does not
 * decrypt ([RescueFailures.isUndecryptable]). Cancellation is checked again
 * after every file written, so one seen while the last file was being copied
 * still removes the folder.
 *
 * The timestamp proof and its salt commit to every verified chunk. Once a
 * chunk is excluded, the exported folder no longer holds what they commit to,
 * so they are excluded too ([ExportOutcome.timestampLeftOut]) rather than
 * handed out as a proof the folder cannot match. They are written after every
 * recording, wherever the plan lists them, so that is known by then. The
 * metadata object is not part of that commitment: excluding it alone keeps
 * them.
 *
 * The names are the plan's: an excluded chunk leaves a gap in the numbering
 * of the exported parts.
 *
 * @param decrypt decrypts the STRM file `sealed` to `plain`.
 * @param secureDelete overwrites then unlinks a private plaintext file; a
 *   no-op on a missing file.
 * @param destination where the files go.
 */
internal class ExportRun<D>(
    private val decrypt: (sealed: File, plain: File) -> Unit,
    private val secureDelete: (File) -> Unit,
    private val destination: Destination<D>,
    private val undecryptable: (Throwable) -> Boolean = RescueFailures::isUndecryptable,
) {

    /** Where the files go: in the app, documents of the folder the witness picked. */
    interface Destination<D> {
        /** Create the file [item] names. */
        fun create(item: ExportPlan.Item): D

        /** Copy the private plaintext [plain] into [target]; returns the
         *  number of bytes written. */
        fun copy(plain: File, target: D): Long

        /** Write the timestamp proof, or its salt, as [item]'s kind says. */
        fun writeTimestamp(item: ExportPlan.Item, target: D)
    }

    /**
     * Write [plan]. Each recording comes from [sources] (relay object name →
     * local encrypted file) and is decrypted to [plain].
     *
     * @param onItem `(done, total)` after each planned item, written or excluded.
     */
    fun run(
        plan: List<ExportPlan.Item>,
        sources: Map<String, File>,
        plain: File,
        isActive: () -> Boolean,
        onItem: (done: Int, total: Int) -> Unit,
    ): ExportOutcome {
        val (recordings, timestamp) = plan.partition {
            it.kind == ExportPlan.Kind.VIDEO || it.kind == ExportPlan.Kind.METADATA
        }
        var done = 0
        var written = 0
        var excluded = 0
        var chunkExcluded = false
        for (item in recordings) {
            if (!isActive()) throw CancellationException("export cancelled")
            val sealed = item.sourceName?.let { sources[it] } ?: throw IOException("object to export missing")
            try {
                if (decrypts(sealed, plain)) {
                    val expected = plain.length()
                    val copied = destination.copy(plain, destination.create(item))
                    if (copied != expected) throw IOException("export copy incomplete")
                    // A close or an emergency wipe erases the private copy in
                    // place while it is being read: a copy that ran into one
                    // is not trusted even when its length came out right.
                    if (!isActive()) throw CancellationException("export cancelled")
                    written++
                } else {
                    excluded++
                    if (item.kind == ExportPlan.Kind.VIDEO) chunkExcluded = true
                }
            } finally {
                secureDelete(plain)
            }
            onItem(++done, plan.size)
        }
        var timestampLeftOut = false
        for (item in timestamp) {
            if (!isActive()) throw CancellationException("export cancelled")
            if (chunkExcluded) {
                timestampLeftOut = true
            } else {
                destination.writeTimestamp(item, destination.create(item))
                if (!isActive()) throw CancellationException("export cancelled")
                written++
            }
            onItem(++done, plan.size)
        }
        return ExportOutcome(written, excluded, timestampLeftOut)
    }

    /** True when [sealed] decrypted to [plain], false when it does not
     *  decrypt; any other failure is rethrown. */
    private fun decrypts(sealed: File, plain: File): Boolean = try {
        decrypt(sealed, plain)
        true
    } catch (e: Exception) {
        if (!undecryptable(e)) throw e
        false
    }
}
