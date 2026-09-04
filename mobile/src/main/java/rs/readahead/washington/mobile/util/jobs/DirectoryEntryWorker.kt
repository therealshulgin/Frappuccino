package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Data
import androidx.work.Worker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import org.stream.crypto.upload.StreamUploadManager
import timber.log.Timber
import java.io.File

/**
 * WorkManager Worker that appends ONE entry to the witness's report directory
 * over the relay-blind capability path (Phase C).
 *
 * An entry's relay-visible blob name must stay the opaque, secret-derived
 * `directoryEntryNameHex(n)` (M-1), and its body must stay index-free. The
 * local staging name is a plain `%010d`; reusing that on the wire would turn
 * the directory into a session counter the blind relay can read off.
 *
 * Why the directory exists. The relay is blind (it stores `report_id →
 * report_pk`, never "identity → its reports"), so the rescue device cannot ask
 * "what do I own" — it must discover its reports by deriving `report_id_0,
 * report_id_1, …`. Without an authoritative `n_max` it would have to *guess*
 * where to stop (a hole-tolerance constant), which silently truncates the
 * recovery when a run of allocated-but-never-uploaded indices (failed/aborted
 * recordings) sits between two real reports. The directory removes the guess:
 * it is a singleton, phrase-derived report (dedicated HKDF context). The device
 * appends one tiny entry per session start; at rescue, `list_blobs(directory)`
 * yields those opaque names and the rescue re-derives
 * `directoryEntryNameHex(0..)` to match them back, recovering the authoritative
 * `n_max`, so it enumerates `0..n_max` exactly.
 *
 * Contract. One entry per session, written at index allocation (so the
 * directory's `n_max` is always ≥ any created report — a directory entry without
 * a report is a harmless 404 at rescue; a report without its directory entry
 * only matters if it is the very latest, the inherent single-relay residual).
 * `is_creation = (reportIndex == 0)`: the first session after enrollment/cutover
 * lazily creates the directory report (0x07 + bearer); every later entry is a
 * pure write (0x08, no bearer) and 425-retries until the creating entry lands.
 * Rust-only + retry-on-Throwable, identical to the chunk path (the keyring IS
 * the FFI, so there is no signable fallback).
 */
@HiltWorker
class DirectoryEntryWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters
) : Worker(context, workerParams) {

    companion object {
        const val KEY_FILE_PATH = "filePath"
        const val KEY_SERVER_URL = "serverUrl"
        const val KEY_REPORT_INDEX = "reportIndex"

        fun buildInputData(filePath: String, serverUrl: String, reportIndex: Int): Data =
            Data.Builder()
                .putString(KEY_FILE_PATH, filePath)
                .putString(KEY_SERVER_URL, serverUrl)
                .putInt(KEY_REPORT_INDEX, reportIndex)
                .build()

        /** LOCAL staging filename + WorkManager unique-work key for a report
         *  index. LOCAL-ONLY — never sent to the relay. The relay-visible WIRE
         *  name is the opaque, secret-derived `keyring.directoryEntryNameHex(n)`
         *  (M-1), computed in [doWork]; the staging file is read by absolute path,
         *  so its local name is just a stable per-index handle. */
        fun localStagingName(reportIndex: Int): String = "%010d".format(reportIndex)
    }

    override fun doWork(): Result {
        val filePath = inputData.getString(KEY_FILE_PATH) ?: return Result.failure()
        val serverUrl = inputData.getString(KEY_SERVER_URL) ?: return Result.failure()
        val reportIndex = inputData.getInt(KEY_REPORT_INDEX, -1)
        if (reportIndex < 0) {
            Timber.e("DirectoryEntryWorker: missing reportIndex, failing")
            return Result.failure()
        }

        val file = File(filePath)
        if (!file.exists() || file.length() == 0L) {
            Timber.d("DirectoryEntryWorker: entry blob missing/empty, nothing to do: %d", reportIndex)
            return Result.success()
        }

        val keyring = StreamUploadManager.getInstance(applicationContext).reportKeyring
        if (keyring == null) {
            Timber.tag("StreamMetrics").i("directory retry reason=no_report_keyring index=%d", reportIndex)
            return Result.retry()
        }

        // Index 0's entry lazily creates the directory report (needs the bearer).
        // Later entries are pure writes (no bearer); they 425-retry until the
        // creating entry lands. The creation isn't latency-critical, so on a
        // missing bearer we simply retry until the session's auth publishes one.
        val isCreation = reportIndex == 0
        if (isCreation && !UploadAuthHolder.isPresent()) {
            Timber.tag("StreamMetrics").i("directory retry reason=no_auth_token index=0 creation=true")
            return Result.retry()
        }

        if (UploadCircuitBreaker.isOpen()) {
            Timber.tag("StreamMetrics").i("directory retry reason=circuit_open index=%d", reportIndex)
            return Result.retry()
        }

        return try {
            // M-1 — the relay-visible WIRE name is opaque + secret-derived (hex of
            // HKDF(report_master, ctx || n)), so the directory no longer
            // fingerprints as a `%010d` session counter. Derived from the live
            // keyring here (a throw is caught + retried below, entry preserved).
            val filename = keyring.directoryEntryNameHex(reportIndex.toUInt())
            val url = "$serverUrl/file/${keyring.directoryIdHex()}/$filename"
            val outcome = uniffi.frappuccino.uploadPutDirectoryEntry(
                url, file.absolutePath, RustUploadTransport.mode, keyring, filename, isCreation,
            )
            val code = outcome.httpStatus.toInt()
            if (code == 0 && outcome.errorDetail == "file_missing") {
                Timber.d("DirectoryEntryWorker: entry gone (race), success %d", reportIndex)
                return Result.success()
            }
            mapStatus(code, file, reportIndex, isCreation)
        } catch (t: Throwable) {
            // Rust-only (Phase C): the capability headers are signed by the
            // reportKeyring (the FFI), so a sick binding has no signable
            // fallback. Retry (the entry stays on disk, 0 loss). VME propagates;
            // a benign Interrupted is restored + retried.
            if (t is VirtualMachineError) throw t
            if (t is InterruptedException) {
                Thread.currentThread().interrupt()
                Timber.tag("StreamMetrics").i("directory retry reason=interrupted index=%d", reportIndex)
                return Result.retry()
            }
            Timber.e(t, "DirectoryEntryWorker: native transport threw for index %d — retry (entry preserved)", reportIndex)
            Timber.tag("StreamMetrics").i("directory retry reason=transport_threw index=%d", reportIndex)
            Result.retry()
        }
    }

    /** Mirrors [ChunkUploadWorker]'s status handling (425 retry, 429 retry, 4xx
     *  failure, 5xx/507/0 retry, 2xx → success + secure-delete). */
    private fun mapStatus(code: Int, file: File, reportIndex: Int, isCreation: Boolean): Result {
        return when {
            code in 200..299 -> {
                UploadCircuitBreaker.reportSuccess()
                Timber.i("Directory entry %d written (creation=%b)", reportIndex, isCreation)
                try {
                    uniffi.frappuccino.secureDeleteFile(file.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "DirectoryEntryWorker: secureDelete after upload failed for %d", reportIndex)
                    file.delete()
                }
                Result.success()
            }
            code == 401 -> {
                Timber.w("DirectoryEntryWorker: 401 — clearing JWT and retrying %d", reportIndex)
                UploadAuthHolder.clear()
                Result.retry()
            }
            code == 425 -> {
                // Directory report not created yet (this non-creating entry beat
                // the index-0 creating entry). Retry until the directory exists.
                Timber.d("DirectoryEntryWorker: 425 directory not created yet, retry %d", reportIndex)
                Timber.tag("StreamMetrics").i("directory retry reason=not_created index=%d", reportIndex)
                Result.retry()
            }
            code == 429 -> {
                // Two possible sources, both transient and both correctly handled
                // by a retry: the per-(identity, batch) creation budget, which
                // only the creating entry can hit since it alone carries a
                // bearer, and the per-IP rate limit on the PUT route, which any
                // entry can hit during a backlog flush. Retry, never drop. (The
                // metrics label below still reads `creation_budget`, narrower
                // than the two cases.)
                Timber.w("DirectoryEntryWorker: 429 creation budget — retry %d", reportIndex)
                Timber.tag("StreamMetrics").i("directory retry reason=creation_budget index=%d", reportIndex)
                Result.retry()
            }
            code in 400..499 -> {
                Timber.e("DirectoryEntryWorker: permanent failure %d for index %d", code, reportIndex)
                Result.failure()
            }
            code == 507 -> {
                UploadCircuitBreaker.reportDiskFull()
                Timber.w("DirectoryEntryWorker: 507 disk-full for %d — circuit opened", reportIndex)
                Result.retry()
            }
            code >= 500 -> {
                UploadCircuitBreaker.reportServerError(code)
                Timber.w("DirectoryEntryWorker: temporary failure %d for index %d", code, reportIndex)
                Result.retry()
            }
            else -> {
                // code == 0 — transport error (no HTTP response).
                UploadCircuitBreaker.reportServerError(0)
                Timber.tag("StreamMetrics").i("directory retry reason=transport_error index=%d", reportIndex)
                Result.retry()
            }
        }
    }
}
