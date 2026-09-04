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
 * Makes a recording's opt-in OTS proof (`<sessionId>.ots`) durable on the relay,
 * over the relay-blind capability path (§10.11).
 *
 * Rust-only by construction, like [ChunkUploadWorker]: the capability headers
 * are signed by the reportKeyring, which IS the FFI, so a sick native binding
 * has no OkHttp fallback that could sign. Don't add one for robustness — an
 * OkHttp PUT would be identity-based and rejected by the blind relay. A
 * [Throwable] is caught and we retry (the `.ots` stays on disk, 0 loss) until a
 * healthy build runs it.
 *
 * The write is never a creation (relay-blind contract, Phase C 3.3e). The `.ots`
 * is just another opaque blob under the recording's report
 * (`PUT /file/{report_id}/{filename}`, write-once, idempotent), and the report
 * is created by the session's metadata blob (seq 0), so this worker always PUTs
 * with `is_creation = false`. If the report does not exist yet — its metadata
 * PUT hasn't landed — the relay answers **425**, meaning "not yet, come back",
 * and we retry until it does. Treating that 425 as a failure, or flipping
 * `is_creation` to true, breaks the contract. No bearer is needed either: the
 * write-sig authorises the write.
 *
 * The local `filesDir/stream_provenance/<sessionId>.ots` is secure-deleted after
 * a confirmed upload. Keeping it "to be safe" does the opposite: once durable on
 * the relay it is redundant at-rest data, and the `<sessionId>.ots` filename is
 * a session-correlation handle on a seizable device. `panicWipe` purges
 * `stream_provenance` to cover the build→upload window and any never-uploaded
 * orphan.
 *
 * Like the chunk path, this re-derives the identity-free report_id and signs the
 * 0x08 write-sig INSIDE Rust from the live [StreamUploadManager.reportKeyring],
 * carrying only the report's derivation index `n` — never the report_id, never
 * the identity.
 *
 * It survives process death + reboot and auto-retries on network, like the video
 * chunks it accompanies. The `.ots` is the durability artefact — losing it to a
 * device wipe / seizure is exactly what uploading it prevents.
 */
@HiltWorker
class ProvenanceUploadWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters
) : Worker(context, workerParams) {

    companion object {
        const val KEY_FILE_PATH = "filePath"
        const val KEY_SERVER_URL = "serverUrl"
        // Phase C — the report's derivation index n (report_id =
        // reportKeyring.reportIdHex(n)), not the server-assigned report_id.
        const val KEY_REPORT_INDEX = "reportIndex"
        const val KEY_BLOB_NAME = "blobName"

        fun buildInputData(
            filePath: String,
            serverUrl: String,
            reportIndex: Int,
            blobName: String,
        ): Data = Data.Builder()
            .putString(KEY_FILE_PATH, filePath)
            .putString(KEY_SERVER_URL, serverUrl)
            .putInt(KEY_REPORT_INDEX, reportIndex)
            .putString(KEY_BLOB_NAME, blobName)
            .build()
    }

    override fun doWork(): Result {
        val filePath = inputData.getString(KEY_FILE_PATH) ?: return Result.failure()
        val serverUrl = inputData.getString(KEY_SERVER_URL) ?: return Result.failure()
        val reportIndex = inputData.getInt(KEY_REPORT_INDEX, -1)
        if (reportIndex < 0) {
            Timber.e("ProvenanceUploadWorker: missing reportIndex, failing")
            return Result.failure()
        }
        val blobName = inputData.getString(KEY_BLOB_NAME) ?: return Result.failure()

        val file = File(filePath)
        if (!file.exists() || file.length() == 0L) {
            // Already gone (e.g. panic-wipe ran, or a prior success removed it)
            // — nothing to upload, not a failure.
            Timber.d("ProvenanceUploadWorker: blob missing/empty, nothing to do: %s", blobName)
            return Result.success()
        }

        // Phase C — the keyring (FFI) signs the write. Absent = ratchet locked →
        // defer; the next unlock reloads it. No bearer/secret enters the JVM.
        val keyring = StreamUploadManager.getInstance(applicationContext).reportKeyring
        if (keyring == null) {
            Timber.tag("StreamMetrics").i("provenance retry reason=no_report_keyring blob=%s", blobName)
            return Result.retry()
        }

        // Coordinate with the chunk cohort's circuit breaker: if the relay is
        // already known-down, defer rather than add noise. Read-only here.
        if (UploadCircuitBreaker.isOpen()) {
            Timber.tag("StreamMetrics").i("provenance retry reason=circuit_open blob=%s", blobName)
            return Result.retry()
        }

        return try {
            val reportIdHex = keyring.reportIdHex(reportIndex.toUInt())
            val url = "$serverUrl/file/$reportIdHex/$blobName"
            // Heap-0 capability PUT (write only, never creation): Rust re-derives
            // report_id from (keyring, n), hashes the blob byte-identically to the
            // relay, signs the 0x08 write-sig, and PUTs.
            val outcome = uniffi.frappuccino.uploadPutReportChunk(
                url, file.absolutePath, RustUploadTransport.mode,
                keyring, reportIndex.toUInt(), blobName, /* isCreation = */ false,
            )
            val code = outcome.httpStatus.toInt()
            if (code == 0 && outcome.errorDetail == "file_missing") {
                Timber.d("ProvenanceUploadWorker: blob gone (race), success %s", blobName)
                return Result.success()
            }
            mapStatus(code, file, blobName, outcome.transportUsed)
        } catch (t: Throwable) {
            // Rust-only (Phase C): the capability headers are signed by the
            // reportKeyring, which IS the FFI — a Throwable means the native
            // binding is unhealthy in THIS build, and the same break disables the
            // keyring, so there is no OkHttp fallback that could sign. We retry
            // (the .ots stays on disk, 0 loss). VME propagates; a benign
            // Interrupted is restored + retried.
            if (t is VirtualMachineError) throw t
            if (t is InterruptedException) {
                Thread.currentThread().interrupt()
                Timber.tag("StreamMetrics").i("provenance retry reason=interrupted blob=%s", blobName)
                return Result.retry()
            }
            Timber.e(t, "ProvenanceUploadWorker: native transport threw for %s — retry (blob preserved)", blobName)
            Timber.tag("StreamMetrics").i("provenance retry reason=transport_threw blob=%s", blobName)
            Result.retry()
        }
    }

    /**
     * Map an HTTP status to a WorkManager [Result]. Close to
     * [ChunkUploadWorker]'s status handling, though not identical to it.
     *
     * The 401 branch is kept for symmetry with the chunk path, not because a
     * bearer would be required here — a write carries none. Don't remove it as
     * dead code: a 401 would then land in the generic 4xx case, hence in a
     * permanent failure.
     *
     * 507 stays a branch of its own, tested before `>= 500`, because it opens
     * the disk-full circuit and retries so as never to lose the blob. Folding it
     * into the generic 5xx case loses that opening.
     *
     * On this path any 4xx other than 401 and 425 is a permanent failure, 429
     * included — unlike the chunk path, which retries 429 explicitly because a
     * failure there would be data loss.
     */
    private fun mapStatus(code: Int, file: File, blobName: String, transportUsed: String): Result {
        return when {
            code in 200..299 -> {
                UploadCircuitBreaker.reportSuccess()
                Timber.i("Provenance blob uploaded: %s (%d bytes) transport=%s", blobName, file.length(), transportUsed)
                // Durable on the relay now → secure-delete the local copy: leaving
                // it on a seizable device is redundant at-rest data, and the
                // <sessionId>.ots filename is a session-correlation handle.
                try {
                    uniffi.frappuccino.secureDeleteFile(file.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "ProvenanceUploadWorker: secureDelete after upload failed for %s", blobName)
                    file.delete()
                }
                Result.success()
            }
            code == 401 -> {
                Timber.w("ProvenanceUploadWorker: 401 — clearing JWT and retrying %s", blobName)
                UploadAuthHolder.clear()
                Result.retry()
            }
            code == 425 -> {
                Timber.d("ProvenanceUploadWorker: 425 report not created yet, retry %s", blobName)
                Timber.tag("StreamMetrics").i("provenance retry reason=report_not_created blob=%s", blobName)
                Result.retry()
            }
            code in 400..499 -> {
                Timber.e("ProvenanceUploadWorker: permanent failure %d for %s", code, blobName)
                Result.failure()
            }
            code == 507 -> {
                UploadCircuitBreaker.reportDiskFull()
                Timber.w("ProvenanceUploadWorker: 507 disk-full for %s — circuit opened", blobName)
                Timber.tag("StreamMetrics").i("provenance retry reason=server_disk_full blob=%s", blobName)
                Result.retry()
            }
            code >= 500 -> {
                UploadCircuitBreaker.reportServerError(code)
                Timber.w("ProvenanceUploadWorker: temporary failure %d for %s", code, blobName)
                Result.retry()
            }
            else -> {
                // code == 0 — transport error (no HTTP response).
                UploadCircuitBreaker.reportServerError(0)
                Timber.tag("StreamMetrics").i("provenance retry reason=transport_error blob=%s", blobName)
                Result.retry()
            }
        }
    }
}
