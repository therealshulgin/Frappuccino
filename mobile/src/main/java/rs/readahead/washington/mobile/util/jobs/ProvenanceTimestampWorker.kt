package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Data
import androidx.work.Worker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.io.File

/**
 * Submits a recording's salted OTS commitment to the relay for trustless
 * timestamping (§10.11).
 *
 * Never make the device submit the commitment straight to the `OpenTimestamps`
 * calendars, even though it would be one hop shorter: those calendars are third
 * parties the witness never chose, and a direct submission would show them the
 * witness's IP. The device only ever talks to the relay it already trusts, and
 * the relay submits on its behalf.
 *
 * Opt-in per recording, default OFF ([org.stream.crypto.StreamPreferences.
 * isProvenanceTimestampEnabled]): a `.ots` is a permanent PUBLIC Bitcoin
 * breadcrumb. What is submitted is a salted commitment over the media Merkle
 * root — `SHA-256(salt ‖ chunk_merkle_root(chunk hashes))`, salt =
 * HKDF(provenance seed, recording_id). No signature and no manifest are
 * committed. The salt is what stops the relay from linking the stamp to a
 * stored report, and it is re-derived at rescue (never uploaded).
 *
 * The POST goes to `POST /api/v2/timestamp` and comes back with a detached
 * `.ots` proof, written to the `otsFilePath`
 * (`filesDir/stream_provenance/<sessionId>.ots`); a CHAINED
 * [ProvenanceUploadWorker] (WorkManager `.then`) then makes it durable on the
 * relay and secure-deletes the local copy — same survive-process-death +
 * survive-reboot + auto-retry guarantees as the `.fpm` and the video chunks.
 *
 * Unlike the heap-0 chunk PUT path, this reads the bearer from
 * [UploadAuthHolder] into the JVM because the `.ots` response body must be read
 * back. Accepted for a rare opt-in POST — but since the chunk PUT moved into
 * Rust this is the only OkHttp path still carrying the bearer, which is what
 * [UploadAuthHolder.clear]'s connection-pool eviction is there for.
 */
@HiltWorker
class ProvenanceTimestampWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters
) : Worker(context, workerParams) {

    companion object {
        const val KEY_COMMITMENT_HEX = "commitmentHex"
        const val KEY_SERVER_URL = "serverUrl"
        const val KEY_SESSION_ID = "sessionId"
        const val KEY_OTS_FILE_PATH = "otsFilePath"

        fun buildInputData(
            commitmentHex: String,
            serverUrl: String,
            sessionId: String,
            otsFilePath: String,
        ): Data = Data.Builder()
            .putString(KEY_COMMITMENT_HEX, commitmentHex)
            .putString(KEY_SERVER_URL, serverUrl)
            .putString(KEY_SESSION_ID, sessionId)
            .putString(KEY_OTS_FILE_PATH, otsFilePath)
            .build()
    }

    override fun doWork(): Result {
        val commitmentHex = inputData.getString(KEY_COMMITMENT_HEX) ?: return Result.failure()
        val serverUrl = inputData.getString(KEY_SERVER_URL) ?: return Result.failure()
        val sessionId = inputData.getString(KEY_SESSION_ID) ?: return Result.failure()
        val otsFilePath = inputData.getString(KEY_OTS_FILE_PATH) ?: return Result.failure()

        // The .ots response body must be read → JVM OkHttp path (not heap-0).
        val authToken = UploadAuthHolder.get() ?: run {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=no_auth_token session=%s", sessionId)
            return Result.retry()
        }
        // Coordinate with the chunk cohort's circuit breaker: if the relay is
        // already known-down, defer rather than add noise.
        if (UploadCircuitBreaker.isOpen()) {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=circuit_open session=%s", sessionId)
            return Result.retry()
        }

        val url = "$serverUrl/api/v2/timestamp"
        val body = "{\"commitment\":\"$commitmentHex\"}"
            .toRequestBody("application/json".toMediaType())
        return try {
            val request = Request.Builder()
                .url(url)
                .header("Authorization", authToken)
                .post(body)
                .build()
            UploadHttpClient.instance.newCall(request).execute().use { resp ->
                mapResponse(resp.code, resp.body?.bytes(), otsFilePath, sessionId)
            }
        } catch (e: Exception) {
            UploadCircuitBreaker.reportServerError(0)
            Timber.w(e, "ProvenanceTimestampWorker: network error for %s, will retry", sessionId)
            Result.retry()
        }
    }

    /**
     * Map the relay's response. On 2xx the `.ots` body is written to
     * `otsFilePath` (the chained upload worker makes it durable). The rest
     * broadly follows the chunk worker's retry/failure policy, with these
     * divergences:
     *  - 503 → relay timestamping is dormant (config, not transient) → give up.
     *  - 502 → calendars unreachable (transient upstream) → retry.
     *  - 429 has no branch of its own here, unlike the chunk path, so it falls
     *    into the 4xx case and gives up for good.
     */
    private fun mapResponse(
        code: Int,
        otsBytes: ByteArray?,
        otsFilePath: String,
        sessionId: String,
    ): Result {
        return when {
            code in 200..299 -> {
                if (otsBytes == null || otsBytes.isEmpty()) {
                    Timber.w("ProvenanceTimestampWorker: empty .ots body for %s — retry", sessionId)
                    return Result.retry()
                }
                UploadCircuitBreaker.reportSuccess()
                val otsFile = File(otsFilePath)
                otsFile.parentFile?.mkdirs()
                otsFile.writeBytes(otsBytes)
                Timber.i(
                    "Provenance .ots received: %s (%d bytes) → chained durable upload",
                    otsFile.name, otsBytes.size
                )
                Result.success()
            }
            code == 401 -> {
                Timber.w("ProvenanceTimestampWorker: 401 — clearing JWT and retrying %s", sessionId)
                UploadAuthHolder.clear()
                Result.retry()
            }
            code == 503 -> {
                // Relay timestamping not enabled. It's a relay config state, not a
                // transient blip — retrying won't help. The opt-in user simply gets
                // no stamp until the operator turns OTS on (separate deploy).
                Timber.w("ProvenanceTimestampWorker: 503 — relay timestamping disabled, giving up for %s", sessionId)
                Timber.tag("StreamMetrics").i("provenance_ts fail reason=ots_disabled session=%s", sessionId)
                Result.failure()
            }
            code == 502 -> {
                Timber.w("ProvenanceTimestampWorker: 502 — calendars unreachable for %s, will retry", sessionId)
                Timber.tag("StreamMetrics").i("provenance_ts retry reason=calendars_unreachable session=%s", sessionId)
                Result.retry()
            }
            code in 400..499 -> {
                Timber.e("ProvenanceTimestampWorker: permanent failure %d for %s", code, sessionId)
                Result.failure()
            }
            code >= 500 -> {
                UploadCircuitBreaker.reportServerError(code)
                Timber.w("ProvenanceTimestampWorker: temporary failure %d for %s, will retry", code, sessionId)
                Result.retry()
            }
            else -> {
                // code == 0 — transport error (no HTTP response).
                UploadCircuitBreaker.reportServerError(0)
                Timber.tag("StreamMetrics").i("provenance_ts retry reason=transport_error session=%s", sessionId)
                Result.retry()
            }
        }
    }
}
