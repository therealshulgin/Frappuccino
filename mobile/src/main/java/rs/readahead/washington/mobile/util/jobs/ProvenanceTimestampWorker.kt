package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.stream.crypto.SecureWipe
import org.stream.crypto.upload.EnvelopeQueue
import org.stream.crypto.upload.LegacyReportMigration
import org.stream.crypto.upload.QueueKeyStore
import org.stream.crypto.upload.StreamUploadManager
import org.stream.crypto.upload.TimestampTicketPolicy
import timber.log.Timber
import uniffi.frappuccino.FfiException
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Gets a closed report's opt-in OTS timestamp (§10.11) and turns it into a
 * queue envelope.
 *
 * Never make the device submit the commitment straight to the `OpenTimestamps`
 * calendars, even though it would be one hop shorter: those calendars are third
 * parties the witness never chose, and a direct submission would show them the
 * witness's IP. The device only ever talks to the relay it already trusts, and
 * the relay submits on its behalf.
 *
 * Opt-in, default OFF: a `.ots` is a permanent PUBLIC Bitcoin breadcrumb. What
 * is submitted is a salted commitment over the hashes of the chunks the
 * closure lists; the salt stops the relay from linking the stamp to a stored
 * report, and it is re-derived at rescue, never uploaded.
 *
 * The job gets the path of a TICKET only (written by Rust at the report's
 * closure, sealed under the queue key: the proof's name in the directory and
 * the commitment). On a 2xx, ONE Rust call checks that the proof stamps the
 * ticket's commitment, encrypts it to the witness's identity, signs it with
 * the directory key and writes the envelope: the `.ots` bytes never reach the
 * disk in clear. That call reads the report state, so the submission is only
 * attempted while the PIN session is open; a locked device waits. The POST
 * needs the upload bearer: without one, the worker gets it itself
 * ([ensureBearer], one ratchet slot at most per need).
 *
 * The ticket is written once and nothing writes it again, so it is deleted
 * only when it can never serve ([TimestampTicketPolicy]); a read that fails
 * for another reason keeps it.
 *
 * The proof's bytes do pass through the JVM (OkHttp reads the response), and
 * so does the bearer for the POST: accepted for a rare opt-in request. The
 * proof array is wiped after sealing.
 */
@HiltWorker
class ProvenanceTimestampWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters
) : Worker(context, workerParams) {

    companion object {
        const val KEY_TICKET_PATH = "ticketPath"
        const val KEY_ENVELOPE_PATH = "envelopePath"
        const val KEY_SERVER_URL = "serverUrl"
        const val TAG = "stream_provenance_ticket"

        fun buildInputData(ticketPath: String, envelopePath: String, serverUrl: String): Data =
            Data.Builder()
                .putString(KEY_TICKET_PATH, ticketPath)
                .putString(KEY_ENVELOPE_PATH, envelopePath)
                .putString(KEY_SERVER_URL, serverUrl)
                .build()

        /**
         * Schedule the submission of [ticket] (unique per ticket, KEEP), unless
         * an emergency wipe began since [wipeGeneration] (the job's row names
         * the session). Returns whether it was scheduled.
         */
        fun enqueue(context: Context, ticket: File, envelope: File, serverUrl: String, wipeGeneration: Int): Boolean {
            val request = OneTimeWorkRequest.Builder(ProvenanceTimestampWorker::class.java)
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .setInputData(buildInputData(ticket.absolutePath, envelope.absolutePath, serverUrl))
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.SECONDS)
                .addTag(TAG)
                .build()
            return StreamUploadManager.unlessWipedSince(wipeGeneration) {
                WorkManager.getInstance(context)
                    .enqueueUniqueWork(ticket.name, ExistingWorkPolicy.KEEP, request)
            } != null
        }
    }

    override fun doWork(): Result {
        val wipeAtStart = StreamUploadManager.wipeGeneration()
        // A job from before the tickets carries no ticket path. It stays
        // pending until the legacy migration has counted it (and told the
        // witness its timestamp was cancelled), then ends.
        val ticketPath = inputData.getString(KEY_TICKET_PATH) ?: return when (
            TimestampTicketPolicy.forLegacyJob(LegacyReportMigration.isNeeded(applicationContext))
        ) {
            TimestampTicketPolicy.Outcome.RETRY -> Result.retry()
            else -> Result.failure()
        }
        val envelopePath = inputData.getString(KEY_ENVELOPE_PATH) ?: return Result.failure()
        val serverUrl = inputData.getString(KEY_SERVER_URL) ?: return Result.failure()
        val ticket = File(ticketPath)
        val envelope = File(envelopePath)
        val queue = EnvelopeQueue.get(applicationContext)

        if (!ticket.exists()) {
            if (envelope.exists()) ChunkUploadWorker.enqueue(applicationContext, envelope, serverUrl, wipeAtStart)
            return Result.success()
        }
        if (envelope.exists() && queue.isQueued(envelope)) {
            // Sealed by an earlier run that died before removing the ticket.
            EnvelopeQueue.secureDelete(ticket)
            ChunkUploadWorker.enqueue(applicationContext, envelope, serverUrl, wipeAtStart)
            return Result.success()
        }

        val manager = StreamUploadManager.getInstance(applicationContext)
        if (!manager.isUnlocked()) {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=locked")
            return Result.retry()
        }
        if (!QueueKeyStore.ensureInstalled(applicationContext)) {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=no_queue_key")
            return Result.retry()
        }
        val commitmentHex = try {
            uniffi.frappuccino.otsTicketCommitment(ticket.absolutePath)
                .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        } catch (e: Exception) {
            return when (TimestampTicketPolicy.forReadFailure(e)) {
                TimestampTicketPolicy.Outcome.DROP_TICKET -> {
                    Timber.w(e, "ProvenanceTimestampWorker: unreadable ticket, dropped")
                    EnvelopeQueue.secureDelete(ticket)
                    Result.failure()
                }
                else -> {
                    Timber.w(e, "ProvenanceTimestampWorker: ticket not read, retry")
                    Result.retry()
                }
            }
        }

        // Nothing else obtains a bearer for a ticket: the sweep only does so
        // for queued envelopes, and the lock-timeout controller drops the
        // bearer once no envelope needs it. Without this, a ticket whose first
        // attempt failed waited for the next recording. One slot at most per
        // need, shared with every other authentication of the process.
        if (!UploadAuthHolder.isPresent() && !ensureBearer(applicationContext, serverUrl)) {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=no_auth_token")
            return Result.retry()
        }
        val authToken = UploadAuthHolder.get() ?: run {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=no_auth_token")
            return Result.retry()
        }
        if (UploadCircuitBreaker.isOpen()) {
            Timber.tag("StreamMetrics").i("provenance_ts retry reason=circuit_open")
            return Result.retry()
        }

        val body = "{\"commitment\":\"$commitmentHex\"}".toRequestBody("application/json".toMediaType())
        return try {
            val request = Request.Builder()
                .url("$serverUrl/api/v2/timestamp")
                .header("Authorization", authToken)
                .post(body)
                .build()
            UploadHttpClient.instance.newCall(request).execute().use { resp ->
                if (resp.code in 200..299) {
                    UploadCircuitBreaker.reportSuccess()
                    sealProof(resp.body?.bytes(), ticket, envelope, serverUrl, wipeAtStart)
                } else {
                    mapFailure(resp.code, ticket)
                }
            }
        } catch (e: Exception) {
            UploadCircuitBreaker.reportServerError(0)
            Timber.w(e, "ProvenanceTimestampWorker: network error, will retry")
            Result.retry()
        }
    }

    /** Seal the received proof into its envelope, then queue it. */
    private fun sealProof(
        proof: ByteArray?,
        ticket: File,
        envelope: File,
        serverUrl: String,
        wipeAtStart: Int,
    ): Result {
        if (proof == null || proof.isEmpty()) {
            Timber.w("ProvenanceTimestampWorker: empty proof, retry")
            return Result.retry()
        }
        val manager = StreamUploadManager.getInstance(applicationContext)
        val author = manager.authorIdentity() ?: run {
            SecureWipe.wipe(proof)
            return Result.retry()
        }
        return try {
            uniffi.frappuccino.pinSessionSealOtsProof(
                manager.reportStatePath(), ticket.absolutePath, proof, author, envelope.absolutePath
            )
            EnvelopeQueue.secureDelete(ticket)
            EnvelopeQueue.get(applicationContext).invalidate()
            ChunkUploadWorker.enqueue(applicationContext, envelope, serverUrl, wipeAtStart)
            Timber.i("Provenance proof sealed and queued")
            Result.success()
        } catch (e: FfiException.ReportRefused) {
            // The proof stamps something else than this ticket's commitment.
            Timber.e(e, "ProvenanceTimestampWorker: proof does not match its ticket, dropped")
            EnvelopeQueue.secureDelete(ticket)
            Result.failure()
        } catch (e: FfiException.InvalidBlob) {
            Timber.e(e, "ProvenanceTimestampWorker: not a timestamp proof, retry")
            Result.retry()
        } catch (e: FfiException) {
            // No PIN session any more (locked meanwhile), no key, I/O: the
            // ticket stays and a later run asks again.
            Timber.w(e, "ProvenanceTimestampWorker: seal deferred")
            Result.retry()
        } finally {
            SecureWipe.wipe(proof)
            author.destroy()
        }
    }

    /**
     * The relay's non-2xx answers. Mostly the chunk policy, with these
     * differences:
     *  - 503: relay timestamping is disabled (configuration, not a blip): give up.
     *  - 502: the calendars are unreachable (transient upstream): retry.
     *  - 401: the bearer was refused: drop it and retry.
     *  - any other 4xx gives up, 429 included.
     * Giving up deletes the ticket: nothing would ever read it again.
     */
    private fun mapFailure(code: Int, ticket: File): Result = when {
        code == 401 -> {
            UploadAuthHolder.clear()
            Result.retry()
        }
        code == 503 -> {
            Timber.tag("StreamMetrics").i("provenance_ts fail reason=ots_disabled")
            EnvelopeQueue.secureDelete(ticket)
            Result.failure()
        }
        code == 502 -> Result.retry()
        code in 400..499 -> {
            Timber.e("ProvenanceTimestampWorker: permanent failure %d", code)
            EnvelopeQueue.secureDelete(ticket)
            Result.failure()
        }
        code >= 500 -> {
            UploadCircuitBreaker.reportServerError(code)
            Result.retry()
        }
        else -> Result.retry()
    }
}
