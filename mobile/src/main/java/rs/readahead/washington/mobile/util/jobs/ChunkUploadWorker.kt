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
import org.stream.crypto.StreamPreferences
import org.stream.crypto.capture.AdaptiveQualityHolder
import org.stream.crypto.upload.EnvelopeNames
import org.stream.crypto.upload.EnvelopeQueue
import org.stream.crypto.upload.QueueKeyStore
import org.stream.crypto.upload.ReportAlerts
import org.stream.crypto.upload.StreamUploadManager
import org.stream.crypto.upload.UploadOutcomePolicy
import org.stream.crypto.upload.UploadOutcomePolicy.Action
import timber.log.Timber
import uniffi.frappuccino.EnvelopeInfo
import uniffi.frappuccino.EnvelopeKind
import uniffi.frappuccino.FfiException
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Sends ONE queue envelope to the relay: a report object, a directory entry, a
 * closure or a timestamp proof. One unique WorkManager job per envelope, named
 * after its local file name (KEEP), so an envelope is never sent twice at once
 * and survives process death and reboot.
 *
 * Every envelope was signed when it was produced. This worker signs nothing,
 * builds no URL and reads no trailer itself: Rust verifies the envelope in
 * full (trailer, payload hash, report id, signatures) before anything goes on
 * the network, and builds the request from it (`upload_send_envelope`). So the
 * worker needs neither the PIN nor the report keys, only the queue key
 * (installed at process start) and, for a creation, the upload bearer.
 *
 * What it does with the answer is [UploadOutcomePolicy]; the short version:
 * delete on 2xx, retry anything transient, move to the failed directory (and
 * tell the witness) whatever the relay refuses for good. It never deletes an
 * envelope the relay does not hold, since nothing can sign it again.
 *
 * Every enqueue site must set `NetworkType.CONNECTED` ([enqueue] does): the
 * worker has no network check of its own, and that constraint is also what
 * resumes it when connectivity returns.
 *
 * Jobs queued by builds from before the envelopes carry the path of a legacy
 * `.strm`; this worker refuses any path outside the envelope queue without
 * touching the file, which the migration converts instead.
 */
@HiltWorker
class ChunkUploadWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters
) : Worker(context, workerParams) {

    companion object {
        const val KEY_FILE_PATH = "filePath"
        const val KEY_SERVER_URL = "serverUrl"

        /** Tag of every envelope job (and of nothing else). */
        const val TAG = "stream_envelope_upload"

        /** Only the path and the relay URL: no report address, no secret. */
        fun buildInputData(filePath: String, serverUrl: String): Data =
            Data.Builder()
                .putString(KEY_FILE_PATH, filePath)
                .putString(KEY_SERVER_URL, serverUrl)
                .build()

        /**
         * Schedule the sending of [envelope] (unique work named after the
         * file, KEEP: a no-op while a job for it is queued or running).
         * [jitterMs] spreads a batch so it does not hit the relay in lockstep.
         *
         * Nothing is scheduled if an emergency wipe began since
         * [wipeGeneration], the generation the caller read when it started
         * working for the current identity. The row a job leaves in
         * WorkManager's database (cleartext SQLite: the envelope's path, named
         * after its session, the relay URL, the time) must not appear after the
         * wipe has cancelled and pruned the others. Returns whether it was
         * scheduled.
         */
        fun enqueue(
            context: Context,
            envelope: File,
            serverUrl: String,
            wipeGeneration: Int,
            jitterMs: Long = 3_000L,
        ): Boolean {
            val request = OneTimeWorkRequest.Builder(ChunkUploadWorker::class.java)
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .setInputData(buildInputData(envelope.absolutePath, serverUrl))
                // 10 s, 20 s, 40 s… capped by WorkManager: quick after a short
                // outage, quiet after a long one.
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.SECONDS)
                .setInitialDelay((Math.random() * jitterMs).toLong(), TimeUnit.MILLISECONDS)
                .addTag(TAG)
                .build()
            // Under the wipe lock: the enqueue is handed to WorkManager either
            // before the wipe starts (the wipe's cancelAllWork and pruneWork,
            // queued after it on WorkManager's serial executor, then cancel
            // and prune it) or not at all.
            return StreamUploadManager.unlessWipedSince(wipeGeneration) {
                WorkManager.getInstance(context)
                    .enqueueUniqueWork(envelope.name, ExistingWorkPolicy.KEEP, request)
            } != null
        }

        /**
         * Schedule every queued envelope, unless an emergency wipe began since
         * [wipeGeneration]. Returns how many were scheduled.
         */
        fun scheduleAll(context: Context, serverUrl: String, wipeGeneration: Int): Int {
            if (StreamUploadManager.wipeGeneration() != wipeGeneration) return 0
            val pending = EnvelopeQueue.get(context).pending()
            return pending.count { file ->
                enqueue(context, file, serverUrl, wipeGeneration, jitterMs = 30_000L)
            }
        }
    }

    override fun doWork(): Result {
        val filePath = inputData.getString(KEY_FILE_PATH) ?: return Result.failure()
        val serverUrl = inputData.getString(KEY_SERVER_URL) ?: return Result.failure()
        val queue = EnvelopeQueue.get(applicationContext)
        val file = File(filePath)
        if (!queue.isQueued(file)) {
            // A job from before the envelopes: its legacy file is the
            // migration's to convert, never ours to send or move.
            Timber.d("ChunkUploadWorker: not a queue envelope, job dropped")
            return Result.failure()
        }
        if (!file.exists()) return Result.success()
        val wipeAtStart = StreamUploadManager.wipeGeneration()

        if (!QueueKeyStore.ensureInstalled(applicationContext)) {
            Timber.tag("StreamMetrics").i("envelope retry reason=no_queue_key")
            return Result.retry()
        }

        val info: EnvelopeInfo = try {
            uniffi.frappuccino.envelopeInspect(file.absolutePath)
        } catch (e: FfiException.EnvelopeCorrupt) {
            return parkFailed(queue, file, ReportAlerts.Reason.FAILED, wipeAtStart)
        } catch (e: FfiException.NoQueueKey) {
            return Result.retry()
        } catch (e: FfiException) {
            return if (!file.exists()) Result.success() else Result.retry()
        }
        // An emergency wipe since this run started took the envelope with it:
        // nothing of it may be cached or sent (cancelAllWork does not stop a
        // run already in doWork).
        if (StreamUploadManager.wipeGeneration() != wipeAtStart) return Result.success()
        queue.rememberReportId(file.name, info.reportIdHex)
        val kind = kindOf(info.kind)

        // A legacy closure lists no object: once the relay records it, the
        // report accepts nothing more. It waits for its report's queue to drain.
        if (info.needsDrain && !UploadOutcomePolicy.legacyClosureReady(hasPeer(queue, file, info))) {
            Timber.tag("StreamMetrics").i("envelope retry reason=legacy_closure_waits")
            return Result.retry()
        }

        val markedNotCreated = queue.isMarkedNotCreated(file.name)
        var bearerHeld = UploadAuthHolder.isPresent()
        if (markedNotCreated && info.hasCreateSig && !bearerHeld) {
            // The relay already said the report does not exist: sending again
            // without the creation headers would only earn another 425.
            bearerHeld = ensureFallbackReAuth(serverUrl)
            if (!bearerHeld) {
                Timber.tag("StreamMetrics").i("envelope retry reason=needs_bearer")
                return Result.retry()
            }
        }
        val useCreation = UploadOutcomePolicy.useCreation(
            kind, info.hasCreateSig, bearerHeld, EnvelopeNames.mayNeedJwt(file.name), markedNotCreated,
        )

        if (UploadCircuitBreaker.isOpen()) {
            Timber.tag("StreamMetrics").i("envelope retry reason=circuit_open")
            return Result.retry()
        }
        if (!UploadConcurrencyLimiter.tryAcquire()) {
            Timber.tag("StreamMetrics").i("envelope retry reason=concurrency_cap")
            return Result.retry()
        }

        var deleteAfterRelease: File? = null
        try {
            // A chained closure's peers are sampled BEFORE the send as well:
            // the envelope that creates the report can be accepted and leave
            // the queue while the closure's 425 is on its way back
            // (UploadOutcomePolicy.closurePeersQueued).
            val chainedClosure = kind == UploadOutcomePolicy.Kind.CLOSURE && !info.needsDrain
            val peersBeforeSend = chainedClosure && hasPeer(queue, file, info)
            val outcome = uniffi.frappuccino.uploadSendEnvelope(
                serverUrl, file.absolutePath, RustUploadTransport.mode, useCreation,
            )
            val code = outcome.httpStatus.toInt()
            val action = UploadOutcomePolicy.decide(
                kind = kind,
                legacyClosure = info.needsDrain,
                httpStatus = code,
                errorDetail = outcome.errorDetail,
                peersQueued = code == 425 && chainedClosure &&
                    UploadOutcomePolicy.closurePeersQueued(peersBeforeSend) { hasPeer(queue, file, info) },
                usedCreation = useCreation,
            )
            reportToBreaker(code, outcome.errorDetail)
            return when (action) {
                Action.DELETE -> {
                    onDelivered(file, outcome.uploadMs.toLong(), outcome.transferMs.toLong(), outcome.transportUsed)
                    deleteAfterRelease = file
                    Result.success()
                }
                Action.ALREADY_GONE -> Result.success()
                Action.RETRY -> {
                    if (outcome.errorDetail == UploadOutcomePolicy.Tag.NO_QUEUE_KEY) {
                        QueueKeyStore.ensureInstalled(applicationContext)
                    }
                    Timber.tag("StreamMetrics").i(
                        "envelope retry reason=%s", if (code == 0) outcome.errorDetail ?: "transport" else "http_$code"
                    )
                    Result.retry()
                }
                Action.RETRY_AFTER_AUTH_REFUSED -> {
                    UploadAuthHolder.clear()
                    Result.retry()
                }
                Action.RETRY_WITH_CREATION -> {
                    // The marker is named after the session: none is written
                    // once an emergency wipe has started.
                    if (StreamUploadManager.wipeGeneration() == wipeAtStart) {
                        queue.markNotCreated(file.name)
                    }
                    Timber.tag("StreamMetrics").i("envelope retry reason=report_not_created")
                    Result.retry()
                }
                Action.RETRY_CLOSE_ROUTE -> {
                    Timber.tag("StreamMetrics").i("envelope retry reason=close_route_absent")
                    Result.retry()
                }
                Action.FAIL -> parkFailed(queue, file, ReportAlerts.Reason.FAILED, wipeAtStart, code)
                Action.FAIL_DIRECTORY_CLOSED ->
                    parkFailed(queue, file, ReportAlerts.Reason.DIRECTORY_REFUSED, wipeAtStart, code)
                Action.ABANDON_CLOSURE ->
                    parkFailed(queue, file, ReportAlerts.Reason.CLOSURE_ABANDONED, wipeAtStart, code)
                Action.DROP_LEGACY_CLOSURE -> {
                    deleteAfterRelease = file
                    Result.success()
                }
            }
        } catch (t: Throwable) {
            // The send never throws by contract; a Throwable means the native
            // binding is unhealthy in this build. There is no fallback that
            // could send an envelope (Rust is what verifies it), so retry: the
            // envelope stays on disk. A client-side break is not a relay-down
            // signal, so the circuit breaker is left alone.
            if (t is VirtualMachineError) throw t
            if (t is InterruptedException) Thread.currentThread().interrupt()
            Timber.e(t, "ChunkUploadWorker: native send threw, retry")
            return Result.retry()
        } finally {
            UploadConcurrencyLimiter.release()
            // Deleted after the permit is released, so the next PUT does not
            // wait on this secure delete.
            deleteAfterRelease?.let { queue.remove(it) }
        }
    }

    private fun kindOf(kind: EnvelopeKind): UploadOutcomePolicy.Kind = when (kind) {
        EnvelopeKind.CHUNK -> UploadOutcomePolicy.Kind.OBJECT
        EnvelopeKind.DIRECTORY_ENTRY -> UploadOutcomePolicy.Kind.DIRECTORY_ENTRY
        EnvelopeKind.CLOSURE -> UploadOutcomePolicy.Kind.CLOSURE
        EnvelopeKind.TIMESTAMP_PROOF -> UploadOutcomePolicy.Kind.TIMESTAMP_PROOF
    }

    /** Whether another queued envelope belongs to the same report. */
    private fun hasPeer(queue: EnvelopeQueue, self: File, info: EnvelopeInfo): Boolean =
        queue.hasPeer(self.name, info.reportIdHex) { other ->
            try {
                uniffi.frappuccino.envelopeInspect(other.absolutePath).reportIdHex
            } catch (e: FfiException.EnvelopeCorrupt) {
                // Can never be sent: it does not hold anything back.
                ""
            } catch (e: Exception) {
                null
            }
        }

    /**
     * Move to the failed directory and tell the witness. The job is done
     * either way: a failed envelope is never retried.
     */
    private fun parkFailed(
        queue: EnvelopeQueue,
        file: File,
        reason: String,
        wipeAtStart: Int,
        code: Int = 0,
    ): Result {
        Timber.w("ChunkUploadWorker: envelope refused for good (%d, %s)", code, reason)
        if (queue.moveToFailed(file) && StreamUploadManager.wipeGeneration() == wipeAtStart) {
            StreamPreferences.addReportAlert(applicationContext, 1, file.lastModified(), reason)
        }
        return Result.success()
    }

    private fun reportToBreaker(code: Int, errorDetail: String?) {
        when {
            code in 200..299 -> UploadCircuitBreaker.reportSuccess()
            code == 507 -> UploadCircuitBreaker.reportDiskFull()
            code >= 500 -> UploadCircuitBreaker.reportServerError(code)
            // Only a real transport failure says the relay may be down; the
            // local tags (no key, unreadable file, no bearer) say nothing about it.
            code == 0 && errorDetail !in LOCAL_TAGS -> UploadCircuitBreaker.reportServerError(0)
        }
    }

    private fun onDelivered(file: File, uploadMs: Long, transferMs: Long, transport: String) {
        UploadSessionStats.onUploaded()
        val parsed = EnvelopeNames.parse(file.name)
        val isMediaChunk = parsed?.role == EnvelopeNames.Role.OBJECT && (parsed.seq ?: 0) >= 1
        if (!isMediaChunk) return
        // Only media chunks feed the adaptive quality and concurrency models:
        // they are the objects whose size the bitrate decides.
        AdaptiveQualityHolder.reportChunkUploadTime(uploadMs)
        UploadConcurrencyLimiter.reportUploadTime(uploadMs)
        try {
            val size = file.length()
            val backlog = AdaptiveQualityHolder.get()?.getBacklog() ?: -1
            UploadSessionStats.reportBacklog(backlog)
            val goodputKbps = if (transferMs > 0L) (size * 8L) / transferMs else -1L
            Timber.tag("StreamMetrics").i(
                "chunk seq=%d quality=%s sizeBytes=%d uploadMs=%d transferMs=%d goodputKbps=%d cap=%d backlog=%d networkType=%s transport=%s",
                parsed?.seq ?: -1,
                AdaptiveQualityHolder.get()?.currentQuality?.displayLabel ?: "?",
                size, uploadMs, transferMs, goodputKbps,
                UploadConcurrencyLimiter.currentCap(), backlog, detectNetworkType(), transport,
            )
        } catch (e: Exception) {
            Timber.tag("StreamMetrics").w(e, "metrics line failed")
        }
    }

    /**
     * Publish a bearer into the Rust holder if none is held, by authenticating
     * once (one ephemeral ratchet slot), single-flight with every other
     * authentication of the process ([ensureBearer]). Returns whether a bearer
     * is held.
     */
    private fun ensureFallbackReAuth(serverUrl: String): Boolean =
        ensureBearer(applicationContext, serverUrl)

    /** Current network transport, for the metrics line. Best-effort. */
    private fun detectNetworkType(): String {
        return try {
            val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            val nw = cm.activeNetwork ?: return "NONE"
            val caps = cm.getNetworkCapabilities(nw) ?: return "UNKNOWN"
            when {
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                else -> "OTHER"
            }
        } catch (e: Exception) {
            "UNKNOWN"
        }
    }

    private val LOCAL_TAGS = setOf(
        UploadOutcomePolicy.Tag.NO_QUEUE_KEY,
        UploadOutcomePolicy.Tag.FILE_MISSING,
        UploadOutcomePolicy.Tag.ENVELOPE_CORRUPT,
        UploadOutcomePolicy.Tag.ENVELOPE_IO,
        UploadOutcomePolicy.Tag.NO_BEARER,
        UploadOutcomePolicy.Tag.NO_CREATE_SIG,
    )
}
