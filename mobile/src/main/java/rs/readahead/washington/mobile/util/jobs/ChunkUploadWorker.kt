package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Data
import androidx.work.Worker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import org.stream.crypto.capture.AdaptiveQualityHolder
import org.stream.crypto.upload.StreamUploadManager
import timber.log.Timber
import java.io.File

/**
 * WorkManager Worker that uploads a single STRM chunk to the relay over the
 * relay-blind capability path. The blob survives process death and phone
 * reboot; WorkManager owns the queue.
 *
 * Every site that enqueues this worker must set the `NetworkType.CONNECTED`
 * constraint. [doWork] has no network check of its own, so without it the
 * worker runs with no link, burns backoff, and on the creation chunk walks into
 * the re-auth path; that same constraint is also what makes a chunk resume by
 * itself once connectivity returns. The current enqueue sites,
 * `StreamRecordingService` and [OrphanSweepWorker], both set it.
 *
 * **Relay-blind contract (Phase C)** — the chunk is addressed and authorised by
 * a phrase-DERIVED report key, never by identity. The worker carries only the
 * report's derivation index `n` (not even the report_id); it re-derives the
 * report_id + signs the write INSIDE Rust from the live
 * [StreamUploadManager.reportKeyring], so neither the bearer nor any report
 * secret ever crosses the FFI as a JVM String — heap-0. The relay stores
 * `report_id → report_pk` and never the identity, so a seizure of its disk
 * reveals no `identity → report` link.
 *
 * Creation vs write. The first blob of a report — seq 0, the session
 * metadata — is the creation PUT: it additionally carries the stream bearer
 * + a 0x07 create-sig and lazily creates the server-side record. Every later
 * chunk (seq ≥ 1) is a pure 0x08 write-sig PUT. If a write reaches the relay
 * before the creation PUT (WorkManager doesn't order them) the relay answers
 * 425 and the worker retries until the record exists.
 *
 * There is no fallback transport to add, by construction: every PUT needs
 * capability headers signed by the reportKeyring, which IS the FFI. If the
 * native binding is unhealthy the keyring is unusable too, so no OkHttp
 * fallback could sign — and the relay-blind relay rejects any identity-based
 * upload anyway. A [Throwable] from the transport is therefore caught and the
 * chunk is retried (it stays on disk, never lost) until a healthy app build
 * runs it.
 */
@HiltWorker
class ChunkUploadWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters
) : Worker(context, workerParams) {

    companion object {
        // Process-wide lock for the creation chunk's
        // fallback re-auth. At most one ChunkUploadWorker consumes an ephemeral
        // ratchet slot at a time; the parallel pool re-checks UploadAuthHolder
        // after acquiring the lock and reuses the just-published JWT.
        private val authFallbackLock = Any()
        const val KEY_FILE_PATH = "filePath"
        const val KEY_SERVER_URL = "serverUrl"

        // Phase C — the report's derivation index n (report_id =
        // reportKeyring.reportIdHex(n)). Replaces the old server-assigned
        // reportId in InputData: the worker re-derives the identity-free
        // report_id from the live keyring, so the WorkManager Data persisted in
        // clear in androidx.work.workdb never carries a report↔identity handle.
        const val KEY_REPORT_INDEX = "reportIndex"

        // The bearer is never passed in InputData (it would persist
        // in clear in androidx.work.workdb). Phase C — neither is any report
        // secret nor the report_id: only the non-secret derivation index n.
        fun buildInputData(filePath: String, serverUrl: String, reportIndex: Int): Data {
            return Data.Builder()
                .putString(KEY_FILE_PATH, filePath)
                .putString(KEY_SERVER_URL, serverUrl)
                .putInt(KEY_REPORT_INDEX, reportIndex)
                .build()
        }
    }

    override fun doWork(): Result {
        val filePath = inputData.getString(KEY_FILE_PATH) ?: return Result.failure()
        val serverUrl = inputData.getString(KEY_SERVER_URL) ?: return Result.failure()
        val reportIndex = inputData.getInt(KEY_REPORT_INDEX, -1)
        if (reportIndex < 0) {
            Timber.e("ChunkUploadWorker: missing reportIndex, failing")
            return Result.failure()
        }

        val blobFile = File(filePath)
        // seq is the monotonic chunk number in the filename `<sid>_NNNNNN.strm`.
        // seq 0 = the session metadata blob = the report-CREATION PUT; seq ≥ 1 =
        // pure write. -1 (unparseable) defaults to non-creation — a stray name
        // must never wrongly claim to create the record.
        val seq = blobFile.name.substringAfterLast('_')
            .substringBefore('.')
            .toIntOrNull() ?: -1
        val isCreation = seq == 0

        // Phase C — the keyring (FFI) is required for EVERY PUT (it signs the
        // write). If the ratchet is locked it is null → defer; the chunk waits
        // on disk and uploads after the next unlock. No bearer/secret enters the
        // JVM. Its lifecycle mirrors the provenanceSigner: it survives a
        // background recording and is wiped only at lock().
        val keyring = StreamUploadManager.getInstance(applicationContext).reportKeyring
        if (keyring == null) {
            Timber.d("ChunkUploadWorker: report keyring locked, retry deferred for %s", blobFile.name)
            Timber.tag("StreamMetrics").i(
                "retry reason=no_report_keyring file=%s", blobFile.name
            )
            return Result.retry()
        }

        if (!blobFile.exists() || blobFile.length() == 0L) {
            Timber.d("ChunkUploadWorker: file already uploaded or missing: %s", filePath)
            return Result.success()
        }

        // Creation chunk (seq 0) additionally needs the stream bearer (read
        // inside Rust). Later chunks authorise purely by write-sig — no bearer,
        // no auth gate, heap-0 even on the chunk path. ensureFallbackReAuth
        // re-publishes a bearer into the Rust holder if absent, WITHOUT pulling
        // it into the JVM.
        if (isCreation && !UploadAuthHolder.isPresent() && !ensureFallbackReAuth(blobFile)) {
            Timber.d("ChunkUploadWorker: no auth token for creation chunk, retry deferred for %s", blobFile.name)
            Timber.tag("StreamMetrics").i(
                "retry reason=no_auth_token file=%s creation=true", blobFile.name
            )
            return Result.retry()
        }

        // Circuit breaker. Skip when too many recent consecutive
        // 5xx on any worker, letting WorkManager re-schedule with EXPONENTIAL
        // backoff instead of re-hammering a relay just knocked over by a burst.
        if (UploadCircuitBreaker.isOpen()) {
            Timber.w("ChunkUploadWorker: circuit OPEN, retry deferred for %s", blobFile.name)
            Timber.tag("StreamMetrics").i("retry reason=circuit_open file=%s", blobFile.name)
            return Result.retry()
        }

        // Global concurrency cap so a slow uplink doesn't saturate
        // with N parallel PUTs each taking 25+ s.
        if (!UploadConcurrencyLimiter.tryAcquire()) {
            Timber.d("ChunkUploadWorker: concurrency cap, retry deferred for %s", blobFile.name)
            Timber.tag("StreamMetrics").i("retry reason=concurrency_cap file=%s", blobFile.name)
            return Result.retry()
        }

        // Stash the blob for the deferred secure-delete; the actual
        // wipe runs in `finally` AFTER the concurrency permit is released so the
        // next chunk's PUT isn't gated by our fsync (only the success path sets
        // this; retry/failure/exception leave the blob in place for re-upload).
        var pendingSecureDelete: File? = null
        try {
            // Re-derive the identity-free report address from (keyring, n) — the
            // same derivation Rust signs over, so URL path and write-sig can't
            // drift. Throwing here (destroyed keyring / sick binding) lands in
            // catch(Throwable) below → retry, blob preserved.
            val reportIdHex = keyring.reportIdHex(reportIndex.toUInt())
            val url = "$serverUrl/file/$reportIdHex/${blobFile.name}"

            // Heap-0 capability PUT: Rust re-derives report_id (== H(report_pk))
            // from (keyring, n), hashes the .strm byte-identically to the relay's
            // hasher, signs the 0x08 write-sig (+ 0x07 create-sig + attaches the
            // bearer when isCreation), and PUTs. Transport mode = DIRECT_TLS /
            // OBF_QUIC per RustUploadTransport. Never throws by contract; every
            // transport error comes back as PutOutcome(httpStatus=0).
            val outcome = uniffi.frappuccino.uploadPutReportChunk(
                url, blobFile.absolutePath, RustUploadTransport.mode,
                keyring, reportIndex.toUInt(), blobFile.name, isCreation,
            )
            val code = outcome.httpStatus.toInt()

            // Race: a concurrent worker already uploaded + secure-deleted the
            // blob (mirrors the OkHttp FileNotFoundException-as-success path).
            if (code == 0 && outcome.errorDetail == "file_missing") {
                Timber.d("ChunkUploadWorker: blob gone (race), treating as success %s", blobFile.name)
                return Result.success()
            }

            if (code !in 200..299) {
                return when {
                    code == 401 -> {
                        // Only the creation chunk sends a bearer; a stale JWT
                        // (server JWT_SECRET rotated / exp past / blacklisted)
                        // clears it and retries. clear() zeroizes the Rust holder
                        // (and resets the Rust transport). The next creation-chunk
                        // run re-auths via ensureFallbackReAuth.
                        Timber.w("ChunkUploadWorker: 401 — clearing JWT and retrying %s", blobFile.name)
                        UploadAuthHolder.clear()
                        Result.retry()
                    }
                    code == 425 -> {
                        // Phase C — record not created yet: this write-only chunk
                        // (seq ≥ 1) reached the relay before its report's creation
                        // PUT (seq 0). Retry; the creation chunk mints the record,
                        // then this one succeeds. NOT a server-down signal, so the
                        // circuit breaker is untouched.
                        Timber.d("ChunkUploadWorker: 425 report not created yet, retry %s", blobFile.name)
                        Timber.tag("StreamMetrics").i(
                            "retry reason=report_not_created file=%s", blobFile.name
                        )
                        Result.retry()
                    }
                    code == 429 -> {
                        // Never map a 429 to failure: that PERMANENTLY drops the
                        // chunk, and on the creation chunk (seq 0) it strands every
                        // later chunk on 425 forever — testimony lost. Retry: the
                        // blob stays on disk and uploads once the budget/window
                        // frees. Not a server-down signal either, so the circuit
                        // breaker is untouched.
                        //
                        // Both sources are transient and self-healing: (a) the Phase
                        // C creation-budget soft cap (per identity×batch,
                        // server/app/routes/upload.py) — only the creation chunk
                        // carries the JWT, and it self-heals when the ratchet rotates
                        // to the next batch as ephemeral slots are consumed by auth;
                        // and (b) WP-B2's per-IP PUT rate limit (same file), which
                        // any chunk (creation or write) can hit during a fast backlog
                        // flush and which self-heals on the next rate window.
                        Timber.w("ChunkUploadWorker: 429 (creation budget or rate limit) — retry, self-heals %s", blobFile.name)
                        Timber.tag("StreamMetrics").i(
                            "retry reason=throttled_429 file=%s", blobFile.name
                        )
                        Result.retry()
                    }
                    code in 400..499 -> {
                        // 4xx ≠ 401/425/429 = client error (malformed path, bad sig,
                        // write-once conflict on differing bytes). Not auth-stale,
                        // not server-down → permanent failure, blob left on disk.
                        Timber.e("ChunkUploadWorker: permanent failure %d for %s", code, blobFile.name)
                        Result.failure()
                    }
                    code == 507 -> {
                        // Phase 1.12 — server storage full. Open the circuit
                        // IMMEDIATELY (no THRESHOLD wait) and Result.retry() —
                        // NEVER failure — so the blob stays on-device and uploads
                        // once space frees.
                        UploadCircuitBreaker.reportDiskFull()
                        Timber.w("ChunkUploadWorker: 507 disk-full for %s — circuit opened", blobFile.name)
                        Timber.tag("StreamMetrics").i("retry reason=server_disk_full file=%s", blobFile.name)
                        Result.retry()
                    }
                    code >= 500 -> {
                        // 5xx = relay down/overloaded. Notify the
                        // circuit breaker to coordinate backoff across workers.
                        UploadCircuitBreaker.reportServerError(code)
                        Timber.w("ChunkUploadWorker: temporary failure %d for %s", code, blobFile.name)
                        Result.retry()
                    }
                    else -> {
                        // code == 0 = transport error (timeout / network / TLS /
                        // no_bearer / client_build). Same as the old OkHttp
                        // catch(Exception): an HTTP-0 server-down signal.
                        UploadCircuitBreaker.reportServerError(0)
                        Timber.tag("StreamMetrics").i(
                            "retry reason=transport_%s file=%s",
                            outcome.errorDetail ?: "error", blobFile.name
                        )
                        Result.retry()
                    }
                }
            }

            // Success (2xx).
            UploadCircuitBreaker.reportSuccess()
            UploadSessionStats.onUploaded()
            val uploadTimeMs = outcome.uploadMs.toLong()
            AdaptiveQualityHolder.reportChunkUploadTime(uploadTimeMs)
            UploadConcurrencyLimiter.reportUploadTime(uploadTimeMs)

            // Structured per-chunk metrics line. transferMs
            // is measured in Rust with the file open + client build excluded; on
            // the QUIC path it also excludes connection establishment (h3
            // handshake included), while on the DirectTls path the first chunk of
            // a session still folds in the TCP+TLS connect, later ones reusing
            // the pooled connection. goodputKbps = bits/ms, the cleaner
            // link-throughput proxy — read it with that first-chunk caveat.
            // Best-effort — a logging hiccup never fails the upload.
            try {
                val qualityLabel = AdaptiveQualityHolder.get()?.currentQuality?.displayLabel ?: "?"
                val backlog = AdaptiveQualityHolder.get()?.getBacklog() ?: -1
                UploadSessionStats.reportBacklog(backlog)
                val cap = UploadConcurrencyLimiter.currentCap()
                val bitrateBps = (blobFile.length() * 8L * 1000L) / 5000L
                val ratio = uploadTimeMs.toDouble() / 5000.0
                val networkType = detectNetworkType()
                val transferMs = outcome.transferMs.toLong()
                val goodputKbps = if (transferMs > 0L) (blobFile.length() * 8L) / transferMs else -1L
                Timber.tag("StreamMetrics").i(
                    "chunk seq=%d quality=%s sizeBytes=%d uploadMs=%d transferMs=%d goodputKbps=%d ratio=%.2f cap=%d backlog=%d networkType=%s bitrateBps=%d transport=%s",
                    seq, qualityLabel, blobFile.length(),
                    uploadTimeMs, transferMs, goodputKbps, ratio, cap, backlog, networkType, bitrateBps,
                    outcome.transportUsed,
                )
            } catch (e: Exception) {
                Timber.tag("StreamMetrics").w(e, "metrics line failed")
            }

            pendingSecureDelete = blobFile
            Timber.d("ChunkUploadWorker: uploaded %s in %d ms (secure-delete deferred to finally)",
                blobFile.name, uploadTimeMs)
            return Result.success()
        } catch (t: Throwable) {
            // Do not add a fallback transport here, and do not report a server
            // error. The capability headers are signed by the reportKeyring,
            // which IS the FFI (Phase C, locked design). A Throwable from
            // uploadPutReportChunk (LinkageError / UnsatisfiedLinkError / a Rust
            // panic across the FFI / a destroyed keyring mid-PUT) means the
            // native binding is unhealthy in this build — but the same break
            // disables the keyring, so an OkHttp fallback could not sign the PUT
            // either, and the relay-blind relay rejects any identity-based
            // upload. There is nothing to flip to: we retry (the chunk stays on
            // disk, 0 loss) until a healthy app build runs it. And no
            // reportServerError(), because a client-side binding break is not a
            // server-down signal: opening the circuit would needlessly delay
            // every other worker.
            //
            // VirtualMachineError (OOM / StackOverflow) is unrecoverable — let it
            // propagate. A benign InterruptedException (WorkManager cancel /
            // constraint lost mid-PUT) restores the interrupt flag and retries.
            if (t is VirtualMachineError) throw t
            if (t is InterruptedException) {
                Thread.currentThread().interrupt()
                Timber.tag("StreamMetrics").i("retry reason=interrupted file=%s", blobFile.name)
                return Result.retry()
            }
            Timber.e(t, "ChunkUploadWorker: native transport threw for %s — retry (chunk preserved on disk)",
                blobFile.name)
            Timber.tag("StreamMetrics").i("retry reason=transport_threw file=%s", blobFile.name)
            return Result.retry()
        } finally {
            // Release the global concurrency permit on every exit.
            UploadConcurrencyLimiter.release()
            // secureDelete runs AFTER release so the next chunk can
            // start its PUT immediately. Only the success path set this.
            pendingSecureDelete?.let { file ->
                try {
                    uniffi.frappuccino.secureDeleteFile(file.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "secureDelete failed on %s, fallback delete()", file.name)
                    file.delete()
                }
            }
        }
    }

    /**
     * Performs the creation chunk's fallback re-auth and reports whether a
     * session bearer is now held. Returns false on any failure.
     *
     * A call here can spend an ephemeral ratchet slot, a finite resource, so the
     * whole body runs under the process-wide [authFallbackLock] and re-checks
     * [UploadAuthHolder.isPresent] once the lock is taken: at most one worker
     * per process consumes a slot, the rest of the parallel pool reuses the JWT
     * that one just published (Phase 3.42-B). Same gating + concurrency-safe
     * pattern as [OrphanSweepWorker].
     *
     * It answers from [UploadAuthHolder.isPresent], a bit, and never pulls a
     * copy of the bearer into the JVM — that is the true-heap-0 rule (Phase 2,
     * §10.6), and making this function return the token would break it.
     *
     * Only the creation chunk (seq 0) calls this — later chunks authorise by
     * write-sig and need no bearer.
     */
    private fun ensureFallbackReAuth(blobFile: File): Boolean {
        synchronized(authFallbackLock) {
            // Re-check : another worker might have just published the
            // token while we were waiting on the lock.
            if (UploadAuthHolder.isPresent()) return true

            // Defer to the recording service if it's running — it owns
            // the auth lifecycle and a parallel re-auth here would race
            // with its initServerSession path.
            // Blue HIGH-6 fix (2026-05-19) — also gate on
            // `isShuttingDown`, set at the top of onDestroy (before
            // `isRunning=false`) and cleared at its very end, so the gate
            // covers the whole teardown. A normal stop does NOT wipe the V2
            // ratchet (only an explicit lock()/panicWipe() does): what this
            // avoids is racing the service's in-flight auth for an ephemeral
            // ratchet slot. See [StreamRecordingService.isShuttingDown].
            val svc = rs.readahead.washington.mobile.service.StreamRecordingService
            if (svc.isRunning || svc.isShuttingDown) {
                Timber.d(
                    "Phase H2-B.16: service running=%b shuttingDown=%b, defer auth for %s",
                    svc.isRunning, svc.isShuttingDown, blobFile.name
                )
                return false
            }
            val manager = org.stream.crypto.upload.StreamUploadManager
                .getInstance(applicationContext)
            if (!manager.isUnlocked()) {
                Timber.d("Phase 3.42-B: ratchet locked, can't re-auth for %s", blobFile.name)
                return false
            }
            if (!isNetworkAvailable()) {
                Timber.d("Phase 3.42-B: no network, defer re-auth for %s", blobFile.name)
                return false
            }
            val authed = try {
                manager.authenticateV2()
            } catch (e: Exception) {
                Timber.w(e, "Phase 3.42-B: authenticateV2 threw for %s", blobFile.name)
                return false
            }
            if (!authed) {
                Timber.w("Phase 3.42-B: authenticateV2 failed for %s", blobFile.name)
                return false
            }
            // §10.6 — verify() stashed the bearer in the Rust holder.
            Timber.i("Phase 3.42-B: fallback re-auth OK (1 slot consumed) for %s", blobFile.name)
            return UploadAuthHolder.isPresent()
        }
    }

    /**
     * Helper — best-effort, returns true if a network is present so
     * we don't burn an auth slot trying to hit a dead link.
     */
    private fun isNetworkAvailable(): Boolean {
        return try {
            val cm = applicationContext.getSystemService(
                android.content.Context.CONNECTIVITY_SERVICE
            ) as android.net.ConnectivityManager
            val nw = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(nw) ?: return false
            caps.hasCapability(
                android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET
            )
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Detect the current network transport so field captures can
     * correlate uploadMs spikes with wifi/cellular switches. Best-effort.
     */
    private fun detectNetworkType(): String {
        return try {
            val cm = applicationContext.getSystemService(
                android.content.Context.CONNECTIVITY_SERVICE
            ) as android.net.ConnectivityManager
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
}
