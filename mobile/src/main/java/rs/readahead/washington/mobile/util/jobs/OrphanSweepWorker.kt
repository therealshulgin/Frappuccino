package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import org.stream.crypto.StreamPreferences
import org.stream.crypto.upload.ChunkUploadQueue
import org.stream.crypto.upload.StreamUploadManager
import timber.log.Timber
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Rescues the `.strm` blobs a previous recording session left behind, and gets
 * them uploaded (Phase 3.26-B).
 *
 * Those blobs leave the device AFTER the user has explicitly left the recording
 * screen. As long as the ratchet is unlocked and the toggle is on, the rescue
 * keeps uploading opportunistically, so a user under coercion who needs that to
 * stop can flip the auto-upload toggle off in Settings (Phase 3.26-C), or
 * panic-wipe, which clears the mappings via [StreamPreferences.wipeAll].
 * [StreamPreferences.isAutoUploadOrphansEnabled] gates the whole worker and
 * defaults to ON; off means no auth flow and no upload, the blobs decaying
 * instead through the 48 h TTL sweep.
 *
 * This is the rescue path's **only** deletion authority: at [MAX_RETRIES] the
 * session's blobs are secure-deleted and the mapping dropped, the server-side
 * report being presumed unrecoverable. The counter is bumped only when we
 * actually attempt an auth+enqueue — a skip for "no network" or "ratchet locked"
 * must never burn budget, or a handful of network outages would end up deleting
 * genuine testimony. Because it takes that many *real* attempts, a transient
 * outage never drops genuine data.
 *
 * The worker yields as soon as a recording is live: if [StreamRecordingService.
 * isRunning] is true it exits early without touching the queue. The service
 * handles its own session's blobs, and we want neither two auth flows racing for
 * ephemeral ratchet slots nor two scheduleUpload paths racing on the same blob
 * set.
 *
 * Authentication is hoisted OUT of the per-session loop: one sweep authenticates
 * at most once for all orphan sessions, reusing a still-valid live JWT when the
 * process kept one. Moving it into the loop would burn one ephemeral ratchet
 * slot per orphan session.
 *
 * Why it exists: when the user stops a recording while the upload queue still
 * has chunks pending, those blobs stay on disk. The filename carries the
 * originating session's id, and `scheduleUpload` only ever re-enqueues the
 * current session's blobs (Phase 3.25), so the next recording — different
 * sessionId, different report — never picks them up. Nothing else does either:
 * they would sit there until the 48 h TTL sweep (Phase 3.19) secure-deletes
 * them, and the user loses data they had reasonably expected to upload.
 *
 * How it works: a periodic worker — every 30 min, which is a chosen cadence and
 * not a platform floor, WorkManager's minimum periodic interval being 15 min —
 * that wakes up on a CONNECTED network, looks at the orphan blobs ACTUALLY
 * present in the queue (grouped by their originating sessionId), authenticates,
 * and enqueues regular [ChunkUploadWorker]s for each orphan blob against the
 * original session's report. The blobs then upload via the same idempotent PUT
 * pipeline as live chunks.
 *
 * Offline-start sessions (gap closed 2026-06-18, Phase 3.26-D ; Phase C
 * relay-blind) : every session now gets its report derivation index `n`
 * allocated LOCALLY at recording start ([StreamRecordingService] →
 * [StreamPreferences.allocateReportIndexForSession]), so offline-start
 * sessions already carry a `{sessionId → entry(reportId, n)}` mapping. We
 * still iterate the sessionIds present on disk and, for any orphan without a
 * usable derived index (a mapping dropped while blobs survived), allocate one
 * now — idempotent per sessionId. The relay no longer authorises by identity:
 * a chunk is addressed + signed by the phrase-derived report key (the report
 * is created lazily by the session's metadata blob, seq 0). We then enqueue
 * regular [ChunkUploadWorker]s carrying that index.
 */
@HiltWorker
class OrphanSweepWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
) : Worker(context, params) {

    override fun doWork(): Result {
        // (1) User opted out — sleep until next tick.
        if (!StreamPreferences.isAutoUploadOrphansEnabled(applicationContext)) {
            Timber.d("[OrphanSweep] auto-upload disabled, skip")
            return Result.success()
        }

        // (2) Live recording in progress — yield. The recording service
        //     handles its own session's blobs; we don't want to race it
        //     for auth slots or scheduling.
        //     Blue HIGH-6 fix (2026-05-19) — also gate
        //     on `isShuttingDown`. A sweep tick that fires DURING
        //     onDestroy (between isRunning=false and the end of teardown)
        //     would otherwise see isRunning=false, decide the service was
        //     gone, and re-authenticate while the service is still
        //     finishing its own auth lifecycle — racing it for an
        //     ephemeral ratchet slot. (A clean stop does NOT wipe the V2
        //     ratchet; only lock() / panicWipe() do.) Symmetric to the
        //     gate in ChunkUploadWorker.ensureFallbackReAuth. See
        //     [StreamRecordingService.isShuttingDown] doc for details.
        val svc = rs.readahead.washington.mobile.service.StreamRecordingService
        if (svc.isRunning || svc.isShuttingDown) {
            Timber.d(
                "[OrphanSweep] service running=%b shuttingDown=%b, yield",
                svc.isRunning, svc.isShuttingDown
            )
            return Result.success()
        }

        // (3) Ratchet locked — can't authenticate. Retry later (PeriodicWork
        //     keeps the schedule; this Retry just nudges the next attempt
        //     sooner via the exponential backoff).
        val manager = StreamUploadManager.getInstance(applicationContext)
        if (!manager.isUnlocked()) {
            Timber.d("[OrphanSweep] ratchet locked, retry later")
            return Result.retry()
        }

        // Phase C (relay-blind reports) — the reportKeyring (loaded at unlock,
        // lifecycle mirrors provenanceSigner) derives each orphan session's
        // identity-free report_id and signs its writes INSIDE Rust. If it is
        // absent on an unlocked manager (best-effort reload failed), defer — the
        // next unlock reloads it. Without it we cannot address or sign any
        // report upload, so there is nothing this sweep can do.
        val keyring = manager.reportKeyring
        if (keyring == null) {
            Timber.d("[OrphanSweep] reportKeyring absent, retry later")
            return Result.retry()
        }

        // (4) Network check — retry WITHOUT burning the retry budget if
        //     we can't reach the relay anyway. Per therealshulgin's 2026-05-14
        //     requirement : "max 3 retries with monitoring réseau, on ne
        //     retry pas si pas de connection internet".
        if (!isNetworkAvailable()) {
            Timber.d("[OrphanSweep] no network, retry later (budget preserved)")
            return Result.retry()
        }

        // Serialize every sweep execution in-process, whole body included.
        // The periodic (UNIQUE_NAME) and one-shot ("$UNIQUE_NAME-oneshot")
        // runs are enqueued under different WorkManager unique names, so
        // nothing stops WorkManager from running them CONCURRENTLY. Don't
        // shrink this critical section down to the mapping reads: what it
        // covers is the whole sweep — auth attempt, retry-budget bump,
        // give-up secure-delete. Holding the lock across the network calls
        // costs little, recording being already excluded (gate 2), so
        // contention is only periodic-vs-one-shot and rare. The body
        // re-reads the mappings INSIDE the lock so the second waiter acts
        // on what the first saved, not on a stale snapshot. Early `return`s
        // are non-local (inline synchronized) and release the lock.
        // The case this lock was first added for was two concurrent runs
        // each minting a separate report for the same offline-start session
        // — the Phase 1.15 split-session class, on the rescue path. That one
        // is today also ruled out upstream, [StreamPreferences.
        // allocateReportIndexForSession] being atomic and idempotent per
        // sessionId.
        return synchronized(sweepLock) {
        // (5) Enumerate orphan blobs ACTUALLY on disk, grouped by their
        //     originating sessionId. We iterate the disk (not just the
        //     mapping keys) so offline-start sessions with no mapping are
        //     still seen (gap A, Phase 3.26-D).
        val queue = ChunkUploadQueue(applicationContext)
        val mappings = StreamPreferences.getSessionReports(applicationContext)
        val pending = queue.getPending()
        if (pending.isEmpty()) {
            // Nothing on disk. Drop any stale mappings (their blobs already
            // uploaded or were swept) so the map doesn't grow unbounded.
            for (sid in mappings.keys) {
                StreamPreferences.removeSessionReport(applicationContext, sid)
            }
            Timber.d("[OrphanSweep] queue empty, nothing to sweep")
            return Result.success()
        }
        val orphanSessionIds = pending.mapNotNull { sessionIdOf(it.name) }.toSet()

        // Configure the server URL on the manager before any auth. In a
        // fresh process (e.g. the one-shot fired right after unlock, before
        // any recording) setServerUrl() was never called, so authenticateV2()
        // throws "Server URL not set" (field-caught on OnePlus 2026-06-18).
        // initServerSession does this too; idempotent.
        manager.setServerUrl(
            rs.readahead.washington.mobile.service
                .StreamRecordingService.DEFAULT_SERVER_URL
        )

        // (6) Ensure a bearer once. Reuse a still-valid live JWT if the
        //     process kept one (Phase 3.35 — no slot burned), else
        //     authenticate (one ephemeral ratchet slot). Needed both so the
        //     ChunkUploadWorkers we enqueue can PUT, and so we can mint a
        //     report for any unmapped (offline-start) session. Audit R-01
        //     invariant preserved : the JWT is never persisted; it lives
        //     only in the Rust holder, pulled transiently at PUT time.
        if (UploadAuthHolder.isPresent()) {
            Timber.d("[OrphanSweep] reusing live JWT (no slot consumed)")
        } else {
            val authed = try {
                manager.authenticateV2()
            } catch (e: Exception) {
                Timber.w(e, "[OrphanSweep] auth threw")
                false
            }
            if (!authed) {
                Timber.w("[OrphanSweep] auth failed, retry later")
                return Result.retry()
            }
        }

        val wm = WorkManager.getInstance(applicationContext)
        // Only the periodic run bumps the per-session giveup budget; the
        // one-shot rescues without burning it (see [scheduleOneShot]).
        // `true` is just the fallback for an untagged caller (none exists
        // today) — note a bump moves a session TOWARD give-up, so true is
        // not the data-safe value, merely the bounded one.
        val bumpRetry = inputData.getBoolean(KEY_BUMP_RETRY, true)
        var sessionsHandled = 0
        var sessionsAbandoned = 0
        var reportsCreated = 0
        var blobsScheduled = 0

        for (sessionId in orphanSessionIds) {
            val orphans = queue.getPendingForSession(sessionId)
            if (orphans.isEmpty()) continue

            // Resolve this session's derivation index n. An unmapped orphan
            // (legacy offline-start, or a mapping dropped while blobs survived)
            // gets one allocated now — idempotent per sessionId, so a re-run
            // reuses the same n and never splits the report. The report itself
            // is created LAZILY by the session's metadata blob (seq 0) PUT,
            // exactly like a live session, which is why no network create step
            // appears here (the old uploadCreateReport mint is gone).
            // A legacy entry that predates the migration (server-assigned
            // reportId, reportIndex == -1) cannot be addressed by the
            // relay-blind relay, so we skip it rather than mis-upload; the
            // clean-break cutover wipes those.
            val existing = mappings[sessionId]
            val entry = when {
                existing != null && existing.reportIndex >= 0 -> existing
                existing == null -> {
                    val allocated = StreamPreferences.allocateReportIndexForSession(
                        applicationContext, sessionId
                    ) { n -> keyring.reportIdHex(n.toUInt()) }
                    reportsCreated++
                    Timber.i(
                        "[OrphanSweep] allocated rescue report index %d for offline-start session %s (%d blobs)",
                        allocated.reportIndex, sessionId, orphans.size,
                    )
                    allocated
                }
                else -> {
                    Timber.w(
                        "[OrphanSweep] legacy session %s has no derived index, skipping (pre-cutover)",
                        sessionId
                    )
                    continue
                }
            }
            val reportIndex = entry.reportIndex
            val retryCount = entry.retryCount

            // Exhausted budget — secure-delete this session's blobs and
            // drop the mapping (report presumed unrecoverable). Only the
            // rescue side deletes here, and only after MAX_RETRIES *real*
            // attempts, so a transient outage never drops genuine data.
            if (retryCount >= MAX_RETRIES) {
                Timber.i(
                    "[OrphanSweep] giving up on session %s after %d retries (%d blobs)",
                    sessionId, retryCount, orphans.size,
                )
                // Surface the loss in-app (no notification).
                // Count ACTUAL deletions, not orphans.size: a blob that
                // survives a failed secure-delete AND a failed File.delete()
                // stays on disk (retried next tick), so it must not be reported
                // as lost — else the user sees a phantom/inflated loss count,
                // re-counted every giveup cycle. Mirrors sweepStaleChunks,
                // which already counts real removals.
                val oldestMs = orphans.minOfOrNull { it.lastModified() } ?: 0L
                var deleted = 0
                for (blob in orphans) {
                    val ok = try {
                        uniffi.frappuccino.secureDeleteFile(blob.absolutePath)
                        true
                    } catch (e: Exception) {
                        Timber.w(e, "[OrphanSweep] secureDelete failed on %s", blob.name)
                        blob.delete()
                    }
                    if (ok) deleted++
                }
                // addOrphanDeletion no-ops on count <= 0.
                StreamPreferences.addOrphanDeletion(
                    applicationContext, deleted, oldestMs, "unrecoverable"
                )
                StreamPreferences.removeSessionReport(applicationContext, sessionId)
                sessionsAbandoned++
                continue
            }

            blobsScheduled += enqueueOrphanUploads(wm, sessionId, reportIndex, orphans)
            // One-shot runs (fired on unlock) must NOT bump the budget: a
            // few rapid unlocks while a blob is still uploading would
            // otherwise exhaust the 3-retry budget and secure-delete
            // in-flight data. So the MAX_RETRIES give-up is driven only by
            // periodic ticks (= persistent failure DESPITE connectivity);
            // prolonged-offline sessions are handled by the age-based 48 h
            // TTL backstop instead, not by this counter.
            val newCount = if (bumpRetry) {
                StreamPreferences.incrementSessionReportRetry(applicationContext, sessionId)
            } else {
                retryCount
            }
            Timber.i(
                "[OrphanSweep] session %s — enqueued %d orphan(s) → report idx %d, retry %d/%d (bump=%b)",
                sessionId, orphans.size, reportIndex, newCount, MAX_RETRIES, bumpRetry,
            )
            sessionsHandled++
        }

        // Drop mappings whose blobs are fully drained (no longer on disk).
        for (sid in mappings.keys) {
            if (sid !in orphanSessionIds) {
                StreamPreferences.removeSessionReport(applicationContext, sid)
                Timber.d("[OrphanSweep] session %s drained, mapping cleared", sid)
            }
        }

        Timber.tag("StreamMetrics").i(
            "orphanSweep handled=%d abandoned=%d reportsCreated=%d blobsScheduled=%d",
            sessionsHandled, sessionsAbandoned, reportsCreated, blobsScheduled,
        )
        Result.success()
        } // end synchronized(sweepLock)
    }

    /**
     * Enqueue one [ChunkUploadWorker] per orphan blob, targeting the ORIGINAL
     * session's report. The enqueue is unique by filename: switching to a plain
     * `enqueue()` would schedule duplicate PUTs for the same blob.
     *
     * The initial delay spreads the batch over roughly a 0-30 s window
     * (Blue MED-6), so a large orphan batch left by a long outage doesn't slam
     * the relay in lockstep. The UploadConcurrencyLimiter caps in-flight PUTs
     * but not the enqueue rate, which was otherwise instantaneous — dropping
     * the jitter because "the limiter already covers it" would be wrong.
     */
    private fun enqueueOrphanUploads(
        wm: WorkManager,
        sessionId: String,
        reportIndex: Int,
        orphans: List<File>,
    ): Int {
        val jitterRangeMs = 30_000L
        var scheduled = 0
        for ((index, blob) in orphans.withIndex()) {
            val baseOffset = if (orphans.size > 1) {
                (jitterRangeMs * index) / (orphans.size - 1)
            } else {
                0L
            }
            val randomJitter = (Math.random() * 1000L).toLong()
            val req = OneTimeWorkRequestBuilder<ChunkUploadWorker>()
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setInputData(
                    ChunkUploadWorker.buildInputData(
                        filePath = blob.absolutePath,
                        serverUrl = rs.readahead.washington.mobile.service
                            .StreamRecordingService.DEFAULT_SERVER_URL,
                        reportIndex = reportIndex,
                    )
                )
                .setInitialDelay(baseOffset + randomJitter, TimeUnit.MILLISECONDS)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    10, TimeUnit.SECONDS,
                )
                .addTag("stream_chunk_upload")
                .addTag("orphan_sweep")
                .addTag(sessionId)
                .build()
            wm.enqueueUniqueWork(
                blob.name,
                ExistingWorkPolicy.KEEP,
                req,
            )
            scheduled++
        }
        return scheduled
    }

    /**
     * Derive the originating sessionId from a queue blob filename.
     *
     * The sessionId is an opaque token with **no internal `_`**
     * (§10.11 MAJEUR-2), so it is everything before the LAST underscore.
     *
     * It has to be the last underscore and not the first: that is also what
     * recovers the legacy `<author>_<unix>_<rand>` triple unchanged (its last
     * `_` likewise precedes the seq), so legacy chunks still in flight keep
     * grouping correctly across the upgrade.
     *
     * Chunk blobs are named `<sessionId>_<seq>.strm`; the metadata blob shares
     * that shape as `<sessionId>_000000.strm`. A name with no `_` is ignored
     * rather than mis-grouped.
     */
    private fun sessionIdOf(name: String): String? {
        val idx = name.lastIndexOf('_')
        return if (idx > 0) name.substring(0, idx) else null
    }

    private fun isNetworkAvailable(): Boolean {
        return try {
            val cm = applicationContext.getSystemService(
                Context.CONNECTIVITY_SERVICE
            ) as android.net.ConnectivityManager
            val nw = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(nw) ?: return false
            caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        } catch (e: Exception) {
            false
        }
    }

    companion object {
        const val UNIQUE_NAME = "frappuccino-orphan-sweep"
        const val MAX_RETRIES = 3

        /**
         * Age at which an un-uploaded orphan blob is secure-deleted by the
         * TTL backstop ([ChunkUploadQueue.sweepStaleChunks], called at each
         * session start). Single source of truth — also referenced by
         * StreamRecordingService and the StreamActivity at-risk warning.
         */
        const val PURGE_AGE_MS = 48L * 60 * 60 * 1000

        /**
         * Age at which the StreamActivity banner starts
         * warning that an orphan is approaching [PURGE_AGE_MS] (24 h lead
         * time). Below this a normal post-stop backlog is still draining,
         * so we don't alarm.
         */
        const val WARN_AGE_MS = 24L * 60 * 60 * 1000

        /** Input flag: only the periodic run bumps the per-session giveup
         *  budget; the one-shot unlock run rescues without burning it. */
        private const val KEY_BUMP_RETRY = "bump_retry"

        /**
         * Process-wide lock serializing [doWork] bodies. The periodic and
         * one-shot schedules have different unique work names, so WorkManager
         * can run both at once; this lock then serializes a whole sweep body
         * (auth attempt, retry-budget bump, give-up secure-delete). The
         * double report for one offline-start session, this lock's original
         * motive (HIGH, neutral review 2026-06-18), is today already covered
         * upstream by the atomicity and idempotence of
         * [StreamPreferences.allocateReportIndexForSession]. Static (companion)
         * so it is shared across the per-run Worker instances WorkManager
         * constructs.
         */
        private val sweepLock = Any()

        /**
         * Sweep cadence. Set by therealshulgin's brief of 2026-05-14 ("30 minutes
         * max"), not by the library: WorkManager accepts periods from 15 min
         * up ([androidx.work.PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS]).
         */
        const val PERIOD_MINUTES = 30L

        /**
         * Enqueue (or no-op if already enqueued) the periodic sweep.
         * Call from `Application.onCreate` so the schedule survives
         * process death + reboot (WorkManager persists periodic work).
         */
        fun schedulePeriodicWork(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = PeriodicWorkRequestBuilder<OrphanSweepWorker>(
                PERIOD_MINUTES, TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setInputData(workDataOf(KEY_BUMP_RETRY to true))
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    1, TimeUnit.MINUTES,
                )
                .addTag("frappuccino_orphan_sweep")
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
            Timber.d("OrphanSweepWorker periodic schedule enqueued (every %d min)",
                PERIOD_MINUTES)
        }

        /**
         * Fire a ONE-SHOT sweep immediately, e.g. right after the ratchet is
         * unlocked ([PinUnlockActivity]). CONNECTED-gated.
         *
         * REPLACE, not KEEP, so a fresh unlock preempts any prior one-shot
         * still stuck in retry backoff. A failed one-shot keeps the unique-name
         * slot: under KEEP the new trigger would no-op and the backlog would
         * wait out the stale run's grown backoff. Observed in test on
         * 2026-06-18: a one-shot that had failed kept the slot, and later
         * unlocks could not re-fire it.
         * REPLACE is only safe because `bumpRetry=false` stops rapid unlocks
         * from burning the giveup budget and secure-deleting blobs that are
         * still in flight; the two go together.
         *
         * Why it exists (gap C): the periodic schedule only ticks every 30 min
         * and bails while locked, so an orphan backlog would otherwise wait up
         * to 30 min after unlock before its first rescue attempt — and on a
         * device that stays mostly locked between sessions it could miss every
         * eligible window and reach the 48 h TTL.
         */
        fun scheduleOneShot(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = OneTimeWorkRequestBuilder<OrphanSweepWorker>()
                .setConstraints(constraints)
                .setInputData(workDataOf(KEY_BUMP_RETRY to false))
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    10, TimeUnit.SECONDS,
                )
                .addTag("frappuccino_orphan_sweep")
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                "$UNIQUE_NAME-oneshot",
                ExistingWorkPolicy.REPLACE,
                request,
            )
            Timber.d("OrphanSweepWorker one-shot enqueued (REPLACE)")
        }

        // App-level "network is back" trigger.
        @Volatile private var networkTriggerRegistered = false
        @Volatile private var lastNetworkTriggerMs = 0L
        private const val NETWORK_TRIGGER_COOLDOWN_MS = 15_000L

        /**
         * Register a process-lifetime callback that, when a VALIDATED internet
         * network becomes available, resets the upload backoff and kicks the
         * orphan rescue — between sessions.
         *
         * Call this once from `Application.onCreate`, and from nowhere else:
         * process scope is the whole point of it. The callback is never
         * unregistered, it is meant to live as long as the process. Moving it
         * into an Activity or into the recording service would lose exactly
         * what distinguishes it from the service's own `onAvailable`, which
         * only covers the duration of a recording. A second call is harmless,
         * the registration being idempotent.
         *
         * Rationale (therealshulgin, 2026-06-18): WorkManager's exponential upload
         * backoff grows to hours on a flaky link, so when good network
         * returns a backed-off worker would otherwise wait out that stale
         * delay. The recording service already resets this on its own
         * onAvailable, but only while it runs; this lifts the same behaviour
         * to the whole app, so a backlog left by a stopped session drains as
         * soon as the network is back instead of waiting for the 30-min
         * periodic tick.
         */
        fun registerNetworkRescueTrigger(context: Context) {
            if (networkTriggerRegistered) return
            val appCtx = context.applicationContext
            val cm = appCtx.getSystemService(Context.CONNECTIVITY_SERVICE)
                as? android.net.ConnectivityManager ?: return
            val request = android.net.NetworkRequest.Builder()
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                .build()
            val cb = object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    onValidatedNetworkBack(appCtx)
                }
            }
            try {
                cm.registerNetworkCallback(request, cb)
                networkTriggerRegistered = true
                Timber.d("OrphanSweep network rescue trigger registered")
            } catch (e: Exception) {
                Timber.w(e, "registerNetworkRescueTrigger failed")
            }
        }

        private fun onValidatedNetworkBack(context: Context) {
            // Yield to an active recording: the service runs its own
            // onAvailable re-enqueue, and OrphanSweepWorker also yields to it.
            // Avoid double-handling / racing for blobs + ephemeral auth slots.
            if (rs.readahead.washington.mobile.service.StreamRecordingService.isRunning ||
                rs.readahead.washington.mobile.service.StreamRecordingService.isShuttingDown
            ) {
                return
            }
            // Respect the orphan-upload opt-out (neutral review LOW): if
            // disabled, the sweep bails without re-enqueuing, so we must NOT
            // cancel the queued workers here either — else an opted-out
            // user's previous-session uploads get cancelled with no
            // re-enqueue (surviving only to the 48h TTL). Matches doWork's
            // first gate.
            if (!StreamPreferences.isAutoUploadOrphansEnabled(context)) return
            // Debounce wifi<->cellular flaps (onAvailable fires per network).
            val now = System.currentTimeMillis()
            if (now - lastNetworkTriggerMs < NETWORK_TRIGGER_COOLDOWN_MS) return
            lastNetworkTriggerMs = now
            // The callback runs on a binder thread; the WM queries below
            // block, so hop off it.
            Thread({ kickRescue(context) }, "OrphanNetworkRescue").start()
        }

        /**
         * User-initiated rescue from the StreamActivity orphan
         * banner ("Réessayer l'envoi"). Same effect as the network-return
         * trigger but WITHOUT the debounce — an explicit tap must always act.
         * Requires the ratchet unlocked to authenticate; the caller
         * (StreamActivity, banner only shown post-unlock) guarantees that.
         * Yields to an active recording and respects the auto-upload opt-out.
         */
        fun triggerManualRescue(context: Context) {
            if (rs.readahead.washington.mobile.service.StreamRecordingService.isRunning ||
                rs.readahead.washington.mobile.service.StreamRecordingService.isShuttingDown
            ) {
                return
            }
            if (!StreamPreferences.isAutoUploadOrphansEnabled(context)) return
            val appCtx = context.applicationContext
            Thread({ kickRescue(appCtx) }, "OrphanManualRescue").start()
        }

        /**
         * Reset the upload backoff and kick a one-shot sweep. Shared by the
         * network-return trigger and the manual banner button. Must run off
         * the caller thread (the WM queries below block).
         */
        private fun kickRescue(context: Context) {
            try {
                UploadCircuitBreaker.reset()
                val wm = WorkManager.getInstance(context)
                // Cancel ENQUEUED (backed-off) upload workers so they don't
                // wait out a grown exponential backoff now that the network
                // is back; preserve RUNNING (never kill an in-flight PUT).
                // The orphan sweep below re-enqueues fresh (= reset backoff).
                // Mirrors the service's Phase 3.12 onAvailable handling,
                // lifted to between-session scope.
                try {
                    val infos = wm.getWorkInfosByTag("stream_chunk_upload").get()
                    var cancelled = 0
                    for (info in infos) {
                        if (info.state == WorkInfo.State.ENQUEUED) {
                            wm.cancelWorkById(info.id)
                            cancelled++
                        }
                    }
                    wm.pruneWork()
                    Timber.tag("StreamMetrics").i(
                        "networkRescue cancelledBackoff=%d", cancelled
                    )
                } catch (e: Exception) {
                    Timber.w(e, "networkRescue cancel/prune failed")
                }
                scheduleOneShot(context)
            } catch (e: Exception) {
                Timber.w(e, "networkRescue failed")
            }
        }
    }
}
