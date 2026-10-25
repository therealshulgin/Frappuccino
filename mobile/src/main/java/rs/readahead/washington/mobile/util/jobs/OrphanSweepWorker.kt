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
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import org.stream.crypto.StreamPreferences
import org.stream.crypto.upload.EnvelopeQueue
import org.stream.crypto.upload.LegacyReportMigration
import org.stream.crypto.upload.QueueKeyStore
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.service.StreamRecordingService
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Makes sure every envelope waiting in the queue has a live upload job.
 *
 * Envelopes are scheduled when they are produced, but a job can end without
 * its envelope leaving: WorkManager history pruned, a job cancelled to reset
 * its backoff, an app update in between. This worker walks the queue and
 * re-enqueues each envelope under its unique name (KEEP: a no-op for one whose
 * job is still queued or running).
 *
 * It deletes nothing, ever. Every envelope was signed when produced and the
 * key that signed it may be gone; deleting one because it waited too long
 * would destroy footage nothing can sign again. Whatever the relay refuses for
 * good is parked in the failed directory by the upload worker itself.
 *
 * It does not yield to a recording any more: re-enqueueing envelopes cannot
 * race the recording for anything. What it still leaves to the recording
 * service while it runs is authentication, which would race the service for
 * an ephemeral ratchet slot.
 *
 * It authenticates (and so needs the device unlocked) only when an envelope in
 * the queue may need the upload bearer to go: the first object of a report, a
 * directory entry, or one the relay answered 425 for. Everything else goes
 * without any bearer or PIN.
 *
 * The auto-upload toggle in Settings gates the whole worker (default ON): a
 * witness under coercion can stop envelopes from being re-sent in the
 * background. They stay in the queue meanwhile.
 *
 * Suspended while the legacy migration runs, which converts files into the
 * queue and schedules them itself at the end.
 */
@HiltWorker
class OrphanSweepWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
) : Worker(context, params) {

    override fun doWork(): Result {
        if (!StreamPreferences.isAutoUploadOrphansEnabled(applicationContext)) {
            Timber.d("[OrphanSweep] auto-upload disabled, skip")
            return Result.success()
        }
        if (LegacyReportMigration.inProgress) {
            Timber.d("[OrphanSweep] legacy migration running, skip")
            return Result.success()
        }
        // An emergency wipe after this point cancels the jobs; nothing this
        // run schedules may land after it.
        val wipeAtStart = StreamUploadManager.wipeGeneration()
        QueueKeyStore.ensureInstalled(applicationContext)
        val queue = EnvelopeQueue.get(applicationContext)
        if (queue.pendingCount() == 0) return Result.success()

        // Serialises the periodic and the one-shot runs, which WorkManager may
        // run at the same time (different unique names).
        synchronized(sweepLock) {
            maybeAuthenticate(queue)
            val scheduled = ChunkUploadWorker.scheduleAll(
                applicationContext, StreamRecordingService.DEFAULT_SERVER_URL, wipeAtStart,
            )
            Timber.tag("StreamMetrics").i(
                "orphanSweep scheduled=%d failed=%d", scheduled, queue.failedCount()
            )
        }
        return Result.success()
    }

    /**
     * Publish a bearer when a queued envelope may need one and none is held,
     * single-flight with every other authentication of the process
     * ([ensureBearer]): a sweep and an upload worker meeting on the same need
     * spend one slot. Best effort: without it those envelopes simply wait for
     * the next run.
     */
    private fun maybeAuthenticate(queue: EnvelopeQueue) {
        if (!queue.hasBearerDependent() || UploadAuthHolder.isPresent()) return
        if (!ensureBearer(applicationContext, StreamRecordingService.DEFAULT_SERVER_URL)) {
            Timber.d("[OrphanSweep] no bearer this run")
        }
    }

    companion object {
        const val UNIQUE_NAME = "frappuccino-orphan-sweep"

        /**
         * Age past which a queued envelope is shown to the witness as "still on
         * the phone": it has not reached the relay in a day, so it is exposed to
         * a seizure of the device. Nothing is deleted at any age.
         */
        const val WARN_AGE_MS = 24L * 60 * 60 * 1000

        /** Serialises [doWork] bodies across the per-run Worker instances. */
        private val sweepLock = Any()

        /**
         * Sweep cadence: 30 min, a chosen value (WorkManager accepts periods
         * from 15 min up).
         */
        const val PERIOD_MINUTES = 30L

        /**
         * Enqueue (or keep) the periodic sweep. Call from `Application.onCreate`
         * so the schedule survives process death and reboot.
         */
        fun schedulePeriodicWork(context: Context) {
            val request = PeriodicWorkRequestBuilder<OrphanSweepWorker>(PERIOD_MINUTES, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
                .addTag("frappuccino_orphan_sweep")
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_NAME, ExistingPeriodicWorkPolicy.KEEP, request,
            )
        }

        /**
         * Fire a one-shot sweep now (after an unlock, on network return, on the
         * banner's retry button). REPLACE so a fresh trigger is not swallowed by
         * a previous one-shot sitting in a long backoff.
         */
        fun scheduleOneShot(context: Context) {
            val request = OneTimeWorkRequestBuilder<OrphanSweepWorker>()
                .setConstraints(
                    Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.SECONDS)
                .addTag("frappuccino_orphan_sweep")
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                "$UNIQUE_NAME-oneshot", ExistingWorkPolicy.REPLACE, request,
            )
        }

        @Volatile private var networkTriggerRegistered = false
        @Volatile private var lastNetworkTriggerMs = 0L
        private const val NETWORK_TRIGGER_COOLDOWN_MS = 15_000L

        /**
         * Register, once per process, a callback that resets the upload backoff
         * and kicks a sweep when a validated network returns, between
         * recordings. WorkManager's exponential backoff grows to hours on a flaky
         * link; without this, a backlog would wait out that stale delay. Call
         * from `Application.onCreate` only: process scope is the point.
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
            } catch (e: Exception) {
                Timber.w(e, "registerNetworkRescueTrigger failed")
            }
        }

        private fun onValidatedNetworkBack(context: Context) {
            // During a recording the service's own network callback does the
            // same reset; doing it twice would only cancel each other's jobs.
            if (StreamRecordingService.isRunning || StreamRecordingService.isShuttingDown) return
            if (!StreamPreferences.isAutoUploadOrphansEnabled(context)) return
            val now = System.currentTimeMillis()
            if (now - lastNetworkTriggerMs < NETWORK_TRIGGER_COOLDOWN_MS) return
            lastNetworkTriggerMs = now
            // Binder thread: the WorkManager queries below block.
            Thread({ kickRescue(context) }, "OrphanNetworkRescue").start()
        }

        /** The banner's "retry" button: same as a network return, no debounce. */
        fun triggerManualRescue(context: Context) {
            if (!StreamPreferences.isAutoUploadOrphansEnabled(context)) return
            val appCtx = context.applicationContext
            Thread({ kickRescue(appCtx) }, "OrphanManualRescue").start()
        }

        /**
         * Cancel the envelope jobs waiting in backoff (never a running one) and
         * fire a one-shot sweep, which re-enqueues them with a fresh backoff.
         */
        private fun kickRescue(context: Context) {
            try {
                UploadCircuitBreaker.reset()
                val wm = WorkManager.getInstance(context)
                try {
                    var cancelled = 0
                    for (info in wm.getWorkInfosByTag(ChunkUploadWorker.TAG).get()) {
                        if (info.state == WorkInfo.State.ENQUEUED) {
                            wm.cancelWorkById(info.id)
                            cancelled++
                        }
                    }
                    wm.pruneWork()
                    Timber.tag("StreamMetrics").i("networkRescue cancelledBackoff=%d", cancelled)
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
