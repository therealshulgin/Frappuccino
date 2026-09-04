package rs.readahead.washington.mobile.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder
import rs.readahead.washington.mobile.views.activity.ArchiveModeActivity
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap

/**
 * Foreground service that runs the archive rescue download (single report or
 * bulk "TOUT TÉLÉCHARGER") so it survives screen-off and app-backgrounding.
 *
 * Secrets never travel through an Intent: the identity + authenticated session
 * are handed over via [ArchiveAuthHolder], in RAM, and only public report IDs
 * go into the Intent. The wipe follows the "last one alive wipes" rule (see
 * [ArchiveAuthHolder]); this service performs it in [onDestroy] iff the
 * activity is already gone, so dropping that condition either leaves a secret
 * in RAM or wipes it from under a still-living activity.
 *
 * Progress reaches the UI over a broadcast confined to the app's own package:
 * every send goes through a helper that sets `intent.setPackage(packageName)`
 * first. That confinement is a security property, not an implementation
 * detail — without it the rescue progress, report ids and blob names included,
 * goes out to any app that listens. `@Volatile @JvmStatic` mirror counters back
 * it up for onResume re-attach.
 *
 * Do not move the batch back into `ArchiveModeActivity.lifecycleScope`, where
 * it used to run with no foreground service and no wakeLock. When the screen
 * turned off or the app went to the background, the OS throttled/cut the
 * network (the blocking FFI `downloadAndDecrypt` then threw → batch "Stoppé")
 * or destroyed the activity, cancelling the job AND wiping the session, which
 * forces re-entry of the 12-word phrase. The recording path survives the exact
 * same scenario only because `StreamRecordingService` holds a foreground +
 * `PARTIAL_WAKE_LOCK` (Phase 1.14); this service gives the download the same
 * protection. (Phase 4.4.8.)
 */
class ArchiveDownloadService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    @Volatile
    private var batchJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Ordering: clear the shutdown flag and flip
        // isRunning on BEFORE any heavy work, so the busy-guard in the
        // activity is correct from the first instant.
        isShuttingDown = false
        isRunning = true

        // startForeground FIRST, synchronously — Android kills the
        // service with a crash if it's not foreground within ~5 s of
        // startForegroundService().
        try {
            val notification = buildNotification(getString(R.string.archive_fgs_starting))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Timber.e(e, "ArchiveDownloadService: startForeground threw — stopping")
            isRunning = false
            stopSelf()
            return START_NOT_STICKY
        }

        // Re-entrant start guard : a double-tap race (the user taps the row
        // before isRunning flips in the UI) could call startForegroundService
        // twice → don't launch a second concurrent batch on the same holder.
        if (batchJob?.isActive == true) {
            Timber.w("ArchiveDownloadService: re-entrant start ignored (batch active)")
            return START_NOT_STICKY
        }

        // PARTIAL_WAKE_LOCK so the CPU keeps running with the screen off.
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "frappuccino:archive")
            wakeLock?.acquire(2 * 60 * 60 * 1000L) // 2 h ceiling
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: wakeLock acquire failed (continuing)")
        }

        // WifiLock (HIGH_PERF) so WiFi doesn't drop to power-save with the
        // screen off — THE root cause of long downloads stalling: the CPU
        // stayed up via the wakelock, but the WiFi chip slept after a while,
        // freezing the sustained socket reads. HIGH_PERF is deprecated in
        // favour of LOW_LATENCY, but LOW_LATENCY only engages while the app
        // is the *foreground* app (screen on) — useless here. HIGH_PERF
        // keeps WiFi fully awake regardless, which is exactly screen-off.
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            wifiLock = wm.createWifiLock(
                WifiManager.WIFI_MODE_FULL_HIGH_PERF, "frappuccino:archive-wifi",
            )
            wifiLock?.acquire()
            Timber.i("ArchiveDownloadService: wifiLock held=%s", wifiLock?.isHeld)
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: wifiLock acquire failed (continuing)")
        }

        val pendingIds = intent?.getStringArrayListExtra(EXTRA_PENDING_IDS) ?: arrayListOf()
        val clearFirst = intent?.getBooleanExtra(EXTRA_CLEAR_FIRST, false) ?: false

        // Reset the re-attach mirrors for this fresh batch.
        doneReportIds.clear()
        lastReportIndex = 0
        lastReportTotal = pendingIds.size

        if (pendingIds.isEmpty()) {
            Timber.w("ArchiveDownloadService: no pending ids — stopping")
            stopSelf()
            return START_NOT_STICKY
        }

        batchJob = serviceScope.launch { runBatch(pendingIds, clearFirst) }

        // RAM-only secrets → no point restarting after a process kill.
        return START_NOT_STICKY
    }

    private suspend fun runBatch(pendingIds: List<String>, clearFirst: Boolean) {
        val identity = ArchiveAuthHolder.getIdentity()
        val session = ArchiveAuthHolder.getSession()
        // §10.11 Phase B — null on a pure-archive rescue that couldn't derive it;
        // the downloader then skips the OTS salt export (best-effort).
        val provenanceSigner = ArchiveAuthHolder.getProvenanceSigner()
        if (identity == null || session == null) {
            Timber.e("ArchiveDownloadService: holder empty (identity/session null)")
            broadcast(Intent(ACTION_ARCHIVE_ERROR).apply {
                putExtra(EXTRA_REPORT_INDEX, 0)
                putExtra(EXTRA_REPORT_TOTAL, pendingIds.size)
                putExtra(EXTRA_MESSAGE, "session perdue")
            })
            stopSelf()
            return
        }

        val downloader = ArchiveDownloader(this)
        val total = pendingIds.size
        var lastPublicDir: String? = null
        var doneCount = 0

        try {
            for ((idx, reportId) in pendingIds.withIndex()) {
                val reportIndex = idx + 1
                lastReportIndex = reportIndex
                updateNotification(
                    getString(R.string.archive_fgs_progress, reportIndex, total)
                )
                broadcast(Intent(ACTION_ARCHIVE_PROGRESS).apply {
                    putExtra(EXTRA_REPORT_ID, reportId)
                    putExtra(EXTRA_REPORT_INDEX, reportIndex)
                    putExtra(EXTRA_REPORT_TOTAL, total)
                    putExtra(EXTRA_BLOB_INDEX, 0)
                    putExtra(EXTRA_BLOB_TOTAL, 0)
                })

                if (clearFirst) {
                    downloader.clearReportFolder(reportId)
                }

                val outcome = downloader.downloadReport(
                    reportId, identity, session, provenanceSigner,
                ) { blobName, blobIndex, blobTotal ->
                    broadcast(Intent(ACTION_ARCHIVE_PROGRESS).apply {
                        putExtra(EXTRA_REPORT_ID, reportId)
                        putExtra(EXTRA_REPORT_INDEX, reportIndex)
                        putExtra(EXTRA_REPORT_TOTAL, total)
                        putExtra(EXTRA_BLOB_NAME, blobName)
                        putExtra(EXTRA_BLOB_INDEX, blobIndex)
                        putExtra(EXTRA_BLOB_TOTAL, blobTotal)
                    })
                }

                when (outcome) {
                    is ArchiveDownloader.ReportOutcome.Success -> {
                        lastPublicDir = outcome.publicDir
                        doneCount += 1
                        doneReportIds.add(reportId)
                        broadcast(Intent(ACTION_ARCHIVE_REPORT_DONE).apply {
                            putExtra(EXTRA_REPORT_ID, reportId)
                        })
                    }
                    // Empty report (0 blobs): nothing to fetch, but mark it
                    // done so a re-tap of the batch doesn't keep retrying it.
                    ArchiveDownloader.ReportOutcome.Empty -> {
                        doneReportIds.add(reportId)
                        broadcast(Intent(ACTION_ARCHIVE_REPORT_DONE).apply {
                            putExtra(EXTRA_REPORT_ID, reportId)
                        })
                    }
                    is ArchiveDownloader.ReportOutcome.Failure -> {
                        // Resumable: stop here, leave the already-done ones
                        // marked ✓, let the user re-tap to resume the rest.
                        broadcast(Intent(ACTION_ARCHIVE_ERROR).apply {
                            putExtra(EXTRA_REPORT_ID, reportId)
                            putExtra(EXTRA_REPORT_INDEX, reportIndex)
                            putExtra(EXTRA_REPORT_TOTAL, total)
                            putExtra(EXTRA_MESSAGE, outcome.message)
                        })
                        return
                    }
                }
            }

            broadcast(Intent(ACTION_ARCHIVE_BATCH_DONE).apply {
                putExtra(EXTRA_COUNT, doneCount)
                putExtra(EXTRA_PUBLIC_DIR, lastPublicDir ?: "Download/Frappuccino/")
            })
        } catch (e: Exception) {
            Timber.e(e, "ArchiveDownloadService: batch threw")
            broadcast(Intent(ACTION_ARCHIVE_ERROR).apply {
                putExtra(EXTRA_REPORT_INDEX, lastReportIndex)
                putExtra(EXTRA_REPORT_TOTAL, total)
                putExtra(EXTRA_MESSAGE, e.message ?: "batch error")
            })
        } finally {
            stopSelf()
        }
    }

    override fun onDestroy() {
        // Ordering: announce teardown before flipping
        // isRunning off, so any concurrent reader sees "busy" across the
        // whole onDestroy window.
        isShuttingDown = true

        // Stop any in-flight download coroutine. The blocking FFI call in
        // flight finishes on its own; the coroutine then unwinds (its
        // finally sweeps the transient cacheDir).
        try {
            serviceScope.cancel()
        } catch (_: Exception) {
        }

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        wifiLock?.let { if (it.isHeld) it.release() }
        wifiLock = null

        // "Last one alive wipes": if the activity is gone, WE own the
        // final wipe of identity + session. If it's still alive, it wipes
        // on its own onDestroy. clear() is idempotent → a race is safe.
        if (!ArchiveAuthHolder.activityAlive) {
            ArchiveAuthHolder.clear()
        }

        isRunning = false
        isShuttingDown = false
        super.onDestroy()
    }

    // ---- notification ----

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Archive download", NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Active while downloading archived streams"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, ArchiveModeActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Frappuccino")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_settings_white)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, buildNotification(text))
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: updateNotification failed")
        }
    }

    // ---- broadcast helper ----

    private fun broadcast(intent: Intent) {
        intent.setPackage(packageName)
        sendBroadcast(intent)
    }

    companion object {
        const val NOTIFICATION_ID = 7778
        const val CHANNEL_ID = "archive_download"

        // Intent extras (input).
        const val EXTRA_PENDING_IDS = "pending_ids" // ArrayList<String> — public report ids
        const val EXTRA_CLEAR_FIRST = "clear_first"  // Boolean — purge folder before re-download

        // Broadcast actions (output) + their extras.
        const val ACTION_ARCHIVE_PROGRESS = "org.stream.ARCHIVE_DOWNLOAD_PROGRESS"
        const val ACTION_ARCHIVE_REPORT_DONE = "org.stream.ARCHIVE_REPORT_DONE"
        const val ACTION_ARCHIVE_BATCH_DONE = "org.stream.ARCHIVE_BATCH_DONE"
        const val ACTION_ARCHIVE_ERROR = "org.stream.ARCHIVE_DOWNLOAD_ERROR"

        const val EXTRA_REPORT_ID = "report_id"
        const val EXTRA_REPORT_INDEX = "report_index"
        const val EXTRA_REPORT_TOTAL = "report_total"
        const val EXTRA_BLOB_NAME = "blob_name"
        const val EXTRA_BLOB_INDEX = "blob_index"
        const val EXTRA_BLOB_TOTAL = "blob_total"
        const val EXTRA_COUNT = "count"
        const val EXTRA_PUBLIC_DIR = "public_dir"
        const val EXTRA_MESSAGE = "message"

        @Volatile
        @JvmStatic
        var isRunning: Boolean = false
            private set

        @Volatile
        @JvmStatic
        var isShuttingDown: Boolean = false
            private set

        // Re-attach mirrors: an activity recreated mid-batch reads these
        // (+ the live broadcasts) to restore progress text and ✓ marks.
        @Volatile
        @JvmStatic
        var lastReportIndex: Int = 0
            private set

        @Volatile
        @JvmStatic
        var lastReportTotal: Int = 0
            private set

        /** Report ids completed during the current batch (thread-safe,
         *  weakly-consistent iteration → safe to snapshot from the UI). */
        @JvmStatic
        val doneReportIds: MutableSet<String> = ConcurrentHashMap.newKeySet()
    }
}
