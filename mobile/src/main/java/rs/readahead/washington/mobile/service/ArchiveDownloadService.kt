package rs.readahead.washington.mobile.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.upload.ArchiveSession
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.archive.ArchiveLocalData
import rs.readahead.washington.mobile.archive.ArchivePurgeRules
import rs.readahead.washington.mobile.archive.DirectoryRead
import rs.readahead.washington.mobile.archive.EnumerationEnd
import rs.readahead.washington.mobile.archive.FailureReason
import rs.readahead.washington.mobile.archive.ProbePlan
import rs.readahead.washington.mobile.archive.RescueCallRunner
import rs.readahead.washington.mobile.archive.RescueEnumeration
import rs.readahead.washington.mobile.archive.RescueFailures
import rs.readahead.washington.mobile.archive.RescueRetryPolicy
import rs.readahead.washington.mobile.archive.RescueSession
import rs.readahead.washington.mobile.archive.readDirectory
import rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder
import rs.readahead.washington.mobile.views.activity.ArchiveModeActivity
import timber.log.Timber
import uniffi.frappuccino.ClosureState
import uniffi.frappuccino.ReportCheck
import uniffi.frappuccino.RescuePlanner
import uniffi.frappuccino.RescueTarget
import kotlin.coroutines.cancellation.CancellationException

/**
 * Foreground service that runs the rescue's network and disk work (a "batch"):
 * the enumeration of the witness's reports, their verification, and an export.
 * It exists so that work survives screen-off and backgrounding: the screen
 * only starts batches and paints [RescueSession].
 *
 * Secrets never travel through an Intent: the identity, the provenance signer
 * and the rescue context are borrowed from [ArchiveAuthHolder], in RAM; an
 * Intent carries only a report's position in the list, or the destination the
 * witness picked for an export and which of the report's two sections goes
 * there.
 *
 * "The last one alive purges": when a batch ends and no archive screen is
 * attached any more, this service wipes the secrets and purges the local
 * copies ([ArchiveLocalData.purgeAll]) in [onDestroy]; with a screen still
 * attached it leaves both to the screens. Dropping that condition either
 * leaves a secret and decrypted-capable copies behind with nobody to remove
 * them, or erases them from under a screen that is still showing them. An
 * explicit close of the rescue screen cancels the batch first
 * ([cancelCurrentBatch]), so the purge follows at once.
 *
 * Progress reaches the screens through [RescueSession] plus a broadcast
 * confined to the app's own package: every send goes through [notifyChanged],
 * which sets the package first. That confinement is a security property — an
 * unconfined broadcast would tell any listening app that a rescue is running.
 *
 * Do not move the batch back into an Activity's `lifecycleScope`. Without a
 * foreground service and a wake lock, the OS throttles or cuts the network
 * with the screen off (the blocking FFI call then throws) or destroys the
 * activity, and a long rescue dies half-way.
 */
class ArchiveDownloadService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    @Volatile
    private var batchJob: Job? = null

    /** The action of [batchJob]. */
    @Volatile
    private var batchAction: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Flip the flags before any heavy work, so the screens' busy guard is
        // right from the first instant.
        isShuttingDown = false
        isRunning = true

        // startForeground first, synchronously: Android kills a service that
        // is not foreground within a few seconds of startForegroundService().
        try {
            val notification = buildNotification(getString(R.string.archive_fgs_starting))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Timber.e(e, "ArchiveDownloadService: startForeground threw, stopping")
            // The screen already shows a search it asked for as running:
            // end it, or the line stays "searching" with RECOVER hidden.
            // Unless a search already runs here (a second tap): that one
            // owns the state.
            if (batchJob?.isActive != true || batchAction != ACTION_ENUMERATE) {
                RescueSession.failStartedEnumeration(isEnumeration = intent?.action == ACTION_ENUMERATE)
            }
            stopSelf()
            return START_NOT_STICKY
        }

        // A double tap can start the service twice: one batch at a time.
        if (batchJob?.isActive == true) {
            Timber.w("ArchiveDownloadService: start ignored, a batch is running")
            // A search refused because another kind of batch runs never
            // starts; a second tap on a search that runs changes nothing.
            if (batchAction != ACTION_ENUMERATE) {
                RescueSession.failStartedEnumeration(isEnumeration = intent?.action == ACTION_ENUMERATE)
            }
            return START_NOT_STICKY
        }

        val work: (suspend () -> Unit)? = when (intent?.action) {
            ACTION_ENUMERATE -> ({ runEnumeration() })
            ACTION_VERIFY -> {
                val ordinals = intent.getIntArrayExtra(EXTRA_ORDINALS) ?: IntArray(0)
                ({ runVerification(ordinals) })
            }
            ACTION_EXPORT -> {
                val ordinal = intent.getIntExtra(EXTRA_ORDINAL, -1)
                val tree = intent.data
                val unverifiable = intent.getBooleanExtra(EXTRA_UNVERIFIABLE, false)
                if (ordinal > 0 && tree != null) ({ runExport(ordinal, tree, unverifiable) }) else null
            }
            else -> null
        }
        if (work == null) {
            Timber.w("ArchiveDownloadService: nothing to do, stopping")
            stopSelf()
            return START_NOT_STICKY
        }

        acquireLocks()
        val job = serviceScope.launch {
            try {
                work()
            } catch (e: CancellationException) {
                Timber.i("ArchiveDownloadService: batch cancelled")
            } catch (e: Exception) {
                Timber.e(e, "ArchiveDownloadService: batch failed")
            } finally {
                notifyChanged()
                stopSelf()
            }
        }
        batchJob = job
        batchAction = intent?.action
        currentJob = job

        // Secrets live in RAM only: restarting after a process kill would have
        // nothing to work with.
        return START_NOT_STICKY
    }

    // ---- batches ----

    private fun runner(): RescueCallRunner = RescueCallRunner(
        policy = RescueRetryPolicy(),
        classify = RescueFailures::classify,
        sleep = { delay(it) },
        onRateLimited = { wait ->
            RescueSession.setRateLimitedUntil(System.currentTimeMillis() + wait)
            updateNotification(getString(R.string.archive_fgs_rate_limited))
            notifyChanged()
        },
    )

    /** Whether the calling batch is still wanted: false once it is cancelled
     *  (explicit close, emergency wipe, service teardown). */
    private suspend fun activeCheck(): () -> Boolean {
        val job = currentCoroutineContext()[Job]
        return { job?.isActive ?: true }
    }

    private suspend fun runEnumeration() {
        val session = ArchiveAuthHolder.getSession() ?: return
        val active = activeCheck()
        val runner = runner()
        // A new enumeration replaces the list: the reports of the previous
        // one, and their local copies, go before anything is probed.
        RescueSession.entries().mapNotNull { it.dir }.forEach { ArchiveLocalData.purgeDir(it) }
        val gen = RescueSession.beginEnumeration()
        updateNotification(getString(R.string.archive_fgs_enumerating))
        notifyChanged()

        // An unreadable directory is an anomaly, not a stop: the search goes
        // on without it, over the long tail, as the desktop CLI does.
        val read = readDirectory(runner, RescueFailures::isUnreadable) { session.openDirectory() }
        val (directory, directoryState) = when (read) {
            is DirectoryRead.Listed -> Pair(
                read.directory,
                if (read.directory == null) RescueSession.DirectoryState.ABSENT else RescueSession.DirectoryState.LISTED,
            )
            DirectoryRead.Unreadable -> Pair(null, RescueSession.DirectoryState.UNREADABLE)
            is DirectoryRead.Failed -> {
                if (active()) {
                    Timber.w(read.cause, "ArchiveDownloadService: directory not read")
                    RescueSession.endEnumeration(gen, RescueSession.EnumerationState.INCOMPLETE, RescueFailures.reason(read.cause))
                } else {
                    RescueSession.endEnumeration(gen, RescueSession.EnumerationState.CANCELLED, null)
                }
                return
            }
        }
        // Any closure on the directory is an anomaly (the planner probes
        // further whenever there is one, valid or not). It is checked so the
        // screen can say whether it is valid, and that it could not be
        // checked when the check fails.
        val closure = directory?.takeIf { it.hasClosure() }?.let { directoryClosure(it, runner) }
        val planner: RescuePlanner = try {
            session.planner(directory)
        } catch (e: Exception) {
            // The directory was read: say what it holds before stopping.
            RescueSession.setDirectory(gen, directory, directoryState, closure, unmatched = 0, longTail = false)
            RescueSession.endEnumeration(gen, RescueSession.EnumerationState.INCOMPLETE, RescueFailures.reason(e))
            return
        }
        try {
            val current = RescueSession.setDirectory(
                gen, directory, directoryState, closure,
                planner.unmatchedEntries().toInt(),
                planner.probesLongTail(),
            )
            if (!current) return
            notifyChanged()
            val plan = object : ProbePlan<RescueTarget> {
                override fun next(): RescueTarget? = planner.next()
                override fun record(found: Boolean) = planner.record(found)
                override fun hitCap(): Boolean = planner.hitProbeCap()
            }
            val end = RescueEnumeration(plan, runner, RescueFailures::isUnreadable) { target ->
                session.openReport(target)
            }.run(
                isActive = active,
                onFound = { target, check ->
                    RescueSession.addEntry(
                        gen, check, target.scheme, target.index.toLong(), check.objectNames().size,
                    )
                    RescueSession.setRateLimitedUntil(0L)
                    notifyChanged()
                },
                onUnreadable = {
                    RescueSession.noteUnreadableListing(gen)
                    notifyChanged()
                },
                onDiscard = { check ->
                    try {
                        check.destroy()
                    } catch (_: Exception) {
                    }
                },
                onProbed = { probed ->
                    RescueSession.setProbed(gen, probed)
                    if (probed % PROGRESS_EVERY == 0) notifyChanged()
                },
            )
            when (end) {
                EnumerationEnd.Complete ->
                    RescueSession.endEnumeration(gen, RescueSession.EnumerationState.COMPLETE, null)
                EnumerationEnd.Capped -> {
                    Timber.w("ArchiveDownloadService: enumeration stopped on the probe cap")
                    RescueSession.endEnumeration(gen, RescueSession.EnumerationState.INCOMPLETE, FailureReason.PROBE_CAP)
                }
                EnumerationEnd.Cancelled ->
                    RescueSession.endEnumeration(gen, RescueSession.EnumerationState.CANCELLED, null)
                is EnumerationEnd.Incomplete -> {
                    Timber.w(end.cause, "ArchiveDownloadService: enumeration incomplete")
                    RescueSession.endEnumeration(
                        gen,
                        RescueSession.EnumerationState.INCOMPLETE,
                        RescueFailures.reason(end.cause),
                    )
                }
            }
        } finally {
            planner.destroy()
        }
    }

    /** The checked state of the closure recorded on [directory];
     *  [ClosureState.UNCHECKED] when the check could not be made. */
    private suspend fun directoryClosure(directory: ReportCheck, runner: RescueCallRunner): ClosureState {
        val scratch = java.io.File(cacheDir, "archive-directory-closure.bin")
        return try {
            runner.run { directory.verifyClosure(scratch.path) }
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: directory closure not checked")
            ClosureState.UNCHECKED
        } finally {
            scratch.delete()
        }
    }

    private suspend fun runVerification(ordinals: IntArray) {
        val session = ArchiveAuthHolder.getSession() ?: return
        val active = activeCheck()
        val identity = ArchiveAuthHolder.getIdentity() ?: return
        val signer = ArchiveAuthHolder.getProvenanceSigner()
        val directory = RescueSession.directoryCheck()
        val downloader = ArchiveDownloader(this)
        val runner = runner()
        val total = ordinals.size
        for ((i, ordinal) in ordinals.withIndex()) {
            if (!active()) return
            val entry = RescueSession.entry(ordinal) ?: continue
            if (entry.state == RescueSession.EntryState.VERIFIED) continue
            entry.state = RescueSession.EntryState.VERIFYING
            entry.failure = null
            updateNotification(getString(R.string.archive_fgs_verifying, i + 1, total))
            notifyChanged()
            try {
                downloader.verifyReport(
                    entry, session, identity, signer, directory, runner,
                    isActive = active,
                ) { done, _ ->
                    if (done % PROGRESS_EVERY == 0) notifyChanged()
                }
            } catch (e: CancellationException) {
                entry.state = RescueSession.EntryState.LISTED
                throw e
            } catch (e: Exception) {
                Timber.w(e, "ArchiveDownloadService: verification of a report failed")
                entry.state = RescueSession.EntryState.FAILED
                entry.failure = RescueFailures.reason(e)
            }
            RescueSession.setRateLimitedUntil(0L)
            notifyChanged()
        }
    }

    private suspend fun runExport(ordinal: Int, tree: Uri, unverifiable: Boolean) {
        val active = activeCheck()
        val session = ArchiveAuthHolder.getSession() ?: return
        val identity = ArchiveAuthHolder.getIdentity() ?: return
        val entry = RescueSession.entry(ordinal) ?: return
        if (entry.state != RescueSession.EntryState.VERIFIED) return
        if (unverifiable) {
            runUnverifiableExport(entry, tree, session, identity, active)
            return
        }
        entry.exportState = RescueSession.ExportState.RUNNING
        entry.exportDone = 0
        entry.exportTotal = 0
        entry.exportOutcome = null
        updateNotification(getString(R.string.archive_fgs_exporting))
        notifyChanged()
        try {
            entry.exportOutcome = ArchiveDownloader(this).exportReport(
                entry, tree, session, identity, ArchiveAuthHolder.getProvenanceSigner(),
                isActive = active,
            ) { done, total ->
                entry.exportDone = done
                entry.exportTotal = total
                notifyChanged()
            }
            entry.exportState = RescueSession.ExportState.DONE
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: export failed")
            entry.exportState = RescueSession.ExportState.FAILED
        }
    }

    /** The export of the objects kept apart as not verifiable: its own
     *  folder and its own progress, never the verified export's. */
    private fun runUnverifiableExport(
        entry: RescueSession.Entry,
        tree: Uri,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        active: () -> Boolean,
    ) {
        entry.unverifiableExportState = RescueSession.ExportState.RUNNING
        entry.unverifiableExportDone = 0
        entry.unverifiableExportTotal = 0
        entry.unverifiableExportOutcome = null
        updateNotification(getString(R.string.archive_fgs_exporting))
        notifyChanged()
        try {
            entry.unverifiableExportOutcome = ArchiveDownloader(this).exportUnverifiable(
                entry, tree, session, identity, isActive = active,
            ) { done, total ->
                entry.unverifiableExportDone = done
                entry.unverifiableExportTotal = total
                notifyChanged()
            }
            entry.unverifiableExportState = RescueSession.ExportState.DONE
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: export of the not-verifiable objects failed")
            entry.unverifiableExportState = RescueSession.ExportState.FAILED
        }
    }

    override fun onDestroy() {
        // Announce the teardown before flipping isRunning off, so a concurrent
        // reader sees "busy" across the whole of onDestroy.
        isShuttingDown = true

        // Stop the batch. A blocking FFI call in flight finishes on its own;
        // the coroutine then unwinds at its next check.
        try {
            serviceScope.cancel()
        } catch (_: Exception) {
        }
        currentJob = null

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        wifiLock?.let { if (it.isHeld) it.release() }
        wifiLock = null

        // The last one alive purges. Screens and this service both run these
        // callbacks on the main thread, so the check and the flag flip below
        // cannot interleave with a screen's own check.
        if (ArchivePurgeRules.shouldPurge(if (ArchiveAuthHolder.activityAlive) 1 else 0, batchRunning = false)) {
            ArchiveAuthHolder.clear()
            ArchiveLocalData.purgeAll(this)
        }

        isRunning = false
        isShuttingDown = false
        notifyChanged()
        super.onDestroy()
    }

    // ---- locks ----

    private fun acquireLocks() {
        // PARTIAL_WAKE_LOCK so the CPU keeps running with the screen off.
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "frappuccino:archive")
            wakeLock?.acquire(WAKE_LOCK_CEILING_MS)
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: wakeLock acquire failed (continuing)")
        }
        // WifiLock (HIGH_PERF) so WiFi does not drop to power-save with the
        // screen off, which freezes long downloads even with the CPU awake.
        // HIGH_PERF is deprecated in favour of LOW_LATENCY, but LOW_LATENCY
        // only engages while the app is in the foreground with the screen on.
        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "frappuccino:archive-wifi")
            wifiLock?.acquire()
        } catch (e: Exception) {
            Timber.w(e, "ArchiveDownloadService: wifiLock acquire failed (continuing)")
        }
    }

    // ---- notification ----

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, getString(R.string.archive_fgs_channel), NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        // SINGLE_TOP | CLEAR_TOP: a tap returns to the rescue screen that is
        // already open instead of stacking a second one on it.
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, ArchiveModeActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
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

    private fun notifyChanged() {
        val intent = Intent(ACTION_RESCUE_CHANGED)
        intent.setPackage(packageName)
        sendBroadcast(intent)
    }

    companion object {
        const val NOTIFICATION_ID = 7778
        const val CHANNEL_ID = "archive_download"

        private const val ACTION_ENUMERATE = "org.stream.ARCHIVE_ENUMERATE"
        private const val ACTION_VERIFY = "org.stream.ARCHIVE_VERIFY"
        private const val ACTION_EXPORT = "org.stream.ARCHIVE_EXPORT"
        private const val EXTRA_ORDINALS = "ordinals"
        private const val EXTRA_ORDINAL = "ordinal"
        private const val EXTRA_UNVERIFIABLE = "unverifiable"

        /** Broadcast (confined to the app's package): [RescueSession]
         *  changed, repaint. */
        const val ACTION_RESCUE_CHANGED = "org.stream.ARCHIVE_RESCUE_CHANGED"

        private const val PROGRESS_EVERY = 4
        private const val WAKE_LOCK_CEILING_MS = 4 * 60 * 60 * 1000L

        @Volatile
        @JvmStatic
        var isRunning: Boolean = false
            private set

        @Volatile
        @JvmStatic
        var isShuttingDown: Boolean = false
            private set

        @Volatile
        private var currentJob: Job? = null

        /** Enumerate the witness's reports. */
        fun startEnumeration(context: Context) = start(context, Intent(context, ArchiveDownloadService::class.java).setAction(ACTION_ENUMERATE))

        /** Fetch and verify the reports at these positions (1-based). */
        fun startVerification(context: Context, ordinals: IntArray) = start(
            context,
            Intent(context, ArchiveDownloadService::class.java).setAction(ACTION_VERIFY)
                .putExtra(EXTRA_ORDINALS, ordinals),
        )

        /**
         * Export the report at [ordinal] into the tree [treeUri]: its verified
         * objects, or, with [unverifiable], only the ones kept apart as not
         * verifiable, to a separate folder.
         */
        fun startExport(context: Context, ordinal: Int, treeUri: Uri, unverifiable: Boolean = false) = start(
            context,
            Intent(context, ArchiveDownloadService::class.java).setAction(ACTION_EXPORT)
                .putExtra(EXTRA_ORDINAL, ordinal)
                .putExtra(EXTRA_UNVERIFIABLE, unverifiable)
                .setData(treeUri),
        )

        /** Cancel the running batch, if any. Its service stops once the call
         *  in flight returns. Safe from any thread. */
        fun cancelCurrentBatch() {
            currentJob?.cancel()
        }

        /** Cancel the running batch and stop the service now: its teardown
         *  (and the purge it may owe) runs without waiting for the call in
         *  flight, whose late writes then fail on a renamed directory. */
        fun stop(context: Context) {
            cancelCurrentBatch()
            try {
                context.stopService(Intent(context, ArchiveDownloadService::class.java))
            } catch (e: Exception) {
                Timber.w(e, "ArchiveDownloadService: stopService failed")
            }
        }

        private fun start(context: Context, intent: Intent) {
            ContextCompat.startForegroundService(context, intent)
        }
    }
}
