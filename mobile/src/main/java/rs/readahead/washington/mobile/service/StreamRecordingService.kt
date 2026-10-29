package rs.readahead.washington.mobile.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.camera.core.CameraSelector
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import org.json.JSONObject
import org.stream.crypto.StreamPreferences
import org.stream.crypto.capture.ChunkEncoderBundle
import org.stream.crypto.capture.RollingChunkRecorder
import org.stream.crypto.upload.EnvelopeNames
import org.stream.crypto.upload.EnvelopeQueue
import org.stream.crypto.upload.QueueKeyStore
import org.stream.crypto.upload.ReportAlerts
import org.stream.crypto.upload.ReportProducer
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.util.jobs.ChunkUploadWorker
import rs.readahead.washington.mobile.util.jobs.LegacyMigrationWorker
import rs.readahead.washington.mobile.util.jobs.ProvenanceTimestampWorker
import rs.readahead.washington.mobile.views.activity.StreamActivity
import timber.log.Timber
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Foreground service for continuous encrypted video streaming.
 *
 * Pipeline: CameraX (camera bind + preview) → GL wedge + MediaCodec
 * (RollingChunkRecorder) → MP4 chunks (5 s) → the report's writer
 * ([ReportProducer], Rust over UniFFI: encrypt + sign + write an envelope) →
 * envelope queue → one upload job per envelope ([ChunkUploadWorker]).
 *
 * One recording = one report. It is opened before the camera starts (its
 * directory entry and its metadata are sealed first; if that fails the
 * recording does not start), every chunk is sealed as it comes, and the
 * report is closed after the last chunk: the closure is the writer's last
 * task, submitted once the recorder's stop() has returned. The service stays
 * in the foreground, wake lock held, until that closure is written; a stop
 * never blocks the main thread.
 */
class StreamRecordingService : Service(), LifecycleOwner {

    companion object {
        const val CHANNEL_ID = "stream_recording"
        const val NOTIFICATION_ID = 7777
        const val DEFAULT_CHUNK_INTERVAL_MS = 5000L
        const val DEFAULT_SERVER_URL = "https://relay.shake-document-protect.org:8443"

        // The CONTROL_AE_TARGET_FPS_RANGE requested on the Preview
        // (buildHevcPreview), named so that the field log of what the camera
        // advertises compares against the value actually requested.
        private const val AE_TARGET_FPS_MIN = 24
        private const val AE_TARGET_FPS_MAX = 30

        // Device-side low-storage thresholds (free bytes on
        // the internal /data partition, checked on the 1 Hz notification tick).
        // Below WARN we surface a heads-up in the notification; below CRITICAL
        // we stop the recording cleanly (finalize + seal the current chunk,
        // close the report) before a full disk makes chunk writes fail silently
        // or the OS kills us uncleanly. CRITICAL is small but enough for a
        // clean finalize (a 720p HEVC chunk + its envelope is only a few MB).
        const val DEVICE_STORAGE_WARN_BYTES = 400L * 1024 * 1024      // 400 MB
        const val DEVICE_STORAGE_CRITICAL_BYTES = 100L * 1024 * 1024  // 100 MB

        // Broadcast actions for UI updates
        const val ACTION_CHUNK_UPDATE = "org.stream.CHUNK_UPDATE"
        const val EXTRA_CHUNKS_ENCRYPTED = "encrypted"
        const val EXTRA_CHUNKS_UPLOADED = "uploaded"
        const val EXTRA_CHUNKS_LOST = "lost"

        /**
         * Intent action that ends the recording. Sent with startService, not
         * stopService: the service then closes the report while still in the
         * foreground and stops itself once the closure is written. A plain
         * stopService still works (the same teardown runs from onDestroy), but
         * without the foreground status protecting it.
         */
        const val ACTION_STOP = "org.stream.STOP_RECORDING"

        /**
         * The safety bound on the recorder's stop(): past it the report is
         * closed anyway, and a chunk the recorder delivers later is counted
         * lost and shown. Long on purpose: a normal stop takes well under a
         * second, and closing early costs a chunk.
         */
        private const val RECORDER_STOP_BOUND_MS = 60_000L

        /** How long the teardown waits for the closure to be written. */
        private const val CLOSE_WAIT_MS = 120_000L

        /**
         * How long the teardown waits for a report the init thread is still
         * opening (the migration's first steps, then the two opening seals).
         */
        private const val OPENING_WAIT_MS = 120_000L

        /**
         * After the closure is given up: how long to wait for the writer to
         * report the chunks it can no longer seal. They fail at once once the
         * key is gone; only a seal stuck in its own write takes longer.
         */
        private const val ABORT_DRAIN_MS = 10_000L

        /** Slack on top of the teardown's own bounds, for the wake lock. */
        private const val TEARDOWN_MARGIN_MS = 60_000L

        // Adaptive quality broadcast for HUD updates.
        const val ACTION_QUALITY_UPDATE = "org.stream.QUALITY_UPDATE"
        const val EXTRA_QUALITY_LABEL = "quality_label"

        // Last-known counters, written by the service and
        // read by `StreamActivity.onResume` to recover from
        // broadcasts dropped while the activity was paused (screen off
        // turning the activity into a paused-but-still-foreground state
        // where the BroadcastReceiver is unregistered). Survives the
        // service running, NOT process death — but at process death the
        // service stops too, so semantically the values reset together.
        @Volatile @JvmStatic
        var lastChunksEncrypted: Int = 0
            private set
        @Volatile @JvmStatic
        var lastChunksUploaded: Int = 0
            private set

        // Last broadcast quality label, mirrored static for
        // onResume recovery. Default "720p" (HD initial).
        @Volatile @JvmStatic
        var lastQualityLabel: String = "720p"
            private set

        /** Chunks of the current recording lost at capture (never sealed). */
        @Volatile @JvmStatic
        var lastChunksLost: Int = 0
            private set

        /** Reset by the service when a new recording session starts. */
        fun resetCounters() {
            lastChunksEncrypted = 0
            lastChunksUploaded = 0
            lastChunksLost = 0
            lastQualityLabel = "720p"
        }

        /**
         * Single-flight guard: one recording session per process, from the
         * start command until its teardown has finished (closure written). A
         * second start command while it is held is ignored: it must not start
         * a second report, and must not stop the one running either. Rust
         * refuses a second live writer too; this guard keeps the service from
         * even trying.
         */
        private val sessionClaim = AtomicBoolean(false)

        /** Whether a recording session (or its teardown) holds the process. */
        @JvmStatic
        fun isBusy(): Boolean = sessionClaim.get()

        /**
         * Ask a running recording to stop (closure written in the foreground).
         * A no-op when no session is running.
         */
        fun requestStop(context: Context) {
            if (!sessionClaim.get()) return
            try {
                context.startService(
                    Intent(context, StreamRecordingService::class.java).setAction(ACTION_STOP)
                )
            } catch (e: Exception) {
                // Background start refused: fall back to a plain stop, which
                // runs the same teardown from onDestroy.
                Timber.w(e, "stop intent refused, stopping the service directly")
                context.stopService(Intent(context, StreamRecordingService::class.java))
            }
        }

        /**
         * Process-local "is a recording session live ?" flag, read by the
         * workers and the lock-timeout controller so they leave authentication
         * to the recording while it runs (avoiding races on the ratchet slot
         * pool). Volatile + JvmStatic so cross-thread reads see the latest
         * value without needing the service binder.
         */
        @Volatile @JvmStatic
        var isRunning: Boolean = false
            private set

        /**
         * Never let [isRunning] flip to false before this flag is true, and
         * never merge the two : `isShuttingDown` is raised at the very top
         * of [requestStop], before `isRunning = false`, and only goes back to
         * false at the end of the teardown ([finishTeardown]). Workers
         * ([ChunkUploadWorker.ensureFallbackReAuth],
         * [rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker])
         * gate on `isRunning || isShuttingDown`, written literally that
         * way, so the entire teardown window is covered — not just the
         * instant where `isRunning` flips. Teardown here means the recorder
         * stop, the last seals, the report's closure and the release of the
         * GL/encoder/muxer.
         *
         * What reopening that window costs : a worker that wakes up
         * between `isRunning=false` and the end of teardown (~50-500 ms
         * later) reads `isRunning=false`, decides it is safe to re-auth
         * itself, and calls `manager.authenticateV2()` while the service
         * is still finishing its own auth lifecycle (initServerSession /
         * maybeRetryAuth) — racing it for an ephemeral ratchet slot → a
         * no_auth_token loop or a half-published JWT. Seen once, on
         * OnePlus 13 at 2026-05-19T00:14:34 (Blue HIGH-6, Phase H2-B.16).
         *
         * Clearing it at the very end of the teardown matters too : a new
         * service instance, or a parallel orphan sweep running after this one
         * is fully dead, has to start from a clean flag.
         *
         * A normal stop does NOT wipe the V2 ratchet — only an explicit
         * `StreamUploadManager.lock()` / `panicWipe()` does. So
         * `isUnlocked()` stays true after a clean stop and a surviving
         * process CAN re-auth ; the defer above is about not racing the
         * service's in-flight auth, not about a torn-down ratchet.
         */
        @Volatile @JvmStatic
        var isShuttingDown: Boolean = false
            private set

        /**
         * Chunks handed to the writer and not sealed (or given up) yet. Do not
         * fold this into [pendingChunks] as a duplicate : it mirrors the same
         * count, but [pendingChunks] is a private instance field and the
         * service-less [V2LockTimeoutController] cannot read it, hence a
         * process-scoped copy. The controller defers the upload-JWT
         * auto-clear and the ratchet auto-lock while this is > 0: a chunk
         * being sealed is not in the queue yet, so the queue cannot vouch for
         * it.
         */
        @JvmStatic
        private val encryptionsInFlightCounter = AtomicInteger(0)

        @JvmStatic
        fun encryptionsInFlight(): Int = encryptionsInFlightCounter.get()
    }

    // Lifecycle for CameraX
    private val lifecycleRegistry = LifecycleRegistry(this)

    override fun getLifecycle(): Lifecycle = lifecycleRegistry

    // Created and taken on the main thread when the session claim is taken,
    // released on the main thread at the very end of the teardown
    // ([finishTeardown]): one thread for both, so the release can never run
    // before the acquire. Not reference counted, so the re-acquire at the stop
    // (which re-arms its timeout for the teardown) needs only one release.
    @Volatile private var wakeLock: PowerManager.WakeLock? = null
    // [startCamera] drives this rolling HEVC recorder (GL wedge +
    // MediaCodec) as the sole capture pipeline.
    private var hevcRecorder: RollingChunkRecorder? = null

    // Single-flight guard for HEVC quality
    // swaps. Since H2-B §Bugs #5 the swap is done IN PLACE by
    // [RollingChunkRecorder.swapVideoConfig] — no camera rebind, no GL
    // teardown, no preview black-out — but it is not instantaneous for all
    // that : it posts to the recorder's rotate handler and blocks until the
    // swap completes. If [AdaptiveQualityManager] fires a second
    // transition while the first is still settling, we drop it ; the
    // manager's hysteresis (3 SLOW / 10 FAST / 30 s backlog cooldown)
    // already guarantees the next decision is at least one chunk-tick
    // away, so dropping one missed transition is harmless — the manager
    // will request it again on the next eligible tick.
    private val hevcSwapInFlight = java.util.concurrent.atomic.AtomicBoolean(false)

    // On-screen preview Surface for the
    // HEVC pipeline. Set by the activity from its SurfaceView's
    // SurfaceHolder.Callback ; forwarded to [hevcRecorder] when it
    // exists, otherwise cached until [startCamera] runs.
    @Volatile private var hevcPreviewSurface: android.view.Surface? = null

    // Phase H2-B adaptive VBR↔CBR (2026-05-17) — current rate-control
    // mode in effect for the HEVC encoder. Toggled by
    // [AdaptiveQualityManager.onBitrateModeChange] in response to
    // upload backlog. Read by [buildHevcVideoConfigFor] so that every
    // swap (quality or mode driven) picks up the latest value.
    @Volatile private var currentHevcBitrateMode:
        org.stream.crypto.capture.ChunkEncoderBundle.BitrateMode =
        org.stream.crypto.capture.ChunkEncoderBundle.BitrateMode.VBR

    // The writer of this recording's report, through its single thread. Set
    // once the report is open (directory entry + metadata sealed); null before
    // that and for a start that failed.
    @Volatile private var producer: ReportProducer? = null
    private var envelopeQueue: EnvelopeQueue? = null

    // The emergency-wipe generation when this session started. If it moved,
    // the identity this session wrote for no longer exists: nothing more of it
    // may be written (no alert, no timestamp ticket).
    @Volatile private var wipeGenerationAtStart: Int = 0

    // §10.11 — whether this recording is tracked for provenance: a snapshot
    // taken at session start (toggle ON + signer loaded), so the perimeter stays
    // the same for the whole recording even if the toggle changes meanwhile.
    // The chunk hashes themselves come from the writer at closure.
    @Volatile private var provenanceActive: Boolean = false

    // Teardown state: requested once ([requestStop]); past the recorder's
    // stop (or its safety bound) every chunk still delivered is lost.
    private val stopRequested = AtomicBoolean(false)
    @Volatile private var acceptingChunks = true

    // Orders the start of the session's report and recorder against the
    // teardown: whatever the teardown reads under it is what it stops, and
    // nothing starts after that read.
    private val lifecycleLock = Any()

    // Counted down by the init thread once the report it opens is published
    // (or once it gave up opening one). The teardown waits for it before it
    // looks for the report, so a report opened while the stop was arriving is
    // closed by the teardown, in the foreground and under the wake lock, and
    // the session claim is only released after the writer is.
    private val openingDone = java.util.concurrent.CountDownLatch(1)

    // The network callback, registered by the init thread after the initial
    // authentication and removed by requestStop: never registered after the
    // stop, so none outlives the session.
    private val networkRegistration =
        org.stream.crypto.capture.StopGuardedRegistration<android.net.ConnectivityManager.NetworkCallback>()

    // Whether this instance took the session claim (a start command that was
    // ignored, or a stop request sent to an idle service, did not).
    @Volatile private var ownsSession = false

    // The session claim is released once BOTH the teardown has finished and
    // onDestroy has run, whichever comes last: a start arriving in between
    // would otherwise land on an instance that is being destroyed.
    private var teardownFinished = false
    private var destroyCalled = false

    // Revised H2-B §Bugs #5 — CameraX refs promoted to fields by
    // [startCamera]. They no longer serve to rebind the camera (a quality
    // swap is done in place by the recorder) : [applyQuality] reads them
    // only as a readiness signal — non-null means the initial startCamera
    // bind ran. Reset to null at the end of the teardown so a late callback can't work on
    // a dead service.
    private var cameraProviderRef: androidx.camera.lifecycle.ProcessCameraProvider? = null
    private var previewRef: Preview? = null
    // Do not simplify this filter down to `requireLensFacing(BACK)`. Matching
    // the field of view means preferring the logical multi-camera wrapper
    // (Mediatek Seeker cam id=4 = wrap(0 main, 2 ultra-wide, 3 tele) with
    // zoom range 0.6×–20×, and the OEM camera app's default bind), observed
    // 2026-05-18. The filter falls through to the first BACK camera if no
    // multi-cam wrapper is exposed.
    //
    // There is no derivable criterion for finding it, only a heuristic : an
    // abnormally wide advertised zoom range is the wrapper's signature. So we
    // pick the BACK [CameraInfo] whose [zoomState] has minZoomRatio < 0.95 OR
    // maxZoomRatio > 8.
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private val cameraSelectorHevc: CameraSelector = CameraSelector.Builder()
        .requireLensFacing(CameraSelector.LENS_FACING_BACK)
        .addCameraFilter { cameraInfos ->
            val multiCam = cameraInfos.firstOrNull { info ->
                val z = info.zoomState.value
                z != null && (z.minZoomRatio < 0.95f || z.maxZoomRatio > 8f)
            }
            val pick = multiCam ?: cameraInfos.firstOrNull()
            val pickedCam2id = pick?.let {
                try {
                    androidx.camera.camera2.interop.Camera2CameraInfo.from(it).cameraId
                } catch (e: Exception) { "?" }
            } ?: "?"
            Timber.tag("StreamMetrics").i(
                "cameraSelectorPick cam2id=%s (multiCam=%b) pipeline=hevc",
                pickedCam2id, multiCam != null
            )
            listOfNotNull(pick)
        }
        .build()

    @Volatile private var sessionId: String = ""
    private val chunksEncrypted = AtomicInteger(0)
    // Chunks of this recording lost at capture. Written to the alerts in bulk
    // at the closure, and one by one for a loss that comes after it.
    @Volatile private var losses = org.stream.crypto.capture.CaptureLossLedger()
    // Chunks remis à l'écrivain et pas encore terminés (scellés ou abandonnés).
    // C'est la FIFO de l'écrivain qui ordonne la clôture après eux ; ce
    // compteur est ce que lit le contrôleur de verrouillage (via
    // encryptionsInFlightCounter) et ce qu'affiche la métrique snapshot.
    //
    // Ne jamais recompter les chunks uploadés avec un AtomicInteger incrémenté
    // à l'enqueue, comme le faisait `chunksUploaded` : scheduleUpload() reparcourt
    // la TOTALITÉ du pending à chaque chunk produit, donc pendant un wifi off
    // pending grandit et un tel compteur monte quadratiquement (vu in-vivo
    // 2026-05-10 : "280/281, up non-stop"). La valeur affichée doit rester
    // dérivée au moment du broadcast, depuis (encrypted - pendingCount)
    // (Phase 3.7).
    private val pendingChunks = AtomicInteger(0)

    /**
     * Names of the envelopes already passed to `WorkManager.enqueueUniqueWork`,
     * so `scheduleUpload` doesn't re-enqueue the whole queue every time a new
     * chunk is sealed.
     *
     * This set MUST be emptied on NetworkCallback recovery — the `onAvailable`
     * path calls `enqueuedEnvelopeNames.clear()`. Without that reset, a job
     * that has ended, or whose ENQUEUED state was just cancelled, can never be
     * re-enqueued from here.
     *
     * The set is not there for correctness : `ExistingWorkPolicy.KEEP` already
     * makes a re-enqueue a no-op on the WorkManager side. It is there for the
     * cost: each enqueue is an IPC roundtrip + a SQL hit on the WorkManager DB,
     * and walking a 200-envelope backlog on every 5 s chunk adds up on low-end
     * devices (Blue MED-4, Phase H2-B.15).
     *
     * Thread-safety : ConcurrentHashMap.newKeySet, accessed from the writer
     * thread (each sealed chunk) and from the NetworkCallback path.
     */
    private val enqueuedEnvelopeNames =
        java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    // Runs the auth upkeep (offline-start recovery, JWT refresh) that used to
    // ride on each chunk's encryption thread. Kept off the writer thread, which
    // must never wait on the network. One task at a time; a kick while one is
    // queued is dropped (the cooldowns make it redundant anyway).
    private val authExecutor = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS,
        java.util.concurrent.ArrayBlockingQueue(1),
        { r -> Thread(r, "recording-auth").apply { isDaemon = true } },
        java.util.concurrent.ThreadPoolExecutor.DiscardPolicy(),
    )

    // 2026-05-09 — retry initServerSession au network-up (cas : recording
    // démarré offline, wifi arrive plus tard). Cooldown 30s pour ne pas
    // épuiser le batch de clés éphémères : chaque authenticateV2() consomme
    // 1 slot/50 du batch courant.
    @Volatile private var lastAuthAttemptMs: Long = 0L
    private val AUTH_RETRY_COOLDOWN_MS = 30_000L
    // Never cache the bearer JWT here as a String field. It lives in a
    // Zeroizing holder inside Rust (stashed by verify()); a creation request
    // has Rust attach it from that holder. Keeping a copy "to save an FFI
    // roundtrip" puts the bearer back in the JVM heap and reopens the heap-dump
    // finding (§10.6, 2026-06-13). What this service keeps is
    // `authTokenIssuedAtMs` below : a non-secret "do we have an auth session"
    // signal (> 0L) plus refresh clock.
    //
    // There is no report creation call either: the report is opened locally
    // (Rust advances the report state, no network), and the relay creates its
    // record from the first envelope sent in creation mode. A recording begun
    // offline therefore has its report from the start.
    //
    // @Volatile is load-bearing on the auth-session signal: it is written on
    // the init thread and read from the notification refresher, the
    // NetworkCallback (binder pool) and the auth executor. A reader left on a
    // stale value simply never refreshes, with no exception and no crash
    // (Phase 3.36).

    // JWT refresh proactif. Le token V2 dure 24h côté serveur
    // (config.JWT_EXPIRE_HOURS = 24). On rafraîchit quand age > 23h pour
    // éviter qu'un worker qui run au-delà de 24h tape un 401 → fail → backoff.
    // Pour des sessions courtes (<23h, le cas pratique sur Seeker), aucun
    // refresh n'a lieu : le branchement est gratuit en l'absence d'expiration
    // proche.
    @Volatile private var authTokenIssuedAtMs: Long = 0L
    @Volatile private var lastRefreshAttemptMs: Long = 0L
    private val JWT_LIFETIME_MS = 24 * 60 * 60 * 1000L  // = config.JWT_EXPIRE_HOURS * 3600 * 1000
    private val JWT_REFRESH_THRESHOLD_MS = 60 * 60 * 1000L  // refresh à T-1h
    private val JWT_REFRESH_COOLDOWN_MS = 30_000L

    // Le NetworkCallback (voir [networkRegistration]) est déclenché par le
    // système au moment exact où une nouvelle network VALIDATED devient
    // disponible. Plus rapide que le polling à chaque chunk (5s) et beaucoup
    // plus léger en CPU. Le cooldown 30s sur maybeRetryAuth() est conservé
    // pour éviter de hammer auth si le réseau flap (wifi qui se connecte /
    // déconnecte vite).

    // Notification persistante format complet
    // (`Streaming... 12 chunks • 00:01:05`). recordingStartMs est posé quand
    // hevcRecorder.start() OK (premier instant où "le recording tourne
    // vraiment"). Le notificationRefresher tique toutes les 1s pour que le
    // timer affiché bouge même entre deux chunks (chunk = 5s).
    @Volatile private var recordingStartMs: Long = 0L
    // Set this flag when the teardown starts, BEFORE the `removeCallbacks()`
    // calls, and keep the `if (isDestroyed) return` at the top of every Handler
    // runnable. removeCallbacks looks sufficient on its own and is not : a
    // runnable already mid-`run()` when the teardown calls remove re-schedules
    // a NEW task with the postDelayed at the end of run(), one the prior
    // removeCallbacks didn't cover. That task keeps the stopping service's
    // runnable alive, logging stale snapshots and broadcasting stale HUD
    // counters from a dead session. Nothing crashes, no test turns red.
    //
    // The receiving side can't clean this up : the activity receiver has no
    // way to distinguish broadcasts by service generation, so this flag is
    // the only thing that stops a dead instance from talking. Signature to
    // look for in a field logcat, observed in-vivo 2026-05-15 : two
    // snapshots emitted 3s apart with different t= values (one from a
    // 7.5 min old zombie, one from the fresh service), and the HUD
    // flickering between "1↑/1" and "0↑/0" (Phase 3.47).
    @Volatile private var isDestroyed: Boolean = false
    private val notificationRefresher = Handler(Looper.getMainLooper())
    private val notificationRefreshTask = object : Runnable {
        override fun run() {
            if (isDestroyed) return
            refreshNotification()
            notificationRefresher.postDelayed(this, 1_000L)
        }
    }

    // Fallback "kick" timer that re-triggers scheduleUpload() every 30 s.
    // It is deliberate redundancy next to the event-driven NetworkCallback,
    // not polling to be removed : on a rapid wifi switch (box → hotspot) the
    // system may fire onAvailable in a state that the service misses
    // (NetworkCallback was unregistered for some reason, or the callback
    // thread was preempted). Without this timer, if both onAvailable events
    // are mis-handled, the queue stays full and the HUD freezes until the
    // user reopens the app — chunks that don't leave the device although the
    // network is back. Don't shorten the period either : 30 s is short
    // enough to feel responsive but long enough to never become the primary
    // upload driver, which is still onAvailable + onChunkReady scheduling
    // (Phase 3.23).
    //
    // The same tick also emits a structured `StreamMetrics snapshot` line,
    // so field captures have a periodic view of the upload pipeline state
    // even between chunk events. Filterable with
    // `adb logcat -s StreamMetrics:I` (Phase 3.33).
    private val uploadKicker = Handler(Looper.getMainLooper())
    private val uploadKickerTask = object : Runnable {
        override fun run() {
            if (isDestroyed) return  // Phase 3.47 — see notificationRefreshTask comment.
            try {
                if (recordingStartMs > 0L) {
                    // The whole queue, not only this session: an envelope needs
                    // neither the session nor a bearer to be scheduled.
                    val pending = envelopeQueue?.pendingCount() ?: 0
                    if (pending > 0 && isNetworkAvailable()) {
                        Timber.d("[Phase 3.23] kick — %d pending, reschedule", pending)
                        scheduleUpload()
                    }
                }
                emitSnapshotMetric()
            } catch (e: Exception) {
                Timber.w(e, "[Phase 3.23] uploadKicker iteration failed")
            }
            uploadKicker.postDelayed(this, 30_000L)
        }
    }

    // Ne pas retirer cette télémétrie appareil en la prenant pour du debug
    // oublié : c'est la seule instrumentation qui départage les deux causes
    // candidates du drop FPS observé sur Seeker (session 17:51→18:23 UTC :
    // ~9 min calé à 23.9 fps au lieu de 30, sans trigger applicatif — pas
    // qualityTransition, pas bitrateModeTransition, pas backlog). L'enquête
    // n'est pas close ; supprimer ce texte fait supprimer la mesure, et la
    // prochaine occurrence repart de zéro. Les deux hypothèses à départager
    // au prochain field test :
    //   H1 = thermal throttling SoC (PowerManager.currentThermalStatus
    //        monte LIGHT→MODERATE→SEVERE en cours de capture HEVC longue)
    //   H2 = Camera AE adaptive sensor framerate (AE_TARGET_FPS_RANGE
    //        descendu à [24,24] par Camera2 HAL pour exposition plus longue
    //        en scène sombre)
    // emitDeviceTelemetry n'émet exactement que ces deux grandeurs, une par
    // hypothèse. Tick toutes les 5 s pendant un recording (alignement
    // glFrameRate cadence). Cleanup symétrique au début de la fin de session
    // (requestStop, Phase H2-B.8).
    @Volatile private var lastAeFpsRange: android.util.Range<Int>? = null
    private val deviceTelemetryRefresher = Handler(Looper.getMainLooper())
    private val deviceTelemetryTask = object : Runnable {
        override fun run() {
            if (isDestroyed) return  // Phase 3.47 — anti-zombie pattern.
            try {
                if (recordingStartMs > 0L) {
                    emitDeviceTelemetry()
                }
            } catch (e: Exception) {
                Timber.tag("StreamMetrics").w(e, "deviceTelemetry iteration failed")
            }
            deviceTelemetryRefresher.postDelayed(this, 5_000L)
        }
    }

    /**
     * Fires on every camera frame produced (~30/s), so keep the body to the
     * single dictionary lookup + volatile write it does today : a Timber
     * call, a formatting or an allocation added here is paid 30 times a
     * second during HEVC capture, on exactly the low-end devices this
     * telemetry exists to observe.
     *
     * It deliberately logs nothing. We only store the latest
     * [CaptureResult.CONTROL_AE_TARGET_FPS_RANGE] in a volatile field — the
     * periodic [deviceTelemetryTask] is what actually emits the log. A silent
     * callback here is not a bug to fix, and that task is where to look when
     * tracing that log line back.
     *
     * Wired into the HEVC `Preview` use-case via `Camera2Interop.Extender`
     * (Phase H2-B.8, 2026-05-18).
     */
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private val aeFpsCaptureCallback =
        object : android.hardware.camera2.CameraCaptureSession.CaptureCallback() {
            override fun onCaptureCompleted(
                session: android.hardware.camera2.CameraCaptureSession,
                request: android.hardware.camera2.CaptureRequest,
                result: android.hardware.camera2.TotalCaptureResult
            ) {
                val r = result.get(
                    android.hardware.camera2.CaptureResult.CONTROL_AE_TARGET_FPS_RANGE
                )
                if (r != null) lastAeFpsRange = r
            }
        }

    /**
     * Emit thermal status + last observed AE FPS range.
     * Greppable as `deviceTelemetry`. Thermal status is the OS-wide
     * indication that the SoC is throttling (Android API 29+) ; AE FPS
     * range is the sensor framerate ceiling the camera HAL is currently
     * holding to (a [24,24] when we expect [30,30] is a smoking gun for
     * dark-scene AE throttling).
     */
    private fun emitDeviceTelemetry() {
        val thermal = try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
                thermalStatusName(pm.currentThermalStatus)
            } else {
                "API<29"
            }
        } catch (e: Exception) {
            "ERR:${e.javaClass.simpleName}"
        }
        val fps = lastAeFpsRange?.let { "${it.lower}..${it.upper}" } ?: "?"
        Timber.tag("StreamMetrics").i(
            "deviceTelemetry thermal=%s aeFpsRange=%s",
            thermal, fps
        )
    }

    private fun thermalStatusName(status: Int): String = when (status) {
        android.os.PowerManager.THERMAL_STATUS_NONE -> "NONE"
        android.os.PowerManager.THERMAL_STATUS_LIGHT -> "LIGHT"
        android.os.PowerManager.THERMAL_STATUS_MODERATE -> "MODERATE"
        android.os.PowerManager.THERMAL_STATUS_SEVERE -> "SEVERE"
        android.os.PowerManager.THERMAL_STATUS_CRITICAL -> "CRITICAL"
        android.os.PowerManager.THERMAL_STATUS_EMERGENCY -> "EMERGENCY"
        android.os.PowerManager.THERMAL_STATUS_SHUTDOWN -> "SHUTDOWN"
        else -> "UNKNOWN($status)"
    }

    /**
     * Periodic state snapshot for field analysis. Fires
     * every 30 s while a recording is active.
     */
    private fun emitSnapshotMetric() {
        if (recordingStartMs <= 0L) return
        try {
            val queue = envelopeQueue
            val pending = queue?.pendingChunksOfSession(sessionId) ?: -1
            val totalOnDisk = queue?.pendingCount() ?: -1
            val orphans = (totalOnDisk - pending).coerceAtLeast(0)
            val quality = org.stream.crypto.capture.AdaptiveQualityHolder
                .get()?.currentQuality?.displayLabel ?: "?"
            val cap = rs.readahead.washington.mobile.util.jobs
                .UploadConcurrencyLimiter.currentCap()
            val net = detectNetworkType()
            val elapsedSec = (System.currentTimeMillis() - recordingStartMs) / 1000
            Timber.tag("StreamMetrics").i(
                "snapshot t=%ds quality=%s cap=%d backlog=%d others=%d sealed=%d uploaded=%d lost=%d sealing=%d networkType=%s",
                elapsedSec, quality, cap, pending, orphans,
                chunksEncrypted.get(), lastChunksUploaded, losses.total, pendingChunks.get(), net,
            )
        } catch (e: Exception) {
            Timber.tag("StreamMetrics").w(e, "snapshot failed")
        }
    }

    /** Service-side network type detection (mirrored from
     *  [rs.readahead.washington.mobile.util.jobs.ChunkUploadWorker]).
     */
    private fun detectNetworkType(): String {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE)
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

    // Binder for the activity to obtain the service instance.
    inner class LocalBinder : Binder() {
        fun getService(): StreamRecordingService = this@StreamRecordingService
    }
    private val binder = LocalBinder()

    override fun onBind(intent: Intent?): IBinder = binder

    /**
     * Attach (or detach) the on-screen preview Surface used by the HEVC
     * pipeline. The activity must wire BOTH halves from its SurfaceView's
     * [android.view.SurfaceHolder.Callback] : `surfaceCreated` → pass the
     * Holder's Surface, `surfaceDestroyed` → pass null. Skipping the null on
     * destroy leaves the service able to forward a dead Surface to the GL
     * pipeline. A third caller replays the Surface held pending by the
     * activity when the service binds after `surfaceCreated` has fired.
     *
     * No ordering guard is needed on the caller's side. Calling this while no
     * recording is running is not a lost call : the value stays cached in the
     * field and is attached to the recorder at the next [startCamera]. Calling
     * it at any point during a recording is fine too. (Phase H2-B.3.)
     */
    fun setHevcPreviewSurface(surface: android.view.Surface?) {
        hevcPreviewSurface = surface
        hevcRecorder?.setPreviewSurface(surface)
    }

    override fun onCreate() {
        super.onCreate()
        Timber.d("StreamRecordingService created")
        lifecycleRegistry.currentState = Lifecycle.State.CREATED
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A stop request comes through startService (not stopService) so that
        // the closure is written while the service is still in the foreground.
        // It needs no startForeground: it was not sent with
        // startForegroundService.
        if (intent?.action == ACTION_STOP) {
            if (sessionClaim.get()) {
                requestStop("user")
            } else {
                stopSelf()
            }
            return START_NOT_STICKY
        }

        // CRITIQUE — Bug 2026-05-09 reproduit sur appareil :
        // ForegroundServiceDidNotStartInTimeException kill le process si
        // startForeground() n'est pas appelé < 5s après startForegroundService().
        // Hardening : startForeground EN PREMIER, avant TOUT autre init.
        // Aucun appel JNI / IO / réseau / DB avant (le wake lock est pris plus
        // bas, après startForeground). Tout le reste va dans
        // un Thread bg qui ne peut pas faire planter le main thread. Ceci vaut
        // aussi pour une commande de démarrage ignorée plus bas : chaque
        // startForegroundService exige son startForeground.

        // 1. Notification minimale safe — fallback si buildNotification throw
        //    (canal pas encore créé, ressource manquante, etc.)
        val notification = try {
            buildNotification("Starting stream...")
        } catch (e: Exception) {
            Timber.e(e, "buildNotification failed, using fallback")
            androidx.core.app.NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Frappuccino")
                .setContentText("Streaming…")
                .setSmallIcon(android.R.drawable.ic_menu_camera)
                .setOngoing(true)
                .build()
        }

        // 2. startForeground synchrone, en premier, avec try/catch.
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            // Si startForeground throw lui-même (ForegroundServiceStartNotAllowed
            // sur Android 12+ par exemple), on ne peut rien faire de plus —
            // mieux vaut stopSelf cleanly que laisser le process être killed.
            Timber.e(e, "startForeground threw — stopping service")
            if (!sessionClaim.get()) stopSelf()
            return START_NOT_STICKY
        }

        // Single-flight: a second start while a session (or its teardown)
        // holds the process is ignored. Never stopSelf here: that would end
        // the session that is running.
        if (!sessionClaim.compareAndSet(false, true)) {
            Timber.w("start command ignored: a recording session is already active")
            return START_STICKY
        }
        ownsSession = true

        // The wake lock is taken here, on the main thread, and released by
        // finishTeardown on the same thread: a stop that arrives before the
        // init thread has run can no longer release it first and leave the
        // init thread to take it for hours afterwards.
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "frappuccino:stream").apply {
                setReferenceCounted(false)
                acquire(4 * 60 * 60 * 1000L)
            }
        } catch (e: Exception) {
            Timber.w(e, "wake lock not taken")
        }

        // Mark the session running so the workers leave authentication to it.
        isRunning = true
        // Defensive clear: a previous instance clears it at the end of its
        // teardown, which this claim waited for.
        isShuttingDown = false
        // Fresh session : drop any stray in-flight count a prior crashed
        // instance might have left non-zero.
        encryptionsInFlightCounter.set(0)
        stopRequested.set(false)
        acceptingChunks = true

        Timber.d("StreamRecordingService — startForeground OK at %d", System.currentTimeMillis())

        // 3. Tout le reste de l'init dans un Thread bg avec try/catch global.
        //    Si quoi que ce soit throw, on log + on arrête proprement (la
        //    même fin de session qu'un stop utilisateur) — pas de
        //    propagation d'exception qui kill le process.
        Thread {
            try {
                initializePipelineFromOnStart()
            } catch (e: Exception) {
                Timber.e(e, "Pipeline init failed — stopping service")
                requestStop("init")
            } finally {
                // Whatever happened, the teardown must not wait for an opening
                // that will never come.
                openingDone.countDown()
            }
        }.start()

        return START_STICKY
    }

    /**
     * Sépare le pipeline init lourd (ouverture du rapport, server auth, camera
     * bind) du onStartCommand. Appelé depuis un Thread bg pour ne jamais
     * bloquer le main thread > 5s (qui ferait crasher le process avec
     * ForegroundServiceDidNotStartInTimeException).
     *
     * Le rapport est ouvert AVANT la caméra : son entrée d'annuaire et ses
     * métadonnées (seq 0) sont scellées d'abord, et un échec arrête tout,
     * caméra jamais démarrée. L'index ouvert est alors perdu, ce que le
     * secours tolère (un trou dans la suite des index).
     */
    private fun initializePipelineFromOnStart() {
        // Opening a report reads the report state, sealed under the PIN-session
        // key: the device must be unlocked.
        val uploadManager = StreamUploadManager.getInstance()
        if (uploadManager == null || !uploadManager.isUnlocked()) {
            Timber.e("StreamUploadManager not unlocked — cannot stream")
            requestStop("locked")
            return
        }

        sessionId = generateSessionId()
        wipeGenerationAtStart = StreamUploadManager.wipeGeneration()

        // Re-arm QUIC for this recording. A previous session that hit a
        // UDP-blocked network latched the transport to DirectTls so its
        // remaining chunks would not each re-pay the connect timeout; that latch
        // otherwise survives until the next lock or auth clear, which can be
        // several recordings away. Since the obfuscation protects the data plane,
        // staying latched needlessly re-exposes the direct-IP signal for the
        // whole session.
        //
        // This call is the whole reason the latch clears at all: it used to be a
        // side effect of `uploadCreateReport`, which lost its last caller when
        // report creation became lazy, so the re-arm stopped firing without
        // anything failing. Do not fold it back into another call for tidiness.
        // It is idempotent and cannot throw.
        uniffi.frappuccino.uploadTransportRearm()

        val queue = EnvelopeQueue.get(this)
        envelopeQueue = queue

        // No report can be opened before the report state exists. A device
        // updated from the legacy scheme gets it from the migration, normally
        // run right after the unlock; if this recording came first, only the
        // migration's first steps (the state) run here, and its conversions go
        // on in the background (LegacyMigrationWorker).
        if (!uploadManager.hasReportState() && uploadManager.needsLegacyMigration()) {
            LegacyMigrationWorker.ensureStateBlocking(this)
            LegacyMigrationWorker.start(this)
        }
        if (!uploadManager.hasReportState()) {
            Timber.e("no report state — cannot open a report, stopping")
            requestStop("no_state")
            return
        }
        if (!QueueKeyStore.ensureInstalled(this)) {
            Timber.e("no queue key — no envelope can be written, stopping")
            requestStop("no_queue_key")
            return
        }
        // A stop that came meanwhile (during the migration, say): open no
        // report for it, which would spend an index and leave an empty report.
        if (stopRequested.get()) return

        // Reset les compteurs statiques pour que l'UI ne montre
        // pas des valeurs périmées d'une session précédente. Avant
        // l'ouverture du rapport : dès qu'il est publié, le démontage peut
        // les lire.
        chunksEncrypted.set(0)
        losses = org.stream.crypto.capture.CaptureLossLedger()
        resetCounters()

        // Open the report: Rust advances the state durably, then hands back
        // the writer. Its directory entry and its metadata are sealed before
        // the camera starts.
        val writer = try {
            uploadManager.openReportWriter()
        } catch (e: uniffi.frappuccino.FfiException.WriterBusy) {
            Timber.e("a report writer is already live in this process, stopping")
            requestStop("writer_busy")
            return
        }
        val p = ReportProducer(writer, queue, sessionId) { QueueKeyStore.ensureInstalled(this) }
        try {
            p.open(buildSessionMetadata().toByteArray(Charsets.UTF_8))
        } catch (e: Exception) {
            Timber.e(e, "report opening failed — recording not started")
            requestStop("open_failed")
            return
        }
        // Published even if the stop came while the report was being opened:
        // the teardown waits for [openingDone] before it looks for the report,
        // so it is the one that closes it, in the foreground and under the
        // wake lock. Nothing more starts after a stop: no camera, no auth.
        synchronized(lifecycleLock) { producer = p }
        openingDone.countDown()
        if (stopRequested.get()) return
        Timber.i("report opened for this session")

        // Transport plan, ROADMAP §10.9 Gate 0 — start the
        // per-session upload counters and log the active TCP congestion
        // control. Logging-only, no behaviour change.
        rs.readahead.washington.mobile.util.jobs.UploadSessionStats
            .startSession(sessionId)

        // Start each session with a clean rolling window
        // for the adaptive concurrency cap, so the first adjustment
        // decision is taken on fresh samples. This does NOT re-arm the
        // cap itself : `activeCap` is process-local singleton state that
        // outlives the session (one that ended at cap = 1 restarts at
        // cap = 1). What re-arms the cap in one step is
        // UploadConcurrencyLimiter.bumpCapForRecovery(), called from
        // NetworkCallback.onAvailable ; the same class's maybeAdjustCap() also
        // grows the cap, but one notch at a time and only once fresh
        // successful uploads have filled its sample window.
        rs.readahead.washington.mobile.util.jobs
            .UploadConcurrencyLimiter.resetSamples()

        // §10.11 — capture une fois si cet enregistrement est tracké pour la
        // provenance (toggle ON + signer chargé au unlock). L'engagement de fin
        // est gaté sur ce snapshot, donc le périmètre reste cohérent même si le
        // toggle change pendant l'enregistrement.
        provenanceActive = StreamPreferences.isProvenanceEnabled(this) &&
            uploadManager.provenanceSigner != null
        if (provenanceActive) Timber.d("Provenance tracking active for this session")

        // The two opening envelopes go to the queue now; neither needs the
        // network to be sealed, and both are sent whenever it comes.
        scheduleEnvelope(p.directoryEntryFile)
        scheduleEnvelope(p.metadataFile)

        // Auth (network, ~1-3s), puis start camera sur main thread. The auth
        // only serves the creation requests (report and directory); nothing
        // waits for it to start recording.
        initServerSession()

        // Ne jamais remonter cet appel au-dessus de initServerSession() : le
        // système fire `onAvailable` à la registration si une network VALIDATED
        // est déjà dispo, et la version AVANT créait une race avec l'auth en
        // cours : les deux initServerSession() concurrents consommaient 2
        // slots/50 du batch ephemeral au lieu d'1, validé in-vivo 2026-05-09.
        // C'est une race mesurée sur device, pas une crainte théorique.
        // L'ordre choisi est sûr dans les deux branches, et le démarrage
        // hors-ligne doit continuer de marcher :
        // - Cas en ligne (commun) : auth OK, callback registered ; callback
        //   fire onAvailable mais maybeRetryAuth() return early grâce au guard
        //   à trois termes `authTokenIssuedAtMs > 0L && producer != null &&
        //   UploadAuthHolder.isPresent()`.
        // - Cas offline : auth retourne sans token (catch dans
        //   initServerSession), callback registered ; quand réseau revient,
        //   callback fire onAvailable, maybeRetryAuth() voit
        //   `authTokenIssuedAtMs == 0L` (l'horloge n'est posée qu'au succès de
        //   l'auth), passe le cooldown (jamais set), retry → succès.
        // (Phase 2.4.2.)
        // L'auth ci-dessus peut durer plusieurs secondes : un arrêt arrivé
        // pendant ce temps a déjà désenregistré le callback, qui n'est donc
        // plus enregistré (sinon il survivrait à la session, ré-authentifiant
        // à chaque changement de réseau).
        registerNetworkCallback()
        if (stopRequested.get()) return
        android.os.Handler(Looper.getMainLooper()).post {
            if (stopRequested.get()) return@post
            try {
                lifecycleRegistry.currentState = Lifecycle.State.STARTED
                lifecycleRegistry.currentState = Lifecycle.State.RESUMED
                startCamera()
            } catch (e: Exception) {
                Timber.e(e, "startCamera failed on main thread")
                requestStop("camera")
            }
        }
    }

    // Opt-in for Camera2Interop.Extender used
    // in the HEVC PreviewBuilder branch to attach a SessionCaptureCallback
    // for AE_TARGET_FPS_RANGE observation. The existing per-field @OptIn
    // pattern (on `cameraSelectorHevc` and `aeFpsCaptureCallback`) covers
    // compile-time properties ; since the Extender mutation happens inside
    // this function's body we need to opt-in at the function level too.
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private fun startCamera() {
        Timber.d("[Phase 7.12] startCamera entered at %d", System.currentTimeMillis())
        // Ne jamais déplacer ce purge plus loin dans l'init, ni le rejouer
        // depuis un point de reprise : purgeOrphanChunks secure-delete TOUT MP4
        // du répertoire de chunks, quelle que soit sa taille, et il n'est
        // inoffensif ici que parce que la caméra n'est pas encore bindée, donc
        // aucun chunk live n'existe à racer. Appelé pendant une capture, il
        // efface le chunk en cours d'écriture (le contrat d'appel formel, avec
        // exceptCurrentPaths, est énoncé côté CaptureScratchCleaner). Ce qui est
        // nettoyé ici : les MP4 orphelins laissés par une mort anormale d'une
        // session passée, toute taille (Phase H2-B.11, F-01 cross-audit
        // 2026-06-30).
        //
        // Le purge des orphelins est SYNCHRONE parce que borné (≤ quelques
        // fichiers) ; celui de debug_raw part sur un Thread bg parce qu'il peut
        // être long (potentiellement nombreux fichiers, ~50-200ms chacun), et
        // bloquer ici c'est manquer la 5 s deadline ForegroundService, que le
        // système punit en tuant le process. Ne pas « harmoniser » les deux en
        // synchrone.
        try {
            org.stream.crypto.capture.CaptureScratchCleaner.purgeOrphanChunks(
                org.stream.crypto.capture.CaptureScratchCleaner.defaultChunkDir(this)
            )
        } catch (e: Exception) {
            Timber.w(e, "CaptureScratchCleaner.purgeOrphanChunks failed at service start")
        }
        Thread({
            try {
                org.stream.crypto.capture.CaptureScratchCleaner.purgeDebugRaw(this)
            } catch (e: Exception) {
                Timber.w(e, "CaptureScratchCleaner.purgeDebugRaw failed at service start")
            }
        }, "scratch-cleaner").start()
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            // A stop that came while CameraX was initialising: build nothing.
            // The stops that can land here all run on this (main) thread, so
            // none can come between this check and the recorder's construction.
            if (stopRequested.get()) return@addListener
            try {
                val cameraProvider = cameraProviderFuture.get()
                Timber.d("[Phase 7.12] cameraProvider ready at %d", System.currentTimeMillis())

                // Diagnostic (multi-cam FOV follow-up, 2026-05-18) — log
                // every physical sub-camera the device exposes plus its
                // focal length and physical sensor size, so we can map
                // CameraX's "logical" selection back to the device's
                // physical lens stack and decide which sub-camera to bind
                // explicitly (the OEM camera app picks main, CameraX
                // default-selects the logical wrapper).
                try {
                    logPhysicalCameras()
                } catch (e: Exception) {
                    Timber.w(e, "physical camera enumeration failed")
                }
                try {
                    logCameraXInfos(cameraProvider)
                } catch (e: Exception) {
                    Timber.w(e, "CameraX info enumeration failed")
                }

                // Debug calibration (2026-05-16) : when the fixed-bitrate
                // toggle is on, start at the operator-pinned resolution
                // (HD or SD) instead of the HD default.
                val initialQuality = resolveInitialQuality()
                val debugForced = org.stream.crypto.StreamPreferences
                    .isDebugBitrateEnabled(this)

                // Preview use-case avec SurfaceProvider
                // toujours valide. CameraX exige un Preview bind sur la
                // plupart des devices (sinon la caméra peut refuser
                // silencieusement de produire des frames).
                //
                // The HAL does NOT crop the 4:3 sensor down to a clean 16:9
                // buffer, it ANAMORPHICALLY SQUISHES 4:3→16:9, baking a ~1.33×
                // horizontal compression into the buffer itself, UPSTREAM of
                // GL. No GL scaling can undo a pre-squished buffer — this is
                // the "unexplained fudge" H2-B.3 chased (the camera reported
                // 1280×720 but the pixels were a squished 4:3 FOV), and it is
                // why the vertical correction below is not the identity. The
                // rear cam is 4:3-native (Seeker ~1600×1200, OnePlus likewise) ;
                // field measurement 2026-05-24 (decoded a debug_raw chunk: a
                // real 16:9 laptop screen came out ~4:3) is what proved it
                // (Phase H2-B.21).
                //
                // H2-B.21's first answer — request RATIO_4_3 so the HAL
                // delivers its native square-pixel frame, then let the
                // Phase H2-B.20 letterbox FIT that 4:3 (rotated to 3:4
                // portrait) into the 9:16 viewport with black bars top/bottom
                // — is NOT what ships. What belongs to a diagnostic mode is the
                // RATIO_4_3 request, not the letterbox : the fit is the shipped
                // geometry, on every aspect mode and on both passes (it is the
                // body of GlVideoPipeline.drawFullscreenQuad), and it carries
                // its own "never go back to a hand-tuned scale factor" there.
                // The shipped path (debug aspect mode 4 = F, the default)
                // requests 16:9 and corrects in GL with a vscale DERIVED from
                // the negotiated dimensions, so don't go back to a hand-tuned
                // constant either : see
                // buildHevcPreview() and GlVideoPipeline.DERIVE_VSCALE.
                //
                // GL aspect globals are a one-time startCamera concern (sticky
                // GlVideoPipeline companion fields). Set them here from the debug
                // aspect mode (0=A 4:3  1=B 16:9  2=D 4:3  3=E 16:9  4=F 16:9
                // shipped default) ; the Preview itself is built by the shared
                // buildHevcPreview() helper, which is the single Preview
                // construction path — an adaptive quality swap rebinds nothing
                // at all (applyQualityHevc swaps the encoder in place), so the
                // two can never drift. Keep it that way : the divergence
                // between two Preview construction paths is the H2-B §Bugs #5
                // FOV-zoom bug class.
                run {
                    val aspectMode = org.stream.crypto.StreamPreferences
                        .getDebugAspectMode(this)
                    val deriveVScale = aspectMode == 4
                    val wantIdentityGl = aspectMode == 1 || aspectMode == 2
                    org.stream.crypto.capture.GlVideoPipeline.ANAMORPHIC_VSCALE =
                        if (wantIdentityGl) 1.0f else 0.75f
                    org.stream.crypto.capture.GlVideoPipeline.ZOOM_IN =
                        if (wantIdentityGl || deriveVScale) 1.0f else 1.2f
                    org.stream.crypto.capture.GlVideoPipeline.DERIVE_VSCALE = deriveVScale
                }
                val preview = buildHevcPreview(buildHevcVideoConfigFor(initialQuality))

                run {
                    // No separate video-capture use case is bound, and none
                    // should be added — nor a second Preview for the on-screen
                    // display. The camera only feeds the Preview, and we route
                    // Preview's surface provider to the recorder's
                    // SurfaceTexture ; drawing the on-screen preview from GL
                    // rather than from a use case of its own is what buys the
                    // WYSIWYG framing (see GlVideoPipeline's
                    // setPreviewOutputSurface).
                    //
                    // The RollingChunkRecorder owns a permanent GL pipeline
                    // whose SurfaceTexture is what the camera writes into ; the
                    // GL pipeline then renders onto per-chunk MediaCodec input
                    // Surfaces. The on-screen preview (B.3) is the SurfaceView
                    // Surface forwarded via setHevcPreviewSurface — not a second
                    // camera output, but a second GL draw : the pipeline draws
                    // each frame from the same OES texture onto BOTH the encoder
                    // input Surface and that preview Surface (when present).
                    // (Phase H2-B.7, HEVC/MediaCodec/GL-wedge pipeline.)
                    val chunkDir = java.io.File(cacheDir, "stream_chunks").also { it.mkdirs() }
                    val initialConfig = buildHevcVideoConfigFor(initialQuality)
                    Timber.tag("StreamMetrics").i(
                        "hevcPipelineMime chosen=%s", initialConfig.mime
                    )
                    val rec = RollingChunkRecorder(
                        chunkDir = chunkDir,
                        chunkIntervalMs = DEFAULT_CHUNK_INTERVAL_MS,
                        preallocLeadMs = 500L,
                        initialVideoConfig = initialConfig,
                        audioConfig = ChunkEncoderBundle.AudioConfig(),
                        // Native portrait encoding (B.4) — never change this
                        // constant without first reading the
                        // `rotationCrosscheck` log on the device concerned
                        // (emitted at bind time : cam2id, sensorOrientation,
                        // displayRotation, facing, expected angle). The MP4
                        // orientation hint stays 0 because the GL pipeline
                        // samples the buffer in the target orientation already
                        // (via Mediatek's stMatrix reflection on Seeker), so a
                        // non-zero hint would rotate the picture a SECOND time
                        // — and only at playback, the hint being container
                        // metadata handed to MediaMuxer.setOrientationHint,
                        // which the on-device GL preview never goes through.
                        // That is a per-SoC property, not a law : if a device's
                        // stMatrix doesn't include the rotation, a non-zero
                        // hint here + an MVP rotation in GL would be the fix.
                        // The crosscheck was wired for exactly that decision
                        // (Phase H2-B.7-bis).
                        orientationHintDegrees = 0,
                        // The recorder's seq is the report's capture number:
                        // unique and increasing for the whole session, because
                        // this is the session's only recorder. A quality change
                        // and the HEVC → H.264 fallback both swap the encoder
                        // inside it (swapVideoConfig) and keep its counter;
                        // nothing creates a second recorder for the same
                        // session. If something ever does, it must continue the
                        // numbering, never restart it: the writer refuses a seq
                        // it already sealed.
                        onChunkReady = { chunkFile, seqNum ->
                            onChunkReady(chunkFile, seqNum)
                        },
                        onError = { e ->
                            if (e is org.stream.crypto.capture.CaptureUnrecoverableException) {
                                // Fail-closed backstop (#2/N1): the capture pipeline
                                // can't recover (rotation failed MAX_ROTATION_FAILURES
                                // times). Stop cleanly — requestStop() runs
                                // hevcRecorder.stop(), which finalizes the in-flight
                                // clear chunk (sealed via onChunkReady) instead of
                                // letting it grow unbounded, then closes the report,
                                // and tells the operator. Same clean path as a user
                                // stop / the device-storage-critical stop.
                                Timber.e(e, "[Phase H2-B.7] HEVC pipeline unrecoverable — stopping capture cleanly")
                                android.os.Handler(Looper.getMainLooper()).post {
                                    if (!isShuttingDown) {
                                        try {
                                            updateNotification("Erreur caméra — enregistrement arrêté (données sauvegardées)")
                                        } catch (_: Exception) { }
                                        requestStop("capture")
                                    }
                                }
                            } else {
                                Timber.e(e, "[Phase H2-B.7] HEVC pipeline error")
                            }
                        },
                    )
                    // Under the lock: the teardown reads it under the same one.
                    synchronized(lifecycleLock) { hevcRecorder = rec }
                    // Wire the on-screen preview Surface
                    // if the activity already pushed one before service
                    // started. setPreviewSurface stores the ref ; the
                    // recorder's start() will forward it to GL.
                    hevcPreviewSurface?.let { rec.setPreviewSurface(it) }
                    // Wire the camera→GL surface + the source-transform listener
                    // via the shared helper. Since the move to an in-place
                    // encoder swap, its only caller is this initial bind : a
                    // quality change (applyQualityHevc →
                    // RollingChunkRecorder.swapVideoConfig) rebinds no camera
                    // and re-wires no SurfaceProvider.
                    wireHevcSurfaceProvider(preview, rec.cameraSurfaceTexture())
                }

                cameraProvider.unbindAll()
                run {
                    val camera = cameraProvider.bindToLifecycle(
                        this, cameraSelectorHevc, preview
                    )
                    // Multi-cam ultra-wide FOV match + rotation crosscheck. The
                    // zoom set here holds for the whole session : a quality
                    // change swaps the encoder in place, with no camera rebind,
                    // so nothing resets it to 1.0× (H2-B §Bugs #5).
                    applyHevcCameraConfig(camera)
                    // Logging only: what the camera does after the bind, and
                    // whether the AE range we ask for is one it offers.
                    logCameraStateAndAeRanges(camera)
                }

                // Promote the refs so applyQuality() has a
                // readiness signal : their non-nullity attests that the
                // initial startCamera bind ran.
                cameraProviderRef = cameraProvider
                previewRef = preview

                // The onQualityChange callback may fire from the upload worker
                // thread (WorkManager), and CameraX requires the main thread.
                // The hop back is made inside [applyQuality], not at this
                // install site, so a callback added here must not assume it
                // already runs on the main thread.
                //
                // Debug calibration (2026-05-16) : if the toggle is on,
                // create the manager in `forced` mode so adaptive
                // transitions don't fight the operator's pinned values —
                // that toggle is the only thing that still forces.
                // (Phase 3-C, Phase H2-B.5.)
                val forcedMode = debugForced
                // Phase H2-B adaptive VBR↔CBR (2026-05-17). `KEY_BITRATE_MODE`
                // is config-time only on MediaCodec : the mode cannot be
                // flipped on a live encoder. That is why the manager goes
                // through this callback, which triggers a config swap at the
                // current quality (a full encoder rebuild).
                val onBitrateModeChangeCb: ((
                    org.stream.crypto.capture.ChunkEncoderBundle.BitrateMode
                ) -> Unit)? = { newMode ->
                    Timber.i(
                        "[Phase H2-B] adaptive bitrate mode change: %s",
                        newMode.name
                    )
                    currentHevcBitrateMode = newMode
                    // Trigger a config swap with the current quality
                    // but the new mode in effect. applyQuality reads
                    // currentHevcBitrateMode via buildHevcVideoConfigFor,
                    // so passing the in-flight quality is enough.
                    val q = org.stream.crypto.capture
                        .AdaptiveQualityHolder.get()?.currentQuality
                        ?: initialQuality
                    applyQuality(q)
                }
                org.stream.crypto.capture.AdaptiveQualityHolder.set(
                    org.stream.crypto.capture.AdaptiveQualityManager(
                        chunkIntervalMs = DEFAULT_CHUNK_INTERVAL_MS,
                        initialQuality = initialQuality,
                        onQualityChange = { newQuality ->
                            Timber.i(
                                "[Phase 3-C] adaptive quality change: %s",
                                newQuality.displayLabel
                            )
                            applyQuality(newQuality)
                            broadcastQualityUpdate(newQuality)
                        },
                        forced = forcedMode,
                        onBitrateModeChange = onBitrateModeChangeCb,
                        // Honour the user's max-quality cap in
                        // production. Debug calibration ignores it (FHD = no
                        // cap) since the operator pins resolution explicitly.
                        maxQuality = if (debugForced) {
                            org.stream.crypto.capture.StreamQuality.FHD
                        } else {
                            org.stream.crypto.StreamPreferences.getMaxQualityCap(this)
                        },
                    )
                )

                if (debugForced) {
                    val kbps = org.stream.crypto.StreamPreferences
                        .getDebugBitrateKbps(this)
                    Timber.tag("StreamMetrics").i(
                        "debugBitrate enabled quality=%s kbps=%d",
                        initialQuality.displayLabel, kbps
                    )
                }
                Timber.tag("StreamMetrics").i(
                    "hevcPipelineEnabled quality=%s",
                    initialQuality.displayLabel
                )

                // Broadcast initial quality so the HUD picks
                // it up even without a quality change.
                broadcastQualityUpdate(initialQuality)

                val started = synchronized(lifecycleLock) {
                    if (stopRequested.get()) false else {
                        hevcRecorder?.start()
                        true
                    }
                }
                if (!started) {
                    Timber.w("stop requested before the recorder started")
                    releaseUnstartedRecorder()
                    return@addListener
                }

                // Démarrage du timer + refresher notification.
                // Le timer démarre ici (et pas plus tôt) pour ne pas compter
                // le temps de boot caméra dans la durée d'enregistrement
                // affichée à l'user.
                recordingStartMs = System.currentTimeMillis()
                notificationRefresher.removeCallbacks(notificationRefreshTask)
                notificationRefresher.post(notificationRefreshTask)
                // Fallback kick timer.
                uploadKicker.removeCallbacks(uploadKickerTask)
                uploadKicker.postDelayed(uploadKickerTask, 30_000L)
                // Device telemetry (thermal + AE FPS).
                // Start delayed by 5 s : the AE callback needs a few
                // captures before lastAeFpsRange is populated, so the
                // very first tick at t=5 s already has a real value
                // instead of `?`.
                deviceTelemetryRefresher.removeCallbacks(deviceTelemetryTask)
                deviceTelemetryRefresher.postDelayed(deviceTelemetryTask, 5_000L)

                Timber.d("Camera started, chunks rotating every %dms", DEFAULT_CHUNK_INTERVAL_MS)
                Timber.d("[Phase 7.12] chunk rotation started at %d", System.currentTimeMillis())

            } catch (e: Exception) {
                Timber.e(e, "Failed to start camera")
                // A recorder built before the failure (bindToLifecycle threw,
                // say) never started: its stop() would do nothing for it.
                releaseUnstartedRecorder()
                requestStop("camera")
            }
        }, ContextCompat.getMainExecutor(this))
    }

    /**
     * Free a recorder that was built but never started, and forget it: its
     * constructor already holds a GL thread, an EGL context and the first
     * chunk's encoders. Does nothing for a recorder that started (the
     * teardown stops it), nor when there is none.
     */
    private fun releaseUnstartedRecorder() {
        val rec = synchronized(lifecycleLock) { hevcRecorder } ?: return
        try {
            if (rec.release()) synchronized(lifecycleLock) { if (hevcRecorder === rec) hevcRecorder = null }
        } catch (e: Exception) {
            Timber.w(e, "unstarted recorder release failed")
        }
    }

    /**
     * Mirrors a finalized chunk MP4 to `filesDir/debug_raw/` when fixed-bitrate
     * mode is on. Called from [onChunkReady], the single converging point where
     * the HEVC [RollingChunkRecorder] delivers each finalized chunk — that is
     * where anything needing every chunk gets hooked in.
     */
    private fun saveRawDebugCopyIfEnabled(chunkFile: File, seqNum: Int) {
        // Defense-in-depth (audit R-E-1): the debug-bitrate toggle is only
        // settable from the DEBUG settings section, now gated to debug builds —
        // but also refuse the plaintext write here via the build-gate, which
        // reads android:debuggable at runtime (tamper-resistant vs BuildConfig).
        // In a release build this is always false → no plaintext MP4 ever hits
        // filesDir/debug_raw, even if the pref were somehow set.
        if (!org.stream.crypto.capture.CaptureScratchCleaner.debugRawAllowed(this)) return
        if (!org.stream.crypto.StreamPreferences.isDebugBitrateEnabled(this)) return
        try {
            val quality = org.stream.crypto.StreamPreferences.getDebugBitrateQuality(this)
            val resolutionLabel = if (quality == "SD") "480p" else "720p"
            val kbps = org.stream.crypto.StreamPreferences.getDebugBitrateKbps(this)
            val timestamp = java.text.SimpleDateFormat("HHmmss", java.util.Locale.US)
                .format(java.util.Date())
            val dir = java.io.File(filesDir, "debug_raw").also { it.mkdirs() }
            val name = "$resolutionLabel-${kbps}kbps-$timestamp-seq$seqNum.mp4"
            val dest = java.io.File(dir, name)
            chunkFile.copyTo(dest, overwrite = true)
            Timber.tag("StreamMetrics").i(
                "debugRawSaved file=%s sizeBytes=%d", name, dest.length()
            )
        } catch (e: Exception) {
            Timber.w(e, "debug raw copy failed for chunk #%d", seqNum)
        }
    }

    /**
     * Diagnostic for field FOV mismatches: on a phone with several back lenses
     * (main + ultra-wide + tele), CameraX may pick a different sub-camera than
     * the OEM camera app, producing a visibly different FOV in the preview. These
     * `physCam` lines are what maps CameraX's logical selection back to the
     * device's physical lens stack.
     *
     * Enumerates every camera and sub-camera exposed by
     * [android.hardware.camera2.CameraManager], dumping focal length, physical
     * sensor size and lens facing on the StreamMetrics tag. `cameraIdList` does
     * not show the sub-cameras of a multi-physical logical camera, hence the
     * extra pass over `getPhysicalCameraIds()` — without it the enumeration only
     * looks exhaustive.
     */
    private fun logPhysicalCameras() {
        val cm = getSystemService(android.content.Context.CAMERA_SERVICE)
            as android.hardware.camera2.CameraManager
        val ids = cm.cameraIdList
        Timber.tag("StreamMetrics").i("physCamList ids=%s", ids.joinToString(","))
        // Track the physical IDs we discover via getPhysicalCameraIds()
        // (sub-cameras hidden from cameraIdList).
        val allIds = linkedSetOf<String>()
        allIds.addAll(ids.toList())
        for (id in ids) {
            try {
                val chars = cm.getCameraCharacteristics(id)
                val physIds = chars.physicalCameraIds // requires API 28+, our minSdk >=24
                if (physIds.isNotEmpty()) {
                    Timber.tag("StreamMetrics").i(
                        "physCamLogical id=%s subIds=%s", id, physIds.joinToString(",")
                    )
                    allIds.addAll(physIds)
                }
            } catch (e: Exception) {
                Timber.w(e, "physCam : characteristics failed for id=%s", id)
            }
        }
        for (id in allIds) {
            try {
                val chars = cm.getCameraCharacteristics(id)
                val facing = chars.get(
                    android.hardware.camera2.CameraCharacteristics.LENS_FACING
                )
                val facingStr = when (facing) {
                    android.hardware.camera2.CameraCharacteristics.LENS_FACING_BACK -> "BACK"
                    android.hardware.camera2.CameraCharacteristics.LENS_FACING_FRONT -> "FRONT"
                    android.hardware.camera2.CameraCharacteristics.LENS_FACING_EXTERNAL -> "EXTERNAL"
                    else -> "?"
                }
                val focalLengths = chars.get(
                    android.hardware.camera2.CameraCharacteristics
                        .LENS_INFO_AVAILABLE_FOCAL_LENGTHS
                ) ?: floatArrayOf()
                val sensorSize = chars.get(
                    android.hardware.camera2.CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE
                )
                val focalMm = focalLengths.firstOrNull() ?: -1f
                val sw = sensorSize?.width ?: -1f
                val sh = sensorSize?.height ?: -1f
                // 35mm full-frame diagonal = 43.27mm. Equivalent focal =
                // focal × (35mmDiag / sensorDiag).
                val sensorDiag = kotlin.math.sqrt(sw * sw + sh * sh).coerceAtLeast(0.01f)
                val equiv35mm = focalMm * 43.27f / sensorDiag
                // Horizontal FOV = 2 × atan(sensorW / (2 × focal)), in degrees.
                val fovHorizDeg =
                    if (focalMm > 0f && sw > 0f) {
                        Math.toDegrees(
                            (2.0 * kotlin.math.atan(sw / (2.0 * focalMm))).toDouble()
                        ).toFloat()
                    } else -1f
                Timber.tag("StreamMetrics").i(
                    "physCam id=%s facing=%s focalMm=%.2f sensorMm=%.2fx%.2f equiv35mm~%.1fmm fov~%.1f°",
                    id, facingStr, focalMm, sw, sh, equiv35mm, fovHorizDeg
                )
            } catch (e: Exception) {
                Timber.w(e, "physCam : enum failed for id=%s", id)
            }
        }
    }

    /**
     * Multi-camera diagnostic (2026-05-18) — log every [CameraInfo] CameraX
     * exposes via [ProcessCameraProvider.getAvailableCameraInfos], paired
     * with its underlying Camera2 cameraId (so we can cross-reference with
     * [logPhysicalCameras]). On phones with multiple BACK cameras CameraX
     * filters its public list to the "logical" cameras only ; this is the
     * stack our [CameraSelector] picks from.
     */
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private fun logCameraXInfos(
        provider: androidx.camera.lifecycle.ProcessCameraProvider
    ) {
        val infos = provider.availableCameraInfos
        Timber.tag("StreamMetrics").i(
            "camxInfos count=%d", infos.size
        )
        infos.forEachIndexed { idx, info ->
            try {
                val cam2id = androidx.camera.camera2.interop.Camera2CameraInfo
                    .from(info).cameraId
                val facing = when (info.lensFacing) {
                    CameraSelector.LENS_FACING_BACK -> "BACK"
                    CameraSelector.LENS_FACING_FRONT -> "FRONT"
                    CameraSelector.LENS_FACING_EXTERNAL -> "EXTERNAL"
                    else -> "?"
                }
                val zoomState = info.zoomState.value
                Timber.tag("StreamMetrics").i(
                    "camxInfo idx=%d cam2id=%s facing=%s zoomMin=%.2f zoomMax=%.2f zoomDefault=%.2f",
                    idx, cam2id, facing,
                    zoomState?.minZoomRatio ?: -1f,
                    zoomState?.maxZoomRatio ?: -1f,
                    zoomState?.zoomRatio ?: -1f
                )
            } catch (e: Exception) {
                Timber.w(e, "camxInfo : enum failed for idx=%d", idx)
            }
        }
    }

    /**
     * Logs the rotation values that drive portrait video output, so that an OEM
     * deviating from the textbook formula surfaces in field logs. This function
     * logs the formula only (`SENSOR_ORIENTATION - displayRotation*90`), on the
     * `rotationCrosscheck` line. What CameraX actually reports comes from the
     * [TransformationInfo] listener installed by [wireHevcSurfaceProvider] and is
     * logged separately as `hevcSourceTransform ... rot=`; the crosscheck is done
     * by comparing those two field-log lines, not inside this function.
     *
     * On Seeker portrait : SENSOR_ORIENTATION=90, Display.rotation=0
     * (StreamActivity locked portrait), expected=90, CameraX reports 90 — match.
     * Other OEMs (Tensor, Qualcomm 8 Elite, Exynos) may report different values
     * and this crosscheck will flag it. (H2-B.7-bis.)
     */
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private fun logRotationCrosscheck(cameraInfo: androidx.camera.core.CameraInfo) {
        val cam2 = androidx.camera.camera2.interop.Camera2CameraInfo.from(cameraInfo)
        val sensorOrientation = cam2.getCameraCharacteristic(
            android.hardware.camera2.CameraCharacteristics.SENSOR_ORIENTATION
        ) ?: -1
        val displayRotation = try {
            @Suppress("DEPRECATION")
            (getSystemService(WINDOW_SERVICE) as? android.view.WindowManager)
                ?.defaultDisplay?.rotation ?: 0
        } catch (e: Exception) { 0 }
        val displayDeg = when (displayRotation) {
            android.view.Surface.ROTATION_0 -> 0
            android.view.Surface.ROTATION_90 -> 90
            android.view.Surface.ROTATION_180 -> 180
            android.view.Surface.ROTATION_270 -> 270
            else -> 0
        }
        val isFront = cameraInfo.lensFacing == CameraSelector.LENS_FACING_FRONT
        // Standard Android formula for the output rotation needed to put
        // a buffer (sensor-native orientation) into target display
        // orientation. For BACK : subtract. For FRONT : add (mirror).
        val expected = if (isFront) {
            (sensorOrientation + displayDeg) % 360
        } else {
            (sensorOrientation - displayDeg + 360) % 360
        }
        val cam2id = try { cam2.cameraId } catch (e: Exception) { "?" }
        Timber.tag("StreamMetrics").i(
            "rotationCrosscheck cam2id=%s sensorOrientation=%d displayRotation=%d facing=%s expected=%d",
            cam2id, sensorOrientation, displayDeg,
            if (isFront) "FRONT" else "BACK", expected
        )
    }

    /**
     * Resolution the session starts at. When the debug fixed-bitrate toggle is on
     * this is the operator's pinned choice, read from preferences; [startCamera]
     * also creates the AdaptiveQualityManager in `forced` mode in that case, so
     * the pinned resolution holds for the whole recording instead of being
     * overridden by the first adaptive transition.
     */
    private fun resolveInitialQuality(): org.stream.crypto.capture.StreamQuality {
        if (!org.stream.crypto.StreamPreferences.isDebugBitrateEnabled(this)) {
            // Start at HD but never above the user's max cap
            // (a 480p cap must start at 480p, not HD-then-immediately-drop).
            return org.stream.crypto.capture.StreamQuality.HD
                .coerceAtMost(org.stream.crypto.StreamPreferences.getMaxQualityCap(this))
        }
        val key = org.stream.crypto.StreamPreferences.getDebugBitrateQuality(this)
        return when (key) {
            "SD" -> org.stream.crypto.capture.StreamQuality.SD
            else -> org.stream.crypto.capture.StreamQuality.HD
        }
    }

    /**
     * The single place a [ChunkEncoderBundle.VideoConfig] is built, for the
     * initial bind ([startCamera]) and for every mid-stream quality swap
     * ([applyQuality]) alike. Keep it single: giving one of the two paths its own
     * construction site is how the two configs drift apart, the same class of
     * divergence that produced the Berlin field-test bug on the preview side
     * (H2-B §Bugs #5). The encoder resolution is portrait-native with no rotation
     * hint (B.4 fix): do not "correct" it to landscape plus a rotation hint, GL
     * is what puts the frame back to portrait, from the TransformationInfo
     * rotation. Bitrate honours the debug calibration override when the toggle is
     * on.
     *
     * The mime is re-derived on every call. Today that costs nothing and buys
     * nothing: [pickBestVideoMime] only queries MediaCodecList, so in practice it
     * returns the same answer for the lifetime of the process. In particular the
     * runtime HEVC → H.264 fallback that does exist rewrites the recorder's own
     * copy of the config (`videoConfig.copy(mime = "video/avc")` in
     * [RollingChunkRecorder]) without changing what [pickBestVideoMime] reports,
     * so a quality swap coming back through here comes out as `video/hevc` again.
     * A fallback for a first `configure()` that fails does not exist at all; that
     * gap is documented on [pickBestVideoMime] itself. Should a swap ever need to
     * inherit a runtime fallback, this function will have to read that state
     * explicitly — calling [pickBestVideoMime] again will not do it.
     */
    private fun buildHevcVideoConfigFor(
        quality: org.stream.crypto.capture.StreamQuality
    ): ChunkEncoderBundle.VideoConfig {
        // Portrait-native dims (B.4 fix — no rotation hint). Each step
        // matches the displayLabel on [StreamQuality] : 1080p / 720p /
        // 480p with a 16:9 aspect ratio expressed short-edge × long-edge.
        // These are the encoder's dims: the camera HAL still delivers a
        // buffer in sensor orientation (landscape), and GL rotates it to
        // portrait using the TransformationInfo rotation. heightPx is
        // therefore the long axis, and buildHevcPreview depends on that
        // to size the ResolutionSelector.
        val (w, h) = when (quality) {
            org.stream.crypto.capture.StreamQuality.FHD -> 1080 to 1920
            org.stream.crypto.capture.StreamQuality.HD -> 720 to 1280
            org.stream.crypto.capture.StreamQuality.SD -> 480 to 854
        }
        val debugForced = org.stream.crypto.StreamPreferences.isDebugBitrateEnabled(this)
        val bitrateBps = if (debugForced) {
            org.stream.crypto.StreamPreferences.getDebugBitrateKbps(this) * 1_000
        } else {
            quality.targetBitrateBps
        }
        val mime = org.stream.crypto.capture
            .HevcMediaCodecEncoder.pickBestVideoMime()
        return ChunkEncoderBundle.VideoConfig(
            mime = mime,
            widthPx = w,
            heightPx = h,
            bitrateBps = bitrateBps,
            // 1 IDR per chunk (encoder always emits one at start ;
            // next scheduled IDR falls past the chunk window). Cuts
            // ~30 % off effective bitrate vs the 1 s default.
            keyframeIntervalSec =
                (DEFAULT_CHUNK_INTERVAL_MS / 1000L).toInt().coerceAtLeast(1),
            // Phase H2-B adaptive VBR↔CBR (2026-05-17). Mode is owned
            // by the service (toggled via the manager's
            // onBitrateModeChange callback) so every swap — quality or
            // mode driven — picks up the current value without
            // re-deriving it from backlog here.
            bitrateMode = currentHevcBitrateMode,
        )
    }

    /**
     * Apply an adaptive quality change by delegating to the
     * HEVC pipeline (the sole capture path). [applyQualityHevc] swaps the
     * rolling recorder's video config IN PLACE (no camera rebind anymore —
     * H2-B §Bugs #5). The non-null provider/preview refs are the readiness
     * signal that the initial [startCamera] bind ran.
     */
    private fun applyQuality(newQuality: org.stream.crypto.capture.StreamQuality) {
        android.os.Handler(Looper.getMainLooper()).post {
            val hevcRec = hevcRecorder
            if (cameraProviderRef == null || previewRef == null || hevcRec == null) {
                Timber.w("applyQuality: pipeline not ready, skipping (quality=%s)",
                    newQuality.displayLabel)
                return@post
            }
            applyQualityHevc(hevcRec, newQuality)
        }
    }

    /**
     * Builds the [Preview] for the camera bind. Its only caller today is
     * [startCamera]: an adaptive quality swap no longer rebinds anything —
     * [applyQualityHevc] hands the new video config to
     * [RollingChunkRecorder.swapVideoConfig], which swaps the encoder's surface
     * in place, with no camera rebind and no GL teardown. The camera config
     * therefore cannot diverge from one quality to the next, by construction.
     *
     * Keep that property. It was the divergence between two Preview construction
     * paths that produced the Berlin field-test bug (H2-B §Bugs #5): the swap path
     * stayed frozen at H2-B.5 while the initial bind kept gaining the
     * ResolutionSelector (H2-B.21), the multi-cam ultra-wide zoom and the AE FPS
     * floor (H2-B.9), so each adaptive downgrade rebuilt a *barer* Preview →
     * CameraX reverted to its default (~4:3) sensor pick, shifting the crop/FOV,
     * and dropped the source transform. Anyone reintroducing a rebind on the swap
     * side must come back through this helper, never write a second Preview.
     *
     * Carries: the ResolutionSelector (aspect strategy + resolution strategy
     * derived from [config]) so the HAL keeps the same sensor crop at every
     * quality; setTargetRotation(ROTATION_0) so CameraX reports a consistent
     * TransformationInfo rotation; the Camera2Interop AE FPS callback +
     * Range(24,30) floor (H2-B.8/B.9). Does not touch the GlVideoPipeline aspect
     * globals — those are a one-time [startCamera] concern (sticky companion
     * fields).
     */
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private fun buildHevcPreview(config: ChunkEncoderBundle.VideoConfig): Preview {
        // Debug squish harness (2026-06-02) — aspect mode selects 4:3/16:9.
        //   0=A 4:3  1=B 16:9  2=D 4:3  3=E 16:9  4=F 16:9 (the shipped default)
        val aspectMode = org.stream.crypto.StreamPreferences.getDebugAspectMode(this)
        val want16x9 = aspectMode == 1 || aspectMode == 3 || aspectMode == 4
        // CameraX Size is sensor-orientation = landscape. Long axis matches the
        // encoder's long axis ; short axis is 9/16 for 16:9 or 3/4 for 4:3.
        // e.g. 720p (long axis 1280) -> 1280x720 (16:9) or 1280x960 (4:3).
        val sensorSize = if (want16x9) android.util.Size(
            config.heightPx, (config.heightPx * 9) / 16
        ) else android.util.Size(
            config.heightPx, (config.heightPx * 3) / 4
        )
        val builder = Preview.Builder()
            .setResolutionSelector(
                androidx.camera.core.resolutionselector.ResolutionSelector.Builder()
                    .setAspectRatioStrategy(
                        if (want16x9)
                            androidx.camera.core.resolutionselector
                                .AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY
                        else
                            androidx.camera.core.resolutionselector
                                .AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY
                    )
                    .setResolutionStrategy(
                        androidx.camera.core.resolutionselector.ResolutionStrategy(
                            sensorSize,
                            androidx.camera.core.resolutionselector
                                .ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER
                        )
                    )
                    .build()
            )
            // Target the device's natural portrait ; CameraX computes the CCW
            // rotation to bring the sensor-landscape buffer to portrait, which we
            // read back via TransformationInfo and apply in GL (Mediatek's
            // stMatrix does NOT carry the mount-to-display rotation).
            .setTargetRotation(android.view.Surface.ROTATION_0)
        // H2-B.8/B.9 — observe + pin CONTROL_AE_TARGET_FPS_RANGE to Range(24,30)
        // (floor 24 fps keeps the testimony fluid in dark scenes instead of
        // Camera2 dropping to 5..10 fps for longer exposure). Attached before
        // build() because the Extender mutates the builder's config map.
        androidx.camera.camera2.interop.Camera2Interop.Extender(builder)
            .setSessionCaptureCallback(aeFpsCaptureCallback)
            .setCaptureRequestOption(
                android.hardware.camera2.CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE,
                android.util.Range(AE_TARGET_FPS_MIN, AE_TARGET_FPS_MAX)
            )
        return builder.build()
    }

    /**
     * Field diagnostics for a camera that fails after the bind, logged under
     * StreamMetrics: each transition of CameraX's camera state with its error
     * (code, name, and whether CameraX classes it as critical), and the AE
     * target range [buildHevcPreview] requests next to the ranges this camera
     * advertises. A requested range absent from the advertised list is left
     * to the camera HAL to handle, and HALs differ in how they do. Logging
     * only: nothing here changes what the camera is asked to do.
     *
     * The observer is bound to this service's lifecycle, which the teardown
     * moves to DESTROYED, so it does not outlive the session.
     */
    @androidx.annotation.OptIn(androidx.camera.camera2.interop.ExperimentalCamera2Interop::class)
    private fun logCameraStateAndAeRanges(camera: androidx.camera.core.Camera) {
        try {
            camera.cameraInfo.cameraState.observe(this, ::logCameraState)
        } catch (e: Exception) {
            Timber.w(e, "camera state observer not installed")
        }
        try {
            val advertised = androidx.camera.camera2.interop.Camera2CameraInfo.from(camera.cameraInfo)
                .getCameraCharacteristic(
                    android.hardware.camera2.CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES
                )
            val offered = advertised?.any { it.lower == AE_TARGET_FPS_MIN && it.upper == AE_TARGET_FPS_MAX }
            Timber.tag("StreamMetrics").i(
                "aeFpsRanges requested=[%d,%d] advertised=%s requestedAdvertised=%s",
                AE_TARGET_FPS_MIN, AE_TARGET_FPS_MAX,
                advertised?.joinToString(",") { "[${it.lower},${it.upper}]" } ?: "?",
                offered?.toString() ?: "?"
            )
        } catch (e: Exception) {
            Timber.w(e, "AE range comparison failed")
        }
    }

    private fun logCameraState(state: androidx.camera.core.CameraState) {
        val error = state.error
        if (error == null) {
            Timber.tag("StreamMetrics").i("cameraState type=%s", state.type)
        } else {
            Timber.tag("StreamMetrics").w(
                "cameraState type=%s error=%d(%s) critical=%b",
                state.type, error.code, cameraStateErrorName(error.code),
                error.type == androidx.camera.core.CameraState.ErrorType.CRITICAL
            )
        }
    }

    private fun cameraStateErrorName(code: Int): String = when (code) {
        androidx.camera.core.CameraState.ERROR_STREAM_CONFIG -> "STREAM_CONFIG"
        androidx.camera.core.CameraState.ERROR_CAMERA_IN_USE -> "CAMERA_IN_USE"
        androidx.camera.core.CameraState.ERROR_MAX_CAMERAS_IN_USE -> "MAX_CAMERAS_IN_USE"
        androidx.camera.core.CameraState.ERROR_OTHER_RECOVERABLE_ERROR -> "OTHER_RECOVERABLE_ERROR"
        androidx.camera.core.CameraState.ERROR_CAMERA_DISABLED -> "CAMERA_DISABLED"
        androidx.camera.core.CameraState.ERROR_CAMERA_FATAL_ERROR -> "CAMERA_FATAL_ERROR"
        androidx.camera.core.CameraState.ERROR_DO_NOT_DISTURB_MODE_ENABLED -> "DO_NOT_DISTURB_MODE_ENABLED"
        else -> "UNKNOWN"
    }

    /**
     * Wire the [Preview]'s SurfaceProvider at the initial bind. Forwards camera
     * frames to [surfaceTexture] (the recorder's GL input) AND installs the
     * TransformationInfo listener that feeds the GL letterbox fit via
     * [RollingChunkRecorder.setSourceTransform] — the piece the old rebind-based
     * swap path was missing (H2-B §Bugs #5), which left GL scaling on stale
     * source dims after each resolution renegotiation. Since the swap became an
     * in-place encoder swap, there is no camera-side renegotiation left to catch
     * up with.
     */
    private fun wireHevcSurfaceProvider(
        preview: Preview,
        surfaceTexture: android.graphics.SurfaceTexture,
    ) {
        val cameraSurface = android.view.Surface(surfaceTexture)
        preview.setSurfaceProvider { request ->
            val res = request.resolution
            Timber.tag("StreamMetrics").i(
                "hevcPreviewNegotiated w=%d h=%d ratio=%.3f",
                res.width, res.height,
                res.width.toFloat() / res.height.toFloat()
            )
            request.setTransformationInfoListener(mainExecutor) { info ->
                val rotation = info.rotationDegrees
                Timber.tag("StreamMetrics").i(
                    "hevcSourceTransform w=%d h=%d rot=%d",
                    res.width, res.height, rotation
                )
                hevcRecorder?.setSourceTransform(res.width, res.height, rotation)
            }
            request.provideSurface(cameraSurface, mainExecutor) { result ->
                cameraSurface.release()
                Timber.d(
                    "[Phase H2-B] camera surface released, result=%d",
                    result.resultCode
                )
            }
        }
    }

    /**
     * Post-bind camera configuration, applied once by [startCamera]:
     *   - drive the logical multi-cam to its widest sub-camera via setZoomRatio
     *     (ultra-wide FOV match). Back when a quality change rebound the camera,
     *     the fresh Camera2 session reset the zoom to 1.0× (main lens), zooming
     *     the FOV in — cumulatively across repeated downgrades (H2-B §Bugs #5).
     *     Since the swap became an in-place encoder swap there is no rebind, so
     *     this config persists from the initial bind instead of being reapplied.
     *   - the rotation crosscheck canary (H2-B.7-bis).
     */
    private fun applyHevcCameraConfig(camera: androidx.camera.core.Camera) {
        try {
            val z = camera.cameraInfo.zoomState.value
            if (z != null && z.minZoomRatio < 1f) {
                camera.cameraControl.setZoomRatio(z.minZoomRatio)
                Timber.tag("StreamMetrics").i(
                    "cameraZoomSet ratio=%.2f (min of %.2f..%.2f)",
                    z.minZoomRatio, z.minZoomRatio, z.maxZoomRatio
                )
            } else {
                Timber.tag("StreamMetrics").i(
                    "cameraZoomKept range=%.2f..%.2f (no sub-1x available)",
                    z?.minZoomRatio ?: -1f, z?.maxZoomRatio ?: -1f
                )
            }
        } catch (e: Exception) {
            Timber.w(e, "cameraControl.setZoomRatio failed")
        }
        try {
            logRotationCrosscheck(camera.cameraInfo)
        } catch (e: Exception) {
            Timber.w(e, "rotation crosscheck failed")
        }
    }

    /**
     * Applies an adaptive quality change by swapping the encoder's GL output
     * surface IN PLACE (new resolution/bitrate), through
     * [RollingChunkRecorder.swapVideoConfig]. The camera, the GL pipeline and the
     * on-screen preview all stay live, so there is no camera rebind and no
     * preview black-out, and the FOV can't drift — the camera config persists
     * from the single startCamera bind. Do not "simplify" this back into a
     * rebind: the previous version rebuilt the GL pipeline and rebound the camera
     * to a fresh Preview, which blacked out the preview and zoomed the FOV
     * cumulatively on every swap (H2-B §Bugs #5).
     *
     * The single-flight guard drops a request that arrives while a previous swap
     * is still settling, rather than queueing it. That is acceptable only because
     * the AdaptiveQualityManager re-proposes on its next tick; the dropped
     * request itself is gone.
     */
    private fun applyQualityHevc(
        recorder: RollingChunkRecorder,
        newQuality: org.stream.crypto.capture.StreamQuality,
    ) {
        if (!hevcSwapInFlight.compareAndSet(false, true)) {
            Timber.w(
                "applyQualityHevc: swap already in flight, dropping request for %s",
                newQuality.displayLabel
            )
            return
        }
        val newConfig = buildHevcVideoConfigFor(newQuality)
        val swapThread = Thread({
            try {
                // In-place encoder swap : no camera rebind, no GL teardown, no
                // preview black-out. The camera config (resolution, ultra-wide
                // zoom, AE FPS floor) persists from the single startCamera bind,
                // so the FOV can't drift. swapVideoConfig posts to the recorder's
                // rotate handler and blocks until the swap completes.
                recorder.swapVideoConfig(newConfig)
                Timber.tag("StreamMetrics").i(
                    "applyQualityHevc rebound quality=%s w=%d h=%d kbps=%d",
                    newQuality.displayLabel,
                    newConfig.widthPx, newConfig.heightPx,
                    newConfig.bitrateBps / 1000
                )
            } catch (e: Exception) {
                Timber.e(e, "applyQualityHevc: swap failed for %s", newQuality.displayLabel)
            } finally {
                hevcSwapInFlight.set(false)
            }
        }, "HevcQualitySwap")
        // WP-F2 (audit 2026-06-28) — if start() throws (OOM creating the native
        // thread), the body's finally never clears hevcSwapInFlight, so the
        // single-flight guard above drops EVERY later quality swap for the rest
        // of the session (frozen adaptivity, stuck at the current quality).
        // Reset the guard on a failed start.
        try {
            swapThread.start()
        } catch (t: Throwable) {
            hevcSwapInFlight.set(false)
            Timber.e(
                t,
                "applyQualityHevc: swap thread start() failed for %s — in-flight guard reset",
                newQuality.displayLabel
            )
        }
    }

    /**
     * Every finalized chunk MP4 arrives here, from the recorder's drain
     * threads or from its stop(). It is handed to the report's writer thread,
     * which seals it (encrypt, sign, write the envelope durably) and only then
     * deletes the MP4. Nothing here waits on the writer: a drain thread must
     * never block on encryption.
     *
     * A chunk that arrives once the report is closing (after the recorder's
     * stop, or past its safety bound) cannot be sealed any more: its MP4 is
     * deleted and the loss is counted and shown.
     */
    private fun onChunkReady(chunkFile: File, seqNum: Int) {
        Timber.d("Chunk #%d ready (%d bytes)", seqNum, chunkFile.length())

        // Mirror the chunk MP4 to filesDir/debug_raw/ when fixed-bitrate mode
        // is on. Done synchronously, before the seal is queued, so the source
        // file is still intact at copy time.
        saveRawDebugCopyIfEnabled(chunkFile, seqNum)

        val p = producer
        if (p == null || !acceptingChunks) {
            dropLateChunk(chunkFile, seqNum)
            return
        }
        // Both counts go up BEFORE the hand-over, so that a reader (the
        // lock-timeout controller, the snapshot) can never miss a chunk that
        // is between the two.
        pendingChunks.incrementAndGet()
        encryptionsInFlightCounter.incrementAndGet()
        val submitted = p.submitChunk(seqNum, chunkFile) { result ->
            try {
                onChunkSealed(result)
            } finally {
                pendingChunks.decrementAndGet()
                encryptionsInFlightCounter.decrementAndGet()
            }
        }
        when (submitted) {
            ReportProducer.Submit.ACCEPTED -> Unit
            ReportProducer.Submit.DUPLICATE -> {
                // The same chunk delivered a second time: the file is the one
                // the first submission is sealing, and that one deletes it.
                // Deleting it here would destroy what is being sealed.
                pendingChunks.decrementAndGet()
                encryptionsInFlightCounter.decrementAndGet()
                Timber.tag("StreamMetrics").w("chunkDuplicate seq=%d", seqNum)
            }
            ReportProducer.Submit.REFUSED -> {
                pendingChunks.decrementAndGet()
                encryptionsInFlightCounter.decrementAndGet()
                dropLateChunk(chunkFile, seqNum)
            }
        }
    }

    /** Runs on the writer thread, once per chunk. Never blocks on the network. */
    private fun onChunkSealed(result: ReportProducer.ChunkResult) {
        when (result) {
            is ReportProducer.ChunkResult.Sealed -> {
                chunksEncrypted.incrementAndGet()
                scheduleEnvelope(result.envelope)
                broadcastChunkUpdate()
                // The auth upkeep that used to follow each chunk runs on its
                // own thread now: offline-start recovery (maybeRetryAuth, with
                // its 30 s cooldown) and the proactive JWT refresh.
                kickAuthUpkeep()
            }
            is ReportProducer.ChunkResult.Lost -> {
                persistLateLoss(losses.onLoss())
                broadcastChunkUpdate()
            }
            is ReportProducer.ChunkResult.Dropped -> Unit
        }
    }

    /**
     * A chunk the report can no longer take: delete the MP4, count the loss.
     * A file that holds nothing (an empty MP4, or one the teardown already
     * purged and counted) is not a loss.
     */
    private fun dropLateChunk(chunkFile: File, seqNum: Int) {
        val hadVideo = chunkFile.length() > 0L
        EnvelopeQueue.secureDelete(chunkFile)
        if (StreamUploadManager.wipeGeneration() != wipeGenerationAtStart) return
        if (!hadVideo) return
        persistLateLoss(losses.onLoss())
        Timber.tag("StreamMetrics").w("chunkLost seq=%d reason=after_close", seqNum)
        broadcastChunkUpdate()
    }

    /**
     * Write [count] losses the closure's bulk alert did not include (the
     * ledger hands back 0 until the bulk is written). After the teardown the
     * HUD is gone, so the alert is the only place the witness sees them.
     */
    private fun persistLateLoss(count: Int) {
        if (count <= 0) return
        StreamUploadManager.unlessWipedSince(wipeGenerationAtStart) {
            StreamPreferences.addReportAlert(this, count, recordingStartMs, ReportAlerts.Reason.CAPTURE_LOST)
        }
    }

    private fun kickAuthUpkeep() {
        if (StreamUploadManager.wipeGeneration() != wipeGenerationAtStart) return
        try {
            authExecutor.execute {
                try {
                    maybeRetryAuth()
                    maybeRefreshJwt()
                } catch (e: Exception) {
                    Timber.w(e, "auth upkeep failed")
                }
            }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            // Shut down by the teardown: nothing left to keep up.
        }
    }

    /**
     * §10.11 — at the report's closure, write the opt-in timestamp ticket.
     *
     * There is **no manifest, no signature, no sealing** of provenance here.
     * The commitment is a salted hash over the plaintext hashes of the chunks
     * the closure lists (in seq order, as the writer returns them): exactly the
     * media a verifier reassembles from the verified objects. The salt comes
     * from the provenance seed (the signer this reads signs nothing), so the
     * relay cannot link the stamp to the report. Attribution stays on-demand at
     * disclosure, never baked into a stored, seizable artifact.
     *
     * Default OFF: a `.ots` is a permanent public Bitcoin breadcrumb. Needs the
     * provenance signer, which a lock during the recording wipes: no ticket then.
     * The ticket (sealed under the queue key by Rust) is all the worker gets;
     * it asks for the stamp once a PIN session is open, and gets a bearer
     * itself if none is held.
     *
     * The ticket and its job are written as one step with respect to an
     * emergency wipe ([StreamUploadManager.unlessWipedSince]): both before
     * the wipe starts, or neither, so the ticket's directory is not recreated
     * once a wipe has renamed it away.
     */
    private fun writeTimestampTicket(info: uniffi.frappuccino.CloseInfo) {
        if (!provenanceActive) return
        if (!StreamPreferences.isProvenanceTimestampEnabled(this)) return
        if (StreamUploadManager.wipeGeneration() != wipeGenerationAtStart) return
        if (info.plaintextHashes.isEmpty()) return
        val signer = StreamUploadManager.getInstance()?.provenanceSigner ?: run {
            Timber.d("Provenance TS: signer gone (locked during the recording), no ticket")
            return
        }
        val queue = envelopeQueue ?: return
        try {
            val commitment = uniffi.frappuccino.provenanceOtsCommitment(
                info.plaintextHashes, recordingIdFor(sessionId), signer
            )
            val written = StreamUploadManager.unlessWipedSince(wipeGenerationAtStart) {
                val dir = File(filesDir, org.stream.crypto.upload.LegacyReportMigration.PROVENANCE_DIR)
                    .apply { mkdirs() }
                val ticket = File(dir, "$sessionId.ticket")
                uniffi.frappuccino.otsTicketWrite(ticket.absolutePath, info.otsName, commitment)
                ProvenanceTimestampWorker.enqueue(
                    this, ticket, queue.pathFor(EnvelopeNames.timestampProof(sessionId)),
                    DEFAULT_SERVER_URL, wipeGenerationAtStart,
                )
            }
            if (written != null) Timber.i("Provenance timestamp ticket written")
        } catch (e: Exception) {
            Timber.w(e, "provenance ticket failed (non-fatal)")
        }
    }

    /** §10.11 — deterministic 16-byte recording id derived from the sessionId. */
    private fun recordingIdFor(sessionId: String): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(sessionId.toByteArray(Charsets.UTF_8))
            .copyOf(16)

    /**
     * `onAvailable` est appelé sur un thread binder système, pas sur le main
     * thread : c'est pour ça que maybeRetryAuth() y tourne dans un Thread de
     * fond et pas en direct. Cet appel fait de l'I/O réseau (auth + report
     * creation, ~1-3s), et bloquer un thread qui appartient au système est
     * mauvais pour le service — Doze le lui impute.
     *
     * Le callback ConnectivityManager fire dès qu'une network VALIDATED +
     * INTERNET devient dispo, ce qui est plus immédiat que le polling fait à
     * chaque chunk (5s d'intervalle).
     */
    private fun registerNetworkCallback() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            val request = android.net.NetworkRequest.Builder()
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                .build()
            val cb = object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    Timber.d("[Phase 2.4.2] NetworkCallback.onAvailable")
                    // Structured network event for field
                    // capture analysis (correlates with uploadMs spikes).
                    Timber.tag("StreamMetrics").i(
                        "networkEvent type=onAvailable transportType=%s",
                        detectNetworkType()
                    )
                    Thread {
                        // Never for a session that is stopping: its teardown
                        // owns what is left, and the workers take over after.
                        if (stopRequested.get()) return@Thread
                        try {
                            // Kick the upload backlog at reconnect time
                            // without disturbing in-flight PUTs. Cancel
                            // ENQUEUED workers only — the ones sitting in
                            // WorkManager backoff — never RUNNING ones:
                            // the previous cancelAllWorkByTag killed
                            // workers whose PUT was already complete
                            // server-side, the retry then re-PUT the same
                            // filename, and the append-mode
                            // storage.upload_blob of the time appended the
                            // same bytes to themselves, leaving a 2× blob
                            // that fails to decode at play time, long
                            // after the upload had reported success
                            // (Phase 3.12).
                            //
                            // The relay stores write-once today, which
                            // makes that race benign for a different
                            // reason: a byte-identical re-PUT is a no-op
                            // that returns "identical" and leaves the
                            // stored bytes alone. It does NOT overwrite —
                            // a PUT whose bytes differ from what is stored
                            // raises WriteOnceConflictError and comes back
                            // as 409 (server/app/storage.py,
                            // server/app/routes/upload.py). Skipping
                            // running workers is still the correct
                            // semantic.
                            //
                            // - reset() = we have external proof (validated
                            //   network) that the server is reachable, so
                            //   we drop a possibly-stale 5xx counter.
                            // - pruneWork() = drop terminal entries
                            //   (SUCCEEDED/CANCELLED) so the next
                            //   scheduleUpload doesn't double-enqueue.
                            // - scheduleUpload() = re-enqueue every queued
                            //   envelope. A re-send of identical bytes is a
                            //   server-side no-op, so a concurrent worker
                            //   finishing on its own is harmless.
                            rs.readahead.washington.mobile.util.jobs
                                .UploadCircuitBreaker.reset()
                            try {
                                val wm = androidx.work.WorkManager
                                    .getInstance(this@StreamRecordingService)
                                val infos = wm.getWorkInfosByTag(
                                    ChunkUploadWorker.TAG
                                ).get()
                                var cancelled = 0
                                for (info in infos) {
                                    if (info.state == androidx.work.WorkInfo.State.ENQUEUED) {
                                        wm.cancelWorkById(info.id)
                                        cancelled++
                                    }
                                }
                                wm.pruneWork()
                                Timber.i(
                                    "[Phase 3.12] Network back — circuit reset, %d ENQUEUED cancelled, RUNNING preserved",
                                    cancelled
                                )
                            } catch (e: Exception) {
                                Timber.w(e, "[Phase 3.12] cancel/prune failed")
                            }
                            // Blue MED-4 fix. Wipe the
                            // already-enqueued name set on recovery so a
                            // job that has ended (or whose ENQUEUED state
                            // was just cancelled above) can be re-enqueued
                            // by the upcoming scheduleUpload(). Without
                            // this, the set would block those retries
                            // until process death.
                            enqueuedEnvelopeNames.clear()
                            maybeRetryAuth()
                            scheduleUpload()
                            // Don't drop these two calls as redundant with the
                            // cancel / prune / scheduleUpload above: they undo
                            // state the recovery path cannot otherwise unwind.
                            // The concurrency cap may have shrunk to 1 during
                            // the bad-network spell and has no way back up on
                            // its own — the only path that grows it needs fresh
                            // successful uploads, which a cap of 1 plus
                            // WorkManager backoff starves. The quality
                            // SLOW/FAST streak accumulated during the spell
                            // likewise survives the reconnect, so clearing it
                            // is what lets the fresh post-recovery samples,
                            // rather than the stale ones, decide the next
                            // transition. Measured in the field on 2026-06-23 :
                            // the cap stayed at 1 for ~14 min after a
                            // cellular→WiFi switch (Phase 3.49).
                            //
                            // Both are safe to call from this callback. The cap
                            // only ever grows, and bumpCapForRecovery also
                            // wipes the rolling sample window so the next
                            // decision is taken on post-recovery samples rather
                            // than the stale slow ones. onNetworkRecovered does
                            // not force a quality step: hysteresis and
                            // BACKLOG_FREEZE_THRESHOLD still govern any upgrade.
                            rs.readahead.washington.mobile.util.jobs
                                .UploadConcurrencyLimiter.bumpCapForRecovery()
                            org.stream.crypto.capture.AdaptiveQualityHolder
                                .get()?.onNetworkRecovered()
                        } catch (e: Exception) {
                            Timber.e(e, "[Phase 2.4.2] retry from callback failed")
                        }
                    }.start()
                }

                override fun onLost(network: android.net.Network) {
                    // Structured loss event. Don't call
                    // detectNetworkType() here : by the time the callback
                    // fires, activeNetwork may have already switched to
                    // another transport (e.g. wifi → cellular fallback),
                    // so we'd log the post-state, not the loss itself.
                    Timber.tag("StreamMetrics").i("networkEvent type=onLost")
                }
            }
            // Not registered once the stop has run: its unregister would
            // never come again (see [networkRegistration]).
            val registered = networkRegistration.registerUnlessStopped {
                cm.registerNetworkCallback(request, cb)
                cb
            }
            Timber.d("[Phase 2.4.2] NetworkCallback registered=%b", registered)
        } catch (e: Exception) {
            Timber.e(e, "[Phase 2.4.2] Failed to register NetworkCallback — fallback polling")
        }
    }

    private fun unregisterNetworkCallback() {
        try {
            networkRegistration.stop { cb ->
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE)
                    as android.net.ConnectivityManager
                cm.unregisterNetworkCallback(cb)
                Timber.d("[Phase 2.4.2] NetworkCallback unregistered")
            }
        } catch (e: Exception) {
            Timber.w(e, "[Phase 2.4.2] Failed to unregister NetworkCallback")
        }
    }

    /**
     * Ne pas baisser ni retirer le cooldown de 30 s : il ne sert pas qu'à
     * ménager le relais, il dédoublonne deux sources d'appel qui peuvent tirer
     * quasi simultanément — le `NetworkCallback.onAvailable` (Phase 2.4.2,
     * instantané au reconnect) et le polling de repli après chaque chunk
     * scellé (Phase 2.4.1, gardé au cas où le callback ne fire pas). Sans lui, une
     * simple reconnexion déclenche deux `authenticateV2()` de suite, soit deux
     * slots consommés sur les 50 du batch éphémère pour un seul événement
     * réseau.
     *
     * Ce n'est pas du retry défensif : le cas couvert est celui d'un
     * enregistrement démarré sans réseau (typiquement en mode avion), dont
     * l'authentification initiale a donc échoué, le réseau arrivant plus tard
     * en cours de captation. On retente alors initServerSession() si le réseau
     * est disponible et si le cooldown est écoulé.
     *
     * Une fois l'auth récupérée, ce sont les appelants qui enchaînent sur
     * scheduleUpload() — cette fonction ne l'appelle pas elle-même. L'auth ne
     * sert qu'aux envois en mode création (le premier objet d'un rapport, une
     * entrée d'annuaire, ou un objet pour lequel le relais a répondu 425) ;
     * toute autre enveloppe part sur sa seule signature.
     */
    private fun maybeRetryAuth() {
        // Never simplify the guard below to `authTokenIssuedAtMs > 0 &&
        // producer != null`: the isPresent() term is the only thing that makes
        // a 401 taken mid-session recoverable. Gap C (2026-06-15) — such a 401
        // (server-side JWT_SECRET rotated, or token blacklisted / expired
        // early) clears the Rust-held bearer (UploadAuthHolder.clear →
        // UPLOAD_JWT zeroize) but does NOT reset authTokenIssuedAtMs, the
        // worker having no handle on the service. Drop the term and
        // maybeRetryAuth sees "already authed" and returns.
        //
        // What that costs is narrower than every chunk, and worth stating
        // exactly. Only a creation request carries the bearer (the envelope
        // worker's creation mode); every other envelope goes on its signature
        // alone, and the relay asks for a JWT only while the report record
        // does not exist yet (server/app/routes/upload.py). A 401 landing after
        // the report is created therefore costs nothing. One landing before it
        // leaves the creating envelopes waiting for a bearer, and every other
        // object of the session comes back 425 and waits on disk. Nothing
        // re-authenticates for them until the recording stops: the workers
        // defer to the service through ensureFallbackReAuth's
        // `isRunning || isShuttingDown` gate. With isPresent(), a cleared
        // holder re-drives the full re-auth here.
        //
        // Re-driving it is safe on three counts. initServerSession is auth-only
        // (the report is opened locally at session start), so re-invoking it
        // only refreshes the ephemeral JWT and can never open a second report;
        // `producer != null` just confirms the session is fully initialised. It
        // is bounded by AUTH_RETRY_COOLDOWN_MS + isRelayReachable below. And
        // only the service re-auths while it runs (the worker keeps deferring),
        // so there is no slot-pool race — invariant H2-B.16 preserved.
        // isPresent() (not get()) keeps the bearer out of the JVM heap (heap-0,
        // §10.6).
        if (authTokenIssuedAtMs > 0L && producer != null &&
            rs.readahead.washington.mobile.util.jobs.UploadAuthHolder.isPresent()
        ) return  // déjà OK
        // A stopping session authenticates no more: the creations still
        // pending keep the bearer already held, and the workers take over the
        // authentication once the teardown is done.
        if (stopRequested.get()) return
        val now = System.currentTimeMillis()
        if (now - lastAuthAttemptMs < AUTH_RETRY_COOLDOWN_MS) return
        if (!isNetworkAvailable()) {
            Timber.d("maybeRetryAuth: réseau toujours indispo, skip")
            return
        }
        // Guard against captive portal / DNS-up-but-host-down. The system fires
        // onAvailable as soon as a network is "validated", i.e. as soon as the
        // OS connectivity probe passes, which says nothing about the relay host
        // being reachable — corporate firewall, geo-block, server restart in
        // progress. Without this, initServerSession()/authenticateV2() would pay
        // the control-plane client's own timeouts on every flap (10 s connect /
        // 15 s call, `crypto-rs/stream/src/protocol.rs`) before failing ; a 3 s
        // probe fails fast instead. The 120 s ceiling belongs to the data plane,
        // not to this path (`crypto-rs/stream/src/upload.rs`, and the QUIC
        // CALL_TIMEOUT in `crypto-rs/stream/src/quic.rs`). Phase 3.18.
        //
        // The probe does not preserve a ratchet slot, whatever it may look
        // like, and this comment used to claim it did (WP-F3, audit 2026-06-28,
        // L-8). authenticateV2() calls challenge() first, which only fetches a
        // server nonce, and returns on its failure — before signAndAdvance(),
        // the only slot-consuming step. The probe's real value is fast-fail. It
        // hits the same DirectTls control-plane endpoint (:8443) that the very
        // next challenge()/verify() use anyway (the auth control-plane rides
        // DirectTls by design; only the bulk chunk PUT is ObfQuic), so it adds
        // no exposure class the imminent auth doesn't already have. See WP-G
        // for the documented control-plane-on-DirectTls scope of the
        // obfuscation.
        if (!isRelayReachable()) {
            Timber.d("maybeRetryAuth: relay /health unreachable, skip (fast-fail before DirectTls auth)")
            return
        }
        lastAuthAttemptMs = now
        Timber.i("maybeRetryAuth: réseau de retour, retry initServerSession")
        try {
            initServerSession()
            if (authTokenIssuedAtMs > 0L) {
                Timber.i("maybeRetryAuth: auth récupérée OK — backlog va se vider")
            }
        } catch (e: Exception) {
            Timber.e(e, "maybeRetryAuth: initServerSession threw")
        }
    }

    /**
     * Quick reachability probe of the relay's `/health` endpoint, used to
     * fast-fail before a DirectTls auth (Phase 3.18).
     *
     * Derive the client from the shared UploadHttpClient with `newBuilder()`,
     * never build a fresh `OkHttpClient` here: a new client
     * would lose the CertificatePinner — three SPKI pins accepted in union,
     * defence in depth on top of `network_security_config.xml` — and the
     * process-wide connection pool, so every probe would pay a full TLS
     * handshake.
     *
     * WP-F3 (audit 2026-06-28, L-8) — this deliberately targets the DirectTls
     * control-plane endpoint ([DEFAULT_SERVER_URL] = :8443), the same one the
     * auth handshake (challenge/verify/enroll) uses. The ObfQuic front
     * (:8445) obfuscates only the bulk data-plane (chunk PUT); the control plane
     * is DirectTls by design, so this probe leaks no IP/SNI signal the imminent
     * auth doesn't already. Bounded: it only runs during an active recording,
     * immediately before a DirectTls auth. See WP-G for the documented scope.
     */
    private fun isRelayReachable(): Boolean {
        return try {
            // GET (not HEAD) because the FastAPI route is declared
            // @app.get and doesn't auto-generate HEAD ; the body is
            // just `{"status":"ok"}`, ~16 bytes, negligible.
            val req = okhttp3.Request.Builder()
                .url("$DEFAULT_SERVER_URL/health")
                .get()
                .build()
            val client = rs.readahead.washington.mobile.util.jobs
                .UploadHttpClient.instance.newBuilder()
                .callTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                .build()
            client.newCall(req).execute().use { resp ->
                resp.isSuccessful
            }
        } catch (e: Exception) {
            Timber.d("isRelayReachable: %s", e.javaClass.simpleName)
            false
        }
    }

    /**
     * Refresh proactif du JWT si proche de l'expiration (Phase 2.4.3).
     *
     * Chaque authenticateV2() consomme 1 slot sur les 50 du batch éphémère du
     * ratchet : ne pas rafraîchir plus tôt, ni périodiquement « pour être
     * tranquille », sous peine de vider le batch et de forcer une rotation
     * prématurée. Pour une session courte (<23h, le cas pratique sur device),
     * aucun refresh n'a lieu — la fonction return immédiatement.
     *
     * Le 24h n'est pas une valeur locale : c'est une copie de
     * config.JWT_EXPIRE_HOURS côté serveur, que le client ne lit jamais. Si les
     * deux divergent, la fenêtre de refresh disparaît en silence — déclenchée
     * trop tard, après l'expiration, ou jamais.
     *
     * Ce que le refresh avant T-1h protège, ce sont les envois en mode
     * création d'un rapport ouvert au-delà de l'expiration. Le bearer ne sert
     * qu'à eux (le premier objet du rapport, une entrée d'annuaire, un objet
     * qui a reçu 425) ; toute autre enveloppe s'autorise par sa seule
     * signature, sans aucune garde d'auth, et le relais ne réclame un JWT que
     * tant que l'enregistrement du rapport n'existe pas. Un JWT périmé ne fait
     * donc pas échouer les autres envois : il fait repartir la création sur un
     * 401 → bearer effacé → nouvel essai.
     *
     * Ne pas en déduire que les envois de création sont les seuls
     * consommateurs du bearer : ProvenanceTimestampWorker (soumission .ots) en
     * dépend aussi ; sans bearer, il en obtient un lui-même hors
     * enregistrement (ensureBearer), et attend la fin de l'enregistrement
     * sinon.
     *
     * Cooldown 30s pour éviter de hammer si réseau flap.
     */
    private fun maybeRefreshJwt() {
        if (authTokenIssuedAtMs == 0L) return  // pas de session à refresh
        val ageMs = System.currentTimeMillis() - authTokenIssuedAtMs
        if (ageMs < JWT_LIFETIME_MS - JWT_REFRESH_THRESHOLD_MS) return  // encore frais
        val now = System.currentTimeMillis()
        if (now - lastRefreshAttemptMs < JWT_REFRESH_COOLDOWN_MS) return
        if (!isNetworkAvailable()) {
            Timber.d("[Phase 2.4.3] JWT refresh: réseau indispo, skip (age=%ds)", ageMs / 1000)
            return
        }
        lastRefreshAttemptMs = now
        Timber.i("[Phase 2.4.3] JWT proche expiration (age=%ds / %ds), refresh proactif",
            ageMs / 1000, JWT_LIFETIME_MS / 1000)
        try {
            val manager = StreamUploadManager.getInstance() ?: return
            val refreshed = manager.authenticateV2()
            if (!refreshed) {
                Timber.w("[Phase 2.4.3] authenticateV2 a échoué pendant refresh — keep ancienne session")
                return
            }
            // §10.6 — the fresh bearer is now in the Rust holder (stashed by
            // verify()); we only bump the issuance clock here.
            authTokenIssuedAtMs = System.currentTimeMillis()
            // No batch number or slot count in the line: the relay stores
            // each identity's batch and used slots, and a test build sends
            // its log to the relay.
            Timber.i("[Phase 2.4.3] JWT refresh OK")
        } catch (e: Exception) {
            Timber.e(e, "[Phase 2.4.3] JWT refresh threw")
        }
    }

    private fun isNetworkAvailable(): Boolean {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            val nw = cm.activeNetwork ?: return false
            val cap = cm.getNetworkCapabilities(nw) ?: return false
            cap.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                cap.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Schedule the upload of one envelope (unique work named after the file,
     * KEEP). Needs neither a bearer nor the unlocked state: the envelope is
     * already signed, and the worker decides when it can go. Nothing is
     * scheduled once an emergency wipe has started: a seal that finished while
     * the wipe was aborting the writer must not leave a job row behind it.
     */
    private fun scheduleEnvelope(envelope: File) {
        if (!enqueuedEnvelopeNames.add(envelope.name)) return
        try {
            if (!ChunkUploadWorker.enqueue(this, envelope, DEFAULT_SERVER_URL, wipeGenerationAtStart)) {
                enqueuedEnvelopeNames.remove(envelope.name)
            }
        } catch (e: Exception) {
            // Not scheduled: forget it so the next pass tries again. The
            // envelope stays in the queue either way.
            enqueuedEnvelopeNames.remove(envelope.name)
            Timber.w(e, "envelope scheduling failed")
        }
    }

    /**
     * Schedule every queued envelope, whichever session or report it belongs
     * to: an envelope left by an earlier recording, or converted by the
     * migration, goes the same way as this session's.
     */
    private fun scheduleUpload() {
        val queue = envelopeQueue ?: return
        for (envelope in queue.pending()) scheduleEnvelope(envelope)
        // One broadcast after the whole pass, not one per envelope: the count
        // is read from the queue, so it stays consistent.
        broadcastChunkUpdate()
    }

    private fun initServerSession() {
        try {
            val manager = StreamUploadManager.getInstance()
            if (manager == null) {
                Timber.e("StreamUploadManager not available")
                return
            }

            // Configure URL serveur (persistée aussi dans StreamPreferences)
            manager.setServerUrl(DEFAULT_SERVER_URL)

            // Claim the auth cooldown window here, before the call and
            // not after it: this timestamp means "we tried to auth", not
            // "we succeeded". Moving it below authenticateV2(), or into
            // an `if (authed)` branch, reopens the hole it closes — a
            // NetworkCallback `onAvailable` firing while
            // initServerSession is still in its network call (e.g. wifi
            // already up before it ran) would see a pristine cooldown,
            // and maybeRetryAuth() would tail us into a second
            // authenticateV2() within the same 30 s window, consuming
            // 2 slots out of the 50-key ratchet batch for a single boot.
            // The cooldown check in maybeRetryAuth() reads this
            // timestamp, so it now means : "if we tried to auth in the
            // last 30 s, don't re-auth", regardless of whether the prior
            // attempt succeeded or failed. Phase 3.36.
            lastAuthAttemptMs = System.currentTimeMillis()

            // V2 auth : challenge + verify avec clé éphémère du ratchet
            val authed = manager.authenticateV2()
            if (!authed) {
                Timber.e("V2 auth failed — serveur indisponible ou identité non enrôlée")
                return
            }
            authTokenIssuedAtMs = System.currentTimeMillis()  // Phase 2.4.3
            // §10.6 — the bearer is stashed in the Rust holder by verify(). On
            // the envelope path only the existence bit crosses the FFI
            // (UploadAuthHolder.isPresent()): a creation request has Rust
            // attach the bearer itself, every other envelope goes without one,
            // so it never enters the JVM heap there. One caller still pulls a
            // transient copy via UploadAuthHolder.get() — the
            // ProvenanceTimestampWorker, for the .ots submission. Nothing is
            // persisted by WorkManager (Audit R-01) and the JWT is never a
            // long-lived JVM String.
            //
            // No batch number or slot count in the line: the relay stores
            // each identity's batch and used slots, and a test build sends
            // its log to the relay.
            Timber.i("V2 auth OK")

            // Do not add a report-creation call here: its absence is
            // deliberate. The report was opened locally at session start (Rust
            // advanced the report state; no network), and the relay creates
            // its record from the first envelope sent in creation mode. A
            // session therefore has exactly one report for its whole life,
            // fixed before the first chunk exists, which makes the old
            // split-report field bug (2026-05-20: one session creating twice →
            // chunks halved across two report ids) structurally impossible.
            //
            // initServerSession is auth-only as a result: it stays idempotently
            // re-runnable from maybeRetryAuth (offline-start recovery) and can
            // never open a second report.

        } catch (e: Exception) {
            Timber.e(e, "Failed to init V2 server session")
        }
    }

    /**
     * End the recording: idempotent, never blocks the caller. The teardown
     * runs on its own thread while the service stays in the foreground with
     * its wake lock, and the service stops itself once the report's closure is
     * written (or given up).
     *
     * Every way a recording ends comes through here: the user's stop
     * ([ACTION_STOP]), the Lock button, a full device, an unrecoverable
     * capture, a failed start, and [onDestroy] when the service is stopped
     * from outside.
     */
    private fun requestStop(reason: String) {
        if (!stopRequested.compareAndSet(false, true)) return
        Timber.i("recording stop requested (%s)", reason)
        if (!ownsSession) {
            Thread({ teardown() }, "recording-teardown").start()
            return
        }

        // Never let [isRunning] flip before this shutdown indicator. Workers
        // gate on `isRunning || isShuttingDown`, and only this order covers the
        // entire teardown window — until `isShuttingDown = false` at the end of
        // [finishTeardown] — instead of just the instant where [isRunning]
        // changes state. See the companion object doc on [isShuttingDown]
        // (Phase H2-B.16, Blue HIGH-6 fix, 2026-05-19).
        isShuttingDown = true

        // Set before the removeCallbacks below, never after: removeCallbacks
        // does not stop an iteration already running on the main looper, and
        // that iteration posts a fresh task. With the flag set first, it bails
        // at its next `if (isDestroyed) return` check instead (Phase 3.47).
        isDestroyed = true
        isRunning = false

        notificationRefresher.removeCallbacks(notificationRefreshTask)
        uploadKicker.removeCallbacks(uploadKickerTask)
        deviceTelemetryRefresher.removeCallbacks(deviceTelemetryTask)

        // No more network events during the teardown: one could start an auth
        // while the session is being taken down. A callback that is never
        // unregistered stays with the ConnectivityManager until the process
        // dies; [networkRegistration] also keeps the init thread from
        // registering one after this.
        unregisterNetworkCallback()

        // The teardown's own bounds, re-armed now: the timeout taken at the
        // start may have run out during a long recording, and the closure has
        // to be written with the screen off too.
        try {
            wakeLock?.acquire(RECORDER_STOP_BOUND_MS + OPENING_WAIT_MS + CLOSE_WAIT_MS + ABORT_DRAIN_MS + TEARDOWN_MARGIN_MS)
        } catch (e: Exception) {
            Timber.w(e, "wake lock not re-armed for the teardown")
        }

        try {
            updateNotification(getString(R.string.stream_recording_finalizing))
        } catch (_: Exception) { }

        Thread({ teardown() }, "recording-teardown").start()
    }

    /**
     * In order: stop the recorder (all its deliveries returned), close the
     * report as the writer's last task, write the timestamp ticket, schedule
     * what is left, purge the MP4 scratch, release the camera, and only then
     * leave the foreground.
     */
    private fun teardown() {
        try {
            // No session ran on an instance that never took the claim (a
            // failed start, a stop sent to an idle service): nothing to stop,
            // close or purge.
            if (ownsSession) closeSession()
        } catch (t: Throwable) {
            // Whatever failed, the service must still leave the foreground and
            // release the session; the queue keeps whatever was written.
            Timber.e(t, "teardown failed")
        } finally {
            // 5. Release the camera and leave the foreground, on the main
            //    thread.
            android.os.Handler(Looper.getMainLooper()).post { finishTeardown() }
        }
    }

    private fun closeSession() {
        val wiped = { StreamUploadManager.wipeGeneration() != wipeGenerationAtStart }

        // 1. The recorder's stop() returns once every chunk it produced has
        //    been handed over (onChunkReady returned). It runs on its own
        //    thread so that a wedged encoder cannot hold the closure for
        //    ever: past the safety bound the report is closed anyway, and a
        //    chunk delivered later is counted lost.
        // Under the lock: once this read is done no recorder can start any
        // more (the camera listener checks stopRequested under the same lock).
        val recorder = synchronized(lifecycleLock) { hevcRecorder }
        if (recorder != null) {
            val stopper = Thread({
                try {
                    if (!recorder.stop()) {
                        Timber.w("recorder stop returned with deliveries still running")
                    }
                } catch (e: Exception) {
                    Timber.e(e, "Error stopping recorder")
                }
                // A recorder built but never started (the stop came while the
                // camera was binding) still holds its GL thread, its EGL
                // context and its encoders; this frees them. It does nothing
                // for a recorder that ran.
                try {
                    recorder.release()
                } catch (e: Exception) {
                    Timber.w(e, "recorder release failed")
                }
            }, "recorder-stop")
            stopper.start()
            try {
                stopper.join(RECORDER_STOP_BOUND_MS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            if (stopper.isAlive) {
                Timber.e("recorder stop exceeded its safety bound — closing the report anyway")
            }
        }

        // 2. The closure: the writer's last task. Everything the recorder
        //    delivered is already queued ahead of it. A report the init thread
        //    is still opening is waited for first, so that this teardown is
        //    the one that closes it, in the foreground and under the wake lock.
        try {
            if (!openingDone.await(OPENING_WAIT_MS, TimeUnit.MILLISECONDS)) {
                Timber.e("report opening still running past its bound")
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        val p = synchronized(lifecycleLock) {
            acceptingChunks = false
            producer
        }
        var writerIdle = true
        val closeResult: ReportProducer.CloseResult? = p?.let {
            val (result, idle) = closeReport(it)
            writerIdle = idle
            result
        }
        authExecutor.shutdown()

        when (closeResult) {
            is ReportProducer.CloseResult.Closed -> {
                scheduleEnvelope(closeResult.envelope)
                writeTimestampTicket(closeResult.info)
                Timber.tag("StreamMetrics").i(
                    "reportClosed objects=%d lost=%d", closeResult.info.objectCount.toInt(), losses.total
                )
            }
            ReportProducer.CloseResult.Interrupted -> if (!wiped()) {
                // The key went without a closure: every object stays verifiable
                // on its own, the end of the recording is not certified.
                StreamUploadManager.unlessWipedSince(wipeGenerationAtStart) {
                    StreamPreferences.addReportAlert(this, 1, recordingStartMs, ReportAlerts.Reason.INTERRUPTED)
                }
            }
            ReportProducer.CloseResult.Aborted, null -> Unit
        }
        // Every loss so far, in one alert; the chunks cut off by giving up on
        // the closure are in it (closeReport waited for the writer to report
        // them). A loss counted after this point is written on its own
        // (persistLateLoss).
        val bulkLost = losses.close()
        StreamUploadManager.unlessWipedSince(wipeGenerationAtStart) {
            StreamPreferences.addReportAlert(this, bulkLost, recordingStartMs, ReportAlerts.Reason.CAPTURE_LOST)
        }

        // 3. Whatever is still queued gets a job, then the session summary.
        try {
            scheduleUpload()
        } catch (e: Exception) {
            Timber.w(e, "final scheduling failed (the sweep retries)")
        }
        try {
            val pendingAtStop = envelopeQueue?.pendingChunksOfSession(sessionId) ?: -1
            rs.readahead.washington.mobile.util.jobs.UploadSessionStats
                .summarize(pendingAtStop, detectNetworkType())
        } catch (e: Exception) {
            Timber.tag("StreamMetrics").w(e, "sessionSummary failed")
        }

        // 4. Scratch safety net, after the closure, so no seal is still
        //    waiting for an MP4: secure-delete every MP4 left in the chunk
        //    directory, any size. A finalized chunk whose seal never ran is
        //    footage in the clear, readable off a seized device, and nothing
        //    else sweeps it. debug_raw is deliberately NOT purged here — it is
        //    purged at the next service start (so the operator can pull the
        //    raw clips after a stop). (Phase 3.7 + F-01, cross-audit 2026-06-30.)
        //
        //    A non-empty MP4 still here is, in practice, a chunk that will
        //    never be sealed: the one a recorder stuck past its bound was
        //    still writing, or one a drain never delivered. It is counted
        //    lost. Not while the writer is still busy: it may be sealing one
        //    of them, and reports that chunk itself. The rare MP4 whose own
        //    deletion failed after its seal would be counted too.
        try {
            val chunkDir = org.stream.crypto.capture.CaptureScratchCleaner.defaultChunkDir(this)
            val unsealed = if (writerIdle) {
                org.stream.crypto.capture.CaptureScratchCleaner.nonEmptyChunkCount(chunkDir)
            } else 0
            org.stream.crypto.capture.CaptureScratchCleaner.purgeOrphanChunks(chunkDir)
            if (unsealed > 0 && !wiped()) {
                Timber.tag("StreamMetrics").w("chunkLost count=%d reason=never_delivered", unsealed)
                persistLateLoss(losses.onLoss(unsealed))
            }
        } catch (e: Exception) {
            Timber.w(e, "CaptureScratchCleaner.purgeOrphanChunks failed at teardown")
        }

        // Drop the adaptive quality manager so an upload worker that runs
        // after this point doesn't keep mutating stale recording-session state.
        org.stream.crypto.capture.AdaptiveQualityHolder.clear()

        // DO NOT clear UploadAuthHolder here. Clearing it on every stop made
        // every creation still pending at stop time fail with
        // `no_auth_token` (repro 2026-05-14 in-vivo, Phase 3.35): sending the
        // queue after the user stops recording is the expected behaviour. The
        // bearer is dropped on every path that should drop privileges: the
        // Lock button, the drain-gated V2LockTimeoutController, panicWipe(),
        // and process death (it lives in a Zeroizing holder inside Rust,
        // process-local, nothing on disk). Audit R-01 (no on-disk JWT) holds.
        //
        // Only this service's non-secret issuance clock is reset.
        authTokenIssuedAtMs = 0L
    }

    /**
     * Submit the closure as the writer's last task and wait for it, bounded
     * by [CLOSE_WAIT_MS]. Past the bound the closure is given up
     * ([ReportProducer.abort]): the chunks still queued behind it can no longer
     * be sealed and are reported lost, which this waits for, briefly, so the
     * bulk alert includes them. A closure that was in fact written while the
     * abort waited for the writer is still taken as written.
     *
     * Returns the outcome, and whether the writer thread is idle at the end.
     */
    private fun closeReport(p: ReportProducer): Pair<ReportProducer.CloseResult, Boolean> {
        val future = p.submitClose()
        val result = try {
            future.get(CLOSE_WAIT_MS, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            Timber.e("closure not written in time — giving it up")
            p.abort()
            null
        } catch (e: Exception) {
            Timber.e(e, "closure task failed")
            p.abort()
            null
        }
        val idle = p.awaitIdle(ABORT_DRAIN_MS)
        if (result != null) return result to idle
        val late = if (future.isDone) {
            try {
                future.get()
            } catch (e: Exception) {
                null
            }
        } else null
        return (if (late is ReportProducer.CloseResult.Closed) late else ReportProducer.CloseResult.Interrupted) to idle
    }

    /**
     * Last step, on the main thread. A normal stop does NOT wipe the V2
     * ratchet — only an explicit lock() / panicWipe() does. Never add one here
     * "for hygiene": a ratchet locked at the end of every recording leaves the
     * envelopes that still need a bearer waiting until the user re-enters the
     * PIN.
     */
    private fun finishTeardown() {
        hevcRecorder = null
        // A destroyed SurfaceView's Surface must not be re-used next time.
        hevcPreviewSurface = null
        cameraProviderRef = null
        previewRef = null
        producer = null
        try {
            lifecycleRegistry.currentState = Lifecycle.State.DESTROYED
        } catch (e: Exception) {
            Timber.w(e, "lifecycle teardown")
        }
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        try {
            androidx.core.app.ServiceCompat.stopForeground(
                this, androidx.core.app.ServiceCompat.STOP_FOREGROUND_REMOVE
            )
        } catch (e: Exception) {
            Timber.w(e, "stopForeground")
        }
        // Teardown is complete: workers may act again (Phase H2-B.16).
        if (ownsSession) isShuttingDown = false
        synchronized(lifecycleLock) { teardownFinished = true }
        releaseClaimIfDone()
        // A pre-release test build requests an upload of its log now (it
        // leaves once a network is there), including the lines of a recording
        // that failed to start; a production build does nothing here.
        try {
            rs.readahead.washington.mobile.diagnostics.Diagnostics.onRecordingFinished(this)
        } catch (e: Exception) {
            Timber.w(e, "diagnostics upload request failed")
        }
        stopSelf()
    }

    override fun onDestroy() {
        Timber.d("StreamRecordingService destroyed")
        // Stopped from outside (stopService, the system) without a stop
        // request: run the same teardown. It continues after this method
        // returns, without the foreground status but with the wake lock, and
        // releases the wake lock when done.
        requestStop("destroyed")
        synchronized(lifecycleLock) { destroyCalled = true }
        releaseClaimIfDone()
        super.onDestroy()
    }

    /** A new session may start once this instance is torn down AND destroyed. */
    private fun releaseClaimIfDone() {
        val done = synchronized(lifecycleLock) { teardownFinished && destroyCalled }
        if (done && ownsSession) {
            ownsSession = false
            sessionClaim.set(false)
        }
    }

    /**
     * Opaque random session id : 16 bytes of CSPRNG, lowercase hex.
     *
     * Never put an identity prefix or a timestamp back into it. The id used to
     * be `<pk[..4]>_<unixSeconds>_<rand>`, which leaked the witness's identity
     * prefix AND the exact recording time **in the clear** to the relay via the
     * blob filenames (`<sessionId>_<seq>.strm`, plus, at the time, a sealed
     * `<sessionId>.fpm` and the `<sessionId>.ots`) — undermining the E2E
     * sealing, and contradicting "a relay seizure exposes nothing" on every
     * surface where object names travel (MinIO backups, nginx URL logs, bucket
     * listings).
     *
     * Keep it lowercase hex: the local envelope names are built from it, and
     * EnvelopeNames accepts nothing else for a chained session (that is what
     * keeps them apart from the legacy names, which start with `L`).
     *
     * On the relay a chained report's objects are named by their seq alone
     * (`000001.strm`); the id names the local envelopes, and otherwise travels
     * only inside the encrypted session metadata (`sessionId`, from which the
     * opt-in timestamp's salt is derived), as the recording time does
     * (`startedAt`). (§10.11, MAJEUR-2, 2026-06-25.)
     */
    private fun generateSessionId(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun buildSessionMetadata(): String {
        val json = JSONObject()
        json.put("version", 1)
        json.put("sessionId", sessionId)
        json.put("startedAt", java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'",
            java.util.Locale.US).format(java.util.Date()))
        json.put("triggerMethod", "manual")
        json.put("chunkIntervalMs", DEFAULT_CHUNK_INTERVAL_MS)
        return json.toString()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Stream Recording",
                NotificationManager.IMPORTANCE_LOW).apply {
                description = "Active when streaming encrypted video"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    /**
     * Format `mm:ss` ou `h:mm:ss` selon durée.
     * Aucun padding `0h` quand recording < 1h pour rester compact dans la
     * notification (qui est tronquée à ~40 chars sur la plupart des launchers).
     */
    private fun formatElapsed(ms: Long): String {
        val totalSec = ms / 1000
        val h = totalSec / 3600
        val m = (totalSec % 3600) / 60
        val s = totalSec % 60
        return if (h > 0) String.format("%d:%02d:%02d", h, m, s)
            else String.format("%02d:%02d", m, s)
    }

    /**
     * Construit le texte notification depuis l'état courant.
     * Format : `Streaming... 12 chunks • 01:05` (`h:mm:ss` au-delà d'une heure).
     * Avant le start camera, recordingStartMs == 0L → on n'affiche pas le
     * timer (juste `Starting stream...`). Le refresher Handler tique 1Hz et
     * appelle cette méthode pour faire bouger le timer en continu.
     */
    private fun refreshNotification() {
        // Watch the free space on this 1 Hz tick: before a full disk starts
        // failing chunk writes (silent loss) or the OS kills us uncleanly, stop
        // cleanly so the footage up to now is finalized + sealed. Probing
        // filesDir alone is enough, and no second threshold on cacheDir is
        // needed: filesDir and cacheDir share the internal /data partition, so
        // filesDir.usableSpace covers both the in-progress plaintext MP4
        // (cacheDir/stream_chunks) and the envelope queue (filesDir).
        // requestStop() runs hevcRecorder.stop() and closes the report, the
        // same clean path as a user stop; the isShuttingDown guard keeps a later
        // tick from re-entering it. Device-side analog of the HTTP 507
        // (server-full) path just below (Phase 8.1.6-#4b).
        val freeBytes = try { filesDir.usableSpace } catch (e: Exception) { Long.MAX_VALUE }
        if (recordingStartMs > 0L && !isShuttingDown &&
            freeBytes < DEVICE_STORAGE_CRITICAL_BYTES
        ) {
            Timber.tag("StreamMetrics").w(
                "deviceStorageCritical freeMb=%d - stopping recording cleanly",
                freeBytes / (1024L * 1024L)
            )
            try {
                updateNotification("Stockage de l'appareil plein — enregistrement arrêté")
            } catch (_: Exception) { }
            requestStop("storage")
            return
        }
        val text = if (recordingStartMs == 0L) {
            "Starting stream..."
        } else if (rs.readahead.washington.mobile.util.jobs.UploadCircuitBreaker.isDiskFull()) {
            // Phase 1.12 — server returned HTTP 507 (out of disk). Surface
            // it so the user can act (contact admin / free space).
            // Recording keeps going and blobs queue locally — they upload
            // once space frees, nothing is lost. This 1 Hz tick clears the
            // message automatically on the next successful upload.
            val backlog = envelopeQueue?.pendingChunksOfSession(sessionId) ?: 0
            "Server storage full — contact admin ($backlog queued)"
        } else {
            val elapsed = formatElapsed(System.currentTimeMillis() - recordingStartMs)
            val low = if (freeBytes < DEVICE_STORAGE_WARN_BYTES) " • stockage faible" else ""
            val lost = losses.total
            val lostText = if (lost > 0) {
                " • " + resources.getQuantityString(R.plurals.stream_chunks_lost, lost, lost)
            } else ""
            "Streaming... ${chunksEncrypted.get()} chunks • $elapsed$low$lostText"
        }
        try {
            updateNotification(text)
        } catch (e: Exception) {
            Timber.w(e, "refreshNotification failed (service likely stopping)")
        }
        // Phase 3.7 — push a HUD update every notif tick (1Hz) so the
        // counter follows worker uploads in real-time, not just chunk
        // production. Cheap : just reads chunksEncrypted + listFiles() on
        // the queue dir.
        if (recordingStartMs > 0L) {
            broadcastChunkUpdate()
            // Feed the current backlog to the adaptive
            // quality manager so it can gate upgrades while we're behind.
            // This session's chunks only: envelopes of other reports don't
            // drive the quality decisions for this one.
            val pending = envelopeQueue?.pendingChunksOfSession(sessionId) ?: 0
            org.stream.crypto.capture.AdaptiveQualityHolder.setBacklog(pending)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(this, 0,
            Intent(this, StreamActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

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
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun broadcastChunkUpdate() {
        // Mirror to the static last-known counters so the activity can recover
        // the value at onResume even if the broadcast was dropped while it was
        // paused. `uploaded` is derived from `sealed - pending - refused` at
        // broadcast time rather than counted at enqueue (Phase 3.7: a counter
        // bumped at each scheduling pass climbed quadratically during an
        // outage). Pending is read from the queue (one cached listing per
        // second at most); a chunk the relay refused for good leaves the queue
        // for the failed directory and must not show as sent.
        val encrypted = chunksEncrypted.get()
        // This session's chunks only: envelopes of earlier recordings are
        // still sent, but they don't drive this session's HUD.
        val pending = envelopeQueue?.pendingChunksOfSession(sessionId) ?: 0
        val refused = envelopeQueue?.failedChunksOfSession(sessionId) ?: 0
        val uploaded = org.stream.crypto.upload.HudCounters.delivered(encrypted, pending, refused)
        val lost = losses.total
        lastChunksEncrypted = encrypted
        lastChunksUploaded = uploaded
        lastChunksLost = lost
        val intent = Intent(ACTION_CHUNK_UPDATE).apply {
            putExtra(EXTRA_CHUNKS_ENCRYPTED, encrypted)
            putExtra(EXTRA_CHUNKS_UPLOADED, uploaded)
            putExtra(EXTRA_CHUNKS_LOST, lost)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    /**
     * Push the active quality to the HUD. Sent both at
     * recording start (so the indicator shows the initial level) and on
     * every adaptive change.
     */
    private fun broadcastQualityUpdate(quality: org.stream.crypto.capture.StreamQuality) {
        lastQualityLabel = quality.displayLabel
        val intent = Intent(ACTION_QUALITY_UPDATE).apply {
            putExtra(EXTRA_QUALITY_LABEL, quality.displayLabel)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }
}
