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
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.stream.crypto.capture.ChunkEncoderBundle
import org.stream.crypto.capture.RollingChunkRecorder
import org.stream.crypto.capture.StreamChunkEncryptor
import org.stream.crypto.upload.ChunkUploadQueue
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.activity.StreamActivity
import timber.log.Timber
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * Foreground service for continuous encrypted video streaming.
 *
 * Pipeline: CameraX (camera bind + preview) → GL wedge + MediaCodec
 * (RollingChunkRecorder) → MP4 chunks (5s) → StreamChunkEncryptor (Rust crypto
 * over UniFFI) → STRM blobs → upload queue
 */
class StreamRecordingService : Service(), LifecycleOwner {

    companion object {
        const val CHANNEL_ID = "stream_recording"
        const val NOTIFICATION_ID = 7777
        const val DEFAULT_CHUNK_INTERVAL_MS = 5000L
        const val DEFAULT_SERVER_URL = "https://relay.shake-document-protect.org:8443"

        // Device-side low-storage thresholds (free bytes on
        // the internal /data partition, checked on the 1 Hz notification tick).
        // Below WARN we surface a heads-up in the notification; below CRITICAL
        // we stop the recording cleanly (finalize + encrypt the current chunk)
        // before a full disk makes chunk writes fail silently or the OS kills us
        // uncleanly. CRITICAL is small but enough for a clean finalize (a 720p
        // HEVC chunk + its .strm blob is only a few MB).
        const val DEVICE_STORAGE_WARN_BYTES = 400L * 1024 * 1024      // 400 MB
        const val DEVICE_STORAGE_CRITICAL_BYTES = 100L * 1024 * 1024  // 100 MB

        // Broadcast actions for UI updates
        const val ACTION_CHUNK_UPDATE = "org.stream.CHUNK_UPDATE"
        const val EXTRA_CHUNKS_ENCRYPTED = "encrypted"
        const val EXTRA_CHUNKS_UPLOADED = "uploaded"

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

        /** Reset by the service when a new recording session starts. */
        fun resetCounters() {
            lastChunksEncrypted = 0
            lastChunksUploaded = 0
            lastQualityLabel = "720p"
        }

        /**
         * Process-local "is a recording session live ?"
         * flag, read by [rs.readahead.washington.mobile.util.jobs.
         * OrphanSweepWorker] so it can yield to an active recording
         * (avoiding auth/upload races on the ratchet slot pool).
         * Volatile + JvmStatic so cross-thread reads from the worker
         * see the latest value without needing the service binder.
         */
        @Volatile @JvmStatic
        var isRunning: Boolean = false
            private set

        /**
         * Never let [isRunning] flip to false before this flag is true, and
         * never merge the two : `isShuttingDown` is raised at the very top
         * of [onDestroy], before `isRunning = false`, and only goes back to
         * false on the last line of [onDestroy]. Workers
         * ([ChunkUploadWorker.ensureFallbackReAuth],
         * [rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker])
         * gate on `isRunning || isShuttingDown`, written literally that
         * way, so the entire teardown window is covered — not just the
         * instant where `isRunning` flips. Teardown here means the final
         * queue-drain attempt, the chunkEncryptor close and the
         * hevcRecorder + GL/encoder/muxer release.
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
         * Clearing it on the last line matters too : a new service
         * instance, or a parallel orphan sweep running after this one is
         * fully dead, has to start from a clean flag.
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
         * Do not fold this into [pendingChunks] as a duplicate : it mirrors
         * the same count, but [pendingChunks] is a private instance field
         * and the service-less [V2LockTimeoutController] cannot read it,
         * hence a process-scoped copy. The controller defers two teardown
         * actions while this is > 0 — the upload-JWT auto-clear and the
         * ratchet auto-lock. A chunk mid-encryption is not yet in the
         * upload queue and so is invisible to that controller's
         * queue-pending guard : that is the gap that strands the last chunk
         * on `no_auth_token` (ROADMAP 2.2.6).
         */
        @JvmStatic
        private val encryptionsInFlightCounter = AtomicInteger(0)

        @JvmStatic
        fun encryptionsInFlight(): Int = encryptionsInFlightCounter.get()
    }

    // Lifecycle for CameraX
    private val lifecycleRegistry = LifecycleRegistry(this)

    override fun getLifecycle(): Lifecycle = lifecycleRegistry

    private var wakeLock: PowerManager.WakeLock? = null
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
    private var chunkEncryptor: StreamChunkEncryptor? = null

    // §10.11 — provenance : hash SHA-256 de chaque chunk EN CLAIR, keyé par
    // seqNum (l'ordre du Merkle ne dépend pas de l'ordre de fin des threads
    // d'encryption). `provenanceActive` est un snapshot pris au démarrage de
    // session (toggle ON + signer chargé) → cohérent sur tout l'enregistrement.
    private val provenanceChunkHashes = java.util.concurrent.ConcurrentHashMap<Int, ByteArray>()
    @Volatile private var provenanceActive: Boolean = false
    private var uploadQueue: ChunkUploadQueue? = null

    // Revised H2-B §Bugs #5 — CameraX refs promoted to fields by
    // [startCamera]. They no longer serve to rebind the camera (a quality
    // swap is done in place by the recorder) : [applyQuality] reads them
    // only as a readiness signal — non-null means the initial startCamera
    // bind ran. Reset to null in onDestroy so a late callback can't work on
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

    private var sessionId: String = ""
    private val chunksEncrypted = AtomicInteger(0)
    // Compteur des Threads d'encryption en cours : onChunkReady lance un
    // Thread pour encrypter chaque chunk MP4, et onDestroy attend que ce
    // compteur retombe à 0 avant de nettoyer le chunkDir. Ce n'est pas un
    // compteur de confort — sans cette attente, le cleanup efface des MP4 dont
    // le chiffrement n'a pas encore rendu de blob, donc des chunks perdus à
    // l'arrêt (Phase 2.1.5).
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
     * Names of the blobs already passed to `WorkManager.enqueueUniqueWork`,
     * so `scheduleUpload` doesn't re-enqueue the whole pending list every
     * time a new chunk is produced.
     *
     * This set MUST be emptied on NetworkCallback recovery — the
     * `onAvailable` path calls `enqueuedBlobNames.clear()`. Without that
     * reset, a worker that has FAILED, or whose ENQUEUED state was just
     * cancelled, can never be re-enqueued and the whole backlog stays stuck
     * until the process dies.
     *
     * The set is not there for correctness : `ExistingWorkPolicy.KEEP`
     * already makes a re-enqueue a no-op on the WorkManager side. It is
     * there for the cost, because `scheduleUpload` walks the entire pending
     * list on every chunk produced and each call is an IPC roundtrip + a SQL
     * hit on the WorkManager DB. With 200 pending blobs (long outage) and 1
     * new chunk every 5 s, that's 200 IPC + 200 SQL hits per 5 s = 40 IPC/s
     * baseline on Seeker (low-end MTK, contributed to thermal observed
     * 2026-05-18), O(N²) over the outage window. With the set, each new blob
     * costs at most 1 IPC call. Read that before dismissing it as an obscure
     * micro-optimisation sitting in front of an already idempotent API
     * (Blue MED-4, Phase H2-B.15).
     *
     * Thread-safety : ConcurrentHashMap.newKeySet, accessed from
     * `scheduleUpload` (Thread bg from onChunkReady) and from the
     * NetworkCallback path (binder thread).
     */
    private val enqueuedBlobNames =
        java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    // 2026-05-09 — retry initServerSession au network-up (cas : recording
    // démarré offline, wifi arrive plus tard). Cooldown 30s pour ne pas
    // épuiser le batch de clés éphémères : chaque authenticateV2() consomme
    // 1 slot/50 du batch courant.
    @Volatile private var lastAuthAttemptMs: Long = 0L
    private val AUTH_RETRY_COOLDOWN_MS = 30_000L
    // Never cache the bearer JWT here as a String field. It lives in a
    // Zeroizing holder inside Rust (stashed by verify()) and the upload path
    // pulls a transient "Bearer <jwt>" from it via UploadAuthHolder.get() ;
    // keeping a copy "to save an FFI roundtrip" puts the bearer back in the JVM
    // heap and reopens the heap-dump finding (§10.6, 2026-06-13). What this
    // service keeps is `authTokenIssuedAtMs` below : a non-secret "do we have
    // an auth session" signal (> 0L) plus refresh clock.
    //
    // There is no server-assigned report id any more (Phase C, relay-blind
    // reports). `reportId` is the phrase-derived, identity-free report address
    // (reportKeyring.reportIdHex(reportIndex)), allocated locally at session
    // start, with no network involved — do not add a "create report" POST, it
    // would break both the offline start and the relay's blindness. The record
    // is created lazily by the metadata blob's first PUT. `reportId` itself is
    // only kept as a presence signal : the uploadKicker tick and maybeRetryAuth
    // check it is non-null before doing anything. Addressing goes through
    // `reportIndex` everywhere — both the chunk upload path and the opt-in
    // provenance .ots upload carry the index and re-derive the id + signatures
    // inside Rust from the live keyring.
    //
    // @Volatile is load-bearing on `reportId` and on the auth-session signal
    // (authTokenIssuedAtMs, below) : both are written on the init thread
    // (Thread { initServerSession() } from onStartCommand) and read from at
    // least three other threads :
    //   - the main-looper notification refresher / uploadKicker tick
    //   - the NetworkCallback (onAvailable runs on the binder pool)
    //   - the onChunkReady encryption thread that fires scheduleUpload
    // Without @Volatile the JMM doesn't guarantee the readers see the value the
    // init thread wrote ; a reader left on a stale null simply never starts an
    // upload, with no exception and no crash (Phase 3.36).
    @Volatile private var reportId: String? = null

    // Phase C — the report's derivation index n for this session (report_id =
    // reportKeyring.reportIdHex(n)). Allocated once at session start via
    // StreamPreferences.allocateReportIndexForSession (atomic + idempotent on
    // sessionId). Passed to ChunkUploadWorker, which re-derives the capability
    // (report_id + 0x07/0x08 signatures) inside Rust from the live reportKeyring.
    // -1 until allocated.
    @Volatile private var reportIndex: Int = -1

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

    // NetworkCallback proper, déclenché par le système au moment
    // exact où une nouvelle network VALIDATED devient disponible. Plus rapide
    // que le polling à chaque chunk (5s) et beaucoup plus léger en CPU. Le
    // cooldown 30s sur maybeRetryAuth() est conservé pour éviter de hammer
    // auth si le réseau flap (wifi qui se connecte / déconnecte vite).
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null

    // Notification persistante format complet
    // (`Streaming... 12 chunks • 00:01:05`). recordingStartMs est posé quand
    // hevcRecorder.start() OK (premier instant où "le recording tourne
    // vraiment"). Le notificationRefresher tique toutes les 1s pour que le
    // timer affiché bouge même entre deux chunks (chunk = 5s).
    @Volatile private var recordingStartMs: Long = 0L
    // Set this flag in onDestroy BEFORE the `removeCallbacks()` calls, and
    // keep the `if (isDestroyed) return` at the top of every Handler
    // runnable. removeCallbacks looks sufficient on its own and is not : a
    // runnable already mid-`run()` when onDestroy calls remove re-schedules
    // a NEW task with the postDelayed at the end of run(), one the prior
    // removeCallbacks didn't cover. That task keeps the destroyed service's
    // runnable alive, logging stale snapshots and broadcasting stale HUD
    // counters from the dead instance. Nothing crashes, no test turns red.
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
                if (recordingStartMs > 0L && authTokenIssuedAtMs > 0L && reportId != null) {
                    // Only count current-session blobs.
                    // Orphans don't trigger a kick.
                    val pending = uploadQueue?.getPendingCountForSession(sessionId) ?: 0
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
    // glFrameRate cadence). Cleanup symétrique dans onDestroy (Phase H2-B.8).
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
            val pending = uploadQueue?.getPendingCountForSession(sessionId) ?: -1
            val totalOnDisk = uploadQueue?.getPendingCount() ?: -1
            val orphans = (totalOnDisk - pending).coerceAtLeast(0)
            val quality = org.stream.crypto.capture.AdaptiveQualityHolder
                .get()?.currentQuality?.displayLabel ?: "?"
            val cap = rs.readahead.washington.mobile.util.jobs
                .UploadConcurrencyLimiter.currentCap()
            val net = detectNetworkType()
            val elapsedSec = (System.currentTimeMillis() - recordingStartMs) / 1000
            Timber.tag("StreamMetrics").i(
                "snapshot t=%ds quality=%s cap=%d backlog=%d orphans=%d encrypted=%d uploaded=%d networkType=%s",
                elapsedSec, quality, cap, pending, orphans,
                chunksEncrypted.get(), lastChunksUploaded, net,
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
        // Mark service as running so OrphanSweepWorker
        // yields its tick instead of racing for auth slots.
        isRunning = true
        // Defensive clear. Normally `onDestroy` of the
        // previous instance has already reset `isShuttingDown` to false
        // (at the very end, after teardown), but if a brand-new
        // service instance starts before the prior one's onDestroy
        // fully completed (uncommon but legal), clearing here ensures
        // workers don't see a stale "shutdown in progress" indicator.
        isShuttingDown = false
        // Fresh session : drop any stray in-flight count a
        // prior crashed instance might have left non-zero.
        encryptionsInFlightCounter.set(0)

        // CRITIQUE — Bug 2026-05-09 reproduit in-vivo therealshulgin :
        // ForegroundServiceDidNotStartInTimeException kill le process si
        // startForeground() n'est pas appelé < 5s après startForegroundService().
        // Hardening : startForeground EN PREMIER, avant TOUT autre init.
        // Aucun appel JNI / IO / réseau / DB avant. Tout le reste va dans
        // un Thread bg qui ne peut pas faire planter le main thread.

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
            stopSelf()
            return START_NOT_STICKY
        }

        Timber.d("StreamRecordingService — startForeground OK at %d", System.currentTimeMillis())

        // 3. Tout le reste de l'init dans un Thread bg avec try/catch global.
        //    Si quoi que ce soit throw (uploadManager null, NPE,
        //    encryptMetadata fail, etc.), on log + stopSelf — pas de
        //    propagation d'exception qui kill le process.
        Thread {
            try {
                initializePipelineFromOnStart()
            } catch (e: Exception) {
                Timber.e(e, "Pipeline init failed — stopping service")
                stopSelf()
            }
        }.start()

        return START_STICKY
    }

    /**
     * Sépare le pipeline init lourd (encryption, server auth, camera bind)
     * du onStartCommand. Appelé depuis un Thread bg pour ne jamais bloquer
     * le main thread > 5s (qui ferait crasher le process avec
     * ForegroundServiceDidNotStartInTimeException).
     */
    private fun initializePipelineFromOnStart() {
        // Wake lock
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "frappuccino:stream")
        wakeLock?.acquire(4 * 60 * 60 * 1000L)

        // V2 live streaming uses chunk capture (no legacy vault provider).
        // `isUnlocked()` est le bon predicate.
        val uploadManager = StreamUploadManager.getInstance()
        if (uploadManager == null || !uploadManager.isUnlocked()) {
            Timber.e("StreamUploadManager not unlocked — cannot stream")
            stopSelf()
            return
        }

        sessionId = generateSessionId()

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
        // report creation became lazy (minted by the seq-0 PUT), so the re-arm
        // stopped firing without anything failing. Do not fold it back into
        // another call for tidiness. It is idempotent and cannot throw.
        uniffi.frappuccino.uploadTransportRearm()

        uploadQueue = ChunkUploadQueue(this)

        // allocateReportIndexForSession is atomic + idempotent on sessionId, so
        // a process restart mid-session reuses the same n (never a 2nd report).
        // Don't replace it with a direct derivation and don't move the call :
        // the blobs already handed to the relay are addressed to the report_id
        // of the first n, and a second n would leave them attached to nothing.
        // The derivation is LOCAL (no network: works offline, unlike the old
        // report-creation POST it replaces), so don't put a connectivity check
        // or a retry in front of it either. The server-side record is created
        // lazily by the metadata blob's first PUT (seq 0 = creation).
        //
        // reportKeyring is loaded at unlock (mirror of provenanceSigner); if it
        // is somehow absent on an unlocked manager (best-effort reload failed)
        // we can't address a report — bail cleanly, rather than record chunks
        // that could not be attached to anything. That is deliberately harsher
        // than OrphanSweepWorker, which defers and retries in the same
        // situation. (Phase C, relay-blind reports.)
        val reportKeyring = uploadManager.reportKeyring
        if (reportKeyring == null) {
            Timber.e("Phase C: reportKeyring absent on unlocked manager — cannot derive report, stopping")
            stopSelf()
            return
        }
        val reportEntry = org.stream.crypto.StreamPreferences.allocateReportIndexForSession(
            this, sessionId
        ) { n -> reportKeyring.reportIdHex(n.toUInt()) }
        reportIndex = reportEntry.reportIndex
        reportId = reportEntry.reportId
        Timber.i(
            "Phase C: session %s → report index %d (id %s…)",
            sessionId, reportIndex, reportId?.take(8) ?: "?"
        )
        // Phase C — append this index to the report directory so the rescue can
        // read the authoritative n_max and enumerate reports EXACTLY (no
        // hole-tolerance guess). Idempotent per index (unique work), retried by
        // WorkManager; serves the rescue, not the live upload.
        scheduleDirectoryEntry(reportIndex)

        // Transport plan, ROADMAP §10.9 Gate 0 — start the
        // per-session upload counters and log the active TCP congestion
        // control. The sender governs upload throughput, so this is the
        // datum that tells us whether field chunk-loss is CC-bound (cubic
        // collapsing under loss) or not. Logging-only, no behaviour change.
        rs.readahead.washington.mobile.util.jobs.UploadSessionStats
            .startSession(sessionId)

        // Never cancel this work by tag. `cancelAllWorkByTag` also kills
        // RUNNING workers — including those currently mid-PUT — as it did when
        // the user tapped REC : their retry counter bumps and after 3 cycles
        // the OrphanSweepWorker secure-deletes the blob, costing legitimate
        // user data. It also cancels the ENQUEUED workers belonging to the
        // orphan_sweep tag (Phase 3.26-B), which directly undoes the
        // OrphanSweepWorker's own scheduling work from the prior tick. Only
        // ENQUEUED `stream_chunk_upload` workers that are NOT part of an
        // orphan sweep may be cancelled at session start.
        //
        // The anti-pattern was explicitly forbidden by Phase 3.12 and was
        // re-introduced once anyway ; Phase 3.36 is the ENQUEUED filter plus
        // orphan_sweep exemption that replaced it. The reconnect path in
        // [registerNetworkCallback] iterates manually for the same reason —
        // note that one cancels every ENQUEUED entry, without the orphan_sweep
        // exemption made here.
        //
        // Clear WorkManager entries from previous sessions
        // (they reference the wrong reportId so they'd 404 forever),
        // BUT keep the blobs themselves on disk. We do NOT purge them
        // because they may represent rescuable user data (recording
        // stopped with a backlog, user starts a new session before the
        // backlog drained) : it is the WorkManager entries that are stale,
        // not the bytes. The HUD only counts current-session blobs
        // and scheduleUpload only enqueues current-session blobs, so
        // the orphans don't pollute the new session. They'll be
        // cleared by sweepStaleChunks below once their TTL elapses, or
        // by a future rescue path that re-authenticates against their
        // original report.
        try {
            val wm = androidx.work.WorkManager.getInstance(this)
            val infos = wm.getWorkInfosByTag("stream_chunk_upload").get()
            var cancelled = 0
            var preservedRunning = 0
            var preservedOrphan = 0
            for (info in infos) {
                val isOrphan = info.tags.contains("orphan_sweep")
                if (info.state == androidx.work.WorkInfo.State.ENQUEUED && !isOrphan) {
                    wm.cancelWorkById(info.id)
                    cancelled++
                } else if (info.state == androidx.work.WorkInfo.State.RUNNING) {
                    preservedRunning++
                } else if (isOrphan) {
                    preservedOrphan++
                }
            }
            wm.pruneWork()
            Timber.i(
                "[Phase 3.25/3.36] cleared %d ENQUEUED entries (RUNNING preserved=%d, orphan_sweep preserved=%d)",
                cancelled, preservedRunning, preservedOrphan,
            )
        } catch (e: Exception) {
            Timber.w(e, "[Phase 3.25/3.36] WorkManager cleanup failed (non-fatal)")
        }

        // Read the 48h bound from OrphanSweepWorker.PURGE_AGE_MS, never inline
        // a copy of it here : the StreamActivity at-risk banner derives its
        // warning window from that same constant, and a second copy would make
        // the banner announce a deadline that is no longer the one at which the
        // user's data is destroyed (Phase 3.26-E, single source of truth).
        //
        // Don't lengthen the TTL back towards the 7d it came from either.
        // Orphan blobs sitting unuploadable (no matching server-side report)
        // shouldn't keep ciphertext + nonces on disk for a week. 48h is
        // generous enough for a user to come back the next day and a half ;
        // beyond that, assume the data is lost and secure-delete to shrink the
        // forensic surface. Audit R-10 (originally 7d) is satisfied either
        // way ; the bound was tightened (Phase 3.25) once we knew that
        // accumulating blobs is normal in failure modes.
        uploadQueue?.sweepStaleChunks(
            rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker.PURGE_AGE_MS
        )

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

        // Reset les compteurs statiques pour que l'UI ne montre
        // pas des valeurs périmées d'une session précédente.
        chunksEncrypted.set(0)
        resetCounters()

        chunkEncryptor = uploadManager.createChunkEncryptor(File(cacheDir, "stream_encrypted"))

        // §10.11 — capture une fois si cet enregistrement est tracké pour la
        // provenance (toggle ON + signer chargé au unlock). Le hash par chunk
        // ET le manifeste de fin sont gatés sur ce snapshot, donc le périmètre
        // reste cohérent même si le toggle change pendant l'enregistrement.
        provenanceChunkHashes.clear()
        provenanceActive = org.stream.crypto.StreamPreferences.isProvenanceEnabled(this) &&
            uploadManager.provenanceSigner != null
        if (provenanceActive) Timber.d("Provenance tracking active for session %s", sessionId)

        // Encrypt + enqueue session metadata
        val metadata = buildSessionMetadata()
        val metaBlob = chunkEncryptor!!.encryptMetadata(metadata, sessionId)
        if (metaBlob != null) {
            uploadQueue!!.enqueue(metaBlob)
            scheduleUpload()
        }

        // Auth + report creation (network, ~1-3s), puis start camera sur main thread.
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
        //   à trois termes `authTokenIssuedAtMs > 0L && reportId != null &&
        //   UploadAuthHolder.isPresent()`.
        // - Cas offline : auth retourne sans token (catch dans
        //   initServerSession), callback registered ; quand réseau revient,
        //   callback fire onAvailable, maybeRetryAuth() voit
        //   `authTokenIssuedAtMs == 0L` (l'horloge n'est posée qu'au succès de
        //   l'auth), passe le cooldown (jamais set), retry → succès.
        // (Phase 2.4.2.)
        registerNetworkCallback()
        android.os.Handler(Looper.getMainLooper()).post {
            try {
                lifecycleRegistry.currentState = Lifecycle.State.STARTED
                lifecycleRegistry.currentState = Lifecycle.State.RESUMED
                startCamera()
            } catch (e: Exception) {
                Timber.e(e, "startCamera failed on main thread")
                stopSelf()
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
                        onChunkReady = { chunkFile, seqNum ->
                            onChunkReady(chunkFile, seqNum)
                        },
                        onError = { e ->
                            if (e is org.stream.crypto.capture.CaptureUnrecoverableException) {
                                // Fail-closed backstop (#2/N1): the capture pipeline
                                // can't recover (rotation failed MAX_ROTATION_FAILURES
                                // times). Stop cleanly on the main thread — stopSelf()
                                // drives onDestroy -> hevcRecorder.stop(), which
                                // finalizes + encrypts the in-flight clear chunk (via
                                // onChunkReady) instead of letting it grow unbounded,
                                // and tells the operator. Same clean path as a user
                                // stop / the device-storage-critical stop.
                                Timber.e(e, "[Phase H2-B.7] HEVC pipeline unrecoverable — stopping capture cleanly")
                                android.os.Handler(Looper.getMainLooper()).post {
                                    if (!isShuttingDown) {
                                        try {
                                            updateNotification("Erreur caméra — enregistrement arrêté (données sauvegardées)")
                                        } catch (_: Exception) { }
                                        stopSelf()
                                    }
                                }
                            } else {
                                Timber.e(e, "[Phase H2-B.7] HEVC pipeline error")
                            }
                        },
                    )
                    hevcRecorder = rec
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

                hevcRecorder!!.start()

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
            }
        }, ContextCompat.getMainExecutor(this))
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
                android.util.Range(24, 30)
            )
        return builder.build()
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

    private fun onChunkReady(chunkFile: File, seqNum: Int) {
        Timber.d("Chunk #%d ready: %s (%d bytes)", seqNum, chunkFile.name, chunkFile.length())

        // Mirror the chunk MP4 to
        // filesDir/debug_raw/ when fixed-bitrate mode is on. The HEVC
        // pipeline (RollingChunkRecorder) wires onChunkReady directly,
        // so the mirror happens here. Done synchronously, before kicking
        // the encryption thread, so the source file is still intact at
        // copy time.
        saveRawDebugCopyIfEnabled(chunkFile, seqNum)

        // Track les Threads d'encryption pour pouvoir attendre
        // leur fin dans onDestroy avant de cleanup le chunkDir. increment AVANT
        // de start le Thread pour qu'on ne rate aucun chunk même si onDestroy
        // arrive juste après.
        pendingChunks.incrementAndGet()
        encryptionsInFlightCounter.incrementAndGet()  // Phase 2.2.6 — mirror for V2LockTimeoutController

        // Encrypt on background thread
        val encThread = Thread {
            try {
                // §10.11 — hash le chunk EN CLAIR AVANT encryptChunk (qui le
                // secure-delete). On ne commit le hash dans la map QU'APRÈS un
                // encrypt réussi, pour que l'ensemble de chunks du manifeste
                // corresponde exactement au média qu'un vérificateur réassemble.
                // Best-effort : un échec de hash ne bloque jamais le pipeline.
                val provHash: ByteArray? = if (provenanceActive) {
                    try {
                        uniffi.frappuccino.provenanceHashPlaintextFile(chunkFile.absolutePath)
                    } catch (e: Exception) {
                        Timber.w(e, "provenance hash failed for chunk #%d (non-fatal)", seqNum)
                        null
                    }
                } else null

                val blob = chunkEncryptor?.encryptChunk(chunkFile, sessionId, seqNum)
                if (blob != null) {
                    if (provHash != null) provenanceChunkHashes[seqNum] = provHash
                    chunksEncrypted.incrementAndGet()
                    uploadQueue?.enqueue(blob)
                    broadcastChunkUpdate()

                    // 2026-05-09 — retry l'auth ici si elle a échoué au start
                    // (cas : recording démarré offline, wifi arrivé entretemps).
                    // Cooldown 30s pour ne pas épuiser le batch de clés
                    // éphémères : maybeRetryAuth() est appelé une fois par
                    // chunk, et tout authenticateV2() qui passe challenge()
                    // consomme 1 slot sur les 50 du batch courant, quelle que
                    // soit la suite (signAndAdvance est atteint avant le verify
                    // et avant la création du rapport). Le check réseau, lui,
                    // ne préserve aucun slot — un appel qui échoue dès
                    // challenge() n'en consomme pas — il sert à échouer vite ;
                    // voir le bloc de la sonde /health dans maybeRetryAuth.
                    maybeRetryAuth()

                    // Refresh proactif du JWT si proche de
                    // l'expiration (24h - 1h = 23h). Pour une session normale
                    // (<23h) c'est un no-op : juste 2 comparaisons d'entiers.
                    maybeRefreshJwt()

                    scheduleUpload()
                    // Pas d'updateNotification ici, le refresher
                    // 1Hz s'en charge ; ça évite un flush notification manager
                    // sur chaque chunk en plus du refresher périodique.
                }
            } catch (e: Exception) {
                Timber.e(e, "Encryption error for chunk #%d", seqNum)
            } finally {
                pendingChunks.decrementAndGet()
                encryptionsInFlightCounter.decrementAndGet()  // Phase 2.2.6 — mirror
            }
        }
        // Never move the two counter increments down into the thread body, and
        // never drop this catch. They are incremented ABOVE on purpose, so that
        // onDestroy's drain and the V2LockTimeoutController can never miss a
        // chunk that races their read between the increment and the thread
        // actually starting. But if Thread.start() itself throws — OOM "unable
        // to create native thread" under memory pressure — the body's finally
        // never runs, so the counters would stay >0 forever: onDestroy spins to
        // its deadline and encryptionsInFlight() never returns to 0, wedging the
        // lock-timeout controller (and delaying auto-lock). Rolling the
        // pre-increments back on a failed start is what preserves liveness; the
        // chunk file stays on disk. (WP-F2, L-6/L-7/F-B1.)
        try {
            encThread.start()
        } catch (t: Throwable) {
            pendingChunks.decrementAndGet()
            encryptionsInFlightCounter.decrementAndGet()
            Timber.e(
                t,
                "onChunkReady: encryption thread start() failed for chunk #%d — counters rolled back",
                seqNum
            )
        }
    }

    /**
     * There is **no manifest, no signature, no sealing** here. Re-signing, or
     * storing a manifest, would not be finishing this path — it would break the
     * motto: attribution is on-demand at disclosure, never baked into a stored,
     * seizable artifact (a seizure exposes nothing). The ProvenanceSigner this
     * function fetches is there to derive the salt, not to sign anything. The
     * only thing that may leave the device is the opt-in `.ots` proof.
     *
     * At recording stop, computes the salted OTS commitment over the media Merkle
     * root and, if the witness opted into timestamping, submits it to the relay
     * (§10.11, the lean "hash + Bitcoin" design). Best-effort — never blocks or
     * breaks the stop path. The commitment is built only if every encrypted chunk
     * was hashed (size match), so the media root covers exactly the uploaded
     * media; relaxing that check yields a root that matches nothing verifiable,
     * so an incomplete set is skipped instead.
     */
    private fun maybeSubmitProvenanceTimestamp() {
        if (!provenanceActive) return
        val mgr = StreamUploadManager.getInstance() ?: return
        val signer = mgr.provenanceSigner ?: return
        val encryptedCount = chunksEncrypted.get()
        if (provenanceChunkHashes.isEmpty() || provenanceChunkHashes.size != encryptedCount) {
            Timber.w(
                "Provenance: hash count %d != chunk count %d for %s — skipping",
                provenanceChunkHashes.size, encryptedCount, sessionId
            )
            return
        }
        try {
            val orderedHashes = provenanceChunkHashes.toSortedMap().values.toList()
            // SHA-256(salt ‖ chunk_merkle_root(hashes)) — the ONLY provenance
            // artifact now. The root is recomputable from the disclosed chunks at
            // verify time, so nothing is sealed or stored.
            val commitment = uniffi.frappuccino.provenanceOtsCommitment(
                orderedHashes, recordingIdFor(sessionId), signer
            )
            // Opt-in trustless timestamp: submit the salted commitment to the
            // relay (which stamps it via the OpenTimestamps calendars). Default
            // OFF — a `.ots` is a permanent public Bitcoin breadcrumb.
            maybeScheduleProvenanceTimestamp(sessionId, commitment)
        } catch (e: Exception) {
            Timber.w(e, "provenance commitment failed (non-fatal)")
        }
    }

    /** §10.11 — deterministic 16-byte recording id derived from the sessionId. */
    private fun recordingIdFor(sessionId: String): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(sessionId.toByteArray(Charsets.UTF_8))
            .copyOf(16)

    /**
     * §10.11 Phase B (slice 2) — schedule the opt-in trustless timestamp for this
     * recording. Gated on the per-recording toggle (default OFF), an auth
     * session, and a report. Submits the salted OTS commitment (computed in Rust
     * from the Merkle root of the chunk hashes, salted from the provenance seed
     * and the recording id — there is no manifest and no signature) to the relay.
     */
    private fun maybeScheduleProvenanceTimestamp(sessionId: String, commitment: ByteArray) {
        if (!org.stream.crypto.StreamPreferences.isProvenanceTimestampEnabled(this)) return
        if (commitment.isEmpty()) {
            Timber.w("Provenance TS: empty commitment for %s, skipping", sessionId)
            return
        }
        if (authTokenIssuedAtMs == 0L) {
            Timber.d("Provenance TS: no auth session, skipping for %s", sessionId)
            return
        }
        // Phase C — the .ots upload is a relay-blind capability write; carry the
        // report's derivation index n (the worker re-derives the report_id).
        val idx = reportIndex
        if (idx < 0) {
            Timber.d("Provenance TS: no report index, skipping for %s", sessionId)
            return
        }
        val commitmentHex = commitment.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        scheduleProvenanceTimestamp(sessionId, commitmentHex, idx)
    }

    /**
     * §10.11 Phase B (slice 2) — enqueue a unique WorkManager chain:
     *   1. [ProvenanceTimestampWorker] POSTs the commitment and writes the
     *      returned `.ots` to `filesDir/stream_provenance/<sid>.ots`.
     *   2. on its success, the chained [ProvenanceUploadWorker] makes that `.ots`
     *      durable on the relay (and secure-deletes the local copy).
     * Keyed on the `.ots` blob name (KEEP) so re-runs are idempotent.
     */
    private fun scheduleProvenanceTimestamp(sessionId: String, commitmentHex: String, reportIndex: Int) {
        try {
            val otsBlobName = "$sessionId.ots"
            val otsPath = File(File(filesDir, "stream_provenance"), otsBlobName).absolutePath
            val constraints = androidx.work.Constraints.Builder()
                .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED)
                .build()
            val stampReq = androidx.work.OneTimeWorkRequest.Builder(
                rs.readahead.washington.mobile.util.jobs.ProvenanceTimestampWorker::class.java
            )
                .setConstraints(constraints)
                .setInputData(
                    rs.readahead.washington.mobile.util.jobs.ProvenanceTimestampWorker.buildInputData(
                        commitmentHex = commitmentHex,
                        serverUrl = DEFAULT_SERVER_URL,
                        sessionId = sessionId,
                        otsFilePath = otsPath,
                    )
                )
                .setBackoffCriteria(
                    androidx.work.BackoffPolicy.EXPONENTIAL,
                    10, java.util.concurrent.TimeUnit.SECONDS
                )
                .addTag("stream_provenance_timestamp")
                .addTag(sessionId)
                .build()
            val uploadReq = androidx.work.OneTimeWorkRequest.Builder(
                rs.readahead.washington.mobile.util.jobs.ProvenanceUploadWorker::class.java
            )
                .setConstraints(constraints)
                .setInputData(
                    rs.readahead.washington.mobile.util.jobs.ProvenanceUploadWorker.buildInputData(
                        filePath = otsPath,
                        serverUrl = DEFAULT_SERVER_URL,
                        reportIndex = reportIndex,
                        blobName = otsBlobName,
                    )
                )
                .setBackoffCriteria(
                    androidx.work.BackoffPolicy.EXPONENTIAL,
                    10, java.util.concurrent.TimeUnit.SECONDS
                )
                .addTag("stream_provenance_upload")
                .addTag(sessionId)
                .build()
            androidx.work.WorkManager.getInstance(this)
                .beginUniqueWork(otsBlobName, androidx.work.ExistingWorkPolicy.KEEP, stampReq)
                .then(uploadReq)
                .enqueue()
            Timber.i("Provenance timestamp scheduled: %s → report idx %d", otsBlobName, reportIndex)
        } catch (e: Exception) {
            Timber.w(e, "provenance timestamp scheduling failed (non-fatal) for %s", sessionId)
        }
    }

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
                            // - scheduleUpload() = re-enqueue the
                            //   filesystem-backed pending. A re-PUT of
                            //   identical bytes is a server-side no-op, so
                            //   a concurrent worker finishing on its own is
                            //   harmless.
                            rs.readahead.washington.mobile.util.jobs
                                .UploadCircuitBreaker.reset()
                            try {
                                val wm = androidx.work.WorkManager
                                    .getInstance(this@StreamRecordingService)
                                val infos = wm.getWorkInfosByTag(
                                    "stream_chunk_upload"
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
                            // worker that may have FAILED (or whose
                            // ENQUEUED state was just cancelled above) can
                            // be re-enqueued by the upcoming
                            // scheduleUpload(). Without this, the set
                            // would block all retries indefinitely
                            // until process death.
                            enqueuedBlobNames.clear()
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
            cm.registerNetworkCallback(request, cb)
            networkCallback = cb
            Timber.d("[Phase 2.4.2] NetworkCallback registered")
        } catch (e: Exception) {
            Timber.e(e, "[Phase 2.4.2] Failed to register NetworkCallback — fallback polling")
        }
    }

    private fun unregisterNetworkCallback() {
        try {
            val cb = networkCallback ?: return
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE)
                as android.net.ConnectivityManager
            cm.unregisterNetworkCallback(cb)
            Timber.d("[Phase 2.4.2] NetworkCallback unregistered")
        } catch (e: Exception) {
            Timber.w(e, "[Phase 2.4.2] Failed to unregister NetworkCallback")
        }
        networkCallback = null
    }

    /**
     * Ne pas baisser ni retirer le cooldown de 30 s : il ne sert pas qu'à
     * ménager le relais, il dédoublonne deux sources d'appel qui peuvent tirer
     * quasi simultanément — le `NetworkCallback.onAvailable` (Phase 2.4.2,
     * instantané au reconnect) et le polling de repli depuis `onChunkReady`
     * (Phase 2.4.1, gardé au cas où le callback ne fire pas). Sans lui, une
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
     * scheduleUpload() — cette fonction ne l'appelle pas elle-même — et le
     * pending de la session courante part alors sur le réseau.
     */
    private fun maybeRetryAuth() {
        // Never simplify the guard below to `authTokenIssuedAtMs > 0 &&
        // reportId != null`: the isPresent() term is the only thing that makes
        // a 401 taken mid-session recoverable. Gap C (2026-06-15) — such a 401
        // (server-side JWT_SECRET rotated, or token blacklisted / expired
        // early) clears the Rust-held bearer (UploadAuthHolder.clear →
        // UPLOAD_JWT zeroize) but does NOT reset authTokenIssuedAtMs, the
        // worker having no handle on the service. Drop the term and
        // maybeRetryAuth sees "already authed" and returns.
        //
        // What that costs is narrower than every chunk, and worth stating
        // exactly. Only the creation chunk (seq 0) carries the bearer; later
        // chunks authorise purely by write-sig and cross no auth gate at all
        // (see ChunkUploadWorker), and the relay asks for a JWT only while the
        // report record does not exist yet (server/app/routes/upload.py). A 401
        // landing after the report is created therefore costs the chunk path
        // nothing. One landing before it stalls seq 0 on no_auth_token — and
        // with it the record — so every other chunk of the session comes back
        // 425 "Report not yet created" and waits on disk. Either way nothing
        // re-authenticates until the recording stops: the workers defer to the
        // service through ensureFallbackReAuth's `isRunning || isShuttingDown`
        // gate. With isPresent(), a cleared holder re-drives the full re-auth
        // here.
        //
        // Re-driving it is safe on three counts. Phase C — initServerSession is
        // now auth-only (the report is derived + persisted at session start,
        // created lazily by the metadata PUT), so re-invoking it only refreshes
        // the ephemeral JWT and can never mint a second report; reportId is
        // already non-null from start, it just confirms the session is fully
        // initialised. It is bounded by AUTH_RETRY_COOLDOWN_MS +
        // isRelayReachable below. And only the service re-auths while it runs
        // (the worker keeps deferring), so there is no slot-pool race —
        // invariant H2-B.16 preserved. isPresent() (not get()) keeps the bearer
        // out of the JVM heap (heap-0, §10.6).
        if (authTokenIssuedAtMs > 0L && reportId != null &&
            rs.readahead.washington.mobile.util.jobs.UploadAuthHolder.isPresent()
        ) return  // déjà OK
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
     * Ce que le refresh avant T-1h protège, c'est le PUT de création d'un
     * rapport ouvert au-delà de l'expiration. Sur le chemin des CHUNKS, le
     * bearer ne sert qu'au chunk de création (seq 0) ; les suivants
     * s'autorisent uniquement par write-sig, sans aucune garde d'auth, et le
     * relais ne réclame un JWT que tant que l'enregistrement du rapport
     * n'existe pas. Un JWT périmé ne fait donc pas échouer les workers de chunk
     * déjà en queue : il fait repartir la création sur un 401 → fail → backoff.
     *
     * Ne pas en déduire que le chunk de création est le seul consommateur du
     * bearer : d'autres workers en dépendent, entre autres DirectoryEntryWorker
     * (l'entrée d'index 0, celle qui crée le rapport d'annuaire) et
     * ProvenanceTimestampWorker (soumission .ots), qui se mettent en retry tant
     * que UploadAuthHolder n'a rien à leur donner.
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
            Timber.i("[Phase 2.4.3] JWT refresh OK (batch=%d remaining=%d)",
                manager.currentBatchNumber(), manager.remainingKeysInBatch())
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
     * Appends this session's allocated index to the report directory, a
     * singleton phrase-derived report (Phase C, relay-blind reports).
     *
     * An entry's relay-visible blob name must stay the opaque, secret-derived
     * `keyring.directoryEntryNameHex(n)` (M-1), never the plain index: the
     * index is what would turn the directory into a session counter a blind
     * relay can read straight off. The same rule governs the entry's body,
     * written just below.
     *
     * The directory is what gives the rescue an authoritative `n_max`:
     * `list_blobs(directory)` yields the opaque names, the witness re-derives
     * `directoryEntryNameHex(0..)` and matches them back, and reports `0..n_max`
     * are then enumerated exactly instead of guessing where to stop — see
     * [DirectoryEntryWorker] for why guessing truncates the recovery. One tiny
     * write-once entry per session, enqueued here at index allocation so
     * `n_max` is always ≥ any created report; the worker creates the directory
     * on index 0 and appends
     * otherwise, retried by WorkManager, idempotent per index via unique work.
     *
     * Best-effort: a failure here must never block recording. It only degrades
     * the rescue to its dense-enumeration fallback, so do not turn the catch
     * below into a fatal error.
     */
    private fun scheduleDirectoryEntry(index: Int) {
        try {
            val filename = rs.readahead.washington.mobile.util.jobs
                .DirectoryEntryWorker.localStagingName(index)
            val dir = File(cacheDir, "directory_entries").apply { mkdirs() }
            val entryFile = File(dir, filename)
            if (!entryFile.exists() || entryFile.length() == 0L) {
                // M-1 — the body must NOT carry the index: it is uploaded
                // UNSEALED and the relay stores it in cleartext, so writing `n`
                // here would re-leak the session count/cadence the opaque NAME
                // just closed. The rescue never reads a directory entry body (it
                // recovers n_max by derive-and-match over NAMES), so the body is
                // a single constant byte — only needed because the relay rejects
                // empty uploads. Constant (not random) keeps write-once re-PUTs
                // byte-identical on retry.
                entryFile.writeBytes(byteArrayOf(0x01))
            }
            val req = androidx.work.OneTimeWorkRequest.Builder(
                rs.readahead.washington.mobile.util.jobs.DirectoryEntryWorker::class.java
            )
                .setConstraints(
                    androidx.work.Constraints.Builder()
                        .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED)
                        .build()
                )
                .setInputData(
                    rs.readahead.washington.mobile.util.jobs.DirectoryEntryWorker.buildInputData(
                        filePath = entryFile.absolutePath,
                        serverUrl = DEFAULT_SERVER_URL,
                        reportIndex = index,
                    )
                )
                .setBackoffCriteria(
                    androidx.work.BackoffPolicy.EXPONENTIAL,
                    10, java.util.concurrent.TimeUnit.SECONDS
                )
                .addTag("stream_directory_entry")
                .build()
            androidx.work.WorkManager.getInstance(this)
                .enqueueUniqueWork(
                    "directory_entry_$filename",
                    androidx.work.ExistingWorkPolicy.KEEP,
                    req,
                )
            Timber.d("Phase C: directory entry %d scheduled", index)
        } catch (e: Exception) {
            Timber.w(e, "Phase C: scheduleDirectoryEntry failed (non-fatal) for index %d", index)
        }
    }

    private fun scheduleUpload() {
        // §10.6 — gate on the auth-session signal being present
        // locally (no point enqueueing if the session has no auth). The bearer
        // itself lives in the Rust holder; on the chunk path nothing pulls a
        // copy of it into the JVM. The worker only reads the existence bit
        // (UploadAuthHolder.isPresent()), and for the creation chunk alone Rust
        // attaches the bearer from its own holder during the PUT — do not
        // introduce an UploadAuthHolder.get() call here.
        if (authTokenIssuedAtMs == 0L) return
        // Phase C — the chunk path carries the report's derivation index n; the
        // worker re-derives the identity-free report_id from the live keyring.
        val idx = reportIndex
        if (idx < 0) return
        // Only enqueue blobs that belong to the current
        // session. Orphans from previous sessions stay on disk (they
        // may be rescuable later, audit R-10 sweep eventually removes
        // them at TTL) but would fail under the wrong report index here.
        val pending = uploadQueue?.getPendingForSession(sessionId) ?: return

        for (blob in pending) {
            // Blue MED-4 fix. Skip if we already
            // enqueued this blob since the last NetworkCallback
            // recovery. WorkManager's KEEP policy would have made the
            // call a no-op anyway, but we save the IPC + SQL hit. On
            // recovery, `enqueuedBlobNames.clear()` is called in the
            // `onAvailable` callback so workers that may have FAILED
            // can be re-enqueued.
            if (!enqueuedBlobNames.add(blob.name)) {
                continue
            }
            val workRequest = androidx.work.OneTimeWorkRequest.Builder(
                rs.readahead.washington.mobile.util.jobs.ChunkUploadWorker::class.java
            )
                .setConstraints(
                    androidx.work.Constraints.Builder()
                        .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED)
                        .build()
                )
                .setInputData(
                    rs.readahead.washington.mobile.util.jobs.ChunkUploadWorker.buildInputData(
                        filePath = blob.absolutePath,
                        serverUrl = DEFAULT_SERVER_URL,
                        reportIndex = idx
                    )
                )
                // Backoff EXPONENTIAL 10s base au lieu de
                // LINEAR 30s. Sur réseau pourri, LINEAR 30s constant fait
                // que tous les workers d'une cohorte retry en cluster toutes
                // les 30s → surcharge réseau quand le serveur revient.
                // EXPONENTIAL 10s : 10s, 20s, 40s, 80s, ... cappé à 5h par
                // WorkManager. Plus rapide à récupérer (10s) si la coupure
                // était courte ; plus relax à long terme (évite le poll
                // inutile sur device en mode avion 2h).
                .setBackoffCriteria(
                    androidx.work.BackoffPolicy.EXPONENTIAL,
                    10, java.util.concurrent.TimeUnit.SECONDS
                )
                // Manual jitter on initial enqueue. WorkManager
                // doesn't expose a jitter knob, but `setInitialDelay`
                // randomized over a short window decorrelates a cohort
                // of workers that would otherwise hit the server in
                // lockstep after the same backoff bucket (R-08 audit
                // finding ; AWS Architecture Blog "Exponential Backoff
                // and Jitter", Marc Brooker 2015).
                .setInitialDelay(
                    (Math.random() * 3000L).toLong(),
                    java.util.concurrent.TimeUnit.MILLISECONDS
                )
                .addTag("stream_chunk_upload")
                .addTag(sessionId)
                .build()

            // Never replace enqueueUniqueWork(blob.name, KEEP) with a
            // plain enqueue(). scheduleUpload is re-run on every chunk
            // and on every reconnection, so without a unique key each
            // pass re-enqueues a fresh worker for every blob still
            // pending, and the worker count grows as O(N²) in the
            // number of chunks produced during an outage. The defect is
            // invisible on a short test — measured in vivo on
            // 2026-05-13 : 2 min wifi off → ~24 chunks pending → 301
            // ENQUEUED workers at the Phase 3.12 reconnect flush of the
            // network-recovery block above (= 24×25/2 = 300, ✓ math).
            //
            // KEEP, not REPLACE: KEEP keeps the existing worker if one
            // is already ENQUEUED/RUNNING for this filename and lets a
            // new one run if the previous terminated
            // (SUCCEEDED/FAILED/CANCELLED), where REPLACE would kill an
            // upload in flight. uniqueName is scoped per-blob and not
            // per-session, so independent chunks remain parallelisable
            // up to UploadConcurrencyLimiter.
            androidx.work.WorkManager.getInstance(this)
                .enqueueUniqueWork(
                    /* uniqueName = */ blob.name,
                    /* policy = */ androidx.work.ExistingWorkPolicy.KEEP,
                    /* workRequest = */ workRequest,
                )
        }
        // Phase 3.7 — un seul broadcast après l'enqueue de tout le pending,
        // au lieu d'un par blob. broadcastChunkUpdate() lit pendingCount
        // depuis le filesystem, donc la valeur reste cohérente.
        broadcastChunkUpdate()
        // La notification est rafraîchie par le refresher 1Hz,
        // pas besoin d'updateNotification manuel ici.
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
            // the chunk PUT path only the existence bit crosses the FFI
            // (UploadAuthHolder.isPresent()): the creation chunk (seq 0) has
            // Rust read the bearer, later chunks authorise by write-sig with no
            // bearer at all, so it never enters the JVM heap. One caller still
            // pulls a transient copy via UploadAuthHolder.get() — the
            // ProvenanceTimestampWorker, for the .ots submission. Nothing is
            // persisted by WorkManager (Audit R-01) and the JWT is never a
            // long-lived JVM String.
            Timber.i("V2 auth OK — batch=%d remaining=%d",
                manager.currentBatchNumber(), manager.remainingKeysInBatch())

            // Do not add a report-creation POST back here: its absence is
            // deliberate, not an oversight. The report is addressed by a
            // phrase-DERIVED id, allocated + persisted at session start in
            // initializePipelineFromOnStart (via
            // StreamPreferences.allocateReportIndexForSession) and created
            // lazily by the metadata blob's first PUT (seq 0, carrying the 0x07
            // create-sig + bearer). A session therefore has exactly one derived
            // report_id for its whole life, fixed before the first chunk is
            // ever enqueued, which makes the old split-report field bug
            // (2026-05-20: one session POSTing twice → chunks halved across two
            // report_ids) structurally impossible rather than merely avoided.
            // Deriving locally also removes the network dependency at start-up,
            // so a recording begun offline still gets its report id.
            // Phase C (relay-blind reports).
            //
            // initServerSession is auth-only as a result: it stays idempotently
            // re-runnable from maybeRetryAuth (offline-start recovery) and can
            // never mint a second report — there is nothing to mint.

        } catch (e: Exception) {
            Timber.e(e, "Failed to init V2 server session")
        }
    }

    override fun onDestroy() {
        Timber.d("StreamRecordingService stopping — flushing last chunk (Phase 2.1.5)")

        // Never let [isRunning] flip before this shutdown indicator. Workers
        // (ChunkUploadWorker.ensureFallbackReAuth, OrphanSweepWorker) gate on
        // `isRunning || isShuttingDown`, and only this order covers the entire
        // teardown window — until the final `isShuttingDown = false` at the
        // bottom of this method — instead of just the instant where [isRunning]
        // changes state. See the companion object doc on [isShuttingDown] for
        // the full bug rationale (Phase H2-B.16, Blue HIGH-6 fix, 2026-05-19 :
        // no_auth_token race observed on OnePlus 13 at 2026-05-19T00:14:34).
        isShuttingDown = true

        // Set this volatile flag before the removeCallbacks below, never after :
        // removeCallbacks does not stop an iteration already running on the main
        // looper, and that iteration posts a fresh task that survives onDestroy.
        // With the flag set first, it bails at its next `if (isDestroyed) return`
        // check instead. Otherwise the destroyed service keeps broadcasting stale
        // HUD counters and emitting snapshot metrics every 30 s, racing the next
        // service instance's broadcasts and making the UI flicker between the
        // real values and the zombie's "0/0" (Phase 3.47).
        isDestroyed = true

        // Mark the service stopped early in the teardown. Since
        // H2-B.16 this does NOT make the OrphanSweepWorker free to act on this
        // session's leftovers : combined with `isShuttingDown = true` just
        // above, workers that gate on `isRunning || isShuttingDown` defer
        // through the entire teardown, up to the final `isShuttingDown = false`.
        // The flag is set here so a parallel sweep tick that races onDestroy
        // sees the right state, not to open the door for it.
        isRunning = false

        // Stop le timer notification immédiatement, sinon il
        // peut continuer à tick sur le main looper après que le service est
        // détruit (et appeler updateNotification sur un context mort).
        notificationRefresher.removeCallbacks(notificationRefreshTask)
        // Symmetric stop of the upload kicker.
        uploadKicker.removeCallbacks(uploadKickerTask)
        // Symmetric stop of the device telemetry refresher.
        deviceTelemetryRefresher.removeCallbacks(deviceTelemetryTask)

        // Unregister le NetworkCallback avant flush pour ne plus
        // recevoir d'event onAvailable pendant onDestroy (qui pourrait
        // déclencher une auth pendant qu'on est en train de détruire les
        // ressources upload). Le ConnectivityManager fuit silencieusement les
        // callbacks non-unregistered jusqu'à kill du process.
        unregisterNetworkCallback()

        // Flush du dernier chunk au stop : finalize + encrypt + enqueue.
        // hevcRecorder.stop() draine le chunk in-flight de façon synchrone, il
        // doit donc être appelé depuis un thread != main et avec un join borné :
        // le join juste en dessous plafonne l'attente à 3,5 s, ce qu'un stop()
        // appelé directement ici ne permettrait pas. La suite se lit juste en
        // dessous — le chunk part en Thread d'encryption via onChunkReady, on
        // attend pendingChunks==0, puis scheduleUpload() final pour que le
        // dernier blob passe en queue WorkManager — et, plus bas dans
        // onDestroy, CaptureScratchCleaner.purgeOrphanChunks() secure-delete les
        // MP4 résiduels du chunkDir.
        //
        // En pratique <1s sur un device fluide. On bloque onDestroy pendant ce
        // temps plutôt que de rendre la main au risque de perdre le dernier
        // chunk : l'user attend la fin du recording qu'il vient lui-même de
        // demander (Phase 2.1.5).
        val flushThread = Thread {
            try {
                // Stop the HEVC recorder. Its
                // stop() drains the in-flight chunk synchronously and
                // delivers it via onChunkReady, so the downstream
                // encryption / upload flow is unaffected.
                hevcRecorder?.stop()
            } catch (e: Exception) {
                Timber.e(e, "Error stopping recorder")
            }
        }
        flushThread.start()
        try {
            flushThread.join(3500)  // 3s pour Finalize + 500ms marge
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        // Wait pour que les Threads d'encryption async se terminent. Ne pas
        // redescendre ce budget sous 3 s. pendingChunks est incrémenté avant le
        // Thread.start() et n'est décrémenté que dans le finally du Thread
        // d'encryption : attendre pendingChunks==0 couvre donc tout le corps du
        // try — encryption, enqueue, maybeRetryAuth, maybeRefreshJwt,
        // scheduleUpload. Ces étapes peuvent prendre :
        //   - encryption : 50-100 ms
        //   - enqueue + fsync queueDir : 50-200 ms (eMMC)
        //   - maybeRetryAuth : potentiellement un appel network
        //     (authenticateV2 sur recovery réseau juste avant stop)
        //     pouvant prendre 1-30 s
        //   - scheduleUpload : ~ms IPC vers WorkManager
        // 1.5 s était insuffisant quand maybeRetryAuth firait un
        // appel network juste au moment du stop → le dernier chunk
        // pouvait être abandonné (Phase H2-B.15, Blue HIGH-2 fix,
        // 2026-05-18 : timeout 1.5 s → 3 s). 3 s couvre les cas réalistes
        // sans bloquer trop longtemps l'utilisateur qui attend la fin de
        // session.
        val deadline = System.currentTimeMillis() + 3000
        while (pendingChunks.get() > 0 && System.currentTimeMillis() < deadline) {
            try { Thread.sleep(50) } catch (_: InterruptedException) { break }
        }
        if (pendingChunks.get() > 0) {
            Timber.w("Phase 2.1.5: %d encryption Threads still running at onDestroy timeout",
                pendingChunks.get())
        }

        // §10.11 (lean) — point du teardown où les chunks sont normalement tous
        // chiffrés + hashés ; calcule le commitment OTS (racine Merkle salée) et,
        // si opt-in, planifie l'horodatage. Attention, le drain ci-dessus est
        // borné à 3 s : s'il expire, les derniers chunks manquent au commitment.
        // Best-effort : ne bloque ni ne casse jamais le chemin d'arrêt.
        maybeSubmitProvenanceTimestamp()

        // Final flush — enqueue tout reste pending dans uploadQueue
        scheduleUpload()

        // Transport plan, ROADMAP §10.9 Gate 0 — emit the
        // per-session upload summary (logging-only). Snapshot the at-stop
        // pending count so a cubic-vs-bbr field comparison can see how far
        // behind the upload was when the user stopped. The WorkManager
        // drain continues after this point; this is an at-stop snapshot.
        try {
            val pendingAtStop = uploadQueue?.getPendingForSession(sessionId)?.size ?: -1
            rs.readahead.washington.mobile.util.jobs.UploadSessionStats
                .summarize(pendingAtStop, detectNetworkType())
        } catch (e: Exception) {
            Timber.tag("StreamMetrics").w(e, "sessionSummary failed")
        }

        // Teardown safety net for the chunkDir scratch: secure-delete every MP4
        // still present, ANY size, not just the 0-byte ones. A finalized chunk
        // whose encryption was interrupted or failed is footage left in the
        // clear, recoverable off a seized device, and nothing else sweeps it —
        // OrphanSweepWorker only walks the queued `.strm` blobs. "Failed" is
        // not hypothetical : encryptChunk() runs under a catch that only logs
        // (see onChunkReady), so an exception there leaves the MP4 behind even
        // though the drain completed normally.
        // Keep the call here, after the drain and with the recorder stopped, so
        // nothing live is being written: each delivered chunk's MP4 is already
        // secure-deleted right after encryption (StreamChunkEncryptor), and the
        // drain above gives in-flight encryptions a deadline to finish.
        // debug_raw is deliberately NOT purged here — it is purged at the next
        // service start (so the operator can pull the raw clips after a stop).
        // (Phase 3.7 + F-01, cross-audit 2026-06-30.)
        try {
            org.stream.crypto.capture.CaptureScratchCleaner.purgeOrphanChunks(
                org.stream.crypto.capture.CaptureScratchCleaner.defaultChunkDir(this)
            )
        } catch (e: Exception) {
            Timber.w(e, "CaptureScratchCleaner.purgeOrphanChunks failed at onDestroy")
        }
        // Null out the HEVC recorder ref so
        // a stale callback can't reach it. The recorder's stop() above
        // already released GL / encoders / muxer / AudioRecord.
        hevcRecorder = null
        // Clear cached preview Surface so a destroyed
        // SurfaceView's Surface can't be re-used at the next start().
        hevcPreviewSurface = null

        // FRAG-R1-7 — release the Rust UniFFI handle behind
        // StreamChunkEncryptor. Each instance pins an `Arc<Identity>` in
        // the Rust core; on process churn (start/stop cycles in the same
        // VM, e.g. multiple short recording sessions) the leak isn't a
        // secret-bearing one (the Arc owns public keys), but it
        // accumulates handles indefinitely. close() is idempotent and
        // wraps `ffiIdentity.destroy()` (see StreamChunkEncryptor.close()).
        try {
            chunkEncryptor?.close()
        } catch (e: Exception) {
            Timber.w(e, "chunkEncryptor.close() threw at onDestroy")
        }
        chunkEncryptor = null

        // Drop the adaptive quality manager so any upload
        // worker that runs after this point (re-enqueued retries, etc.)
        // doesn't keep mutating stale recording-session state.
        org.stream.crypto.capture.AdaptiveQualityHolder.clear()

        // DO NOT clear UploadAuthHolder here. The original Phase 3.13 cleared
        // it on every onDestroy "to collapse post-stop exposure to zero", but
        // that made every chunk still pending in the WorkManager queue at stop
        // time fail with `no_auth_token` — repro 2026-05-14 in-vivo :
        // recording stopped right after a forced backlog downgrade, 7 chunks
        // pending, 0 ever made it to the server. Draining the pending queue
        // after the user stops recording is the expected behaviour : that's
        // what the WorkManager survival story is for (Phase 3.35).
        // The JWT is already short-lived (24 h) and is dropped on every path
        // that should drop privileges :
        //   - the Lock button : lock() wipes the ratchet, and the call site
        //     clears the bearer right after (StreamSettingsActivity)
        //   - V2LockTimeoutController's drain-gated clear (fires once no chunk
        //     is encrypting and the queue is empty)
        //   - StreamUploadManager.panicWipe(), which clears the bearer itself
        //   - process death : the bearer lives in a Zeroizing holder inside
        //     Rust, process-local, nothing on disk
        // Audit R-01 fix (no on-disk persistence of the JWT) stays intact.

        // §10.6 (2026-06-13) — drop this service's auth-session signal. The
        // bearer itself no longer lives in the JVM at all (it is held in a
        // Zeroizing holder inside Rust, stashed by verify()), so there is no
        // String to null here — only the non-secret issuance clock. The Rust
        // holder is NOT cleared on onDestroy (Phase 3.35: a post-stop drain may
        // still need it); it is zeroized by the drain-gated
        // V2LockTimeoutController, by panicWipe(), and by the UI Lock gesture,
        // which calls UploadAuthHolder.clear() next to lock().
        // StreamUploadManager.lock() itself does not clear the bearer: the
        // ratchet auto-lock goes through lock() alone, so the bearer stays in
        // place there until the controller's separate clear.
        authTokenIssuedAtMs = 0L

        // Release CameraX refs so a stale callback fired
        // after onDestroy can't try to rebind on a dead service.
        cameraProviderRef = null
        previewRef = null

        lifecycleRegistry.currentState = Lifecycle.State.DESTROYED

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        // A normal stop does NOT wipe the V2 ratchet — only an explicit
        // lock() / panicWipe() does. Never add one here "for hygiene" : a
        // ratchet locked at the end of every recording leaves every chunk still
        // in the queue unuploadable until the user re-enters the PIN by hand.
        // As it stands, a surviving process's workers can re-auth cleanly via
        // their own authenticateV2 against the still-unlocked ratchet ; if the
        // process died and relaunched locked, recovery waits for the user to
        // re-open + re-PIN (then OrphanSweepWorker finishes the queued chunks).
        //
        // Teardown is complete at this point : chunkEncryptor closed,
        // hevcRecorder + GL/encoder released, final queue-drain attempt done —
        // which is why the flag is cleared here and not higher up. Workers then
        // exit their defer loop (Phase H2-B.16, Blue HIGH-6 fix, 2026-05-19).
        isShuttingDown = false

        super.onDestroy()
    }

    /**
     * Opaque random session id : 16 bytes of CSPRNG, hex, with no internal
     * `_` or `.`.
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
     * The ban on `_` and `.` is what keeps two parsers in another module
     * working : the `<id>_<seq>.strm` seq-parsing (ChunkUploadWorker) and the
     * `<id>_<seq>` → id grouping (OrphanSweepWorker.sessionIdOf,
     * last-underscore).
     *
     * The id is a purely opaque device-local correlation key for the upload
     * queue; the recording time now travels only inside the encrypted session
     * metadata blob (`startedAt`), never in a plaintext name.
     * (§10.11, MAJEUR-2, 2026-06-25.)
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
        // cleanly so the footage up to now is finalized + encrypted. Probing
        // filesDir alone is enough, and no second threshold on cacheDir is
        // needed: filesDir and cacheDir share the internal /data partition, so
        // filesDir.usableSpace covers both the in-progress plaintext MP4
        // (cacheDir/stream_chunks) and the encrypted .strm queue (filesDir).
        // stopSelf() drives onDestroy then hevcRecorder.stop(), the same clean
        // path as a user stop; the isShuttingDown guard keeps a later tick from
        // re-entering it. Device-side analog of the HTTP 507 (server-full) path
        // just below (Phase 8.1.6-#4b).
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
            stopSelf()
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
            val backlog = uploadQueue?.getPendingCountForSession(sessionId) ?: 0
            "Server storage full — contact admin ($backlog queued)"
        } else {
            val elapsed = formatElapsed(System.currentTimeMillis() - recordingStartMs)
            val low = if (freeBytes < DEVICE_STORAGE_WARN_BYTES) " • stockage faible" else ""
            "Streaming... ${chunksEncrypted.get()} chunks • $elapsed$low"
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
            // Current-session only ; orphans don't drive
            // the quality decisions for this session.
            val pending = uploadQueue?.getPendingCountForSession(sessionId) ?: 0
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
        // Mirror to the static last-known counters so the
        // activity can recover the value at onResume even if the broadcast
        // was dropped while the activity was paused.
        // Phase 3.7 : `uploaded` est dérivé de `encrypted - pending` plutôt
        // que d'un AtomicInteger incrémenté à l'enqueue (qui montait
        // quadratiquement pendant un wifi off, vu in-vivo 2026-05-10).
        // pendingCount lit le filesystem (cheap : listFiles() ~ms), c'est
        // la source de vérité de "ce qui n'a pas encore été uploadé".
        val encrypted = chunksEncrypted.get()
        // Current-session only. Orphan blobs from previous
        // sessions are kept on disk (rescuable, audit R-10) but they
        // don't drive this session's HUD or its `uploaded` derivation.
        val pending = uploadQueue?.getPendingCountForSession(sessionId) ?: 0
        val uploaded = (encrypted - pending).coerceAtLeast(0)
        lastChunksEncrypted = encrypted
        lastChunksUploaded = uploaded
        val intent = Intent(ACTION_CHUNK_UPDATE).apply {
            putExtra(EXTRA_CHUNKS_ENCRYPTED, encrypted)
            putExtra(EXTRA_CHUNKS_UPLOADED, uploaded)
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
