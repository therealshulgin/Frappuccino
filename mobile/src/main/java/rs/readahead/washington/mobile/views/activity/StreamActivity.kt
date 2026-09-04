package rs.readahead.washington.mobile.views.activity

import android.Manifest
import android.animation.ValueAnimator
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.hardware.SensorManager
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Vibrator
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.view.WindowManager
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.stream.crypto.StreamPreferences
import org.stream.crypto.capture.ShakeDetector
import org.stream.crypto.upload.ChunkUploadQueue
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.service.StreamRecordingService
import rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class StreamActivity : AppCompatActivity() {

    // On-screen preview for the HEVC
    // pipeline (the camera feeds GL, which double-draws each frame onto
    // this Surface). Hidden by default ; shown during a recording session.
    private lateinit var hevcPreviewSurfaceView: SurfaceView

    // Latest Surface delivered by the SurfaceView's SurfaceHolder.
    // Pushed to the service either at surfaceCreated time or, if the
    // service binds later, at onServiceConnected time. Cleared on
    // surfaceDestroyed so the service can't forward a dead Surface to
    // the GL pipeline.
    private var pendingHevcPreviewSurface: Surface? = null

    // Top HUD (recording-only)
    private lateinit var timerText: TextView
    private lateinit var recIndicator: TextView
    private lateinit var chunkStatus: TextView
    private lateinit var qualityIndicator: TextView

    // Idle-only decorations (wordmark removed — brand lives on PIN + about)
    private lateinit var idleScrim: View
    private lateinit var fingerprintText: TextView
    // Bandeau orange "ENRÔLEMENT EN ATTENTE" visible
    // uniquement en idle quand StreamPreferences.hasPendingEnrollment().
    private lateinit var enrollmentBanner: TextView
    // Bandeau orphelins : fragments en attente d'envoi depuis
    // trop longtemps (risque de purge 48h) ou déjà supprimés faute de réseau.
    // In-app only (choix threat-model : pas de notif système).
    private lateinit var orphanBanner: TextView

    // Toggle button (one for start + stop)
    private lateinit var recButton: View

    // Pulse animation. Idle = slow gentle breath (0.97↔1.03 / 1.5s).
    // Recording = faster, more pronounced energy pulse (1.0↔1.10 / 800ms).
    // Cancelled in onPause to avoid wasting frames in the background.
    private var recButtonPulseAnim: ValueAnimator? = null

    // True stealth: single-tap drops FLAG_KEEP_SCREEN_ON
    // so the system display timer turns the screen off naturally.
    // v2.3 — overlay noir pour effet visuel immédiat (timeout système 15s
    // est trop long pour l'UX "tap → noir tout de suite").
    private var hudGestureDetector: GestureDetector? = null
    private var isStealthMode = false
    private lateinit var settingsBtn: View
    private lateinit var stealthOverlay: View

    private var isRecording = false
    // 2026-05-09 — flag set pendant la fin de session pour bloquer les
    // double-tap REC qui crashent le process. Phase 2.1.5 flush bloque
    // onDestroy jusqu'à ~5s ; tant que ce délai n'est pas écoulé, un
    // nouveau startForegroundService déclenche
    // ForegroundServiceDidNotStartInTimeException côté Android 12+.
    private var isStopping = false
    // Debounce simple anti-double-click sur le bouton REC.
    private var lastRecClickTime = 0L
    private var recordingStartTime = 0L
    private val timerHandler = Handler(Looper.getMainLooper())
    private val recBlinkHandler = Handler(Looper.getMainLooper())
    private var shakeDetector: ShakeDetector? = null
    private lateinit var sensorManager: SensorManager

    private val chunkUpdateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val uploaded = intent?.getIntExtra(StreamRecordingService.EXTRA_CHUNKS_UPLOADED, 0) ?: 0
            val encrypted = intent?.getIntExtra(StreamRecordingService.EXTRA_CHUNKS_ENCRYPTED, 0) ?: 0
            val pending = encrypted - uploaded
            // Phase 3.7 : show uploaded/encrypted with arrow + check icon
            // when caught up. Orange when pending > 5 (~25 s of catchup
            // at default 5 s chunk interval) so the user spots a backlog
            // at a glance.
            chunkStatus.text = when {
                encrypted == 0 -> "0\u2191/0"
                pending <= 0 -> "$encrypted\u2191 \u2713"
                else -> "$uploaded\u2191/$encrypted"
            }
            val ctx = context ?: this@StreamActivity
            chunkStatus.setTextColor(
                if (pending > 5) ContextCompat.getColor(ctx, R.color.wa_orange)
                else android.graphics.Color.parseColor("#AAFFFFFF")
            )
        }
    }

    // Adaptive quality indicator updates.
    private val qualityUpdateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val label = intent?.getStringExtra(StreamRecordingService.EXTRA_QUALITY_LABEL)
            if (!label.isNullOrEmpty()) {
                qualityIndicator.text = label
            }
        }
    }

    private val CAMERA_PERMISSION_CODE = 100
    private val REQUIRED_PERMISSIONS = arrayOf(
        Manifest.permission.CAMERA,
        Manifest.permission.RECORD_AUDIO
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Fullscreen immersive
        window.setFlags(
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS
        )
        // V2 : empêche screenshots, apparition dans l'overview, capture d'écran à distance
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_stream)

        hevcPreviewSurfaceView = findViewById(R.id.hevcPreviewSurfaceView)
        hevcPreviewSurfaceView.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(holder: SurfaceHolder) {
                pendingHevcPreviewSurface = holder.surface
                streamService?.setHevcPreviewSurface(holder.surface)
            }
            override fun surfaceChanged(
                holder: SurfaceHolder, format: Int, width: Int, height: Int
            ) {
                // Diagnostic instrumentation (cover-fit 2.05× follow-up,
                // 2026-05-17) — log the SurfaceView buffer dims +
                // SurfaceView dp/px dims + DisplayMetrics so we can
                // correlate with eglQuerySurface(pw, ph) on the GL side
                // and isolate where the 2.05× factor comes from.
                val metrics = resources.displayMetrics
                timber.log.Timber.tag("StreamMetrics").i(
                    "hevcPreviewSurfaceChanged bufferW=%d bufferH=%d format=%d " +
                        "viewW=%d viewH=%d density=%.2f displayW=%d displayH=%d",
                    width, height, format,
                    hevcPreviewSurfaceView.width, hevcPreviewSurfaceView.height,
                    metrics.density,
                    metrics.widthPixels, metrics.heightPixels
                )
            }
            override fun surfaceDestroyed(holder: SurfaceHolder) {
                pendingHevcPreviewSurface = null
                streamService?.setHevcPreviewSurface(null)
            }
        })
        idleScrim = findViewById(R.id.idleScrim)
        timerText = findViewById(R.id.timerText)
        recIndicator = findViewById(R.id.recIndicator)
        chunkStatus = findViewById(R.id.chunkStatus)
        qualityIndicator = findViewById(R.id.qualityIndicator)
        fingerprintText = findViewById(R.id.fingerprintText)
        enrollmentBanner = findViewById(R.id.enrollmentBanner)
        recButton = findViewById(R.id.recButton)
        settingsBtn = findViewById(R.id.settingsBtn)
        stealthOverlay = findViewById(R.id.stealthOverlay)
        setupStealthGestures()

        // Phase 7.12 — pre-warm ProcessCameraProvider singleton.
        // L'instance est cached dans le static après le 1er call. Lancer ça
        // dès onCreate économise 200-500ms quand StreamRecordingService appelle
        // getInstance() au tap REC : sur les devices fluides on passe de
        // ~2-3s tap → premier chunk à ~800-1500ms. Fire-and-forget — pas de
        // listener, le second getInstance() depuis le service récupèrera
        // l'instance déjà résolue.
        androidx.camera.lifecycle.ProcessCameraProvider.getInstance(this)

        // Tap sur le bandeau ouvre Settings où le bouton
        // RÉESSAYER L'ENRÔLEMENT SERVEUR + statut d'enrôlement vivent.
        enrollmentBanner.setOnClickListener {
            startActivity(android.content.Intent(this, StreamSettingsActivity::class.java))
        }

        // Orphan fragments banner. Tap → detail dialog with a
        // "retry now" action. Hidden by default; refreshOrphanBanner() decides
        // visibility on each idle resume.
        orphanBanner = findViewById(R.id.orphanBanner)
        orphanBanner.setOnClickListener { showOrphanDialog() }

        // Ensure StreamUploadManager is initialized (fallback if onSuccessfulUnlock didn't run)
        ensureStreamInitialized()

        // Display identity fingerprint (idle-only decoration)
        val uploadManager = StreamUploadManager.getInstance()
        if (uploadManager != null && uploadManager.identity != null) {
            fingerprintText.text = uploadManager.identity!!.readableFingerprint()
        }

        // Les deux gardes de ce listener empêchent un crash de process : ne
        // retirer ni l'une ni l'autre. Android tue le process avec
        // ForegroundServiceDidNotStartInTimeException si un service démarré
        // par startForegroundService n'appelle pas startForeground dans les
        // 5 s, et un tap REC rapide enchaînait deux startForegroundService,
        // le second n'ayant plus le temps. D'où :
        //   1. isStopping bloque tout nouveau start tant que la session
        //      précédente n'a pas fini son onDestroy + son flush. Le flag est
        //      armé et relâché dans stopRecording, dont le commentaire porte
        //      le décompte du flush : changer l'un sans relire l'autre casse
        //      l'accord entre les deux.
        //   2. Debounce 800 ms pour les double-clicks accidentels.
        recButton.setOnClickListener {
            val now = System.currentTimeMillis()
            if (isStopping) {
                Toast.makeText(
                    this,
                    "Session précédente en cours de finalisation, attends 2-3s.",
                    Toast.LENGTH_SHORT
                ).show()
                timber.log.Timber.d("[REC] click ignored — isStopping=true")
                return@setOnClickListener
            }
            if (now - lastRecClickTime < 800L) {
                timber.log.Timber.d("[REC] click debounced (< 800ms)")
                return@setOnClickListener
            }
            lastRecClickTime = now

            if (isRecording) {
                stopRecording()
            } else {
                // Phase 7.12 — trace cold-start latency. Pour mesurer,
                // adb logcat | grep "Phase 7.12" et calculer le delta entre
                // "tap REC" et "chunk rotation started" (côté service,
                // StreamRecordingService). Ce second repère marque le
                // démarrage de la rotation, pas la disponibilité du premier
                // chunk chiffré : pour mesurer celle-ci, il faut d'abord
                // ajouter la trace correspondante.
                timber.log.Timber.d("[Phase 7.12] tap REC at %d", now)
                requestPermissionsAndStartRecording()
            }
        }

        // Settings
        findViewById<View>(R.id.settingsBtn).setOnClickListener {
            startActivity(android.content.Intent(this, StreamSettingsActivity::class.java))
        }

        // Shake-to-record (Phase 7.3 — toggle + sensitivity in Settings).
        // The detector is (re)built in onResume from the current pref so a
        // sensitivity change takes effect on return; it only listens when the
        // shake-to-record toggle is enabled.
        sensorManager = getSystemService(Context.SENSOR_SERVICE) as SensorManager
    }

    private val RC_PIN_UNLOCK = 200
    // Garde anti-boucle, ne pas retirer : onResume est rappelé au retour de
    // PinUnlockActivity, donc sans ce drapeau la branche LOCKED de
    // maybeLaunchPinUnlock relancerait l'écran de PIN indéfiniment. Il n'est
    // relâché que dans onActivityResult, une fois l'écran revenu.
    private var pinUnlockLaunched = false

    /**
     * Instancie StreamUploadManager s'il ne l'est pas déjà — filet de sécurité
     * pour le cas où onSuccessfulUnlock n'a pas tourné. Rien d'autre : l'état
     * du ratchet n'est pas testé ici. C'est maybeLaunchPinUnlock, appelé
     * depuis onResume (pour éviter les boucles — voir [pinUnlockLaunched]),
     * qui aiguille — LOCKED → PinUnlockActivity, pas d'identité V2 → retour à
     * OnBoardingActivity.
     *
     * Note : en V2 live streaming, le streamProvider legacy (VaultFile) n'est
     * plus wired — on capture directement depuis CameraX.
     */
    private fun ensureStreamInitialized() {
        StreamUploadManager.getInstance(this)
    }

    private fun maybeLaunchPinUnlock() {
        val manager = StreamUploadManager.getInstance(this)
        when {
            !manager.isEnrolled() -> {
                // Pas d'identité V2. Tella lock est déjà setup (puisqu'on est
                // ici après son unlock) → IS_ONBOARD_LOCK_SET=true skip le
                // setup Tella et va direct à mnemonic → V2 SetPin.
                val intent = android.content.Intent(
                    this,
                    rs.readahead.washington.mobile.views.activity.onboarding.OnBoardingActivity::class.java
                ).apply {
                    putExtra(rs.readahead.washington.mobile.util.IS_ONBOARD_LOCK_SET, true)
                    flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                            android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK
                }
                startActivity(intent)
                finish()
            }
            manager.isLocked() && !pinUnlockLaunched -> {
                pinUnlockLaunched = true
                startActivityForResult(
                    android.content.Intent(this, PinUnlockActivity::class.java),
                    RC_PIN_UNLOCK
                )
            }
            manager.isUnlocked() -> {
                // Prêt à streamer : affiche le fingerprint. L'info batch n'est
                // plus exposée dans l'UI — c'est une primitive interne, jamais
                // actionnable par l'utilisateur.
                manager.identity?.let { fingerprintText.text = it.readableFingerprint() }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == RC_PIN_UNLOCK) {
            pinUnlockLaunched = false
            if (resultCode != RESULT_OK) {
                // User cancelled unlock → finish StreamActivity
                Toast.makeText(this, R.string.stream_unlock_cancelled, Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    /**
     * (Re)build the shake detector from the current sensitivity
     * pref. Called from onResume so a sensitivity change in Settings takes
     * effect on return without restarting the activity.
     */
    private fun buildShakeDetector() {
        val threshold = ShakeDetector.thresholdFor(StreamPreferences.getShakeSensitivity(this))
        shakeDetector = ShakeDetector(sensorManager, joltThreshold = threshold) {
            runOnUiThread {
                if (!isRecording) {
                    // Vibrate to confirm shake trigger
                    try {
                        @Suppress("DEPRECATION")
                        (getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator)?.vibrate(200)
                    } catch (_: Exception) {}
                    Toast.makeText(this, R.string.stream_shake_detected, Toast.LENGTH_SHORT).show()
                    requestPermissionsAndStartRecording()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!isRecording) {
            // Honour the shake-to-record toggle + sensitivity:
            // rebuild from the current pref (picks up a Settings change) and
            // only listen when enabled.
            shakeDetector?.stop()
            if (StreamPreferences.isShakeToRecordEnabled(this)) {
                buildShakeDetector()
                shakeDetector?.start()
            }
            // Gentle breathing pulse so the button reads as
            // "ready / live" rather than "frozen". Active version starts
            // in startRecording().
            startIdleRecPulse()
        } else {
            startRecordingRecPulse()
        }
        // Déclenche PinUnlockActivity si locked (après résumé de l'activity)
        maybeLaunchPinUnlock()

        // OEM-killer feedback loop (2026-06-23) — if the system killed a
        // recording while we were away, surface the "run without restriction"
        // guide once for that kill (gated to unlocked + not recording).
        maybeWarnRecentKill()

        // Refresh visibility du bandeau enrollment selon
        // l'état pending courant. Aussi : consume le flag one-shot set
        // par EnrollmentRetryWorker en background pour notifier l'user
        // que son enrôlement vient d'aboutir.
        refreshEnrollmentBanner()
        // Surface orphan fragments at risk / deleted (in-app).
        refreshOrphanBanner()
        if (StreamPreferences.consumeEnrollmentSucceededFlag(this)) {
            Toast.makeText(
                this,
                getString(R.string.enrollment_succeeded_toast),
                Toast.LENGTH_LONG
            ).show()
        }

        // Re-sync chunk counter from the service's last-known
        // value — a broadcast may have been missed while the activity was
        // paused. Do not "align the code" by unregistering in onPause: the
        // receivers are registered in startRecording and unregistered in
        // stopRecording only, and nothing re-registers them in onResume, so an
        // unregister here would freeze the counter for the rest of the
        // session. Re-pull on resume.
        if (isRecording) {
            chunkStatus.text = "${StreamRecordingService.lastChunksUploaded}/${StreamRecordingService.lastChunksEncrypted}↑"
            // Coming back from stealth (power button →
            // unlock → onResume) : passe par exitStealthMode pour cacher
            // l'overlay noir + re-arm KEEP_SCREEN_ON proprement. Si on
            // n'est pas en stealth, exitStealthMode est un no-op (early
            // return sur isStealthMode false).
            if (isStealthMode) {
                exitStealthMode()
            } else {
                window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }
        }
    }

    /**
     * Visibility orchestrator pour le bandeau enrollment.
     * Visible UNIQUEMENT en idle ET si une preuve d'enrôlement est en
     * attente (cas onboarding offline). Pendant le recording, on garde
     * l'écran épuré (Blackmagic-style) — sans enrôlement serveur les
     * uploads échouent de toute façon, le compteur 0/N suffit à signaler.
     */
    private fun refreshEnrollmentBanner() {
        val pending = StreamUploadManager.getInstance(this).hasPendingServerEnrollment()
        enrollmentBanner.visibility =
            if (pending && !isRecording) View.VISIBLE else View.GONE
    }

    // -- Phase 3.26-E — orphan fragments banner (in-app, no notification) --
    //
    // Surfaces two states the user must not discover only by their footage
    // going missing: (1) AT-RISK = orphan blobs older than WARN_AGE_MS still
    // on disk, heading for the 48 h secure-delete; (2) DELETED = blobs the
    // rescue/TTL already purged. By therealshulgin's threat-model choice this is
    // IN-APP ONLY (a system notification would force POST_NOTIFICATIONS,
    // un-hiding the recording FGS notification during covert recording).

    private data class OrphanState(
        val deletedCount: Int,
        val deletedOldestMs: Long,
        val atRiskCount: Int,
        val atRiskOldestMs: Long,
    )

    private fun computeOrphanState(): OrphanState? {
        val deletions = StreamPreferences.getOrphanDeletions(this)
        val deletedCount = deletions.sumOf { it.count }
        val deletedOldest = deletions
            .mapNotNull { if (it.oldestBlobMs > 0L) it.oldestBlobMs else null }
            .minOrNull() ?: 0L

        var atRiskCount = 0
        var atRiskOldest = 0L
        // At-risk only matters if auto-upload is ON. If the user opted out,
        // they chose to let orphans expire — a warning would contradict that.
        if (StreamPreferences.isAutoUploadOrphansEnabled(this)) {
            val pending = try {
                ChunkUploadQueue(this).getPending()
            } catch (e: Exception) {
                emptyList()
            }
            // Only count blobs actually past the warning age. A fresh backlog
            // still draining normally must NOT raise a false "at risk" alarm
            // (counting all pending would inflate the number and erode trust
            // in the warning — the opposite of this feature's intent).
            val now = System.currentTimeMillis()
            val atRisk = pending.filter {
                (now - it.lastModified()) >= OrphanSweepWorker.WARN_AGE_MS
            }
            if (atRisk.isNotEmpty()) {
                atRiskCount = atRisk.size
                atRiskOldest = atRisk.minOf { it.lastModified() }
            }
        }
        return if (deletedCount <= 0 && atRiskCount <= 0) null
        else OrphanState(deletedCount, deletedOldest, atRiskCount, atRiskOldest)
    }

    private fun refreshOrphanBanner() {
        if (isRecording) {
            orphanBanner.visibility = View.GONE
            return
        }
        // Only when unlocked: enforce the "read AFTER unlock" invariant (the
        // banner/dialog detail must never surface while the PIN screen is up
        // over this FLAG_SECURE activity) and skip a disk scan for a banner
        // that would stay hidden anyway.
        if (!StreamUploadManager.getInstance(this).isUnlocked()) {
            orphanBanner.visibility = View.GONE
            return
        }
        val state = computeOrphanState()
        if (state == null) {
            orphanBanner.visibility = View.GONE
            return
        }
        // Deleted (irreversible) takes banner priority over at-risk; the
        // dialog still shows both. Red = deleted, amber = at-risk.
        if (state.deletedCount > 0) {
            orphanBanner.text = getString(R.string.orphan_banner_deleted, state.deletedCount)
            orphanBanner.setBackgroundColor(android.graphics.Color.parseColor("#CC1A1A"))
        } else {
            orphanBanner.text = getString(R.string.orphan_banner_at_risk, state.atRiskCount)
            orphanBanner.setBackgroundColor(android.graphics.Color.parseColor("#E0A300"))
        }
        orphanBanner.visibility = View.VISIBLE
    }

    private fun showOrphanDialog() {
        val state = computeOrphanState() ?: return
        val sb = StringBuilder()
        if (state.atRiskCount > 0) {
            sb.append(
                getString(
                    R.string.orphan_dialog_at_risk,
                    state.atRiskCount,
                    formatOrphanDate(state.atRiskOldestMs),
                    formatOrphanDate(state.atRiskOldestMs + OrphanSweepWorker.PURGE_AGE_MS),
                )
            )
        }
        if (state.deletedCount > 0) {
            if (sb.isNotEmpty()) sb.append("\n\n")
            sb.append(
                getString(
                    R.string.orphan_dialog_deleted,
                    state.deletedCount,
                    formatOrphanDate(state.deletedOldestMs),
                )
            )
        }
        val builder = androidx.appcompat.app.AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.orphan_dialog_title)
            .setMessage(sb.toString())
        if (state.atRiskCount > 0) {
            builder.setPositiveButton(R.string.orphan_action_retry) { _, _ ->
                OrphanSweepWorker.triggerManualRescue(applicationContext)
                Toast.makeText(this, R.string.orphan_retry_toast, Toast.LENGTH_SHORT).show()
            }
        }
        if (state.deletedCount > 0) {
            builder.setNeutralButton(R.string.orphan_action_ack) { _, _ ->
                StreamPreferences.clearOrphanDeletions(this)
                refreshOrphanBanner()
            }
        }
        builder.setNegativeButton(R.string.orphan_action_close, null)
        builder.show()
    }

    private fun formatOrphanDate(ms: Long): String {
        if (ms <= 0L) return getString(R.string.orphan_date_unknown)
        return SimpleDateFormat("d MMM HH:mm", Locale.getDefault()).format(Date(ms))
    }

    override fun onPause() {
        super.onPause()
        // Don't stop shake detector if recording (service handles it)
        if (!isRecording) {
            shakeDetector?.stop()
        }
        // Stop the pulse animator while the activity is in
        // background. Restarts on the next onResume.
        stopRecButtonPulse()
    }

    /**
     * Pulse animations on the REC button. The two must stay tellable apart:
     * the slow, gentle breathing reads as "armed and ready", the faster and
     * wider one reads as "capturing now" and pairs with the bright-red disc
     * of rec_button_active. Swapping them, or aligning their cadences to
     * "harmonise" the two, erases that difference.
     */
    private fun startIdleRecPulse() {
        stopRecButtonPulse()
        recButtonPulseAnim = ValueAnimator.ofFloat(0.97f, 1.03f).apply {
            duration = 1500L
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            addUpdateListener { animator ->
                val scale = animator.animatedValue as Float
                recButton.scaleX = scale
                recButton.scaleY = scale
            }
            start()
        }
    }

    private fun startRecordingRecPulse() {
        stopRecButtonPulse()
        recButtonPulseAnim = ValueAnimator.ofFloat(1.0f, 1.10f).apply {
            duration = 800L
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            addUpdateListener { animator ->
                val scale = animator.animatedValue as Float
                recButton.scaleX = scale
                recButton.scaleY = scale
            }
            start()
        }
    }

    private fun stopRecButtonPulse() {
        recButtonPulseAnim?.cancel()
        recButtonPulseAnim = null
        if (::recButton.isInitialized) {
            recButton.scaleX = 1.0f
            recButton.scaleY = 1.0f
        }
    }

    private fun requestPermissionsAndStartRecording() {
        val missingPermissions = REQUIRED_PERMISSIONS.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missingPermissions.toTypedArray(), CAMERA_PERMISSION_CODE)
            return
        }
        // OEM-killer guidance (2026-06-23) — make sure the OS
        // won't kill the recording foreground service. On OEMs with an
        // aggressive proprietary killer (OnePlus/Oppo/Xiaomi/…) the standard
        // Doze exemption is NOT enough (field-proven on OxygenOS 16: the app
        // was Doze-exempt yet o-killed mid-recording), so show the richer
        // "run without restriction" guide once instead. On stock/Samsung/Pixel
        // the Doze one-tap dialog is sufficient.
        if (rs.readahead.washington.mobile.util.OemKillerHelper.isAggressiveOem()) {
            maybePromptOemThenRecord()
            return
        }
        if (!rs.readahead.washington.mobile.util.BatteryOptimizationHelper.isExempt(this)) {
            promptBatteryOptimizationExemption { startRecording() }
            return
        }
        startRecording()
    }

    /**
     * Explain the battery-opt exemption before launching the
     * system dialog. The user can decline ("Plus tard") and recording will
     * still start, just with the warning that uploads may stall once the
     * screen turns off.
     */
    private fun promptBatteryOptimizationExemption(onProceed: () -> Unit) {
        androidx.appcompat.app.AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_battery_dialog_title)
            .setMessage(R.string.stream_battery_dialog_message)
            .setPositiveButton(R.string.stream_battery_dialog_configure) { _, _ ->
                rs.readahead.washington.mobile.util.BatteryOptimizationHelper
                    .requestExemption(this)
                // Start recording immediately. The user will land back on
                // this activity (onResume) once they've accepted/refused
                // the system dialog.
                onProceed()
            }
            .setNegativeButton(R.string.stream_battery_dialog_later) { _, _ ->
                Toast.makeText(this, R.string.stream_battery_degraded, Toast.LENGTH_LONG).show()
                onProceed()
            }
            .setCancelable(false)
            .show()
    }

    /**
     * OEM-killer guidance — proactive path. On an aggressive OEM, show the
     * "run without restriction" guide once (gated by a pref flag), then start
     * recording. Later recordings skip straight to recording.
     */
    private fun maybePromptOemThenRecord() {
        if (!rs.readahead.washington.mobile.data.sharedpref.Preferences.isOemGuideShown()) {
            rs.readahead.washington.mobile.data.sharedpref.Preferences.setOemGuideShown(true)
            promptOemKillerGuide(reactive = false) { startRecording() }
        } else {
            startRecording()
        }
    }

    /**
     * OEM-killer guidance dialog. [reactive] picks the wording shown after a
     * kill was detected. The positive button best-effort deep-links the OEM
     * battery / auto-start screen (fallback: app-details). [onProceed] runs
     * after either choice — the proactive path starts recording, the reactive
     * path is a no-op.
     */
    private fun promptOemKillerGuide(reactive: Boolean, onProceed: () -> Unit) {
        val messageRes = if (reactive) {
            R.string.stream_oem_killer_message_reactive
        } else {
            R.string.stream_oem_killer_message
        }
        androidx.appcompat.app.AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_oem_killer_title)
            .setMessage(messageRes)
            .setPositiveButton(R.string.stream_oem_killer_open) { _, _ ->
                rs.readahead.washington.mobile.util.OemKillerHelper.openOemBatterySettings(this)
                onProceed()
            }
            .setNegativeButton(R.string.stream_oem_killer_later) { _, _ -> onProceed() }
            .setCancelable(!reactive)
            .show()
    }

    /**
     * OEM-killer guidance — reactive path (the feedback loop). If the system
     * recently killed a recording's foreground service while we were away,
     * surface the guide once for that kill. Skipped until past the PIN gate
     * ([StreamUploadManager.isUnlocked]) and never during a live recording.
     */
    private fun maybeWarnRecentKill() {
        if (isRecording) return
        if (!StreamUploadManager.getInstance(this).isUnlocked()) return
        val killMs = rs.readahead.washington.mobile.util.OemKillerHelper
            .lastForegroundKillMs(this) ?: return
        if (killMs > rs.readahead.washington.mobile.data.sharedpref.Preferences.getLastSeenKillMs()) {
            rs.readahead.washington.mobile.data.sharedpref.Preferences.setLastSeenKillMs(killMs)
            promptOemKillerGuide(reactive = true) { }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_CODE) {
            if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                startRecording()
            } else {
                Toast.makeText(this, R.string.stream_camera_mic_required, Toast.LENGTH_LONG).show()
            }
        }
    }

    private var serviceBound = false
    private var streamService: StreamRecordingService? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as StreamRecordingService.LocalBinder
            streamService = binder.getService()
            // If the SurfaceView's Surface is already
            // available (typical : we toggled visibility=VISIBLE before
            // binding the service), push it now ; the HEVC pipeline
            // attaches it to the GL pipeline.
            streamService?.setHevcPreviewSurface(pendingHevcPreviewSurface)
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            streamService = null
            serviceBound = false
        }
    }

    private fun startRecording() {
        // Verify the ratchet is unlocked before starting. `isUnlocked()` is
        // the predicate used here; StreamUploadManager exposes no other
        // "ready" state. The `isReady()` / `streamProvider` pair this comment
        // used to invoke no longer exists in the code — do not go looking for
        // it.
        val uploadManager = StreamUploadManager.getInstance()
        if (uploadManager == null || !uploadManager.isUnlocked()) {
            Toast.makeText(this, R.string.stream_encryption_not_initialized, Toast.LENGTH_LONG).show()
            return
        }

        isRecording = true
        recordingStartTime = System.currentTimeMillis()

        // Show the HEVC preview SurfaceView.
        // Made VISIBLE before bindService so the SurfaceView's
        // surfaceCreated callback can fire before / during the service
        // start, with no race in either order :
        //   - if surfaceCreated fires first, pendingHevcPreviewSurface
        //     holds the Surface and onServiceConnected forwards it
        //   - if onServiceConnected fires first, it forwards null and
        //     surfaceCreated will forward the Surface itself when ready
        hevcPreviewSurfaceView.visibility = View.VISIBLE

        // Switch UI to recording state — minimalist HUD:
        //   scrim + fingerprint go away
        //   timer + chunks counter + blinking REC dot come in
        //   REC button flips to its "activated" (bright red) state
        idleScrim.visibility = View.GONE
        fingerprintText.visibility = View.GONE
        // Cache aussi le bandeau enrollment pour garder
        // l'écran de recording épuré.
        enrollmentBanner.visibility = View.GONE
        // Same: keep the recording HUD clean.
        orphanBanner.visibility = View.GONE
        timerText.visibility = View.VISIBLE
        chunkStatus.visibility = View.VISIBLE
        chunkStatus.text = "0\u2191/0"
        chunkStatus.setTextColor(android.graphics.Color.parseColor("#AAFFFFFF"))
        // Show quality indicator (initial label from service
        // last-known mirror; updated by ACTION_QUALITY_UPDATE broadcast).
        qualityIndicator.visibility = View.VISIBLE
        qualityIndicator.text = StreamRecordingService.lastQualityLabel
        recIndicator.visibility = View.VISIBLE
        recButton.isActivated = true
        // Switch from gentle idle breathing to active recording pulse.
        startRecordingRecPulse()

        // Phase 3.7 \u2014 single source of truth for the HUD : the broadcast
        // sent 1Hz by StreamRecordingService carries chunksEncrypted +
        // chunksUploaded (the latter derived from encrypted - pending).
        // The previous WorkManager LiveData observer was racing this
        // broadcast and showed a different denominator (it counted total
        // WorkInfos, including CANCELLED ones from a Phase 3.8 reconnect
        // flush) \u2014 replaced entirely.
        registerReceiver(chunkUpdateReceiver, IntentFilter(StreamRecordingService.ACTION_CHUNK_UPDATE),
            Context.RECEIVER_NOT_EXPORTED)

        // Adaptive quality indicator broadcast.
        registerReceiver(qualityUpdateReceiver,
            IntentFilter(StreamRecordingService.ACTION_QUALITY_UPDATE),
            Context.RECEIVER_NOT_EXPORTED)

        // Start and bind the foreground recording service
        val intent = Intent(this, StreamRecordingService::class.java)
        ContextCompat.startForegroundService(this, intent)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        serviceBound = true

        // Start timer
        timerHandler.post(timerRunnable)

        // Start REC blink
        recBlinkHandler.post(recBlinkRunnable)

        // Keep screen on during recording
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }


    /**
     * True stealth mode: a single tap on the camera preview while recording
     * drops `FLAG_KEEP_SCREEN_ON` and lets the screen really go off.
     *
     * What must never come back is what v1 did: `brightness = 0` with the
     * screen kept ON. That halfway "screen on but black" state was treated as
     * idle by Doze, which froze uploads. The black overlay is NOT part of that
     * mistake and is still there ([enterStealthMode]): it hides preview and
     * HUD at once, while
     * `clearFlags(FLAG_KEEP_SCREEN_ON)` hands the display back to the system
     * timer, which turns the screen off after its configured timeout
     * (typically 30 s). Letting it really go off is both more discreet and
     * more reliable for upload throughput.
     *
     * The foreground service keeps running CameraX + WorkManager throughout,
     * so recording and uploads are unaffected: capture must not be stopped on
     * the grounds that the screen is off.
     *
     * Recovery: the system power button brings the activity back to onResume,
     * where we re-arm `FLAG_KEEP_SCREEN_ON` so the user gets the full HUD
     * again without further input. A single tap also leaves stealth
     * ([exitStealthMode], from the gesture detector below), which is the
     * usable exit while the screen has not actually gone off yet.
     */
    private fun setupStealthGestures() {
        hudGestureDetector =
            GestureDetector(this, object : GestureDetector.SimpleOnGestureListener() {
                override fun onSingleTapConfirmed(e: MotionEvent): Boolean {
                    if (!isRecording) return false
                    // v2.4 — tap pendant le stealth = sortie du stealth (UX
                    // alternative au power button). Plus rapide pour
                    // l'utilisateur qui veut juste vérifier le compteur.
                    if (isStealthMode) {
                        exitStealthMode()
                        return true
                    }
                    // Tap normal pendant recording (hors recButton) = entrée
                    // stealth.
                    if (!isOnRecButton(e)) {
                        enterStealthMode()
                        return true
                    }
                    return false
                }
            })
        // Voir dispatchTouchEvent ci-dessous, qui est
        // l'override appelé en amont de toute la hiérarchie de vues.
        // Ni setOnTouchListener sur la preview (consume DOWN et bloque la
        // séquence) ni sur streamRoot (la vue plein écran en match_parent
        // consume avant que les events ne remontent au root) ne
        // fonctionnait sur Seeker. dispatchTouchEvent reçoit les
        // events au niveau Activity AVANT le dispatching aux vues, c'est
        // garanti pour passer.
    }

    /**
     * Capture des taps stealth au niveau Activity.
     *
     * `dispatchTouchEvent` est invoqué AVANT que les events ne soient
     * descendus dans la hiérarchie des vues. On y branche le gesture
     * detector tout en relayant inconditionnellement à `super` pour ne
     * casser aucun listener (recButton click, settingsBtn click, etc.).
     */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        // v2.4 — accepter les events MEME en stealth mode pour permettre
        // le tap-to-exit (cf. onSingleTapConfirmed plus haut).
        if (isRecording) {
            hudGestureDetector?.onTouchEvent(ev)
        }
        return super.dispatchTouchEvent(ev)
    }

    /**
     * Vérifie si l'event est dans la zone du recButton — pour éviter que
     * le simple tap "Stop recording" ne déclenche aussi le stealth.
     */
    private fun isOnRecButton(e: MotionEvent): Boolean {
        if (!::recButton.isInitialized) return false
        val location = IntArray(2)
        recButton.getLocationOnScreen(location)
        val x = location[0]
        val y = location[1]
        return e.rawX >= x && e.rawX <= x + recButton.width &&
            e.rawY >= y && e.rawY <= y + recButton.height
    }

    private fun enterStealthMode() {
        if (isStealthMode) return
        isStealthMode = true

        // Overlay noir opaque immédiat. Visuellement
        // l'écran paraît éteint dès le tap. Sans ça, l'user devait
        // attendre le timeout système (15s sur Seeker) pour que ça
        // s'éteigne vraiment et l'effet "tap → rien" était trompeur.
        stealthOverlay.visibility = View.VISIBLE

        // Drop the keep-on flag so the OS display timer is back in charge.
        // L'écran s'éteindra vraiment après le timeout (typiquement 15-30s
        // selon les Settings device). Pendant cet intervalle, l'overlay
        // noir cache la preview/HUD donc visuellement "off" tout de suite.
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Subtle haptic = "ok, écran éteint".
        try {
            @Suppress("DEPRECATION")
            (getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator)?.vibrate(40)
        } catch (_: Exception) {}
    }

    private fun exitStealthMode() {
        if (!isStealthMode) return
        isStealthMode = false

        // Retire l'overlay noir → preview + HUD redeviennent visibles.
        stealthOverlay.visibility = View.GONE

        // Re-arm keep-on so the HUD doesn't disappear again 15-30s later.
        if (isRecording) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }

        // Subtle haptic = "back to normal".
        try {
            @Suppress("DEPRECATION")
            (getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator)?.vibrate(80)
        } catch (_: Exception) {}
    }

    private fun stopRecording() {
        isRecording = false
        // Crash fix 2026-05-09 — bloque tout nouveau startForegroundService
        // pendant que l'ancien service finit son onDestroy. Phase 2.1.5 : ce
        // flush attend jusqu'à 3,5 s (join du thread de stop) puis jusqu'à
        // 3 s (threads de chiffrement), soit 6,5 s bornés avant le reste du
        // teardown ; le flag est à 5500 ms et ne couvre donc plus le pire cas.
        // Ce pire cas suppose que maybeRetryAuth parte sur un appel réseau,
        // que le service décrit comme rare (« en pratique <1s sur un device
        // fluide »). Si l'user re-tap REC pendant cette fenêtre, le click
        // listener affiche un toast au lieu de relancer le service.
        isStopping = true
        timerHandler.postDelayed({
            isStopping = false
            timber.log.Timber.d("[REC] isStopping cleared — ready for new session")
        }, 5500L)

        // Leaving recording state must also leave stealth,
        // otherwise the black overlay stays drawn over the idle screen.
        if (isStealthMode) {
            exitStealthMode()
        }

        // Unregister receiver and stop service
        try { unregisterReceiver(chunkUpdateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(qualityUpdateReceiver) } catch (_: Exception) {}
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        streamService = null
        val intent = Intent(this, StreamRecordingService::class.java)
        stopService(intent)

        // Switch UI back to idle — symmetric to startRecording:
        //   timer / chunks / blinking dot out
        //   scrim + fingerprint back
        //   REC button returns to its "idle" (dim red) state
        timerText.visibility = View.GONE
        chunkStatus.visibility = View.GONE
        qualityIndicator.visibility = View.GONE
        recIndicator.visibility = View.GONE
        idleScrim.visibility = View.VISIBLE
        // Drop the preview surface at stop (symmetric to
        // startRecording's VISIBLE). The camera is released together with the
        // recording service, so leaving the SurfaceView up would freeze it on
        // the last frame and show it dimly until the screen turns off. Hiding
        // it destroys the Surface via the SAME well-tested surface-null path
        // as screen-off-during-recording → clean dark idle, no frozen frame.
        hevcPreviewSurfaceView.visibility = View.GONE
        fingerprintText.visibility = View.VISIBLE
        // Re-évalue la visibilité du bandeau enrollment
        // (redevient visible si l'enrôlement serveur est toujours pending).
        refreshEnrollmentBanner()
        // Re-check orphan fragments now that we're idle again.
        refreshOrphanBanner()
        recButton.isActivated = false
        // Back to gentle idle breathing.
        startIdleRecPulse()

        // Stop timer and blink
        timerHandler.removeCallbacks(timerRunnable)
        recBlinkHandler.removeCallbacks(recBlinkRunnable)

        // Allow screen to turn off
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    private val timerRunnable = object : Runnable {
        override fun run() {
            if (isRecording) {
                val elapsed = System.currentTimeMillis() - recordingStartTime
                val seconds = (elapsed / 1000) % 60
                val minutes = (elapsed / 60000) % 60
                val hours = elapsed / 3600000
                timerText.text = String.format("%02d:%02d:%02d", hours, minutes, seconds)
                timerHandler.postDelayed(this, 1000)
            }
        }
    }

    private val recBlinkRunnable = object : Runnable {
        override fun run() {
            if (isRecording) {
                recIndicator.visibility =
                    if (recIndicator.visibility == View.VISIBLE) View.INVISIBLE else View.VISIBLE
                recBlinkHandler.postDelayed(this, 500)
            }
        }
    }

    override fun onBackPressed() {
        if (isRecording) {
            // Block back press during recording — safety feature
            Toast.makeText(this, R.string.stream_press_stop, Toast.LENGTH_SHORT).show()
        } else {
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        timerHandler.removeCallbacksAndMessages(null)
        recBlinkHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
