package rs.readahead.washington.mobile.views.activity

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import org.stream.crypto.StreamPreferences
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.BuildConfig
import rs.readahead.washington.mobile.data.sharedpref.Preferences
import rs.readahead.washington.mobile.R

private const val AGPL_V3_URL = "https://www.gnu.org/licenses/agpl-3.0.html"

/**
 * StreamSettingsActivity — Panneau de contrôle V2.
 *
 * Pas de section RATCHET, et ce n'est pas un oubli : l'état des lots et le
 * compteur de clés ne sont actionnables par aucun utilisateur, et les afficher
 * ferait de cet écran un oracle local reliant une identité à son activité.
 *
 * Sections du panneau, dans l'ordre du layout `activity_stream_settings.xml` :
 *   - IDENTITÉ : fingerprint + statut enrôlement
 *   - SERVEUR : URL
 *   - ENREGISTREMENT : plafond de qualité, shake-to-record + sensibilité,
 *     toggle provenance, toggle horodatage OTS
 *   - ACTIONS : retry enrollment, archive, auto-upload des orphelins, délai
 *     d'auto-lock, lock, panic-wipe
 *   - DEBUG (CALIBRATION) : dev-only — le conteneur passe GONE et ses
 *     listeners ne sont pas câblés en release (voir le gate `BuildConfig.DEBUG`
 *     dans `onCreate`)
 *   - À PROPOS : version + commit hash + lien AGPLv3
 */
class StreamSettingsActivity : AppCompatActivity() {

    private lateinit var fingerprintView: TextView
    // Ligne statut enrôlement (sous fingerprint, dans
    // section IDENTITÉ). Vert / rouge (R.color.wa_orange = #CC1A1A malgré
    // son nom) / gris.
    private lateinit var enrollmentStatusView: TextView
    private lateinit var serverUrlView: TextView
    private lateinit var retryEnrollmentBtn: TextView
    private lateinit var archiveBtn: TextView
    // Toggle auto-upload des chunks orphelins.
    private lateinit var autoUploadBtn: TextView
    // Plafond qualité d'enregistrement (FHD = pas de plafond).
    private lateinit var qualityCapBtn: TextView
    // §10.11 — toggle provenance (sceller un manifeste vérifiable, défaut ON).
    private lateinit var provenanceBtn: TextView
    // §10.11 Phase B — toggle horodatage OTS du manifeste (opt-in, défaut OFF).
    private lateinit var provenanceTimestampBtn: TextView
    // Shake-to-record : toggle ON/OFF + sensibilité.
    private lateinit var shakeBtn: TextView
    private lateinit var shakeSensitivityBtn: TextView
    // Debug calibration (2026-05-16) — fixed-bitrate mode for face-legibility tests.
    private lateinit var debugBitrateBtn: TextView
    private lateinit var debugQualityBtn: TextView
    private lateinit var debugKbpsBtn: TextView
    // Codec probe + HEVC standalone test.
    private lateinit var debugCodecProbeBtn: TextView
    private lateinit var debugHevcTestBtn: TextView
    private lateinit var debugHevcGridBtn: TextView
    // Phase H2-B.2 (2026-05-16) — HEVC + AAC audio bundled test.
    private lateinit var debugHevcAudioTestBtn: TextView
    // Rolling chunk recorder test.
    private lateinit var debugRollingTestBtn: TextView
    // Debug A/B (2026-06-02) — 4:3+0.75 (A) vs 16:9 identity (B) aspect toggle.
    private lateinit var debugAspectBtn: TextView
    private lateinit var debugQuicBtn: TextView
    private lateinit var autoLockBtn: TextView
    private lateinit var lockBtn: TextView
    private lateinit var panicBtn: TextView
    private lateinit var aboutVersionView: TextView
    private lateinit var aboutCommitView: TextView
    private lateinit var aboutLicenseView: TextView
    private lateinit var closeBtn: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_stream_settings)

        fingerprintView = findViewById(R.id.settingsFingerprint)
        enrollmentStatusView = findViewById(R.id.settingsEnrollmentStatus)
        serverUrlView = findViewById(R.id.settingsServerUrl)
        retryEnrollmentBtn = findViewById(R.id.settingsRetryEnrollmentBtn)
        archiveBtn = findViewById(R.id.settingsArchiveBtn)
        autoUploadBtn = findViewById(R.id.settingsAutoUploadBtn)
        qualityCapBtn = findViewById(R.id.settingsQualityCapBtn)
        provenanceBtn = findViewById(R.id.settingsProvenanceBtn)
        provenanceTimestampBtn = findViewById(R.id.settingsProvenanceTimestampBtn)
        shakeBtn = findViewById(R.id.settingsShakeBtn)
        shakeSensitivityBtn = findViewById(R.id.settingsShakeSensitivityBtn)
        // — DEBUG (CALIBRATION) — is dev-only. Gate the whole section behind
        // BuildConfig.DEBUG so it is unreachable (and R8-stripped) in a release
        // build: it enabled the fixed-bitrate toggle (which writes PLAINTEXT MP4
        // to filesDir/debug_raw*, bypassing the E2E-at-rest guarantee) and the
        // quality-cap/adaptive bypass. Audit R-E-1/R-G-1 (CRITICAL), roadmap
        // §8.2.8. In a debug build the section stays fully functional.
        val debugSection = findViewById<View>(R.id.settingsDebugSection)
        if (BuildConfig.DEBUG) {
            debugBitrateBtn = findViewById(R.id.settingsDebugBitrateBtn)
            debugQualityBtn = findViewById(R.id.settingsDebugQualityBtn)
            debugKbpsBtn = findViewById(R.id.settingsDebugKbpsBtn)
            debugCodecProbeBtn = findViewById(R.id.settingsDebugCodecProbeBtn)
            debugHevcTestBtn = findViewById(R.id.settingsDebugHevcTestBtn)
            debugHevcGridBtn = findViewById(R.id.settingsDebugHevcGridBtn)
            debugHevcAudioTestBtn = findViewById(R.id.settingsDebugHevcAudioTestBtn)
            debugRollingTestBtn = findViewById(R.id.settingsDebugRollingTestBtn)
            debugAspectBtn = findViewById(R.id.settingsDebugAspectBtn)
            debugQuicBtn = findViewById(R.id.settingsDebugQuicBtn)
        } else {
            debugSection.visibility = View.GONE
        }
        autoLockBtn = findViewById(R.id.settingsAutoLockBtn)
        lockBtn = findViewById(R.id.settingsLockBtn)
        panicBtn = findViewById(R.id.settingsPanicBtn)
        aboutVersionView = findViewById(R.id.settingsAboutVersion)
        aboutCommitView = findViewById(R.id.settingsAboutCommit)
        aboutLicenseView = findViewById(R.id.settingsAboutLicense)
        closeBtn = findViewById(R.id.settingsCloseBtn)

        retryEnrollmentBtn.setOnClickListener { retryServerEnrollment() }
        archiveBtn.setOnClickListener {
            startActivity(Intent(this, ArchiveModeActivity::class.java))
        }
        autoUploadBtn.setOnClickListener {
            val newValue = !StreamPreferences.isAutoUploadOrphansEnabled(this)
            StreamPreferences.setAutoUploadOrphansEnabled(this, newValue)
            refreshAutoUploadBtn()
        }
        qualityCapBtn.setOnClickListener { showQualityCapDialog() }
        provenanceBtn.setOnClickListener {
            val newValue = !StreamPreferences.isProvenanceEnabled(this)
            StreamPreferences.setProvenanceEnabled(this, newValue)
            refreshProvenanceBtn()
            // §10.11 Phase B — the OTS toggle is meaningless without a manifest:
            // show it only while provenance is ON.
            provenanceTimestampBtn.visibility = if (newValue) View.VISIBLE else View.GONE
        }
        provenanceTimestampBtn.setOnClickListener {
            val newValue = !StreamPreferences.isProvenanceTimestampEnabled(this)
            StreamPreferences.setProvenanceTimestampEnabled(this, newValue)
            refreshProvenanceTimestampBtn()
        }
        shakeBtn.setOnClickListener {
            val newValue = !StreamPreferences.isShakeToRecordEnabled(this)
            StreamPreferences.setShakeToRecordEnabled(this, newValue)
            refreshShakeBtns()
        }
        shakeSensitivityBtn.setOnClickListener { showShakeSensitivityDialog() }
        // — DEBUG — listeners wired only in debug builds; in release R8 strips
        // these + the run*/refresh* methods that write plaintext debug MP4s
        // (debug_raw_hevc / debug_rolling). Audit R-E-1/R-G-1, roadmap §8.2.8.
        if (BuildConfig.DEBUG) {
        debugBitrateBtn.setOnClickListener {
            val newValue = !StreamPreferences.isDebugBitrateEnabled(this)
            StreamPreferences.setDebugBitrateEnabled(this, newValue)
            refreshDebugBitrateBtns()
        }
        debugQualityBtn.setOnClickListener {
            val next = when (StreamPreferences.getDebugBitrateQuality(this)) {
                "HD" -> "SD"
                else -> "HD"
            }
            StreamPreferences.setDebugBitrateQuality(this, next)
            refreshDebugBitrateBtns()
        }
        debugKbpsBtn.setOnClickListener {
            val current = StreamPreferences.getDebugBitrateKbps(this)
            val next = nextKbpsPalier(current)
            StreamPreferences.setDebugBitrateKbps(this, next)
            refreshDebugBitrateBtns()
        }
        debugCodecProbeBtn.setOnClickListener { runCodecProbe() }
        debugHevcTestBtn.setOnClickListener { runHevcSampleRecording() }
        debugHevcGridBtn.setOnClickListener { runHevcGrid() }
        debugHevcAudioTestBtn.setOnClickListener { runHevcAudioSampleRecording() }
        debugRollingTestBtn.setOnClickListener { runRollingChunksTest() }
        debugAspectBtn.setOnClickListener {
            val next = (StreamPreferences.getDebugAspectMode(this) + 1) % 5
            StreamPreferences.setDebugAspectMode(this, next)
            refreshAspectBtn()
            android.widget.Toast.makeText(
                this,
                "Mode ${aspectModeLabel(next)} — relance l'enregistrement",
                android.widget.Toast.LENGTH_LONG,
            ).show()
        }
        debugQuicBtn.setOnClickListener {
            val next = !StreamPreferences.isDebugQuicTransport(this)
            StreamPreferences.setDebugQuicTransport(this, next)
            refreshDebugQuicBtn()
            android.widget.Toast.makeText(
                this,
                if (next) "Transport QUIC/h3 (BBR) actif — relance l'enregistrement"
                else "Transport DirectTLS actif",
                android.widget.Toast.LENGTH_LONG,
            ).show()
        }
        }
        autoLockBtn.setOnClickListener { showAutoLockDialog() }
        lockBtn.setOnClickListener { confirmLock() }
        panicBtn.setOnClickListener { confirmPanicWipe() }
        closeBtn.setOnClickListener { finish() }

        // ABOUT — version/build immutables sur la durée de vie de
        // l'Activity. Affiche depuis BuildConfig (gradle versionName +
        // GIT_HASH évalué au build time).
        aboutVersionView.text = getString(
            R.string.stream_settings_about_version, BuildConfig.VERSION_NAME
        )
        aboutCommitView.text = getString(
            R.string.stream_settings_about_commit, BuildConfig.GIT_HASH
        )
        aboutLicenseView.setOnClickListener {
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(AGPL_V3_URL)))
            } catch (_: Exception) {
                // Pas de browser dispo — silently ignore
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Phase 6 — if the ratchet auto-locked while backgrounded, this screen
        // has no unlock UI: bounce to StreamActivity, whose onResume re-prompts
        // for the PIN. Without it, returning to Settings after the inactivity
        // auto-lock left the app usable with a wiped ratchet (no re-PIN).
        if (StreamUploadManager.getInstance(this).isLocked()) {
            finish()
            return
        }
        refresh()
        // Belt-and-braces: re-enqueue the retry worker each
        // time the user lands on Settings, in case the original onboarding
        // enqueue was dropped (app uninstall + reinstall, system clear of
        // WorkManager DB, etc.). KEEP policy makes this idempotent.
        if (StreamUploadManager.getInstance(this).hasPendingServerEnrollment()) {
            rs.readahead.washington.mobile.util.jobs.EnrollmentRetryWorker.enqueue(this)
        }
        // Pickup du flag one-shot set par EnrollmentRetryWorker.
        // (Le flag est aussi consommé par StreamActivity.onResume ; le premier
        // qui passe gagne, l'autre voit false. Pas de double-toast possible.)
        if (org.stream.crypto.StreamPreferences.consumeEnrollmentSucceededFlag(this)) {
            android.widget.Toast.makeText(
                this,
                getString(R.string.enrollment_succeeded_toast),
                android.widget.Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun refresh() {
        val manager = StreamUploadManager.getInstance(this)
        val identity = manager.identity ?: StreamPreferences.getIdentity(this)

        fingerprintView.text = identity?.readableFingerprint() ?: "— non enrôlé —"

        // Ligne statut enrôlement explicite, 3 états :
        //   OK (vert wa_green) : identité + blob ratchet locaux, et aucune
        //     preuve d'enrôlement en attente localement — le code ne sonde pas
        //     le serveur au moment de l'affichage
        //   PENDING : preuve d'enrôlement encore en attente d'envoi au serveur
        //     (R.color.wa_orange, qui vaut #CC1A1A, soit le rouge d'accent de
        //     l'app — le nom de la constante est trompeur)
        //   NONE (gris wa_gray) : isEnrolled() faux, donc pas d'identité ou pas
        //     de blob ratchet
        when {
            !manager.isEnrolled() -> {
                enrollmentStatusView.text = getString(R.string.enrollment_status_none)
                enrollmentStatusView.setTextColor(resources.getColor(R.color.wa_gray, theme))
            }
            manager.hasPendingServerEnrollment() -> {
                enrollmentStatusView.text = getString(R.string.enrollment_status_pending)
                enrollmentStatusView.setTextColor(resources.getColor(R.color.wa_orange, theme))
            }
            else -> {
                enrollmentStatusView.text = getString(R.string.enrollment_status_ok)
                enrollmentStatusView.setTextColor(resources.getColor(R.color.wa_green, theme))
            }
        }

        serverUrlView.text = StreamPreferences.getServerUrl(this)
            ?: "https://relay.shake-document-protect.org:8443"

        // Masque Archive & Panic si pas enrôlé
        val hasIdentity = identity != null
        archiveBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        panicBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        lockBtn.visibility = if (manager.isUnlocked()) View.VISIBLE else View.GONE
        // Auto-upload toggle only meaningful when enrolled.
        autoUploadBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        autoLockBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        // Recording quality cap + shake only meaningful once enrolled.
        qualityCapBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        provenanceBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        // §10.11 Phase B — OTS timestamp toggle only meaningful while provenance is ON.
        provenanceTimestampBtn.visibility =
            if (hasIdentity && StreamPreferences.isProvenanceEnabled(this)) View.VISIBLE else View.GONE
        shakeBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        shakeSensitivityBtn.visibility = if (hasIdentity) View.VISIBLE else View.GONE
        refreshAutoUploadBtn()
        refreshAutoLockBtn()
        refreshQualityCapBtn()
        refreshProvenanceBtn()
        refreshProvenanceTimestampBtn()
        refreshShakeBtns()
        if (BuildConfig.DEBUG) {
            refreshDebugBitrateBtns()
            refreshAspectBtn()
            refreshDebugQuicBtn()
        }
        // Bouton retry visible uniquement si l'enrôlement
        // serveur est en attente (cas onboarding offline).
        retryEnrollmentBtn.visibility =
            if (manager.hasPendingServerEnrollment()) View.VISIBLE else View.GONE
    }

    /**
     * Debug (2026-06-02) — squish 2x2 harness label. Cycles 0=A 1=B 2=D 3=E 4=F.
     * Ne pas refermer l'énumération sur E : le mode 4 (F : 16:9 + vscale
     * dérivé) est le défaut et la configuration expédiée en production, les
     * modes 0-3 sont des variants de diagnostic.
     */
    private fun aspectModeLabel(mode: Int): String = when (mode) {
        1 -> "B : 16:9 + identité"
        2 -> "D : 4:3 + identité"
        3 -> "E : 16:9 + fudge"
        4 -> "F : 16:9 + vscale dérivé"
        else -> "A : 4:3 + 0.75 (legacy)"
    }

    private fun refreshAspectBtn() {
        debugAspectBtn.text = "ASPECT — " + aspectModeLabel(StreamPreferences.getDebugAspectMode(this))
    }

    /**
     * Phase 3a (2026-06-20) — sync the QUIC transport toggle label AND re-apply
     * the persisted choice to [RustUploadTransport.mode]. Opening Settings thus
     * restores the transport selection after a process restart (the worker reads
     * the field live, so no further action is needed).
     */
    private fun refreshDebugQuicBtn() {
        val quic = StreamPreferences.isDebugQuicTransport(this)
        rs.readahead.washington.mobile.util.jobs.RustUploadTransport.mode =
            if (quic) uniffi.frappuccino.TransportMode.OBF_QUIC
            else uniffi.frappuccino.TransportMode.DIRECT_TLS
        debugQuicBtn.text = "TRANSPORT — " + if (quic) "QUIC/h3 (BBR)" else "DirectTLS"
    }

    /**
     * Sync the toggle label to the persisted flag.
     * Default is ON (matches StreamPreferences default).
     */
    private fun refreshAutoUploadBtn() {
        val enabled = StreamPreferences.isAutoUploadOrphansEnabled(this)
        autoUploadBtn.text = getString(
            if (enabled) R.string.stream_settings_auto_upload_on
            else R.string.stream_settings_auto_upload_off
        )
    }

    /** §10.11 — sync the provenance toggle label to the persisted flag (default ON). */
    private fun refreshProvenanceBtn() {
        provenanceBtn.text = getString(
            if (StreamPreferences.isProvenanceEnabled(this)) R.string.stream_settings_provenance_on
            else R.string.stream_settings_provenance_off
        )
    }

    /** §10.11 Phase B — sync the OTS-timestamp toggle label (default OFF, opt-in). */
    private fun refreshProvenanceTimestampBtn() {
        provenanceTimestampBtn.text = getString(
            if (StreamPreferences.isProvenanceTimestampEnabled(this)) R.string.stream_settings_provenance_ts_on
            else R.string.stream_settings_provenance_ts_off
        )
    }

    /**
     * Debug calibration (2026-05-16) — sync the 3 toggle/cycle labels. The
     * quality + kbps buttons are dimmed when the toggle is OFF (still
     * clickable so the operator can preset values before flipping it on).
     */
    private fun refreshDebugBitrateBtns() {
        val enabled = StreamPreferences.isDebugBitrateEnabled(this)
        debugBitrateBtn.text = getString(
            if (enabled) R.string.stream_settings_debug_bitrate_on
            else R.string.stream_settings_debug_bitrate_off
        )
        val quality = StreamPreferences.getDebugBitrateQuality(this)
        val qualityLabel = if (quality == "SD") "480p" else "720p"
        debugQualityBtn.text = getString(R.string.stream_settings_debug_quality, qualityLabel)
        val kbps = StreamPreferences.getDebugBitrateKbps(this)
        debugKbpsBtn.text = getString(R.string.stream_settings_debug_kbps, kbps)
        val alpha = if (enabled) 1.0f else 0.45f
        debugQualityBtn.alpha = alpha
        debugKbpsBtn.alpha = alpha
    }

    /**
     * Cycle through calibration paliers : 300 → 500 → 800 → 1200 → 1800
     * → 2500 → 4000 → 300… The codec floor on the Seeker hardware
     * encoder is around 300 kbps (anything lower may trip
     * ERROR_NO_VALID_DATA observed in Phase 3.22), so we don't go
     * below.
     */
    private fun nextKbpsPalier(current: Int): Int {
        val paliers = intArrayOf(300, 500, 800, 1200, 1800, 2500, 4000)
        val idx = paliers.indexOfFirst { it == current }
        return if (idx < 0 || idx == paliers.lastIndex) paliers.first()
        else paliers[idx + 1]
    }

    /**
     * Enumerate hardware video encoders and
     * their bitrate ranges. Pure metadata query, no recording. Outputs
     * to logcat tag `StreamMetrics` (mirrored to metrics.log) and shows
     * a toast summary so the operator can read it on-device without
     * adb.
     */
    private fun runCodecProbe() {
        val mimes = listOf("video/avc" to "H.264", "video/hevc" to "HEVC", "video/av01" to "AV1")
        val summary = StringBuilder()
        for ((mime, label) in mimes) {
            val info = org.stream.crypto.capture.HevcMediaCodecEncoder.pickEncoder(mime)
            if (info == null) {
                timber.log.Timber.tag("StreamMetrics").i(
                    "codecProbe mime=%s name=NONE", mime
                )
                summary.append("$label: ✗\n")
                continue
            }
            val isHardware = !info.name.startsWith("c2.android.")
            val caps = info.getCapabilitiesForType(mime).videoCapabilities
            val br = caps.bitrateRange
            timber.log.Timber.tag("StreamMetrics").i(
                "codecProbe mime=%s name=%s hardware=%s bitrateRange=[%d,%d] maxRes=%dx%d",
                mime, info.name, isHardware,
                br.lower, br.upper,
                caps.supportedWidths.upper, caps.supportedHeights.upper
            )
            val tag = if (isHardware) "HW" else "SW"
            summary.append("$label ($tag): ${br.lower / 1000}-${br.upper / 1_000_000}M\n")
        }
        android.widget.Toast.makeText(
            this, summary.toString().trim(), android.widget.Toast.LENGTH_LONG
        ).show()
    }

    /**
     * Standalone 10-second HEVC test recording.
     *
     * This path is deliberately independent from the production recording
     * pipeline: it drives CameraX `Preview` directly, with no `Recorder`, and
     * pipes the Surface output into our custom [org.stream.crypto.capture
     * .HevcMediaCodecEncoder]. Do not factor the two paths together — real
     * recordings must not end up depending on a calibration tool, and
     * debugging an HEVC problem here is not debugging what ships.
     *
     * Bitrate + quality are read from the same StreamPreferences values as the
     * H.264 calibration mode. That is what makes the comparison meaningful:
     * giving this test its own constants would break the measurement protocol
     * without breaking a single line of code. The operator can run it with or
     * without the fixed-bitrate toggle active.
     *
     * The resulting MP4 lands in `filesDir/debug_raw_hevc/` and can be pulled
     * via adb run-as.
     */
    private fun runHevcSampleRecording() {
        debugHevcTestBtn.isEnabled = false
        debugHevcTestBtn.text = "REC HEVC…"
        val quality = StreamPreferences.getDebugBitrateQuality(this)
        val kbps = StreamPreferences.getDebugBitrateKbps(this)
        recordHevcOneClip(quality, kbps, withAudio = false) { resultMsg ->
            debugHevcTestBtn.isEnabled = true
            debugHevcTestBtn.text = getString(R.string.stream_settings_debug_hevc_test)
            android.widget.Toast.makeText(
                this, resultMsg, android.widget.Toast.LENGTH_LONG
            ).show()
        }
    }

    /**
     * 10-second HEVC + AAC audio clip via
     * [org.stream.crypto.capture.ChunkEncoderBundle], with an
     * [org.stream.crypto.capture.AudioCaptureEncoder] running in parallel and
     * muxed into the same MP4. It shares the GL wedge with the video-only
     * test, so a wedge regression shows up in both at once.
     *
     * Output filename prefixed with `hevc-av-` so it's easy to cherry-pick
     * from `debug_raw_hevc/` next to the video-only `hevc-v-` clips.
     */
    private fun runHevcAudioSampleRecording() {
        debugHevcAudioTestBtn.isEnabled = false
        debugHevcAudioTestBtn.text = "REC HEVC+AUDIO…"
        val quality = StreamPreferences.getDebugBitrateQuality(this)
        val kbps = StreamPreferences.getDebugBitrateKbps(this)
        recordHevcOneClip(quality, kbps, withAudio = true) { resultMsg ->
            debugHevcAudioTestBtn.isEnabled = true
            debugHevcAudioTestBtn.text = getString(R.string.stream_settings_debug_hevc_audio_test)
            android.widget.Toast.makeText(
                this, resultMsg, android.widget.Toast.LENGTH_LONG
            ).show()
        }
    }

    /**
     * Exercises the [org.stream.crypto.capture.RollingChunkRecorder] over 4
     * chunk rotations + a short tail.
     *
     * The invariant this test protects : camera + GL pipeline +
     * PcmCaptureThread stay alive across rotations, and only the `MediaCodec`
     * encoders + the `MediaMuxer` are recreated per chunk. Never rebuild the
     * camera or the GL pipeline to "restart clean" on a failed rotation — that
     * loses frames and audio samples at every chunk boundary, which is exactly
     * the data loss this design avoids. The next chunk's encoders are
     * pre-allocated 500 ms before each rotation tick, which is what keeps the
     * actual swap latency under about 10 ms.
     *
     * Output : `filesDir/debug_rolling/chunk-001.mp4` ..
     * `chunk-005.mp4`. The last file is deliberately shorter than the others :
     * it is the tail delivered at stop, not a truncated chunk.
     */
    private fun runRollingChunksTest() {
        debugRollingTestBtn.isEnabled = false
        debugRollingTestBtn.text = "ROLLING…"

        val quality = StreamPreferences.getDebugBitrateQuality(this)
        val kbps = StreamPreferences.getDebugBitrateKbps(this)
        // Native portrait : see recordHevcOneClip for rationale.
        val (w, h) = if (quality == "SD") 480 to 854 else 720 to 1280
        val outDir = java.io.File(filesDir, "debug_rolling").also {
            it.mkdirs()
            // Clear previous run so the test results are unambiguous.
            it.listFiles()?.forEach { f -> f.delete() }
        }

        val readyCount = java.util.concurrent.atomic.AtomicInteger(0)
        val recorder = org.stream.crypto.capture.RollingChunkRecorder(
            chunkDir = outDir,
            chunkIntervalMs = 5_000L,
            preallocLeadMs = 500L,
            initialVideoConfig = org.stream.crypto.capture.ChunkEncoderBundle.VideoConfig(
                mime = "video/hevc",
                widthPx = w, heightPx = h,
                bitrateBps = kbps * 1_000,
                // 1 IDR per chunk — see HevcMediaCodecEncoder doc.
                keyframeIntervalSec = 5,
            ),
            audioConfig = org.stream.crypto.capture.ChunkEncoderBundle.AudioConfig(),
            orientationHintDegrees = 0,
            onChunkReady = { file, seq ->
                val n = readyCount.incrementAndGet()
                timber.log.Timber.tag("StreamMetrics").i(
                    "rollingTest chunkReady seq=%d size=%d total=%d",
                    seq, file.length(), n
                )
            },
            onError = { e ->
                timber.log.Timber.e(e, "rollingTest onError")
            },
        )

        val providerFuture = androidx.camera.lifecycle.ProcessCameraProvider.getInstance(this)
        providerFuture.addListener({
            try {
                val provider = providerFuture.get()
                val cameraSurfaceTexture = recorder.cameraSurfaceTexture()
                val cameraSurface = android.view.Surface(cameraSurfaceTexture)
                val preview = androidx.camera.core.Preview.Builder().build().apply {
                    setSurfaceProvider { request ->
                        request.provideSurface(cameraSurface, mainExecutor) { result ->
                            timber.log.Timber.d(
                                "rollingTest camera surface released, result=%d",
                                result.resultCode
                            )
                        }
                    }
                }
                provider.unbindAll()
                provider.bindToLifecycle(
                    this,
                    androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                )
                recorder.start()

                // Stop after 4 rotations + 1s of tail. With chunkInterval=5s
                // and start at T=0 : rotations at T=5/10/15/20, stop at
                // T=21 → 4 complete 5s chunks + 1 short tail (~1s).
                android.os.Handler(mainLooper).postDelayed({
                    Thread {
                        try { recorder.stop() } catch (e: Exception) {
                            timber.log.Timber.w(e, "rollingTest recorder.stop failed")
                        }
                        try { cameraSurface.release() } catch (e: Exception) {
                            timber.log.Timber.w(e, "rollingTest camera surface release failed")
                        }
                        runOnUiThread {
                            try { provider.unbindAll() } catch (e: Exception) {
                                timber.log.Timber.w(e, "rollingTest unbindAll failed")
                            }
                            debugRollingTestBtn.isEnabled = true
                            debugRollingTestBtn.text =
                                getString(R.string.stream_settings_debug_rolling_test)
                            val n = readyCount.get()
                            val totalBytes = outDir.listFiles()?.sumOf { it.length() } ?: 0L
                            android.widget.Toast.makeText(
                                this,
                                "ROLLING OK: $n chunks, ${totalBytes / 1024} KiB",
                                android.widget.Toast.LENGTH_LONG
                            ).show()
                        }
                    }.start()
                }, 21_000L)
            } catch (e: Exception) {
                timber.log.Timber.e(e, "rollingTest setup failed")
                try { recorder.stop() } catch (_: Exception) {}
                runOnUiThread {
                    debugRollingTestBtn.isEnabled = true
                    debugRollingTestBtn.text =
                        getString(R.string.stream_settings_debug_rolling_test)
                    android.widget.Toast.makeText(
                        this,
                        "ROLLING setup err: ${e.message}",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
            }
        }, mainExecutor)
    }

    /**
     * Records 7 successive HEVC clips at 300/500/800/1200/1800/2500/4000 kbps
     * using the current resolution setting (HD/SD). Each clip is 10 s, and the
     * 1 s gap between paliers is there to let CameraX tear down + rebind
     * cleanly — keep it, nothing in the bare `postDelayed(…, 1_000L)` below
     * says why it exists. The grid runs as one block of ~80 s, during which
     * the button stays disabled and the camera is busy.
     *
     * Output files end up in `filesDir/debug_raw_hevc/`, named
     * `hevc-v-{res}-{kbps}kbps-{HHmmss}.mp4` : `{res}` is `720p` or `480p`,
     * and the `v` is the no-audio tag that the shared [recordHevcOneClip]
     * always inserts (`av` when audio is captured) — the grid always records
     * without audio. Same layout as the H.264 calibration grid produced by the
     * fixed-bitrate toggle, for direct visual comparison at matched bitrates.
     */
    private fun runHevcGrid() {
        debugHevcGridBtn.isEnabled = false
        val quality = StreamPreferences.getDebugBitrateQuality(this)
        val paliers = intArrayOf(300, 500, 800, 1200, 1800, 2500, 4000)
        recordHevcPalier(quality, paliers, 0)
    }

    private fun recordHevcPalier(quality: String, paliers: IntArray, idx: Int) {
        if (idx >= paliers.size) {
            debugHevcGridBtn.isEnabled = true
            debugHevcGridBtn.text = getString(R.string.stream_settings_debug_hevc_grid)
            android.widget.Toast.makeText(
                this, "GRILLE HEVC TERMINÉE (${paliers.size} clips)",
                android.widget.Toast.LENGTH_LONG
            ).show()
            return
        }
        val kbps = paliers[idx]
        debugHevcGridBtn.text = "GRILLE ${idx + 1}/${paliers.size} (${kbps} kbps)"
        recordHevcOneClip(quality, kbps, withAudio = false) { _ ->
            // 1 s gap, then next palier.
            android.os.Handler(mainLooper).postDelayed({
                recordHevcPalier(quality, paliers, idx + 1)
            }, 1_000L)
        }
    }

    /**
     * Records ONE HEVC clip (10 s) at the given resolution + bitrate via
     * the GL wedge pipeline + [org.stream.crypto.capture.ChunkEncoderBundle].
     * If [withAudio] is true, an AAC audio track is captured in parallel
     * and muxed into the same MP4 via [org.stream.crypto.capture
     * .AudioCaptureEncoder]. Calls [onDone] on the main thread with a
     * status message after teardown.
     *
     * Output filename : `hevc-{av|v}-{res}-{kbps}kbps-{HHmmss}.mp4` in
     * `filesDir/debug_raw_hevc/`. Keep the `av` / `v` tag if you touch this
     * name : it is what sorts clips with and without audio at a glance when
     * they are adb-pulled in bulk, and no test covers a calibration clip name.
     */
    private fun recordHevcOneClip(
        quality: String,
        kbps: Int,
        withAudio: Boolean,
        onDone: (String) -> Unit,
    ) {
        val outDir = java.io.File(filesDir, "debug_raw_hevc").also { it.mkdirs() }
        // Encode the buffer in portrait natively (width < height). Never
        // switch to landscape with a playback-time rotation hint : that hint
        // only rotates pixels at display time, it doesn't change the encoded
        // aspect ratio, so the camera frame gets stretched into a landscape
        // canvas and then rotated → distorted faces on playback. That
        // regression is invisible to an automated test (the file exists, the
        // duration is right) and only shows on a face, which is the product's
        // actual content. The encoder + GL window + camera SurfaceTexture must
        // ALL be portrait together for the driver to hand back a
        // portrait-aspect buffer ; aligning only one of the three changes
        // nothing. (H2-B.4 fix.)
        val (w, h) = if (quality == "SD") 480 to 854 else 720 to 1280
        val ts = java.text.SimpleDateFormat("HHmmss", java.util.Locale.US)
            .format(java.util.Date())
        val resLabel = if (quality == "SD") "480p" else "720p"
        val audioTag = if (withAudio) "av" else "v"
        val outFile = java.io.File(outDir, "hevc-$audioTag-$resLabel-${kbps}kbps-$ts.mp4")
        val bundle = org.stream.crypto.capture.ChunkEncoderBundle(
            outputFile = outFile,
            videoConfig = org.stream.crypto.capture.ChunkEncoderBundle.VideoConfig(
                mime = "video/hevc",
                widthPx = w, heightPx = h,
                bitrateBps = kbps * 1_000,
            ),
            audioConfig = if (withAudio) {
                org.stream.crypto.capture.ChunkEncoderBundle.AudioConfig()
            } else null,
            // Native portrait encoding → no rotation hint needed.
            orientationHintDegrees = 0,
        )
        runHevcBundleOnUiThread(bundle, outFile, w, h, withAudio, onDone)
    }

    /**
     * Drives a [org.stream.crypto.capture.ChunkEncoderBundle] for ~10 s
     * with CameraX feeding a GL wedge, then tears everything down in
     * the order GL pipeline → bundle (which stops audio + video
     * encoders internally before closing the muxer) → camera Surface
     * → unbindAll. The GL-first teardown order avoids `EGL_BAD_SURFACE`
     * (encoder Surface invalidated under a still-rendering GL thread).
     */
    private fun runHevcBundleOnUiThread(
        bundle: org.stream.crypto.capture.ChunkEncoderBundle,
        outFile: java.io.File,
        widthPx: Int,
        heightPx: Int,
        withAudio: Boolean,
        onDone: (String) -> Unit = { },
    ) {
        val providerFuture = androidx.camera.lifecycle.ProcessCameraProvider.getInstance(this)
        providerFuture.addListener({
            var glPipeline: org.stream.crypto.capture.GlVideoPipeline? = null
            // PcmCaptureThread is now an
            // external dependency of the bundle (so it can be kept
            // alive across chunk rotations in B.4 proper). For the
            // single-chunk standalone test we just spin up a throwaway
            // one and wire it to the bundle's audio encoder.
            var pcmThread: org.stream.crypto.capture.PcmCaptureThread? = null
            try {
                val provider = providerFuture.get()
                val encoderSurface = bundle.createVideoInputSurface()
                glPipeline = org.stream.crypto.capture.GlVideoPipeline(
                    initialOutputSurface = encoderSurface,
                    widthPx = widthPx, heightPx = heightPx,
                ).also { it.start() }
                val cameraSurfaceTexture = glPipeline.cameraSurfaceTexture()
                val cameraSurface = android.view.Surface(cameraSurfaceTexture)

                val preview = androidx.camera.core.Preview.Builder().build().apply {
                    setSurfaceProvider { request ->
                        request.provideSurface(cameraSurface, mainExecutor) { result ->
                            timber.log.Timber.d(
                                "HEVC+GL : camera surface released, result=%d",
                                result.resultCode
                            )
                        }
                    }
                }
                provider.unbindAll()
                provider.bindToLifecycle(
                    this,
                    androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                )
                bundle.start()

                // Wire audio capture if requested.
                if (withAudio) {
                    val audioEncoder = bundle.audioEncoder
                    if (audioEncoder != null) {
                        pcmThread = org.stream.crypto.capture.PcmCaptureThread().also {
                            it.start()
                            it.setSink(audioEncoder)
                        }
                    }
                }

                android.os.Handler(mainLooper).postDelayed({
                    Thread {
                        // Teardown order (2026-05-16 lesson) : GL pipeline
                        // first. bundle.stop() invalidates the encoder
                        // Surface — if glPipeline is still rendering, the
                        // last eglSwapBuffers crashes with EGL_BAD_SURFACE.
                        try { glPipeline?.stop() } catch (e: Exception) {
                            timber.log.Timber.w(e, "glPipeline.stop failed")
                        }
                        // Detach the sink and signal EOS on the audio
                        // encoder so its drain thread can exit cleanly
                        // before bundle.stop() joins it.
                        try {
                            pcmThread?.setSink(null)
                            bundle.audioEncoder?.signalEos()
                        } catch (e: Exception) {
                            timber.log.Timber.w(e, "audio EOS prep failed")
                        }
                        try { bundle.stop() } catch (e: Exception) {
                            timber.log.Timber.w(e, "bundle.stop failed")
                        }
                        try { pcmThread?.stop() } catch (e: Exception) {
                            timber.log.Timber.w(e, "pcmThread.stop failed")
                        }
                        try { cameraSurface.release() } catch (e: Exception) {
                            timber.log.Timber.w(e, "cameraSurface.release failed")
                        }
                        runOnUiThread {
                            try { provider.unbindAll() } catch (e: Exception) {
                                timber.log.Timber.w(e, "unbindAll failed")
                            }
                            val tag = if (withAudio) "HEVC+AUDIO" else "HEVC"
                            val msg = if (outFile.length() > 0) {
                                "$tag OK ${outFile.length() / 1024} KiB"
                            } else {
                                "$tag FAILED (0 B)"
                            }
                            onDone(msg)
                        }
                    }.start()
                }, 10_000L)
            } catch (e: Exception) {
                timber.log.Timber.e(e, "HEVC+GL sample setup failed")
                try { glPipeline?.stop() } catch (_: Exception) {}
                try { pcmThread?.stop() } catch (_: Exception) {}
                try { bundle.stop() } catch (_: Exception) {}
                onDone("HEVC+GL setup err: ${e.message}")
            }
        }, mainExecutor)
    }

    private fun retryServerEnrollment() {
        retryEnrollmentBtn.isEnabled = false
        retryEnrollmentBtn.text = "ENVOI EN COURS…"
        Thread {
            val ok = try {
                StreamUploadManager.getInstance(this).retryServerEnrollment()
            } catch (e: Exception) {
                false
            }
            runOnUiThread {
                retryEnrollmentBtn.isEnabled = true
                retryEnrollmentBtn.text = "RÉESSAYER L'ENRÔLEMENT SERVEUR"
                if (ok) {
                    android.widget.Toast.makeText(
                        this,
                        "Enrôlement serveur réussi.",
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                } else {
                    android.widget.Toast.makeText(
                        this,
                        "Serveur toujours injoignable. Réessayez plus tard.",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
                refresh()
            }
        }.start()
    }

    // Phase 6 — ratchet inactivity auto-lock (re-PIN after N min idle in the
    // background). Separate from the JWT-clear lock_timeout. -1L = "Never".
    private val autoLockOptionsMs = longArrayOf(60_000L, 300_000L, 900_000L, 1_800_000L, -1L)

    private fun autoLockLabel(ms: Long): String = when (ms) {
        60_000L -> getString(R.string.stream_settings_autolock_1min)
        300_000L -> getString(R.string.stream_settings_autolock_5min)
        900_000L -> getString(R.string.stream_settings_autolock_15min)
        1_800_000L -> getString(R.string.stream_settings_autolock_30min)
        else -> getString(R.string.stream_settings_autolock_never)
    }

    private fun refreshAutoLockBtn() {
        val ms = Preferences.getRatchetAutoLockMs()
        autoLockBtn.text =
            getString(R.string.stream_settings_autolock_title) + " : " + autoLockLabel(ms)
    }

    private fun showAutoLockDialog() {
        val current = Preferences.getRatchetAutoLockMs()
        val labels = autoLockOptionsMs.map { autoLockLabel(it) }.toTypedArray()
        // Default highlight = 15 min (index 2) if the stored value isn't a known option.
        val checked = autoLockOptionsMs.indexOfFirst { it == current }.let { if (it < 0) 2 else it }
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_settings_autolock_title)
            .setSingleChoiceItems(labels, checked) { dialog, which ->
                Preferences.setRatchetAutoLockMs(autoLockOptionsMs[which])
                refreshAutoLockBtn()
                dialog.dismiss()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    // Max recording quality cap. FHD = no cap (= legacy). The
    // adaptive ladder still drops below the cap on a degrading network ;
    // a change applies to the next recording (the manager is rebuilt per
    // session). Debug calibration ignores the cap.
    private val qualityCapOptions = arrayOf(
        org.stream.crypto.capture.StreamQuality.FHD,
        org.stream.crypto.capture.StreamQuality.HD,
        org.stream.crypto.capture.StreamQuality.SD,
    )

    private fun qualityCapLabel(q: org.stream.crypto.capture.StreamQuality): String = when (q) {
        org.stream.crypto.capture.StreamQuality.FHD ->
            getString(R.string.stream_settings_quality_auto)
        org.stream.crypto.capture.StreamQuality.HD ->
            getString(R.string.stream_settings_quality_720)
        org.stream.crypto.capture.StreamQuality.SD ->
            getString(R.string.stream_settings_quality_480)
    }

    private fun refreshQualityCapBtn() {
        val cap = StreamPreferences.getMaxQualityCap(this)
        qualityCapBtn.text =
            getString(R.string.stream_settings_quality_title) + " : " + qualityCapLabel(cap)
    }

    private fun showQualityCapDialog() {
        val current = StreamPreferences.getMaxQualityCap(this)
        val labels = qualityCapOptions.map { qualityCapLabel(it) }.toTypedArray()
        val checked = qualityCapOptions.indexOf(current).let { if (it < 0) 0 else it }
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_settings_quality_title)
            .setSingleChoiceItems(labels, checked) { dialog, which ->
                StreamPreferences.setMaxQualityCap(this, qualityCapOptions[which])
                refreshQualityCapBtn()
                dialog.dismiss()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    // Shake-to-record toggle + sensitivity. The sensitivity row
    // is dimmed (still tappable to preset) while the toggle is OFF, mirroring
    // the debug-bitrate quality/kbps rows. Default sensitivity MED = the
    // historical hard-coded behaviour ; the toggle defaults ON.
    private val shakeSensitivityOptions = arrayOf("LOW", "MED", "HIGH")

    private fun shakeSensitivityLabel(s: String): String = when (s) {
        "LOW" -> getString(R.string.stream_settings_shake_low)
        "HIGH" -> getString(R.string.stream_settings_shake_high)
        else -> getString(R.string.stream_settings_shake_med)
    }

    private fun refreshShakeBtns() {
        val enabled = StreamPreferences.isShakeToRecordEnabled(this)
        shakeBtn.text = getString(
            if (enabled) R.string.stream_settings_shake_on
            else R.string.stream_settings_shake_off
        )
        val sensitivity = StreamPreferences.getShakeSensitivity(this)
        shakeSensitivityBtn.text =
            getString(R.string.stream_settings_shake_sensitivity_title) +
                " : " + shakeSensitivityLabel(sensitivity)
        shakeSensitivityBtn.alpha = if (enabled) 1.0f else 0.45f
    }

    private fun showShakeSensitivityDialog() {
        val current = StreamPreferences.getShakeSensitivity(this)
        val labels = shakeSensitivityOptions.map { shakeSensitivityLabel(it) }.toTypedArray()
        // Default highlight = MED (index 1) if the stored value isn't known.
        val checked = shakeSensitivityOptions.indexOf(current).let { if (it < 0) 1 else it }
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_settings_shake_sensitivity_title)
            .setSingleChoiceItems(labels, checked) { dialog, which ->
                StreamPreferences.setShakeSensitivity(this, shakeSensitivityOptions[which])
                refreshShakeBtns()
                dialog.dismiss()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun confirmLock() {
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_settings_lock_dialog_title)
            .setMessage(R.string.stream_settings_lock_dialog_message)
            .setPositiveButton(R.string.stream_settings_lock_dialog_action) { _, _ ->
                // Signal the recording service to stop BEFORE wiping the
                // ratchet, and keep the two calls in that order. If a
                // recording is active when the user taps Lock, the service
                // would otherwise keep emitting frames and the next
                // chunkEncryptor.encryptChunk() would crash on a wiped ratchet
                // (null kit). Audit FRAG-R1-4, Phase 3.40.
                //
                // stopService is async — onDestroy takes up to ~6.5 s to
                // drain : flushThread.join(3500) then a 3 s wait on
                // pendingChunks (StreamRecordingService, raised from 1.5 s to
                // 3 s by the Blue HIGH-2 fix). Encryption attempts during that
                // window fail and skip gracefully rather than crash, which is
                // the right semantics for an explicit Lock — don't "fix" that
                // race by blocking the UI thread on a join.
                stopService(Intent(this, rs.readahead.washington.mobile
                    .service.StreamRecordingService::class.java))

                StreamUploadManager.getInstance(this).lock()
                // Clear the upload JWT on user-initiated
                // lock. The token survives a plain `Stop recording`
                // (so pending chunks drain), but a Lock is an
                // explicit "drop privileges now".
                rs.readahead.washington.mobile.util.jobs
                    .UploadAuthHolder.clear()
                refresh()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun confirmPanicWipe() {
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.stream_settings_wipe_dialog_title)
            .setMessage(R.string.stream_settings_wipe_dialog_message)
            .setPositiveButton(R.string.stream_settings_wipe_dialog_action) { _, _ ->
                // Double confirmation
                AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
                    .setTitle(R.string.stream_settings_wipe_confirm_title)
                    .setMessage(R.string.stream_settings_wipe_confirm_message)
                    .setPositiveButton(R.string.stream_settings_wipe_confirm_yes) { _, _ ->
                        // FRAG-R1-4 — stop the recording
                        // service before wiping. Same rationale as
                        // confirmLock(): a panic wipe must terminate
                        // any in-flight encryption before destroying
                        // the keys it depends on. The blobs already on
                        // disk are wiped by panicWipe() itself.
                        stopService(Intent(this, rs.readahead.washington
                            .mobile.service.StreamRecordingService::class.java))

                        // Wipe V2 state (identité + ratchet + blobs)
                        StreamUploadManager.getInstance(this).panicWipe()
                        // §10.6 — also drop the upload bearer on the Kotlin
                        // side. panicWipe() already zeroizes the Rust-held
                        // holder ; this call keeps its reason to exist for the
                        // OkHttp connection-pool eviction, which retains
                        // bearer copies (HPACK / Headers) that panicWipe
                        // doesn't reach.
                        rs.readahead.washington.mobile.util.jobs
                            .UploadAuthHolder.clear()

                        // Audit R-E-2 — purge the WorkManager history too.
                        // androidx.work.workdb (cleartext SQLite) holds the
                        // pending chunk file paths, the relay URL and report
                        // IDs; panicWipe (stream-crypto) doesn't reach it, so on
                        // a seized device it left a forensic upload timeline.
                        // Cancel all queued work + prune the terminal rows.
                        // Best-effort/async (UI callback): the cancel is
                        // persisted immediately, pruneWork drops finished rows.
                        try {
                            val wm = androidx.work.WorkManager.getInstance(this)
                            wm.cancelAllWork()
                            wm.pruneWork()
                        } catch (e: Exception) {
                            android.util.Log.w(
                                "StreamSettings", "WorkManager panic prune failed", e
                            )
                        }

                        // Lance OnBoardingActivity avec le flag IS_ONBOARD_LOCK_SET=true :
                        // Tella sait que le lock est déjà setup → saute directement à
                        // OnBoardLockSetFragment → OnBoardMnemonicGenerateFragment
                        // → confirm → V2 SetPin → enrollment.
                        val intent = Intent(
                            this,
                            rs.readahead.washington.mobile.views.activity.onboarding.OnBoardingActivity::class.java
                        ).apply {
                            putExtra(rs.readahead.washington.mobile.util.IS_ONBOARD_LOCK_SET, true)
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                                    Intent.FLAG_ACTIVITY_CLEAR_TASK
                        }
                        startActivity(intent)
                        finish()
                    }
                    .setNegativeButton(R.string.action_cancel, null)
                    .show()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }
}
