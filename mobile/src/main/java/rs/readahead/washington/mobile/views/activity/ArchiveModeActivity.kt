package rs.readahead.washington.mobile.views.activity

import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.SecureWipe
import org.stream.crypto.StreamPreferences
import org.stream.crypto.upload.ArchiveSession
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.archive.ArchiveLocalData
import rs.readahead.washington.mobile.archive.ArchivePlayerActivity
import rs.readahead.washington.mobile.archive.ArchivePurgeRules
import rs.readahead.washington.mobile.archive.ArchiveWipeWatch
import rs.readahead.washington.mobile.archive.FailureReason
import rs.readahead.washington.mobile.archive.PendingExport
import rs.readahead.washington.mobile.archive.RescueAnomalies
import rs.readahead.washington.mobile.archive.RescueAnomaly
import rs.readahead.washington.mobile.archive.RescueSession
import rs.readahead.washington.mobile.service.ArchiveDownloadService
import rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder
import rs.readahead.washington.mobile.views.adapters.ArchiveReportsAdapter
import rs.readahead.washington.mobile.views.adapters.ArchiveUnverifiableAdapter
import timber.log.Timber
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.ProvenanceSigner

/**
 * ArchiveModeActivity — l'écran de secours : retrouver et vérifier son
 * témoignage depuis la seule phrase de récupération. Accessible depuis
 * StreamSettingsActivity.
 *
 * Le flux :
 * 1. Saisie de la phrase BIP-39 (12 mots). Elle est convertie en octets, sert
 *    à dériver l'identité de déchiffrement, le signataire de provenance et le
 *    contexte de secours ([ArchiveSession]), puis elle est effacée : elle ne
 *    quitte jamais cette activité (pas de log, pas de Bundle, pas d'Intent).
 * 2. RÉCUPÉRER lance la recherche des rapports par dérivation, dans
 *    [ArchiveDownloadService] : l'annuaire, puis chaque index que le plan
 *    désigne. Un 429 fait attendre au moins une minute puis rejoue la même
 *    cible ; une recherche qui ne peut pas aller au bout s'affiche
 *    INCOMPLÈTE, jamais comme une liste courte.
 * 3. VÉRIFIER (par rapport ou TOUT VÉRIFIER) télécharge chaque objet chiffré
 *    dans `noBackupFilesDir/archive_view/<jeton>/`, où Rust le classe ; ce qui
 *    est exclu est effacé et compté. Chaque rapport affiche son statut, ses
 *    compteurs et l'intervalle de dates du relais.
 * 4. REGARDER ouvre le lecteur interne ; EXPORTER, après un avertissement,
 *    écrit les seuls objets vérifiés dans un dossier choisi par le témoin.
 *    Plus rien n'est écrit dans le dossier public Download.
 * 5. Les objets legacy stockés avant que le relais garde les signatures ne
 *    sont ni vérifiés ni exclus : ils sont gardés à part et listés dans la
 *    section « non vérifiable », sous les rapports. On peut les y regarder
 *    (bandeau permanent dans le lecteur) et les exporter, après un second
 *    avertissement, dans un dossier distinct étiqueté `not-verified`. Ils ne
 *    sont jamais mêlés au témoignage vérifié.
 *
 * Durée de vie des secrets et des copies : « le dernier vivant purge »
 * (cf. [ArchiveAuthHolder], [ArchiveLocalData]). Une fermeture explicite
 * (bouton ← ou retour) annule le lot en cours ; si plus aucun écran
 * d'archive ni lot ne vit, cette activité efface les secrets et purge les
 * copies, sinon le service le fait en fin de lot. Une destruction par le
 * système (activité en arrière-plan) n'est pas une fermeture : le lot continue
 * et la notification ramène à l'écran, qui se rattache à la session en RAM.
 * L'effacement d'urgence, lui, ferme l'écran même en arrière-plan
 * ([ArchiveWipeWatch]).
 */
class ArchiveModeActivity : AppCompatActivity() {

    private lateinit var mnemonicInput: EditText
    private lateinit var statusView: TextView
    private lateinit var fingerprintView: TextView
    private lateinit var unlockBtn: TextView
    private lateinit var closeBtn: TextView
    private lateinit var streamsInfoView: TextView
    private lateinit var retrieveBtn: TextView
    private lateinit var enumStatusView: TextView
    private lateinit var anomaliesView: TextView
    private lateinit var verifyAllBtn: TextView
    private lateinit var reportsList: RecyclerView
    private lateinit var unverifiableSection: View
    private lateinit var unverifiableList: RecyclerView

    private lateinit var reportsAdapter: ArchiveReportsAdapter
    private lateinit var unverifiableAdapter: ArchiveUnverifiableAdapter

    /** The export waiting for the folder picker. Saved with the instance
     *  state: the picker's answer may reach a recreated screen. */
    private var pendingExport: PendingExport? = null

    private var unlocking = false

    private val pickExportFolder =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
            val answer = PendingExport.answer(pendingExport, folderChosen = uri != null)
            pendingExport = null
            when (answer) {
                is PendingExport.Answer.Start ->
                    if (uri != null && ArchiveAuthHolder.isUnlocked()) {
                        ArchiveDownloadService.startExport(this, answer.ordinal, uri, answer.unverifiable)
                    } else {
                        Toast.makeText(this, R.string.archive_export_lost, Toast.LENGTH_LONG).show()
                    }
                PendingExport.Answer.Lost ->
                    Toast.makeText(this, R.string.archive_export_lost, Toast.LENGTH_LONG).show()
                PendingExport.Answer.Cancelled -> Unit
            }
        }

    private val rescueReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ArchiveDownloadService.ACTION_RESCUE_CHANGED) render()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        ArchiveWipeWatch.attach(this) { finish() }
        setContentView(R.layout.activity_archive_mode)
        // Before the picker's answer, which arrives after onStart.
        pendingExport = savedInstanceState?.let {
            PendingExport.fromSaved(
                it.getInt(PendingExport.KEY_ORDINAL, 0),
                it.getBoolean(PendingExport.KEY_UNVERIFIABLE, false),
            )
        }

        mnemonicInput = findViewById(R.id.archiveMnemonicInput)
        statusView = findViewById(R.id.archiveStatus)
        fingerprintView = findViewById(R.id.archiveFingerprint)
        unlockBtn = findViewById(R.id.archiveUnlockBtn)
        closeBtn = findViewById(R.id.archiveCloseBtn)
        streamsInfoView = findViewById(R.id.archiveStreamsInfo)
        retrieveBtn = findViewById(R.id.archiveRetrieveBtn)
        enumStatusView = findViewById(R.id.archiveEnumStatus)
        anomaliesView = findViewById(R.id.archiveAnomalies)
        verifyAllBtn = findViewById(R.id.archiveVerifyAllBtn)
        reportsList = findViewById(R.id.archiveReportsList)
        unverifiableSection = findViewById(R.id.archiveUnverifiableSection)
        unverifiableList = findViewById(R.id.archiveUnverifiableList)

        reportsAdapter = ArchiveReportsAdapter(
            onVerify = { ordinal -> startVerification(intArrayOf(ordinal)) },
            onPlay = { ordinal -> openPlayer(ordinal) },
            onExport = { ordinal -> confirmExport(ordinal) },
        )
        reportsList.layoutManager = LinearLayoutManager(this)
        reportsList.adapter = reportsAdapter
        unverifiableAdapter = ArchiveUnverifiableAdapter(
            onPlay = { ordinal -> openPlayer(ordinal, unverifiable = true) },
            onExport = { ordinal -> confirmExport(ordinal, unverifiable = true) },
        )
        unverifiableList.layoutManager = LinearLayoutManager(this)
        unverifiableList.adapter = unverifiableAdapter

        unlockBtn.setOnClickListener { tryUnlock() }
        closeBtn.setOnClickListener { requestClose() }
        retrieveBtn.setOnClickListener { startEnumeration() }
        verifyAllBtn.setOnClickListener { verifyAll() }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = requestClose()
        })

        ArchiveAuthHolder.attachActivity()

        // Back from the notification, or recreated by the system while a
        // batch ran: the session is still in RAM, show it.
        if (ArchiveAuthHolder.isUnlocked()) showUnlocked(ArchiveAuthHolder.getIdentity())
    }

    // ---- unlock ----

    private fun tryUnlock() {
        if (unlocking) return
        // The EditText hands out a String: unavoidable. Everything after it
        // works on bytes, wiped once the keys are derived.
        val words = mnemonicInput.text.toString().trim().lowercase()
            .split(Regex("\\s+")).filter { it.isNotBlank() }
        if (words.size != 12) {
            setStatus(getString(R.string.archive_phrase_wrong_count, words.size), warning = true)
            return
        }
        val serverUrl = StreamUploadManager.getInstance(this).getServerUrl()
        if (serverUrl.isNullOrBlank()) {
            setStatus(getString(R.string.archive_no_server), warning = true)
            return
        }
        val mnemonicBytes = words.joinToString(" ").toByteArray(Charsets.UTF_8)
        unlocking = true
        setStatus(getString(R.string.archive_deriving), warning = false)

        lifecycleScope.launch {
            // Set from the derivation thread as soon as the keys exist, and
            // cleared once the holder owns them: if this screen is destroyed
            // meanwhile, the finally below wipes them instead of leaving them
            // to the garbage collector.
            var unowned: Unlock.Done? = null
            try {
                val result = withContext(Dispatchers.Default) {
                    derive(mnemonicBytes, serverUrl).also { if (it is Unlock.Done) unowned = it }
                }
                unlocking = false
                when (result) {
                    is Unlock.Done -> {
                        ArchiveAuthHolder.set(result.identity, result.session, result.signer)
                        unowned = null
                        // Cleared on success only: a mistyped phrase stays to be corrected.
                        mnemonicInput.setText("")
                        hideKeyboard()
                        showUnlocked(result.identity)
                    }
                    is Unlock.Failed -> setStatus(getString(result.message), warning = true)
                }
            } finally {
                unowned?.wipe()
            }
        }
    }

    /** Derive the rescue's keys from the phrase, then wipe the phrase. */
    private fun derive(mnemonicBytes: ByteArray, serverUrl: String): Unlock {
        try {
            uniffi.frappuccino.bip39ValidateFr(mnemonicBytes)
            val identity = ArchiveIdentity.fromMnemonic(mnemonicBytes)
            val session = try {
                ArchiveSession.open(serverUrl, mnemonicBytes)
            } catch (e: Exception) {
                identity.close()
                throw e
            }
            // Best effort: the timestamp check needs it, the rescue itself
            // does not.
            val signer = try {
                ProvenanceSigner.fromMnemonic(mnemonicBytes, byteArrayOf())
            } catch (e: Exception) {
                Timber.w(e, "ArchiveModeActivity: provenance signer not derived")
                null
            }
            return Unlock.Done(identity, session, signer)
        } catch (e: FfiException.InvalidMnemonicWord) {
            return Unlock.Failed(R.string.archive_unknown_word)
        } catch (e: FfiException.InvalidMnemonic) {
            return Unlock.Failed(R.string.archive_invalid_phrase)
        } catch (e: Exception) {
            Timber.e(e, "ArchiveModeActivity: key derivation failed")
            return Unlock.Failed(R.string.archive_unlock_failed)
        } finally {
            SecureWipe.wipe(mnemonicBytes)
        }
    }

    private sealed class Unlock {
        class Done(val identity: ArchiveIdentity, val session: ArchiveSession, val signer: ProvenanceSigner?) : Unlock() {
            fun wipe() {
                session.close()
                identity.close()
                try {
                    signer?.destroy()
                } catch (_: Exception) {
                }
            }
        }

        class Failed(val message: Int) : Unlock()
    }

    private fun showUnlocked(identity: ArchiveIdentity?) {
        mnemonicInput.visibility = View.GONE
        unlockBtn.visibility = View.GONE
        setStatus(getString(R.string.archive_unlocked), warning = false)
        if (identity != null) {
            fingerprintView.text = identity.readableFingerprint()
            fingerprintView.visibility = View.VISIBLE
            val local = StreamPreferences.getIdentity(this)
            streamsInfoView.text = getString(
                when {
                    local == null -> R.string.archive_identity_none
                    local.ed25519PublicKey.contentEquals(identity.ed25519PublicKey) -> R.string.archive_identity_matches
                    else -> R.string.archive_identity_differs
                },
            )
            streamsInfoView.visibility = View.VISIBLE
        }
        render()
    }

    private fun hideKeyboard() {
        try {
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
            imm?.hideSoftInputFromWindow(mnemonicInput.windowToken, 0)
            mnemonicInput.clearFocus()
        } catch (e: Exception) {
            Timber.w(e, "ArchiveModeActivity: hide IME failed (cosmetic)")
        }
    }

    private fun setStatus(text: String, warning: Boolean) {
        statusView.text = text
        statusView.setTextColor(ContextCompat.getColor(this, if (warning) R.color.wa_orange else R.color.wa_white))
    }

    // ---- batches ----

    private fun busy(): Boolean {
        if (ArchiveDownloadService.isRunning) {
            Toast.makeText(this, R.string.archive_busy, Toast.LENGTH_SHORT).show()
            return true
        }
        return false
    }

    private fun startEnumeration() {
        if (!ArchiveAuthHolder.isUnlocked() || busy()) return
        RescueSession.markEnumerationStarting()
        ArchiveDownloadService.startEnumeration(this)
        render()
    }

    private fun startVerification(ordinals: IntArray) {
        if (ordinals.isEmpty() || !ArchiveAuthHolder.isUnlocked() || busy()) return
        ArchiveDownloadService.startVerification(this, ordinals)
    }

    private fun verifyAll() {
        val pending = RescueSession.snapshot().entries
            .filter { it.state != RescueSession.EntryState.VERIFIED }
            .map { it.ordinal }
        startVerification(pending.toIntArray())
    }

    /** [unverifiable]: play the chunks kept apart as not verifiable, from
     *  their own section, instead of the verified ones. */
    private fun openPlayer(ordinal: Int, unverifiable: Boolean = false) {
        val entry = RescueSession.snapshot().entries.firstOrNull { it.ordinal == ordinal } ?: return
        val token = entry.token
        val chunks = if (unverifiable) entry.unverifiableChunks else entry.playableChunks
        if (token == null || chunks == 0) {
            Toast.makeText(
                this,
                if (unverifiable) R.string.archive_play_none_unverifiable else R.string.archive_play_none,
                Toast.LENGTH_SHORT,
            ).show()
            return
        }
        startActivity(ArchivePlayerActivity.intent(this, token, unverifiable))
    }

    /**
     * Export: an explicit warning first (the copy leaves the app's
     * protection and the emergency wipe), then the system folder picker. A
     * phone without one says so instead of failing silently. The export of
     * the objects kept apart as not verifiable ([unverifiable]) has its own
     * warning, which adds that nothing proves they are the witness's.
     */
    private fun confirmExport(ordinal: Int, unverifiable: Boolean = false) {
        if (busy()) return
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(
                if (unverifiable) R.string.archive_unverifiable_export_warning_title
                else R.string.archive_export_warning_title,
            )
            .setMessage(
                if (unverifiable) R.string.archive_unverifiable_export_warning_message
                else R.string.archive_export_warning_message,
            )
            .setPositiveButton(R.string.archive_export_confirm) { _, _ ->
                pendingExport = PendingExport(ordinal, unverifiable)
                try {
                    pickExportFolder.launch(null)
                } catch (e: ActivityNotFoundException) {
                    pendingExport = null
                    Toast.makeText(this, R.string.archive_export_no_picker, Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton(R.string.archive_cancel, null)
            .show()
    }

    // ---- rendering ----

    private fun render() {
        if (!ArchiveAuthHolder.isUnlocked()) {
            retrieveBtn.visibility = View.GONE
            enumStatusView.visibility = View.GONE
            anomaliesView.visibility = View.GONE
            verifyAllBtn.visibility = View.GONE
            reportsList.visibility = View.GONE
            unverifiableSection.visibility = View.GONE
            return
        }
        val snapshot = RescueSession.snapshot()
        val enumeration = snapshot.enumeration
        val running = ArchiveDownloadService.isRunning

        retrieveBtn.setText(
            if (enumeration.state == RescueSession.EnumerationState.NOT_STARTED) R.string.archive_retrieve_btn
            else R.string.archive_retry_btn,
        )
        retrieveBtn.visibility = when (enumeration.state) {
            RescueSession.EnumerationState.NOT_STARTED,
            RescueSession.EnumerationState.INCOMPLETE,
            RescueSession.EnumerationState.CANCELLED,
            -> if (running) View.GONE else View.VISIBLE
            else -> View.GONE
        }

        val enumText = enumerationText(enumeration)
        enumStatusView.text = enumText
        enumStatusView.visibility = if (enumText.isEmpty()) View.GONE else View.VISIBLE
        enumStatusView.setTextColor(
            ContextCompat.getColor(
                this,
                if (enumeration.state == RescueSession.EnumerationState.INCOMPLETE) R.color.wa_orange else R.color.wa_white,
            ),
        )

        val anomalies = anomaliesText(enumeration)
        anomaliesView.text = anomalies
        anomaliesView.visibility = if (anomalies.isEmpty()) View.GONE else View.VISIBLE

        reportsAdapter.submit(snapshot.entries)
        reportsList.visibility = if (snapshot.entries.isEmpty()) View.GONE else View.VISIBLE
        val unverified = snapshot.entries.any { it.state != RescueSession.EntryState.VERIFIED }
        verifyAllBtn.visibility = if (unverified && !running) View.VISIBLE else View.GONE

        unverifiableAdapter.submit(snapshot.entries)
        unverifiableSection.visibility =
            if (ArchiveUnverifiableAdapter.rows(snapshot.entries).isEmpty()) View.GONE else View.VISIBLE
    }

    private fun enumerationText(e: RescueSession.EnumerationView): String {
        val found = resources.getQuantityString(R.plurals.archive_reports_found, e.found, e.found)
        // A 429 being waited out, during the search or a verification: say
        // why nothing moves for a minute.
        val waitMs = e.rateLimitedUntil - System.currentTimeMillis()
        if (waitMs > 0 && ArchiveDownloadService.isRunning) {
            return getString(R.string.archive_enum_rate_limited, ((waitMs + 999) / 1000).toInt())
        }
        return when (e.state) {
            RescueSession.EnumerationState.NOT_STARTED -> ""
            RescueSession.EnumerationState.RUNNING -> getString(
                R.string.archive_enum_running,
                resources.getQuantityString(R.plurals.archive_enum_probed, e.probed, e.probed),
                found,
            )
            RescueSession.EnumerationState.COMPLETE ->
                if (e.found == 0) getString(R.string.archive_enum_none) else getString(R.string.archive_enum_complete, found)
            // Cut at the planner's probe cap: searching again stops at the
            // same cap, so the line must not suggest that it would help.
            RescueSession.EnumerationState.INCOMPLETE ->
                if (e.failure == FailureReason.PROBE_CAP) {
                    getString(R.string.archive_enum_capped, found)
                } else {
                    getString(
                        R.string.archive_enum_incomplete,
                        ArchiveReportsAdapter.reasonText(this, e.failure),
                        found,
                    )
                }
            RescueSession.EnumerationState.CANCELLED -> getString(R.string.archive_enum_cancelled)
        }
    }

    /** The anomalies of [e], chosen by [RescueAnomalies]; only the wording is
     *  decided here. */
    private fun anomaliesText(e: RescueSession.EnumerationView): String =
        RescueAnomalies.of(e).joinToString("\n") { anomaly ->
            when (anomaly) {
                RescueAnomaly.DirectoryClosed -> getString(R.string.archive_anomaly_directory_closed)
                RescueAnomaly.DirectoryClosureInvalid -> getString(R.string.archive_anomaly_directory_closure_invalid)
                RescueAnomaly.DirectoryClosureUnchecked -> getString(R.string.archive_anomaly_directory_closure_unchecked)
                RescueAnomaly.DirectoryAbsent -> getString(R.string.archive_anomaly_directory_absent)
                RescueAnomaly.DirectoryUnreadable -> getString(R.string.archive_anomaly_directory_unreadable)
                is RescueAnomaly.Unmatched ->
                    resources.getQuantityString(R.plurals.archive_anomaly_unmatched, anomaly.count, anomaly.count)
                is RescueAnomaly.UnreadableListings ->
                    resources.getQuantityString(R.plurals.archive_anomaly_unreadable_listings, anomaly.count, anomaly.count)
            }
        }

    // ---- lifecycle ----

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        // A position and a flag, nothing secret (see PendingExport).
        pendingExport?.let {
            outState.putInt(PendingExport.KEY_ORDINAL, it.ordinal)
            outState.putBoolean(PendingExport.KEY_UNVERIFIABLE, it.unverifiable)
        }
    }

    override fun onResume() {
        super.onResume()
        // Only the repaint signal: the emergency wipe is watched for the
        // screen's whole life, not only while it is shown (ArchiveWipeWatch).
        val filter = IntentFilter(ArchiveDownloadService.ACTION_RESCUE_CHANGED)
        // androidx.core in this project predates ContextCompat.registerReceiver
        // (added 1.9.0), so branch on the API level directly. The broadcasts
        // are package-local (setPackage), so the NOT_EXPORTED flag is only a
        // belt on API 33+ where it exists.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(rescueReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(rescueReceiver, filter)
        }
        // Changes made while paused were not received: catch up.
        if (ArchiveAuthHolder.isUnlocked()) render() else if (unlockBtn.visibility == View.GONE) finish()
    }

    override fun onPause() {
        try {
            unregisterReceiver(rescueReceiver)
        } catch (_: Exception) {
        }
        super.onPause()
    }

    /** Explicit close: confirm if work is running (it will be cancelled). */
    private fun requestClose() {
        if (!ArchiveDownloadService.isRunning) {
            finish()
            return
        }
        AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.archive_close_confirm_title)
            .setMessage(R.string.archive_close_confirm_message)
            .setPositiveButton(R.string.archive_close_confirm_yes) { _, _ -> finish() }
            .setNegativeButton(R.string.archive_cancel, null)
            .show()
    }

    override fun onDestroy() {
        // An explicit close (finish) ends the rescue: cancel the batch and stop
        // the service, whose teardown then purges at once (no screen is left)
        // instead of after the call in flight. A destruction by the system is
        // not a close, and the batch goes on. Nor is a recreation for a
        // configuration change: the new instance attaches right after this
        // one detaches, so this one must not purge on its way out.
        val stillAttached = ArchiveAuthHolder.detachActivity()
        if (isFinishing) ArchiveDownloadService.stop(this)
        if (!isChangingConfigurations &&
            ArchivePurgeRules.shouldPurge(stillAttached, ArchiveDownloadService.isRunning)
        ) {
            ArchiveAuthHolder.clear()
            ArchiveLocalData.purgeAll(this)
        }
        super.onDestroy()
    }
}
