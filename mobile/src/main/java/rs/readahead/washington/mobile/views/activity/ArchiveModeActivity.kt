package rs.readahead.washington.mobile.views.activity

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.upload.ArchiveSession
import org.stream.crypto.upload.DiscoveredReport
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.service.ArchiveDownloadService
import rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder
import rs.readahead.washington.mobile.views.adapters.ArchiveReportsAdapter
import timber.log.Timber

/**
 * ArchiveModeActivity — Mode archive V2, l'écran de récupération d'un
 * témoignage depuis la phrase de récupération. Accessible depuis
 * StreamSettingsActivity.
 *
 * Lifetime des secrets : par défaut l'activity wipe [ArchiveIdentity] +
 * [ArchiveSession] en [onDestroy]. Pendant un batch, [ArchiveDownloadService]
 * les emprunte et la règle « le dernier vivant wipe » arbitre
 * (cf. [ArchiveAuthHolder]) — d'où le test sur le service dans [onDestroy] :
 * un wipe inconditionnel zéroiserait les secrets sous les pieds d'un download
 * en cours. La phrase, elle, ne quitte jamais cette activity : pas de log, pas
 * de Bundle, pas de putExtra.
 *
 * Le flux : saisie de la phrase BIP-39 (12 mots), dérivation d'une
 * [ArchiveIdentity] temporaire en SecureMemory, affichage du fingerprint
 * dérivé pour comparaison avec l'identité locale, puis découverte des reports
 * par DÉRIVATION — il n'y a pas de listing : [ArchiveSession] sonde
 * report_id_0, report_id_1, … sans auth ni bearer, parce que le report_id
 * dérivé de la phrase est la capability. Un tap sur un report, ou le bouton
 * « TOUT TÉLÉCHARGER », délègue à [ArchiveDownloadService] : il télécharge et
 * déchiffre les blobs vers le dossier public de téléchargements
 * (`Frappuccino/<rid>/`, via MediaStore), écrit un `playlist.m3u` à côté, et
 * renvoie sa progression par broadcasts. Les reports terminés restent listés
 * et marqués. Cette activity n'est qu'un contrôleur : elle démarre le service,
 * observe, met à jour l'UI.
 */
class ArchiveModeActivity : AppCompatActivity() {

    private lateinit var mnemonicInput: EditText
    private lateinit var statusView: TextView
    private lateinit var fingerprintView: TextView
    private lateinit var unlockBtn: TextView
    private lateinit var closeBtn: TextView
    private lateinit var streamsInfoView: TextView
    private lateinit var retrieveBtn: TextView
    private lateinit var downloadAllBtn: TextView
    private lateinit var reportsList: RecyclerView
    private lateinit var progressView: TextView
    private lateinit var openFolderBtn: TextView

    private var archiveIdentity: ArchiveIdentity? = null
    // §10.11 Phase B — provenance signer derived from the SAME phrase, held to
    // re-derive the per-recording OTS salt for the disclosure bundle. Wiped with
    // the identity (onDestroy / ArchiveAuthHolder.clear).
    private var archiveProvenanceSigner: uniffi.frappuccino.ProvenanceSigner? = null
    // Phase C — cached bytes of the validated mnemonic, used at startRetrieve to
    // derive the report keyring for relay-blind enumeration. Wiped right after
    // the keyring is derived (and defensively in onDestroy).
    private var cachedMnemonic: ByteArray? = null
    private var archiveSession: ArchiveSession? = null
    private var reportsAdapter: ArchiveReportsAdapter? = null

    /**
     * Receives download progress/results from
     * [ArchiveDownloadService] (registered in onResume, unregistered in
     * onPause). Drives the progressView text + the adapter ✓ marks. The
     * heavy lifting is in the service; this just paints the UI.
     */
    private val downloadReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                ArchiveDownloadService.ACTION_ARCHIVE_PROGRESS -> {
                    val rId = intent.getStringExtra(ArchiveDownloadService.EXTRA_REPORT_ID) ?: ""
                    val rIdx = intent.getIntExtra(ArchiveDownloadService.EXTRA_REPORT_INDEX, 0)
                    val rTot = intent.getIntExtra(ArchiveDownloadService.EXTRA_REPORT_TOTAL, 0)
                    val bName = intent.getStringExtra(ArchiveDownloadService.EXTRA_BLOB_NAME) ?: ""
                    val bIdx = intent.getIntExtra(ArchiveDownloadService.EXTRA_BLOB_INDEX, 0)
                    val bTot = intent.getIntExtra(ArchiveDownloadService.EXTRA_BLOB_TOTAL, 0)
                    progressView.visibility = View.VISIBLE
                    progressView.text = if (bTot > 0) {
                        getString(R.string.archive_retrieving_blob, bName, bIdx, bTot)
                    } else {
                        getString(R.string.archive_download_all_progress, rIdx, rTot, rId.take(8))
                    }
                }

                ArchiveDownloadService.ACTION_ARCHIVE_REPORT_DONE -> {
                    val rId = intent.getStringExtra(ArchiveDownloadService.EXTRA_REPORT_ID) ?: return
                    reportsAdapter?.markDownloaded(rId)
                }

                ArchiveDownloadService.ACTION_ARCHIVE_BATCH_DONE -> {
                    val count = intent.getIntExtra(ArchiveDownloadService.EXTRA_COUNT, 0)
                    val dir = intent.getStringExtra(ArchiveDownloadService.EXTRA_PUBLIC_DIR) ?: ""
                    progressView.visibility = View.VISIBLE
                    progressView.text = getString(R.string.archive_download_all_done, count, dir)
                    openFolderBtn.visibility = View.VISIBLE
                    setDownloadInProgress(false)
                }

                ArchiveDownloadService.ACTION_ARCHIVE_ERROR -> {
                    val rIdx = intent.getIntExtra(ArchiveDownloadService.EXTRA_REPORT_INDEX, 0)
                    val rTot = intent.getIntExtra(ArchiveDownloadService.EXTRA_REPORT_TOTAL, 0)
                    progressView.visibility = View.VISIBLE
                    progressView.text = getString(R.string.archive_download_all_partial, rIdx, rTot)
                    setDownloadInProgress(false)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_archive_mode)

        mnemonicInput = findViewById(R.id.archiveMnemonicInput)
        statusView = findViewById(R.id.archiveStatus)
        fingerprintView = findViewById(R.id.archiveFingerprint)
        unlockBtn = findViewById(R.id.archiveUnlockBtn)
        closeBtn = findViewById(R.id.archiveCloseBtn)
        streamsInfoView = findViewById(R.id.archiveStreamsInfo)
        retrieveBtn = findViewById(R.id.archiveRetrieveBtn)
        downloadAllBtn = findViewById(R.id.archiveDownloadAllBtn)
        reportsList = findViewById(R.id.archiveReportsList)
        progressView = findViewById(R.id.archiveProgressText)
        openFolderBtn = findViewById(R.id.archiveOpenFolderBtn)

        reportsList.layoutManager = LinearLayoutManager(this)
        reportsAdapter = ArchiveReportsAdapter(mutableListOf()) { report ->
            // Single-report download. Phase 4.4.5 — the list stays visible ;
            // the row is just marked ✓ when finished.
            startSingleDownload(report)
        }
        reportsList.adapter = reportsAdapter

        unlockBtn.setOnClickListener { tryUnlock() }
        closeBtn.setOnClickListener { finish() }
        retrieveBtn.setOnClickListener { startRetrieve() }
        downloadAllBtn.setOnClickListener { startDownloadAll() }
        openFolderBtn.setOnClickListener { openRecoveryFolder() }

        // Mark the activity alive so a running download
        // service knows the activity still owns the final secret wipe.
        ArchiveAuthHolder.setActivityAlive(true)
    }

    private fun tryUnlock() {
        val phrase = mnemonicInput.text.toString().trim().lowercase()
        val words = phrase.split(Regex("\\s+")).filter { it.isNotBlank() }
        if (words.size != 12) {
            statusView.text = "PHRASE INVALIDE : attendu 12 mots, recu ${words.size}"
            statusView.setTextColor(resources.getColor(R.color.wa_orange, theme))
            return
        }

        statusView.text = "DERIVATION DE LA CLE..."
        statusView.setTextColor(resources.getColor(R.color.wa_white, theme))

        // Convertir immediatement en ByteArray UTF-8
        // (jamais de CharArray intermediaire ni de String passee a FFI).
        val mnemonicBytes = words.joinToString(" ").toByteArray(Charsets.UTF_8)
        try {
            try {
                uniffi.frappuccino.bip39ValidateFr(mnemonicBytes)
            } catch (e: uniffi.frappuccino.FfiException.InvalidMnemonicWord) {
                statusView.text = "Mot inconnu : '${e.word}'. Verifiez l'orthographe."
                statusView.setTextColor(resources.getColor(R.color.wa_orange, theme))
                return
            } catch (e: uniffi.frappuccino.FfiException.InvalidMnemonic) {
                statusView.text = "Phrase BIP-39 invalide : ${e.detail}"
                statusView.setTextColor(resources.getColor(R.color.wa_orange, theme))
                return
            }

            val manager = StreamUploadManager.getInstance(this)
            val archive = manager.createArchiveIdentity(mnemonicBytes)
            archiveIdentity = archive

            // §10.11 Phase B — derive the provenance signer from the SAME phrase
            // (empty passphrase, as at enrollment) so the rescue can re-derive the
            // per-recording OTS salt to export into the disclosure bundle. Held +
            // wiped exactly like the identity; best-effort (provenance is opt-in,
            // a derivation failure must never break the archive unlock).
            archiveProvenanceSigner = try {
                uniffi.frappuccino.ProvenanceSigner.fromMnemonic(mnemonicBytes, byteArrayOf())
            } catch (e: Exception) {
                Timber.w(e, "tryUnlock: provenance signer derivation failed (OTS salt export disabled)")
                null
            }

            // Phase 4.4.2 — cache a COPY of the mnemonic for the auth flow.
            cachedMnemonic = mnemonicBytes.copyOf()

            mnemonicInput.setText("")
            // Phase 4.4.2 fix (2026-05-20) : dismiss the IME after a
            // successful unlock (otherwise the soft keyboard hides the list).
            try {
                val imm = getSystemService(android.content.Context.INPUT_METHOD_SERVICE)
                    as? android.view.inputmethod.InputMethodManager
                imm?.hideSoftInputFromWindow(mnemonicInput.windowToken, 0)
                mnemonicInput.clearFocus()
            } catch (e: Exception) {
                Timber.w(e, "tryUnlock: hide IME failed (cosmetic)")
            }

            statusView.text = "ARCHIVE DEVERROUILLEE"
            statusView.setTextColor(resources.getColor(R.color.wa_white, theme))
            fingerprintView.text = archive.readableFingerprint()
            fingerprintView.visibility = View.VISIBLE
            streamsInfoView.visibility = View.VISIBLE
            retrieveBtn.visibility = View.VISIBLE

            val localIdentity = org.stream.crypto.StreamPreferences.getIdentity(this)
            if (localIdentity != null) {
                val matches = localIdentity.ed25519PublicKey.contentEquals(archive.ed25519PublicKey)
                streamsInfoView.text = if (matches) {
                    "OK Phrase correspond a l'identite de ce device.\n\nTape sur RECUPERER pour fetch les streams uploades."
                } else {
                    "ATTENTION Phrase DIFFERENTE de l'identite locale.\nTu vas dechiffrer les streams d'une AUTRE identite."
                }
            } else {
                streamsInfoView.text = "Pas d'identite locale — archive seule.\n\nTape sur RECUPERER pour fetch les streams uploades."
            }

            unlockBtn.visibility = View.GONE
        } catch (e: Exception) {
            Timber.e(e, "Archive derivation failed")
            statusView.text = "ERREUR : ${e.message}"
            statusView.setTextColor(resources.getColor(R.color.wa_orange, theme))
        } finally {
            // SecureWipe au lieu de fill (resiste JIT).
            org.stream.crypto.SecureWipe.wipe(mnemonicBytes)
        }
    }

    /**
     * Orchestrates the relay-blind retrieval flow : derive a report keyring
     * from the phrase, then enumerate the witness's own reports by DERIVATION
     * — [ArchiveSession] probes report_id_0, report_id_1, …, with no auth call
     * and no listing endpoint, the phrase-derived report_id being the
     * capability. The reports are then displayed in the RecyclerView, ready
     * for tap-to-download and/or "TOUT TÉLÉCHARGER" bulk action.
     *
     * Stays on lifecycleScope/Dispatchers.IO : this is a short operation
     * (derivation + enumeration), screen-off during it is not a concern. The
     * long part (the actual download) runs in [ArchiveDownloadService].
     */
    private fun startRetrieve() {
        archiveIdentity ?: run {
            Timber.w("startRetrieve: no archiveIdentity")
            return
        }
        val mnemonic = cachedMnemonic ?: run {
            Timber.w("startRetrieve: no cached mnemonic — re-unlock needed")
            statusView.text = "Phrase perdue, ressaisis-la."
            return
        }
        val manager = StreamUploadManager.getInstance(this)
        val serverUrl = manager.getServerUrl() ?: run {
            statusView.text = "Pas d'URL serveur configuree dans Settings."
            return
        }

        retrieveBtn.visibility = View.GONE
        statusView.text = getString(R.string.archive_retrieving_reports)

        lifecycleScope.launch(Dispatchers.IO) {
            // Phase C relay-blind — id-free session. No auth, no bearer: the
            // phrase-derived report_id is the capability. The witness discovers
            // its own reports by DERIVATION (not "list what I own"): derive the
            // report keyring from the phrase and enumerate report_id_0.. .
            val session = ArchiveSession(serverUrl)
            archiveSession = session

            val keyring = try {
                uniffi.frappuccino.ReportKeyring.fromMnemonic(mnemonic, byteArrayOf())
            } catch (e: Exception) {
                Timber.e(e, "startRetrieve: report keyring derivation threw")
                withContext(Dispatchers.Main) {
                    statusView.text = "Erreur derivation cle : ${e.message}"
                    retrieveBtn.visibility = View.VISIBLE
                }
                return@launch
            } finally {
                // The keyring (and the already-derived identity + provenance
                // signer) is all we need from the phrase — wipe the activity-side
                // copy now. SecureWipe = volatile overwrite (resists JIT).
                org.stream.crypto.SecureWipe.wipe(mnemonic)
                cachedMnemonic = null
            }

            val reports = try {
                session.enumerate(keyring)
            } catch (e: Exception) {
                // A persistent transport failure aborts enumeration rather than
                // truncating it (a relay outage must never read as "no reports").
                Timber.e(e, "startRetrieve: enumerate threw")
                withContext(Dispatchers.Main) {
                    statusView.text = "Erreur reseau enumeration : ${e.message}"
                    retrieveBtn.visibility = View.VISIBLE
                }
                return@launch
            } finally {
                // The report_ids are captured (Strings); the keyring secret is
                // no longer needed for the download phase (id-free by report_id).
                try {
                    keyring.destroy()
                } catch (e: Exception) {
                    Timber.w(e, "startRetrieve: keyring.destroy() threw (best-effort)")
                }
            }

            withContext(Dispatchers.Main) {
                if (reports.isEmpty()) {
                    statusView.text = getString(R.string.archive_no_reports)
                    retrieveBtn.visibility = View.VISIBLE
                    return@withContext
                }
                statusView.text =
                    "${reports.size} report(s) trouve(s) — tape pour telecharger"
                streamsInfoView.visibility = View.GONE
                reportsAdapter?.submit(reports)
                reportsList.visibility = View.VISIBLE
                // Expose the bulk DOWNLOAD ALL button as soon
                // as we have something to download.
                downloadAllBtn.visibility = View.VISIBLE
            }
        }
    }

    /**
     * Visual guard for "a download is running" : the orange
     * "TOUT TÉLÉCHARGER" button is disabled + faded while a batch runs.
     * Driven on at [startDownloadService], off by the BATCH_DONE / ERROR
     * broadcasts (and onResume re-attach).
     */
    private fun setDownloadInProgress(active: Boolean) {
        downloadAllBtn.isEnabled = !active
        downloadAllBtn.alpha = if (active) 0.4f else 1f
    }

    /**
     * Confirmation dialog before re-downloading a
     * report that's already saved. Prevents a finger-slip from kicking off
     * a heavy re-download. Calls [onConfirm] only on the positive button.
     */
    private fun confirmRedownload(
        onConfirm: () -> Unit,
    ) {
        androidx.appcompat.app.AlertDialog.Builder(this, R.style.AlertDialogDarkTheme)
            .setTitle(R.string.archive_redownload_title)
            .setMessage(R.string.archive_redownload_message)
            .setPositiveButton(R.string.archive_redownload_confirm) { _, _ -> onConfirm() }
            .setNegativeButton(R.string.archive_redownload_cancel, null)
            .show()
    }

    /**
     * Single-report download (tap on a row). Routes
     * through [ArchiveDownloadService] like the bulk path (same screen-off
     * resilience). Busy guard + re-download confirm are unchanged.
     */
    private fun startSingleDownload(report: DiscoveredReport) {
        if (ArchiveDownloadService.isRunning) {
            Toast.makeText(this, R.string.archive_busy, Toast.LENGTH_SHORT).show()
            return
        }
        if (reportsAdapter?.isDownloaded(report.reportId) == true) {
            confirmRedownload {
                startDownloadService(listOf(report.reportId), clearFirst = true)
            }
            return
        }
        startDownloadService(listOf(report.reportId), clearFirst = false)
    }

    /**
     * Bulk "TOUT TÉLÉCHARGER". Hands the adapter's
     * pending reports (not yet ✓ this session) to [ArchiveDownloadService],
     * which downloads them sequentially and survives screen-off. Resumable :
     * re-tapping only retries the remaining ones.
     */
    private fun startDownloadAll() {
        if (ArchiveDownloadService.isRunning) {
            Toast.makeText(this, R.string.archive_busy, Toast.LENGTH_SHORT).show()
            return
        }
        val pending = reportsAdapter?.pendingReports() ?: emptyList()
        if (pending.isEmpty()) {
            progressView.visibility = View.VISIBLE
            progressView.text = "Tous les reports sont déjà téléchargés ✓"
            return
        }
        startDownloadService(pending.map { it.reportId }, clearFirst = false)
    }

    /**
     * Hand the unlocked identity + archive session (relay-blind:
     * no identity, no bearer) to [ArchiveDownloadService] via
     * [ArchiveAuthHolder] (RAM, NEVER through the Intent — only the public
     * report ids travel in the Intent) and start the foreground service.
     */
    private fun startDownloadService(pendingIds: List<String>, clearFirst: Boolean) {
        val id = archiveIdentity
        val session = archiveSession
        if (id == null || session == null) {
            Toast.makeText(this, R.string.archive_auth_refused, Toast.LENGTH_SHORT).show()
            return
        }
        ArchiveAuthHolder.set(id, session, archiveProvenanceSigner)
        setDownloadInProgress(true)
        progressView.visibility = View.VISIBLE
        val intent = Intent(this, ArchiveDownloadService::class.java).apply {
            putStringArrayListExtra(
                ArchiveDownloadService.EXTRA_PENDING_IDS, ArrayList(pendingIds)
            )
            putExtra(ArchiveDownloadService.EXTRA_CLEAR_FIRST, clearFirst)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    /**
     * Phase 4.4.2 fix — open the public Downloads folder via an
     * `ACTION_VIEW_DOWNLOADS` intent. Falls back to a toast carrying a
     * hardcoded folder hint if the intent isn't resolved; that hint is not
     * the relative path actually used at write time
     * (`Environment.DIRECTORY_DOWNLOADS` + `/Frappuccino/<report_id>`).
     */
    private fun openRecoveryFolder() {
        val hint = "Downloads/Frappuccino/"
        try {
            val intent = Intent(android.app.DownloadManager.ACTION_VIEW_DOWNLOADS).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Timber.w(e, "openRecoveryFolder: DownloadManager intent failed, fallback toast")
            Toast.makeText(
                this,
                "Fichiers récupérés dans : $hint",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    override fun onResume() {
        super.onResume()
        // Re-assert ownership (covers an activity recreate that raced a
        // running service's teardown).
        ArchiveAuthHolder.setActivityAlive(true)

        val filter = IntentFilter().apply {
            addAction(ArchiveDownloadService.ACTION_ARCHIVE_PROGRESS)
            addAction(ArchiveDownloadService.ACTION_ARCHIVE_REPORT_DONE)
            addAction(ArchiveDownloadService.ACTION_ARCHIVE_BATCH_DONE)
            addAction(ArchiveDownloadService.ACTION_ARCHIVE_ERROR)
        }
        // androidx.core in this project predates ContextCompat.registerReceiver
        // (added 1.9.0), so branch on the API level directly. The broadcasts
        // are package-local (setPackage), so the NOT_EXPORTED flag is only a
        // belt on API 33+ where it exists.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(downloadReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(downloadReceiver, filter)
        }

        // Re-attach : broadcasts may have been missed while paused / the
        // activity was stopped. Restore the ✓ marks + progress from the
        // service's static mirrors.
        val doneIds = ArchiveDownloadService.doneReportIds.toList()
        doneIds.forEach { reportsAdapter?.markDownloaded(it) }
        if (ArchiveDownloadService.isRunning) {
            setDownloadInProgress(true)
            val idx = ArchiveDownloadService.lastReportIndex
            val tot = ArchiveDownloadService.lastReportTotal
            if (tot > 0) {
                progressView.visibility = View.VISIBLE
                progressView.text =
                    getString(R.string.archive_download_all_progress, idx, tot, "")
            }
        } else {
            setDownloadInProgress(false)
            if (doneIds.isNotEmpty()) openFolderBtn.visibility = View.VISIBLE
        }
    }

    override fun onPause() {
        try {
            unregisterReceiver(downloadReceiver)
        } catch (_: Exception) {
        }
        super.onPause()
    }

    override fun onDestroy() {
        // The activity is no longer the unconditional owner
        // of the archive secrets. If a download service is running, it
        // borrows identity+session via ArchiveAuthHolder and wipes them
        // when it stops (activityAlive=false tells it to). If no service is
        // running, we wipe here as before. close() is idempotent → any
        // race between the two paths is a harmless no-op.
        ArchiveAuthHolder.setActivityAlive(false)
        if (!ArchiveDownloadService.isRunning) {
            // Wipes the holder copy (same refs) AND the activity refs.
            ArchiveAuthHolder.clear()
            try {
                archiveSession?.close()
            } catch (_: Exception) {
            }
            archiveIdentity?.close()
            // §10.11 Phase B — wipe the provenance signer's seed (mlock'd). The
            // holder.clear() above already destroyed the shared ref; destroy() is
            // idempotent, so this is a no-op if it ran, and a safety net otherwise.
            try {
                archiveProvenanceSigner?.destroy()
            } catch (_: Exception) {
            }
        }
        archiveSession = null
        archiveIdentity = null
        archiveProvenanceSigner = null

        // Defensive wipe of any leftover mnemonic.
        cachedMnemonic?.let { org.stream.crypto.SecureWipe.wipe(it) }
        cachedMnemonic = null

        super.onDestroy()
    }
}
