package rs.readahead.washington.mobile.views.activity

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import rs.readahead.washington.mobile.views.pin.NoImeEditText
import org.hzontal.shared_ui.pinview.PinLockListener
import org.hzontal.shared_ui.pinview.PinLockView
import org.stream.crypto.upload.StreamUploadManager
import uniffi.frappuccino.FfiException
import rs.readahead.washington.mobile.R
import timber.log.Timber

/**
 * PinUnlockActivity — Écran de déverrouillage du ratchet V2.
 *
 * Lancé par [StreamActivity] quand `manager.isLocked()`. Sur échec répété,
 * applique un délai exponentiel persistant via [PinAttemptTracker] (plafonné
 * à 10 min) qui résiste au force-kill : c'est ce backoff qui borne un
 * brute-force, il ne doit pas être allégé. Il n'y a PAS de panic wipe sur N
 * échecs (audit 2026-06-26, R-CR-4 — la doc précédente le promettait à tort) ;
 * ne pas raisonner comme si cette défense existait, et surtout ne pas s'appuyer
 * dessus pour relâcher le backoff. Le coût d'un brute-force est borné par
 * Argon2id (~1 s/essai côté Rust) + le backoff, pas par un wipe.
 *
 * Ne pas remplacer [PinLockView] par un pavé PIN maison sur cet écran : un
 * PinPadView V2 custom a existé et a été retiré, parce que l'écran de
 * déverrouillage doit rester visuellement identique à l'écran de création du
 * PIN, qui est aujourd'hui OnBoardSetPinFragment. Le composant partagé vient
 * du module `:shared-ui`.
 *
 * Le prix assumé de ce partage : [PinLockView] livre le PIN comme String
 * (immuable, pool intern), donc impossible à effacer. On le convertit en
 * ByteArray au plus tôt et c'est ce ByteArray qu'on wipe. Voir le commentaire
 * dans OnBoardSetPinFragment pour la justification (cohérence visuelle >
 * strictness sur tout le path, l'attaquant qui exploite le pool intern aurait
 * déjà root le device).
 *
 * Sur succès → finish(RESULT_OK). Sur back-press → finish(RESULT_CANCELED) ;
 * l'appelant décide quoi faire.
 */
class PinUnlockActivity : AppCompatActivity(), PinLockListener {

    private lateinit var pinLockView: PinLockView
    private lateinit var pinEditText: NoImeEditText
    private lateinit var errorView: TextView
    private lateinit var statusView: TextView
    private lateinit var fingerprintView: TextView

    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var unlockInProgress = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE : empêche les screenshots et apparition dans overview
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_pin_unlock)

        pinEditText = findViewById(R.id.unlockDots)
        errorView = findViewById(R.id.unlockError)
        statusView = findViewById(R.id.unlockSubtitle)
        fingerprintView = findViewById(R.id.unlockFingerprint)
        pinLockView = findViewById(R.id.unlockPinLockView)

        pinLockView.minPinLength = 6
        pinLockView.setPinLockListener(this)

        // BT-HIGH-15 — si un lockout est actif (persisté entre sessions),
        // l'indiquer tout de suite à l'utilisateur et afficher le reste.
        val lockUntil = PinAttemptTracker.getLockUntilMs(this)
        val now = System.currentTimeMillis()
        if (lockUntil > now) {
            val remain = (lockUntil - now) / 1000
            showError("Attendez ${remain}s avant de retenter")
        }

        // Affiche le fingerprint pour confirmer visuellement quelle identité
        // est en train d'être déverrouillée
        try {
            val prefs = org.stream.crypto.StreamPreferences.getIdentity(this)
            if (prefs != null) {
                fingerprintView.text = prefs.readableFingerprint()
            }
        } catch (_: Exception) { /* silencieux */ }
    }

    // -- PinLockListener --

    override fun onEmpty() {
        pinEditText.setText("")
    }

    override fun onPinChange(pinLength: Int, intermediatePin: String?) {
        // PinLockView traque la saisie ; on miroite simplement les chiffres
        // dans l'EditText (style Password_EditText les affiche en dots).
        pinEditText.setText(intermediatePin ?: "")
        // Auto-submit dès qu'on atteint 6 chiffres — pas besoin d'un bouton
        // "Continuer" pour cohérence avec OnBoardSetPinFragment.
        if (pinLength == 6 && intermediatePin != null) {
            handlePinSubmit(intermediatePin)
        }
    }

    override fun onPinConfirmation(pin: String?) {
        // Path alternatif (touch terminator). Idem onPinChange à 6 chiffres.
        if (pin != null && pin.length == 6) {
            handlePinSubmit(pin)
        }
    }

    private fun handlePinSubmit(pinStr: String) {
        // Anti-double-submit : Argon2id prend ~1s, l'user pourrait tap encore
        // entretemps si le PinLockView ne se reset pas immédiatement.
        if (unlockInProgress) return
        unlockInProgress = true

        // Convert direct String -> ByteArray (UTF-8 pour
        // ASCII digits = byte-pour-byte). Plus de CharArray intermédiaire.
        // Le `pinStr` String reste en JVM heap brièvement (input du
        // PinLockView Tella), c'est la limite incompressible de cette UI
        // legacy. Le PIN comme bytes part direct au FFI Rust, qui le reçoit
        // en slice nu et le passe à la dérivation Argon2id : ce sont la clé
        // dérivée et le plaintext du blob qui vivent en Zeroizing, pas le
        // PIN. La copie liftée par UniFFI n'est pas effacée à notre
        // connaissance, donc ne pas retirer les SecureWipe.wipe(pin) plus
        // bas en pensant que le Rust s'en charge.
        val pin = pinStr.toByteArray(Charsets.UTF_8)
        // Reset le composant tout de suite pour effacer son state interne
        // mPin (le pinLockView garde une string interne via OnKeyBoardClickListener).
        pinLockView.setPinLockListener(this)
        pinEditText.setText("")
        tryUnlock(pin)
    }

    private fun tryUnlock(pin: ByteArray) {
        val now = System.currentTimeMillis()
        // BT-HIGH-15 — lockUntilMs lu depuis SharedPreferences (survit aux
        // force-kills). Pas de contournement par kill+relaunch.
        val lockUntilMs = PinAttemptTracker.getLockUntilMs(this)
        if (now < lockUntilMs) {
            org.stream.crypto.SecureWipe.wipe(pin)
            val remain = (lockUntilMs - now) / 1000
            showError("Attendez ${remain}s")
            unlockInProgress = false
            return
        }

        statusView.text = "DÉRIVATION DE LA CLÉ…"
        errorView.visibility = View.GONE

        // L'Argon2id bloque ~1s. On laisse sur le main thread pour le demo
        // (l'UI reste frozen ~1s mais c'est fin pour un déverrouillage).
        // TODO(phase 4) : basculer sur un coroutine background.
        try {
            val manager = StreamUploadManager.getInstance(this)
            manager.initializeWithPin(pin)
            org.stream.crypto.SecureWipe.wipe(pin)
            // BT-HIGH-15 — reset persistant du compteur sur succès.
            PinAttemptTracker.recordSuccess(this)
            Timber.d("Ratchet unlocked successfully")
            // The ratchet is now open; kick a one-shot orphan
            // sweep so any backlog from a session that stopped offline starts
            // draining immediately instead of waiting for the 30-min periodic
            // tick (which bails while locked). Closes gap C (2026-06-18).
            rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker
                .scheduleOneShot(applicationContext)
            setResult(RESULT_OK)
            finish()
        } catch (e: FfiException.WrongPin) {
            org.stream.crypto.SecureWipe.wipe(pin)
            // BT-HIGH-15 — persiste l'échec + backoff synchrone avant
            // toute UI update, pour que force-kill ne le perde pas.
            val newLockUntil = PinAttemptTracker.recordFailure(this)
            val attempts = PinAttemptTracker.getAttempts(this)
            if (newLockUntil > 0) {
                val penaltySec = (newLockUntil - System.currentTimeMillis()) / 1000
                showError("PIN incorrect — attendez ${penaltySec}s")
            } else {
                showError("PIN incorrect (tentative $attempts)")
            }
            statusView.text = "PIN POUR DÉVERROUILLER"
            unlockInProgress = false
        } catch (e: Exception) {
            org.stream.crypto.SecureWipe.wipe(pin)
            Timber.e(e, "Unlock failed")
            showError("Erreur : ${e.message}")
            statusView.text = "PIN POUR DÉVERROUILLER"
            unlockInProgress = false
        }
    }

    private fun showError(msg: String) {
        errorView.text = msg
        errorView.visibility = View.VISIBLE
    }

    override fun onBackPressed() {
        setResult(RESULT_CANCELED)
        super.onBackPressed()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
