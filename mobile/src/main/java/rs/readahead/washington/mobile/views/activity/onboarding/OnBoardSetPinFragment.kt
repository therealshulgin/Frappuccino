package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.FragmentManager
import rs.readahead.washington.mobile.views.pin.NoImeEditText
import org.hzontal.shared_ui.pinview.PinLockListener
import org.hzontal.shared_ui.pinview.PinLockView
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.base_ui.BaseFragment
import timber.log.Timber

/**
 * Ne jamais réintroduire un pavé PIN maison pour tenir le PIN dans un tableau
 * wipable de bout en bout. Cet écran partage volontairement le composant
 * [PinLockView] avec l'écran de déverrouillage, pour que les deux écrans PIN
 * de l'app se ressemblent ; le PinPadView V2 maison, retiré ici
 * (Option C-revert), gardait bien un [CharArray] sur tout le chemin, mais
 * l'écart visuel n'était pas acceptable. L'harmonisation était purement
 * cosmétique et n'a jamais autorisé à toucher au pipeline d'enrôlement.
 *
 * Le prix assumé de ce partage : [PinLockView] livre le PIN comme [String]
 * dans son listener. Une String est immuable, donc impossible à wiper — elle
 * reste sur le heap JVM jusqu'au GC. On la convertit en ByteArray le plus tôt
 * possible et c'est ce ByteArray-là qu'on wipe après usage ; c'est le mieux
 * que l'API permette, et le résidu est connu et accepté.
 *
 * Étape finale de l'onboarding V2, après la phrase BIP-39. Le PIN se saisit
 * deux fois, [Step.ENTER] puis [Step.CONFIRM], et c'est tout ce que demande
 * l'onboarding : les écrans PIN Tella (SetPinActivity / ConfirmPinActivity)
 * ne sont plus dans le dépôt, seuls leurs noms subsistent dans des
 * commentaires. Si les deux saisies correspondent,
 * [StreamUploadManager.enrollFromMnemonic] persiste l'identité et le ratchet
 * PIN-wrappé, puis on navigue vers OnBoardInviteCodeFragment ; sinon on
 * revient à la première saisie avec un message d'erreur.
 */
class OnBoardSetPinFragment : BaseFragment(), PinLockListener {

    private enum class Step { ENTER, CONFIRM }
    private var step = Step.ENTER
    // ByteArray (ASCII digits) au lieu de CharArray. Évite
    // une étape de conversion supplémentaire vers le ByteArray attendu par
    // le FFI Rust.
    private var firstPin: ByteArray? = null

    private lateinit var stepLabelView: TextView
    private lateinit var titleView: TextView
    private lateinit var msgView: TextView
    private lateinit var errorView: TextView
    private lateinit var pinEditText: NoImeEditText
    private lateinit var pinLockView: PinLockView

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_onboard_set_pin, container, false)
    }

    override fun initView(view: View) {
        (baseActivity as OnBoardActivityInterface).hideProgress()

        stepLabelView = view.findViewById(R.id.onboardPin_stepLabel)
        titleView = view.findViewById(R.id.onboardPin_enterTV)
        msgView = view.findViewById(R.id.onboardPin_msgTV)
        errorView = view.findViewById(R.id.onboardPin_error)
        pinEditText = view.findViewById(R.id.onboardPin_editText)
        pinLockView = view.findViewById(R.id.onboardPin_lockView)

        pinLockView.minPinLength = 6
        pinLockView.setPinLockListener(this)

        updateUIForStep()

        view.findViewById<TextView>(R.id.onboardPin_leftBtn).setOnClickListener {
            if (step == Step.CONFIRM) {
                // Go back to step 1
                wipeFirstPin()
                step = Step.ENTER
                resetPinLockView()
                updateUIForStep()
            } else {
                baseActivity.onBackPressed()
            }
        }
    }

    // -- PinLockListener --

    override fun onEmpty() {
        pinEditText.setText("")
    }

    override fun onPinChange(pinLength: Int, intermediatePin: String?) {
        // PinLockView traque la saisie ; on miroite simplement les chiffres
        // dans l'EditText (style Password_EditText l'affichera en dots ).
        pinEditText.setText(intermediatePin ?: "")
        // Auto-confirm dès qu'on atteint 6 chiffres — pas besoin d'un bouton
        // "Continuer" comme dans les écrans Tella, l'UX V2 reste "tape 6
        // chiffres et c'est validé".
        if (pinLength == 6 && intermediatePin != null) {
            handlePinSubmit(intermediatePin)
            resetPinLockView()
        }
    }

    override fun onPinConfirmation(pin: String?) {
        // Path alternatif : certains keypads valident via touch terminator.
        // Si onPinChange n'a pas auto-soumis (cas où le user tap "OK" hors
        // du 6e chiffre), on traite ici aussi.
        if (pin != null && pin.length == 6) {
            handlePinSubmit(pin)
            resetPinLockView()
        }
    }

    private fun handlePinSubmit(pinStr: String) {
        // Convert String → ByteArray UTF-8 directement
        // (ASCII digits = byte-pour-byte). Plus de CharArray intermédiaire.
        // Le `pinStr` String d'origine reste en JVM heap brièvement
        // (input PinLockView Tella legacy, contrainte API), mais notre
        // copie part en ByteArray vers le FFI Rust.
        val pin = pinStr.toByteArray(Charsets.UTF_8)
        onPinEntered(pin)
    }

    private fun updateUIForStep() {
        when (step) {
            Step.ENTER -> {
                stepLabelView.text = getString(R.string.OnboardPinStep_1)
                stepLabelView.visibility = View.VISIBLE
                titleView.text = getString(R.string.OnboardPinStep_1_Title)
                msgView.text = getString(R.string.OnboardPinStep_1_Hint)
                errorView.visibility = View.GONE
            }
            Step.CONFIRM -> {
                stepLabelView.text = getString(R.string.OnboardPinStep_2)
                stepLabelView.visibility = View.VISIBLE
                titleView.text = getString(R.string.OnboardPinStep_2_Title)
                msgView.text = getString(R.string.OnboardPinStep_2_Hint)
                errorView.visibility = View.GONE
            }
        }
        pinEditText.setText("")
    }

    private fun onPinEntered(pin: ByteArray) {
        when (step) {
            Step.ENTER -> {
                firstPin = pin  // take ownership, will wipe later
                step = Step.CONFIRM
                updateUIForStep()
            }
            Step.CONFIRM -> {
                val first = firstPin
                if (first == null) {
                    org.stream.crypto.SecureWipe.wipe(pin)
                    resetToEnter("Erreur interne — recommencez")
                    return
                }
                if (!first.contentEquals(pin)) {
                    org.stream.crypto.SecureWipe.wipe(pin)
                    wipeFirstPin()
                    resetToEnter("PINs différents — recommencez")
                    return
                }
                // Match → enroll
                enrollWithPin(pin)  // takes ownership
            }
        }
    }

    private fun resetToEnter(errorMsg: String) {
        step = Step.ENTER
        resetPinLockView()
        updateUIForStep()
        errorView.text = errorMsg
        errorView.visibility = View.VISIBLE
    }

    private fun wipeFirstPin() {
        firstPin?.let { org.stream.crypto.SecureWipe.wipe(it) }
        firstPin = null
    }

    /**
     * Le composant [PinLockView] n'expose pas de méthode `reset()` publique.
     * Re-définir le listener recrée son `OnKeyBoardClickListener` interne
     * (lequel garde `mPin = ""`) et re-attache les click handlers — effet
     * net : le PIN saisi est purgé et la frappe repart à 0 chiffres.
     * On miroite le reset visuel dans pinEditText pour que les dots
     * disparaissent en même temps.
     */
    private fun resetPinLockView() {
        pinLockView.setPinLockListener(this)
        pinEditText.setText("")
    }

    private fun enrollWithPin(pin: ByteArray) {
        // MnemonicHolder.mnemonic retourne un ByteArray
        // (UTF-8 bytes du mnemonic, jamais une String). Le caller (nous)
        // est proprietaire et doit wipe via SecureWipe.
        val mnemonicBytes = MnemonicHolder.mnemonic
        if (mnemonicBytes == null || mnemonicBytes.isEmpty()) {
            // Observabilité bug "phrase perdue". Path textuel
            // (le message s'affiche). Combiner avec les logs MnemonicHolder
            // pour identifier qui a fait le clear() et combien de temps avant.
            Timber.tag("MnemonicHolder").e(
                Throwable("phrase_holder_null_setpin"),
                "SetPin.enrollWithPin: holder null/empty -> 'Phrase perdue'"
            )
            org.stream.crypto.SecureWipe.wipe(pin)
            wipeFirstPin()
            resetToEnter("Phrase perdue — retour à l'étape précédente")
            return
        }

        msgView.text = "ENRÔLEMENT LOCAL…"

        // Enrollment local (crypto) + server call must run off the main thread
        // (Argon2id + network). On garde une ref au fragment.
        val ctx = requireContext().applicationContext
        Thread {
            val manager = StreamUploadManager.getInstance(ctx)
            var proof: org.stream.crypto.upload.StreamUploadManager.EnrollmentProof? = null
            var errMsg: String? = null
            var serverOk = false

            try {
                // 1. Dérivation + stockage local (Argon2id ~1.2s)
                proof = manager.enrollFromMnemonic(mnemonicBytes, pin)
                Timber.d("Local enrollment OK — fingerprint: %s",
                    proof.identity.readableFingerprint())

                // 2. UI update : enrôlement serveur
                view?.post { msgView.text = "ENRÔLEMENT SERVEUR…" }

                // 3. POST /auth/v2/enroll
                manager.setServerUrl(DEFAULT_SERVER_URL)
                serverOk = manager.enrollOnServer(proof)

            } catch (e: Exception) {
                Timber.e(e, "Enrollment failed")
                errMsg = e.message ?: "inconnu"
            } finally {
                org.stream.crypto.SecureWipe.wipe(mnemonicBytes)
            }

            // 4. Wipe + navigate on main thread
            view?.post {
                org.stream.crypto.SecureWipe.wipe(pin)
                wipeFirstPin()

                when {
                    errMsg != null -> {
                        // NE PAS clear MnemonicHolder ici. Le
                        // local enrollment a échoué (exception Argon2id, FFI
                        // throw, serveur unreachable wrapped en exception).
                        // L'utilisateur va voir le message d'erreur et
                        // re-saisir son PIN — le mnemonic doit rester en RAM
                        // sinon le retry produit "Phrase perdue" et oblige à
                        // refaire toute l'onboarding (regenerate phrase +
                        // confirm 3 mots) pour récupérer.
                        resetToEnter("Enrôlement échoué : $errMsg")
                    }
                    !serverOk -> {
                        // Local enrollment OK + serveur indisponible. La preuve
                        // a été persistée par enrollFromMnemonic() avant cet
                        // appel. Phase 2.3.2 : EnrollmentRetryWorker auto-retry
                        // dès que le réseau est dispo. Settings expose aussi un
                        // bouton manuel. Le mnemonic n'est plus nécessaire (la
                        // clé est dérivée et stockée localement) — on peut
                        // clear.
                        MnemonicHolder.clear()
                        rs.readahead.washington.mobile.util.jobs.EnrollmentRetryWorker
                            .enqueue(ctx)
                        android.widget.Toast.makeText(
                            ctx,
                            "Serveur indisponible. L'identité est enrôlée localement ; " +
                                "l'enrôlement serveur sera retenté automatiquement dès " +
                                "que le réseau est de retour. Tu peux aussi forcer " +
                                "depuis Réglages → Réessayer l'enrôlement serveur.",
                            android.widget.Toast.LENGTH_LONG
                        ).show()
                        navigateToInviteCode()
                    }
                    else -> {
                        // Local + serveur OK → enroll terminé.
                        MnemonicHolder.clear()
                        Timber.i("V2 enrollment complete — server + local OK")
                        navigateToInviteCode()
                    }
                }
            }
        }.start()
    }

    /**
     * Toujours dépiler TOUTE la chaîne identity-setup avant d'ajouter
     * InviteCode : sans ce pop, `addFragment` empile, et un back depuis
     * InviteCode revient sur un SetPin orphelin dont l'état a survécu (vue et
     * listener [PinLockView] intacts) alors que MnemonicHolder vient d'être
     * vidé. L'utilisateur retape son PIN et reçoit "Phrase perdue" — de son
     * point de vue, sa phrase de récupération a disparu après un enrôlement
     * réussi (bug 7.20).
     *
     * Le pop doit rester synchrone : `popBackStackImmediate` et non
     * `popBackStack`, parce que l'`addFragment` juste en dessous compte sur
     * une pile déjà vidée. Et il doit rester suivi immédiatement de cet ajout,
     * sinon `backStackEntryCount` retombe à 0 et le pager d'intro réapparaît
     * derrière : c'est `addOnBackStackChangedListener` dans OnBoardingActivity
     * qui rend le pager visible dès que la pile est vide, celui-là même qui le
     * cache à l'entrée depuis `goToIdentitySetup()`. Le couplage ne se lit
     * dans aucun des deux fichiers pris isolément.
     */
    private fun navigateToInviteCode() {
        baseActivity.supportFragmentManager.popBackStackImmediate(
            null, FragmentManager.POP_BACK_STACK_INCLUSIVE
        )
        baseActivity.addFragment(
            this@OnBoardSetPinFragment, OnBoardInviteCodeFragment(), R.id.rootOnboard
        )
    }

    companion object {
        private const val DEFAULT_SERVER_URL = "https://relay.shake-document-protect.org:8443"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        wipeFirstPin()
    }
}
