package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.base_ui.BaseFragment
import timber.log.Timber

class OnBoardMnemonicConfirmFragment : BaseFragment() {

    // ByteArray (UTF-8 bytes) au lieu de CharArray.
    // MnemonicHolder.mnemonic retourne maintenant un ByteArray.
    private var mnemonic: ByteArray = ByteArray(0)

    // Individual words — not sensitive alone (public BIP-39 wordlist).
    private var words: List<String> = emptyList()
    private var checkIndices: List<Int> = emptyList()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_onboard_mnemonic_confirm, container, false)
    }

    // Do NOT override onViewCreated — BaseFragment calls initView() for us

    override fun initView(view: View) {
        val held = MnemonicHolder.mnemonic
        if (held == null) {
            // Observabilité bug "phrase perdue". Path silencieux :
            // Confirm a été ré-affiché (recreate fragment via process death,
            // config change, ou flow inattendu) et MnemonicHolder est vide.
            // L'utilisateur sera renvoyé vers Generate qui régénère, ce qui
            // ressemble à "ma phrase a changé toute seule".
            Timber.tag("MnemonicHolder").e(
                Throwable("phrase_holder_null_confirm"),
                "Confirm.initView: holder null -> popping back to Generate"
            )
            baseActivity.onBackPressed()
            return
        }
        mnemonic = held
        // Transient String pour split — short-lived,
        // uniquement pour comparaison des 3 mots echantillon (mots
        // individuels = wordlist publique BIP-39, pas sensibles isoles).
        // Le mnemonic reste ByteArray pour le passage au FFI Rust.
        words = String(mnemonic, Charsets.UTF_8).split(" ").filter { it.isNotBlank() }
        if (words.size < 12) {
            baseActivity.onBackPressed()
            return
        }
        checkIndices = (0 until words.size).shuffled().take(3).sorted()

        (baseActivity as OnBoardActivityInterface).hideProgress()

        val label1 = view.findViewById<TextView>(R.id.wordLabel1)
        val label2 = view.findViewById<TextView>(R.id.wordLabel2)
        val label3 = view.findViewById<TextView>(R.id.wordLabel3)
        val input1 = view.findViewById<EditText>(R.id.wordInput1)
        val input2 = view.findViewById<EditText>(R.id.wordInput2)
        val input3 = view.findViewById<EditText>(R.id.wordInput3)
        val errorText = view.findViewById<TextView>(R.id.errorText)

        label1.text = "Mot #${checkIndices[0] + 1}"
        label2.text = "Mot #${checkIndices[1] + 1}"
        label3.text = "Mot #${checkIndices[2] + 1}"

        view.findViewById<TextView>(R.id.confirmBtn).setOnClickListener {
            // V2 fix : compare en forme accent-stripped pour tolerer "aieul" == "aieul"
            val w1 = org.stream.crypto.Bip39.stripAccents(input1.text.toString().trim().lowercase())
            val w2 = org.stream.crypto.Bip39.stripAccents(input2.text.toString().trim().lowercase())
            val w3 = org.stream.crypto.Bip39.stripAccents(input3.text.toString().trim().lowercase())

            val correct = w1 == org.stream.crypto.Bip39.stripAccents(words[checkIndices[0]].lowercase()) &&
                    w2 == org.stream.crypto.Bip39.stripAccents(words[checkIndices[1]].lowercase()) &&
                    w3 == org.stream.crypto.Bip39.stripAccents(words[checkIndices[2]].lowercase())

            if (correct) {
                // V2 : la phrase reste dans MnemonicHolder (RAM seulement,
                // ByteArray wipeable via SecureWipe).
                // OnBoardSetPinFragment la consomme + PIN via enrollFromMnemonic,
                // puis clear le MnemonicHolder et continue.
                baseActivity.addFragment(
                    this, OnBoardSetPinFragment(), R.id.rootOnboard
                )
            } else {
                errorText.visibility = View.VISIBLE
                errorText.text = "Un ou plusieurs mots sont incorrects. Verifiez votre phrase."
            }
        }

        view.findViewById<TextView>(R.id.backBtn).setOnClickListener {
            baseActivity.onBackPressed()
        }
    }

    override fun onDestroy() {
        // SecureWipe au lieu de fill (resiste JIT).
        org.stream.crypto.SecureWipe.wipe(mnemonic)
        super.onDestroy()
    }
}
