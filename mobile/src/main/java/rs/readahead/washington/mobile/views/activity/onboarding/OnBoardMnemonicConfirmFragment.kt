package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.core.widget.doAfterTextChanged
import org.stream.crypto.Bip39
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.base_ui.BaseFragment
import timber.log.Timber

class OnBoardMnemonicConfirmFragment : BaseFragment() {

    // ByteArray (UTF-8 bytes) au lieu de CharArray.
    // MnemonicHolder.mnemonic retourne maintenant un ByteArray.
    private var mnemonic: ByteArray = ByteArray(0)

    // Les trois mots tirés au sort que le témoin doit retaper, sans accents,
    // dans l'ordre de checkIndices. Chaque mot est un morceau du secret : un
    // mot et sa position réduisent l'espace à fouiller pour retrouver la
    // phrase. Seuls ces trois-là deviennent des String ; les neuf autres
    // restent dans le ByteArray, wipé dans onDestroy.
    private var expected: List<String> = emptyList()
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
        // Les mots sont repérés dans les octets, sans décoder la phrase
        // entière en String : seuls les trois mots tirés sont décodés.
        // Le mnemonic reste ByteArray pour le passage au FFI Rust.
        val words = wordRanges(mnemonic)
        if (words.size < 12) {
            baseActivity.onBackPressed()
            return
        }
        checkIndices = words.indices.shuffled().take(3).sorted()
        expected = checkIndices.map { i ->
            val range = words[i]
            Bip39.stripAccents(
                String(mnemonic, range.first, range.last - range.first + 1, Charsets.UTF_8).lowercase()
            )
        }

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

        // Le message d'erreur porte sur les mots tapés : il disparaît dès que
        // le témoin retape dans une case. Une case vidée ne le retire pas ;
        // les cases vidées après une confirmation réussie non plus, c'est la
        // branche de succès qui le retire elle-même, plus bas.
        for (input in listOf(input1, input2, input3)) {
            input.doAfterTextChanged { if (!it.isNullOrEmpty()) errorText.visibility = View.GONE }
        }

        view.findViewById<TextView>(R.id.confirmBtn).setOnClickListener {
            // V2 fix : compare en forme accent-stripped pour tolerer "aieul" == "aieul"
            val typed = listOf(input1, input2, input3).map {
                Bip39.stripAccents(it.text.toString().trim().lowercase())
            }

            if (typed == expected) {
                // Les mots quittent les cases avant l'écran suivant : ce
                // fragment reste dans la pile, caché, pendant le choix du PIN,
                // et revient tel quel sur un retour arrière. setText("") et non
                // text.clear() : clear() est une modification que l'historique
                // d'annulation garde, et qu'une annulation rejouerait.
                // setText remplace le tampon et oublie cet historique ; il
                // n'efface pas pour autant l'ancien tampon de la mémoire, ni
                // les String lues ci-dessus. Le message d'une tentative
                // ratée part avec eux : au retour, il resterait affiché
                // au-dessus de cases vides, comme si la phrase notée était
                // fausse.
                errorText.visibility = View.GONE
                input1.setText("")
                input2.setText("")
                input3.setText("")
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
        expected = emptyList()
        super.onDestroy()
    }

    private companion object {
        val BLANKS = " \t\n\r".toByteArray(Charsets.US_ASCII).toSet()

        /**
         * Bornes (inclusives) de chaque mot de la phrase, séparés par des
         * blancs ASCII. Couper sur des octets ASCII est sûr en UTF-8 : un
         * caractère accentué n'est codé qu'avec des octets >= 0x80.
         */
        fun wordRanges(bytes: ByteArray): List<IntRange> {
            val ranges = mutableListOf<IntRange>()
            var start = -1
            for (i in bytes.indices) {
                val blank = bytes[i] in BLANKS
                if (!blank && start < 0) start = i
                if (blank && start >= 0) {
                    ranges += start until i
                    start = -1
                }
            }
            if (start >= 0) ranges += start until bytes.size
            return ranges
        }
    }
}
