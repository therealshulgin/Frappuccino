package rs.readahead.washington.mobile.views.activity.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.base_ui.BaseFragment
import uniffi.frappuccino.bip39GenerateFr

class OnBoardMnemonicGenerateFragment : BaseFragment() {

    // ByteArray (UTF-8 bytes du mnemonic) au lieu de
    // CharArray. La generation vient du Rust UniFFI : cote Rust la SOURCE est
    // un Zeroizing<String> wipe a son drop, mais les octets rendus ici sont
    // une copie NON zeroizee (cf. la note WP-F1 plus bas) — c'est au Kotlin de
    // les SecureWipe. Pas de String / CharArray cote Kotlin avant Rust.
    private var mnemonic: ByteArray = ByteArray(0)

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_onboard_mnemonic_generate, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        initView(view)
    }

    override fun initView(view: View) {
        (baseActivity as OnBoardActivityInterface).hideProgress()

        generateMnemonic(view)

        view.findViewById<TextView>(R.id.regenerateBtn).setOnClickListener {
            generateMnemonic(view)
        }

        view.findViewById<TextView>(R.id.nextBtn).setOnClickListener {
            // MnemonicHolder defensively copies — our ByteArray is still valid after.
            MnemonicHolder.set(mnemonic)
            baseActivity.addFragment(this, OnBoardMnemonicConfirmFragment(), R.id.rootOnboard)
        }

        view.findViewById<TextView>(R.id.backBtn).setOnClickListener {
            baseActivity.onBackPressed()
        }
    }

    private fun generateMnemonic(view: View) {
        // Le ByteArray rendu par bip39GenerateFr() est une COPIE NON zeroizee.
        // Cote Rust, seule la SOURCE (Zeroizing<String> de core::bip39) est
        // wipe a son drop : UniFFI n'expose aucun hook de zeroize sur un retour
        // de bytes, il copie les octets dans un RustBuffer puis drop la source
        // sans wiper la copie. Ne pas croire, ni reecrire, que "le buffer Rust
        // est wipe au drop" : c'est ce que disait l'ancien commentaire et c'est
        // faux (WP-F1, audit L-1). Ne pas supprimer non plus les deux defenses
        // Kotlin qui en decoulent — le SecureWipe juste en dessous avant
        // regeneration, et celui de onDestroy() — sinon la phrase de
        // recuperation, racine de l'identite, reste en clair dans la heap JVM
        // pour toute la vie du process.
        //
        // Ce ByteArray est le buffer de travail (bytes UTF-8).
        // C'est un residu transitoire borne, inevitable pour afficher la phrase
        // a l'ecran ; les Strings de la grille en sont un second, decrit sur
        // displayWords(). Cf. WP-G (residu documente).
        org.stream.crypto.SecureWipe.wipe(mnemonic)
        mnemonic = bip39GenerateFr()
        displayWords(view)
    }

    private fun displayWords(view: View) {
        val grid = view.findViewById<androidx.gridlayout.widget.GridLayout>(R.id.wordsGrid)
        grid.removeAllViews()

        // Conversion ByteArray UTF-8 -> String pour
        // l'affichage TextView (TextView.setText prend CharSequence, impose
        // par Android). C'est le seul chemin ou le mnemonic prend la forme
        // String : la phrase entiere le temps du decoupage, puis un mot par
        // TextView. Ces Strings ne sont jamais persistees, mais elles ne sont
        // pas wipables et restent atteignables en heap tant que la grille est
        // affichee, puis jusqu'au GC — residu transitoire assume (cf. WP-G).
        // Le reste du flow (passage a FFI Rust) reste en bytes.
        val mnemonicStr = String(mnemonic, Charsets.UTF_8)
        val words = mnemonicStr.split(" ")
        for (i in words.indices) {
            val wordView = TextView(requireContext()).apply {
                text = "${i + 1}. ${words[i]}"
                textSize = 16f
                setTextColor(resources.getColor(R.color.wa_white, null))
                setPadding(16, 12, 16, 12)
                layoutParams = androidx.gridlayout.widget.GridLayout.LayoutParams().apply {
                    columnSpec = androidx.gridlayout.widget.GridLayout.spec(i % 3, 1f)
                    rowSpec = androidx.gridlayout.widget.GridLayout.spec(i / 3)
                    setMargins(4, 4, 4, 4)
                }
            }
            grid.addView(wordView)
        }
    }

    override fun onDestroy() {
        org.stream.crypto.SecureWipe.wipe(mnemonic)
        super.onDestroy()
    }
}
