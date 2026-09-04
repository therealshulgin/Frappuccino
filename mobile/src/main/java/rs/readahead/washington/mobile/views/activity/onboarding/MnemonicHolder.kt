package rs.readahead.washington.mobile.views.activity.onboarding

import timber.log.Timber

/**
 * In-memory holder for the BIP-39 mnemonic during onboarding.
 *
 * Ne jamais faire transiter ce secret par un Android Bundle : un Bundle peut
 * être sérialisé sur disque, donc la phrase de récupération finirait écrite
 * sur le stockage d'un appareil saisissable. C'est la forme la plus naturelle
 * de passage entre fragments, donc précisément celle qu'on refera si personne
 * ne l'interdit par écrit. D'où ce holder.
 *
 * Garanties :
 *   * [set] copie défensivement le buffer du caller (qui garde sa propre
 *     responsabilité de wipe).
 *   * [mnemonic] retourne aussi une copie défensive — le consumer doit
 *     wiper ce qu'il reçoit (idéalement via [org.stream.crypto.SecureWipe.wipe]).
 *   * [clear] zéroïse le buffer interne avant de drop la référence.
 *
 * Le buffer est un `ByteArray` (bytes UTF-8 du mnemonic) depuis 6.1.4-B. Ne
 * pas revenir à `CharArray` sous prétexte que `char[]` est la forme
 * habituellement recommandée pour un secret en Java : c'est ce qui existait
 * avant (CRIT-02, audit V2), et cela obligeait à faire `String(mnemonic)` au
 * point d'entrée FFI, donc à matérialiser une String Java immuable, impossible
 * à effacer avant le GC. Les bytes passent tels quels à FFI Rust, qui les wrap
 * en `Zeroizing<Vec<u8>>` au plus tôt.
 *
 * Le holder lui-même ne matérialise jamais de `String`, et le chemin
 * d'enrôlement reste en bytes jusqu'au FFI. Un consommateur peut en revanche
 * en fabriquer une : l'écran de confirmation construit une String transitoire
 * pour découper les mots ([OnBoardMnemonicConfirmFragment]), résidu borné et
 * documenté sur place. Si tu ajoutes un consommateur, reste sur les bytes.
 */
object MnemonicHolder {

    @Volatile
    private var buffer: ByteArray? = null

    /** Replace the held mnemonic with a defensive copy of [value]. Wipes the previous. */
    @Synchronized
    fun set(value: ByteArray) {
        val prev = buffer
        buffer = value.copyOf()
        prev?.let { org.stream.crypto.SecureWipe.wipe(it) }
        // Observabilité bug "phrase perdue". Stack trace permet
        // d'identifier le callsite exact en field.
        Timber.tag("MnemonicHolder").d(
            Throwable("phrase_holder_set"),
            "set() len=%d (prev_was_present=%b)", value.size, prev != null
        )
    }

    /**
     * Returns a defensive copy of the held mnemonic, or null if none.
     * The returned [ByteArray] MUST be wiped by the caller (idéalement via
     * [org.stream.crypto.SecureWipe.wipe]) après usage.
     */
    @get:Synchronized
    val mnemonic: ByteArray?
        get() = buffer?.copyOf()

    /** True iff a mnemonic is currently held. Cheaper than [mnemonic] (no copy). */
    @get:Synchronized
    val isPresent: Boolean
        get() = buffer != null

    /** Wipe the held mnemonic and drop the reference. Idempotent. */
    @Synchronized
    fun clear() {
        val wasPresent = buffer != null
        buffer?.let { org.stream.crypto.SecureWipe.wipe(it) }
        buffer = null
        if (wasPresent) {
            // Observabilité bug "phrase perdue". Le stack
            // identifie quel chemin (success enroll / server-down / autre)
            // a effacé le mnemonic avant qu'un back ne ramène l'utilisateur
            // sur SetPin/Confirm sans phrase disponible.
            Timber.tag("MnemonicHolder").d(
                Throwable("phrase_holder_clear"),
                "clear() called (was present)"
            )
        }
    }
}
