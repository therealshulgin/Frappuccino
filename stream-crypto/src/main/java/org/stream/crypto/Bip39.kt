package org.stream.crypto

/**
 * Bip39 — ce qui reste de BIP-39 cote Kotlin, c'est-a-dire presque rien.
 *
 * Aucune logique BIP-39 ne doit revenir ici. Depuis le pivot "100% crypto Rust",
 * generation, normalisation, derivation de seed et validation vivent cote Rust
 * dans `crypto-rs/core/src/bip39.rs`, exposees via UniFFI :
 *
 *   - `uniffi.frappuccino.bip39GenerateFr()` -> ByteArray (UTF-8)
 *   - `uniffi.frappuccino.bip39ValidateFr(mnemonic: ByteArray)`
 *   - `uniffi.frappuccino.bip39NormalizeWordFr(word: String) -> String`
 *
 * La surface est FR-only : l'`ENGLISH_WORDLIST` d'origine est partie avec le
 * reste du code Kotlin, et cote Rust `Language` ne connait que le francais.
 *
 * Le seul helper encore necessaire cote Kotlin est `stripAccents`, utilise par
 * `OnBoardMnemonicConfirmFragment` pour comparer les mots tapes par l'user en
 * mode "tolerant accents" : un mot saisi sans accent doit matcher le mot accentue
 * de la wordlist, et inversement. Ce n'est pas de la crypto, juste une
 * normalisation UTF-8 / NFD : ne cherchez pas ici de propriete de wipe ou de
 * temps constant.
 */
object Bip39 {

    /**
     * Strip les accents d'une chaine : "aieul" -> "aieul", "zebre" -> "zebre".
     * Utilise Unicode NFD + filtre des combining marks.
     *
     * Pas de crypto, juste de la normalisation UTF-8 — utile pour comparer
     * des mots saisis par l'user a la wordlist canonique sans se soucier
     * des accents.
     */
    fun stripAccents(s: String): String {
        val decomposed = java.text.Normalizer.normalize(s, java.text.Normalizer.Form.NFD)
        return decomposed.replace(Regex("\\p{Mn}+"), "")
    }
}
