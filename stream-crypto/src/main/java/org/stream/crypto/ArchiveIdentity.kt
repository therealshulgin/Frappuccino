package org.stream.crypto

import uniffi.frappuccino.ArchiveIdentity as FfiArchiveIdentity

/**
 * ArchiveIdentity — Identite temporaire pour DECHIFFRER les streams passes.
 *
 * Cette classe pose une capacite de dechiffrement sur le telephone et brise donc
 * l'asymetrie device/archive : un appareil saisi ne doit pas pouvoir relire les
 * enregistrements qu'il a produits. Elle est legitime uniquement en mode archive
 * explicite, JAMAIS pendant une session de streaming.
 *
 * Elle se derive uniquement de la phrase BIP-39 et n'est jamais persistee. La cle
 * privee X25519 vit cote Rust dans une `LockedSecret` (mlock'd, ZeroizeOnDrop) qui
 * se wipe quand l'`Arc` UniFFI est droppe, c'est-a-dire a `close()` ou au GC
 * Kotlin. C'est la raison d'etre de l'`AutoCloseable` : sans `use { }`, la cle
 * reste en RAM jusqu'au GC.
 *
 * Le mnemonic et la passphrase passent en `ByteArray` : l'UDL UniFFI accepte
 * `bytes` directement, donc aucune `String` transitoire n'atterrit dans le pool
 * d'intern de la JVM, ou un heap dump la retrouverait. Le type a ne pas
 * reintroduire n'est pas `String`, que personne ne proposerait — c'est
 * `CharArray`, le conseil standard pour manipuler un mot de passe en Java, et
 * c'est justement la signature d'avant : elle obligeait a repasser par un
 * `String(mnemonic)` au boundary FFI, nettoye au mieux par un hack de reflexion.
 * 6.1.4-B a supprime les deux. Le wipe des tableaux, lui, revient a l'appelant —
 * voir [fromMnemonic].
 *
 * La session key et le plaintext ne traversent jamais la JVM : la classe est
 * passee comme handle au chemin de dechiffrement cote Rust
 * (`StreamServerClient.archiveDownloadAndDecrypt` via [inner]), qui descelle et
 * ecrit le clair dans un fichier.
 *
 * ```
 * val mnBytes = ...  // UTF-8 bytes du mnemonic
 * try {
 *   ArchiveIdentity.fromMnemonic(mnBytes).use { archive ->
 *     ArchiveSession(...).download(archive, ...)  // dechiffre cote Rust -> fichier
 *   }  // -> x25519_sk wipe cote Rust
 * } finally {
 *   org.stream.crypto.SecureWipe.wipe(mnBytes)
 * }
 * ```
 *
 * Ne pas reintroduire `decryptSessionKey` : il ramenait la session key 32 octets
 * dans un ByteArray JVM non-Zeroizing et n'avait aucun appelant de production. Il
 * a ete supprime jusque cote FFI (B-CR-4, audit 2026-06-26) ; la primitive
 * d'unseal vit cote Rust uniquement, le chemin reel descelle et dechiffre la-bas.
 *
 * Depuis S8c.4, la classe n'est plus qu'un thin wrapper autour de
 * `uniffi.frappuccino.ArchiveIdentity` : toute la crypto est cote Rust, il n'y a
 * plus de `SecureMemory` ni de lazysodium Kotlin.
 *
 * Consommateur de production :
 * [rs.readahead.washington.mobile.views.activity.ArchiveModeActivity] (mode
 * archive explicite), via `StreamUploadManager.createArchiveIdentity` — c'est la
 * qu'on va verifier que le wipe appelant est bien fait.
 */
class ArchiveIdentity private constructor(
    private val ffi: FfiArchiveIdentity,
    val ed25519PublicKey: ByteArray,
    val x25519PublicKey: ByteArray
) : AutoCloseable {

    @Volatile private var closed = false
    val isClosed: Boolean get() = closed

    /**
     * Handle FFI brut, tenu hors de l'API publique : `internal` porte sur le
     * module Gradle `stream-crypto`, ce qui suffit a
     * [org.stream.crypto.upload.ArchiveSession] pour forwarder l'appel a
     * `archiveDownloadAndDecrypt` sans wrap/unwrap intermediaire (Phase 4.4.2).
     */
    internal val inner: FfiArchiveIdentity get() {
        check(!closed) { "ArchiveIdentity is closed" }
        return ffi
    }

    /**
     * Retourne un fingerprint lisible de l'identite (SHA-256 tronque).
     * Permet a l'utilisateur de verifier qu'il a saisi la bonne phrase.
     */
    fun readableFingerprint(): String {
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(ed25519PublicKey)
        return hash.take(12).joinToString("") { "%02x".format(it) }
            .chunked(4).joinToString(" ")
    }

    override fun close() {
        if (!closed) {
            closed = true
            try {
                ffi.destroy()
            } catch (_: Exception) {
                // already destroyed / never valid — silently no-op
            }
        }
    }

    companion object {
        /**
         * Derive une identite d'archive depuis une phrase BIP-39.
         *
         * Cette fonction ne wipe pas ses arguments : elle les transmet a la
         * FFI et rend la main. L'appelant DOIT wiper [mnemonic] et
         * [passphrase] juste apres l'appel, via `SecureWipe.wipe(...)` —
         * cette phrase est la cle de toutes les archives.
         *
         * Les deux sont des `ByteArray`, ni `CharArray` (le type d'avant) ni
         * `String` : l'UDL UniFFI accepte `bytes` directement, donc aucune
         * `String` transitoire n'est creee et le mnemonic ne touche jamais le
         * pool intern de la JVM (Phase 6.1.4-B).
         */
        fun fromMnemonic(
            mnemonic: ByteArray,
            passphrase: ByteArray = ByteArray(0)
        ): ArchiveIdentity {
            val ffi = FfiArchiveIdentity.fromMnemonic(mnemonic, passphrase)
            // Snapshot the pubkeys so `readableFingerprint()` doesn't need
            // a round-trip through FFI on every call.
            val id = ffi.identity()
            val edPk = id.ed25519Pk()
            val xPk = id.x25519Pk()
            id.destroy()
            return ArchiveIdentity(ffi, edPk, xPk)
        }
    }
}
