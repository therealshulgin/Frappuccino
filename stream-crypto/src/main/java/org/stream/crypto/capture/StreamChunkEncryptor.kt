package org.stream.crypto.capture

import org.stream.crypto.StreamIdentity
import timber.log.Timber
import uniffi.frappuccino.StreamIdentity as FfiStreamIdentity
import uniffi.frappuccino.strmEncrypt
import uniffi.frappuccino.strmEncryptFile
import java.io.File

/**
 * Encrypts individual video chunks as standalone STRM blobs.
 *
 * "Autonome" est la garantie anti-perte de vidéo : chaque chunk se déchiffre
 * seul, donc si le stream coupe après N chunks, les chunks 1..N restent tous
 * récupérables avec la phrase BIP-39. C'est ce qui interdit tout refactor vers
 * un chiffrement chaîné ou incrémental, qui rendrait illisible la fin d'un
 * enregistrement interrompu.
 *
 * La fenêtre RAM est d'environ un chunk entier (HD 720p @ 5 s ≈ 1-3 MB), et
 * elle est côté Rust, pas JVM : `strmEncryptFile` lit le MP4 entier dans un
 * `Zeroizing<Vec<u8>>`, et `strmEncrypt` (chemin métadonnées) prend un
 * `ByteArray`. C'est acceptable pour la taille de chunk visée.
 *
 * Chiffrement en Rust pur via UniFFI depuis S8c.2 (plus de dépendance à
 * `LazySodiumAndroid` ici), byte-exact avec l'ancienne implémentation
 * `SovereignEncryptor`.
 *
 * @property identity Identité de l'auteur (sert à sceller la session key).
 *                    Un `Arc<uniffi.frappuccino.StreamIdentity>` est construit
 *                    une fois via `fromPublicKeys` et réutilisé pour tous les
 *                    chunks d'une session — `close()` doit être appelé à la
 *                    fin, sinon on fuit le handle Rust.
 * @property outputDir Dossier où écrire les .strm ; créé s'il n'existe pas.
 */
class StreamChunkEncryptor(
    private val identity: StreamIdentity,
    private val outputDir: File
) : AutoCloseable {

    private val ffiIdentity: FfiStreamIdentity =
        FfiStreamIdentity.fromPublicKeys(identity.ed25519PublicKey, identity.x25519PublicKey)

    init {
        outputDir.mkdirs()
    }

    /**
     * Chiffre un fichier MP4 en clair en blob STRM. Le fichier en clair est
     * secure-deleted immédiatement après chiffrement, réussi ou pas.
     *
     * Ne pas revenir à `readBytes()` + `strmEncrypt`. C'est l'API voisine,
     * déjà importée en tête de ce fichier et utilisée par [encryptMetadata],
     * donc le retour en arrière est facile et passerait inaperçu — et il
     * rouvrirait la fenêtre que ce chemin a fermée. Ici c'est Rust qui ouvre
     * le MP4 lui-même (`File::open` + `Zeroizing<Vec<u8>>`), chiffre et écrit
     * le STRM : la vidéo en clair, le secret le plus sensible du produit, ne
     * transite jamais par la heap JVM. Avant ce refactor,
     * `chunkFile.readBytes()` l'y copiait pendant ~10 ms, fenêtre exposable à
     * un dump live. (Phase 6.1.4-C, pivot "100 % crypto Rust".)
     *
     * @return Le blob `.strm` produit, ou null en cas d'erreur.
     */
    fun encryptChunk(chunkFile: File, sessionId: String, seqNum: Int): File? {
        val blobName = "${sessionId}_${String.format("%06d", seqNum)}.strm"
        val blobFile = File(outputDir, blobName)

        try {
            // Rust lit le MP4, chiffre, écrit le STRM
            // directement. Aucun ByteArray plaintext en JVM heap.
            val blobSize = strmEncryptFile(
                chunkFile.absolutePath,
                blobFile.absolutePath,
                ffiIdentity,
            )
            Timber.d(
                "Encrypted chunk #%d: %s → %s (%d bytes)",
                seqNum, chunkFile.name, blobFile.name, blobSize.toLong()
            )
        } catch (e: Exception) {
            Timber.e(e, "Failed to encrypt chunk #%d", seqNum)
            // Blob STRM partiel à secure-delete (peut
            // contenir un ciphertext incomplet + nonce).
            try {
                uniffi.frappuccino.secureDeleteFile(blobFile.absolutePath)
            } catch (e2: Exception) {
                Timber.w(e2, "secureDelete failed on partial blob, fallback delete()")
                blobFile.delete()
            }
            return null
        } finally {
            // CRITICAL Phase 6.1.4-D : MP4 plaintext = secret le plus sensible
            // (vidéo en clair). Secure-delete via Rust (overwrite + fsync +
            // truncate + unlink). Si fail, fallback delete() pour ne pas
            // laisser le file traîner.
            try {
                uniffi.frappuccino.secureDeleteFile(chunkFile.absolutePath)
            } catch (e: Exception) {
                Timber.w(e, "secureDelete failed on plaintext chunk #%d, fallback delete()", seqNum)
                chunkFile.delete()
            }
        }
        return blobFile
    }

    /**
     * Chiffre le JSON de métadonnées de session en blob STRM (séquence 0).
     */
    fun encryptMetadata(metadataJson: String, sessionId: String): File? {
        val blobName = "${sessionId}_000000.strm"
        val blobFile = File(outputDir, blobName)
        try {
            val plaintext = metadataJson.toByteArray(Charsets.UTF_8)
            try {
                val blob = strmEncrypt(plaintext, ffiIdentity)
                // WP-D (audit H1) — fsync the metadata blob to stable storage,
                // same durability discipline as the chunk path (strmEncryptFile
                // now sync_all's). A plain writeBytes leaves the blob in the page
                // cache; a power-loss before flush loses the seq-0 session
                // metadata. (No secure-deleted plaintext counterpart here, so a
                // lesser gap than the chunk path, but closed for symmetry.)
                java.io.FileOutputStream(blobFile).use { fos ->
                    fos.write(blob)
                    fos.fd.sync()
                }
                Timber.d("Encrypted session metadata: %s (%d bytes)", blobFile.name, blobFile.length())
            } finally {
                // Wipe Kotlin ByteArray (defense-in-depth).
                org.stream.crypto.SecureWipe.wipe(plaintext)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to encrypt session metadata")
            // Secure-delete blob partiel.
            try {
                uniffi.frappuccino.secureDeleteFile(blobFile.absolutePath)
            } catch (e2: Exception) {
                Timber.w(e2, "secureDelete failed on partial metadata blob, fallback delete()")
                blobFile.delete()
            }
            return null
        }
        return blobFile
    }

    /** Libère l'Arc UniFFI. Sûr à appeler plusieurs fois. */
    override fun close() {
        try {
            ffiIdentity.destroy()
        } catch (_: Exception) {
            // already destroyed
        }
    }
}
