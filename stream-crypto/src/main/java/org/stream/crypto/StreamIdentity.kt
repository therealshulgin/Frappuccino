package org.stream.crypto

/**
 * StreamIdentity — Identité **publique** du militant (V2).
 *
 * Cette classe ne contient que des clés publiques, et ne doit jamais en contenir
 * d'autres : y ajouter une clé privée ou une méthode de signature romprait
 * l'asymétrie qui fait la V2. Contrairement à V1, le device ne peut pas déchiffrer
 * son propre contenu passé et ne peut pas signer avec l'identité long-terme ; il ne
 * peut QUE signer avec des clés éphémères consommables.
 *
 * Elle sert donc uniquement à identifier l'auteur (via [ed25519PublicKey]), chiffrer
 * vers soi (via [x25519PublicKey], sealed_box) et afficher le fingerprint.
 *
 * Les chemins vers une clé privée sont ailleurs — au moins ceux-ci :
 *   - Enrôlement initial → [EnrollmentKit.fromMnemonic]
 *   - Déchiffrement des streams passés → [ArchiveIdentity.fromMnemonic]
 *   - Signature des uploads → [org.stream.crypto.ratchet.EphemeralRatchet]
 *   - Signature de provenance → `ProvenanceSigner.fromMnemonic`
 *   - Clés de capacité des reports → `ReportKeyring.fromMnemonic`
 *
 * Ces deux derniers sont dérivés de la même phrase à l'enrôlement, dans
 * `StreamUploadManager.enrollFromMnemonic` : qui audite la surface de clés
 * privées ne doit pas s'arrêter aux trois premiers.
 */
data class StreamIdentity(
    /** 32 bytes — identité pseudonyme stable (déterministe depuis phrase BIP-39). */
    val ed25519PublicKey: ByteArray,
    /** 32 bytes — cible des sealed_box pour chiffrer vers soi. */
    val x25519PublicKey: ByteArray
) {
    init {
        require(ed25519PublicKey.size == 32) {
            "ed25519PublicKey must be 32 bytes, got ${ed25519PublicKey.size}"
        }
        require(x25519PublicKey.size == 32) {
            "x25519PublicKey must be 32 bytes, got ${x25519PublicKey.size}"
        }
    }

    /** Fingerprint humain-lisible : 12 premiers bytes du SHA-256 de l'Ed25519_pk. */
    fun readableFingerprint(): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(ed25519PublicKey)
        return hash.take(12).joinToString("") { "%02x".format(it) }
            .chunked(4).joinToString(" ")
    }

    /** Ed25519 public key encodé en hex (64 caractères lowercase). */
    fun ed25519PublicKeyHex(): String =
        ed25519PublicKey.joinToString("") { "%02x".format(it) }

    // data class auto-generated equals/hashCode use reference equality for ByteArray.
    // Override for value equality.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StreamIdentity) return false
        return ed25519PublicKey.contentEquals(other.ed25519PublicKey) &&
                x25519PublicKey.contentEquals(other.x25519PublicKey)
    }

    override fun hashCode(): Int {
        var result = ed25519PublicKey.contentHashCode()
        result = 31 * result + x25519PublicKey.contentHashCode()
        return result
    }
}
