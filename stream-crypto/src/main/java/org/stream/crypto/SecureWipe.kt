package org.stream.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Effacement de secrets en mémoire, résistant aux optimisations du JIT.
 *
 * Ne pas réduire `wipe()` à un `buf.fill(0)`. `ByteArray.fill(0)` (Kotlin)
 * comme `Arrays.fill(bytes, 0)` (Java) sont vulnérables au "dead store
 * elimination" du JIT : si le compilateur détecte que le buffer n'est jamais
 * relu après le `fill`, il peut purement et simplement supprimer l'appel. Le
 * secret — clé, PIN, mnemonic — reste alors en mémoire jusqu'à ce que le GC
 * réutilise le slot, donc lisible dans le dump d'un téléphone saisi.
 *
 * D'où le double passage : on overwrite d'abord avec
 * `SecureRandom.nextBytes(...)`, qui a des **side effects** (JNI vers
 * /dev/urandom ou équivalent Android) que le JIT ne peut pas observer comme
 * déterministes — il ne peut donc PAS supprimer l'appel. Le `fill(0)` qui
 * suit laisse le buffer en état "clearly cleared" (utile pour les dumps
 * mémoire / debug).
 *
 * Le surcoût est négligeable : ~ns pour un ByteArray de 32 bytes (taille
 * typique d'une clé), bien moindre que le coût d'une opération AEAD. C'est
 * la réponse à l'objection perf qui motiverait justement la simplification
 * dangereuse ci-dessus.
 *
 * Threat model adressé : RT M-04 ("zéroisation peut être élidée par JIT"),
 * compatible avec les recommandations OWASP MASVS-CRYPTO-2. (Phase 6.1.4.)
 *
 * Usage, pour un ByteArray comme pour un CharArray (PIN, mnemonic,
 * passphrase) :
 * ```
 * val key = ByteArray(32)
 * try {
 *     // ... use key ...
 * } finally {
 *     SecureWipe.wipe(key)
 * }
 * ```
 */
object SecureWipe {
    /**
     * Une seule instance, thread-safe (SecureRandom est documentée
     * thread-safe sur Android depuis API 21+).
     */
    private val rng = SecureRandom()

    /**
     * Overwrite `buf` avec random bytes, puis zéros.
     *
     * No-op si `buf` est null ou empty. Le double pass est intentionnel :
     * - `rng.nextBytes(buf)` : empêche JIT d'éliminer le fill
     * - `buf.fill(0)` : laisse le buffer dans un état "clearly cleared"
     */
    @JvmStatic
    fun wipe(buf: ByteArray?) {
        if (buf == null || buf.isEmpty()) return
        rng.nextBytes(buf)
        buf.fill(0)
    }

    /**
     * Overwrite `buf` avec random chars (interprétation 16-bit du random
     * stream), puis ' '.
     *
     * Pas de méthode `nextChars` sur SecureRandom, on dérive depuis bytes.
     */
    @JvmStatic
    fun wipe(buf: CharArray?) {
        if (buf == null || buf.isEmpty()) return
        // 2 bytes par char (UTF-16). On génère le double, puis reconstruit.
        val bytes = ByteArray(buf.size * 2)
        rng.nextBytes(bytes)
        for (i in buf.indices) {
            val low = bytes[i * 2].toInt() and 0xff
            val high = bytes[i * 2 + 1].toInt() and 0xff
            buf[i] = ((high shl 8) or low).toChar()
        }
        bytes.fill(0)
        buf.fill(' ')
    }

    /**
     * Overwrite the region `[position, limit)` of a [ByteBuffer] with random
     * bytes, then zeros. Returns `true` iff the bytes were actually
     * overwritten; `false` if the buffer was null, empty, **read-only**, or an
     * unexpected error aborted the wipe.
     *
     * The return value is the point of this overload, not a courtesy.
     * `MediaCodec.getOutputBuffer()` returns a read-only ByteBuffer by
     * contract, so on a compliant device the scrub of a codec output buffer
     * cannot happen in place: the plaintext frame is simply NOT wiped here.
     * That skip used to be silent, which meant believing in a scrub that never
     * ran (WP-F4, audit 2026-06-28, L-9). Do not turn this back into a `Unit`
     * function and do not let the read-only branch fall through quietly — the
     * Boolean is what lets the caller make the skip observable. The caller logs
     * it once per encoder session, so once per chunk rather than once per frame
     * (`plaintextScrubUnavailableLogged` in `HevcMediaCodecEncoder`'s drain
     * loop). Writing through a read-only view would take fragile reflection
     * on the codec's native memory, a band-aid we refuse. The residual is
     * bounded and recorded under WP-G: the codec overwrites that pool buffer
     * with the next frame, nothing is written at rest.
     *
     * What it is for: transient plaintext that lands in NIO buffers whose
     * lifecycle the app does not own, chiefly MediaCodec output `ByteBuffer`s
     * holding the compressed (but not-yet-encrypted) HEVC bitstream of a chunk
     * before it is muxed and STRM-encrypted. Same random-then-zero double pass
     * as the [ByteArray] overload, for the same reason: the random pass has
     * observable side effects (a native-memory or heap store the JIT cannot
     * prove dead), defeating dead-store elimination; the zero pass leaves the
     * buffer "clearly cleared".
     *
     * Works for both direct and heap (writable) buffers via relative bulk
     * `put`, chunked to bound the temp allocation. The caller's `position` and
     * `limit` are restored, and the call never throws on a wipe path — a
     * teardown or drain must never die here. (Phase 8.1.6-#3.)
     */
    @JvmStatic
    fun wipe(buf: ByteBuffer?): Boolean {
        if (buf == null || buf.isReadOnly) return false
        val savedPos = buf.position()
        val savedLimit = buf.limit()
        val len = savedLimit - savedPos
        if (len <= 0) return false
        var wiped = false
        try {
            val tmp = ByteArray(minOf(len, 8192))
            // Random pass — side-effecting, so the JIT cannot dead-store it.
            rng.nextBytes(tmp)
            buf.position(savedPos)
            var rem = len
            while (rem > 0) {
                val n = minOf(rem, tmp.size)
                buf.put(tmp, 0, n)
                rem -= n
            }
            // Zero pass — leave the region "clearly cleared".
            tmp.fill(0)
            buf.position(savedPos)
            rem = len
            while (rem > 0) {
                val n = minOf(rem, tmp.size)
                buf.put(tmp, 0, n)
                rem -= n
            }
            wiped = true
        } catch (_: Exception) {
            // Best-effort: an otherwise-unwritable buffer must never crash a
            // teardown or drain path. `wiped` stays false so the caller knows.
        } finally {
            try {
                buf.limit(savedLimit)
                buf.position(savedPos)
            } catch (_: Exception) {
                // Buffer state is the caller's concern past this point.
            }
        }
        return wiped
    }
}
