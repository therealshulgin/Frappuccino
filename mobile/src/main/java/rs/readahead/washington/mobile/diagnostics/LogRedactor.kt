package rs.readahead.washington.mobile.diagnostics

import org.stream.crypto.Bip39
import java.util.Locale

/**
 * What a log line loses before a pre-release test build stores it on the phone
 * or sends it to the test relay. Every line goes through [redact] first: the
 * app's own log, the logcat capture, the crash trace and the device profile.
 * A production version collects nothing and never calls it.
 *
 * Two kinds of value are at stake. Identifiers written in hex (report ids,
 * which name the reports on the relay, session ids, which name the envelopes
 * on the phone) would let whoever reads the logs link them to reports, and the
 * identity's fingerprint, hex written in groups, to the identity the relay has
 * on record; keys, signatures, bearer tokens, addresses and e-mails do not
 * belong off the phone at all. Each is replaced by a placeholder that keeps
 * the line readable: `<hex>`, `<uuid>`, `<jwt>`, `<b64>`, `<auth>`, `<ip>`,
 * `<email>`.
 *
 * A line holding three consecutive words of the French BIP-39 list is dropped
 * whole, accents ignored: the recovery phrase must never reach a log line, and
 * no code is meant to log it, so this is a guard against a mistake rather than
 * a filter for something expected. Some list words are ordinary in a camera
 * app's log ("caméra", "image", "surface", "service", "signal", "source"), so
 * three of them in a row drop a line that held no phrase; that is the price
 * of the guard. The list is the one the Rust core embeds
 * (crypto-rs/core/src/bip39_fr.txt), copied into the APK by the build. If it
 * cannot be read, every line is dropped: a redactor that cannot recognise the
 * phrase must not pass lines through.
 *
 * What stays: class names (Camera2CameraImpl), codec names
 * (c2.exynos.hevc.encoder), error codes, sizes, camera ids, short git hashes,
 * timestamps, and the routes and directories of URLs and file paths, whose
 * ids alone are replaced. The rules are patterns, not a parser, so they are
 * wrong in both directions at the edges: a 40-character run of letters
 * without separators is taken for base64, a four-part dotted version number
 * for an IPv4 address, four space-separated numbers of 16 digits in all for
 * grouped hex, and a secret shorter than the thresholds below passes. The
 * thresholds are the contract the tests hold.
 */
object LogRedactor {

    /** Where the build puts the French BIP-39 list (mobile/build.gradle). */
    internal const val WORDLIST_RESOURCE = "rs/readahead/washington/mobile/diagnostics/bip39_fr.txt"

    /** Consecutive list words that make a line a possible recovery phrase. */
    internal const val PHRASE_RUN = 3

    /**
     * The redacted [line], or null when it must be dropped. Works on a block
     * of several lines too; the phrase check then also catches words split
     * across lines.
     */
    fun redact(line: String): String? {
        if (mentionsPhrase(line)) return null
        var s = line
        s = AUTHORIZATION.replace(s) { it.groupValues[1] + "<auth>" }
        s = BEARER.replace(s) { it.groupValues[1] + "<auth>" }
        s = JWT.replace(s, "<jwt>")
        s = EMAIL.replace(s, "<email>")
        s = UUID.replace(s, "<uuid>")
        s = IPV4.replace(s, "<ip>")
        s = IPV6.replace(s, "<ip>")
        s = GROUPED_HEX.replace(s) { if (it.value.count(::isHexDigit) >= 16) "<hex>" else it.value }
        // A long run of hex digits also matches the base64 pattern; it keeps
        // its own placeholder. A path keeps its names: the HEX rule below
        // replaces the ids in it.
        s = BASE64.replace(s) {
            when {
                HEX_ONLY.matches(it.value.trimEnd('=')) -> "<hex>"
                isPath(it.value) -> it.value
                else -> "<b64>"
            }
        }
        s = HEX.replace(s, "<hex>")
        return s
    }

    /**
     * True when [run], a match of the base64 pattern, is a file path or a URL
     * route rather than a key: it holds a '/', has no '=' padding, and every
     * segment between the slashes reads as a name, that is lowercase letters,
     * digits, '_' and '-', after one capital at most (a class name), shorter
     * than 40 characters, a run of 16 or more hex digits counting as one
     * character. Standard base64 mixes capitals, lowercase and digits all
     * along, so the segments of a 40-character key fail this except with a
     * vanishing probability, and the whole run is replaced as before. A path
     * with a segment in mixed case (Camera2CameraImpl) is replaced whole too,
     * the safe way round.
     */
    private fun isPath(run: String): Boolean {
        if ('/' !in run || run.endsWith('=')) return false
        return run.split('/').all { PATH_SEGMENT.matches(HEX.replace(it, "h")) }
    }

    private fun isHexDigit(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    /**
     * True when [text] holds [PHRASE_RUN] or more consecutive words of the
     * French BIP-39 list, compared without accents and case. Digits and
     * punctuation between the words do not break the run ("1. abeille
     * 2. abolir ..."); any other word does. True as well when the list could
     * not be read.
     */
    fun mentionsPhrase(text: String): Boolean {
        val words = wordlist ?: return true
        var run = 0
        for (m in WORD.findAll(text)) {
            if (normalize(m.value) in words) {
                run++
                if (run >= PHRASE_RUN) return true
            } else {
                run = 0
            }
        }
        return false
    }

    /** Number of words loaded from the list; 0 when it could not be read. */
    internal val wordCount: Int get() = wordlist?.size ?: 0

    private val wordlist: Set<String>? by lazy {
        try {
            val stream = LogRedactor::class.java.classLoader?.getResourceAsStream(WORDLIST_RESOURCE)
                ?: return@lazy null
            val words = stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.map { it.trim() }.filter { it.isNotEmpty() }.map(::normalize).toHashSet()
            }
            if (words.size == WORDLIST_SIZE) words else null
        } catch (e: Exception) {
            null
        }
    }

    private const val WORDLIST_SIZE = 2048

    private fun normalize(word: String): String = Bip39.stripAccents(word.lowercase(Locale.ROOT))

    // Letters with their combining marks, so a decomposed accent does not
    // split a word in two.
    private val WORD = Regex("""[\p{L}\p{M}]+""")

    // The whole value after the header name, to the end of the line.
    private val AUTHORIZATION = Regex("""(?i)(\bauthorization\s*:\s*).*""")
    // Case-sensitive on purpose: the scheme as the app writes it. The
    // lowercase word is ordinary prose in this app's logs ("no bearer this
    // run").
    private val BEARER = Regex("""(\bBearer\s+).*""")
    private val JWT = Regex("""(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*""")
    private val EMAIL = Regex("""[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}""")
    private val UUID = Regex(
        """(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"""
    )
    // Not followed by a digit nor by ".digit", so an address that ends a
    // sentence is still caught and a five-part number is left alone.
    private val IPV4 = Regex("""(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)""")
    // Full form (eight groups) or any form with "::". The boundaries keep a
    // C++ scope ("android::MediaCodec") and a clock time (12:34:56) out.
    private val IPV6 = Regex(
        """(?<![0-9A-Za-z:.])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}""" +
            """|(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?)""" +
            """(?![0-9A-Za-z:])"""
    )
    // Hex written in groups, the way the app shows the identity's fingerprint
    // (StreamIdentity.readableFingerprint: "3fa9 07c1 be42 9d10 5e6a c0f8")
    // or a tool prints a digest ("AB:CD:EF:..."): four groups or more of two
    // to four hex digits, one separator throughout (space, colon or dash).
    // Replaced once it holds 16 hex digits in all, the HEX threshold.
    private val GROUPED_HEX = Regex(
        """(?<![0-9A-Za-z])[0-9A-Fa-f]{2,4}([ :-])[0-9A-Fa-f]{2,4}(?:\1[0-9A-Fa-f]{2,4}){2,}(?![0-9A-Za-z])"""
    )
    private val BASE64 = Regex("""[A-Za-z0-9+/_-]{40,}={0,2}""")
    private val PATH_SEGMENT = Regex("""[A-Z]?[a-z0-9_-]{0,38}""")
    private val HEX_ONLY = Regex("""[0-9A-Fa-f]+""")
    private val HEX = Regex("""[0-9A-Fa-f]{16,}""")
}
