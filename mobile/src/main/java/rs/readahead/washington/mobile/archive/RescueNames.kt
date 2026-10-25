package rs.readahead.washington.mobile.archive

import java.security.SecureRandom

/**
 * Names used by the rescue: how a relay object name maps to a sequence number,
 * and how files are named on this phone and in an export.
 *
 * Two rules hold for every local name. No local name carries the `report_id`
 * or the recording's session id: a directory listing of the phone, or of an
 * export, must not hand out the address of a report on the relay. And no local
 * name is taken from the relay: the relay picks the object names, so they are
 * matched in memory and never joined onto a path.
 */
object RescueNames {

    /** A chained report's object: `NNNNNN.strm`, seq 0 = session metadata. */
    private val CHAIN_OBJECT = Regex("""(\d{6})\.strm""")

    /**
     * A legacy report's object: `<sessionId>_NNNNNN.strm`. The seq is read
     * from the end: an old session-id format had underscores of its own
     * (`<pk prefix>_<seconds>_<random>`), and the recorder's queue accepts
     * those names too (`EnvelopeNames.isLegacySessionId`).
     */
    private val LEGACY_OBJECT = Regex("""[A-Za-z0-9_-]+_(\d{6})\.strm""")

    /** The sequence number of a recording object, or null for any other name
     *  (a timestamp proof, a directory entry, relay junk). */
    fun parseSeq(name: String): Int? {
        val match = CHAIN_OBJECT.matchEntire(name) ?: LEGACY_OBJECT.matchEntire(name) ?: return null
        return match.groupValues[1].toInt()
    }

    /** The session metadata object (seq 0) among [verifiedNames], if any. */
    fun metadataName(verifiedNames: List<String>): String? =
        verifiedNames.firstOrNull { parseSeq(it) == 0 }

    /**
     * The video chunks among [verifiedNames], in reading order: seq >= 1,
     * increasing. Gaps are expected (a chunk lost at capture) and kept as is;
     * nothing here invents or reorders a chunk.
     */
    fun playbackOrder(verifiedNames: List<String>): List<String> =
        verifiedNames
            .mapNotNull { name -> parseSeq(name)?.takeIf { it >= 1 }?.let { it to name } }
            .sortedWith(compareBy<Pair<Int, String>> { it.first }.thenBy { it.second })
            .map { it.second }

    /** Local file name of the [ordinal]-th fetched object of a report. */
    fun localObjectFileName(ordinal: Int): String = "o%06d.bin".format(ordinal)

    /**
     * Local file name for one decryption of the [ordinal]-th chunk: the
     * position plus a fresh random token, so no two decryptions share a
     * name. Erases are aimed at a path and may run late; with a name shared
     * between decryptions, a late erase of one could destroy the file the
     * next one had just written.
     */
    fun newPlainFileName(ordinal: Int, random: SecureRandom = SecureRandom()): String =
        "p%06d-%s.mp4".format(ordinal, newToken(random))

    /** A fresh random directory name: 16 random bytes, lowercase hex. */
    fun newToken(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(TOKEN_BYTES)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    /** Whether [name] is a directory name [newToken] could have produced. */
    fun isToken(name: String): Boolean =
        name.length == TOKEN_BYTES * 2 && name.all { it in '0'..'9' || it in 'a'..'f' }

    /** Folder created in the export destination for the [ordinal]-th report
     *  shown on screen (1-based). */
    fun exportFolderName(ordinal: Int): String = "recording-%02d".format(ordinal)

    /** Name of the [part]-th exported video chunk (1-based, reading order). */
    fun exportVideoName(part: Int): String = "part-%04d.mp4".format(part)

    /**
     * Name of a joined video of the [ordinal]-th report: `prise-NN.mp4` when
     * the report joined into a single video ([part] null), otherwise
     * `prise-NN-partie-MM.mp4` for its [part]-th video (1-based).
     *
     * The part number is padded to two digits, or to the width of
     * [maxParts] when it is wider: the most videos the report can make, one
     * per chunk. Sorted by name, as file managers and shell globs sort them,
     * the parts then stay in recording order (`partie-02` before
     * `partie-10`).
     */
    fun exportJoinedVideoName(ordinal: Int, part: Int?, maxParts: Int): String {
        if (part == null) return "prise-%02d.mp4".format(ordinal)
        val width = maxOf(2, maxParts.toString().length)
        return "prise-%02d-partie-%0${width}d.mp4".format(ordinal, part)
    }

    /** Subfolder of a report's export holding its chunks as recorded, with
     *  the timestamp proof and its salt when they are exported. */
    const val EXPORT_RAW_FOLDER_NAME = "morceaux-bruts"

    const val EXPORT_METADATA_NAME = "metadata.json"
    const val EXPORT_OTS_NAME = "timestamp.ots"
    const val EXPORT_OTS_SALT_NAME = "timestamp.otssalt"

    /**
     * Label carried by the export of the objects kept apart as not
     * verifiable: by its folder AND by every file in it, so a file moved out
     * of the folder still says what it is.
     */
    const val UNVERIFIED_LABEL = "not-verified"

    /** Folder for the not-verifiable objects of the [ordinal]-th report;
     *  never the folder of its verified export. */
    fun exportUnverifiedFolderName(ordinal: Int): String = "${exportFolderName(ordinal)}-$UNVERIFIED_LABEL"

    /** Name of the [part]-th exported not-verifiable chunk (1-based). */
    fun exportUnverifiedVideoName(part: Int): String = "$UNVERIFIED_LABEL-${exportVideoName(part)}"

    const val EXPORT_UNVERIFIED_METADATA_NAME = "$UNVERIFIED_LABEL-$EXPORT_METADATA_NAME"

    /**
     * A relay `last_modified` (ISO-8601, e.g. `2026-05-15T12:34:56.123+00:00`)
     * shortened to `2026-05-15 12:34 UTC` for display. Anything else is shown
     * as received: it is the relay's clock, and the screen says so.
     */
    fun displayDate(raw: String): String {
        val match = ISO_PREFIX.find(raw) ?: return raw
        val zone = when {
            raw.endsWith("Z") || raw.endsWith("+00:00") -> " UTC"
            else -> ISO_OFFSET.find(raw)?.let { " ${it.value}" } ?: ""
        }
        return "${match.groupValues[1]} ${match.groupValues[2]}$zone"
    }

    private val ISO_PREFIX = Regex("""^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})""")
    private val ISO_OFFSET = Regex("""[+-]\d{2}:\d{2}$""")

    private const val TOKEN_BYTES = 16
}

/**
 * Reads the session id out of a decrypted session metadata object without
 * turning the plaintext into a `String`: the metadata is part of the
 * testimony, and a `String` cannot be wiped. The caller wipes [json].
 */
object SessionIdReader {

    private val KEY = "\"sessionId\"".toByteArray(Charsets.US_ASCII)

    /**
     * The bytes of the `sessionId` string value, or null if absent or not a
     * plain string of `[A-Za-z0-9_-]` (what the recorder writes today: 32
     * lowercase hex; an old format also had underscores). Whitespace around
     * the colon is accepted.
     */
    fun sessionIdBytes(json: ByteArray): ByteArray? {
        var at = indexOf(json, KEY, 0)
        while (at >= 0) {
            var i = at + KEY.size
            i = skipSpaces(json, i)
            if (i < json.size && json[i] == ':'.code.toByte()) {
                i = skipSpaces(json, i + 1)
                if (i < json.size && json[i] == '"'.code.toByte()) {
                    val start = i + 1
                    var end = start
                    while (end < json.size && isIdByte(json[end])) end++
                    return if (end < json.size && json[end] == '"'.code.toByte() && end > start) {
                        json.copyOfRange(start, end)
                    } else {
                        null
                    }
                }
            }
            at = indexOf(json, KEY, at + 1)
        }
        return null
    }

    private fun isIdByte(b: Byte): Boolean {
        val c = b.toInt().toChar()
        return c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_'
    }

    private fun skipSpaces(buf: ByteArray, from: Int): Int {
        var i = from
        while (i < buf.size && (buf[i] == ' '.code.toByte() || buf[i] == '\t'.code.toByte() ||
                buf[i] == '\n'.code.toByte() || buf[i] == '\r'.code.toByte())
        ) i++
        return i
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int): Int {
        var i = from
        while (i + needle.size <= haystack.size) {
            var match = true
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) {
                    match = false
                    break
                }
            }
            if (match) return i
            i++
        }
        return -1
    }
}
