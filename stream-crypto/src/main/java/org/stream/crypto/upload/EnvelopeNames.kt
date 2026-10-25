package org.stream.crypto.upload

/**
 * Local names of the queue envelopes (`filesDir/stream_envelopes/`).
 *
 * A local name is never sent. What the relay sees (the report id, the object
 * name, the signatures) travels inside the envelope's trailer, sealed under the
 * queue key, and only Rust reads it. A local name has two jobs: be unique on
 * the device, and be deterministic, so that a second attempt at sealing the same
 * object writes over the first attempt's file instead of producing a second
 * one, and so that the WorkManager unique work keyed on the name stays one job
 * per object.
 *
 * Chained reports, one per recording session (`sid` = the session id, lowercase
 * hex, see [isSessionId]):
 *
 *     <sid>_c<seq6>.fqe   report object `seq` (0 = metadata, >= 1 = media chunk)
 *     <sid>_d.fqe         the report's directory entry
 *     <sid>_z.fqe         the report's closure
 *     <sid>_o.fqe         the report's timestamp proof (opt-in)
 *
 * Legacy reports, converted once by the migration (`i` = the legacy index):
 *
 *     L<i>_<sid>_<seq6>.fqe   a pending legacy object
 *     L<i>_d.fqe, L<i>_z.fqe, L<i>_o.fqe
 *
 * A legacy `sid` may contain underscores (an old session-id format did), which
 * is why a legacy object name is parsed from both ends. A chained `sid` is plain
 * lowercase hex, so it can never start with the uppercase `L` of a legacy name
 * and the two families never overlap.
 *
 * Pure JVM on purpose: it is unit-tested without the native library.
 */
object EnvelopeNames {

    const val EXTENSION = "fqe"
    private const val DOT_EXT = ".$EXTENSION"

    /** Upper bound of a sequence number, the writer's own bound. */
    const val MAX_SEQ = 999_999

    /** What an envelope carries, as far as its local name tells. */
    enum class Role { OBJECT, DIRECTORY_ENTRY, CLOSURE, TIMESTAMP_PROOF }

    /**
     * A parsed local name. [legacyIndex] is null for a chained report;
     * [sessionId] is null for the legacy entry, closure and proof (they are
     * named by index only); [seq] is set for objects only.
     */
    data class Parsed(
        val role: Role,
        val legacyIndex: Int?,
        val sessionId: String?,
        val seq: Int?,
    ) {
        val isLegacy: Boolean get() = legacyIndex != null
    }

    private val SESSION_ID = Regex("[0-9a-f]{1,64}")
    private val LEGACY_PREFIX = Regex("L(0|[1-9][0-9]{0,6})_(.+)")
    private val SEQ6 = Regex("[0-9]{6}")

    /** Whether [sid] can name a chained report's envelopes. */
    fun isSessionId(sid: String): Boolean = SESSION_ID.matches(sid)

    fun chunk(sid: String, seq: Int): String {
        requireSession(sid)
        requireSeq(seq)
        return "${sid}_c${seq6(seq)}$DOT_EXT"
    }

    fun directoryEntry(sid: String): String {
        requireSession(sid)
        return "${sid}_d$DOT_EXT"
    }

    fun closure(sid: String): String {
        requireSession(sid)
        return "${sid}_z$DOT_EXT"
    }

    fun timestampProof(sid: String): String {
        requireSession(sid)
        return "${sid}_o$DOT_EXT"
    }

    fun legacyObject(index: Int, sid: String, seq: Int): String {
        requireIndex(index)
        require(isLegacySessionId(sid)) { "not a legacy session id" }
        requireSeq(seq)
        return "L${index}_${sid}_${seq6(seq)}$DOT_EXT"
    }

    fun legacyDirectoryEntry(index: Int): String {
        requireIndex(index)
        return "L${index}_d$DOT_EXT"
    }

    fun legacyClosure(index: Int): String {
        requireIndex(index)
        return "L${index}_z$DOT_EXT"
    }

    fun legacyTimestampProof(index: Int): String {
        requireIndex(index)
        return "L${index}_o$DOT_EXT"
    }

    /** Parses a local name; null for anything this queue never writes. */
    fun parse(name: String): Parsed? {
        if (!name.endsWith(DOT_EXT)) return null
        val stem = name.removeSuffix(DOT_EXT)
        LEGACY_PREFIX.matchEntire(stem)?.let { m ->
            val index = m.groupValues[1].toIntOrNull() ?: return null
            return parseLegacyRest(index, m.groupValues[2])
        }
        val cut = stem.lastIndexOf('_')
        if (cut <= 0) return null
        val sid = stem.substring(0, cut)
        if (!isSessionId(sid)) return null
        return when (val tag = stem.substring(cut + 1)) {
            "d" -> Parsed(Role.DIRECTORY_ENTRY, null, sid, null)
            "z" -> Parsed(Role.CLOSURE, null, sid, null)
            "o" -> Parsed(Role.TIMESTAMP_PROOF, null, sid, null)
            else -> {
                if (tag.length != 7 || tag[0] != 'c') return null
                val digits = tag.substring(1)
                if (!SEQ6.matches(digits)) return null
                Parsed(Role.OBJECT, null, sid, digits.toInt())
            }
        }
    }

    private fun parseLegacyRest(index: Int, rest: String): Parsed? {
        when (rest) {
            "d" -> return Parsed(Role.DIRECTORY_ENTRY, index, null, null)
            "z" -> return Parsed(Role.CLOSURE, index, null, null)
            "o" -> return Parsed(Role.TIMESTAMP_PROOF, index, null, null)
        }
        val cut = rest.lastIndexOf('_')
        if (cut <= 0) return null
        val sid = rest.substring(0, cut)
        val digits = rest.substring(cut + 1)
        if (!SEQ6.matches(digits) || !isLegacySessionId(sid)) return null
        return Parsed(Role.OBJECT, index, sid, digits.toInt())
    }

    /**
     * Whether sending this envelope may need the upload bearer: the object that
     * normally creates its report (seq 0, the metadata) and a directory entry
     * (any of them can create the directory). Any other envelope needs it only
     * after the relay answered 425 for it, which the queue records separately
     * ([EnvelopeQueue.isMarkedNotCreated]).
     */
    fun mayNeedJwt(name: String): Boolean {
        val parsed = parse(name) ?: return false
        return when (parsed.role) {
            Role.DIRECTORY_ENTRY -> true
            Role.OBJECT -> parsed.seq == 0
            else -> false
        }
    }

    /** Whether [name] is a media chunk or the metadata of chained session [sid]. */
    fun isObjectOfSession(name: String, sid: String): Boolean {
        val parsed = parse(name) ?: return false
        return parsed.role == Role.OBJECT && !parsed.isLegacy && parsed.sessionId == sid
    }

    /**
     * A legacy session id: what the old queue used before `_<seq>.strm`. Any
     * non-empty run of name-safe characters; underscores are allowed because an
     * old format had them.
     */
    fun isLegacySessionId(sid: String): Boolean =
        sid.isNotEmpty() && sid.length <= 128 && sid.all {
            it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-'
        }

    private fun seq6(seq: Int): String = seq.toString().padStart(6, '0')

    private fun requireSession(sid: String) =
        require(isSessionId(sid)) { "not a session id" }

    private fun requireSeq(seq: Int) =
        require(seq in 0..MAX_SEQ) { "seq out of range: $seq" }

    private fun requireIndex(index: Int) =
        require(index in 0..9_999_999) { "legacy index out of range: $index" }
}
