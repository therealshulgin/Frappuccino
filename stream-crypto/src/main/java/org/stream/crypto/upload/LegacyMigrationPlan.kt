package org.stream.crypto.upload

/**
 * The pure decisions of the legacy migration: how a legacy file name maps to
 * its report and its envelope, and where the chained index space starts.
 *
 * Pure JVM: unit-tested without the native library.
 */
object LegacyMigrationPlan {

    private val BLOB = Regex("(.+)_([0-9]{6})\\.strm")
    private val ENTRY = Regex("[0-9]{10}")
    private val PROOF = Regex("(.+)\\.ots")

    /** A legacy queued blob `<sid>_<seq6>.strm`: its session id and seq. */
    data class Blob(val sessionId: String, val seq: Int)

    fun parseBlob(name: String): Blob? {
        val m = BLOB.matchEntire(name) ?: return null
        val sid = m.groupValues[1]
        if (!EnvelopeNames.isLegacySessionId(sid)) return null
        return Blob(sid, m.groupValues[2].toInt())
    }

    /** A staged legacy directory entry, named by its index (`%010d`). */
    fun parseDirectoryEntry(name: String): Int? {
        if (!ENTRY.matches(name)) return null
        return name.toLongOrNull()?.takeIf { it <= Int.MAX_VALUE }?.toInt()
    }

    /** A received legacy timestamp proof `<sid>.ots`: its session id. */
    fun parseProof(name: String): String? {
        val m = PROOF.matchEntire(name) ?: return null
        val sid = m.groupValues[1]
        return sid.takeIf { EnvelopeNames.isLegacySessionId(it) }
    }

    /**
     * The sessions the migration may give a legacy index to: those with a
     * pending blob. A received proof never gets one on its own. Its session's
     * mapping can be gone while the proof waits (the old sweep dropped the
     * mapping once the session's chunks had left, the proof upload kept its
     * index in its own job data); a fresh index would then put the proof in a
     * report of its own, holding no recording, while the report with the
     * video stays without it. Such a proof is dropped instead.
     */
    fun sessionsNeedingIndex(blobNames: Collection<String>): Set<String> =
        blobNames.mapNotNull { parseBlob(it)?.sessionId }.toSet()

    /**
     * First index of the chained scheme: past every legacy index ever handed
     * out, whether the counter says so or a mapping does (a mapping can be
     * ahead of a counter that was reset). Legacy reports live below it, chained
     * ones from it on, and the rescue relies on that split.
     */
    fun firstChainIndex(nextLegacyIndex: Int, mappedIndices: Collection<Int>): Int {
        val pastMapped = mappedIndices.filter { it >= 0 }.maxOrNull()?.plus(1) ?: 0
        return maxOf(nextLegacyIndex.coerceAtLeast(0), pastMapped)
    }

    /** Legacy indices to close: every one below the chained scheme's first. */
    fun indicesToClose(firstChainIndex: Int): IntRange = 0 until firstChainIndex
}
