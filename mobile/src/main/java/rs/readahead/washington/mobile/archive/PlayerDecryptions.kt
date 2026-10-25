package rs.readahead.washington.mobile.archive

import java.io.File

/**
 * The internal player's record of its decryptions: which chunks of the
 * window are decrypted, which are being decrypted, and under which
 * generation. Kept apart from Android so the rules are testable; not
 * thread-safe, the player guards it with its own lock.
 *
 * The generation changes each time the window is wiped (the screen goes to
 * the background). Three rules follow, and each one keeps a chunk from
 * staying stuck on "decrypting" for the rest of the player's life:
 *
 * - a wipe drops every claim. A decryption still queued when the wipe stops
 *   the decrypt thread never runs, so it would never release its claim
 *   itself; and one still running belongs to the old generation, which may
 *   not keep the new one from decrypting the same chunk again;
 * - a claim is released only by the decryption that holds it: a decryption
 *   of the old generation that ends late leaves the new one's claim alone;
 * - a decryption's output is recorded only if its generation is still the
 *   current one; otherwise the decryption erases its own output.
 *
 * Two decryptions of the same chunk, one from each generation, may then run
 * at once, so each one writes to a file of its own
 * ([RescueNames.newPlainFileName]): an erase aimed at one can never reach
 * the other.
 */
internal class PlayerDecryptions {

    private val decrypted = HashMap<Int, File>()

    /** Chunk index → generation of the decryption in flight for it. */
    private val inFlight = HashMap<Int, Long>()

    var generation = 0L
        private set

    /**
     * Claim [index] for a decryption in the current generation. Returns that
     * generation, or null when the chunk is already decrypted or already
     * being decrypted in this generation.
     */
    fun claim(index: Int): Long? {
        if (decrypted.containsKey(index) || inFlight[index] == generation) return null
        inFlight[index] = generation
        return generation
    }

    /**
     * The decryption of [index] claimed under [gen] ended, having written
     * [out] (null when it failed or never ran). Returns true when [out] is
     * now the window's copy of the chunk; false when the caller must erase it.
     */
    fun finish(index: Int, gen: Long, out: File?): Boolean {
        if (inFlight[index] == gen) inFlight.remove(index)
        if (out == null || gen != generation || decrypted.containsKey(index)) return false
        decrypted[index] = out
        return true
    }

    /** The decrypted copy of [index], if any. */
    fun ready(index: Int): File? = decrypted[index]

    /** Forget the decrypted copy of [index] and return it for erasure. */
    fun remove(index: Int): File? = decrypted.remove(index)

    /** The decrypted chunks, by index. */
    fun decryptedIndices(): Set<Int> = decrypted.keys.toSet()

    /**
     * The window is wiped: a new generation, every claim dropped, and every
     * decrypted copy returned for erasure.
     */
    fun wipe(): List<File> {
        generation++
        inFlight.clear()
        val files = decrypted.values.toList()
        decrypted.clear()
        return files
    }
}
