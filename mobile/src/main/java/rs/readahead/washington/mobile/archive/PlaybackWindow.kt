package rs.readahead.washington.mobile.archive

/**
 * Which chunks of a report are decrypted at a given moment of playback.
 *
 * The internal player never decrypts a whole report: a seized phone in the
 * middle of a viewing should hold the plaintext of a few chunks, not of the
 * recording. The window is the chunk being played plus [ahead] chunks after
 * it; everything else is erased as soon as playback leaves it, including the
 * chunks already watched.
 *
 * Indices are positions in the reading order (0 = first chunk with seq >= 1),
 * not sequence numbers.
 */
class PlaybackWindow(val size: Int, val ahead: Int = 2) {

    init {
        require(size >= 0) { "size must be >= 0" }
        require(ahead >= 0) { "ahead must be >= 0" }
    }

    /** The chunk being played. */
    var current: Int = 0
        private set

    /** Whether there is a chunk after [current]. */
    val hasNext: Boolean get() = current + 1 < size

    /** Whether there is a chunk before [current]. */
    val hasPrevious: Boolean get() = current > 0

    /** The chunks that should be decrypted now, in the order to decrypt them
     *  (the current one first). Empty for an empty report. */
    fun wanted(): List<Int> =
        if (size == 0) emptyList() else (current..minOf(current + ahead, size - 1)).toList()

    /** Of the chunks currently decrypted, those to erase now. */
    fun toErase(decrypted: Collection<Int>): List<Int> {
        val keep = wanted().toSet()
        return decrypted.filter { it !in keep }.sorted()
    }

    /** Move to the next chunk; false at the end. */
    fun advance(): Boolean {
        if (!hasNext) return false
        current++
        return true
    }

    /** Move to the previous chunk; false at the start. */
    fun back(): Boolean {
        if (!hasPrevious) return false
        current--
        return true
    }
}
