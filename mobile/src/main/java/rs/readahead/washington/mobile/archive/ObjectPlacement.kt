package rs.readahead.washington.mobile.archive

import uniffi.frappuccino.ObjectStatus
import java.io.File
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException

/**
 * Where a fetched object goes once Rust has classified it. Kept apart from
 * Android and from the FFI handles so the rule is testable.
 *
 * Three places, never merged:
 * - [TESTIMONY]: the verified testimony (`enc/`), the only objects the normal
 *   player and export use;
 * - [APART]: a legacy object the relay stored before it kept signatures
 *   (`unverifiable/`). Nothing proves it is the witness's, since an object
 *   sealed to the witness's identity can come from anyone who knows its public
 *   key, but it may be the only copy left of a recording made before this
 *   version. It stays readable and exportable from its own section, under its
 *   own label, and never counts as verified;
 * - [DROPPED]: excluded by the verification. Rust has already deleted the file.
 */
enum class Placement { TESTIMONY, APART, DROPPED }

object ObjectPlacement {

    /** Every status is listed: a new one must be placed on purpose. */
    fun of(status: ObjectStatus): Placement = when (status) {
        ObjectStatus.VERIFIED -> Placement.TESTIMONY
        ObjectStatus.UNVERIFIABLE -> Placement.APART
        ObjectStatus.FOREIGN,
        ObjectStatus.MISSING,
        ObjectStatus.UNEXPECTED,
        ObjectStatus.UNEXPECTED_SIGNED,
        ObjectStatus.INVALID,
        -> Placement.DROPPED
    }

    /** Relay object name → local encrypted file, for each kept place. */
    class Placed(val verified: Map<String, File>, val unverifiable: Map<String, File>)

    /**
     * Fetch each of [names] into `dir.incoming` with [fetch], which lands the
     * object, classifies it and deletes it when it is excluded (what
     * `ReportCheck.fetch_object` does), then move it to the directory [of]
     * names. A move that fails fails the whole report: an object kept nowhere
     * would be counted by the verdict and still be missing from the screens.
     *
     * @param onPlaced the number of objects handled so far, after each one.
     */
    suspend fun placeAll(
        names: List<String>,
        dir: ReportDir,
        fetch: suspend (name: String, landing: File) -> ObjectStatus,
        isActive: () -> Boolean,
        onPlaced: (done: Int) -> Unit,
    ): Placed {
        val verified = LinkedHashMap<String, File>()
        val unverifiable = LinkedHashMap<String, File>()
        for ((ordinal, name) in names.withIndex()) {
            if (!isActive()) throw CancellationException("rescue cancelled")
            val landing = File(dir.incoming, RescueNames.localObjectFileName(ordinal))
            when (of(fetch(name, landing))) {
                Placement.TESTIMONY -> verified[name] = moveInto(landing, dir.enc)
                Placement.APART -> unverifiable[name] = moveInto(landing, dir.unverifiable)
                Placement.DROPPED -> Unit
            }
            onPlaced(ordinal + 1)
        }
        return Placed(verified, unverifiable)
    }

    private fun moveInto(landing: File, into: File): File {
        val target = File(into, landing.name)
        if (!landing.renameTo(target)) throw IOException("cannot keep a fetched object")
        return target
    }
}
