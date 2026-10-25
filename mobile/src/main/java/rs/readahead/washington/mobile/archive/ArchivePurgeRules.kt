package rs.readahead.washington.mobile.archive

import java.io.File

/**
 * One report's local directory, `noBackupFilesDir/archive_view/<token>/`.
 * The token is random: a listing of the phone never shows a `report_id`.
 *
 * - [incoming]: where an object lands while Rust classifies it (whatever
 *   does not verify is deleted there by Rust);
 * - [enc]: the VERIFIED objects, still encrypted (STRM);
 * - [unverifiable]: the legacy objects stored without a signature, still
 *   encrypted, kept apart from [enc] and never moved into it (see
 *   [ObjectPlacement]);
 * - [plain]: decrypted plaintext, short-lived (the player's window, an export
 *   in progress), always secure-deleted after use.
 *
 * All four live under the token directory, so every purge of the rescue
 * erases the objects kept apart along with the verified ones.
 */
class ReportDir(val token: String, val root: File) {
    val incoming: File get() = File(root, "incoming")
    val enc: File get() = File(root, "enc")
    val unverifiable: File get() = File(root, "unverifiable")
    val plain: File get() = File(root, ArchivePurgeRules.PLAIN_DIR)
}

/**
 * Who erases the rescue's local copies, and when. Kept apart from Android so
 * the rule is testable.
 */
object ArchivePurgeRules {

    /**
     * "The last one alive purges": the local copies and the secrets go when
     * no archive screen is attached and no batch runs. With a screen attached
     * the copies are still being looked at; with a batch running the service
     * purges itself when the batch ends.
     */
    fun shouldPurge(attachedScreens: Int, batchRunning: Boolean): Boolean =
        attachedScreens <= 0 && !batchRunning

    /**
     * The background lock timer's rule: once the app has stayed in the
     * background for the timer's delay, the local copies and the secrets go
     * as soon as no batch runs, even under an archive screen still attached.
     * A screen left behind Home stays attached for as long as the process
     * lives; with [shouldPurge]'s rule the timer would almost never purge
     * anything, since every other way out already purges when no screen is
     * left.
     *
     * Only for a timer with a delay: the export's folder picker sends the app
     * to the background too, and a purge at that instant would erase the
     * report being exported.
     *
     * [attachedScreens] does not change the answer; it stays in the
     * signature so the difference with [shouldPurge] is explicit.
     */
    @Suppress("UNUSED_PARAMETER")
    fun shouldPurgeOnBackgroundTimer(attachedScreens: Int, batchRunning: Boolean): Boolean = !batchRunning

    /**
     * The order in which the files under [roots] are secure-deleted: every
     * plaintext file first, across ALL roots, then the rest. Plaintext is a
     * file in a directory named `plain`, or anything under a root for which
     * [isPlaintextRoot] holds (the decrypt buffer of earlier versions holds
     * nothing else). Splitting root by root instead would leave the
     * plaintext of a later root waiting behind the ciphertext of an earlier
     * one.
     */
    fun eraseOrder(roots: List<File>, isPlaintextRoot: (File) -> Boolean): List<File> {
        val plain = ArrayList<File>()
        val rest = ArrayList<File>()
        for (root in roots) {
            val wholeRootPlain = isPlaintextRoot(root)
            for (f in root.walkBottomUp()) {
                if (!f.isFile) continue
                if (wholeRootPlain || f.parentFile?.name == PLAIN_DIR) plain.add(f) else rest.add(f)
            }
        }
        return plain + rest
    }

    /**
     * The emergency wipe's split of the rescue's trash [roots], already
     * renamed, for a pass that erases other parts of the app between the two
     * lists it returns. First: the plaintext directories, that is every root
     * for which [isPlaintextRoot] holds, and the `plain` directory of every
     * report under the other roots. Second: those other roots, whole. The
     * first list goes with the plaintext of the whole app, before any
     * ciphertext, so a report's decrypted files are not left waiting behind
     * the encrypted copies around them.
     */
    fun panicSplit(roots: List<File>, isPlaintextRoot: (File) -> Boolean): Pair<List<File>, List<File>> {
        val plain = ArrayList<File>()
        val rest = ArrayList<File>()
        for (root in roots) {
            if (isPlaintextRoot(root)) {
                plain.add(root)
                continue
            }
            // A report directory is the root itself (one report purged on
            // its own) or one level under it (the whole view directory).
            root.walkTopDown().maxDepth(2)
                .filterTo(plain) { it != root && it.isDirectory && it.name == PLAIN_DIR }
            rest.add(root)
        }
        return plain to rest
    }

    /** Name of the plaintext directory under a report's token directory. */
    const val PLAIN_DIR = "plain"

    /** Name a directory takes while it waits to be erased. */
    fun trashName(base: String, token: String): String = "$base$TRASH_SEPARATOR$token"

    /** Whether [name] is a directory renamed by [trashName] from [base]. */
    fun isTrashOf(base: String, name: String): Boolean = name.startsWith("$base$TRASH_SEPARATOR")

    private const val TRASH_SEPARATOR = ".trash-"
}
