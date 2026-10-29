package org.stream.crypto

import timber.log.Timber
import java.io.File

/**
 * Emergency-wipe helper for whole directories: take them out of the app's
 * reach at once, then overwrite and delete their contents in the background.
 *
 * Why two steps. Overwriting hundreds of files takes seconds, and the
 * emergency wipe runs on a device that may be taken from the witness's hands
 * any moment. A rename is atomic and instant: the moment it returns, no code
 * of this app finds the files under their usual path any more, and a write
 * that was still running against the old path, into a directory it does not
 * create itself, fails instead of recreating a file there. Code that calls
 * `mkdirs()` before writing does recreate the directory: such writes need a
 * guard of their own (the emergency-wipe generation). The slow overwrite then
 * works through the renamed copy.
 *
 * Honest limits: on flash storage with file-based encryption, an overwrite is
 * defence in depth, not a guaranteed erasure; FBE is the control that holds
 * at rest. The renamed directory exists until the background pass is done.
 */
object SecureDirWiper {

    private const val WIPE_SUFFIX = ".wipe-"

    /**
     * Rename [dir] to a sibling that nothing in the app looks for. Returns the
     * new location, the original one if the rename failed (the background pass
     * then works on it in place), or null if [dir] does not exist.
     */
    fun detach(dir: File): File? {
        if (!dir.exists()) return null
        val target = File(dir.parentFile, dir.name + WIPE_SUFFIX + System.nanoTime())
        return if (dir.renameTo(target)) target else {
            Timber.w("SecureDirWiper: rename failed, wiping in place")
            dir
        }
    }

    /**
     * Overwrite and delete everything under [dirs], in order, on a background
     * thread, then run [after] on that same thread. Put the directories
     * holding plaintext first: they are the ones whose remains could be read
     * without any key.
     */
    fun wipeInBackground(
        dirs: List<File>,
        threadName: String = "secure-dir-wipe",
        after: () -> Unit = {},
    ) {
        val todo = dirs.toList()
        Thread({
            for (dir in todo) {
                try {
                    wipeTree(dir)
                } catch (e: Exception) {
                    Timber.w(e, "SecureDirWiper: background wipe failed")
                }
            }
            try {
                after()
            } catch (e: Exception) {
                Timber.w(e, "SecureDirWiper: after-wipe step failed")
            }
        }, threadName).start()
    }

    /**
     * The order of the emergency wipe's single background pass: every
     * plaintext directory before any ciphertext one, whichever part of the app
     * detached it. Plaintext is readable without any key; the ciphertext only
     * reveals sizes and names once the keys are gone.
     */
    fun panicOrder(
        streamPlaintext: List<File>,
        otherPlaintext: List<File>,
        streamCiphertext: List<File>,
        otherCiphertext: List<File>,
    ): List<File> = streamPlaintext + otherPlaintext + streamCiphertext + otherCiphertext

    /** Overwrite and delete every file under [dir], then the directories. */
    fun wipeTree(dir: File) {
        if (!dir.exists()) return
        if (dir.isFile) {
            secureDelete(dir)
            return
        }
        dir.listFiles()?.forEach { child ->
            if (child.isDirectory) wipeTree(child) else secureDelete(child)
        }
        if (!dir.delete()) Timber.w("SecureDirWiper: directory not removed")
    }

    /**
     * Remove what an earlier wipe left half done (a process killed during the
     * background pass): every `<name>.wipe-*` sibling of [names] under [parent].
     */
    fun finishLeftovers(parent: File, names: Collection<String>) {
        val leftovers = leftovers(parent, names)
        if (leftovers.isNotEmpty()) wipeInBackground(leftovers, "secure-dir-wipe-resume")
    }

    /**
     * What [finishLeftovers] erases, without erasing it: every `<name>.wipe-*`
     * sibling of [names] under [parent], for a caller that hands them to its
     * own background pass.
     */
    fun leftovers(parent: File, names: Collection<String>): List<File> =
        parent.listFiles()?.filter { f -> names.any { f.name.startsWith(it + WIPE_SUFFIX) } }.orEmpty()

    private fun secureDelete(file: File) {
        try {
            uniffi.frappuccino.secureDeleteFile(file.absolutePath)
        } catch (e: Exception) {
            Timber.w(e, "SecureDirWiper: secure delete failed, plain delete")
            file.delete()
        }
    }
}
