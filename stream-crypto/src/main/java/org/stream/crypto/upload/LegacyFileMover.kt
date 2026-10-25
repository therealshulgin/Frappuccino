package org.stream.crypto.upload

import java.io.File
import java.io.FileOutputStream

/**
 * Moves the legacy files staged in `cacheDir` into `filesDir` for the
 * migration, never leaving a moment where the only copy of a file is a
 * truncated one.
 *
 * A rename when it works. Otherwise (another filesystem, or a destination
 * left by an earlier interrupted move) a copy to a `.part`, its data synced,
 * renamed into place, the directory synced, and only then the source deleted.
 * The order is the point: the source's secure delete is itself synced to
 * storage, so a destination whose data is not would be the only copy left
 * after a power cut, and possibly empty.
 *
 * The source is deleted, never left in place: a second copy of a legacy blob
 * is a session-correlation handle on a seized phone.
 *
 * The file operations are injected so the order can be unit-tested on the
 * JVM; [Ops.DEFAULT] is what the app uses.
 */
internal class LegacyFileMover(private val ops: Ops = Ops.DEFAULT) {

    interface Ops {
        fun delete(file: File)
        fun syncFile(file: File)
        fun syncDir(dir: File)
        fun copy(from: File, to: File) {
            from.inputStream().use { input ->
                FileOutputStream(to).use { out -> input.copyTo(out) }
            }
        }

        /** Rename into place, replacing [to] (rename(2) semantics on Android). */
        fun replace(from: File, to: File): Boolean = from.renameTo(to)

        companion object {
            val DEFAULT: Ops = object : Ops {
                override fun delete(file: File) = EnvelopeQueue.secureDelete(file)
                override fun syncFile(file: File) {
                    FileOutputStream(file, true).use { it.fd.sync() }
                }
                override fun syncDir(dir: File) = EnvelopeQueue.fsyncDir(dir)
            }
        }
    }

    /** Move the files of [from] that [accept] into [to]. Throws on a failed move. */
    fun moveAll(from: File, to: File, accept: (String) -> Boolean) {
        val files = from.listFiles()?.filter { it.isFile && accept(it.name) } ?: return
        to.mkdirs()
        for (f in files) {
            val dest = File(to, f.name)
            if (f.length() == 0L) {
                // Nothing to move. Never let it replace a destination: an
                // empty source is what a delete interrupted between its
                // truncation and its unlink leaves, and the destination may be
                // the complete copy.
                ops.delete(f)
                continue
            }
            if (dest.exists() && dest.length() == f.length()) {
                // The same file already made it (an earlier move whose source
                // deletion was interrupted): the staged copy is redundant.
                ops.delete(f)
                continue
            }
            if (!dest.exists() && f.renameTo(dest)) continue
            val part = File(to, f.name + EnvelopeQueue.PART_SUFFIX)
            try {
                ops.copy(f, part)
                ops.syncFile(part)
                if (!ops.replace(part, dest)) throw java.io.IOException("could not move a legacy file into place")
                ops.syncDir(to)
            } catch (e: Exception) {
                // The source is intact; no half copy is left behind.
                if (part.exists()) ops.delete(part)
                throw e
            }
            ops.delete(f)
        }
        ops.syncDir(to)
    }
}
