package rs.readahead.washington.mobile.diagnostics

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.Locale

/**
 * The redacted log lines waiting on the phone to be sent, under
 * `filesDir/diag/`, in spill files `spill-000001.log`, `spill-000002.log`...
 * The highest number is the file being written; every other one is closed and
 * never written again, so a file the upload has read is still the same file
 * when it is deleted.
 *
 * Bounded: a file is closed once the next line would take it past
 * [maxFileBytes], and the files together hold at most [maxFiles] times that
 * (512 KiB and 4 by default, 2 MiB in all), the oldest dropped first. The
 * bound is on bytes, not on the number of files: every upload pass closes the
 * current file whatever the relay answers, so a relay that keeps failing
 * leaves one small file per pass, and counting files would drop the oldest
 * lines after a few passes while the store is nearly empty. [maxFileCount]
 * (256) is a backstop for a long outage that leaves many tiny files. A phone
 * that cannot reach the relay loses its oldest lines, never its storage.
 *
 * Every operation holds one lock. That lock is what lets the emergency wipe
 * ([detach]) rename the directory knowing no write is under way, and the
 * [generation] it advances is what makes a write prepared before the wipe
 * ([write] with the old value) land nowhere instead of in the fresh directory.
 *
 * Plain JVM: [detachDir] is the rename (SecureDirWiper.detach in the app), so
 * that the class can be tested without Android.
 */
internal class SpillStore(
    val dir: File,
    private val detachDir: (File) -> File?,
    private val maxFileBytes: Long = MAX_FILE_BYTES,
    private val maxFiles: Int = MAX_FILES,
    private val maxFileCount: Int = MAX_FILE_COUNT,
) {
    private val lock = Any()

    /** Advanced by every [detach]; a value read before it no longer writes. */
    @Volatile
    var generation: Long = 0L
        private set

    // The number of the file being written; 0 until the directory is read.
    private var currentSeq = 0

    /**
     * Append [lines] to the current file, rotating as needed. Does nothing,
     * and returns false, when [gen] is not the current [generation] or the
     * disk refuses the write.
     */
    fun write(lines: List<String>, gen: Long): Boolean = synchronized(lock) {
        if (gen != generation || lines.isEmpty()) return false
        try {
            ensureSeq()
            var file = fileFor(currentSeq)
            val out = StringBuilder()
            var pending = file.length()
            for (line in lines) {
                val size = utf8Size(line) + 1L
                if (pending > 0 && pending + size > maxFileBytes) {
                    appendTo(file, out)
                    out.setLength(0)
                    currentSeq++
                    file = fileFor(currentSeq)
                    pending = 0
                }
                out.append(line).append('\n')
                pending += size
            }
            appendTo(file, out)
            prune()
            true
        } catch (e: IOException) {
            false
        }
    }

    /**
     * Close the current file if it holds anything, and return every closed
     * file, oldest first: what an upload sends. Returns nothing when [gen]
     * is stale.
     */
    fun closeForUpload(gen: Long): List<File> = synchronized(lock) {
        if (gen != generation || !dir.isDirectory) return emptyList()
        readSeq()
        if (fileFor(currentSeq).length() > 0) currentSeq++
        spillFiles().filter { seqOf(it) < currentSeq }
    }

    /** Delete [files] once sent, unless a wipe happened since [gen] was read. */
    fun delete(files: List<File>, gen: Long): Boolean = synchronized(lock) {
        if (gen != generation) return false
        for (f in files) {
            if (f.parentFile == dir && seqOf(f) in 1 until currentSeq) f.delete()
        }
        true
    }

    /**
     * Emergency wipe: advance the [generation] and rename the directory out of
     * reach, under the lock, so that no write is in progress and none prepared
     * before this call lands anywhere. Returns where the directory went, or
     * null when there was none. The next write starts a fresh directory.
     */
    fun detach(): File? = synchronized(lock) {
        generation++
        currentSeq = 0
        if (!dir.exists()) null else detachDir(dir)
    }

    // The directory is created by the first write, never by an upload: a pass
    // that finds nothing must not leave an empty directory behind.
    private fun ensureSeq() {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("cannot create $dir")
        readSeq()
    }

    private fun readSeq() {
        if (currentSeq > 0) return
        currentSeq = spillFiles().maxOfOrNull(::seqOf)?.coerceAtLeast(1) ?: 1
    }

    // Oldest first, while the files, the current one included, hold more than
    // maxFiles x maxFileBytes or number more than maxFileCount. The current
    // file is never dropped.
    private fun prune() {
        val files = spillFiles()
        var bytes = files.sumOf { it.length() }
        var count = files.size
        for (f in files) {
            if (bytes <= maxFiles * maxFileBytes && count <= maxFileCount) break
            if (seqOf(f) >= currentSeq) break
            bytes -= f.length()
            count--
            f.delete()
        }
    }

    private fun spillFiles(): List<File> =
        (dir.listFiles() ?: emptyArray()).filter { seqOf(it) > 0 }.sortedBy(::seqOf)

    // Locale.ROOT: a locale with its own digits would write names that
    // seqOf no longer reads.
    private fun fileFor(seq: Int) = File(dir, String.format(Locale.ROOT, "spill-%06d.log", seq))

    private fun appendTo(file: File, text: CharSequence) {
        if (text.isEmpty()) return
        FileOutputStream(file, true).use { it.write(text.toString().toByteArray(Charsets.UTF_8)) }
    }

    companion object {
        const val MAX_FILE_BYTES = 512L * 1024
        const val MAX_FILES = 4
        const val MAX_FILE_COUNT = 256

        private val NAME = Regex("""spill-(\d{6,9})\.log""")

        /** The number in a spill file's name, or 0 for any other file. */
        fun seqOf(file: File): Int = NAME.matchEntire(file.name)?.groupValues?.get(1)?.toIntOrNull() ?: 0

        fun utf8Size(s: String): Int {
            var n = 0
            var i = 0
            while (i < s.length) {
                val c = s[i]
                n += when {
                    c.code < 0x80 -> 1
                    c.code < 0x800 -> 2
                    Character.isHighSurrogate(c) && i + 1 < s.length -> { i++; 4 }
                    else -> 3
                }
                i++
            }
            return n
        }
    }
}
