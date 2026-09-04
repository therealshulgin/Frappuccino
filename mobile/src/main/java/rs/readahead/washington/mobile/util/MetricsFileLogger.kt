package rs.readahead.washington.mobile.util

import android.content.Context
import android.os.Build
import timber.log.Timber
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * File-backed mirror of the `StreamMetrics` logs. DEBUG BUILDS ONLY.
 *
 * Never plant this tree in a release build (audit 2026-06-26, R-CR-1 / B-1).
 * The file is a persistent recording timeline that survives `panicWipe` and
 * embeds the raw `sessionId`, which is the blob-name prefix on the relay
 * (`.../file/<report_id>/<sessionId>_<seq>.strm`). A seized device (AFU,
 * ratchet wiped) plus relay access would be enough to match `metrics.log` →
 * relay blobs → `report_id`, defeating device-side the unlinkability the
 * blind relay is there to provide. It is planted from
 * [rs.readahead.washington.mobile.MyApplication] `onCreate` on debuggable
 * builds only, and planted once: a second tree would duplicate every line of
 * the file.
 *
 * The file must stay under [Context.getFilesDir], the app-private internal
 * storage — `/data/data/<pkg>/files/metrics.log`. It used to live under
 * `getExternalFilesDir(null)`, which `adb pull` reads without
 * authentication: the session timeline (transitions qualité, networkType,
 * backlog) leaked to any USB or MTP inspection of a seized device, a
 * meaningful side channel for a journalist threat model (BUG audit R-2 round
 * 2, Phase 3.39).
 *
 * Why it exists (Phase 3.34): on a field test `adb logcat -s
 * StreamMetrics:I` loses the useful lines within minutes on a chatty system,
 * the logcat buffer being in RAM. This mirror keeps them until pulled by
 * hand:
 *   `adb exec-out run-as org.hzontal.tellaFOSS cat files/metrics.log > metrics.log`
 *
 * Rotation at [MAX_BYTES] into `metrics.log.1`, two files at most: the
 * deepest history is traded for a bounded disk footprint. Writes are
 * serialized on a private lock because Timber emits from the thread that
 * logged, and `StreamMetrics` lines come from several places at once during
 * a recording; without the lock two concurrent emits interleave bytes
 * mid-line and the pulled file stops being readable. The cost is under a
 * millisecond per line, so there is nothing to win by removing it.
 */
class MetricsFileLogger(context: Context) : Timber.Tree() {

    private val file: File = File(context.filesDir, FILE_NAME)
    private val rotated: File = File(context.filesDir, "$FILE_NAME.1")
    private val writeLock = Any()
    private val timestampFormat = SimpleDateFormat(
        "yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.US
    )

    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (tag != TARGET_TAG) return
        val line = buildString {
            append(timestampFormat.format(Date()))
            append("  ")
            append(message)
            if (t != null) {
                append("  exception=").append(t.javaClass.simpleName)
                t.message?.let { append(" msg=").append(it) }
            }
            append('\n')
        }
        synchronized(writeLock) {
            try {
                if (file.length() >= MAX_BYTES) {
                    rotate()
                }
                file.appendText(line)
            } catch (e: IOException) {
                // Best-effort : don't crash the app over a log line.
                // Fall back to regular logcat (which will retry on the
                // next call when the disk pressure eases).
            }
        }
    }

    private fun rotate() {
        try {
            // Never fold this Files.move back into `rotated.delete()` followed
            // by `file.renameTo(rotated)` because it is shorter and compiles
            // everywhere: that sequence is not atomic. A process crash or power
            // loss between the two steps left the rotated file gone AND the
            // active file un-renamed — i.e. ~8 MiB of history wiped while the
            // next appends keep writing to the pre-rotation file, now over
            // MAX_BYTES. Files.move with ATOMIC_MOVE + REPLACE_EXISTING is
            // atomic on ext4 (the Android internal storage filesystem), so
            // either the rotation happened or it didn't (Phase 3.43, BUG-R2-4).
            //
            // Nor delete the pre-26 branch on the grounds that no bench device
            // takes it: `java.nio.file` lands at API 26 (O) while minSdk is 21,
            // so on Android 5.0 to 7.1 it is the only reachable branch. It
            // keeps the original, non-atomic behaviour; the project's test
            // devices are Android 12+ in practice, which is the only sense in
            // which that path is dead.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Files.move(
                    file.toPath(),
                    rotated.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } else {
                if (rotated.exists()) rotated.delete()
                file.renameTo(rotated)
            }
        } catch (e: Exception) {
            // If rotation fails (rare : disk full, permission glitch),
            // just truncate the active file so we don't grow unbounded.
            try { file.delete() } catch (_: Exception) {}
        }
    }

    companion object {
        const val FILE_NAME = "metrics.log"
        const val TARGET_TAG = "StreamMetrics"
        private const val MAX_BYTES = 4L * 1024 * 1024 // 4 MiB
    }
}
