package rs.readahead.washington.mobile.diagnostics

import android.annotation.SuppressLint
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * The app's own logcat at upload time: what the platform and its libraries
 * log on the app's behalf and that no Timber tree sees, which is most of what
 * a camera failure leaves (CameraX, the Camera2 client, MediaCodec / CCodec,
 * AndroidRuntime for a crash).
 *
 * Only the app's own lines: since Android 4.1 an app without READ_LOGS reads
 * only the entries of its own uid. That view includes the app's earlier
 * processes still in the ring buffer, which is why `--pid` is not passed: the
 * process that crashed is never the one uploading. The capture is the last
 * [MAX_LINES] lines and at most [MAX_BYTES], each line redacted.
 *
 * Its own failures go to android.util.Log, not Timber (see [DiagnosticsTree]).
 */
@SuppressLint("LogNotTimber")
internal object LogcatCapture {

    const val MAX_LINES = 4000
    const val MAX_BYTES = 1024 * 1024
    private const val TIMEOUT_S = 15L

    fun capture(): String {
        val process = try {
            ProcessBuilder(
                "logcat", "-d", "-v", "threadtime", "-b", "main", "-b", "system", "-b", "crash",
                "-t", MAX_LINES.toString(),
            ).redirectErrorStream(true).start()
        } catch (e: Exception) {
            Log.w(DiagnosticsTree.OWN_TAG, "logcat capture failed to start", e)
            return ""
        }
        // A logcat that does not exit on its own is destroyed, which ends the
        // read below.
        val watchdog = Thread({
            try {
                Thread.sleep(TimeUnit.SECONDS.toMillis(TIMEOUT_S))
                process.destroy()
            } catch (_: InterruptedException) {
            }
        }, "diag-logcat-watchdog").apply { isDaemon = true; start() }
        val lines = ArrayDeque<String>()
        var bytes = 0
        try {
            BufferedReader(InputStreamReader(process.inputStream, Charsets.UTF_8)).use { reader ->
                while (true) {
                    val raw = reader.readLine() ?: break
                    val line = LogRedactor.redact(raw) ?: continue
                    lines.addLast(line)
                    bytes += SpillStore.utf8Size(line) + 1
                    while (lines.size > MAX_LINES || bytes > MAX_BYTES) bytes -= SpillStore.utf8Size(lines.removeFirst()) + 1
                }
            }
        } catch (e: Exception) {
            Log.w(DiagnosticsTree.OWN_TAG, "logcat capture read failed", e)
        } finally {
            watchdog.interrupt()
            process.destroy()
        }
        return if (lines.isEmpty()) "" else lines.joinToString("\n", postfix = "\n")
    }

    /**
     * Clear the app's own entries from the logcat buffers (logd clears only
     * the caller's uid for an app). For the emergency wipe: the next capture
     * must not carry lines from before it. Best effort, without a way to
     * check it from the app: a phone on which logd refuses leaves those lines
     * in the buffer until they roll over.
     */
    fun clearOwn() {
        try {
            val p = ProcessBuilder("logcat", "-c", "-b", "main", "-b", "system", "-b", "crash")
                .redirectErrorStream(true).start()
            p.inputStream.use { it.readBytes() }
            p.waitFor()
        } catch (e: Exception) {
            Log.w(DiagnosticsTree.OWN_TAG, "logcat clear failed", e)
        }
    }
}
