package rs.readahead.washington.mobile.diagnostics

import android.util.Log
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Records an uncaught exception in the diagnostics log before the process
 * dies: the lines still queued, then the redacted stack trace, written on the
 * crashing thread before it returns. Then hands the exception to [previous],
 * the handler that was installed before (on Android, the one that shows the
 * crash dialog and kills the process), so the crash itself is unchanged.
 *
 * Writing synchronously is the point: an entry queued for the writer thread
 * would die with the process. It is the only write that happens on a thread
 * other than the writer's.
 */
internal class CrashRecorder(
    private val log: DiagnosticsLog,
    private val previous: Thread.UncaughtExceptionHandler?,
) : Thread.UncaughtExceptionHandler {

    override fun uncaughtException(thread: Thread, e: Throwable) {
        try {
            val trace = StringWriter().also { e.printStackTrace(PrintWriter(it)) }.toString()
            log.writeNow(
                Entry(System.currentTimeMillis(), Log.ASSERT, "CRASH", thread.name, "FATAL EXCEPTION\n$trace")
            )
        } catch (t: Throwable) {
            // Nothing may stop the crash from reaching the previous handler.
        }
        previous?.uncaughtException(thread, e)
    }
}
