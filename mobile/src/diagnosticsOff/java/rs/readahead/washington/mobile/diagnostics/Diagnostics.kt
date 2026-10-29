package rs.readahead.washington.mobile.diagnostics

import android.app.Application
import android.content.Context
import androidx.work.WorkManager
import org.stream.crypto.DetachedDirs
import org.stream.crypto.SecureDirWiper
import timber.log.Timber

/**
 * The diagnostics facade of a production version: it collects nothing and
 * sends nothing. mobile/build.gradle compiles this file instead of
 * src/diagnostics/java whenever the version name is not a pre-release test
 * name (-testN), so a production APK holds no uploader, no endpoint and no
 * log tree. CI checks the dex of such a build for the endpoint path.
 *
 * The one thing it does is remove what a pre-release test build of the same
 * app left on a phone that has since been updated to a production version:
 * its scheduled uploads, its log directory and its install id
 * ([DiagnosticsLeftovers], tested in every build). Without this the test
 * build's redacted log would stay on the phone for good, since no production
 * code would ever read or erase it. DiagnosticsChannelTest checks that
 * [install] keeps doing so.
 */
object Diagnostics {

    fun install(app: Application) {
        try {
            val wm = WorkManager.getInstance(app)
            wm.cancelUniqueWork(DiagnosticsNames.UPLOAD_WORK)
            wm.cancelUniqueWork(DiagnosticsNames.PERIODIC_WORK)
        } catch (e: Exception) {
            Timber.w(e, "could not cancel leftover diagnostics work")
        }
        try {
            val dirs = DiagnosticsLeftovers.detach(app.filesDir)
            if (dirs.isNotEmpty()) SecureDirWiper.wipeInBackground(dirs, "diag-leftover-wipe")
        } catch (e: Exception) {
            Timber.w(e, "could not remove leftover diagnostics files")
        }
    }

    fun onRecordingFinished(context: Context) {}

    fun detachForPanic(context: Context): DetachedDirs = DetachedDirs()
}
