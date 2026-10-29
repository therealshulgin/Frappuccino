package rs.readahead.washington.mobile.views.base_ui

import android.app.Activity
import android.os.Build
import android.view.WindowManager
import android.view.contentcapture.ContentCaptureManager

/**
 * Keeps what this activity shows out of screenshots, screen recordings and the
 * recents thumbnail (FLAG_SECURE), and on API 29+ turns Content Capture off for
 * the activity: the platform channel that can stream what a screen shows, text
 * included, to a system service.
 *
 * Call it at the start of `onCreate`, before `setContentView`. Two reasons:
 *
 * - On API 29+ the activity's Content Capture session is started in
 *   `onPostCreate`, which runs after `onCreate`, `onStart` and
 *   `onRestoreInstanceState`, and that start reads the window flags present
 *   at that moment. A FLAG_SECURE set later, in `onResume`, comes after the
 *   session has started.
 * - The window is secure before anything is drawn in it, rather than from the
 *   first `onResume` on.
 *
 * `setContentCaptureEnabled` is not persisted by the system, which is why it is
 * set again on every `onCreate`. The device's Content Capture service, when
 * there is one, is the one that honours it.
 */
fun Activity.refuseScreenCapture() {
    window.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE,
    )
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        getSystemService(ContentCaptureManager::class.java)?.setContentCaptureEnabled(false)
    }
}
