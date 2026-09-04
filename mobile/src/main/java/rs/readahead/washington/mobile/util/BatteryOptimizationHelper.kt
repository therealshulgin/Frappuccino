package rs.readahead.washington.mobile.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

/**
 * Both entry points here need API 23 or later:
 * `PowerManager.isIgnoringBatteryOptimizations` and
 * `Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` both arrived with
 * Android 6.0, and neither this file nor its call site checks
 * `Build.VERSION.SDK_INT` while the project's minSdk is 21. On an API 21/22
 * device the call fails at runtime instead of returning a default, so guard
 * the version before calling from any new site.
 *
 * Android — especially Samsung One UI, Xiaomi MIUI, OnePlus OxygenOS —
 * aggressively kills foreground services that aren't on the user's
 * battery-optimization whitelist. When the screen turns off during a
 * recording, the system can suspend the StreamRecordingService and gate the
 * ChunkUploadWorker queue; the symptom, seen in vivo by therealshulgin on 2026-05-07,
 * was "écran éteint = peu d'uploads". An upload queue that stalls with the
 * screen off points at this whitelist first, not at the upload pipeline.
 *
 * The system dialog `Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`
 * lets the app ask once for the exemption. Once granted, the user keeps it
 * until they revoke it manually in Android Settings → Battery → App battery
 * usage. There is deliberately no way to revoke it from inside Frappuccino:
 * the OS-level toggle is canonical, and an in-app setting would create two
 * competing states of which only one is true (Phase 2.2.3).
 */
object BatteryOptimizationHelper {

    /**
     * Returns `true` if the app is on the OS's battery-optimization
     * whitelist (or if there is no PowerManager at all).
     */
    fun isExempt(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return true
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /**
     * Launch the system dialog asking the user to whitelist the app.
     *
     * The dialog is not guaranteed to appear. Some OEM skins, Xiaomi
     * notably, intercept `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` and
     * route to a hidden menu instead, so treating this intent as reliable
     * leaves those users un-exempted without anyone noticing, and their
     * uploads stall once the screen turns off. It does show up on stock
     * Android, Samsung One UI and OnePlus. The intent also needs the
     * matching permission in the manifest.
     */
    @SuppressLint("BatteryLife")
    fun requestExemption(context: Context) {
        if (isExempt(context)) return
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
            // Activity context required for ACTION_REQUEST_*; if a
            // non-activity context is passed, fall back to launching from
            // outside an activity stack.
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            context.startActivity(intent)
        } catch (_: Exception) {
            // OEM that doesn't surface the dialog → user has to flip the
            // toggle manually. Caller should display a guide string in
            // that case.
        }
    }
}
