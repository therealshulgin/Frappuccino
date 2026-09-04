package rs.readahead.washington.mobile.util

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.annotation.RequiresApi
import timber.log.Timber

/**
 * Guidance for the OEM aggressive killers.
 *
 * A Doze exemption ([BatteryOptimizationHelper]) is NOT enough on OEMs that
 * ship a proprietary process killer on top of Doze — OnePlus / Oppo / Realme
 * (ColorOS/OxygenOS), Xiaomi (MIUI), Vivo, Huawei. Reading
 * `isIgnoringBatteryOptimizations == true` and concluding the recording is
 * safe sends you looking for the bug somewhere else while recordings keep
 * getting cut: field-proven 2026-06-23 on a OnePlus 13 (OxygenOS 16), where
 * the app was on the deviceidle whitelist and OxygenOS still killed the
 * recording foreground service. The signature to look for is `dumpsys
 * activity exit-info` showing `reason=OTHER` at
 * `importance=FOREGROUND_SERVICE` (an "o-kill"), with zero CRASH and zero
 * ANR. That kill also takes the ratchet auto-lock timer with it, so the app
 * appears never to lock — a security symptom one would otherwise blame on
 * the locking code.
 *
 * The setting the user must change lives in OEM-only menus that no public
 * API can toggle: by design, an app cannot self-exempt from these. The
 * hardcoded OEM components and the try/catch chain below are therefore not
 * carelessness, they are the only lever available:
 *   - [openOemBatterySettings] best-effort deep-links the OEM screen,
 *     falling back to the always-present app-details screen
 *     ([Settings.ACTION_APPLICATION_DETAILS_SETTINGS]);
 *   - the OEM state cannot be read, but [lastForegroundKillMs] detects a
 *     past foreground-service kill via the public ApplicationExitInfo API,
 *     so the guide can be re-surfaced reactively after a real kill.
 *
 * Every OEM component below is best-effort: they are not public API, vary by
 * version, and are frequently non-exported on recent builds (OxygenOS 16
 * etc.) — hence the try/catch chain and the robust fallback.
 */
object OemKillerHelper {

    /** OEMs known to ship an aggressive proprietary killer above Doze. */
    fun isAggressiveOem(): Boolean = Build.MANUFACTURER.lowercase() in AGGRESSIVE_OEMS

    private val AGGRESSIVE_OEMS = setOf(
        "oneplus", "oppo", "realme", "xiaomi", "redmi", "poco",
        "vivo", "iqoo", "huawei", "honor", "meizu",
    )

    /**
     * Try to open the OEM's battery / auto-start screen directly; fall back
     * to the standard app-details settings, which is always present. Safe on
     * every device — a missing or non-exported component just advances to the
     * next candidate, then to the fallback.
     */
    fun openOemBatterySettings(context: Context) {
        for (component in oemComponents()) {
            val intent = Intent()
                .setComponent(component)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                context.startActivity(intent)
                return
            } catch (_: Exception) {
                // not present / non-exported on this version → next candidate
            }
        }
        openAppDetails(context)
    }

    /** The robust fallback: the OS app-details screen (Battery row lives here). */
    fun openAppDetails(context: Context) {
        try {
            context.startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        } catch (e: Exception) {
            Timber.w(e, "OemKillerHelper: could not open app-details settings")
        }
    }

    private fun oemComponents(): List<ComponentName> = when (Build.MANUFACTURER.lowercase()) {
        "oneplus", "oppo", "realme" -> listOf(
            ComponentName("com.oplus.battery", "com.oplus.powermanager.fuelgaue.PowerConsumptionActivity"),
            ComponentName("com.coloros.oppoguardelf", "com.coloros.powermanager.fuelgaue.PowerConsumptionActivity"),
            ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity"),
        )
        "xiaomi", "redmi", "poco" -> listOf(
            ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
            ComponentName("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity"),
        )
        "vivo", "iqoo" -> listOf(
            ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"),
            ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager"),
        )
        "huawei", "honor" -> listOf(
            ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
            ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity"),
        )
        else -> emptyList()
    }

    /**
     * Timestamp of the most recent system kill that happened while a
     * foreground service was running — i.e. a recording cut by the OEM
     * killer. The unit is epoch milliseconds and has to stay that way: the
     * caller compares it to a persisted preference to surface the OEM guide
     * once per kill, so an uptime-relative clock would break that
     * de-duplication without any visible failure.
     *
     * Only `REASON_OTHER` at an importance of FOREGROUND_SERVICE (125) or
     * better (100) counts — the exact signature observed in the field. Do not
     * widen the `<=`, and do not drop the reason test, to "catch more cases":
     * a cached kill (importance 400) is ordinary background reclaim, and a
     * guide that reappears after every one of those teaches the user to
     * dismiss it, so it says nothing on the day the kill is real.
     *
     * Only the last ten process exits are examined, and `null` covers several
     * indistinguishable cases: no matching exit among them, Android older
     * than 11 (where the public ApplicationExitInfo API lands), or
     * ActivityManager unavailable.
     */
    fun lastForegroundKillMs(context: Context): Long? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        return lastForegroundKillMsApi30(context)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun lastForegroundKillMsApi30(context: Context): Long? {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return null
        val reasons = try {
            am.getHistoricalProcessExitReasons(context.packageName, 0, 10)
        } catch (e: Exception) {
            Timber.w(e, "OemKillerHelper: exit reasons unavailable")
            return null
        }
        return reasons.firstOrNull { info ->
            info.reason == ApplicationExitInfo.REASON_OTHER &&
                info.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
        }?.timestamp
    }
}
