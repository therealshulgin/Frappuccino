package rs.readahead.washington.mobile.diagnostics

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.SensorPrivacyManager
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.media.MediaCodecList
import android.os.Build
import android.os.PowerManager
import androidx.core.content.ContextCompat
import rs.readahead.washington.mobile.BuildConfig
import rs.readahead.washington.mobile.util.BatteryOptimizationHelper
import rs.readahead.washington.mobile.util.OemKillerHelper

/**
 * What the phone is, collected at each upload as the first block of the body:
 * build, app version, every camera's capabilities, the HEVC and AVC encoders,
 * and the state that most often explains a recording that does not start
 * (permissions, battery exemption, OEM process killer, thermal status).
 *
 * Every call above the app's minSdk (21) sits behind its own SDK check. A
 * missing method throws NoSuchMethodError, an Error that a
 * `catch (e: Exception)` does not catch; each section also catches
 * LinkageError, for a vendor build whose framework does not match its SDK
 * level, so that one section failing leaves the others.
 *
 * Nothing in it identifies the person: no account, no serial, no IMEI, no
 * Android ID. It does identify the model and build closely
 * ([Build.FINGERPRINT]), which is what makes it useful.
 */
internal object DeviceProfile {

    fun collect(context: Context): String {
        val out = ArrayList<String>()
        section(out, "build") { build(it) }
        section(out, "app") { app(it) }
        section(out, "camera") { cameras(context, it) }
        section(out, "codec") { codecs(it) }
        section(out, "state") { state(context, it) }
        return out.mapNotNull(LogRedactor::redact).joinToString("\n")
    }

    private fun section(out: MutableList<String>, name: String, body: (MutableList<String>) -> Unit) {
        try {
            body(out)
        } catch (e: Exception) {
            out += "$name.error=${e.javaClass.simpleName}: ${e.message}"
        } catch (e: LinkageError) {
            out += "$name.error=${e.javaClass.simpleName}: ${e.message}"
        }
    }

    private fun build(out: MutableList<String>) {
        out += "build.manufacturer=${Build.MANUFACTURER}"
        out += "build.brand=${Build.BRAND}"
        out += "build.model=${Build.MODEL}"
        out += "build.device=${Build.DEVICE}"
        out += "build.product=${Build.PRODUCT}"
        out += "build.hardware=${Build.HARDWARE}"
        out += "build.board=${Build.BOARD}"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            out += "build.soc_manufacturer=${Build.SOC_MANUFACTURER}"
            out += "build.soc_model=${Build.SOC_MODEL}"
        }
        out += "build.fingerprint=${Build.FINGERPRINT}"
        out += "build.release=${Build.VERSION.RELEASE}"
        out += "build.sdk=${Build.VERSION.SDK_INT}"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            out += "build.security_patch=${Build.VERSION.SECURITY_PATCH}"
        }
        oneUi()?.let { out += "build.one_ui=$it" }
        out += "build.abis=${Build.SUPPORTED_ABIS.joinToString(",")}"
    }

    /**
     * Samsung's One UI version, from the field Samsung adds to Build.VERSION
     * (absent on other makers, hence the reflection). The decoding is the one
     * observed on Samsung phones: 90000 + major * 10000 + minor * 100, so that
     * 150100 reads One UI 6.1. The raw value is printed next to it, so a phone
     * that numbers differently can still be read.
     */
    private fun oneUi(): String? {
        val raw = try {
            Build.VERSION::class.java.getField("SEM_PLATFORM_INT").getInt(null)
        } catch (e: Exception) {
            return null
        }
        val v = raw - 90000
        return if (v > 0) "${v / 10000}.${(v % 10000) / 100} (SEM_PLATFORM_INT=$raw)" else "? (SEM_PLATFORM_INT=$raw)"
    }

    private fun app(out: MutableList<String>) {
        out += "app.version_name=${BuildConfig.VERSION_NAME}"
        out += "app.version_code=${BuildConfig.VERSION_CODE}"
        out += "app.git=${BuildConfig.GIT_HASH}"
        out += "app.build_type=${BuildConfig.BUILD_TYPE}"
    }

    private fun cameras(context: Context, out: MutableList<String>) {
        val cm = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val ids = cm.cameraIdList
        out += "camera.ids=${ids.joinToString(",")}"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val spm = context.getSystemService(SensorPrivacyManager::class.java)
            out += "camera.privacy_toggle_supported=" +
                (spm?.supportsSensorToggle(SensorPrivacyManager.Sensors.CAMERA) ?: "?")
        }
        for (id in ids) {
            section(out, "camera.$id") {
                val c = cm.getCameraCharacteristics(id)
                val p = "camera.$id"
                out += "$p.facing=${FACING[c.get(CameraCharacteristics.LENS_FACING)] ?: c.get(CameraCharacteristics.LENS_FACING)}"
                val level = c.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)
                out += "$p.hardware_level=${HARDWARE_LEVEL[level] ?: level}"
                val caps = c.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES) ?: IntArray(0)
                out += "$p.capabilities=${caps.joinToString(",") { CAPABILITY[it] ?: it.toString() }}"
                out += "$p.sensor_orientation=${c.get(CameraCharacteristics.SENSOR_ORIENTATION)}"
                val fps = c.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES)
                out += "$p.ae_fps_ranges=${fps?.joinToString(",") { "[${it.lower},${it.upper}]" }}"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val zoom = c.get(CameraCharacteristics.CONTROL_ZOOM_RATIO_RANGE)
                    out += "$p.zoom_ratio_range=${zoom?.let { "[${it.lower},${it.upper}]" }}"
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    out += "$p.physical_ids=${c.physicalCameraIds.joinToString(",")}"
                }
            }
        }
    }

    private fun codecs(out: MutableList<String>) {
        val infos = MediaCodecList(MediaCodecList.REGULAR_CODECS).codecInfos
        for (mime in listOf("video/hevc", "video/avc")) {
            for (info in infos) {
                if (!info.isEncoder || info.supportedTypes.none { it.equals(mime, ignoreCase = true) }) continue
                section(out, "codec.${info.name}") {
                    val video = info.getCapabilitiesForType(mime).videoCapabilities
                    val hw = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) info.isHardwareAccelerated.toString() else "?"
                    out += "codec.$mime name=${info.name} hw=$hw " +
                        "720x1280=${video?.isSizeSupported(720, 1280)} 1280x720=${video?.isSizeSupported(1280, 720)}"
                }
            }
        }
    }

    private fun state(context: Context, out: MutableList<String>) {
        out += "state.camera_permission=${granted(context, Manifest.permission.CAMERA)}"
        out += "state.record_audio_permission=${granted(context, Manifest.permission.RECORD_AUDIO)}"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            out += "state.battery_optimisation_exempt=${BatteryOptimizationHelper.isExempt(context)}"
        }
        out += "state.aggressive_oem=${OemKillerHelper.isAggressiveOem()}"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            val t = pm?.currentThermalStatus
            out += "state.thermal_status=${THERMAL[t] ?: t}"
        }
    }

    private fun granted(context: Context, permission: String): Boolean =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

    // Values of the PowerManager and CameraMetadata constants, written as
    // numbers so that the names of values added after minSdk do not need an
    // SDK check of their own just to be printed.
    private val THERMAL = mapOf(
        0 to "NONE", 1 to "LIGHT", 2 to "MODERATE", 3 to "SEVERE", 4 to "CRITICAL", 5 to "EMERGENCY", 6 to "SHUTDOWN",
    )
    private val FACING = mapOf(0 to "FRONT", 1 to "BACK", 2 to "EXTERNAL")
    private val HARDWARE_LEVEL = mapOf(0 to "LIMITED", 1 to "FULL", 2 to "LEGACY", 3 to "LEVEL_3", 4 to "EXTERNAL")
    private val CAPABILITY = mapOf(
        0 to "BACKWARD_COMPATIBLE", 1 to "MANUAL_SENSOR", 2 to "MANUAL_POST_PROCESSING", 3 to "RAW",
        4 to "PRIVATE_REPROCESSING", 5 to "READ_SENSOR_SETTINGS", 6 to "BURST_CAPTURE", 7 to "YUV_REPROCESSING",
        8 to "DEPTH_OUTPUT", 9 to "CONSTRAINED_HIGH_SPEED_VIDEO", 10 to "MOTION_TRACKING", 11 to "LOGICAL_MULTI_CAMERA",
        12 to "MONOCHROME", 13 to "SECURE_IMAGE_DATA", 14 to "SYSTEM_CAMERA", 15 to "OFFLINE_PROCESSING",
        16 to "ULTRA_HIGH_RESOLUTION_SENSOR", 17 to "REMOSAIC_REPROCESSING", 18 to "DYNAMIC_RANGE_TEN_BIT",
        19 to "STREAM_USE_CASE", 20 to "COLOR_SPACE_PROFILES",
    )
}
