package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import android.os.Build
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.service.StreamRecordingService

/**
 * How the background paths get an upload bearer when none is held: the
 * upload worker for an envelope the relay answered 425 for, the orphan sweep
 * for a queue that may need one, the timestamp worker for its submission.
 *
 * Each attempt spends one ephemeral ratchet slot, so all of them go through
 * [StreamUploadManager.authenticateIfAbsent]: single-flight with every other
 * authentication of the process, the recording service's included. Two of
 * these paths meeting on the same need wait for each other and spend one slot.
 *
 * Defers to the recording service while it runs or tears down: it owns the
 * authentication then. Needs the device unlocked and a validated network.
 * Answers from [UploadAuthHolder.isPresent] only: the bearer never enters the
 * JVM here. Returns whether a bearer is held.
 */
internal fun ensureBearer(context: Context, serverUrl: String): Boolean {
    val manager = StreamUploadManager.getInstance(context.applicationContext)
    return manager.authenticateIfAbsent({ UploadAuthHolder.isPresent() }) {
        when {
            StreamRecordingService.isRunning || StreamRecordingService.isShuttingDown -> false
            !manager.isUnlocked() || !networkAvailable(context) -> false
            else -> {
                // A fresh process (a worker woken before any screen) has no
                // server client yet; the authentication needs one.
                manager.setServerUrl(serverUrl)
                true
            }
        }
    }
}

/**
 * Whether a validated network with internet access is up. Below API 23 there
 * is neither an active-network handle nor a validation flag: a connected
 * active network is the most that can be asked there.
 */
internal fun networkAvailable(context: Context): Boolean =
    try {
        val cm = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE)
            as android.net.ConnectivityManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            caps != null &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        } else {
            @Suppress("DEPRECATION")
            cm.activeNetworkInfo?.isConnected == true
        }
    } catch (e: Exception) {
        false
    }
