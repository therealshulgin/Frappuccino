package rs.readahead.washington.mobile.archive

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import timber.log.Timber

/**
 * Keeps an archive screen listening for the emergency wipe
 * ([ArchiveLocalData.ACTION_ARCHIVE_WIPED]) for as long as the screen exists:
 * subscribed at ON_CREATE, unsubscribed at ON_DESTROY, and nowhere in between.
 *
 * Do not narrow this to ON_START / ON_STOP. The wipe is started from another
 * screen of the app, so an archive screen that still exists then is in the
 * background: narrowed, it would miss the broadcast and come back after the
 * wipe, still open on a rescue whose secrets and files are gone.
 *
 * The subscription itself is passed in, so the lifetime rule can be tested
 * without Android; [attach] builds the real one.
 */
class ArchiveWipeWatch internal constructor(
    private val subscribe: () -> Unit,
    private val unsubscribe: () -> Unit,
) : DefaultLifecycleObserver {

    /** Whether a wipe broadcast would reach the screen now. */
    var isSubscribed: Boolean = false
        private set

    override fun onCreate(owner: LifecycleOwner) {
        if (isSubscribed) return
        subscribe()
        isSubscribed = true
    }

    override fun onDestroy(owner: LifecycleOwner) {
        if (!isSubscribed) return
        isSubscribed = false
        try {
            unsubscribe()
        } catch (e: IllegalArgumentException) {
            // Not registered any more: nothing to undo.
            Timber.w(e, "ArchiveWipeWatch: receiver already gone")
        }
    }

    companion object {
        /**
         * Watch the wipe for [activity] from now until it is destroyed; [onWipe]
         * runs on the main thread when the broadcast arrives. Call from
         * `onCreate`, before any early `finish()`.
         */
        fun attach(activity: AppCompatActivity, onWipe: () -> Unit): ArchiveWipeWatch {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action == ArchiveLocalData.ACTION_ARCHIVE_WIPED) onWipe()
                }
            }
            val watch = ArchiveWipeWatch(
                subscribe = {
                    val filter = IntentFilter(ArchiveLocalData.ACTION_ARCHIVE_WIPED)
                    // The broadcast is confined to the app's package (setPackage);
                    // NOT_EXPORTED is a second lock where the platform has it.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        activity.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
                    } else {
                        @Suppress("UnspecifiedRegisterReceiverFlag")
                        activity.registerReceiver(receiver, filter)
                    }
                },
                unsubscribe = { activity.unregisterReceiver(receiver) },
            )
            activity.lifecycle.addObserver(watch)
            return watch
        }
    }
}
