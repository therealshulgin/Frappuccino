package rs.readahead.washington.mobile.diagnostics

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import java.io.File
import java.security.SecureRandom

/**
 * The id that groups one installation's uploads on the relay: 16 random bytes
 * in hex, sent as `X-Diag-Install`, which the relay uses as a directory name.
 *
 * Random and nothing else, on purpose: never derive it from the witness's
 * pseudonymous identity, from a device identifier, or from anything else that
 * outlives it, or the logs would become linkable to the identity or across
 * reinstalls. It is not a secret either, which is why it sits in a plain
 * SharedPreferences file of its own ([DiagnosticsNames.PREFS]). The emergency
 * wipe forgets it ([forget]) and the next upload draws a new one.
 */
internal object InstallId {

    private const val KEY = "install_id"
    private val FORMAT = Regex("[0-9a-f]{32}")

    @Synchronized
    fun get(context: Context): String {
        val prefs = context.getSharedPreferences(DiagnosticsNames.PREFS, Context.MODE_PRIVATE)
        prefs.getString(KEY, null)?.takeIf(FORMAT::matches)?.let { return it }
        val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val id = bytes.joinToString("") { "%02x".format(it) }
        prefs.edit().putString(KEY, id).apply()
        return id
    }

    /**
     * Clear the value, then remove the file: an empty preferences file left
     * behind would itself show that something was wiped. Synchronous
     * (commit, not apply): the wipe must not return with the id still on disk.
     */
    @SuppressLint("ApplySharedPref")
    @Synchronized
    fun forget(context: Context) {
        context.getSharedPreferences(DiagnosticsNames.PREFS, Context.MODE_PRIVATE).edit().clear().commit()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            context.deleteSharedPreferences(DiagnosticsNames.PREFS)
        } else {
            File(context.filesDir.parentFile, "shared_prefs/${DiagnosticsNames.PREFS}.xml").delete()
        }
    }
}
