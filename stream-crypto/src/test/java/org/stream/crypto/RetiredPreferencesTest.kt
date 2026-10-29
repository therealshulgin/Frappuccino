package org.stream.crypto

import android.content.SharedPreferences
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [StreamPreferences.forgetRetiredKeys] erases the invitation code that the V1
 * onboarding stored, and nothing else. It runs on a plain in-memory
 * SharedPreferences: the encrypted one needs the Android KeyStore.
 */
class RetiredPreferencesTest {

    @Test
    fun the_invitation_code_is_erased_and_written_at_once() {
        val prefs = MemoryPrefs(mapOf("invite_code" to "ORG-123", "server_url" to "https://relay", "ed25519_pk_hex" to "ab"))
        StreamPreferences.forgetRetiredKeys(prefs)
        assertFalse(prefs.contains("invite_code"))
        assertEquals(mapOf("server_url" to "https://relay", "ed25519_pk_hex" to "ab"), prefs.all)
        assertEquals("commit, not apply: the file must no longer hold it on return", 1, prefs.commits)
        assertEquals(0, prefs.applies)
    }

    @Test
    fun nothing_is_written_when_there_is_nothing_to_erase() {
        val prefs = MemoryPrefs(mapOf("server_url" to "https://relay"))
        StreamPreferences.forgetRetiredKeys(prefs)
        assertEquals(mapOf("server_url" to "https://relay"), prefs.all)
        assertEquals(0, prefs.commits + prefs.applies)
    }

    @Test
    fun a_failed_write_leaves_the_key_for_the_next_process() {
        val failing = MemoryPrefs(mapOf("invite_code" to "ORG-123"), commitSucceeds = false)
        StreamPreferences.forgetRetiredKeys(failing)
        assertTrue(failing.contains("invite_code"))
        val next = MemoryPrefs(failing.all)
        StreamPreferences.forgetRetiredKeys(next)
        assertFalse(next.contains("invite_code"))
    }

    /**
     * The erasure only helps if it runs: on every opening of the prefs, and in
     * the panic wipe. Neither call can be observed without the KeyStore, so
     * the source is read (the unit tests run from the module directory).
     */
    @Test
    fun the_prefs_are_never_handed_out_before_the_erasure() {
        val source = File("src/main/java/org/stream/crypto/StreamPreferences.kt").readText()
        assertTrue(Regex("""\bforgetRetiredKeys\(it\)""").containsMatchIn(bodyOf(source, "getPrefs")))
        assertTrue(Regex("""\.remove\(KEY_RETIRED_INVITE_CODE\)""").containsMatchIn(bodyOf(source, "wipeAll")))
    }

    /** The body of [function], line comments removed: a call commented out is no call. */
    private fun bodyOf(source: String, function: String): String {
        val start = source.indexOf("fun $function(")
        assertTrue("$function not found", start >= 0)
        val open = source.indexOf('{', start)
        var depth = 0
        for (i in open until source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) {
                    return source.substring(open, i + 1).lines().joinToString("\n") { it.substringBefore("//") }
                }
            }
        }
        throw AssertionError("$function has no closed body")
    }

    /** Only what [StreamPreferences.forgetRetiredKeys] can call is implemented. */
    private class MemoryPrefs(
        initial: Map<String, Any?>,
        private val commitSucceeds: Boolean = true,
    ) : SharedPreferences {
        private val values = initial.toMutableMap()
        var commits = 0
        var applies = 0

        override fun getAll(): Map<String, *> = values.toMap()
        override fun contains(key: String): Boolean = key in values
        override fun edit(): SharedPreferences.Editor = Edit()

        override fun getString(key: String, defValue: String?): String? = values[key] as String? ?: defValue
        override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String, defValue: Int): Int = defValue
        override fun getLong(key: String, defValue: Long): Long = defValue
        override fun getFloat(key: String, defValue: Float): Float = defValue
        override fun getBoolean(key: String, defValue: Boolean): Boolean = defValue
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) = Unit

        private inner class Edit : SharedPreferences.Editor {
            private val removed = mutableSetOf<String>()

            override fun remove(key: String): SharedPreferences.Editor = apply { removed += key }
            override fun commit(): Boolean {
                commits++
                if (commitSucceeds) values.keys.removeAll(removed)
                return commitSucceeds
            }
            override fun apply() {
                applies++
                values.keys.removeAll(removed)
            }

            override fun putString(key: String, value: String?) = unsupported()
            override fun putStringSet(key: String, values: MutableSet<String>?) = unsupported()
            override fun putInt(key: String, value: Int) = unsupported()
            override fun putLong(key: String, value: Long) = unsupported()
            override fun putFloat(key: String, value: Float) = unsupported()
            override fun putBoolean(key: String, value: Boolean) = unsupported()
            override fun clear() = unsupported()

            private fun unsupported(): SharedPreferences.Editor =
                throw UnsupportedOperationException("forgetRetiredKeys only removes")
        }
    }
}
