package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import rs.readahead.washington.mobile.views.SourceText

/**
 * No log call of the app is handed the identity or the state of its ratchet.
 *
 * A pre-release test build sends its whole log to the relay, and the relay
 * keeps, for each identity, its public key, its batch number and the slots it
 * has used. A log line holding the fingerprint (SHA-256 of the public key,
 * which the relay can compute for every key it holds) or the batch and slot
 * counts would let the relay tie the test build's install id to the identity
 * from what it stores, and through the timings in the same log, to that
 * identity's reports. The redactor catches the fingerprint as written
 * (LogRedactorTest); this test keeps such values out of the calls in the
 * first place, in every module the APK is built from.
 *
 * It reads source text (comments and the contents of string literals
 * blanked, templates kept, see [SourceText]), so it sees the names passed to
 * a call, not what a variable holds: a value copied into a local first and
 * logged under another name is not seen.
 */
class IdentityFreeLogTest {

    @Test
    fun `no log call is handed the identity or the ratchet state`() {
        val sources = SourceText.sources()
        assertTrue("too few sources: ${sources.size}", sources.size > 100)
        val found = sources.flatMap { src ->
            val code = SourceText.strip(src.code, nested = src.file.extension == "kt", strings = true)
            offending(code).map { "${src.file.name}: $it" }
        }
        assertEquals("log calls handed identity or ratchet values:\n" + found.joinToString("\n"), emptyList<String>(), found)
    }

    // ---- negative controls ----

    @Test
    fun `a call spread over lines, tagged, or in a template is found`() {
        val code = SourceText.strip(
            """
            Timber.d("done %s",
                identity.readableFingerprint())
            Timber.tag(TAG).i("batch=%d", manager.currentBatchNumber())
            Log.w(TAG, "pk ${'$'}{id.ed25519PublicKeyHex()}")
            Timber.i("left %d", manager.remainingKeysInBatch())
            Timber.i("Auto-rotated to the next batch")
            fingerprintView.text = identity.readableFingerprint()
            """.trimIndent(),
            nested = true,
            strings = true,
        )
        assertEquals(4, offending(code).size)
    }

    private companion object {
        val CALL = Regex("""\b(?:Timber(?:\s*\.\s*tag\s*\([^)]*\))?|Log)\s*\.\s*(?:v|d|i|w|e|wtf)\s*\(""")

        // Names of the identity's public keys and fingerprint, and of the
        // ratchet's batch and slot counters.
        val FORBIDDEN = listOf(
            "readableFingerprint", "PublicKey", "BatchNumber", "batchNumber",
            "KeysInBatch", "KeyIndex", "keyIndex", "remainingInBatch",
        )

        fun offending(code: String): List<String> = CALL.findAll(code).mapNotNull { m ->
            val open = m.range.last
            val args = code.substring(open, SourceText.skipBalanced(code, open, '(', ')'))
            FORBIDDEN.firstOrNull { it in args }?.let { "${m.value}... passes $it" }
        }.toList()
    }
}
