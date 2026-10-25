package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.OtsStatus
import java.io.File

/**
 * The timestamp check never fails a verified report: an object that verified
 * but does not decrypt makes it MISMATCH, as in the CLI. A failure that may
 * pass is rethrown, so the report is verified again later.
 */
class TimestampCheckTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** Decrypts by copying, except the files in [undecryptable], which throw
     *  what [failure] gives. */
    private class Fakes(
        val undecryptable: Set<String> = emptySet(),
        val failure: () -> Exception = { FfiException.InvalidBlob("not a STRM for this identity") },
    ) {
        val secureDeleted = ArrayList<File>()

        val decrypt: (File, File) -> Unit = { input, output ->
            if (input.name in undecryptable) throw failure()
            input.copyTo(output, overwrite = true)
        }
        val hash: (File, File) -> ByteArray = { input, scratch ->
            try {
                if (input.name in undecryptable) throw failure()
                input.readBytes().copyOf(32)
            } finally {
                scratch.delete()
            }
        }

        fun check() = TimestampCheck(
            decrypt = decrypt,
            hashPlaintext = hash,
            commitment = { _, recordingId -> recordingId.copyOf(32) },
            proofStatus = { _, _ -> OtsStatus.MATCH },
            secureDelete = { secureDeleted.add(it); it.delete() },
            wipe = { it.fill(0) },
        )
    }

    private lateinit var incoming: File
    private lateinit var plain: File
    private lateinit var enc: File

    private fun layout() {
        incoming = tmp.newFolder("incoming")
        plain = tmp.newFolder("plain")
        enc = tmp.newFolder("enc")
    }

    private fun sealedProof(): File = File(incoming, "ots.bin").apply { writeText("proof") }
    private fun metadata(): File = File(enc, "000000.strm").apply { writeText("""{"sessionId":"0123456789abcdef"}""") }
    private fun chunk(n: Int): File = File(enc, "%06d.strm".format(n)).apply { writeText("chunk $n") }

    @Test
    fun `a verified proof that does not decrypt is MISMATCH and the report stays verified`() {
        layout()
        val fakes = Fakes(undecryptable = setOf("ots.bin"))
        val sealed = sealedProof()
        val proof = File(plain, "ots.proof")
        val outcome = fakes.check().checkSealed(sealed, proof, metadata(), listOf(chunk(1)), plain)
        assertSame(OtsStatus.MISMATCH, outcome.status)
        assertNull(outcome.proof)
        assertNull(outcome.recordingId)
        assertFalse(sealed.exists())
        assertFalse(proof.exists())
    }

    @Test
    fun `a metadata object that does not decrypt is MISMATCH`() {
        layout()
        val fakes = Fakes(undecryptable = setOf("000000.strm"))
        val proof = File(plain, "ots.proof")
        val outcome = fakes.check().checkSealed(sealedProof(), proof, metadata(), listOf(chunk(1)), plain)
        assertSame(OtsStatus.MISMATCH, outcome.status)
        assertFalse(proof.exists())
        assertFalse(File(plain, "metadata.tmp").exists())
    }

    @Test
    fun `a chunk that does not decrypt is MISMATCH, and a stored proof is left in place`() {
        layout()
        val fakes = Fakes(undecryptable = setOf("000002.strm"))
        val stored = File(enc, "session.ots").apply { writeText("proof") }
        val outcome = fakes.check().checkStored(stored, metadata(), listOf(chunk(1), chunk(2)), plain)
        assertSame(OtsStatus.MISMATCH, outcome.status)
        assertTrue(stored.isFile)
    }

    @Test
    fun `a failure that may pass is rethrown, and leaves no plaintext behind`() {
        layout()
        val fakes = Fakes(undecryptable = setOf("ots.bin"), failure = { FfiException.Io("disk full") })
        val sealed = sealedProof()
        val proof = File(plain, "ots.proof")
        try {
            fakes.check().checkSealed(sealed, proof, metadata(), listOf(chunk(1)), plain)
            fail("an I/O failure must not become a verdict")
        } catch (e: FfiException.Io) {
            // expected
        }
        assertFalse(sealed.exists())
        assertFalse(proof.exists())
    }

    @Test
    fun `a matching proof is kept with its recording id`() {
        layout()
        val proof = File(plain, "ots.proof")
        val outcome = Fakes().check().checkSealed(sealedProof(), proof, metadata(), listOf(chunk(1)), plain)
        assertSame(OtsStatus.MATCH, outcome.status)
        assertEquals(proof, outcome.proof)
        assertTrue(proof.isFile)
        assertNotNull(outcome.recordingId)
        assertEquals(16, outcome.recordingId!!.size)
        assertFalse(File(plain, "metadata.tmp").exists())
    }
}
