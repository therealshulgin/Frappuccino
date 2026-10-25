package org.stream.crypto.upload

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream

/**
 * The upload queue's durability on a real device filesystem: an envelope that
 * was queued survives the death of the process, and nothing a death leaves
 * half-written is ever handed to the sender.
 *
 * Non-destructive on a field phone, and it has to stay that way. The test
 * never touches the app's own queue: every [EnvelopeQueue] here is rooted in
 * a directory of its own under `filesDir` ([TEST_ROOT]), created and removed
 * by the test, so running it cannot delete, move or mis-count a real pending
 * envelope. Keep it that way for any new case: build the queue with [queue],
 * never with [EnvelopeQueue.get].
 *
 * A "process restart" is a fresh [EnvelopeQueue] over the same root. That
 * models the real thing because the durable state is the directories
 * themselves; what an instance holds in RAM (a 1 s listing cache, the report
 * id of each name) starts empty in a new process too.
 *
 * The envelope bytes are written here the way Rust writes them (a `.part`,
 * synced, renamed into place, the directory synced: `durable.rs` in the stream
 * crate). Their content is arbitrary: the queue never reads an envelope, only
 * its name and length; Rust reads and checks the trailer before any send, and
 * its parser and atomic write are tested in Rust.
 *
 * Lives in `mobile/` (not `stream-crypto/`) because that source set carries
 * the androidx.test runner and the crypto `.so` the queue's secure delete
 * calls.
 *
 * Run:
 * ```
 * ./gradlew :mobile:connectedDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=org.stream.crypto.upload.EnvelopeQueueDurabilityTest
 * ```
 */
@RunWith(AndroidJUnit4::class)
class EnvelopeQueueDurabilityTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        val context: Context = ApplicationProvider.getApplicationContext()
        root = File(context.filesDir, TEST_ROOT)
        root.deleteRecursively()
        assertTrue(root.mkdirs())
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    /** A queue as a new process would open it. */
    private fun queue(): EnvelopeQueue = EnvelopeQueue(root).also { it.ensureDirs() }

    /** Write [name] into the queue as Rust does, and return it. */
    private fun writeEnvelope(q: EnvelopeQueue, name: String, body: ByteArray = body(name)): File {
        val target = q.pathFor(name)
        val part = File(target.parentFile, name + EnvelopeQueue.PART_SUFFIX)
        FileOutputStream(part).use { out ->
            out.write(body)
            out.fd.sync()
        }
        assertTrue("rename into place", part.renameTo(target))
        EnvelopeQueue.fsyncDir(target.parentFile!!)
        q.invalidate()
        return target
    }

    private fun body(name: String): ByteArray = ("envelope:" + name).toByteArray(Charsets.US_ASCII)

    @Test
    fun queued_envelope_survives_a_process_restart() {
        val name = EnvelopeNames.chunk(SID, 1)
        writeEnvelope(queue(), name)

        val pending = queue().pending()

        assertEquals(listOf(name), pending.map { it.name })
        assertArrayEquals(body(name), pending[0].readBytes())
    }

    @Test
    fun write_interrupted_before_the_rename_is_never_pending_and_is_swept_at_start() {
        val q = queue()
        val complete = writeEnvelope(q, EnvelopeNames.chunk(SID, 1))
        // A death between the write and the rename leaves only the .part.
        val torn = File(q.queueDir, EnvelopeNames.chunk(SID, 2) + EnvelopeQueue.PART_SUFFIX)
        torn.writeBytes(byteArrayOf(1, 2, 3))
        val tornFailed = File(q.failedDir, EnvelopeNames.closure(SID) + EnvelopeQueue.PART_SUFFIX)
        tornFailed.writeBytes(byteArrayOf(4))

        val restarted = queue()
        assertEquals(listOf(complete.name), restarted.pending().map { it.name })

        assertEquals(2, restarted.sweepPartFiles())
        assertFalse(torn.exists())
        assertFalse(tornFailed.exists())
        assertTrue("the complete envelope is left alone", complete.exists())
        assertEquals(listOf(complete.name), queue().pending().map { it.name })
    }

    @Test
    fun zero_byte_envelope_is_not_pending() {
        val q = queue()
        assertTrue(q.pathFor(EnvelopeNames.chunk(SID, 3)).createNewFile())

        assertTrue(queue().pending().isEmpty())
    }

    @Test
    fun removed_envelope_stays_gone_after_restart() {
        val q = queue()
        val sent = writeEnvelope(q, EnvelopeNames.chunk(SID, 4))
        q.markNotCreated(sent.name)

        q.remove(sent)

        val restarted = queue()
        assertTrue(restarted.pending().isEmpty())
        assertFalse(sent.exists())
        assertFalse("the 425 marker goes with it", restarted.isMarkedNotCreated(sent.name))
    }

    @Test
    fun refused_envelope_is_kept_across_restart_but_never_pending() {
        val q = queue()
        val refused = writeEnvelope(q, EnvelopeNames.directoryEntry(SID))

        assertTrue(q.moveToFailed(refused))

        val restarted = queue()
        assertTrue(restarted.pending().isEmpty())
        assertEquals(1, restarted.failedCount())
        val kept = File(restarted.failedDir, refused.name)
        assertArrayEquals("moved, never rewritten", body(refused.name), kept.readBytes())
    }

    @Test
    fun not_created_marker_survives_restart_and_goes_with_its_envelope() {
        val q = queue()
        val waiting = writeEnvelope(q, EnvelopeNames.chunk(SID, 5))
        q.markNotCreated(waiting.name)

        val restarted = queue()
        assertTrue(restarted.isMarkedNotCreated(waiting.name))
        assertTrue("a 425 keeps the bearer needed", restarted.hasBearerDependent())

        // A process that sent the envelope then died before clearing the
        // marker: the start-up sweep drops the marker of a missing envelope.
        assertTrue(waiting.delete())
        queue().sweepPartFiles()
        assertFalse(queue().isMarkedNotCreated(waiting.name))
    }

    @Test
    fun pending_envelopes_come_back_in_name_order() {
        val q = queue()
        for (seq in listOf(10, 1, 2)) writeEnvelope(q, EnvelopeNames.chunk(SID, seq))
        writeEnvelope(q, EnvelopeNames.closure(SID))

        val names = queue().pending().map { it.name }

        assertEquals(
            listOf(
                EnvelopeNames.chunk(SID, 1),
                EnvelopeNames.chunk(SID, 2),
                EnvelopeNames.chunk(SID, 10),
                EnvelopeNames.closure(SID),
            ),
            names,
        )
    }

    companion object {
        /** The test's own root: never the app's queue. */
        private const val TEST_ROOT = "zz_envelope_durability_test"

        private const val SID = "0123456789abcdef0123456789abcdef"
    }
}
