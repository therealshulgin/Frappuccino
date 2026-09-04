package org.stream.crypto.upload

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Non-destructive on a real device, and it has to stay that way. An instrumented
 * test shares the real app's `filesDir`, which on a field phone may hold genuine
 * pending chunks. Every file this test creates carries the [TEST_PREFIX]; setup,
 * teardown and every assertion touch ONLY those files, so running it never
 * deletes or mis-counts a real in-flight upload. Any new setup step, teardown or
 * assertion has to keep that filter.
 *
 * Closes the "upload in flight + abnormal death" half of the data-loss gap
 * (Grok Q2): a crash / OOM / OEM kill while a chunk is queued must not lose the
 * chunk, and a torn write must not surface a partial blob as uploadable. The
 * ratchet half (consume / persist / reload across a crash) is locked
 * deterministically in Rust — see `crypto-rs/core/src/ratchet.rs` tests
 * `unpersisted_consume_is_a_noop_after_reload`, `persisted_consume_survives_reload`,
 * `torn_blob_write_is_rejected_not_silently_accepted`,
 * `interrupted_rotation_reuses_signer_slot_and_is_deterministic`.
 *
 * Nothing here actually kills a process: a "process restart" is simulated by
 * constructing a fresh [ChunkUploadQueue] over the same `filesDir`. That models
 * the real thing because the durable state is the directory itself; the only
 * in-RAM state is a 1 s pending-list cache that a new instance starts empty.
 *
 * Lives in `mobile/` (not `stream-crypto/`) because that source set already
 * carries the androidx.test runner and the crypto `.so` that [ChunkUploadQueue]
 * needs (`secureDeleteFile` on `remove`).
 *
 * Run:
 * ```
 * ./gradlew :mobile:connectedDebugAndroidTest \
 *     --tests 'org.stream.crypto.upload.ChunkUploadQueueDurabilityTest'
 * ```
 */
@RunWith(AndroidJUnit4::class)
class ChunkUploadQueueDurabilityTest {

    private lateinit var context: Context

    private val queueDir: File
        get() = File(context.filesDir, "stream_chunk_queue")

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        deleteTestArtifacts()
    }

    @After
    fun tearDown() {
        deleteTestArtifacts()
    }

    /** Delete ONLY this test's own files — never a real pending chunk. */
    private fun deleteTestArtifacts() {
        context.filesDir.listFiles()?.forEach { if (it.name.startsWith(TEST_PREFIX)) it.delete() }
        queueDir.listFiles()?.forEach { if (it.name.startsWith(TEST_PREFIX)) it.delete() }
    }

    /** This test's view of the queue: only the blobs it staged. */
    private fun testPending(queue: ChunkUploadQueue): List<File> =
        queue.getPending().filter { it.name.startsWith(TEST_PREFIX) }

    /** A finished STRM blob staged in filesDir, ready to be enqueued. */
    private fun stagedBlob(name: String, size: Int = 96): File =
        File(context.filesDir, TEST_PREFIX + name).apply {
            writeBytes(ByteArray(size) { it.toByte() })
        }

    @Test
    fun pending_chunk_survives_a_process_restart() {
        ChunkUploadQueue(context).enqueue(stagedBlob("000001.strm"))

        // Simulate process death: a brand-new instance with an empty in-RAM cache.
        val mine = testPending(ChunkUploadQueue(context))

        assertEquals("the queued chunk must still be pending", 1, mine.size)
        assertEquals(TEST_PREFIX + "000001.strm", mine[0].name)
    }

    @Test
    fun torn_zero_byte_write_is_not_surfaced_as_uploadable() {
        // A power loss mid-write can leave a 0-byte .strm in the queue dir.
        // getPending() must skip it (length > 0 filter) so the worker never
        // tries to upload a partial / empty blob.
        queueDir.mkdirs()
        File(queueDir, TEST_PREFIX + "torn.strm").createNewFile() // 0 bytes

        val pending = ChunkUploadQueue(context).getPending()

        assertTrue(
            "a 0-byte torn write must not be pending",
            pending.none { it.name == TEST_PREFIX + "torn.strm" },
        )
    }

    @Test
    fun removed_chunk_stays_gone_after_restart() {
        val queue = ChunkUploadQueue(context)
        val dest = queue.enqueue(stagedBlob("000003.strm"))
        queue.remove(dest) // secure-delete after a successful upload

        assertTrue(
            "a removed chunk must not reappear in a fresh queue instance",
            testPending(ChunkUploadQueue(context)).isEmpty(),
        )
    }

    @Test
    fun multiple_chunks_return_in_chronological_filename_order() {
        val queue = ChunkUploadQueue(context)
        // Enqueue out of order; getPending must sort by filename (= capture order)
        // so a restart re-uploads chunks in the order they were filmed.
        queue.enqueue(stagedBlob("000003.strm"))
        queue.enqueue(stagedBlob("000001.strm"))
        queue.enqueue(stagedBlob("000002.strm"))

        val names = testPending(ChunkUploadQueue(context)).map { it.name }

        assertEquals(
            listOf(
                TEST_PREFIX + "000001.strm",
                TEST_PREFIX + "000002.strm",
                TEST_PREFIX + "000003.strm",
            ),
            names,
        )
    }

    companion object {
        /** Marks every file this test owns; sorts after real `sess_*` chunks. */
        private const val TEST_PREFIX = "zz_dura_test_"
    }
}
