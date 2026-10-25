package org.stream.crypto.upload

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * The queue's bookkeeping on a temporary directory, with a plain delete in
 * place of the native secure delete. What it pins: `.part` files and failed
 * envelopes never count as pending, a move to the failed directory never
 * deletes, the 425 marker survives a new instance (a process restart), and the
 * peer test is conservative about envelopes it cannot read.
 */
class EnvelopeQueueTest {

    private lateinit var root: File
    private val deleted = ArrayList<String>()
    private val sid = "0123456789abcdef0123456789abcdef"

    private fun newQueue() = EnvelopeQueue(root) { f -> deleted.add(f.name); f.delete() }

    private fun write(queue: EnvelopeQueue, name: String, bytes: Int = 8): File =
        queue.pathFor(name).apply { writeBytes(ByteArray(bytes) { 1 }) }

    @Before
    fun setUp() {
        root = Files.createTempDirectory("envq").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun only_finished_envelopes_are_pending() {
        val q = newQueue().apply { ensureDirs() }
        write(q, EnvelopeNames.chunk(sid, 2))
        write(q, EnvelopeNames.chunk(sid, 1))
        write(q, EnvelopeNames.chunk(sid, 3) + EnvelopeQueue.PART_SUFFIX)
        write(q, EnvelopeNames.chunk(sid, 4), bytes = 0)
        write(q, "legacy_000001.strm")
        assertEquals(
            listOf(EnvelopeNames.chunk(sid, 1), EnvelopeNames.chunk(sid, 2)),
            q.pending().map { it.name },
        )
    }

    @Test
    fun part_files_are_swept_and_counted() {
        val q = newQueue().apply { ensureDirs() }
        write(q, EnvelopeNames.chunk(sid, 1))
        write(q, EnvelopeNames.chunk(sid, 2) + EnvelopeQueue.PART_SUFFIX)
        assertEquals(1, q.sweepPartFiles())
        assertEquals(listOf(EnvelopeNames.chunk(sid, 2) + EnvelopeQueue.PART_SUFFIX), deleted)
        assertTrue(q.pathFor(EnvelopeNames.chunk(sid, 1)).exists())
    }

    @Test
    fun a_failed_envelope_is_moved_never_deleted() {
        val q = newQueue().apply { ensureDirs() }
        val f = write(q, EnvelopeNames.closure(sid))
        assertTrue(q.moveToFailed(f))
        assertFalse(f.exists())
        assertEquals(1, q.failedCount())
        assertEquals(0, q.pendingCount())
        assertTrue(deleted.isEmpty())
        // A second failure under the same name does not overwrite the first.
        val again = write(q, EnvelopeNames.closure(sid))
        assertTrue(q.moveToFailed(again))
        assertEquals(2, q.failedCount())
    }

    @Test
    fun the_425_marker_survives_a_restart_and_goes_with_its_envelope() {
        val q = newQueue().apply { ensureDirs() }
        val name = EnvelopeNames.chunk(sid, 5)
        val f = write(q, name)
        assertFalse(q.hasBearerDependent())
        q.markNotCreated(name)
        val restarted = newQueue()
        assertTrue(restarted.isMarkedNotCreated(name))
        assertTrue(restarted.hasBearerDependent())
        restarted.remove(f)
        assertFalse(restarted.isMarkedNotCreated(name))
        assertFalse(restarted.hasBearerDependent())
    }

    @Test
    fun report_creators_make_the_queue_bearer_dependent() {
        val q = newQueue().apply { ensureDirs() }
        write(q, EnvelopeNames.chunk(sid, 1))
        assertFalse(q.hasBearerDependent())
        write(q, EnvelopeNames.directoryEntry(sid))
        q.invalidate()
        assertTrue(q.hasBearerDependent())
    }

    @Test
    fun peers_are_found_by_report_and_unreadable_ones_count() {
        val q = newQueue().apply { ensureDirs() }
        val closure = write(q, EnvelopeNames.legacyClosure(3))
        write(q, EnvelopeNames.legacyObject(3, "old", 1))
        write(q, EnvelopeNames.legacyDirectoryEntry(3))
        val reports = mapOf(
            EnvelopeNames.legacyObject(3, "old", 1) to "rid3",
            EnvelopeNames.legacyDirectoryEntry(3) to "directory",
        )
        assertTrue(q.hasPeer(closure.name, "rid3") { reports[it.name] })
        assertFalse(q.hasPeer(closure.name, "rid4") { reports[it.name] })
        // An envelope whose trailer cannot be read holds the closure back.
        val blind = newQueue()
        assertTrue(blind.hasPeer(closure.name, "rid4") { null })
    }

    @Test
    fun session_counts_ignore_other_reports_and_the_metadata() {
        val q = newQueue().apply { ensureDirs() }
        val other = "fedcba9876543210fedcba9876543210"
        write(q, EnvelopeNames.chunk(sid, 0))
        write(q, EnvelopeNames.chunk(sid, 1))
        write(q, EnvelopeNames.chunk(sid, 2))
        write(q, EnvelopeNames.chunk(other, 1))
        write(q, EnvelopeNames.directoryEntry(sid))
        assertEquals(3, q.pendingObjectsOfSession(sid))
        assertEquals(2, q.pendingChunksOfSession(sid))
    }

    /** What the emergency wipe does to the queue's directories: rename away. */
    private fun renameQueueAway() {
        for (name in EnvelopeQueue.ALL_DIRS) {
            val dir = File(root, name)
            if (dir.exists()) assertTrue(dir.renameTo(File(root, "$name.wipe-test")))
        }
    }

    @Test
    fun the_wipe_forgets_every_report_id_and_none_comes_back() {
        val q = newQueue().apply { ensureDirs() }
        val mine = write(q, EnvelopeNames.chunk(sid, 1))
        val peer = write(q, EnvelopeNames.chunk(sid, 2))
        q.rememberReportId(mine.name, "aa".repeat(16))
        assertTrue(q.hasPeer(mine.name, "aa".repeat(16)) { "aa".repeat(16) })
        assertEquals("aa".repeat(16), q.knownReportId(peer.name))

        renameQueueAway()
        q.forget()
        assertEquals(null, q.knownReportId(mine.name))
        assertEquals(null, q.knownReportId(peer.name))
        // A worker still in flight re-reads its trailer after the wipe: its
        // envelope is gone, so nothing is cached again.
        q.rememberReportId(mine.name, "aa".repeat(16))
        assertEquals(null, q.knownReportId(mine.name))
    }

    @Test
    fun no_425_marker_is_written_once_the_queue_is_gone() {
        val q = newQueue().apply { ensureDirs() }
        val name = EnvelopeNames.chunk(sid, 7)
        write(q, name)
        renameQueueAway()
        // Directory absent: nothing is created at all.
        q.markNotCreated(name)
        assertFalse(File(root, EnvelopeQueue.MARKER_DIR).exists())
        // Directories recreated empty (an EnvelopeQueue.get after the wipe):
        // still no marker, the envelope is not there.
        q.ensureDirs()
        q.markNotCreated(name)
        assertFalse(q.isMarkedNotCreated(name))
        assertEquals(0, File(root, EnvelopeQueue.MARKER_DIR).listFiles()?.size ?: 0)
    }

    @Test
    fun a_marker_is_still_written_for_a_queued_envelope() {
        val q = newQueue().apply { ensureDirs() }
        val name = EnvelopeNames.chunk(sid, 3)
        write(q, name)
        q.markNotCreated(name)
        assertTrue(q.isMarkedNotCreated(name))
    }

    @Test
    fun refused_chunks_of_the_session_are_counted_apart() {
        val q = newQueue().apply { ensureDirs() }
        val other = "fedcba9876543210fedcba9876543210"
        val c1 = write(q, EnvelopeNames.chunk(sid, 1))
        val c2 = write(q, EnvelopeNames.chunk(sid, 2))
        val c3 = write(q, EnvelopeNames.chunk(sid, 3))
        q.remove(c1)
        assertTrue(q.moveToFailed(c2))
        // A second failure under the same name gets a numeric suffix.
        assertTrue(q.moveToFailed(write(q, EnvelopeNames.chunk(sid, 2))))
        // Not counted: another session, the metadata, a leftover .part.
        assertTrue(q.moveToFailed(write(q, EnvelopeNames.chunk(other, 1))))
        assertTrue(q.moveToFailed(write(q, EnvelopeNames.chunk(sid, 0))))
        File(q.failedDir, EnvelopeNames.chunk(sid, 4) + EnvelopeQueue.PART_SUFFIX).writeBytes(byteArrayOf(1))

        val failed = q.failedChunksOfSession(sid)
        assertEquals(1, failed)
        // Three sealed: one delivered, one still queued, one refused. The HUD
        // must not show the refused one as sent.
        val sealed = 3
        val pending = q.pendingChunksOfSession(sid)
        assertEquals(1, pending)
        assertTrue(c3.exists())
        assertEquals(1, HudCounters.delivered(sealed, pending, failed))
        // What the HUD used to show: the refused chunk counted as sent.
        assertEquals(2, (sealed - pending).coerceAtLeast(0))
    }

    @Test
    fun parked_names_drop_only_a_numeric_suffix() {
        val n = EnvelopeNames.chunk(sid, 5)
        assertEquals(n, EnvelopeQueue.parkedName(n))
        assertEquals(n, EnvelopeQueue.parkedName("$n.1729000000000"))
        assertEquals(null, EnvelopeQueue.parkedName(n + EnvelopeQueue.PART_SUFFIX))
        assertEquals(null, EnvelopeQueue.parkedName("$n.x1"))
        assertEquals(null, EnvelopeQueue.parkedName("$n."))
    }

    @Test
    fun a_closure_sampled_before_its_send_keeps_waiting_for_its_creator() {
        val q = newQueue().apply { ensureDirs() }
        val creator = write(q, EnvelopeNames.chunk(sid, 0))
        val closure = write(q, EnvelopeNames.closure(sid))
        val rid = "bb".repeat(16)
        val ridOf: (File) -> String? = { rid }
        val before = q.hasPeer(closure.name, rid, ridOf)
        // The creator is accepted and removed while the closure's 425 is on
        // its way back.
        q.remove(creator)
        val peers = UploadOutcomePolicy.closurePeersQueued(before) { q.hasPeer(closure.name, rid, ridOf) }
        assertEquals(
            UploadOutcomePolicy.Action.RETRY,
            UploadOutcomePolicy.decide(UploadOutcomePolicy.Kind.CLOSURE, false, 425, null, peers, false),
        )
        // Reading the queue only after the answer, as before, abandons it.
        assertFalse(q.hasPeer(closure.name, rid, ridOf))
    }

    @Test
    fun only_the_queue_directory_holds_sendable_envelopes() {
        val q = newQueue().apply { ensureDirs() }
        assertTrue(q.isQueued(q.pathFor(EnvelopeNames.chunk(sid, 1))))
        assertFalse(q.isQueued(File(q.failedDir, EnvelopeNames.chunk(sid, 1))))
        assertFalse(q.isQueued(File(root, "stream_chunk_queue/${sid}_000001.strm")))
        assertFalse(q.isQueued(q.pathFor("x.strm")))
    }
}
