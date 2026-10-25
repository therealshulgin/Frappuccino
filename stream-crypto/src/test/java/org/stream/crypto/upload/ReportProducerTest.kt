package org.stream.crypto.upload

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.frappuccino.CloseInfo
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.NoPointer
import uniffi.frappuccino.ReportWriter
import uniffi.frappuccino.SealedChunk
import java.io.File
import java.nio.file.Files
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The producer around a fake writer (no native library): what it does with a
 * duplicate seq, and how it counts the chunks still queued when the key goes
 * before the closure.
 *
 * The fake follows the real writer's contract where it matters here: a seal
 * reads the MP4, a seq is sealed once, a call in progress when the writer is
 * aborted finishes, and every call after the abort throws WriterClosed.
 */
class ReportProducerTest {

    private lateinit var root: File
    private lateinit var scratch: File
    private val sid = "0123456789abcdef0123456789abcdef"

    private class FakeWriter(private val holdSeq: Int? = null) : ReportWriter(NoPointer) {
        val hold = CountDownLatch(1)
        val holding = CountDownLatch(1)
        @Volatile var closed = false
        val sealed: MutableSet<Int> = Collections.synchronizedSet(HashSet())
        val mp4SeenAtSeal: MutableMap<Int, Boolean> = Collections.synchronizedMap(HashMap())

        override fun sealChunkFile(seq: UInt, inputPath: String, outPath: String): SealedChunk {
            if (closed) throw FfiException.WriterClosed()
            val s = seq.toInt()
            if (s == holdSeq) {
                holding.countDown()
                hold.await(10, TimeUnit.SECONDS)
            }
            val mp4 = File(inputPath)
            mp4SeenAtSeal[s] = mp4.exists()
            if (!mp4.exists()) throw FfiException.Io("mp4 missing")
            if (!sealed.add(s)) throw FfiException.ReportRefused("seq already sealed")
            File(outPath).writeBytes(mp4.readBytes())
            return SealedChunk(seq, mp4.length().toULong())
        }

        override fun closeReport(outPath: String): CloseInfo {
            if (closed) throw FfiException.WriterClosed()
            File(outPath).writeBytes(byteArrayOf(9))
            closed = true
            return CloseInfo(0u, "00".repeat(16), 0u, 0u, emptyList(), "ots")
        }

        override fun abort() {
            closed = true
        }

        override fun destroy() = Unit
    }

    @Before
    fun setUp() {
        root = Files.createTempDirectory("producer").toFile()
        scratch = File(root, "stream_chunks").apply { mkdirs() }
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    private fun queue() = EnvelopeQueue(root) { it.delete() }.apply { ensureDirs() }

    private fun mp4(seq: Int): File =
        File(scratch, "chunk-%03d.mp4".format(seq)).apply { writeBytes(ByteArray(64) { seq.toByte() }) }

    private fun producer(writer: FakeWriter) = ReportProducer(writer, queue(), sid) { true }

    @Test
    fun a_duplicate_seq_leaves_the_mp4_to_its_first_submission() {
        val writer = FakeWriter(holdSeq = 5)
        val p = producer(writer)
        val results = Collections.synchronizedList(ArrayList<ReportProducer.ChunkResult>())
        val file = mp4(5)

        assertEquals(ReportProducer.Submit.ACCEPTED, p.submitChunk(5, file) { results.add(it) })
        assertTrue(writer.holding.await(5, TimeUnit.SECONDS))
        // The same chunk delivered twice (same seq, same file) while the first
        // seal is still running.
        assertEquals(ReportProducer.Submit.DUPLICATE, p.submitChunk(5, file) { results.add(it) })
        assertTrue("the duplicate must not touch the MP4", file.exists())

        writer.hold.countDown()
        p.submitClose().get(5, TimeUnit.SECONDS)
        assertTrue(p.awaitIdle(5_000))
        assertEquals(true, writer.mp4SeenAtSeal[5])
        assertEquals(1, results.size)
        assertTrue(results.single() is ReportProducer.ChunkResult.Sealed)
        assertEquals(5, results.single().seq)
        assertEquals(0, p.lostCount)
    }

    @Test
    fun a_chunk_after_the_closure_is_refused_and_left_to_the_caller() {
        val p = producer(FakeWriter())
        p.submitClose().get(5, TimeUnit.SECONDS)
        val file = mp4(3)
        assertEquals(ReportProducer.Submit.REFUSED, p.submitChunk(3, file) { })
        assertTrue(file.exists())
    }

    @Test
    fun chunks_cut_off_by_giving_up_on_the_closure_are_lost_and_counted() {
        val writer = FakeWriter(holdSeq = 1)
        val p = producer(writer)
        val results = Collections.synchronizedList(ArrayList<ReportProducer.ChunkResult>())
        val files = (1..4).map { mp4(it) }
        for ((i, f) in files.withIndex()) {
            assertEquals(ReportProducer.Submit.ACCEPTED, p.submitChunk(i + 1, f) { results.add(it) })
        }
        assertTrue(writer.holding.await(5, TimeUnit.SECONDS))
        val close = p.submitClose()
        // The closure is not written in time: the caller gives up on it.
        p.abort()
        // The seal in progress finishes (the real writer serialises it).
        writer.hold.countDown()
        assertTrue(p.awaitIdle(5_000))

        assertEquals(ReportProducer.CloseResult.Aborted, close.get(1, TimeUnit.SECONDS))
        val bySeq = results.associateBy { it.seq }
        assertTrue(bySeq[1] is ReportProducer.ChunkResult.Sealed)
        for (seq in 2..4) {
            assertTrue("seq $seq: ${bySeq[seq]}", bySeq[seq] is ReportProducer.ChunkResult.Lost)
        }
        assertEquals(3, p.lostCount)
        // Plaintext never outlives the key.
        assertTrue(files.none { it.exists() })
    }

    @Test
    fun chunks_cut_off_by_the_emergency_wipe_are_dropped_uncounted() {
        val writer = FakeWriter(holdSeq = 1)
        val p = producer(writer)
        val results = Collections.synchronizedList(ArrayList<ReportProducer.ChunkResult>())
        val files = (1..4).map { mp4(it) }
        for ((i, f) in files.withIndex()) p.submitChunk(i + 1, f) { results.add(it) }
        assertTrue(writer.holding.await(5, TimeUnit.SECONDS))
        // The wipe aborts the live writer process-wide, not through the producer.
        writer.abort()
        writer.hold.countDown()
        p.submitClose()
        assertTrue(p.awaitIdle(5_000))

        val bySeq = results.associateBy { it.seq }
        for (seq in 2..4) {
            assertTrue("seq $seq: ${bySeq[seq]}", bySeq[seq] is ReportProducer.ChunkResult.Dropped)
        }
        assertEquals(0, p.lostCount)
        assertTrue(files.drop(1).none { it.exists() })
    }
}
