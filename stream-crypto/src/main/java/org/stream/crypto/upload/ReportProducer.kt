package org.stream.crypto.upload

import org.stream.crypto.SecureWipe
import timber.log.Timber
import uniffi.frappuccino.CloseInfo
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.ReportWriter
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Drives the writer of one recording's report: every call to the
 * [ReportWriter] goes through ONE thread, in submission order.
 *
 * The order matters for two reasons. The closure must be the last thing the
 * writer does: it signs a manifest of exactly the objects sealed before it, so
 * a chunk sealed after it would be an object the relay refuses and the rescue
 * cannot vouch for. And the writer itself serialises its calls internally, so a
 * second thread would only queue behind the first while making the order of
 * the closure relative to the chunks a matter of luck.
 *
 * What a chunk goes through, on that thread: seal (read the MP4, encrypt, sign,
 * write the envelope durably), then, and only then, securely delete the MP4. A
 * seal that fails is retried a bounded number of times ([SealRetryPolicy]);
 * after the last attempt the chunk is lost: its envelope is deleted if any was
 * left at its (deterministic) path, the MP4 is deleted too (it is plaintext and
 * nothing can seal it any more), and the loss is counted for the witness.
 *
 * Once the closure is submitted, nothing more is accepted: a chunk delivered
 * after it is refused at the door ([submitChunk] returns [Submit.REFUSED]) and
 * the caller counts it lost.
 *
 * Two ways the key can go before the closure, and they are counted apart.
 * [abort] is this class's caller giving up on the closure (it was not written
 * in time): the chunks still queued behind it can no longer be sealed, their
 * video is lost and each is reported [ChunkResult.Lost]. A writer closed from
 * outside, which only the emergency wipe does (it aborts the live writer
 * process-wide), drops them as [ChunkResult.Dropped]: nothing of that identity
 * may be counted or shown any more.
 *
 * Every file this class deletes goes through the queue's deleter
 * ([EnvelopeQueue.delete]).
 *
 * The writer's key lives in Rust and never crosses into the JVM; this class
 * only holds the handle.
 */
class ReportProducer(
    private val writer: ReportWriter,
    private val queue: EnvelopeQueue,
    val sessionId: String,
    private val reinstallQueueKey: () -> Boolean,
) {
    /** Outcome of one chunk, reported once on the writer thread. */
    sealed class ChunkResult {
        abstract val seq: Int

        /** The envelope is durably in the queue; the MP4 is deleted. */
        data class Sealed(override val seq: Int, val envelope: File) : ChunkResult()

        /**
         * Not sealed, and it never will be: given up after the bounded
         * attempts, or still queued when [abort] gave up on the closure. The
         * MP4 is deleted; counted as a loss.
         */
        data class Lost(override val seq: Int) : ChunkResult()

        /**
         * The writer was closed from outside (the emergency wipe): the MP4 is
         * deleted, nothing is counted.
         */
        data class Dropped(override val seq: Int) : ChunkResult()
    }

    /** What [submitChunk] did with a chunk. */
    enum class Submit {
        /** Queued: its [ChunkResult] comes later, and the MP4 is this class's. */
        ACCEPTED,

        /**
         * This seq was already submitted. Nothing is queued, and the MP4 is
         * NOT the caller's to delete: it is the very file the first submission
         * of the seq seals (the path is derived from the seq), and that
         * submission deletes it when it is done.
         */
        DUPLICATE,

        /**
         * Not queued (closure already submitted, writer aborted, writer thread
         * gone): the caller owns the MP4 and the loss.
         */
        REFUSED,
    }

    sealed class CloseResult {
        /** The closure envelope is durably in the queue; the key is wiped. */
        data class Closed(val info: CloseInfo, val envelope: File) : CloseResult()

        /** The closure could not be written: the key is wiped without one. */
        object Interrupted : CloseResult()

        /**
         * The writer was aborted before its closure could be written: by
         * [abort], or from outside (the emergency wipe).
         */
        object Aborted : CloseResult()
    }

    private val executor: ExecutorService = ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue(),
    ) { r -> Thread(r, "report-writer").apply { isDaemon = true } }

    private val submitLock = Any()
    private var closeSubmitted = false
    private val submittedSeqs = HashSet<Int>()

    @Volatile private var aborted = false

    // Set by [abort] only, never by a writer found closed: tells "the caller
    // gave up on the closure" (chunks still queued are lost and counted) from
    // "the emergency wipe closed the writer" (dropped, not counted).
    @Volatile private var abortedHere = false

    private val sealedCounter = AtomicInteger(0)
    private val lostCounter = AtomicInteger(0)

    val sealedCount: Int get() = sealedCounter.get()
    val lostCount: Int get() = lostCounter.get()

    val directoryEntryFile: File = queue.pathFor(EnvelopeNames.directoryEntry(sessionId))
    val metadataFile: File = queue.pathFor(EnvelopeNames.chunk(sessionId, 0))
    val closureFile: File = queue.pathFor(EnvelopeNames.closure(sessionId))

    /**
     * Write the report's two opening envelopes: its directory entry, then its
     * metadata (seq 0). Blocks until done. On failure the writer is aborted
     * and both files are removed: the recording must not start, and its index
     * is simply never used (the rescue tolerates the gap).
     *
     * [metadataJson] is wiped before this returns.
     */
    fun open(metadataJson: ByteArray) {
        try {
            executor.submit(Callable {
                writer.sealDirectoryEntry(directoryEntryFile.absolutePath)
                writer.sealMetadata(metadataJson, metadataFile.absolutePath)
            }).get()
            queue.invalidate()
        } catch (e: Exception) {
            abort()
            queue.delete(directoryEntryFile)
            queue.delete(metadataFile)
            queue.invalidate()
            shutdownAfterAbort()
            throw e
        } finally {
            SecureWipe.wipe(metadataJson)
        }
    }

    /**
     * Queue the sealing of chunk [seq] (the capture number) from [mp4]. On
     * [Submit.ACCEPTED], [onResult] is called exactly once, on the writer
     * thread. On [Submit.REFUSED] the caller owns the MP4 and the loss. On
     * [Submit.DUPLICATE] the caller must leave the MP4 alone: see [Submit].
     */
    fun submitChunk(seq: Int, mp4: File, onResult: (ChunkResult) -> Unit): Submit {
        synchronized(submitLock) {
            if (closeSubmitted || aborted) return Submit.REFUSED
            // A seq is sealed once. Refusing a duplicate here is what makes it
            // safe to delete the file at the seq's deterministic path when a
            // seal is given up: it can only be a leftover of that same seq.
            // Without it, the writer would refuse the second seal, and giving
            // that one up would delete the envelope the first one wrote.
            if (!submittedSeqs.add(seq)) return Submit.DUPLICATE
            return try {
                executor.execute { runChunk(seq, mp4, onResult) }
                Submit.ACCEPTED
            } catch (e: RejectedExecutionException) {
                submittedSeqs.remove(seq)
                Submit.REFUSED
            }
        }
    }

    /**
     * Seal one chunk and report it, exactly once, whatever happens: the caller
     * keeps counts of chunks in flight that only [onResult] brings back down.
     */
    private fun runChunk(seq: Int, mp4: File, onResult: (ChunkResult) -> Unit) {
        var fatal: VirtualMachineError? = null
        val result = try {
            sealChunk(seq, mp4)
        } catch (e: VirtualMachineError) {
            fatal = e
            lostCounter.incrementAndGet()
            ChunkResult.Lost(seq)
        }
        try {
            onResult(result)
        } catch (e: Exception) {
            Timber.w(e, "chunk result callback failed")
        }
        fatal?.let { throw it }
    }

    private fun sealChunk(seq: Int, mp4: File): ChunkResult {
        val out = queue.pathFor(EnvelopeNames.chunk(sessionId, seq))
        var attempts = 0
        while (true) {
            attempts++
            val failure = try {
                writer.sealChunkFile(seq.toUInt(), mp4.absolutePath, out.absolutePath)
                queue.delete(mp4)
                sealedCounter.incrementAndGet()
                queue.invalidate()
                return ChunkResult.Sealed(seq, out)
            } catch (e: VirtualMachineError) {
                throw e
            } catch (e: Throwable) {
                Timber.w(e, "seal of chunk %d failed (attempt %d)", seq, attempts)
                classify(e)
            }
            // The key is gone: nothing seals this chunk any more, and its MP4
            // is plaintext. Chunks are refused at the door once the closure is
            // submitted, so a writer closed here was closed by [abort] (the
            // caller gave up on the closure: a loss, counted) or from outside
            // (the emergency wipe: dropped, not counted).
            if (aborted || failure == SealRetryPolicy.Failure.WRITER_CLOSED) {
                aborted = true
                queue.delete(mp4)
                return lostOrDropped(seq, failure)
            }
            when (val d = SealRetryPolicy.decide(failure, attempts, SealRetryPolicy.CHUNK_ATTEMPTS)) {
                is SealRetryPolicy.Decision.Retry -> {
                    if (d.reinstallQueueKey) reinstallQueueKey()
                    sleepQuietly(d.delayMs)
                }
                SealRetryPolicy.Decision.Abandon -> {
                    // The writer leaves nothing at `out` on a failed seal; this
                    // removes whatever an earlier crash may have left there, so
                    // no stray file of a lost seq waits in the queue.
                    queue.delete(File(out.path + EnvelopeQueue.PART_SUFFIX))
                    queue.delete(out)
                    queue.delete(mp4)
                    queue.invalidate()
                    return lostOrDropped(seq, failure)
                }
            }
        }
    }

    private fun lostOrDropped(seq: Int, failure: SealRetryPolicy.Failure): ChunkResult {
        if (aborted && !abortedHere) return ChunkResult.Dropped(seq)
        lostCounter.incrementAndGet()
        Timber.tag("StreamMetrics").w("chunkLost seq=%d failure=%s", seq, failure.name)
        return ChunkResult.Lost(seq)
    }

    /**
     * Submit the closure as the writer's last task and return its future. No
     * chunk is accepted after this call. The writer handle is released once
     * the closure task has run.
     */
    fun submitClose(): Future<CloseResult> {
        synchronized(submitLock) {
            closeSubmitted = true
            val future = try {
                executor.submit(Callable { closeNow() })
            } catch (e: RejectedExecutionException) {
                // The writer thread is already gone (an abort shut it down):
                // there is nothing left to close.
                java.util.concurrent.FutureTask<CloseResult> { CloseResult.Aborted }.also { it.run() }
            }
            executor.shutdown()
            return future
        }
    }

    private fun closeNow(): CloseResult {
        try {
            var attempts = 0
            while (true) {
                if (aborted) return CloseResult.Aborted
                attempts++
                val failure = try {
                    val info = writer.closeReport(closureFile.absolutePath)
                    queue.invalidate()
                    return CloseResult.Closed(info, closureFile)
                } catch (e: VirtualMachineError) {
                    throw e
                } catch (e: Throwable) {
                    Timber.w(e, "closure write failed (attempt %d)", attempts)
                    classify(e)
                }
                // Same reasoning as for a chunk: a writer closed before its
                // closure succeeded was aborted, by [abort] or from outside.
                if (aborted || failure == SealRetryPolicy.Failure.WRITER_CLOSED) {
                    aborted = true
                    return CloseResult.Aborted
                }
                when (val d = SealRetryPolicy.decide(failure, attempts, SealRetryPolicy.CLOSE_ATTEMPTS)) {
                    is SealRetryPolicy.Decision.Retry -> {
                        if (d.reinstallQueueKey) reinstallQueueKey()
                        sleepQuietly(d.delayMs)
                    }
                    SealRetryPolicy.Decision.Abandon -> {
                        // The key goes without a closure: the report stays
                        // readable object by object, its end uncertified.
                        abortWriterQuietly()
                        return CloseResult.Interrupted
                    }
                }
            }
        } finally {
            releaseWriter()
        }
    }

    /**
     * Give up on the closure: wipe the writer's key without one. Safe from any
     * thread and more than once; a seal in progress finishes its envelope
     * write first (the writer serialises it), every later call fails. The
     * chunks still queued are then reported [ChunkResult.Lost] and counted:
     * they were captured and will never be sealed. Call [awaitIdle] before
     * reading [lostCount] if the count has to include them.
     */
    fun abort() {
        abortedHere = true
        aborted = true
        abortWriterQuietly()
    }

    /** After an abort that will never be followed by [submitClose]. */
    fun shutdownAfterAbort() {
        synchronized(submitLock) { closeSubmitted = true }
        try {
            executor.execute { releaseWriter() }
        } catch (_: RejectedExecutionException) {
            // Already shut down by an earlier call.
        }
        executor.shutdown()
    }

    /** Wait for the writer thread to finish what it has (after close or abort). */
    fun awaitIdle(timeoutMs: Long): Boolean =
        try {
            executor.awaitTermination(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }

    private fun abortWriterQuietly() {
        try {
            writer.abort()
        } catch (e: Exception) {
            // Already released: nothing is left to wipe.
            Timber.d(e, "writer abort after release")
        }
    }

    private fun releaseWriter() {
        try {
            writer.destroy()
        } catch (e: Exception) {
            Timber.d(e, "writer release")
        }
    }

    private fun classify(e: Throwable): SealRetryPolicy.Failure = when (e) {
        is FfiException.WriterClosed -> SealRetryPolicy.Failure.WRITER_CLOSED
        is FfiException.ReportRefused -> SealRetryPolicy.Failure.REFUSED
        is FfiException.NoQueueKey -> SealRetryPolicy.Failure.NO_QUEUE_KEY
        is FfiException.Io -> SealRetryPolicy.Failure.IO
        else -> SealRetryPolicy.Failure.OTHER
    }

    private fun sleepQuietly(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
