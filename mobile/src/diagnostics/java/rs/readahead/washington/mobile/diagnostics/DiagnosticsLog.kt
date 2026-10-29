package rs.readahead.washington.mobile.diagnostics

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** One log call, as captured on the thread that made it. */
internal class Entry(
    val timeMs: Long,
    val priority: Int,
    val tag: String?,
    val thread: String,
    val message: String,
)

/**
 * Takes log entries from any thread and writes them, redacted, to the
 * [SpillStore] on a single background thread.
 *
 * A caller pays for a queue insertion and nothing else: formatting, redaction
 * and the file write all happen on the writer thread, so a camera or encoder
 * thread that logs never waits on the disk. The queue is bounded twice, in
 * entries ([capacity]) and in characters ([maxQueuedChars]); an entry that
 * does not fit is dropped and counted, and the count is written as a line of
 * its own with the next batch.
 *
 * After an emergency wipe ([stopForWipe]) it takes nothing more until the
 * process restarts: a line written after the wipe would be the first thing a
 * seized phone shows, starting with the wipe itself.
 */
internal class DiagnosticsLog(
    private val store: SpillStore,
    private val executor: Executor = defaultExecutor(),
    private val capacity: Int = CAPACITY,
    private val maxQueuedChars: Long = MAX_QUEUED_CHARS,
) {
    private val queue = ArrayBlockingQueue<Entry>(capacity)
    private val queuedChars = AtomicLong()
    private val scheduled = AtomicBoolean(false)
    private val dropped = AtomicLong()

    @Volatile
    private var stopped = false

    /** Entries dropped since the last write. */
    val droppedCount: Long get() = dropped.get()

    /** Queue [entry] for writing; false when it was dropped. */
    fun submit(entry: Entry): Boolean {
        if (stopped) return false
        val size = entry.message.length.toLong()
        if (queuedChars.addAndGet(size) > maxQueuedChars || !queue.offer(entry)) {
            queuedChars.addAndGet(-size)
            dropped.incrementAndGet()
            return false
        }
        if (scheduled.compareAndSet(false, true)) {
            try {
                executor.execute { drain() }
            } catch (e: Exception) {
                scheduled.set(false)
            }
        }
        return true
    }

    /**
     * Write what is queued, then [entry], on the calling thread. For the crash
     * handler, which must not return before its trace is on disk.
     */
    fun writeNow(entry: Entry) {
        if (stopped) return
        val gen = store.generation
        store.write(pendingLines() + format(entry), gen)
    }

    /** Drop what is queued and take nothing more (emergency wipe). */
    fun stopForWipe() {
        stopped = true
        queue.clear()
        queuedChars.set(0)
        dropped.set(0)
    }

    private fun drain() {
        scheduled.set(false)
        // Read before taking the entries: a wipe after this point makes the
        // write below a no-op instead of a write into the fresh directory.
        val gen = store.generation
        val lines = pendingLines()
        if (lines.isNotEmpty() && !stopped) store.write(lines, gen)
    }

    private fun pendingLines(): List<String> {
        val batch = ArrayList<Entry>()
        queue.drainTo(batch)
        val lines = ArrayList<String>()
        for (e in batch) queuedChars.addAndGet(-e.message.length.toLong())
        val lost = dropped.getAndSet(0)
        if (lost > 0) lines += "${formatTime(System.currentTimeMillis())} W/FrappDiag: $lost log entries dropped (queue full)"
        for (e in batch) lines += format(e)
        return lines
    }

    companion object {
        const val CAPACITY = 2048
        const val MAX_QUEUED_CHARS = 2L * 1024 * 1024

        /** Longest message kept; the rest of a longer one is cut. */
        const val MAX_MESSAGE_CHARS = 16 * 1024

        private fun defaultExecutor(): Executor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "diag-writer").apply {
                isDaemon = true
                priority = Thread.MIN_PRIORITY
            }
        }

        private val PRIORITY = charArrayOf('?', '?', 'V', 'D', 'I', 'W', 'E', 'A')

        /**
         * The stored lines of [e], each redacted. A message spanning several
         * lines (a stack trace) gives one stored line per line, each with the
         * same header, and is dropped whole when the phrase check matches
         * across its lines.
         */
        fun format(e: Entry): List<String> {
            val text = if (e.message.length > MAX_MESSAGE_CHARS) {
                e.message.substring(0, MAX_MESSAGE_CHARS) + " [cut at $MAX_MESSAGE_CHARS chars]"
            } else e.message
            if (LogRedactor.mentionsPhrase(text)) return emptyList()
            val p = PRIORITY.getOrElse(e.priority) { '?' }
            val header = "${formatTime(e.timeMs)} $p/${e.tag ?: "-"} [${e.thread}]: "
            return text.split('\n').mapNotNull { line -> LogRedactor.redact(header + line.trimEnd('\r')) }
        }

        private val TIME = object : ThreadLocal<SimpleDateFormat>() {
            override fun initialValue() = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }
        }

        fun formatTime(ms: Long): String = TIME.get()!!.format(Date(ms))
    }
}
