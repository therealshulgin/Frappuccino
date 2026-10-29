package rs.readahead.washington.mobile.diagnostics

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.zip.GZIPOutputStream

/**
 * One upload pass: what the worker does, minus Android and the network.
 *
 * Builds the request bodies, sends them one at a time through [send] and
 * deletes the spill files each one carried once the relay has answered for
 * them. Every body is the gzip of UTF-8 text: the device profile first, then
 * the closed spill files oldest first, then the logcat capture last, and
 * stays within [maxRequestBytes] compressed (the relay refuses more). When
 * everything does not fit in one body it is split by part, each body
 * repeating the profile so that every file stored on the relay reads alone.
 *
 * What the relay's answer does to the files ([outcomeOf]): a 2xx deletes them;
 * so do 400 and 413, since a body the relay refuses would be refused again and
 * would otherwise be resent at every pass; anything else (429, 5xx, a relay
 * that does not have the route yet) and an [IOException] keep them for the
 * next pass and stop this one.
 *
 * An emergency wipe during the pass ends it: [SpillStore.generation] is read
 * once at the start and checked before every request and every deletion, so
 * nothing read before the wipe is sent after it, and no file of the fresh
 * directory is deleted by name. The install id is read after the generation,
 * and the wipe advances the generation before it forgets the id: a fresh id
 * read by a pass that started before the wipe is therefore always caught by
 * the check before the first request, and never sent with the old data.
 */
internal class DiagnosticsUploader(
    private val store: SpillStore,
    private val installId: () -> String,
    private val profile: () -> String,
    private val logcat: () -> String,
    private val send: (body: ByteArray, installId: String) -> Int,
    private val maxRequestBytes: Int = MAX_REQUEST_BYTES,
) {
    enum class Outcome { SENT, REFUSED, RETRY }

    class Part(val title: String, val bytes: ByteArray, val file: File?)

    class Request(val body: ByteArray, val files: List<File>)

    /** True when the pass is over; false when it must be retried later. */
    fun run(): Boolean {
        val gen = store.generation
        val id = installId()
        val parts = ArrayList<Part>()
        for (f in store.closeForUpload(gen)) {
            val bytes = try { f.readBytes() } catch (e: IOException) { continue }
            if (bytes.isNotEmpty()) parts += Part("app log ${f.name}", bytes, f)
        }
        val capture = logcat()
        if (capture.isNotEmpty()) parts += Part("logcat", capture.toByteArray(Charsets.UTF_8), null)
        if (parts.isEmpty()) return true
        val header = "### device profile\n${profile()}\n".toByteArray(Charsets.UTF_8)
        for (request in plan(header, parts, maxRequestBytes)) {
            if (store.generation != gen) return true
            val outcome = try {
                outcomeOf(send(request.body, id))
            } catch (e: IOException) {
                Outcome.RETRY
            }
            if (outcome == Outcome.RETRY) return false
            if (!store.delete(request.files, gen)) return true
        }
        return true
    }

    companion object {
        /** Largest body the relay accepts. */
        const val MAX_REQUEST_BYTES = 1024 * 1024

        /** Uncompressed bound per body, well under the relay's 8 MiB. */
        const val MAX_RAW_BYTES = 4 * 1024 * 1024

        fun outcomeOf(status: Int): Outcome = when (status) {
            in 200..299 -> Outcome.SENT
            400, 413 -> Outcome.REFUSED
            else -> Outcome.RETRY
        }

        /**
         * Pack [parts] in order into as few bodies as fit in [max] bytes each.
         * A part too large for a body on its own is cut down to its most
         * recent lines until it fits.
         */
        fun plan(header: ByteArray, parts: List<Part>, max: Int): List<Request> {
            val requests = ArrayList<Request>()
            var batch = ArrayList<Part>()
            var batchBody: ByteArray? = null
            for (part in parts) {
                val candidate = batch + part
                val body = if (rawSize(header, candidate) <= MAX_RAW_BYTES) gzip(header, candidate) else null
                if (body != null && body.size <= max) {
                    batch = ArrayList(candidate)
                    batchBody = body
                    continue
                }
                if (batch.isNotEmpty()) requests += Request(batchBody!!, batch.mapNotNull { it.file })
                val single = gzip(header, listOf(part))
                if (single.size <= max && rawSize(header, listOf(part)) <= MAX_RAW_BYTES) {
                    batch = arrayListOf(part)
                    batchBody = single
                } else {
                    requests += Request(shrink(header, part, max), listOfNotNull(part.file))
                    batch = ArrayList()
                    batchBody = null
                }
            }
            if (batch.isNotEmpty()) requests += Request(batchBody!!, batch.mapNotNull { it.file })
            return requests
        }

        // Keep the end of the part, halving it until the body fits, and cut
        // at a line start so no line arrives half-written.
        private fun shrink(header: ByteArray, part: Part, max: Int): ByteArray {
            var keep = minOf(part.bytes.size, MAX_RAW_BYTES / 2)
            while (true) {
                var from = part.bytes.size - keep
                while (from in 1 until part.bytes.size && part.bytes[from - 1] != '\n'.code.toByte()) from++
                val tail = part.bytes.copyOfRange(from, part.bytes.size)
                val note = "[cut: the first $from bytes of this part did not fit in a request]\n"
                    .toByteArray(Charsets.UTF_8)
                val body = gzip(header, listOf(Part(part.title, note + tail, null)))
                if (body.size <= max || keep <= 1) return body
                keep /= 2
            }
        }

        private fun rawSize(header: ByteArray, parts: List<Part>): Long =
            header.size + parts.sumOf { it.bytes.size.toLong() + it.title.length + 8 }

        fun gzip(header: ByteArray, parts: List<Part>): ByteArray {
            val out = ByteArrayOutputStream()
            GZIPOutputStream(out).use { z ->
                z.write(header)
                for (p in parts) {
                    z.write("\n### ${p.title}\n".toByteArray(Charsets.UTF_8))
                    z.write(p.bytes)
                }
            }
            return out.toByteArray()
        }
    }
}
