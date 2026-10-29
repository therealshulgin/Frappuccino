package rs.readahead.washington.mobile.archive

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * Clears, in place, what the platform muxer writes about the export into a
 * joined video ([Mp4ChunkMedia]): the creation and modification times of the
 * movie, of each track and of each track's media (`mvhd`, `tkhd`, `mdhd`),
 * which are those of the export; and the metadata boxes (`meta`, `udta`),
 * where it writes the Android version of the phone that exports
 * (`com.android.version`).
 *
 * Nothing moves. No box changes size or place, so the sample offsets
 * (`stco`, `co64`) stay right whether the movie box comes before or after
 * the media data. A date is set to 0. A metadata box is renamed `free`, a
 * box every reader skips, and its content is set to zeros; a `udta` goes
 * whole, since it only ever holds user data about its container, nothing a
 * reader needs to play the file. The boxes that describe the samples are
 * not touched, nor the handler names and track languages.
 *
 * What a cleared file still tells: a cleared box keeps its size, and the
 * size of the `meta` box depends on the length of the Android version string
 * it held ("9", "14", "8.1.0", ...). The version is gone, its length class is
 * not. Removing the box rather than keeping it would not make files from
 * different Android releases alike: the rest of the layout is the exporting
 * phone's muxer's, which may differ between releases too. The residual is in
 * docs/ACCEPTED_RESIDUALS_2026-06-28.md, section "Video export from the
 * rescue".
 *
 * The walk reads only box headers and the start of the date boxes. It
 * enters `moov`, `trak`, `mdia` and `udta`, and treats every other box as
 * opaque.
 *
 * Fail-closed. The file is walked first from a read-only handle, and
 * anything unexpected refuses it with [Unexpected] before a single byte is
 * written: a size that runs past its container or the file, a box shorter
 * than its own header, a size 0 anywhere but on the last top-level box,
 * bytes left over after the last box, nesting deeper than [MAX_DEPTH], more
 * than [MAX_BOXES] boxes, not exactly one `moov`, a `moov` without exactly
 * one `mvhd` or without a track, a `trak` without exactly one `tkhd` and one
 * `mdia`, an `mdia` without exactly one `mdhd`, a date box of a version
 * other than 0 or 1 or shorter than that version's fields. Once written,
 * the file is walked again and must hold no date and no metadata box, or
 * [scrub] throws: a video it cannot account for is never left for a copy.
 *
 * Plain Kotlin on a file, so it runs on a JVM as well as on the phone.
 */
internal object Mp4MetadataScrub {

    /** The file is not one [scrub] knows how to clear; nothing was written. */
    class Unexpected(message: String) : IOException(message)

    /** A box: its [type], where it starts, the size of its header (8, or
     *  16 when its size is a 64-bit `largesize`) and where it ends. */
    class Box(val type: String, val offset: Long, val headerSize: Int, val end: Long) {
        val payload: Long get() = offset + headerSize
    }

    /** A creation or modification time: [width] bytes (4 for a version 0
     *  box, 8 for version 1) at [offset], inside a box of type [box]. */
    class DateField(val box: String, val offset: Long, val width: Int, val value: Long)

    /** What [inspect] finds: every date field of the `mvhd`, `tkhd` and
     *  `mdhd` boxes, and every `meta` or `udta` box outside a `udta`. */
    class Findings(val dates: List<DateField>, val metadata: List<Box>) {
        val datesCleared: Boolean get() = dates.all { it.value == 0L }
        val metadataCleared: Boolean get() = metadata.isEmpty()

        /** No date and no metadata box left: both, since a file can hold one
         *  without the other. */
        val clear: Boolean get() = datesCleared && metadataCleared
    }

    /** Walk [file] without writing. Throws [Unexpected] for a file the
     *  scrub would refuse. */
    fun inspect(file: File): Findings =
        RandomAccessFile(file, "r").use { Walker(it.channel).walk() }

    /**
     * Clear the dates and the metadata boxes of [file], in place. Throws
     * [Unexpected], having written nothing, for a file it does not know how
     * to clear, and [IOException] when the file still holds either after
     * the writes.
     */
    fun scrub(file: File) {
        val found = inspect(file)
        if (found.clear) return
        RandomAccessFile(file, "rw").use { raf ->
            val channel = raf.channel
            for (date in found.dates) {
                if (date.value != 0L) zero(channel, date.offset, date.width.toLong())
            }
            for (box in found.metadata) {
                writeFully(channel, box.offset + 4, ByteBuffer.wrap(FREE))
                zero(channel, box.payload, box.end - box.payload)
            }
        }
        // Checked half by half rather than through `clear`, so that a fault in
        // how `clear` combines the halves cannot also pass a write that left
        // one of them in place. A fault in a half itself (`datesCleared`,
        // `metadataCleared`) would pass here as well: the tests guard those.
        val after = inspect(file)
        if (!after.datesCleared) throw IOException("a date left in the video")
        if (!after.metadataCleared) throw IOException("a metadata box left in the video")
    }

    private class Walker(private val channel: FileChannel) {
        private val dates = ArrayList<DateField>()
        private val metadata = ArrayList<Box>()
        private val header = ByteBuffer.allocate(16)
        private var boxes = 0

        fun walk(): Findings {
            enter(null, 0L, channel.size(), depth = 0, inUserData = false)
            return Findings(dates, metadata)
        }

        /** Walk the children of [type] (null for the file's top level),
         *  which lie in `[from, to)`. Inside a `udta` ([inUserData]) the
         *  boxes are only checked for size: the `udta` is cleared whole. */
        private fun enter(type: String?, from: Long, to: Long, depth: Int, inUserData: Boolean) {
            if (depth > MAX_DEPTH) throw Unexpected("boxes nested too deep")
            val children = children(from, to, topLevel = type == null)
            if (!inUserData) checkLayout(type, children)
            for (box in children) {
                when (box.type) {
                    "mvhd", "tkhd", "mdhd" -> if (!inUserData) readDates(box)
                    "meta" -> if (!inUserData) metadata.add(box)
                    "udta" -> {
                        if (!inUserData) metadata.add(box)
                        enter(box.type, box.payload, box.end, depth + 1, inUserData = true)
                    }
                    "moov", "trak", "mdia" -> enter(box.type, box.payload, box.end, depth + 1, inUserData)
                }
            }
        }

        /** The boxes that tile `[from, to)` exactly. A size 0 (the box runs
         *  to the end of the file) is only taken on the top level. */
        private fun children(from: Long, to: Long, topLevel: Boolean): List<Box> {
            val out = ArrayList<Box>()
            var at = from
            while (at < to) {
                if (++boxes > MAX_BOXES) throw Unexpected("too many boxes")
                if (to - at < 8) throw Unexpected("bytes left over after the last box")
                read(at, 8)
                val size32 = header.getInt(0).toLong() and 0xFFFF_FFFFL
                val type = String(ByteArray(4) { header.get(4 + it) }, Charsets.ISO_8859_1)
                val headerSize: Int
                val size: Long
                when (size32) {
                    0L -> {
                        if (!topLevel) throw Unexpected("box of size 0 inside a box")
                        headerSize = 8
                        size = to - at
                    }
                    1L -> {
                        if (to - at < 16) throw Unexpected("box shorter than its header")
                        read(at, 16)
                        headerSize = 16
                        // Read as signed: a largesize of 2^63 or more is
                        // negative here, and refused with the short ones.
                        size = header.getLong(8)
                        if (size < 16) throw Unexpected("box shorter than its header")
                    }
                    else -> {
                        if (size32 < 8) throw Unexpected("box shorter than its header")
                        headerSize = 8
                        size = size32
                    }
                }
                if (size > to - at) throw Unexpected("box runs past its container")
                out.add(Box(type, at, headerSize, at + size))
                at += size
            }
            return out
        }

        /** The boxes the walk relies on, where it expects them. */
        private fun checkLayout(type: String?, children: List<Box>) {
            fun count(t: String) = children.count { it.type == t }
            val expected = when (type) {
                null -> count("moov") == 1
                "moov" -> count("mvhd") == 1 && count("trak") >= 1
                "trak" -> count("tkhd") == 1 && count("mdia") == 1
                "mdia" -> count("mdhd") == 1
                else -> true
            }
            if (!expected) throw Unexpected("unexpected layout in ${type ?: "the file"}")
        }

        /** The creation and modification times of a `mvhd`, `tkhd` or
         *  `mdhd`: the two fields right after the version and flags, 32-bit
         *  in version 0 and 64-bit in version 1, in all three. */
        private fun readDates(box: Box) {
            val length = box.end - box.payload
            if (length < 4) throw Unexpected("${box.type} shorter than its version")
            read(box.payload, 1)
            val version = header.get(0).toInt() and 0xFF
            val width = when (version) {
                0 -> 4
                1 -> 8
                else -> throw Unexpected("${box.type} of version $version")
            }
            if (length < minimumLength(box.type, version)) throw Unexpected("${box.type} too short")
            for (field in 0..1) {
                val offset = box.payload + 4 + field * width
                read(offset, width)
                val value = if (width == 4) header.getInt(0).toLong() and 0xFFFF_FFFFL else header.getLong(0)
                dates.add(DateField(box.type, offset, width, value))
            }
        }

        private fun read(at: Long, n: Int) {
            header.clear()
            header.limit(n)
            var position = at
            while (header.hasRemaining()) {
                val read = channel.read(header, position)
                if (read < 0) throw Unexpected("file shorter than its boxes")
                position += read
            }
        }
    }

    /** The length, version and flags included, of each date box's fields
     *  up to its last one (ISO/IEC 14496-12): `mvhd` up to `next_track_ID`,
     *  `tkhd` up to `height`, `mdhd` up to `pre_defined`. */
    private fun minimumLength(type: String, version: Int): Long = when (type) {
        "mvhd" -> if (version == 0) 100L else 112L
        "tkhd" -> if (version == 0) 84L else 96L
        else -> if (version == 0) 24L else 36L
    }

    private fun zero(channel: FileChannel, at: Long, length: Long) {
        val zeros = ByteBuffer.allocate(minOf(length, ZERO_CHUNK_BYTES).toInt())
        var position = at
        var left = length
        while (left > 0) {
            val n = minOf(left, zeros.capacity().toLong()).toInt()
            zeros.clear()
            zeros.limit(n)
            writeFully(channel, position, zeros)
            position += n
            left -= n
        }
    }

    private fun writeFully(channel: FileChannel, at: Long, bytes: ByteBuffer) {
        var position = at
        while (bytes.hasRemaining()) position += channel.write(bytes, position)
    }

    /** Deeper than any MP4 the platform muxer writes: the walk enters at
     *  most `moov`, `trak`, `mdia`, then a `udta`. */
    const val MAX_DEPTH = 8

    /** Far more boxes than the containers the walk enters ever hold; the
     *  sample tables are opaque boxes, not counted inside. */
    const val MAX_BOXES = 1 shl 16

    private const val ZERO_CHUNK_BYTES = 64L * 1024
    private val FREE = "free".toByteArray(Charsets.ISO_8859_1)
}
