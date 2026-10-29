package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.ByteBuffer

/**
 * The metadata scrub of a joined video, on MP4s built byte by byte: the
 * dates of the movie, track and media headers become 0, the metadata boxes
 * become `free` boxes of zeros, and every other byte stays where it was,
 * whether the movie box comes before or after the media data and whatever
 * the width of the sizes and dates. A file it does not recognise is refused
 * without a byte written.
 *
 * The expected result is built independently: the same file, written with
 * dates of 0 and each metadata box replaced by a `free` box of zeros of the
 * same size. The scrubbed file must equal it byte for byte.
 *
 * The files mimic what the platform muxer writes: a `meta` box under
 * `moov` and one in a `moov/udta`, holding `com.android.version`, and two
 * tracks whose chunk offsets point into the media data. Two of them hold
 * only one of the two things the scrub clears, dates or metadata, so that
 * each is required on its own before the file counts as cleared; two more
 * have the dates of only some headers at 0, so that every date is.
 */
class Mp4MetadataScrubTest {

    @get:Rule
    val tmp = TemporaryFolder()

    // ---- the scrub on files it knows ----

    @Test
    fun `the export's dates and the phone's tag are cleared, and nothing else changes`() {
        assertScrubbedTo(mp4(), mp4(cleared = true))
    }

    @Test
    fun `version 1 headers have their 64-bit dates cleared`() {
        assertScrubbedTo(mp4(version = 1), mp4(version = 1, cleared = true))
    }

    @Test
    fun `a movie box ahead of the media data is cleared the same, and no sample moves`() {
        assertScrubbedTo(mp4(moovFirst = true), mp4(moovFirst = true, cleared = true))
    }

    @Test
    fun `a 64-bit box size is followed to the next box`() {
        assertScrubbedTo(mp4(largeMdat = true), mp4(largeMdat = true, cleared = true))
        assertScrubbedTo(mp4(largeMdat = true, moovFirst = true), mp4(largeMdat = true, moovFirst = true, cleared = true))
    }

    @Test
    fun `a metadata box with a 64-bit size keeps its size fields`() {
        assertScrubbedTo(mp4(largeMeta = true), mp4(largeMeta = true, cleared = true))
    }

    @Test
    fun `user data inside a track goes too`() {
        assertScrubbedTo(mp4(trackUdta = true), mp4(trackUdta = true, cleared = true))
    }

    @Test
    fun `media data of size 0, running to the end of the file, is taken as the last box`() {
        assertScrubbedTo(mp4(moovFirst = true, openMdat = true), mp4(moovFirst = true, openMdat = true, cleared = true))
    }

    @Test
    fun `dates are cleared in a file that holds no metadata box`() {
        val input = mp4(withMetadata = false)
        assertFalse(contains(input, ANDROID_VERSION_KEY))
        assertScrubbedTo(input, mp4(withMetadata = false, cleared = true), tagged = false)
    }

    @Test
    fun `metadata boxes are cleared in a file whose dates are already 0`() {
        assertScrubbedTo(mp4(datesCleared = true), mp4(cleared = true))
    }

    @Test
    fun `every date counts, the movie's and the tracks'`() {
        // One header's dates already 0 must not pass for all of them, in a
        // file with no metadata box to clear besides.
        val someDatesAt0 = listOf(
            mp4(withMetadata = false, movieDatesCleared = true),
            mp4(withMetadata = false, trackDatesCleared = true),
        )
        for (input in someDatesAt0) {
            assertFalse(Mp4MetadataScrub.inspect(write(input)).datesCleared)
            assertScrubbedTo(input, mp4(withMetadata = false, cleared = true), tagged = false)
        }
    }

    @Test
    fun `the walk finds every date and every metadata box`() {
        val found = Mp4MetadataScrub.inspect(write(mp4(trackUdta = true)))

        // Two dates in the movie header, and in each of the two tracks'
        // track and media headers.
        assertEquals(listOf("mvhd", "mvhd", "tkhd", "tkhd", "mdhd", "mdhd", "tkhd", "tkhd", "mdhd", "mdhd"), found.dates.map { it.box })
        assertTrue(found.dates.all { it.value != 0L })
        // The movie's user data, each track's, and the movie's own `meta`.
        assertEquals(listOf("udta", "udta", "udta", "meta"), found.metadata.map { it.type })
        assertFalse(found.clear)
        assertTrue(Mp4MetadataScrub.inspect(write(mp4(trackUdta = true, cleared = true))).clear)
    }

    @Test
    fun `a file already cleared is left as it is`() {
        val file = write(mp4(cleared = true))

        Mp4MetadataScrub.scrub(file)

        assertArrayEquals(mp4(cleared = true), file.readBytes())
    }

    // ---- files it refuses, without writing ----

    @Test
    fun `a file cut short is refused`() {
        val whole = mp4()
        assertRefused(whole.copyOf(whole.size - 10))
        assertRefused(mp4(moovFirst = true).copyOf(whole.size - 10))
    }

    @Test
    fun `bytes left over after the last box are refused`() {
        assertRefused(mp4() + byteArrayOf(0, 0, 0, 1))
    }

    @Test
    fun `a box running past its container is refused`() {
        val bytes = mp4()
        assertRefused(withSize(bytes, "tkhd", sizeOf(bytes, "trak") + 8))
        assertRefused(withSize(bytes, "moov", sizeOf(bytes, "moov") + 1))
    }

    @Test
    fun `a box shorter than its header is refused`() {
        assertRefused(withSize(mp4(), "mvhd", 4))
        assertRefused(withSize(mp4(), "trak", 7))
    }

    @Test
    fun `a size 0 inside a box is refused, since it would never end`() {
        assertRefused(withSize(mp4(), "trak", 0))
        assertRefused(withSize(mp4(), "udta", 0))
    }

    @Test
    fun `a 64-bit size too small or too large is refused`() {
        val bytes = mp4(largeMdat = true)
        assertRefused(withLargeSize(bytes, "mdat", 8))
        assertRefused(withLargeSize(bytes, "mdat", 1L shl 40))
        // 2^64 - 16 as unsigned: past any file.
        assertRefused(withLargeSize(bytes, "mdat", -16L))
    }

    @Test
    fun `not exactly one movie box is refused`() {
        val ftyp = ftyp()
        val mdat = box("mdat", ByteArray(16))
        assertRefused(ftyp + mdat)
        val one = mp4()
        val moov = one.copyOfRange(indexOfType(one, "moov") - 4, one.size)
        assertRefused(one + moov)
    }

    @Test
    fun `a date box of an unknown version or too short is refused`() {
        val bytes = mp4()
        val version = bytes.copyOf().also { it[indexOfType(it, "mvhd") + 4] = 2 }
        assertRefused(version)
        assertRefused(mp4(shortMvhd = true))
    }

    @Test
    fun `a track without its header or its media header is refused`() {
        assertRefused(mp4(tkhdType = "tkhx"))
        assertRefused(mp4(mdhdType = "mdhx"))
    }

    @Test
    fun `nesting deeper than the limit is refused`() {
        var nested = box("udta")
        repeat(Mp4MetadataScrub.MAX_DEPTH + 1) { nested = box("udta", nested) }
        assertRefused(mp4(extraInMoov = nested))
    }

    @Test
    fun `more boxes than the limit are refused`() {
        val many = ByteArray(8 * (Mp4MetadataScrub.MAX_BOXES + 1))
        for (i in 0..Mp4MetadataScrub.MAX_BOXES) {
            u32(8).copyInto(many, i * 8)
            ascii("free").copyInto(many, i * 8 + 4)
        }
        assertRefused(mp4(extraInMoov = many))
    }

    // ---- helpers ----

    /** [input] scrubbed must equal [expected], which it must differ from.
     *  With [tagged], it must also have held the phone's tag that
     *  [expected] no longer holds. */
    private fun assertScrubbedTo(input: ByteArray, expected: ByteArray, tagged: Boolean = true) {
        assertEquals("the oracle must have the input's size", input.size, expected.size)
        assertFalse("the input already equals the expected file", input.contentEquals(expected))
        if (tagged) assertTrue(contains(input, ANDROID_VERSION_KEY))
        val file = write(input)

        Mp4MetadataScrub.scrub(file)

        val out = file.readBytes()
        assertArrayEquals(expected, out)
        assertFalse(contains(out, ANDROID_VERSION_KEY))
    }

    private fun assertRefused(bytes: ByteArray) {
        val file = write(bytes)
        try {
            Mp4MetadataScrub.scrub(file)
            fail("a malformed file must be refused")
        } catch (_: Mp4MetadataScrub.Unexpected) {
        }
        assertArrayEquals("a refused file must not be written", bytes, file.readBytes())
    }

    private fun write(bytes: ByteArray): File = tmp.newFile().apply { writeBytes(bytes) }

    /**
     * An MP4 laid out as the platform muxer writes it: `ftyp`, then `mdat`
     * and `moov` in either order. With [cleared], the dates are 0 and each
     * metadata box is a `free` box of zeros of the same size: what the
     * scrub must make of the same file. [datesCleared] and
     * [metadataCleared] do one half of it, and [movieDatesCleared] and
     * [trackDatesCleared] one part of the dates (the movie header's, or the
     * track and media headers'); without [withMetadata] the movie has no
     * `meta` or `udta`.
     */
    private fun mp4(
        version: Int = 0,
        cleared: Boolean = false,
        datesCleared: Boolean = cleared,
        movieDatesCleared: Boolean = datesCleared,
        trackDatesCleared: Boolean = datesCleared,
        metadataCleared: Boolean = cleared,
        withMetadata: Boolean = true,
        moovFirst: Boolean = false,
        largeMdat: Boolean = false,
        openMdat: Boolean = false,
        largeMeta: Boolean = false,
        trackUdta: Boolean = false,
        shortMvhd: Boolean = false,
        tkhdType: String = "tkhd",
        mdhdType: String = "mdhd",
        extraInMoov: ByteArray = ByteArray(0),
    ): ByteArray {
        fun createdTime(zero: Boolean) = if (zero) 0L else if (version == 0) CREATED_32 else CREATED_64
        fun modifiedTime(zero: Boolean) = if (zero) 0L else if (version == 0) MODIFIED_32 else MODIFIED_64
        val created = createdTime(trackDatesCleared)
        val modified = modifiedTime(trackDatesCleared)
        fun md(box: ByteArray) = if (metadataCleared) asFree(box) else box
        fun movieMd(box: ByteArray) = if (withMetadata) md(box) else ByteArray(0)
        val ftyp = ftyp()
        val mdatHeader = if (largeMdat) 16 else 8
        val mdat = when {
            largeMdat -> largeBox("mdat", SAMPLES)
            openMdat -> cat(u32(0), ascii("mdat"), SAMPLES)
            else -> box("mdat", SAMPLES)
        }
        val androidMeta = if (largeMeta) largeBox("meta", *androidMetaContent()) else box("meta", *androidMetaContent())
        fun trak(id: Int, handler: String, chunkOffset: Long) = box(
            "trak",
            tkhd(version, created, modified, id, tkhdType),
            box(
                "mdia",
                mdhd(version, created, modified, mdhdType),
                hdlr(handler, if (handler == "vide") "VideoHandle" else "SoundHandle"),
                box(
                    "minf",
                    box("stbl", full("stsd", 0, u32(0)), full("stts", 0, u32(0)), full("stco", 0, u32(1), u32(chunkOffset))),
                ),
            ),
            if (trackUdta) md(box("udta", box(LOCATION, ascii("+00.0000+000.0000/")))) else ByteArray(0),
        )
        fun moov(dataAt: Long) = box(
            "moov",
            mvhd(version, createdTime(movieDatesCleared), modifiedTime(movieDatesCleared), short = shortMvhd),
            movieMd(box("udta", androidMeta)),
            trak(1, "vide", dataAt),
            trak(2, "soun", dataAt + SAMPLES.size / 2),
            movieMd(androidMeta),
            extraInMoov,
        )
        return if (moovFirst) {
            val moovSize = moov(0).size
            cat(ftyp, moov(ftyp.size.toLong() + moovSize + mdatHeader), mdat)
        } else {
            cat(ftyp, mdat, moov(ftyp.size.toLong() + mdatHeader))
        }
    }

    private fun ftyp() = box("ftyp", ascii("mp42"), u32(0), ascii("isom"), ascii("mp42"))

    private fun mvhd(version: Int, created: Long, modified: Long, short: Boolean): ByteArray {
        val rest = filler(if (short) 40 else 80)
        return if (version == 0) {
            full("mvhd", 0, u32(created), u32(modified), u32(TIMESCALE), u32(DURATION), rest)
        } else {
            full("mvhd", 1, u64(created), u64(modified), u32(TIMESCALE), u64(DURATION), rest)
        }
    }

    private fun tkhd(version: Int, created: Long, modified: Long, id: Int, type: String) = if (version == 0) {
        full(type, 0, u32(created), u32(modified), u32(id.toLong()), u32(0), u32(DURATION), filler(60))
    } else {
        full(type, 1, u64(created), u64(modified), u32(id.toLong()), u32(0), u64(DURATION), filler(60))
    }

    private fun mdhd(version: Int, created: Long, modified: Long, type: String) = if (version == 0) {
        full(type, 0, u32(created), u32(modified), u32(TIMESCALE), u32(DURATION), LANGUAGE_ENG, ByteArray(2))
    } else {
        full(type, 1, u64(created), u64(modified), u32(TIMESCALE), u64(DURATION), LANGUAGE_ENG, ByteArray(2))
    }

    private fun hdlr(handler: String, name: String) =
        full("hdlr", 0, u32(0), ascii(handler), ByteArray(12), ascii(name), ByteArray(1))

    /** The content of the platform muxer's `meta` box: a handler, the key
     *  `com.android.version`, and its value. */
    private fun androidMetaContent(): Array<ByteArray> = arrayOf(
        hdlr("mdta", ""),
        full("keys", 0, u32(1), box("mdta", ascii(ANDROID_VERSION_KEY))),
        box("ilst", box("\u0000\u0000\u0000\u0001", box("data", u32(1), u32(0), ascii("14")))),
    )

    /** [box] as the scrub leaves it: type `free`, size fields kept, the
     *  rest zeros. */
    private fun asFree(box: ByteArray): ByteArray {
        val headerSize = if (ByteBuffer.wrap(box).getInt(0) == 1) 16 else 8
        return box.copyOf().also {
            ascii("free").copyInto(it, 4)
            it.fill(0, headerSize, it.size)
        }
    }

    /** [bytes] with the 32-bit size of the first box of [type] set to [size]. */
    private fun withSize(bytes: ByteArray, type: String, size: Long): ByteArray =
        bytes.copyOf().also { u32(size).copyInto(it, indexOfType(it, type) - 4) }

    /** [bytes] with the 64-bit size of the first box of [type] set to [size]. */
    private fun withLargeSize(bytes: ByteArray, type: String, size: Long): ByteArray =
        bytes.copyOf().also { u64(size).copyInto(it, indexOfType(it, type) + 4) }

    private fun sizeOf(bytes: ByteArray, type: String): Long =
        ByteBuffer.wrap(bytes).getInt(indexOfType(bytes, type) - 4).toLong()

    private fun indexOfType(bytes: ByteArray, type: String): Int {
        val needle = ascii(type)
        val at = (0..bytes.size - needle.size).firstOrNull { i -> needle.indices.all { bytes[i + it] == needle[it] } }
        return checkNotNull(at) { "no $type box" }
    }

    private fun contains(bytes: ByteArray, text: String): Boolean {
        val needle = ascii(text)
        return (0..bytes.size - needle.size).any { i -> needle.indices.all { bytes[i + it] == needle[it] } }
    }

    private fun box(type: String, vararg content: ByteArray): ByteArray {
        val body = cat(*content)
        return cat(u32(8L + body.size), ascii(type), body)
    }

    private fun largeBox(type: String, vararg content: ByteArray): ByteArray {
        val body = cat(*content)
        return cat(u32(1), ascii(type), u64(16L + body.size), body)
    }

    private fun full(type: String, version: Int, vararg content: ByteArray): ByteArray =
        box(type, byteArrayOf(version.toByte(), 0, 0, 0), *content)

    private fun cat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var at = 0
        for (p in parts) {
            p.copyInto(out, at)
            at += p.size
        }
        return out
    }

    private fun u32(v: Long): ByteArray = ByteBuffer.allocate(4).putInt(v.toInt()).array()
    private fun u64(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()
    private fun ascii(s: String): ByteArray = s.toByteArray(Charsets.ISO_8859_1)

    /** Bytes no scrub writes: a run of distinct values, so a stray write
     *  shows. */
    private fun filler(n: Int) = ByteArray(n) { (it + 1).toByte() }

    private companion object {
        const val ANDROID_VERSION_KEY = "com.android.version"
        const val TIMESCALE = 90_000L
        const val DURATION = 450_000L
        const val CREATED_32 = 0xE3A1_B2C4L
        const val MODIFIED_32 = 0xE3A1_B2C5L
        const val CREATED_64 = 0x0000_0001_E3A1_B2C4L
        const val MODIFIED_64 = 0x0000_0001_E3A1_B2C5L

        /** "eng", packed as the media header stores a language. */
        val LANGUAGE_ENG = byteArrayOf(0x15, 0xC7.toByte())
        val SAMPLES = ByteArray(64) { (it * 7 + 3).toByte() }

        /** The type of a location box, the byte 0xA9 then "xyz", which the
         *  platform muxer writes in a `udta` when given a location. */
        val LOCATION = 0xA9.toChar() + "xyz"
    }
}
