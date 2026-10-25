package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RescueNamesTest {

    private val sid = "0123456789abcdef0123456789abcdef"
    private val rid = "a6c2f8e53532333e878cce6644f0a419"

    @Test
    fun `sequence numbers are read from both object families`() {
        assertEquals(0, RescueNames.parseSeq("000000.strm"))
        assertEquals(17, RescueNames.parseSeq("000017.strm"))
        assertEquals(999_999, RescueNames.parseSeq("999999.strm"))
        assertEquals(3, RescueNames.parseSeq("${sid}_000003.strm"))
        assertEquals(0, RescueNames.parseSeq("${sid}_000000.strm"))
    }

    @Test
    fun `other names carry no sequence number`() {
        for (name in listOf(
            "manifest", rid, "$sid.ots", "$sid.fpm", "00001.strm", "0000001.strm",
            "000001.mp4", "000001.strm.part", "../000001.strm", "a/000001.strm", "_000001.strm", "",
        )) {
            assertNull(name, RescueNames.parseSeq(name))
        }
    }

    @Test
    fun `playback keeps chunks only, in seq order, gaps included`() {
        val verified = listOf("000003.strm", "000000.strm", "000010.strm", "000001.strm", rid)
        assertEquals(listOf("000001.strm", "000003.strm", "000010.strm"), RescueNames.playbackOrder(verified))
        assertEquals("000000.strm", RescueNames.metadataName(verified))
    }

    @Test
    fun `legacy playback follows the seq suffix`() {
        val verified = listOf("${sid}_000002.strm", "${sid}_000000.strm", "${sid}_000001.strm", "$sid.ots")
        assertEquals(listOf("${sid}_000001.strm", "${sid}_000002.strm"), RescueNames.playbackOrder(verified))
        assertEquals("${sid}_000000.strm", RescueNames.metadataName(verified))
    }

    @Test
    fun `a legacy session id with underscores keeps its seq`() {
        val old = "ab12cd34_1715000000_9f3e"
        assertEquals(7, RescueNames.parseSeq("${old}_000007.strm"))
        val verified = listOf("${old}_000002.strm", "${old}_000000.strm", "${old}_000001.strm")
        assertEquals(listOf("${old}_000001.strm", "${old}_000002.strm"), RescueNames.playbackOrder(verified))
        assertEquals("${old}_000000.strm", RescueNames.metadataName(verified))
        val json = """{"sessionId":"$old"}""".toByteArray(Charsets.UTF_8)
        assertArrayEquals(old.toByteArray(Charsets.US_ASCII), SessionIdReader.sessionIdBytes(json))
    }

    @Test
    fun `no metadata object, no metadata name`() {
        assertNull(RescueNames.metadataName(listOf("000001.strm")))
        assertEquals(emptyList<String>(), RescueNames.playbackOrder(emptyList()))
    }

    @Test
    fun `local names are positional and carry nothing from the relay`() {
        assertEquals("o000000.bin", RescueNames.localObjectFileName(0))
        assertEquals("o000042.bin", RescueNames.localObjectFileName(42))
        assertNotEquals(RescueNames.localObjectFileName(1), RescueNames.localObjectFileName(2))
    }

    @Test
    fun `every decryption of a chunk gets a plaintext name of its own`() {
        // Erases are aimed at a path and run late: a name shared by two
        // decryptions of the same chunk let the erase of the first destroy
        // the file the second had just written.
        val a = RescueNames.newPlainFileName(7)
        val b = RescueNames.newPlainFileName(7)
        assertNotEquals(a, b)
        for (name in listOf(a, b)) {
            assertTrue(name, Regex("""p000007-[0-9a-f]{32}\.mp4""").matches(name))
            // A direct child of plain/: no separator, nothing from the relay.
            assertFalse(name.contains('/') || name.contains('\\'))
        }
    }

    @Test
    fun `tokens are random lowercase hex of fixed length`() {
        val a = RescueNames.newToken()
        val b = RescueNames.newToken()
        assertEquals(32, a.length)
        assertTrue(a.all { it in '0'..'9' || it in 'a'..'f' })
        assertNotEquals(a, b)
        assertTrue(RescueNames.isToken(a))
        assertFalse(RescueNames.isToken("archive_view"))
        assertFalse(RescueNames.isToken(a.uppercase()))
        assertFalse(RescueNames.isToken(a + "0"))
    }

    @Test
    fun `export names are neutral`() {
        val names = listOf(
            RescueNames.exportFolderName(3),
            RescueNames.exportVideoName(1),
            RescueNames.exportVideoName(12),
            RescueNames.EXPORT_METADATA_NAME,
            RescueNames.EXPORT_OTS_NAME,
            RescueNames.EXPORT_OTS_SALT_NAME,
        )
        assertEquals(listOf("recording-03", "part-0001.mp4", "part-0012.mp4"), names.take(3))
        for (n in names) {
            assertFalse(n, n.contains(rid))
            assertFalse(n, n.contains(sid))
            assertFalse(n, n.contains("frappuccino", ignoreCase = true))
        }
    }

    @Test
    fun `joined videos are named after the report's position only`() {
        val names = listOf(
            RescueNames.exportJoinedVideoName(3, null, maxParts = 40),
            RescueNames.exportJoinedVideoName(3, 1, maxParts = 40),
            RescueNames.exportJoinedVideoName(3, 12, maxParts = 40),
            RescueNames.EXPORT_RAW_FOLDER_NAME,
        )
        assertEquals(listOf("prise-03.mp4", "prise-03-partie-01.mp4", "prise-03-partie-12.mp4"), names.take(3))
        for (n in names) {
            assertFalse(n, n.contains(rid))
            assertFalse(n, n.contains(sid))
        }
    }

    @Test
    fun `sorted by name, the parts of a report stay in recording order`() {
        // A file manager or a shell glob sorts by name: partie-10 must not
        // come before partie-2, nor partie-100 before partie-11.
        for (maxParts in listOf(1, 9, 10, 99, 100, 120, 1_500)) {
            val names = (1..maxParts).map { RescueNames.exportJoinedVideoName(3, it, maxParts) }
            assertEquals("maxParts=$maxParts", names, names.sorted())
        }
        assertEquals("prise-03-partie-07.mp4", RescueNames.exportJoinedVideoName(3, 7, maxParts = 12))
        assertEquals("prise-03-partie-007.mp4", RescueNames.exportJoinedVideoName(3, 7, maxParts = 120))
    }

    @Test
    fun `relay dates are shortened, anything else is shown as is`() {
        assertEquals("2026-05-15 12:34 UTC", RescueNames.displayDate("2026-05-15T12:34:56.123000+00:00"))
        assertEquals("2026-05-15 12:34 UTC", RescueNames.displayDate("2026-05-15T12:34:56Z"))
        assertEquals("2026-05-15 12:34 +02:00", RescueNames.displayDate("2026-05-15T12:34:56+02:00"))
        assertEquals("2026-05-15 12:34", RescueNames.displayDate("2026-05-15T12:34:56"))
        assertEquals("yesterday", RescueNames.displayDate("yesterday"))
    }

    @Test
    fun `the session id is read as bytes from the metadata`() {
        val json = """{"version":1,"sessionId":"$sid","startedAt":"2026-05-15T12:34:00Z"}"""
            .toByteArray(Charsets.UTF_8)
        assertArrayEquals(sid.toByteArray(Charsets.US_ASCII), SessionIdReader.sessionIdBytes(json))
        val spaced = """{ "sessionId" : "$sid" }""".toByteArray(Charsets.UTF_8)
        assertArrayEquals(sid.toByteArray(Charsets.US_ASCII), SessionIdReader.sessionIdBytes(spaced))
    }

    @Test
    fun `a missing or malformed session id gives nothing`() {
        for (json in listOf(
            """{"version":1}""",
            """{"sessionId":42}""",
            """{"sessionId":""}""",
            """{"sessionId":"abc""",
            """{"sessionId":"a\"b"}""",
            """{"sessionId":"a b"}""",
            "",
        )) {
            assertNull(json, SessionIdReader.sessionIdBytes(json.toByteArray(Charsets.UTF_8)))
        }
    }

    @Test
    fun `a key named like the session id inside a value is skipped`() {
        val json = """{"note":"sessionId","sessionId":"$sid"}""".toByteArray(Charsets.UTF_8)
        assertArrayEquals(sid.toByteArray(Charsets.US_ASCII), SessionIdReader.sessionIdBytes(json))
    }
}
