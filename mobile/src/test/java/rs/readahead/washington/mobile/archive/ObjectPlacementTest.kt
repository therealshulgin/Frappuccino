package rs.readahead.washington.mobile.archive

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.frappuccino.ObjectStatus
import java.io.File
import java.nio.file.Files

/**
 * Where the rescue puts each fetched object. The legacy objects stored
 * without a signature are the witness's only copy of the recordings made
 * before signatures were kept: they must survive the verification, apart
 * from the testimony, never in it. The generated enum is plain Kotlin and
 * loads no native code.
 */
class ObjectPlacementTest {

    private lateinit var root: File
    private lateinit var dir: ReportDir

    @Before
    fun setUp() {
        root = Files.createTempDirectory("placement").toFile()
        dir = ReportDir("t", File(root, "t"))
        for (sub in listOf(dir.incoming, dir.enc, dir.unverifiable, dir.plain)) sub.mkdirs()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun `a verified object is the testimony, a not-verifiable one is kept apart`() {
        assertEquals(Placement.TESTIMONY, ObjectPlacement.of(ObjectStatus.VERIFIED))
        assertEquals(Placement.APART, ObjectPlacement.of(ObjectStatus.UNVERIFIABLE))
    }

    @Test
    fun `every other status is excluded, and only VERIFIED reaches the testimony`() {
        for (status in ObjectStatus.values()) {
            val placement = ObjectPlacement.of(status)
            when (status) {
                ObjectStatus.VERIFIED -> assertEquals(Placement.TESTIMONY, placement)
                ObjectStatus.UNVERIFIABLE -> assertEquals(Placement.APART, placement)
                else -> assertEquals("$status", Placement.DROPPED, placement)
            }
        }
    }

    @Test
    fun `placing a report keeps the not-verifiable objects intact, in their own directory`() {
        val bodies = mapOf(
            "sid_000000.strm" to byteArrayOf(1, 2, 3),
            "sid_000001.strm" to byteArrayOf(4, 5, 6, 7),
            "000002.strm" to byteArrayOf(8),
            "000003.strm" to byteArrayOf(9, 9),
        )
        val statuses = mapOf(
            "sid_000000.strm" to ObjectStatus.UNVERIFIABLE,
            "sid_000001.strm" to ObjectStatus.UNVERIFIABLE,
            "000002.strm" to ObjectStatus.VERIFIED,
            "000003.strm" to ObjectStatus.FOREIGN,
        )
        val progress = ArrayList<Int>()

        val placed = runBlocking {
            ObjectPlacement.placeAll(
                bodies.keys.toList(), dir,
                fetch = { name, landing ->
                    // What ReportCheck.fetch_object does: land the bytes,
                    // classify, delete what is excluded.
                    landing.writeBytes(bodies.getValue(name))
                    val status = statuses.getValue(name)
                    if (status != ObjectStatus.VERIFIED && status != ObjectStatus.UNVERIFIABLE) landing.delete()
                    status
                },
                isActive = { true },
            ) { progress.add(it) }
        }

        assertEquals(listOf(1, 2, 3, 4), progress)
        assertEquals(setOf("sid_000000.strm", "sid_000001.strm"), placed.unverifiable.keys)
        for ((name, file) in placed.unverifiable) {
            assertEquals(dir.unverifiable.absoluteFile, file.parentFile?.absoluteFile)
            assertArrayEquals(name, bodies.getValue(name), file.readBytes())
        }
        assertEquals(setOf("000002.strm"), placed.verified.keys)
        val verified = placed.verified.getValue("000002.strm")
        assertEquals(dir.enc.absoluteFile, verified.parentFile?.absoluteFile)
        assertArrayEquals(bodies.getValue("000002.strm"), verified.readBytes())

        // Never mixed: no not-verifiable object in the testimony, and the
        // excluded one is nowhere.
        assertTrue(placed.verified.keys.none { it in placed.unverifiable.keys })
        assertEquals(1, dir.enc.listFiles()!!.size)
        assertEquals(2, dir.unverifiable.listFiles()!!.size)
        assertEquals(0, dir.incoming.listFiles()!!.size)
    }

    @Test
    fun `a cancelled placement stops before fetching anything more`() {
        var fetched = 0
        var threw = false
        try {
            runBlocking {
                ObjectPlacement.placeAll(
                    listOf("a_000000.strm", "a_000001.strm"), dir,
                    fetch = { _, landing ->
                        fetched++
                        landing.writeBytes(byteArrayOf(1))
                        ObjectStatus.UNVERIFIABLE
                    },
                    isActive = { fetched == 0 },
                ) {}
            }
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            threw = true
        }
        assertTrue(threw)
        assertEquals(1, fetched)
        assertFalse(File(dir.unverifiable, RescueNames.localObjectFileName(1)).exists())
    }
}
