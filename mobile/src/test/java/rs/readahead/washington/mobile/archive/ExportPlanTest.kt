package rs.readahead.washington.mobile.archive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExportPlanTest {

    private val sid = "0123456789abcdef0123456789abcdef"

    @Test
    fun `metadata first, then the chunks in seq order under neutral names`() {
        val plan = ExportPlan.plan(listOf("000002.strm", "000000.strm", "000005.strm"), otsMatched = false)
        assertEquals(
            listOf(
                ExportPlan.Item(ExportPlan.Kind.METADATA, "000000.strm", "metadata.json", "application/json"),
                ExportPlan.Item(ExportPlan.Kind.VIDEO, "000002.strm", "part-0001.mp4", "video/mp4"),
                ExportPlan.Item(ExportPlan.Kind.VIDEO, "000005.strm", "part-0002.mp4", "video/mp4"),
            ),
            plan,
        )
    }

    @Test
    fun `the timestamp proof and its salt come only with a match`() {
        val names = listOf("000000.strm", "000001.strm")
        assertFalse(ExportPlan.plan(names, otsMatched = false).any { it.kind == ExportPlan.Kind.OTS_PROOF })
        val matched = ExportPlan.plan(names, otsMatched = true)
        assertEquals(
            listOf(ExportPlan.Kind.METADATA, ExportPlan.Kind.VIDEO, ExportPlan.Kind.OTS_PROOF, ExportPlan.Kind.OTS_SALT),
            matched.map { it.kind },
        )
        assertEquals(listOf("timestamp.ots", "timestamp.otssalt"), matched.takeLast(2).map { it.targetName })
    }

    @Test
    fun `only names the verdict lists as verified can be exported`() {
        // Anything that is not a recording object (a proof name, junk) is
        // never turned into an export item on its own.
        val plan = ExportPlan.plan(listOf("a6c2f8e53532333e878cce6644f0a419", "manifest"), otsMatched = false)
        assertEquals(emptyList<ExportPlan.Item>(), plan)
    }

    @Test
    fun `legacy objects export under the same neutral names, without the session id`() {
        val plan = ExportPlan.plan(listOf("${sid}_000000.strm", "${sid}_000001.strm"), otsMatched = false)
        assertEquals(listOf("metadata.json", "part-0001.mp4"), plan.map { it.targetName })
        for (item in plan) assertFalse(item.targetName.contains(sid))
    }

    @Test
    fun `the not-verifiable objects export their recordings, every name labelled`() {
        val plan = ExportPlan.planUnverifiable(
            listOf("${sid}_000003.strm", "${sid}_000000.strm", "$sid.ots", "${sid}_000001.strm"),
        )
        assertEquals(
            listOf(
                ExportPlan.Item(
                    ExportPlan.Kind.METADATA, "${sid}_000000.strm", "not-verified-metadata.json", "application/json",
                ),
                ExportPlan.Item(ExportPlan.Kind.VIDEO, "${sid}_000001.strm", "not-verified-part-0001.mp4", "video/mp4"),
                ExportPlan.Item(ExportPlan.Kind.VIDEO, "${sid}_000003.strm", "not-verified-part-0002.mp4", "video/mp4"),
            ),
            plan,
        )
        for (item in plan) {
            assertTrue(item.targetName.startsWith(RescueNames.UNVERIFIED_LABEL))
            assertFalse(item.targetName.contains(sid))
        }
    }

    @Test
    fun `the not-verifiable export never carries a timestamp proof or its salt`() {
        val kinds = ExportPlan.planUnverifiable(listOf("${sid}_000000.strm", "${sid}_000001.strm", "$sid.ots"))
            .map { it.kind }
        assertFalse(ExportPlan.Kind.OTS_PROOF in kinds)
        assertFalse(ExportPlan.Kind.OTS_SALT in kinds)
    }

    @Test
    fun `the joined export lists the chunks by seq, the metadata apart, no raw copy unless asked`() {
        val joined = ExportPlan.planJoined(
            listOf("000002.strm", "000000.strm", "000005.strm"), missingSeqs = setOf(3, 4), otsMatched = true,
            includeRaw = false, ordinal = 4,
        )
        assertEquals(4, joined.ordinal)
        assertEquals("metadata.json", joined.metadata?.targetName)
        assertEquals(listOf(2, 5), joined.chunks.map { it.seq })
        assertEquals(setOf(3, 4), joined.missingSeqs)
        assertEquals(listOf("000002.strm", "000005.strm"), joined.chunks.map { it.sourceName })
        assertTrue(joined.chunks.all { it.raw == null })
        // The proof commits to the chunks as recorded: without them, it is
        // not exported, matched or not.
        assertTrue(joined.timestamp.isEmpty())
        assertEquals(3, joined.size)
    }

    @Test
    fun `with the raw chunks, they and the matching proof go to the subfolder`() {
        val names = listOf("000000.strm", "000001.strm", "000002.strm")
        val joined = ExportPlan.planJoined(names, emptySet(), otsMatched = true, includeRaw = true, ordinal = 1)
        assertEquals(listOf("part-0001.mp4", "part-0002.mp4"), joined.chunks.map { it.raw?.targetName })
        assertTrue(joined.chunks.all { it.raw?.inRawFolder == true })
        assertEquals(listOf("timestamp.ots", "timestamp.otssalt"), joined.timestamp.map { it.targetName })
        assertTrue(joined.timestamp.all { it.inRawFolder })
        assertFalse(joined.metadata!!.inRawFolder)

        val unmatched = ExportPlan.planJoined(names, emptySet(), otsMatched = false, includeRaw = true, ordinal = 1)
        assertTrue(unmatched.timestamp.isEmpty())
    }

    @Test
    fun `the two exports never share a folder or a file name`() {
        for (ordinal in listOf(1, 7, 42)) {
            assertNotEquals(RescueNames.exportFolderName(ordinal), RescueNames.exportUnverifiedFolderName(ordinal))
            assertTrue(RescueNames.exportUnverifiedFolderName(ordinal).endsWith(RescueNames.UNVERIFIED_LABEL))
        }
        val names = listOf("000000.strm", "000001.strm", "000002.strm")
        val verified = ExportPlan.plan(names, otsMatched = true).map { it.targetName }.toSet()
        val apart = ExportPlan.planUnverifiable(names).map { it.targetName }.toSet()
        assertTrue(verified.intersect(apart).isEmpty())
    }
}
