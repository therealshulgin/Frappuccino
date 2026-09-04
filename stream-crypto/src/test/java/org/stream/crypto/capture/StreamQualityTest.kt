package org.stream.crypto.capture

import org.junit.Assert.assertEquals
import org.junit.Test

class StreamQualityTest {

    @Test
    fun downgrade_walks_FHD_HD_SD_then_floor() {
        assertEquals(StreamQuality.HD, StreamQuality.FHD.downgrade())
        assertEquals(StreamQuality.SD, StreamQuality.HD.downgrade())
        assertEquals(StreamQuality.SD, StreamQuality.SD.downgrade())
    }

    @Test
    fun upgrade_walks_SD_HD_FHD_then_ceiling() {
        assertEquals(StreamQuality.HD, StreamQuality.SD.upgrade())
        assertEquals(StreamQuality.FHD, StreamQuality.HD.upgrade())
        assertEquals(StreamQuality.FHD, StreamQuality.FHD.upgrade())
    }

    @Test
    fun displayLabel_matches_resolution() {
        assertEquals("1080p", StreamQuality.FHD.displayLabel)
        assertEquals("720p", StreamQuality.HD.displayLabel)
        assertEquals("480p", StreamQuality.SD.displayLabel)
    }
}
