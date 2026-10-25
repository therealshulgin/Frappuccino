package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import org.stream.crypto.upload.ReportAlerts.Reason

class ReportAlertsTest {

    @Test
    fun alerts_of_the_same_reason_are_merged() {
        var alerts = emptyList<ReportAlerts.Alert>()
        alerts = ReportAlerts.merge(alerts, 2, 500L, Reason.CAPTURE_LOST, 1_000L)
        alerts = ReportAlerts.merge(alerts, 3, 200L, Reason.CAPTURE_LOST, 2_000L)
        alerts = ReportAlerts.merge(alerts, 1, 0L, Reason.FAILED, 3_000L)
        assertEquals(2, alerts.size)
        val lost = alerts.single { it.reason == Reason.CAPTURE_LOST }
        assertEquals(5, lost.count)
        assertEquals(200L, lost.oldestMs)
        assertEquals(2_000L, lost.recordedAtMs)
        assertEquals(mapOf(Reason.CAPTURE_LOST to 5, Reason.FAILED to 1), ReportAlerts.totals(alerts))
    }

    @Test
    fun an_unknown_date_does_not_hide_a_known_one() {
        var alerts = ReportAlerts.merge(emptyList(), 1, 0L, Reason.INTERRUPTED, 1L)
        alerts = ReportAlerts.merge(alerts, 1, 900L, Reason.INTERRUPTED, 2L)
        assertEquals(900L, alerts.single().oldestMs)
    }

    @Test
    fun nothing_to_add_changes_nothing() {
        val alerts = ReportAlerts.merge(emptyList(), 1, 0L, Reason.FAILED, 1L)
        assertSame(alerts, ReportAlerts.merge(alerts, 0, 0L, Reason.FAILED, 2L))
        assertSame(alerts, ReportAlerts.merge(alerts, -3, 0L, Reason.FAILED, 2L))
    }

    @Test
    fun a_burst_of_one_kind_cannot_push_another_out() {
        var alerts = ReportAlerts.merge(emptyList(), 1, 0L, Reason.CAPTURE_LOST, 1L)
        repeat(100) { alerts = ReportAlerts.merge(alerts, 1, 0L, Reason.FAILED, 2L + it) }
        assertEquals(1, alerts.count { it.reason == Reason.CAPTURE_LOST })
        assertEquals(100, ReportAlerts.totals(alerts)[Reason.FAILED])
    }

    @Test
    fun lost_video_is_counted_apart() {
        var alerts = ReportAlerts.merge(emptyList(), 2, 0L, Reason.CAPTURE_LOST, 1L)
        alerts = ReportAlerts.merge(alerts, 3, 0L, Reason.EXPIRED, 1L)
        alerts = ReportAlerts.merge(alerts, 4, 0L, Reason.MIGRATION_LOST, 1L)
        alerts = ReportAlerts.merge(alerts, 7, 0L, Reason.FAILED, 1L)
        alerts = ReportAlerts.merge(alerts, 1, 0L, Reason.TIMESTAMPS_CANCELLED, 1L)
        assertEquals(9, ReportAlerts.lostTotal(alerts))
    }
}
