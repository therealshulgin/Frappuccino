package org.stream.crypto.capture

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger

class CaptureLossLedgerTest {

    @Test
    fun losses_before_the_closure_go_in_the_bulk() {
        val l = CaptureLossLedger()
        assertEquals(0, l.onLoss())
        assertEquals(0, l.onLoss(2))
        assertEquals(3, l.close())
        assertEquals(3, l.total)
    }

    @Test
    fun a_loss_after_the_closure_is_written_on_its_own() {
        val l = CaptureLossLedger()
        l.onLoss()
        assertEquals(1, l.close())
        // A chunk delivered after the bulk write: without this it would be
        // counted on screen and never written to the alerts.
        assertEquals(1, l.onLoss())
        assertEquals(2, l.total)
        assertEquals(0, l.close())
    }

    @Test
    fun a_loss_racing_the_bulk_is_written_exactly_once() {
        repeat(200) {
            val l = CaptureLossLedger()
            val written = AtomicInteger(0)
            val go = CountDownLatch(1)
            val t = Thread {
                go.await()
                written.addAndGet(l.onLoss())
            }
            t.start()
            go.countDown()
            written.addAndGet(l.close())
            t.join()
            assertEquals(1, written.get())
            assertEquals(1, l.total)
        }
    }
}
