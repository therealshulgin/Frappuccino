package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * The slot where the legacy migration publishes its keyring: the emergency
 * wipe destroys it synchronously instead of waiting for the migration's
 * cleanup, a use that would start after that is refused without touching the
 * handle, a call in flight keeps the handle until it returns, and each handle
 * is destroyed exactly once.
 */
class LiveKeyringSlotTest {

    private class Handle {
        val destroyed = AtomicInteger(0)
    }

    private fun slot() = LiveKeyringSlot<Handle> { it.destroyed.incrementAndGet() }

    private fun assertRefused(slot: LiveKeyringSlot<Handle>) {
        val ran = AtomicBoolean(false)
        try {
            slot.withLive { ran.set(true) }
            fail("a use after the handle is gone must be refused")
        } catch (e: LiveKeyringSlot.Closed) {
            // expected
        }
        assertFalse("the block ran with a handle that is gone", ran.get())
    }

    @Test
    fun a_published_handle_is_lent_to_each_use() {
        val slot = slot()
        val handle = Handle()
        assertTrue(slot.publishUnlessWipedSince(handle, StreamUploadManager.wipeGeneration()))
        assertTrue(slot.isLive())
        assertTrue(slot.withLive { it === handle })
        assertEquals(42, slot.withLive { 42 })
        assertEquals(0, handle.destroyed.get())
    }

    @Test
    fun retiring_destroys_the_handle_once_and_refuses_later_uses() {
        val slot = slot()
        val handle = Handle()
        assertTrue(slot.publishUnlessWipedSince(handle, StreamUploadManager.wipeGeneration()))
        slot.retire(handle)
        assertEquals(1, handle.destroyed.get())
        assertFalse(slot.isLive())
        assertRefused(slot)
        slot.retire(handle)
        assertFalse(slot.destroyLive())
        assertEquals(1, handle.destroyed.get())
    }

    @Test
    fun the_wipe_destroys_the_live_handle_without_waiting_for_the_migration() {
        val slot = slot()
        val handle = Handle()
        assertTrue(slot.publishUnlessWipedSince(handle, StreamUploadManager.wipeGeneration()))

        assertTrue(slot.destroyLive())
        assertEquals(1, handle.destroyed.get())
        assertRefused(slot)

        // The migration's own cleanup, and a second wipe, find nothing more
        // to destroy.
        slot.retire(handle)
        assertFalse(slot.destroyLive())
        assertEquals(1, handle.destroyed.get())
    }

    @Test
    fun a_call_in_flight_keeps_the_handle_until_it_returns_and_the_wipe_does_not_wait() {
        val slot = slot()
        val handle = Handle()
        assertTrue(slot.publishUnlessWipedSince(handle, StreamUploadManager.wipeGeneration()))
        val inCall = CountDownLatch(1)
        val release = CountDownLatch(1)
        val destroyedDuringCall = AtomicInteger(-1)
        val migration = Thread {
            slot.withLive {
                inCall.countDown()
                release.await(5, TimeUnit.SECONDS)
                destroyedDuringCall.set(it.destroyed.get())
            }
        }.apply { start() }
        assertTrue(inCall.await(5, TimeUnit.SECONDS))

        // Returns at once, with the call still running.
        assertTrue(slot.destroyLive())
        assertEquals(0, handle.destroyed.get())
        assertRefused(slot)

        release.countDown()
        migration.join(5_000)
        assertFalse(migration.isAlive)
        assertEquals("released under a call in flight", 0, destroyedDuringCall.get())
        assertEquals(1, handle.destroyed.get())
        slot.retire(handle)
        assertEquals(1, handle.destroyed.get())
    }

    @Test
    fun nothing_is_published_once_a_wipe_began() {
        val slot = slot()
        val handle = Handle()
        val gen = StreamUploadManager.wipeGeneration()
        StreamUploadManager.beginWipe()
        assertFalse(slot.publishUnlessWipedSince(handle, gen))
        assertEquals(1, handle.destroyed.get())
        assertFalse(slot.isLive())
        assertRefused(slot)
    }

    @Test
    fun nothing_is_published_after_a_wipe_even_with_a_generation_read_after_it() {
        val slot = slot()
        slot.destroyLive()
        // A migration that started after the wipe began reads the new
        // generation, so the generation check alone lets it through.
        val gen = StreamUploadManager.wipeGeneration()
        val handle = Handle()
        assertFalse(slot.publishUnlessWipedSince(handle, gen))
        assertEquals(1, handle.destroyed.get())
        assertFalse(slot.isLive())
        assertRefused(slot)
    }

    @Test
    fun a_second_handle_is_refused_and_destroyed_and_the_first_stays() {
        val slot = slot()
        val first = Handle()
        val second = Handle()
        val gen = StreamUploadManager.wipeGeneration()
        assertTrue(slot.publishUnlessWipedSince(first, gen))
        assertFalse(slot.publishUnlessWipedSince(second, gen))
        assertEquals(1, second.destroyed.get())
        assertTrue(slot.withLive { it === first })
        // Retiring a handle that is not the published one changes nothing.
        slot.retire(second)
        assertTrue(slot.isLive())
        assertEquals(0, first.destroyed.get())
    }

    @Test
    fun a_destroy_that_throws_does_not_escape_the_wipe() {
        val slot = LiveKeyringSlot<Handle> { throw IllegalStateException("native release failed") }
        assertTrue(slot.publishUnlessWipedSince(Handle(), StreamUploadManager.wipeGeneration()))
        assertTrue(slot.destroyLive())
        assertRefused(slot)
    }
}
