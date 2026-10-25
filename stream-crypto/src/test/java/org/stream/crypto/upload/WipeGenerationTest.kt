package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The guard that keeps a write from outliving an emergency wipe: "check the
 * generation, then write" must be one step with respect to the wipe's start.
 */
class WipeGenerationTest {

    @Test
    fun nothing_runs_once_a_wipe_began() {
        val gen = StreamUploadManager.wipeGeneration()
        assertEquals(42, StreamUploadManager.unlessWipedSince(gen) { 42 })
        StreamUploadManager.beginWipe()
        val ran = AtomicBoolean(false)
        assertNull(StreamUploadManager.unlessWipedSince(gen) { ran.set(true) })
        assertFalse(ran.get())
    }

    @Test
    fun a_wipe_cannot_start_while_a_guarded_write_runs() {
        val gen = StreamUploadManager.wipeGeneration()
        val inBlock = CountDownLatch(1)
        val release = CountDownLatch(1)
        val writer = Thread {
            StreamUploadManager.unlessWipedSince(gen) {
                inBlock.countDown()
                release.await(5, TimeUnit.SECONDS)
            }
        }.apply { start() }
        assertTrue(inBlock.await(5, TimeUnit.SECONDS))

        val wipeStarted = AtomicBoolean(false)
        val wiper = Thread {
            StreamUploadManager.beginWipe()
            wipeStarted.set(true)
        }.apply { start() }
        // The write is still running: the wipe waits for it, so whatever the
        // write leaves is there before the wipe erases or cancels it.
        Thread.sleep(200)
        assertFalse(wipeStarted.get())
        release.countDown()
        writer.join(5_000)
        wiper.join(5_000)
        assertTrue(wipeStarted.get())
        assertTrue(StreamUploadManager.wipeGeneration() != gen)
    }
}
