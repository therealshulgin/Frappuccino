package org.stream.crypto.capture

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.stream.crypto.upload.StreamUploadManager
import java.io.File
import java.nio.file.Files

/**
 * The capture scratch left by a process death: taken out of reach at the
 * next process start, under a name the interrupted-wipe sweep resumes.
 */
class CaptureScratchCleanerTest {

    private lateinit var cache: File

    @Before
    fun setUp() {
        cache = Files.createTempDirectory("cache").toFile()
    }

    @After
    fun tearDown() {
        cache.deleteRecursively()
    }

    @Test
    fun the_scratch_left_by_a_dead_process_is_detached_at_startup() {
        val scratch = File(cache, "stream_chunks").apply { mkdirs() }
        File(scratch, "chunk-001.mp4").writeBytes(ByteArray(512) { 7 })
        File(scratch, "chunk-002.mp4").writeBytes(ByteArray(0))
        assertEquals(1, CaptureScratchCleaner.nonEmptyChunkCount(scratch))

        val detached = CaptureScratchCleaner.detachForStartup(cache)
        assertFalse("nothing is left under the usual name", scratch.exists())
        assertTrue(detached!!.name.startsWith("stream_chunks.wipe-"))
        assertTrue(File(detached, "chunk-001.mp4").exists())
        // An interrupted overwrite is finished at the next start.
        assertTrue(StreamUploadManager.wipeableDirNames().contains("stream_chunks"))
    }

    @Test
    fun nothing_to_detach_when_there_is_no_scratch() {
        assertNull(CaptureScratchCleaner.detachForStartup(cache))
        assertEquals(0, CaptureScratchCleaner.nonEmptyChunkCount(File(cache, "stream_chunks")))
    }
}
