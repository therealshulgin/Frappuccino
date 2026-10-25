package org.stream.crypto.upload

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files

/**
 * The migration's move of staged legacy files: the only copy of a file is
 * never a truncated one, at any step.
 */
class LegacyFileMoverTest {

    private lateinit var from: File
    private lateinit var to: File
    private val log = ArrayList<String>()

    private open inner class Recording : LegacyFileMover.Ops {
        override fun delete(file: File) {
            log.add("delete ${file.name}")
            file.delete()
        }
        override fun syncFile(file: File) {
            log.add("syncFile ${file.name}")
        }
        override fun syncDir(dir: File) {
            log.add("syncDir ${dir.name}")
        }
        // rename(2) replaces the target on Android; File.renameTo does not
        // on every host the tests run on.
        override fun replace(from: File, to: File): Boolean {
            if (to.exists()) to.delete()
            return from.renameTo(to)
        }
    }

    @Before
    fun setUp() {
        val root = Files.createTempDirectory("mover").toFile()
        from = File(root, "stream_encrypted").apply { mkdirs() }
        to = File(root, "stream_chunk_queue").apply { mkdirs() }
    }

    @After
    fun tearDown() {
        from.parentFile.deleteRecursively()
    }

    private val name = "0123abcd_000001.strm"
    private val body = ByteArray(4096) { (it % 251).toByte() }

    @Test
    fun the_copy_is_synced_into_place_before_the_source_goes() {
        File(from, name).writeBytes(body)
        // A destination of another size forces the copy path (no rename).
        File(to, name).writeBytes(ByteArray(10))
        LegacyFileMover(Recording()).moveAll(from, to) { true }

        assertArrayEquals(body, File(to, name).readBytes())
        assertFalse(File(from, name).exists())
        assertFalse(File(to, name + EnvelopeQueue.PART_SUFFIX).exists())
        val syncData = log.indexOf("syncFile $name${EnvelopeQueue.PART_SUFFIX}")
        val syncDir = log.indexOf("syncDir ${to.name}")
        val deleteSource = log.indexOf("delete $name")
        assertTrue(log.toString(), syncData in 0 until deleteSource)
        assertTrue(log.toString(), syncDir in 0 until deleteSource)
    }

    @Test
    fun a_copy_that_fails_leaves_the_source_and_no_part() {
        File(from, name).writeBytes(body)
        File(to, name).writeBytes(ByteArray(10))
        val failing = object : Recording() {
            override fun copy(from: File, to: File) {
                FileOutputStream(to).use { it.write(body, 0, 100) }
                throw IOException("no space left")
            }
        }
        try {
            LegacyFileMover(failing).moveAll(from, to) { true }
            throw AssertionError("the move should have failed")
        } catch (e: IOException) {
            // expected
        }
        assertArrayEquals(body, File(from, name).readBytes())
        assertFalse(File(to, name + EnvelopeQueue.PART_SUFFIX).exists())
    }

    @Test
    fun an_empty_source_never_replaces_a_complete_destination() {
        File(from, name).writeBytes(ByteArray(0))
        File(to, name).writeBytes(body)
        LegacyFileMover(Recording()).moveAll(from, to) { true }
        assertArrayEquals(body, File(to, name).readBytes())
        assertFalse(File(from, name).exists())
    }

    @Test
    fun a_plain_rename_when_it_works() {
        File(from, name).writeBytes(body)
        LegacyFileMover(Recording()).moveAll(from, to) { true }
        assertArrayEquals(body, File(to, name).readBytes())
        assertEquals(listOf("syncDir ${to.name}"), log)
    }
}
