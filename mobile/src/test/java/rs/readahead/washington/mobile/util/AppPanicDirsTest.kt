package rs.readahead.washington.mobile.util

import org.junit.Assert.assertEquals
import org.stream.crypto.DetachedDirs
import org.junit.Test
import java.io.File

class AppPanicDirsTest {

    @Test
    fun `the parts are concatenated in order and every afterErase runs`() {
        val ran = mutableListOf<String>()
        val combined = AppPanicDirs.combine(
            { DetachedDirs(listOf(File("a-plain")), listOf(File("a-cipher")), afterErase = { ran += "a" }) },
            { DetachedDirs(listOf(File("b-plain")), afterErase = { ran += "b" }) },
        )
        assertEquals(listOf(File("a-plain"), File("b-plain")), combined.plaintext)
        assertEquals(listOf(File("a-cipher")), combined.ciphertext)
        combined.afterErase()
        assertEquals(listOf("a", "b"), ran)
    }

    @Test
    fun `a part that throws does not keep the others from detaching or erasing`() {
        val ran = mutableListOf<String>()
        val combined = AppPanicDirs.combine(
            { throw IllegalStateException("archive failed") },
            { DetachedDirs(listOf(File("diag")), afterErase = { throw IllegalStateException("x") }) },
            { DetachedDirs(listOf(File("other")), afterErase = { ran += "other" }) },
        )
        assertEquals(listOf(File("diag"), File("other")), combined.plaintext)
        combined.afterErase()
        assertEquals(listOf("other"), ran)
    }
}
