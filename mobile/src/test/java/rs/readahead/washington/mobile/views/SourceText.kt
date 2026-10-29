package rs.readahead.washington.mobile.views

import java.io.File
import org.junit.Assert.assertTrue

/**
 * What [SecretInputLayoutTest] and [SecureScreensTest] share: the files Gradle
 * names for them (mobile/build.gradle), and comment stripping that follows the
 * rules of each language.
 */
internal object SourceText {

    const val RES_DIRS_PROPERTY = "secretInput.resDirs"
    const val SRC_DIRS_PROPERTY = "secretInput.srcDirs"
    const val MANIFESTS_PROPERTY = "secretInput.manifests"

    /** The paths Gradle put in [property]; fails rather than return nothing. */
    fun paths(property: String): List<File> {
        val raw = System.getProperty(property)
            ?: throw AssertionError("system property $property is not set: run this test through Gradle (see mobile/build.gradle)")
        val paths = raw.split(File.pathSeparator).filter { it.isNotBlank() }.map(::File)
        assertTrue("$property names nothing", paths.isNotEmpty())
        for (path in paths) assertTrue("$path from $property does not exist", path.exists())
        return paths
    }

    /** The Gradle module a path belongs to: the directory that holds its `src`. */
    fun moduleOf(path: File): String {
        var dir: File? = path
        while (dir != null && dir.name != "src") dir = dir.parentFile
        return dir?.parentFile?.name ?: throw AssertionError("$path is not under a src directory")
    }

    /** Every `.kt` and `.java` file under the source directories, with its text. */
    fun sources(): List<Source> = paths(SRC_DIRS_PROPERTY).flatMap { dir ->
        dir.walkTopDown().filter { it.extension == "kt" || it.extension == "java" }.map { file ->
            val kotlin = file.extension == "kt"
            Source(file, strip(file.readText(), nested = kotlin))
        }.toList()
    }

    class Source(val file: File, val code: String) {
        val packageName: String = PACKAGE.find(code)?.groupValues?.get(1).orEmpty()
        val className: String get() = (if (packageName.isEmpty()) "" else "$packageName.") + file.nameWithoutExtension
    }

    private val PACKAGE = Regex("""^\s*package\s+([\w.]+)""", RegexOption.MULTILINE)

    /**
     * Blanks out comments, keeping every newline so line numbers hold. Kotlin
     * block comments nest, Java ones do not. Strings are left as they are,
     * unless [strings] is set: then the characters of each literal are blanked
     * too, its quotes and the code of its `${...}` templates kept, so that a
     * name quoted in a string is not taken for code. Strings are tracked in
     * any case, so that a comment marker inside one is not taken for a
     * comment, including in Kotlin templates.
     */
    fun strip(src: String, nested: Boolean, strings: Boolean = false): String {
        val out = StringBuilder(src)
        // Modes: CODE (with its brace depth), STRING, RAW (triple-quoted).
        val modes = ArrayDeque<IntArray>().apply { addLast(intArrayOf(CODE, 0)) }
        var i = 0
        fun blank(from: Int, to: Int) {
            for (k in from until minOf(to, src.length)) if (src[k] != '\n') out.setCharAt(k, ' ')
        }
        while (i < src.length) {
            val mode = modes.last()
            val c = src[i]
            when (mode[0]) {
                CODE -> when {
                    src.startsWith("//", i) -> {
                        val end = src.indexOf('\n', i).let { if (it < 0) src.length else it }
                        blank(i, end)
                        i = end
                    }
                    src.startsWith("/*", i) -> {
                        var depth = 1
                        var k = i + 2
                        while (k < src.length && depth > 0) {
                            when {
                                nested && src.startsWith("/*", k) -> { depth++; k += 2 }
                                src.startsWith("*/", k) -> { depth--; k += 2 }
                                else -> k++
                            }
                        }
                        blank(i, k)
                        i = k
                    }
                    src.startsWith("\"\"\"", i) -> { modes.addLast(intArrayOf(RAW, 0)); i += 3 }
                    c == '"' -> { modes.addLast(intArrayOf(STRING, 0)); i++ }
                    c == '\'' -> {
                        var k = i + 1
                        if (k < src.length && src[k] == '\\') k += 2 else k++
                        while (k < src.length && k < i + 10 && src[k] != '\'') k++
                        i = k + 1
                    }
                    c == '{' -> { mode[1]++; i++ }
                    c == '}' -> {
                        if (mode[1] == 0 && modes.size > 1) modes.removeLast() else mode[1]--
                        i++
                    }
                    else -> i++
                }
                STRING -> when {
                    c == '\\' -> { if (strings) blank(i, i + 2); i += 2 }
                    nested && src.startsWith("\${", i) -> { modes.addLast(intArrayOf(CODE, 0)); i += 2 }
                    c == '"' || c == '\n' -> { modes.removeLast(); i++ }
                    else -> { if (strings) blank(i, i + 1); i++ }
                }
                else -> when {
                    src.startsWith("\"\"\"", i) -> { modes.removeLast(); i += 3 }
                    nested && src.startsWith("\${", i) -> { modes.addLast(intArrayOf(CODE, 0)); i += 2 }
                    else -> { if (strings) blank(i, i + 1); i++ }
                }
            }
        }
        return out.toString()
    }

    /** From an opening [open] at [from], the index just past its matching close. */
    fun skipBalanced(code: String, from: Int, open: Char, close: Char): Int {
        var depth = 0
        var i = from
        while (i < code.length) {
            if (code[i] == open) depth++
            if (code[i] == close && --depth == 0) return i + 1
            i++
        }
        return i
    }

    private const val CODE = 0
    private const val STRING = 1
    private const val RAW = 2
}
