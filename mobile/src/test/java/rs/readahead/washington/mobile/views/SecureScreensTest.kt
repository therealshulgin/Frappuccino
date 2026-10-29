package rs.readahead.washington.mobile.views

import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import rs.readahead.washington.mobile.views.SourceText.MANIFESTS_PROPERTY

/**
 * Every activity of the APK keeps its window out of screenshots, screen
 * recordings and the recents thumbnail, and turns Content Capture off, from
 * `onCreate` on: it extends `BaseActivity`, which does so first thing, or its
 * own `onCreate` calls `refuseScreenCapture()` before it sets its content. An
 * activity that shows nothing is listed in [EXEMPT] with its reason.
 *
 * The instrumented test checks the flag on a running BaseActivity; this one
 * holds the rule for every activity of the manifests Gradle names
 * (mobile/build.gradle), so that deleting the call from one screen fails a test.
 * It reads source text, with comments and the contents of string literals
 * blanked. The call must be a statement of `onCreate` itself: one inside a
 * nested block (a lambda such as `post { }`, an `if`, a `try`) or behind a
 * condition may run late or not at all, and does not count. A call made
 * through a helper is not recognised either and fails the test, the safe way
 * round. Being a reading of the text, it cannot see what the code does at run
 * time.
 */
class SecureScreensTest {

    @Test
    fun every_activity_refuses_screen_capture_in_on_create() {
        val sources = SourceText.sources()
        val activities = SourceText.paths(MANIFESTS_PROPERTY).flatMap { activitiesOf(it.readText()) }
        assertTrue("too few activities found: $activities", activities.size >= 8)
        val used = mutableSetOf<String>()
        val problems = activities.mapNotNull { declared ->
            val source = sourceOf(declared, sources) ?: return@mapNotNull "$declared: no source found"
            when {
                source.className in EXEMPT -> { used += source.className; null }
                extendsBaseActivity(source.className) -> null
                else -> onCreateProblem(codeOnly(source))?.let { "${source.className}: $it" }
            }
        }
        assertEquals("activities that do not refuse screen capture:\n" + problems.joinToString("\n"), emptyList<String>(), problems)
        assertEquals("EXEMPT entries that match no activity", emptySet<String>(), EXEMPT.keys - used)
    }

    @Test
    fun base_activity_refuses_screen_capture_before_anything_else() {
        val base = SourceText.sources().single { it.className == BASE_ACTIVITY }
        assertEquals(null, onCreateProblem(codeOnly(base), before = "super.onCreate("))
    }

    // ---- negative controls ----

    @Test
    fun a_missing_or_late_call_is_reported() {
        val missing = """
            class A : AppCompatActivity() {
                override fun onCreate(savedInstanceState: Bundle?) {
                    super.onCreate(savedInstanceState)
                    setContentView(R.layout.a)
                }
            }
        """
        val late = missing.replace("setContentView(R.layout.a)", "setContentView(R.layout.a)\nrefuseScreenCapture()")
        val commented = missing.replace("super.onCreate(savedInstanceState)", "super.onCreate(savedInstanceState) // refuseScreenCapture()")
        val elsewhere = missing.replace("}\n            }", "}\n                fun x() { refuseScreenCapture() }\n            }")
        for (src in listOf(missing, late, commented, elsewhere)) {
            assertTrue(src, onCreateProblem(SourceText.strip(src, nested = true, strings = true)) != null)
        }
        val good = missing.replace("super.onCreate(savedInstanceState)", "super.onCreate(savedInstanceState)\nrefuseScreenCapture()")
        assertEquals(null, onCreateProblem(SourceText.strip(good, nested = true, strings = true)))
        val java = """
            public class J extends Activity {
                @Override protected void onCreate(Bundle b) {
                    super.onCreate(b);
                    setContentView(R.layout.j);
                }
            }
        """
        assertTrue(onCreateProblem(SourceText.strip(java, nested = false, strings = true)) != null)
        val javaGood = java.replace("super.onCreate(b);", "super.onCreate(b);\nrefuseScreenCapture();")
        assertEquals(null, onCreateProblem(SourceText.strip(javaGood, nested = false, strings = true)))
        assertTrue(onCreateProblem("class N : AppCompatActivity()") != null)
    }

    @Test
    fun a_call_that_may_run_late_or_not_at_all_is_reported() {
        val good = """
            class A : AppCompatActivity() {
                override fun onCreate(savedInstanceState: Bundle?) {
                    super.onCreate(savedInstanceState)
                    refuseScreenCapture()
                    setContentView(R.layout.a)
                }
            }
        """
        assertEquals(null, onCreateProblem(SourceText.strip(good, nested = true, strings = true)))
        val call = "                    refuseScreenCapture()\n"
        val variants = mapOf(
            // Runs after the window is added and Content Capture has started.
            "deferred" to "                    window.decorView.post { refuseScreenCapture() }\n",
            "guarded" to "                    if (!BuildConfig.DEBUG) refuseScreenCapture()\n",
            "guarded, next line" to "                    if (!BuildConfig.DEBUG)\n                        refuseScreenCapture()\n",
            "guarded, in a block" to "                    if (!BuildConfig.DEBUG) {\n                        refuseScreenCapture()\n                    }\n",
            "else branch" to "                    if (x) foo() else refuseScreenCapture()\n",
            "else branch, next line" to "                    if (x) foo() else\n                        refuseScreenCapture()\n",
            "Java else branch, next line" to "                    if (x) foo(); else\n                        refuseScreenCapture();\n",
            "guarded after a statement, next line" to "                    foo(); if (x)\n                        refuseScreenCapture()\n",
            "in a try" to "                    try { refuseScreenCapture() } catch (e: Exception) {}\n",
            "in a string" to "                    Timber.d(\"refuseScreenCapture()\")\n",
            "in a raw string" to "                    Timber.d(\"\"\"refuseScreenCapture()\"\"\")\n",
            // Alone on its line, as a statement would be: only blanking the
            // string's contents tells it apart.
            "on a line of a raw string" to "                    val note = \"\"\"\n                        refuseScreenCapture()\n                    \"\"\"\n",
            "inside parentheses" to "                    run(refuseScreenCapture())\n",
        )
        // Every variant is tried, so that a failure names all the accepted ones.
        val accepted = variants.filter { (what, replacement) ->
            val src = good.replace(call, replacement)
            assertTrue("$what: the variant was not built", src != good)
            onCreateProblem(SourceText.strip(src, nested = true, strings = true)) == null
        }.keys
        assertEquals("variants accepted", emptySet<String>(), accepted)
    }

    @Test
    fun string_contents_are_blanked_and_the_rest_is_kept() {
        val src = "val a = \"x // y\" + \"\${f(\"z\")}\" // c\nval b = 'q'"
        val out = SourceText.strip(src, nested = true, strings = true)
        assertEquals(src.length, out.length)
        assertEquals("val a = \"      \" + \"\${f(\" \")}\"     \nval b = 'q'", out)
        assertEquals("val a = \"x // y\" + \"\${f(\"z\")}\"     \nval b = 'q'", SourceText.strip(src, nested = true))
    }

    @Test
    fun the_manifest_reader_sees_relative_and_full_names() {
        val manifest = """
            <manifest xmlns:android="$ANDROID_NS">
                <application>
                    <activity android:name=".a.One" />
                    <activity android:name="x.y.Two" />
                    <activity-alias android:name=".Alias" android:targetActivity=".a.One" />
                </application>
            </manifest>
        """
        assertEquals(listOf(".a.One", "x.y.Two"), activitiesOf(manifest))
    }

    // ---- reading ----

    private fun activitiesOf(xml: String): List<String> {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val all = factory.newDocumentBuilder().parse(xml.byteInputStream()).getElementsByTagName("activity")
        return (0 until all.length).map { (all.item(it) as Element).getAttributeNS(ANDROID_NS, "name") }
    }

    /**
     * The source of a manifest name. A name starting with a dot is relative to
     * the module's namespace, which the manifest does not carry here (it is in
     * build.gradle): the source whose class name ends with it, if only one does.
     */
    private fun sourceOf(declared: String, sources: List<SourceText.Source>): SourceText.Source? {
        val matches = if (declared.startsWith(".")) {
            sources.filter { it.className.endsWith(declared) }
        } else {
            sources.filter { it.className == declared }
        }
        return matches.singleOrNull()
    }

    private fun extendsBaseActivity(className: String): Boolean {
        val loader = javaClass.classLoader!!
        val base = Class.forName(BASE_ACTIVITY, false, loader)
        return base.isAssignableFrom(Class.forName(className, false, loader))
    }

    /** The source with its comments and the contents of its strings blanked. */
    private fun codeOnly(source: SourceText.Source): String =
        SourceText.strip(source.code, nested = source.file.extension == "kt", strings = true)

    /**
     * Null when the body of `onCreate` calls `refuseScreenCapture()`, as a
     * statement of the body itself, before [before], or before any content is
     * set; otherwise what is wrong. [code] has its comments and the contents
     * of its strings blanked.
     */
    private fun onCreateProblem(code: String, before: String? = null): String? {
        val header = ON_CREATE.find(code) ?: return "no onCreate"
        val open = code.indexOf('{', SourceText.skipBalanced(code, code.indexOf('(', header.range.first), '(', ')'))
        if (open < 0) return "no onCreate body"
        val body = code.substring(open, SourceText.skipBalanced(code, open, '{', '}'))
        val calls = REFUSE.findAll(body).map { it.range.first }.toList()
        if (calls.isEmpty()) return "onCreate does not call refuseScreenCapture()"
        val call = calls.firstOrNull { isStatementOfBody(body, it) }
            ?: return "refuseScreenCapture() is not a statement of onCreate itself (nested block, condition or expression)"
        val limits = listOfNotNull(before?.let { body.indexOf(it) }) + CONTENT.findAll(body).map { it.range.first }
        val first = limits.filter { it >= 0 }.minOrNull() ?: return null
        return if (call < first) null else "refuseScreenCapture() comes after ${body.substring(first).substringBefore('(')}"
    }

    /**
     * Whether a statement of [body] (which starts with its `{`) starts at [at]:
     * no brace or parenthesis is open there but the body's own, and what comes
     * before ends a statement. That is the body's `{` or a `;` on the same
     * line, or a previous line that the next one cannot continue: not a
     * condition waiting for its statement (`if (...)`, `else`, ...) and not a
     * line ending on an operator.
     */
    private fun isStatementOfBody(body: String, at: Int): Boolean {
        var braces = 0
        var parens = 0
        for (i in 0 until at) {
            when (body[i]) {
                '{' -> braces++
                '}' -> braces--
                '(' -> parens++
                ')' -> parens--
            }
        }
        if (braces != 1 || parens != 0) return false
        val before = body.substring(0, at)
        val lineStart = before.lastIndexOf('\n') + 1
        val sameLine = before.substring(lineStart).trim()
        if (sameLine.isNotEmpty()) return sameLine.endsWith(";") || (lineStart == 0 && sameLine == "{")
        val previous = before.substring(0, lineStart).trimEnd().substringAfterLast('\n').trim()
        return !CONTINUED.containsMatchIn(previous)
    }

    private companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
        const val BASE_ACTIVITY = "rs.readahead.washington.mobile.views.base_ui.BaseActivity"

        /** Activities that show nothing, with the reason. */
        val EXEMPT = mapOf(
            "rs.readahead.washington.mobile.views.activity.ExitActivity" to
                "Theme.NoDisplay, no content; finishes and removes its task in onCreate",
        )

        val ON_CREATE = Regex("""(?:\bfun|\bvoid)\s+onCreate\s*\(""")
        val REFUSE = Regex("""\brefuseScreenCapture\s*\(\s*\)""")
        val CONTENT = Regex("""\bsetContent(?:View)?\s*[({]""")

        /** A line the next one continues: a condition or loop header waiting
         *  for its statement (at the start of the line or after a `;`), a
         *  line ending on `else` (alone, after a `}` or after the statement
         *  of an `if`), a `do`, or a line ending on an operator, a dot, a
         *  comma or an opening parenthesis. */
        val CONTINUED = Regex(
            """(?:^|;)\s*(?:\}\s*)?(?:else\s+)?(?:if|while|for)\s*\(.*\)$|\belse$|^do$|(?:[.,(=+\-*/%&|?:]|->)$""",
        )
    }
}
