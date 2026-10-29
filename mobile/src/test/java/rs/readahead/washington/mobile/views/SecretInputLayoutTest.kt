package rs.readahead.washington.mobile.views

import java.io.DataInputStream
import java.io.File
import java.net.JarURLConnection
import java.net.URL
import java.util.jar.JarFile
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.w3c.dom.Element
import rs.readahead.washington.mobile.views.SourceText.RES_DIRS_PROPERTY
import rs.readahead.washington.mobile.views.SourceText.SRC_DIRS_PROPERTY

/**
 * Every field that takes a secret, the words of the recovery phrase, must keep
 * what is typed in the field, so it is a [SecretEditText], which applies its
 * protections itself (see its KDoc for what they are and what they do not
 * guarantee). The app has no other text field for the keyboard; the few
 * editable views it does have are listed in [EXEMPT_FIELDS], each with its
 * reason.
 *
 * This test holds that rule over every module merged into the APK (Gradle
 * names their directories, see mobile/build.gradle):
 *
 * - Every layout tag is resolved to its class on the unit-test classpath, the
 *   way the inflater would (bare names under `android.widget`,
 *   `android.webkit`, `android.app`, then `android.view`;
 *   `<view class="...">`). A tag that does not resolve fails the test: what
 *   cannot be resolved cannot be checked.
 * - Every subclass of `android.widget.EditText` must be [SecretEditText], or
 *   the exact class listed for that field in [EXEMPT_FIELDS]; the match is on
 *   the fully qualified class, so a field cannot pass by its name. A
 *   SearchView embeds an EditText the layout does not show, and a TextView
 *   that declares an input type or a key listener, directly or through one of
 *   the app's styles, takes keyboard input: both are refused too.
 * - A [SecretEditText] must also keep its protections declared in the layout,
 *   where a reader sees them, and `allowUndo="false"`, which only a layout can
 *   set.
 * - An entry of [EXEMPT_FIELDS] that no longer matches a field fails the test.
 *
 * A text field built in code would escape the layout scan. Two scans look for
 * one: the compiled classes of the app's packages, for a constructor call on
 * any EditText or SearchView class other than [SecretEditText] (this resolves
 * import aliases, type aliases and classes that borrow a name), and the
 * sources, which also refuse what bytecode does not show as a constructor
 * call: reflection and inflation by class name.
 *
 * Without the system properties Gradle sets, the test fails rather than
 * scanning nothing.
 */
class SecretInputLayoutTest {

    @Test
    fun every_text_field_in_the_layouts_is_a_secret_field() {
        val files = layoutFiles()
        assertTrue("too few layouts found: ${files.size}", files.size > 20)
        val result = scan(files.map { it.key to it.file.readText() }, EXEMPT_FIELDS, appStyles())
        assertEquals("unprotected text fields:\n" + result.violations.joinToString("\n"), emptyList<String>(), result.violations)
        // The scan must see the fields it is meant to guard, or it passes on nothing.
        val ids = result.secretFields.map { it.substringAfter('#') }.toSet()
        for (known in listOf("wordInput1", "wordInput2", "wordInput3", "archiveMnemonicInput")) {
            assertTrue("$known not found among the secret fields", known in ids)
        }
        assertEquals("EXEMPT_FIELDS entries that match no field", emptySet<String>(), EXEMPT_FIELDS.keys - result.exemptionsUsed)
    }

    @Test
    fun the_scan_covers_every_module_of_the_apk() {
        val res = SourceText.paths(RES_DIRS_PROPERTY).map(SourceText::moduleOf).toSet()
        val src = SourceText.paths(SRC_DIRS_PROPERTY).map(SourceText::moduleOf).toSet()
        assertTrue("resource modules: $res", res.containsAll(listOf("mobile", "shared-ui")))
        assertTrue("source modules: $src", src.containsAll(listOf("mobile", "shared-ui", "stream-crypto")))
    }

    @Test
    fun the_grid_that_shows_the_phrase_is_hidden_from_non_tool_accessibility_services() {
        val file = layoutFiles().single { it.key == "mobile/layout/fragment_onboard_mnemonic_generate.xml" }
        val grid = elementsOf(file.file.readText()).single { attrsOf(it)["android:id"] == "@+id/wordsGrid" }
        assertEquals("yes", attrsOf(grid)["android:accessibilityDataSensitive"])
    }

    @Test
    fun no_text_field_is_built_in_the_sources() {
        val sources = SourceText.sources()
        assertTrue("too few sources found: ${sources.size}", sources.size > 50)
        val family = fieldFamily(sources.map { it.code })
        // The scan must know the subclasses it is meant to see.
        assertTrue("NoImeEditText not recognised as a text field class", "NoImeEditText" in family)
        val built = sources.flatMap { constructionsIn(it.file.name, it.code, family) }
        assertEquals("text fields built in code:\n" + built.joinToString("\n"), emptyList<String>(), built)
    }

    @Test
    fun no_text_field_is_built_in_the_compiled_classes() {
        val sources = SourceText.sources()
        val packages = sources.map { it.packageName.replace('.', '/') }.filter { it.isNotEmpty() }.toSet()
        val classes = appClasses(sources, packages)
        val seen = classes.map { it.name.substringBeforeLast('/') }.toSet()
        assertEquals("packages with sources but no compiled class found", emptySet<String>(), packages - seen)
        for (known in listOf(SECRET, NO_IME, "org.hzontal.shared_ui.bottomsheet.BottomSheetUtils")) {
            assertTrue("$known not among the scanned classes", classes.any { it.name == known.replace('.', '/') })
        }
        val scan = compiledConstructions(classes)
        assertEquals("classes the scan could not load: ${scan.unresolved}", emptySet<String>(), scan.unresolved)
        assertEquals("text fields built in code:\n" + scan.built.joinToString("\n"), emptyList<String>(), scan.built)
    }

    @Test
    fun the_exempt_sheets_are_shown_by_nothing() {
        // EXEMPT_FIELDS lets two plain EditTexts through because nothing shows
        // their sheets; this holds that reason.
        val callers = SourceText.sources()
            .filter { it.file.name != "BottomSheetUtils.kt" }
            .flatMap { src -> UNSHOWN_SHEETS.findAll(src.code).map { "${src.file.name}: ${it.value}" }.toList() }
        val included = layoutFiles().flatMap { f -> UNSHOWN_SHEETS.findAll(f.file.readText()).map { "${f.key}: ${it.value}" }.toList() }
        assertEquals("an exempt sheet gained a caller: make its field a SecretEditText", emptyList<String>(), callers + included)
    }

    // ---- negative controls: the layout scan ----

    @Test
    fun a_complete_secret_field_passes() {
        assertEquals(emptyList<String>(), scanOne(secretField()).violations)
    }

    @Test
    fun each_wrong_or_missing_protection_is_reported() {
        val wrong = listOf(
            "android:saveEnabled" to "true",
            "android:importantForAutofill" to "yes",
            "android:imeOptions" to "actionDone",
            "android:inputType" to "textVisiblePassword",
            "android:inputType" to "textNoSuggestions",
            "android:inputType" to "textNoSuggestions|text",
            "android:allowUndo" to "true",
        )
        for ((attr, value) in wrong) {
            val violations = scanOne(secretField(FULL + (attr to value))).violations
            assertEquals("$attr=\"$value\" must be reported: $violations", 1, violations.size)
            assertTrue(violations.single(), violations.single().contains(attr.substringAfter(':')))
        }
        for (attr in FULL.keys) {
            val violations = scanOne(secretField(FULL - attr)).violations
            assertEquals("missing $attr must be reported: $violations", 1, violations.size)
            assertTrue(violations.single(), violations.single().contains(attr.substringAfter(':')))
        }
    }

    @Test
    fun an_editable_field_of_any_other_class_is_reported() {
        // Bare tags: no input type for the TextView rule to catch instead.
        for (tag in listOf(
            "EditText",
            "AutoCompleteTextView",
            "MultiAutoCompleteTextView",
            "android.widget.EditText",
            "androidx.appcompat.widget.AppCompatEditText",
            "androidx.appcompat.widget.AppCompatAutoCompleteTextView",
            "com.google.android.material.textfield.TextInputEditText",
        )) {
            for (attrs in listOf("", attributes(FULL))) {
                val violations = scanOne("""<$tag android:id="@+id/f" $attrs />""").violations
                assertEquals("<$tag $attrs> must be reported: $violations", 1, violations.size)
                assertTrue(violations.single(), violations.single().contains("is an EditText"))
            }
        }
        val generic = scanOne("""<view class="android.widget.EditText" android:id="@+id/f" />""").violations
        assertEquals("<view class=EditText> must be reported: $generic", 1, generic.size)
        assertTrue(generic.single().contains("is an EditText"))
    }

    @Test
    fun a_name_that_only_looks_right_is_not_enough() {
        // Same simple name, another package, and the class exists: it is
        // reported as the EditText it is.
        val impostor = scanOne("""<$IMPOSTOR android:id="@+id/f" ${attributes(FULL)} />""").violations
        assertEquals("the impostor must be reported: $impostor", 1, impostor.size)
        assertTrue(impostor.single(), impostor.single().contains("$IMPOSTOR is an EditText"))
        // And a tag that does not resolve at all is reported as such.
        val fake = scanOne("""<com.example.SecretEditText android:id="@+id/f" ${attributes(FULL)} />""").violations
        assertEquals("an unresolvable tag must be reported: $fake", 1, fake.size)
        assertTrue(fake.single().contains("does not resolve"))
    }

    @Test
    fun hidden_editors_are_reported() {
        for (tag in listOf("SearchView", "androidx.appcompat.widget.SearchView")) {
            val violations = scanOne("""<$tag android:id="@+id/s" />""").violations
            assertEquals(1, violations.size)
            assertTrue(violations.single(), violations.single().contains("embeds a text field"))
        }
        for (attr in listOf(
            "android:inputType=\"text\"",
            "android:editable=\"true\"",
            "android:digits=\"0123\"",
            "android:numeric=\"integer\"",
            "android:phoneNumber=\"true\"",
            "android:autoText=\"true\"",
            "android:capitalize=\"none\"",
            "android:inputMethod=\"android.text.method.TextKeyListener\"",
        )) {
            val violations = scanOne("""<TextView android:id="@+id/t" $attr />""").violations
            assertEquals("<TextView $attr> must be reported: $violations", 1, violations.size)
            assertTrue(violations.single(), violations.single().contains("takes keyboard input"))
        }
        for (attr in listOf("android:inputType=\"none\"", "android:text=\"x\"", "android:autoText=\"false\"", "android:editable=\"false\"")) {
            assertEquals(attr, 0, scanOne("""<TextView android:id="@+id/t" $attr />""").violations.size)
        }
    }

    @Test
    fun an_input_type_from_a_style_is_reported() {
        val styles = mapOf(
            "Pwd" to Style(null, mapOf("android:inputType" to "numberPassword")),
            "Child" to Style("@style/Pwd", emptyMap()),
            "Pwd.Dotted" to Style(null, emptyMap()),
            "Plain" to Style("@android:style/Widget.TextView", mapOf("android:textSize" to "12sp")),
        )
        for (style in listOf("Pwd", "Child", "Pwd.Dotted")) {
            val violations = scanOne("""<TextView android:id="@+id/t" style="@style/$style" />""", styles).violations
            assertEquals("style $style must be reported: $violations", 1, violations.size)
            assertTrue(violations.single().contains("takes keyboard input"))
        }
        assertEquals(0, scanOne("""<TextView android:id="@+id/t" style="@style/Plain" />""", styles).violations.size)
    }

    @Test
    fun the_pin_dots_pass_only_where_they_are_listed() {
        val key = "test/layout/control.xml#dots"
        val dots = """<$NO_IME android:id="@+id/dots" />"""
        val listed = scan(listOf("test/layout/control.xml" to layout(dots)), mapOf(key to Exempt(NO_IME, "control")))
        assertEquals(emptyList<String>(), listed.violations)
        assertEquals(setOf(key), listed.exemptionsUsed)
        // The same class anywhere else is an EditText like any other.
        val elsewhere = scanOne(dots).violations
        assertEquals(1, elsewhere.size)
        assertTrue(elsewhere.single().contains("is an EditText"))
        // An entry names its class: another class at that field is not exempt.
        val swapped = scan(listOf("test/layout/control.xml" to layout("""<EditText android:id="@+id/dots" />""")), mapOf(key to Exempt(NO_IME, "control")))
        assertEquals(1, swapped.violations.size)
        assertEquals(emptySet<String>(), swapped.exemptionsUsed)
        // An entry that matches nothing is visible.
        val unused = scan(listOf("test/layout/control.xml" to layout("<View />")), mapOf(key to Exempt(NO_IME, "control")))
        assertEquals(emptySet<String>(), unused.exemptionsUsed)
    }

    @Test
    fun the_scans_fail_without_the_paths_from_gradle() {
        for (property in listOf(RES_DIRS_PROPERTY, SRC_DIRS_PROPERTY)) {
            val saved = System.getProperty(property)
            System.clearProperty(property)
            try {
                SourceText.paths(property)
                fail("$property: the scan ran without its directories")
            } catch (expected: AssertionError) {
                assertTrue(expected.message.orEmpty().contains(property))
            } finally {
                if (saved != null) System.setProperty(property, saved)
            }
        }
    }

    // ---- negative controls: the source scan ----

    @Test
    fun a_field_built_in_code_is_reported() {
        val src = """
            fun ask(c: Context) {
                val a = EditText(c)
                val b = android.widget.EditText(c)
                val c2 = maybe ?: AppCompatEditText(c)
                val d = object : AutoCompleteTextView(c) {}
                val e = listOf(c).map(::EditText)
                val ok = SecretEditText(c)
            }
        """
        assertEquals(5, kotlin(src).size)
    }

    @Test
    fun what_the_bytecode_does_not_show_is_reported_in_the_source() {
        for (src in listOf(
            "import android.widget.EditText as Box",
            "typealias Box = android.widget.EditText",
            "typealias Box<T> = EditText",
            "val v = AppCompatDelegate.create(a, null).createView(null, \"EditText\", c, attrs)",
            "val v = Class.forName(\"android.widget.EditText\")",
            "val v = EditText::class.java.getConstructor(Context::class.java).newInstance(c)",
        )) {
            assertEquals(src, 1, kotlin(src).size)
        }
        assertEquals(1, java("Object v = EditText.class.getConstructor(Context.class).newInstance(c);").size)
        assertEquals(0, kotlin("val v = \"an EditText\"; val w = SecretEditText::class.java").size)
    }

    @Test
    fun a_class_header_is_exempt_but_its_construction_is_not() {
        val src = """
            class Dots @JvmOverloads constructor(
                context: Context,
                attrs: AttributeSet? = null,
            ) : androidx.appcompat.widget.AppCompatEditText(context, attrs), Marker {
                override fun x() = Unit
            }
            class Deeper(c: Context) : Dots(c)
            class NoPrimary : Deeper {
                constructor(c: Context) : super(c)
            }
            fun build(c: Context) = Deeper(c)
            fun build2(c: Context) = NoPrimary(c)
        """
        val family = fieldFamily(listOf(SourceText.strip(src, nested = true)))
        assertTrue(family.containsAll(listOf("Dots", "Deeper", "NoPrimary")))
        val built = kotlin(src)
        assertEquals(built.toString(), 2, built.size)
        assertTrue(built[0].endsWith("= Deeper(c)") && built[1].endsWith("= NoPrimary(c)"))
    }

    @Test
    fun comments_are_stripped_with_the_rules_of_each_language() {
        // Kotlin nests block comments: all of this is one comment.
        assertEquals(0, kotlin("/* outer /* inner */ val e = EditText(c) */").size)
        // Java does not: the comment ends at the first close, the field is code.
        assertEquals(1, java("/* outer /* inner */ EditText e = new EditText(c);").size)
        assertEquals(0, kotlin("// val e = EditText(c)").size)
        // A comment opener inside a string is not a comment.
        assertEquals(1, kotlin("val s = \"/*\"; val e = EditText(c) // */").size)
        assertEquals(1, kotlin("val s = \"\${\"/*\"}\"; val e = EditText(c) // */").size)
        assertEquals(1, kotlin("val s = \"\"\"/*\"\"\"; val e = EditText(c) // */").size)
        assertEquals(1, kotlin("val q = '\"'; val e = EditText(c) // \"").size)
    }

    // ---- negative controls: the bytecode scan ----

    @Test
    fun the_bytecode_scan_sees_what_simple_names_hide() {
        // secretfixtures/Bypasses.kt, compiled with the tests.
        val url = loader.getResource("$FIXTURES/ByImportAlias.class") ?: throw AssertionError("fixtures not compiled")
        val dir = File(url.toURI()).parentFile
        val classes = dir.listFiles { f -> f.extension == "class" }!!.map { ClassFile.read(it.readBytes()) }
        val scan = compiledConstructions(classes)
        assertEquals(emptySet<String>(), scan.unresolved)
        val builders = scan.built.map { it.substringBefore(" constructs ") }.toSet()
        val expected = listOf("ByImportAlias", "ByTypeAlias", "ByImpostor", "ByAnonymousSubclass", "ByConstructorReference")
            .map { "${FIXTURES.replace('/', '.')}.$it" }.toSet()
        assertEquals(scan.built.joinToString("\n"), expected, builders)
        // The impostor's own call to its superclass constructor is not a field
        // being built; its construction elsewhere is.
        assertTrue(scan.built.none { it.startsWith("$IMPOSTOR constructs") })
    }

    // ---- the layout scan ----

    private class LayoutFile(val key: String, val file: File)

    private class ScanResult(
        val violations: List<String>,
        val secretFields: List<String>,
        val exemptionsUsed: Set<String>,
    )

    /** An editable view allowed at one field: its exact class, and why. */
    private class Exempt(val cls: String, val reason: String)

    private class Style(val parent: String?, val items: Map<String, String>)

    private fun layoutFiles(): List<LayoutFile> = SourceText.paths(RES_DIRS_PROPERTY).flatMap { res ->
        val module = SourceText.moduleOf(res)
        res.listFiles { f -> f.isDirectory && f.name.startsWith("layout") }!!.flatMap { dir ->
            dir.listFiles { f -> f.extension == "xml" }!!.map { LayoutFile("$module/${dir.name}/${it.name}", it) }
        }
    }

    /** Every `<style>` of the app's values directories, by name. */
    private fun appStyles(): Map<String, Style> = SourceText.paths(RES_DIRS_PROPERTY)
        .flatMap { res -> res.listFiles { f -> f.isDirectory && f.name.startsWith("values") }!!.toList() }
        .flatMap { dir -> dir.listFiles { f -> f.extension == "xml" }!!.toList() }
        .flatMap { file -> elementsOf(file.readText()).filter { it.tagName == "style" } }
        .associate { style ->
            val items = (0 until style.childNodes.length).map { style.childNodes.item(it) }
                .filterIsInstance<Element>().filter { it.tagName == "item" }
                .associate { it.getAttribute("name") to it.textContent.trim() }
            style.getAttribute("name") to Style(style.getAttribute("parent").takeIf { style.hasAttribute("parent") }, items)
        }

    private fun scan(
        layouts: List<Pair<String, String>>,
        exempt: Map<String, Exempt>,
        styles: Map<String, Style> = emptyMap(),
    ): ScanResult {
        val violations = mutableListOf<String>()
        val secret = mutableListOf<String>()
        val used = mutableSetOf<String>()
        for ((file, xml) in layouts) {
            for (e in elementsOf(xml)) {
                val tag = e.tagName
                if (tag in NON_VIEW_TAGS) continue
                val attrs = attrsOf(e)
                val key = "$file#${attrs["android:id"]?.substringAfter('/') ?: "<no id>"}"
                val cls = resolve(if (tag == "view") e.getAttribute("class") else tag)
                if (cls == null) {
                    violations += "$key: <$tag> does not resolve to a class on the unit-test classpath"
                    continue
                }
                val problem = when {
                    EDIT_TEXT.isAssignableFrom(cls) -> if (cls.name == SECRET) {
                        secret += key
                        violations += protectionViolations(key, attrs)
                        null
                    } else {
                        "${cls.name} is an EditText: use $SECRET"
                    }
                    SEARCH_VIEWS.any { it.isAssignableFrom(cls) } ->
                        "${cls.name} embeds a text field this scan cannot check"
                    TEXT_VIEW.isAssignableFrom(cls) && (takesInput(attrs) || styleTakesInput(attrs["style"], styles)) ->
                        "${cls.name} declares an input type or a key listener, so it takes keyboard input: use $SECRET"
                    else -> null
                }
                if (problem != null) {
                    if (exempt[key]?.cls == cls.name) used += key else violations += "$key: $problem"
                }
            }
        }
        return ScanResult(violations, secret, used)
    }

    private fun protectionViolations(key: String, attrs: Map<String, String>): List<String> {
        val out = mutableListOf<String>()
        val input = flags(attrs["android:inputType"])
        if ("textNoSuggestions" !in input || "textVisiblePassword" !in input) {
            out += "$key: inputType must include textNoSuggestions and textVisiblePassword"
        }
        if ("flagNoPersonalizedLearning" !in flags(attrs["android:imeOptions"])) {
            out += "$key: imeOptions must include flagNoPersonalizedLearning"
        }
        if (attrs["android:saveEnabled"] != "false") {
            out += "$key: saveEnabled must be false"
        }
        if (attrs["android:importantForAutofill"] !in setOf("no", "noExcludeDescendants")) {
            out += "$key: importantForAutofill must be no or noExcludeDescendants"
        }
        if (attrs["android:allowUndo"] != "false") {
            out += "$key: allowUndo must be false"
        }
        return out
    }

    /**
     * The attributes with which TextView's constructor makes a view editable:
     * an input type, or one of the older attributes that install a key
     * listener (`autoText` and `phoneNumber` only when true; `capitalize`, even
     * "none", whenever present).
     */
    private fun takesInput(attrs: Map<String, String>): Boolean {
        val input = attrs["android:inputType"]
        return (input != null && input != "none") ||
            attrs["android:editable"] == "true" ||
            attrs["android:autoText"] == "true" ||
            attrs["android:phoneNumber"] == "true" ||
            KEY_LISTENER_ATTRS.any { it in attrs }
    }

    /**
     * Follows a `@style/` reference of the app through its parents, explicit
     * or implied by a dotted name. A style of the platform or of a library is
     * not read: the chain stops there.
     */
    private fun styleTakesInput(ref: String?, styles: Map<String, Style>): Boolean {
        var name: String? = ref?.takeIf { it.startsWith("@style/") }?.removePrefix("@style/")
        val seen = mutableSetOf<String>()
        while (name != null && seen.add(name)) {
            val style = styles[name] ?: return false
            if (takesInput(style.items)) return true
            val parent = style.parent
            name = when {
                parent == null -> if ('.' in name) name.substringBeforeLast('.') else null
                parent.isEmpty() || parent.contains("android:") -> null
                else -> parent.removePrefix("@style/").removePrefix("style/")
            }
        }
        return false
    }

    private fun flags(value: String?) = value.orEmpty().split('|').map { it.trim() }.toSet()

    private fun resolve(name: String): Class<*>? {
        if (name.isBlank()) return null
        val candidates = if ('.' in name) listOf(name) else BARE_PREFIXES.map { it + name }
        for (candidate in candidates) {
            load(candidate)?.let { return it }
        }
        return null
    }

    private fun load(name: String): Class<*>? = try {
        Class.forName(name, false, loader)
    } catch (_: ClassNotFoundException) {
        null
    } catch (_: LinkageError) {
        null
    }

    private fun elementsOf(xml: String): List<Element> {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val doc = factory.newDocumentBuilder().parse(xml.byteInputStream())
        val all = doc.getElementsByTagName("*")
        return (0 until all.length).map { all.item(it) as Element }
    }

    private fun attrsOf(e: Element): Map<String, String> =
        (0 until e.attributes.length).associate { i ->
            val a = e.attributes.item(i)
            val prefix = if (a.namespaceURI == ANDROID_NS) "android:" else ""
            "$prefix${a.localName ?: a.nodeName}" to a.nodeValue
        }

    private fun scanOne(body: String, styles: Map<String, Style> = emptyMap()) =
        scan(listOf("test/layout/control.xml" to layout(body)), emptyMap(), styles)

    private fun layout(body: String) =
        """<LinearLayout xmlns:android="$ANDROID_NS">$body</LinearLayout>"""

    private fun attributes(attrs: Map<String, String>) =
        attrs.entries.joinToString(" ") { "${it.key}=\"${it.value}\"" }

    private fun secretField(attrs: Map<String, String> = FULL) =
        """<$SECRET android:id="@+id/f" ${attributes(attrs)} />"""

    // ---- the source scan ----

    private fun kotlin(src: String) = sourceScan("Control.kt", src, nested = true)

    private fun java(src: String) = sourceScan("Control.java", src, nested = false)

    private fun sourceScan(name: String, src: String, nested: Boolean): List<String> {
        val code = SourceText.strip(src, nested)
        return constructionsIn(name, code, fieldFamily(listOf(code)))
    }

    /**
     * The EditText-family simple names, plus every class the sources declare
     * on top of one of them (to a fixed point), minus [SecretEditText].
     */
    private fun fieldFamily(codes: List<String>): Set<String> {
        val family = BASE_FAMILY.toMutableSet()
        val declared = codes.flatMap { declaredSupertypes(it) }
        while (true) {
            val more = declared.filter { (cls, supers) -> cls !in family && supers.any { it in family } }
            if (more.isEmpty()) break
            family += more.map { it.first }
        }
        return family - SECRET.substringAfterLast('.')
    }

    /** (class, simple names of its supertypes) for each class header. */
    private fun declaredSupertypes(code: String): List<Pair<String, List<String>>> {
        val java = JAVA_EXTENDS.findAll(code).map { it.groupValues[1] to listOf(it.groupValues[2].substringAfterLast('.')) }
        val kotlin = CLASS_HEADER.findAll(code).mapNotNull { m ->
            val supers = supertypes(code, m.range.last + 1)
            if (supers.isEmpty()) null else m.groupValues[1] to supers.map { it.name }
        }
        return (java + kotlin).toList()
    }

    /**
     * Constructions of a family class by its simple name, plus what the
     * bytecode scan cannot see or resolve: an import alias or a type alias of
     * a family class (the bytecode scan resolves them, this keeps them out of
     * the sources too), a string that names one (reflection, inflation by
     * name), and a class literal of one (reflection).
     */
    private fun constructionsIn(file: String, code: String, family: Set<String>): List<String> {
        // Neither the name a class header declares (`class Dots(...)`) nor the
        // supertype call of that header is a field being built; the class
        // itself joins the family and its own construction is caught.
        val exempt = CLASS_HEADER.findAll(code)
            .flatMap { m ->
                supertypes(code, m.range.last + 1).filter { it.isCall }.map { it.offset } +
                    m.groups[1]!!.range.first
            }
            .toSet()
        val names = family.joinToString("|")
        val constructions = Regex("""(?:\b($names)\s*\(|::\s*($names)\b)""").findAll(code)
            .filter { m -> m.groups[1] == null || m.groups[1]!!.range.first !in exempt }
        val tripwires = listOf(
            Regex("""\bimport\s+[\w.]*\b($names)\s+as\s+\w+"""),
            Regex("""\btypealias\s+\w+(?:\s*<[^>]*>)?\s*=\s*[\w.]*\b($names)\b"""),
            Regex("\"(?:\\w+\\.)*($names)\""),
            Regex("""\b($names)\s*(?:::\s*class|\.\s*class)\b"""),
        ).flatMap { it.findAll(code).toList() }
        return (constructions + tripwires).sortedBy { it.range.first }.map { m ->
            val line = code.substring(0, m.range.first).count { it == '\n' } + 1
            "$file:$line: ${code.lines()[line - 1].trim()}"
        }.toList()
    }

    private class Supertype(val offset: Int, val name: String, val isCall: Boolean)

    /**
     * Reads a Kotlin class header from [start], just after `class Name`: type
     * parameters, modifiers, annotations and the primary constructor, then the
     * supertype list after a top-level `:`. Returns each supertype with the
     * offset of its simple name, and whether it is written as a constructor
     * call. Anything that is not a class header returns nothing.
     */
    private fun supertypes(code: String, start: Int): List<Supertype> {
        var i = skipSpace(code, start)
        if (i < code.length && code[i] == '<') i = SourceText.skipBalanced(code, i, '<', '>')
        while (true) {
            i = skipSpace(code, i)
            if (i >= code.length) return emptyList()
            when {
                code[i] == '@' -> {
                    i = skipName(code, i + 1)
                    if (i < code.length && code[i] == '(') i = SourceText.skipBalanced(code, i, '(', ')')
                }
                code[i].isLetter() -> {
                    val end = skipName(code, i)
                    if (code.substring(i, end) !in HEADER_WORDS) return emptyList()
                    i = end
                }
                code[i] == '(' -> i = SourceText.skipBalanced(code, i, '(', ')')
                else -> break
            }
        }
        if (code[i] != ':') return emptyList()
        val found = mutableListOf<Supertype>()
        i++
        while (true) {
            i = skipSpace(code, i)
            val nameStart = i
            i = skipName(code, i)
            if (i == nameStart) return found
            val qualified = code.substring(nameStart, i)
            val simple = qualified.substringAfterLast('.')
            val offset = nameStart + qualified.length - simple.length
            i = skipSpace(code, i)
            if (i < code.length && code[i] == '<') i = skipSpace(code, SourceText.skipBalanced(code, i, '<', '>'))
            val isCall = i < code.length && code[i] == '('
            if (isCall) i = skipSpace(code, SourceText.skipBalanced(code, i, '(', ')'))
            found += Supertype(offset, simple, isCall)
            if (i < code.length && code[i] == ',') i++ else return found
        }
    }

    private fun skipSpace(code: String, from: Int): Int {
        var i = from
        while (i < code.length && code[i].isWhitespace()) i++
        return i
    }

    private fun skipName(code: String, from: Int): Int {
        var i = from
        while (i < code.length && (code[i].isLetterOrDigit() || code[i] == '_' || code[i] == '.')) i++
        return i
    }

    // ---- the bytecode scan ----

    /**
     * What a class file says about constructors: its name, its superclass, and
     * the owner of every `<init>` method it references. Constructing an object
     * always references the constructor of its exact class, whatever name the
     * source used for it.
     */
    private class ClassFile(val name: String, val superName: String?, val constructed: Set<String>) {
        companion object {
            fun read(bytes: ByteArray): ClassFile {
                val input = DataInputStream(bytes.inputStream())
                check(input.readInt() == 0xCAFEBABE.toInt()) { "not a class file" }
                input.readUnsignedShort()
                input.readUnsignedShort()
                val count = input.readUnsignedShort()
                val utf8 = arrayOfNulls<String>(count)
                val classNameIndex = IntArray(count)
                val refClass = IntArray(count)
                val refNameAndType = IntArray(count)
                val nameIndex = IntArray(count)
                val methodRefs = mutableListOf<Int>()
                var i = 1
                while (i < count) {
                    when (val tag = input.readUnsignedByte()) {
                        1 -> utf8[i] = input.readUTF()
                        3, 4 -> input.readInt()
                        5, 6 -> { input.readLong(); i++ }
                        7 -> classNameIndex[i] = input.readUnsignedShort()
                        8, 16, 19, 20 -> input.readUnsignedShort()
                        9, 10, 11 -> {
                            refClass[i] = input.readUnsignedShort()
                            refNameAndType[i] = input.readUnsignedShort()
                            if (tag == 10) methodRefs += i
                        }
                        12 -> { nameIndex[i] = input.readUnsignedShort(); input.readUnsignedShort() }
                        15 -> { input.readUnsignedByte(); input.readUnsignedShort() }
                        17, 18 -> { input.readUnsignedShort(); input.readUnsignedShort() }
                        else -> error("unknown constant pool tag $tag")
                    }
                    i++
                }
                input.readUnsignedShort()
                val name = utf8[classNameIndex[input.readUnsignedShort()]]!!
                val superIndex = input.readUnsignedShort()
                val superName = if (superIndex == 0) null else utf8[classNameIndex[superIndex]]
                val constructed = methodRefs
                    .filter { utf8[nameIndex[refNameAndType[it]]] == "<init>" }
                    .map { utf8[classNameIndex[refClass[it]]]!! }
                    .toSet()
                return ClassFile(name, superName, constructed)
            }
        }
    }

    private class CompiledScan(val built: List<String>, val unresolved: Set<String>)

    /**
     * A reference to the constructor of an EditText or SearchView class, other
     * than [SecretEditText], is a field built in code; except a class's call to
     * its own constructors or to its superclass's, which is how a subclass is
     * declared (a construction of that subclass is then caught where it is
     * made). The source scan also sees one made inside such a class.
     */
    private fun compiledConstructions(classes: List<ClassFile>): CompiledScan {
        val built = mutableListOf<String>()
        val unresolved = mutableSetOf<String>()
        for (k in classes) {
            for (owner in k.constructed) {
                if (owner == k.name || owner == k.superName || owner == SECRET.replace('.', '/')) continue
                if (owner.startsWith("[")) continue
                val cls = load(owner.replace('/', '.'))
                if (cls == null) {
                    unresolved += owner
                    continue
                }
                if (EDIT_TEXT.isAssignableFrom(cls) || SEARCH_VIEWS.any { it.isAssignableFrom(cls) }) {
                    built += "${k.name.replace('/', '.')} constructs ${cls.name}"
                }
            }
        }
        return CompiledScan(built.sorted(), unresolved)
    }

    /**
     * The compiled classes of the app's own packages, from the class
     * directories and jars of the unit-test classpath that hold them (the
     * tests' own output excluded). Each root is found from a class the
     * sources declare, then read whole and filtered by package.
     */
    private fun appClasses(sources: List<SourceText.Source>, packages: Set<String>): List<ClassFile> {
        val testRoot = rootOf(classResource(SecretInputLayoutTest::class.java.name))!!
        val roots = sources.flatMap { src ->
            listOf(src.className, src.className + "Kt").mapNotNull { rootOf(classResource(it)) }
        }.toSet() - testRoot
        assertTrue("no class root found", roots.isNotEmpty())
        fun inPackages(path: String) = path.endsWith(".class") && path.substringBeforeLast('/', "") in packages
        return roots.flatMap { root ->
            if (root.isDirectory) {
                root.walkTopDown().filter { inPackages(it.relativeTo(root).invariantSeparatorsPath) }
                    .map { ClassFile.read(it.readBytes()) }.toList()
            } else {
                JarFile(root).use { jar ->
                    jar.entries().toList().filter { inPackages(it.name) }
                        .map { e -> ClassFile.read(jar.getInputStream(e).use { it.readBytes() }) }
                }
            }
        }
    }

    private fun classResource(className: String) = className.replace('.', '/') + ".class"

    /** The class directory or jar a class resource is found in, if any. */
    private fun rootOf(resource: String): File? {
        val url: URL = loader.getResource(resource) ?: return null
        return when (url.protocol) {
            "jar" -> File((url.openConnection() as JarURLConnection).jarFileURL.toURI())
            "file" -> {
                var root = File(url.toURI())
                repeat(resource.count { it == '/' } + 1) { root = root.parentFile }
                root
            }
            else -> throw AssertionError("unexpected class location: $url")
        }
    }

    private companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

        const val SECRET = "rs.readahead.washington.mobile.views.SecretEditText"
        const val NO_IME = "rs.readahead.washington.mobile.views.pin.NoImeEditText"
        const val FIXTURES = "rs/readahead/washington/mobile/views/secretfixtures"
        const val IMPOSTOR = "rs.readahead.washington.mobile.views.secretfixtures.SecretEditText"

        /**
         * The editable views the app keeps besides [SecretEditText], keyed by
         * module/layout dir/file#id, each with its exact class and the reason.
         */
        val EXEMPT_FIELDS = mapOf(
            "mobile/layout/activity_pin_unlock.xml#unlockDots" to Exempt(
                NO_IME,
                "PIN dots: the digits come from the in-app keypad (PinLockView) and the screen copies them " +
                    "in with setText; the view dismisses the soft keyboard and saves no state",
            ),
            "mobile/layout/fragment_onboard_set_pin.xml#onboardPin_editText" to Exempt(
                NO_IME,
                "PIN dots of the onboarding, same as the unlock screen",
            ),
            "shared-ui/layout/sheet_rename.xml#renameEditText" to Exempt(
                "android.widget.EditText",
                "inherited Tella file-rename sheet; nothing calls BottomSheetUtils.showFileRenameSheet " +
                    "(the_exempt_sheets_are_shown_by_nothing holds this)",
            ),
            "shared-ui/layout/enter_string_bottomsheet_layout.xml#code_editText" to Exempt(
                "android.widget.EditText",
                "inherited Tella customization-code sheet; nothing calls " +
                    "BottomSheetUtils.showEnterCustomizationCodeSheet (the_exempt_sheets_are_shown_by_nothing " +
                    "holds this). If it is ever shown, it takes a code: make it a SecretEditText, and set " +
                    "FLAG_SECURE on the sheet's own dialog window, which the activity's flag does not cover",
            ),
        )

        val UNSHOWN_SHEETS = Regex("""\b(showFileRenameSheet|showEnterCustomizationCodeSheet|sheet_rename|enter_string_bottomsheet_layout)\b""")

        val FULL = mapOf(
            "android:inputType" to "textNoSuggestions|textVisiblePassword",
            "android:imeOptions" to "actionDone|flagNoPersonalizedLearning",
            "android:saveEnabled" to "false",
            "android:importantForAutofill" to "no",
            "android:allowUndo" to "false",
        )

        /** Attributes that make a TextView editable whatever their value. */
        val KEY_LISTENER_ATTRS = listOf("android:digits", "android:numeric", "android:capitalize", "android:inputMethod")

        /** Tags that are not views. */
        val NON_VIEW_TAGS = setOf(
            "merge", "include", "requestFocus", "tag", "fragment", "blink", "layout", "data", "variable", "import",
        )

        /** Where the inflater looks up a bare tag name, in its order. */
        val BARE_PREFIXES = listOf("android.widget.", "android.webkit.", "android.app.", "android.view.")

        val loader: ClassLoader = SecretInputLayoutTest::class.java.classLoader!!
        val EDIT_TEXT: Class<*> = Class.forName("android.widget.EditText", false, loader)
        val TEXT_VIEW: Class<*> = Class.forName("android.widget.TextView", false, loader)
        val SEARCH_VIEWS: List<Class<*>> = listOf(
            Class.forName("android.widget.SearchView", false, loader),
            Class.forName("androidx.appcompat.widget.SearchView", false, loader),
        )

        /** Simple names of the platform and library classes that make a text field. */
        val BASE_FAMILY = setOf(
            "EditText", "AppCompatEditText", "TextInputEditText", "ExtractEditText",
            "AutoCompleteTextView", "AppCompatAutoCompleteTextView", "MaterialAutoCompleteTextView",
            "MultiAutoCompleteTextView", "AppCompatMultiAutoCompleteTextView",
            "SearchView", "SearchAutoComplete",
        )

        val CLASS_HEADER = Regex("""\bclass\s+(\w+)""")
        val JAVA_EXTENDS = Regex("""\bclass\s+(\w+)(?:\s*<[^>{]*>)?\s+extends\s+([\w.]+)""")

        /** Words that may stand between `class Name` and its primary constructor. */
        val HEADER_WORDS = setOf("constructor", "private", "protected", "internal", "public")
    }
}
