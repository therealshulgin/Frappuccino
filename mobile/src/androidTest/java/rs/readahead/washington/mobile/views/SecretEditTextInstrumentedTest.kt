package rs.readahead.washington.mobile.views

import android.app.Activity
import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.os.Build
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.text.InputType
import android.text.method.DigitsKeyListener
import android.util.SparseArray
import android.view.ActionMode
import android.view.DragEvent
import android.view.InputDevice
import android.view.KeyEvent
import android.view.LayoutInflater
import android.view.Menu
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.ViewGroup
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.view.inputmethod.EditorInfo
import android.view.textclassifier.TextClassifier
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.TextView
import androidx.appcompat.view.ContextThemeWrapper
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleCallback
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.views.activity.ArchiveModeActivity
import rs.readahead.washington.mobile.views.activity.onboarding.OnBoardingActivity

/**
 * [SecretEditText] on a real device: what the keyboard receives, that a later
 * setter cannot undo the protections, that the menus are filtered from the
 * start, that copy, cut, share and undo do nothing and leave the clipboard
 * alone whatever path asks for them, that accessibility services are offered
 * no action that takes the words out of the field, that nothing of the text
 * goes into its saved state, that a drag of the selection, started by a long
 * press or by a mouse, ends before any drop, and that the field secures a
 * window that was not. For the screens around it: FLAG_SECURE is already on
 * the window when onCreate returns, and the archive screen empties the phrase
 * when it goes to the background.
 *
 * Removing any of the following from the code makes a test fail; each was
 * checked by removing it: the selection-menu filter the field installs when it
 * is built; the accessibility node filter, and the refusal in
 * `performAccessibilityAction` (a test also fails when the refused ids are
 * widened past TextView's own, which would take actions from screen-reader
 * users); the window update of the dialog fallback; the cancel of a mouse
 * drag; the mask that keeps only the multi-line flags of a requested input
 * type. Keep it that way when changing one of them. Where the test needs the
 * platform to do something first (offer another app's text action, start a
 * drag), it asserts that this happened, so that it cannot pass on nothing.
 *
 * What this does not hold:
 * - Some protections are applied twice, and removing one layer alone leaves
 *   every test green: the input type and IME flags put on the keyboard's
 *   EditorInfo in `onCreateInputConnection` repeat what the setters already
 *   put on the field.
 * - No test drives the right-click menu (`onCreateContextMenu`), nor a click
 *   on an item the menu filter hid.
 * - The other assertions check what the field does; not each of them has been
 *   tried against the removal of the line it relies on.
 * - The Content Capture switch-off of `refuseScreenCapture`. On a device
 *   without a Content Capture service, or with this app not allowlisted by it,
 *   there is no manager to ask, and a check would pass on nothing; it is
 *   verified by reading the code only.
 * - Every test runs on the API level of the device; the branches for other
 *   levels run only where those levels do.
 */
@RunWith(AndroidJUnit4::class)
class SecretEditTextInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = ContextThemeWrapper(instrumentation.targetContext, R.style.AppTheme)

    @Test
    fun a_field_built_in_code_carries_every_protection() {
        val field = onMain { SecretEditText(context) }
        onMain { assertProtected(field, "built in code") }
    }

    @Test
    fun the_layout_fields_are_secret_fields_and_keep_their_lines() {
        onMain {
            val archive = inflate(R.layout.activity_archive_mode)
            val phrase = archive.findViewById<View>(R.id.archiveMnemonicInput)
            assertTrue("archiveMnemonicInput is ${phrase.javaClass.name}", phrase is SecretEditText)
            phrase as SecretEditText
            assertProtected(phrase, "archiveMnemonicInput")
            assertTrue(editorInfo(phrase).inputType and InputType.TYPE_TEXT_FLAG_MULTI_LINE != 0)

            val confirm = inflate(R.layout.fragment_onboard_mnemonic_confirm)
            for (id in listOf(R.id.wordInput1, R.id.wordInput2, R.id.wordInput3)) {
                val word = confirm.findViewById<View>(id)
                assertTrue(word is SecretEditText)
                assertProtected(word as SecretEditText, "word input")
            }
        }
    }

    @Test
    fun the_ime_action_survives_the_protections() {
        onMain {
            // Not actionDone: TextView supplies that one itself when none is set.
            val field = SecretEditText(context)
            field.imeOptions = EditorInfo.IME_ACTION_GO
            assertEquals(EditorInfo.IME_ACTION_GO, field.imeOptions and EditorInfo.IME_MASK_ACTION)
            assertEquals(EditorInfo.IME_ACTION_GO, editorInfo(field).imeOptions and EditorInfo.IME_MASK_ACTION)
            assertProtected(field, "with actionGo")
        }
    }

    @Test
    fun later_setters_do_not_remove_the_protections() {
        onMain {
            val field = SecretEditText(context)
            assertProtected(field, "before the setters")
            field.inputType = InputType.TYPE_CLASS_TEXT
            field.setRawInputType(InputType.TYPE_CLASS_TEXT)
            field.imeOptions = 0
            field.isSaveEnabled = true
            field.isSaveFromParentEnabled = true
            field.freezesText = true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                field.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
                field.setTextClassifier(null)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                field.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_YES
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                field.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_NO)
            }
            assertProtected(field, "after the setters")
        }
    }

    @Test
    fun a_new_key_listener_keeps_the_field_protected() {
        onMain {
            val field = SecretEditText(context)
            // setKeyListener sets the input type without going through a setter.
            field.keyListener = DigitsKeyListener.getInstance("0123456789")
            assertProtected(field, "after setKeyListener")
        }
    }

    @Test
    fun the_menus_offer_only_paste_and_select_all() {
        onMain {
            val field = SecretEditText(context)
            // Code that sets its own callback, even one that adds Copy back, is still filtered.
            field.customSelectionActionModeCallback = object : ActionMode.Callback {
                override fun onCreateActionMode(mode: ActionMode?, menu: Menu?): Boolean {
                    menu?.add(Menu.NONE, android.R.id.copy, Menu.NONE, "copy")
                    return true
                }
                override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?) = false
                override fun onActionItemClicked(mode: ActionMode?, item: android.view.MenuItem?) = false
                override fun onDestroyActionMode(mode: ActionMode?) = Unit
            }
            val callbacks = listOfNotNull(
                field.customSelectionActionModeCallback,
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) field.customInsertionActionModeCallback else null,
            )
            assertEquals(if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) 2 else 1, callbacks.size)
            for (callback in callbacks) assertMenuFiltered(callback, field, "after a callback was set")
        }
    }

    @Test
    fun the_menus_are_filtered_before_any_code_sets_a_callback() {
        // The platform's default is no callback at all, and with none nothing
        // hides the other apps' text actions: the filter must come from the
        // field itself, in code and from every layout.
        onMain {
            for ((where, field) in listOf("built in code" to SecretEditText(context)) + layoutFields()) {
                val selection = field.customSelectionActionModeCallback
                assertNotNull("$where: no filter on the selection menu", selection)
                assertMenuFiltered(selection!!, field, "$where, selection menu")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val insertion = field.customInsertionActionModeCallback
                    assertNotNull("$where: no filter on the insertion menu", insertion)
                    assertMenuFiltered(insertion!!, field, "$where, insertion menu")
                }
            }
        }
    }

    @Test
    fun a_requested_type_keeps_only_its_multi_line_flags() {
        val secure = InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        val multiLine = InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_IME_MULTI_LINE
        // Requests that carry a variation and flags of their own: none of it
        // may reach the field or the keyboard, except the multi-line flags.
        val requests = listOf(
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS or
                InputType.TYPE_TEXT_FLAG_AUTO_CORRECT or InputType.TYPE_TEXT_FLAG_AUTO_COMPLETE or
                InputType.TYPE_TEXT_FLAG_CAP_SENTENCES to secure,
            InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD to secure,
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or
                InputType.TYPE_TEXT_FLAG_CAP_WORDS or multiLine to (secure or multiLine),
        )
        val setters = listOf<Pair<String, (SecretEditText, Int) -> Unit>>(
            "setInputType" to { field, type -> field.inputType = type },
            "setRawInputType" to { field, type -> field.setRawInputType(type) },
        )
        onMain {
            for ((requested, expected) in requests) {
                for ((setter, set) in setters) {
                    val field = SecretEditText(context)
                    set(field, requested)
                    val what = "$setter(0x${Integer.toHexString(requested)})"
                    assertEquals("$what: the field's type", expected, field.inputType)
                    assertEquals("$what: the keyboard's type", expected, editorInfo(field).inputType)
                }
            }
        }
    }

    @Test
    fun copy_cut_share_and_undo_do_nothing_whatever_asks_and_paste_still_works() {
        // Reading the clipboard needs a focused window of this app (API 29+).
        val scenario = ActivityScenario.launch(OnBoardingActivity::class.java)
        try {
            lateinit var field: SecretEditText
            scenario.onActivity { activity ->
                field = SecretEditText(activity)
                activity.addContentView(field, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
                field.requestFocus()
            }
            waitForFocus(scenario)
            scenario.onActivity { activity ->
                val clipboard = activity.getSystemService(ClipboardManager::class.java)
                clipboard.setPrimaryClip(ClipData.newPlainText("test", SENTINEL))
                assertEquals("the test cannot read the clipboard", SENTINEL, clipText(activity, clipboard))
                field.setText(SECRET_TEXT)

                val ctrl = KeyEvent(0, 0, KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_C, 0, KeyEvent.META_CTRL_ON or KeyEvent.META_CTRL_LEFT_ON)
                val ctrlX = KeyEvent(0, 0, KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_X, 0, KeyEvent.META_CTRL_ON or KeyEvent.META_CTRL_LEFT_ON)
                val attempts = listOf<Pair<String, () -> Boolean>>(
                    "menu copy" to { field.onTextContextMenuItem(android.R.id.copy) },
                    "menu cut" to { field.onTextContextMenuItem(android.R.id.cut) },
                    "menu share" to { field.onTextContextMenuItem(android.R.id.shareText) },
                    "accessibility copy" to { field.performAccessibilityAction(AccessibilityNodeInfo.ACTION_COPY, null) },
                    "accessibility cut" to { field.performAccessibilityAction(AccessibilityNodeInfo.ACTION_CUT, null) },
                    "Ctrl+C" to { field.onKeyShortcut(KeyEvent.KEYCODE_C, ctrl) },
                    "Ctrl+X" to { field.onKeyShortcut(KeyEvent.KEYCODE_X, ctrlX) },
                )
                for ((what, attempt) in attempts) {
                    field.setSelection(0, SECRET_TEXT.length)
                    assertFalse("$what was performed", attempt())
                    assertEquals("$what reached the clipboard", SENTINEL, clipText(activity, clipboard))
                    assertEquals("$what changed the text", SECRET_TEXT, field.text.toString())
                }

                // Undo would bring back what an edit removed.
                field.text!!.delete(0, field.text!!.length)
                assertFalse("undo was performed", field.onTextContextMenuItem(android.R.id.undo))
                assertFalse("redo was performed", field.onTextContextMenuItem(android.R.id.redo))
                assertEquals("", field.text.toString())

                field.setText(SECRET_TEXT)
                field.setSelection(SECRET_TEXT.length)
                assertTrue("paste was refused", field.onTextContextMenuItem(android.R.id.paste))
                assertTrue("paste brought nothing in", field.text.toString().contains(SENTINEL))
            }
        } finally {
            scenario.close()
        }
    }

    @Test
    fun nothing_of_the_text_goes_into_the_saved_state() {
        onMain {
            val field = SecretEditText(context)
            field.id = View.generateViewId()
            field.setText(SECRET_TEXT)
            field.setSelection(0, 4)
            // What the activity collects: nothing at all.
            val container = SparseArray<android.os.Parcelable>()
            field.saveHierarchyState(container)
            assertEquals(0, container.size())
            // What the view would hand over if asked directly: not the text.
            val state = field.onSaveInstanceState()
            if (state != null) {
                val parcel = Parcel.obtain()
                try {
                    state.writeToParcel(parcel, 0)
                    val bytes = parcel.marshall()
                    for (charset in listOf(Charsets.UTF_8, Charsets.UTF_16LE)) {
                        assertFalse("the text is in the saved state ($charset)", contains(bytes, "abaisser".toByteArray(charset)))
                    }
                } finally {
                    parcel.recycle()
                }
            }
        }
    }

    @Test
    fun a_drag_of_the_selected_words_ends_before_any_drop() {
        assumeTrue("a drag can leave the window from API 24", Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
        val scenario = ActivityScenario.launch(OnBoardingActivity::class.java)
        try {
            val selectionShown = CountDownLatch(1)
            lateinit var scene: DragScene
            scenario.onActivity { activity ->
                scene = DragScene(activity)
                scene.field.customSelectionActionModeCallback = object : ActionMode.Callback {
                    override fun onCreateActionMode(mode: ActionMode?, menu: Menu?): Boolean {
                        selectionShown.countDown()
                        return true
                    }
                    override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?) = false
                    override fun onActionItemClicked(mode: ActionMode?, item: android.view.MenuItem?) = false
                    override fun onDestroyActionMode(mode: ActionMode?) = Unit
                }
            }
            waitForFocus(scenario)
            instrumentation.waitForIdleSync()
            val field = scene.field
            val hold = ViewConfiguration.getLongPressTimeout() * 3L

            // A long press on the first word selects it and shows the selection menu.
            val word = onMain { onScreen(field, field.layout.getPrimaryHorizontal(3)) }
            val first = SystemClock.uptimeMillis()
            touch(first, MotionEvent.ACTION_DOWN, word)
            SystemClock.sleep(hold)
            touch(first, MotionEvent.ACTION_UP, word)
            assertTrue("the selection menu never showed", selectionShown.await(20, TimeUnit.SECONDS))
            assertTrue("nothing was selected", onMain { field.hasSelection() })

            // A long press inside the selection starts a drag; carry it onto
            // the target and release.
            val inside = onMain { onScreen(field, field.layout.getPrimaryHorizontal(3)) }
            val onTarget = onMain { onScreen(scene.target, scene.target.width / 2f, scene.target.height / 2f) }
            val second = SystemClock.uptimeMillis()
            touch(second, MotionEvent.ACTION_DOWN, inside)
            SystemClock.sleep(hold)
            scene.awaitDragStarted()
            for (step in 1..10) {
                val x = inside.first + (onTarget.first - inside.first) * step / 10f
                val y = inside.second + (onTarget.second - inside.second) * step / 10f
                touch(second, MotionEvent.ACTION_MOVE, x to y)
                SystemClock.sleep(30)
            }
            touch(second, MotionEvent.ACTION_UP, onTarget)
            SystemClock.sleep(2_000)
            instrumentation.waitForIdleSync()

            scene.assertNoDrop()
        } finally {
            scenario.close()
        }
    }

    @Test
    fun a_mouse_drag_of_the_selected_words_ends_before_any_drop() {
        assumeTrue("a drag can leave the window from API 24", Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
        val scenario = ActivityScenario.launch(OnBoardingActivity::class.java)
        try {
            lateinit var scene: DragScene
            scenario.onActivity { activity -> scene = DragScene(activity) }
            waitForFocus(scenario)
            instrumentation.waitForIdleSync()
            val field = scene.field
            onMain {
                field.requestFocus()
                field.setSelection(0, SECRET_TEXT.length)
            }

            // The primary button goes down inside the selection and the mouse
            // moves while it is held: the platform starts a drag of the
            // selected text on the first move that stays inside it. Editor
            // ignores a mouse press that does not change the primary button,
            // and a move without it held, so every event carries its state.
            val inside = onMain { onScreen(field, field.layout.getPrimaryHorizontal(3)) }
            val stillInside = onMain { onScreen(field, field.layout.getPrimaryHorizontal(8)) }
            val onTarget = onMain { onScreen(scene.target, scene.target.width / 2f, scene.target.height / 2f) }
            val down = SystemClock.uptimeMillis()
            mouse(down, MotionEvent.ACTION_DOWN, inside, MotionEvent.BUTTON_PRIMARY)
            mouse(down, MotionEvent.ACTION_MOVE, stillInside, MotionEvent.BUTTON_PRIMARY)
            scene.awaitDragStarted()
            for (step in 1..10) {
                val x = stillInside.first + (onTarget.first - stillInside.first) * step / 10f
                val y = stillInside.second + (onTarget.second - stillInside.second) * step / 10f
                mouse(down, MotionEvent.ACTION_MOVE, x to y, MotionEvent.BUTTON_PRIMARY)
                SystemClock.sleep(30)
            }
            mouse(down, MotionEvent.ACTION_UP, onTarget, 0)
            SystemClock.sleep(2_000)
            instrumentation.waitForIdleSync()

            scene.assertNoDrop()
        } finally {
            scenario.close()
        }
    }

    @Test
    fun accessibility_offers_no_action_that_takes_the_words_out() {
        assumeTrue("other apps' text actions exist from API 23", Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        val scenario = ActivityScenario.launch(OnBoardingActivity::class.java)
        // Blocks the launch and counts it: nothing is started for real.
        val launches = instrumentation.addMonitor(
            IntentFilter(Intent.ACTION_PROCESS_TEXT).apply { addDataType("text/plain") }, null, true,
        )
        try {
            lateinit var plain: EditText
            lateinit var secret: SecretEditText
            scenario.onActivity { activity ->
                plain = EditText(activity)
                secret = SecretEditText(activity)
                val column = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
                for (field in listOf(plain, secret)) {
                    // TextView offers the other apps' actions only on a view with an id.
                    field.id = View.generateViewId()
                    field.showSoftInputOnFocus = false
                    field.setText(SECRET_TEXT)
                    column.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
                }
                activity.addContentView(column, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            }
            instrumentation.waitForIdleSync()

            // First the same steps on a plain EditText of the same window: it
            // must offer copy, cut, share and the fixture's action, and that
            // action must start the fixture. Otherwise the checks on the
            // secret field below would pass on nothing (package visibility,
            // for one, could hide the fixture from the app).
            val fixtureAction = onMain {
                val offered = selectAndDescribe(plain).actionList
                val ids = offered.map { it.id }
                for ((name, id) in REFUSED_A11Y_ACTIONS) assertTrue("plain field: $name not offered: $ids", id in ids)
                val fixture = offered.singleOrNull { it.label?.toString() == FIXTURE_LABEL }
                assertNotNull("plain field: the fixture's action is not offered: ${offered.map { it.label }}", fixture)
                assertTrue("plain field: the fixture's action did nothing", plain.performAccessibilityAction(fixture!!.id, null))
                fixture.id
            }
            assertEquals("plain field: the fixture was not started", 1, launches.hits)
            val plainIds = onMain { selectAndDescribe(plain).actionList.map { it.id } }

            onMain {
                val ids = selectAndDescribe(secret).actionList.map { it.id }
                for ((name, id) in REFUSED_A11Y_ACTIONS + ("the fixture's action" to fixtureAction)) {
                    assertFalse("secret field: $name offered: $ids", id in ids)
                }
                // What a screen reader needs to read and edit the field stays:
                // everything the plain field offers but the refused actions.
                for ((name, id) in KEPT_A11Y_ACTIONS) assertTrue("secret field: $name not offered: $ids", id in ids)
                val missing = plainIds.filterNot { id ->
                    id in REFUSED_A11Y_ACTIONS.map { it.second } || id in TEXTVIEW_PROCESS_TEXT_IDS || id in TEXTVIEW_SMART_IDS
                } - ids.toSet()
                assertEquals("secret field: actions the plain field offers are missing ($ids)", emptyList<Int>(), missing)
                // Asked for anyway, with the ids TextView still holds, they do nothing.
                for ((name, id) in REFUSED_A11Y_ACTIONS + ("the fixture's action" to fixtureAction)) {
                    assertFalse("secret field: $name was performed", secret.performAccessibilityAction(id, null))
                }
                assertEquals("secret field: the text changed", SECRET_TEXT, secret.text.toString())
            }
            assertEquals("an app was started with the secret field's selection", 1, launches.hits)
        } finally {
            instrumentation.removeMonitor(launches)
            scenario.close()
        }
    }

    @Test
    fun the_refused_accessibility_ids_are_textview_s_own_and_nothing_else() {
        // A node that already holds actions of every kind, as a delegate or
        // androidx could have added them: only TextView's private ranges and
        // copy, cut and share go.
        onMain {
            val field = SecretEditText(context)
            @Suppress("DEPRECATION")
            val info = AccessibilityNodeInfo.obtain(field)
            val given = listOf(
                0x10000100, 0x10000FFF, // PROCESS_TEXT: the first and the last id of the range
                0x10001000, 0x10001FFF, // smart actions: the same
            )
            val kept = listOf(
                AccessibilityNodeInfo.ACTION_CLICK,
                AccessibilityNodeInfo.ACTION_SET_SELECTION,
                AccessibilityNodeInfo.ACTION_PASTE,
                AccessibilityNodeInfo.ACTION_SET_TEXT,
                android.R.id.accessibilityActionImeEnter,
                0x0FFFFFFF, 0x10000001, 0x100000FF, 0x10002000, // around the ranges
                0x7f0f_fff2, // an app resource id, as androidx custom actions use
            )
            for (id in given + kept) info.addAction(AccessibilityNodeInfo.AccessibilityAction(id, "action $id"))
            field.onInitializeAccessibilityNodeInfo(info)
            val ids = info.actionList.map { it.id }
            for (id in given) assertFalse("0x${Integer.toHexString(id)} kept: $ids", id in ids)
            for (id in kept) assertTrue("0x${Integer.toHexString(id)} removed: $ids", id in ids)
        }
    }

    @Test
    fun a_field_secures_a_window_that_was_not() {
        val scenario = ActivityScenario.launch(OnBoardingActivity::class.java)
        try {
            lateinit var dialog: Dialog
            lateinit var field: SecretEditText
            lateinit var windowManager: RecordingWindowManager
            scenario.onActivity { activity ->
                dialog = Dialog(activity)
                // The field reaches the window manager through its context:
                // this one records what it is told, and passes it on.
                windowManager = RecordingWindowManager(dialog.context.getSystemService(Context.WINDOW_SERVICE) as WindowManager)
                field = SecretEditText(object : ContextWrapper(dialog.context) {
                    override fun getSystemService(name: String): Any? =
                        if (name == Context.WINDOW_SERVICE) windowManager else super.getSystemService(name)
                })
                dialog.setContentView(field)
                val attributes = dialog.window!!.attributes
                assertEquals(0, attributes.flags and WindowManager.LayoutParams.FLAG_SECURE)
                // Set in place before show(), so that nothing is pushed for it.
                attributes.title = DIALOG_TITLE
                dialog.show()
            }
            val deadline = SystemClock.uptimeMillis() + 20_000
            while (!onMain { field.isAttachedToWindow } && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(50)
            onMain {
                assertTrue("the field never got attached", field.isAttachedToWindow)
                val root = field.rootView
                // Setting the flag on the parameters is not enough: the window
                // manager keeps its own copy and only an update reaches it.
                assertTrue(
                    "the window manager was never given FLAG_SECURE for the dialog window",
                    windowManager.updates.any { (view, flags) -> view === root && flags and WindowManager.LayoutParams.FLAG_SECURE != 0 },
                )
                // The flag is set on the window's own attributes, not on a
                // copy: Dialog pushes those again on any later change of its
                // window, and a copy would leave them without the flag.
                val params = root.layoutParams as WindowManager.LayoutParams
                assertTrue("FLAG_SECURE not set on the dialog window", params.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                assertSame(dialog.window!!.attributes, params)
            }
            // And the window as the system holds it.
            val flags = windowFlags(DIALOG_TITLE, until = { "SECURE" in it })
            assertTrue("the system's dialog window has no SECURE flag: $flags", "SECURE" in flags)
            onMain { dialog.dismiss() }
        } finally {
            scenario.close()
        }
    }

    @Test
    fun the_grid_that_shows_the_phrase_is_data_sensitive() {
        assumeTrue("accessibilityDataSensitive exists from API 34", Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
        onMain {
            val screen = inflate(R.layout.fragment_onboard_mnemonic_generate)
            val grid = screen.findViewById<ViewGroup>(R.id.wordsGrid)
            // The words are added by code, as OnBoardMnemonicGenerateFragment does.
            val word = TextView(context).also { grid.addView(it) }
            assertTrue("the grid", grid.isAccessibilityDataSensitive)
            assertTrue("a word added to the grid", word.isAccessibilityDataSensitive)
        }
    }

    @Test
    fun flag_secure_is_on_the_window_when_on_create_returns() {
        var secureAtCreate: Boolean? = null
        val callback = ActivityLifecycleCallback { activity: Activity, stage: Stage ->
            if (stage == Stage.CREATED && activity is OnBoardingActivity) {
                secureAtCreate = activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
            }
        }
        ActivityLifecycleMonitorRegistry.getInstance().addLifecycleCallback(callback)
        try {
            ActivityScenario.launch(OnBoardingActivity::class.java).close()
        } finally {
            ActivityLifecycleMonitorRegistry.getInstance().removeLifecycleCallback(callback)
        }
        assertNotNull("onCreate of OnBoardingActivity was not observed", secureAtCreate)
        assertTrue("FLAG_SECURE missing when onCreate returned", secureAtCreate!!)
    }

    @Test
    fun the_archive_screen_empties_the_phrase_when_it_goes_to_the_background() {
        val scenario = ActivityScenario.launch(ArchiveModeActivity::class.java)
        try {
            scenario.onActivity { it.findViewById<EditText>(R.id.archiveMnemonicInput).setText(SECRET_TEXT) }
            scenario.moveToState(Lifecycle.State.CREATED)
            scenario.onActivity {
                assertEquals("", it.findViewById<EditText>(R.id.archiveMnemonicInput).text.toString())
            }
        } finally {
            scenario.close()
        }
    }

    // ---- helpers ----

    private fun assertProtected(field: SecretEditText, where: String) {
        val type = field.inputType
        assertEquals(where, InputType.TYPE_CLASS_TEXT, type and InputType.TYPE_MASK_CLASS)
        assertEquals(where, InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD, type and InputType.TYPE_MASK_VARIATION)
        assertTrue(where, type and InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS != 0)
        assertFalse("$where: suggestions (spell checker) enabled", field.isSuggestionsEnabled)
        assertEquals(where, IME_FLAGS, field.imeOptions and IME_FLAGS)
        assertFalse(where, field.isSaveEnabled)
        assertFalse(where, field.isSaveFromParentEnabled)
        assertFalse(where, field.freezesText)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            assertEquals(where, View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, field.importantForAutofill)
            assertEquals(where, View.AUTOFILL_TYPE_NONE, field.autofillType)
            assertNull(where, field.autofillValue)
            assertSame("$where: text classifier", TextClassifier.NO_OP, field.textClassifier)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            assertEquals(where, View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS, field.importantForContentCapture)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            assertTrue(where, field.isAccessibilityDataSensitive)
        }
        assertKeyboardProtected(editorInfo(field), where)
    }

    private fun assertKeyboardProtected(info: EditorInfo, where: String) {
        assertEquals("$where: class", InputType.TYPE_CLASS_TEXT, info.inputType and InputType.TYPE_MASK_CLASS)
        assertEquals("$where: variation", InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD, info.inputType and InputType.TYPE_MASK_VARIATION)
        assertTrue("$where: no suggestions", info.inputType and InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS != 0)
        assertEquals("$where: IME flags", IME_FLAGS, info.imeOptions and IME_FLAGS)
    }

    /**
     * [callback] given a menu as the platform builds one: its own items and an
     * unknown one before `onCreateActionMode`, another app's text action and
     * an assist item after it. Only paste, paste as plain text and select all
     * may stay visible.
     */
    private fun assertMenuFiltered(callback: ActionMode.Callback, anchor: View, where: String) {
        val menu = PopupMenu(context, anchor).menu
        for (id in listOf(
            android.R.id.cut, android.R.id.paste, android.R.id.pasteAsPlainText, android.R.id.selectAll,
            android.R.id.shareText, android.R.id.undo, android.R.id.redo, Menu.NONE,
        )) {
            menu.add(Menu.NONE, id, Menu.NONE, "item $id")
        }
        callback.onCreateActionMode(null, menu)
        // The platform adds the other apps' text actions after
        // onCreateActionMode, and the assist items before
        // onPrepareActionMode: only the prepare step can hide them.
        menu.add(Menu.NONE, PROCESS_TEXT_LIKE_ID, Menu.NONE, "translate")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            menu.add(android.R.id.textAssist, android.R.id.textAssist, Menu.NONE, "assist")
        }
        callback.onPrepareActionMode(null, menu)
        val visible = (0 until menu.size()).map { menu.getItem(it) }.filter { it.isVisible }.map { it.itemId }
        assertEquals(where, setOf(android.R.id.paste, android.R.id.pasteAsPlainText, android.R.id.selectAll), visible.toSet())
    }

    /** The secret fields of the layouts, inflated as the screens do. */
    private fun layoutFields(): List<Pair<String, SecretEditText>> {
        val archive = inflate(R.layout.activity_archive_mode)
        val confirm = inflate(R.layout.fragment_onboard_mnemonic_confirm)
        return listOf(
            "archiveMnemonicInput" to archive.findViewById<SecretEditText>(R.id.archiveMnemonicInput),
            "wordInput1" to confirm.findViewById<SecretEditText>(R.id.wordInput1),
            "wordInput2" to confirm.findViewById<SecretEditText>(R.id.wordInput2),
            "wordInput3" to confirm.findViewById<SecretEditText>(R.id.wordInput3),
        )
    }

    private fun editorInfo(field: SecretEditText) = EditorInfo().also { field.onCreateInputConnection(it) }

    private fun inflate(layout: Int): View = LayoutInflater.from(context).inflate(layout, null)

    private fun clipText(context: Context, clipboard: ClipboardManager): String? =
        clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { i -> needle.indices.all { haystack[i + it] == needle[it] } }

    /** A point of [view] on the screen; for a text field, on its first line. */
    private fun onScreen(view: View, x: Float, y: Float? = null): Pair<Float, Float> {
        val at = IntArray(2).also { view.getLocationOnScreen(it) }
        val lineY = (view as? TextView)?.layout?.let { (it.getLineTop(0) + it.getLineBottom(0)) / 2f + view.totalPaddingTop }
        val px = if (view is TextView) x + view.totalPaddingLeft else x
        return at[0] + px to at[1] + (y ?: lineY ?: (view.height / 2f))
    }

    private fun touch(downTime: Long, action: Int, at: Pair<Float, Float>) {
        val event = MotionEvent.obtain(downTime, SystemClock.uptimeMillis(), action, at.first, at.second, 0)
        event.source = InputDevice.SOURCE_TOUCHSCREEN
        inject(event)
    }

    /** A mouse event with the buttons in [buttons] held. */
    private fun mouse(downTime: Long, action: Int, at: Pair<Float, Float>, buttons: Int) {
        val pointer = MotionEvent.PointerProperties().apply {
            id = 0
            toolType = MotionEvent.TOOL_TYPE_MOUSE
        }
        val coords = MotionEvent.PointerCoords().apply {
            x = at.first
            y = at.second
            pressure = 1f
            size = 1f
        }
        val event = MotionEvent.obtain(
            downTime, SystemClock.uptimeMillis(), action, 1, arrayOf(pointer), arrayOf(coords),
            0, buttons, 1f, 1f, 0, 0, InputDevice.SOURCE_MOUSE, 0,
        )
        inject(event)
    }

    private fun inject(event: MotionEvent) {
        try {
            assertTrue("input injection refused", instrumentation.uiAutomation.injectInputEvent(event, true))
        } finally {
            event.recycle()
        }
    }

    /**
     * [field] focused, its whole text selected, and given accessibility focus
     * as a screen reader would (TextView fills its list of other apps' text
     * actions then, whether or not a service is running): the node a service
     * would get.
     */
    private fun selectAndDescribe(field: EditText): AccessibilityNodeInfo {
        assertTrue("could not focus the field", field.requestFocus())
        field.setSelection(0, field.text.length)
        field.sendAccessibilityEvent(AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED)
        return field.createAccessibilityNodeInfo()
    }

    /**
     * The `fl=` flags of the window titled [title] in `dumpsys window`, read
     * until [until] holds or a few seconds have passed; empty if no such window.
     */
    private fun windowFlags(title: String, until: (List<String>) -> Boolean): List<String> {
        val deadline = SystemClock.uptimeMillis() + 10_000
        var flags = emptyList<String>()
        while (SystemClock.uptimeMillis() < deadline) {
            val dump = ParcelFileDescriptor.AutoCloseInputStream(
                instrumentation.uiAutomation.executeShellCommand("dumpsys window windows"),
            ).bufferedReader().use { it.readText() }
            val window = dump.split("\n  Window #").firstOrNull { it.lineSequence().first().contains(" $title}") }
            flags = window?.lineSequence()?.map { it.trim() }?.firstOrNull { it.startsWith("fl=") }
                ?.removePrefix("fl=")?.split(' ')?.filter { it.isNotEmpty() }.orEmpty()
            if (until(flags)) return flags
            SystemClock.sleep(200)
        }
        return flags
    }

    /** Passes everything on to [real], and records each layout update first. */
    private class RecordingWindowManager(private val real: WindowManager) : WindowManager by real {
        /** The view and the flags of each update, in order. */
        val updates = CopyOnWriteArrayList<Pair<View, Int>>()

        override fun updateViewLayout(view: View, params: ViewGroup.LayoutParams) {
            updates += view to (params as WindowManager.LayoutParams).flags
            real.updateViewLayout(view, params)
        }
    }

    /**
     * A secret field holding [SECRET_TEXT] in large type, under a view that
     * accepts any drop and records the drag events it sees.
     */
    private class DragScene(activity: Activity) {
        val events = CopyOnWriteArrayList<Int>()

        @Volatile
        var dropped: String? = null

        val target = View(activity).apply { setBackgroundColor(Color.DKGRAY) }
        val field = SecretEditText(activity).apply {
            textSize = 40f
            showSoftInputOnFocus = false
            setText(SECRET_TEXT)
        }

        init {
            target.setOnDragListener { _, event ->
                events += event.action
                if (event.action == DragEvent.ACTION_DROP) {
                    dropped = event.clipData?.getItemAt(0)?.text?.toString().orEmpty()
                }
                true
            }
            val column = LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundColor(Color.WHITE)
                addView(target, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
                addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(View(activity), LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
            }
            activity.addContentView(column, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        }

        fun awaitDragStarted() {
            val deadline = SystemClock.uptimeMillis() + 10_000
            while (DragEvent.ACTION_DRAG_STARTED !in events && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(50)
        }

        fun assertNoDrop() {
            assertTrue("no drag started: the test did not reach what it guards ($events)", DragEvent.ACTION_DRAG_STARTED in events)
            assertNull("the selected words were dropped: \"$dropped\"", dropped)
            assertFalse("a drop was delivered", DragEvent.ACTION_DROP in events)
        }
    }

    private fun waitForFocus(scenario: ActivityScenario<OnBoardingActivity>) {
        // Generous: on a loaded emulator the window can take many seconds to get focus.
        val deadline = SystemClock.uptimeMillis() + 30_000
        while (SystemClock.uptimeMillis() < deadline) {
            var focused = false
            scenario.onActivity { focused = it.hasWindowFocus() }
            if (focused) return
            SystemClock.sleep(100)
        }
        throw AssertionError("the activity window never got focus")
    }

    private fun <T> onMain(block: () -> T): T {
        var result: Result<T>? = null
        instrumentation.runOnMainSync { result = runCatching(block) }
        return result!!.getOrThrow()
    }

    private companion object {
        const val SENTINEL = "clipboard-sentinel"
        const val SECRET_TEXT = "abaisser abandon"

        /** An id no menu of the platform uses, standing for another app's text action. */
        const val PROCESS_TEXT_LIKE_ID = 0x7f0f_fff1

        /** The label of [ProcessTextFixtureActivity] in the androidTest manifest. */
        const val FIXTURE_LABEL = "Process text fixture"

        const val DIALOG_TITLE = "secret-edit-text-dialog"

        /** TextView's private id of its accessibility share action. */
        const val TEXTVIEW_SHARE = 0x10000000

        /** TextView's private ids of other apps' text actions, and of smart actions. */
        val TEXTVIEW_PROCESS_TEXT_IDS = 0x10000100 until 0x10001000
        val TEXTVIEW_SMART_IDS = 0x10001000 until 0x10002000

        /** What a plain field with a selection offers and a secret one must not. */
        val REFUSED_A11Y_ACTIONS = listOf(
            "copy" to AccessibilityNodeInfo.ACTION_COPY,
            "cut" to AccessibilityNodeInfo.ACTION_CUT,
            "share" to TEXTVIEW_SHARE,
        )

        val KEPT_A11Y_ACTIONS = listOf(
            "set selection" to AccessibilityNodeInfo.ACTION_SET_SELECTION,
            "set text" to AccessibilityNodeInfo.ACTION_SET_TEXT,
            "next at granularity" to AccessibilityNodeInfo.ACTION_NEXT_AT_MOVEMENT_GRANULARITY,
            "previous at granularity" to AccessibilityNodeInfo.ACTION_PREVIOUS_AT_MOVEMENT_GRANULARITY,
        )

        const val IME_FLAGS = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
            EditorInfo.IME_FLAG_NO_EXTRACT_UI or
            EditorInfo.IME_FLAG_NO_FULLSCREEN
    }
}
