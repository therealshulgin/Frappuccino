package rs.readahead.washington.mobile.views

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.text.method.KeyListener
import android.util.AttributeSet
import android.view.ActionMode
import android.view.ContextMenu
import android.view.InputDevice
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo
import android.view.autofill.AutofillValue
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.textclassifier.TextClassifier
import androidx.annotation.RequiresApi
import androidx.appcompat.widget.AppCompatEditText
import timber.log.Timber

/**
 * The text field for the recovery phrase, typed whole or word by word. Every
 * field that takes it is a SecretEditText. `SecretInputLayoutTest` refuses
 * any other editable field in a layout or built in code, except the ones it
 * lists with their reason: the PIN dots (`NoImeEditText`, filled by the in-app
 * keypad, never by the keyboard) and two inherited shared-ui sheets that
 * nothing shows.
 *
 * It applies its protections itself, when it is built and again each time code
 * calls one of the setters below, so a later `setInputType`, `setImeOptions`,
 * `setKeyListener`, `setSaveEnabled`, ... cannot quietly undo them:
 *
 * - **Input type**: text class, visible-password variation and no suggestions,
 *   keeping only the multi-line flags the layout declares. The keyboard is told
 *   not to offer completions or corrections for what is typed, and the
 *   platform's spell checker is not started on the field. A new key listener
 *   brings its own input type: the secure one is put back on top of it.
 * - **IME options**: `IME_FLAG_NO_PERSONALIZED_LEARNING` (the keyboard is asked
 *   not to learn the words into its dictionary or history), plus
 *   `IME_FLAG_NO_EXTRACT_UI` and `IME_FLAG_NO_FULLSCREEN`: in landscape a
 *   keyboard may otherwise show the text in its own full-screen editor, a window
 *   of the keyboard that the activity's FLAG_SECURE may not cover. The action
 *   the layout declares (`actionDone`, ...) is kept. The same flags are applied
 *   once more to the [EditorInfo] handed to the keyboard.
 * - **Saved state**: not saved, by the view or from its parent, and
 *   [getFreezesText] is false, so the text does not go into the Bundle the
 *   activity hands to the system when it is stopped.
 * - **Autofill**: `NO_EXCLUDE_DESCENDANTS` and no autofill type or value, on
 *   API 26+. Content Capture is excluded the same way on API 30+, and the text
 *   classifier is the no-op one on API 26+, so a selection is not handed to the
 *   system's classifier for "smart" actions.
 * - **Accessibility**: `accessibilityDataSensitive` YES on API 34+. The
 *   actions offered to accessibility services (TalkBack, Switch Access, Voice
 *   Access, ...) leave out copy, cut and share, and the actions TextView adds
 *   for other apps that process text (PROCESS_TEXT: "Translate" and the like,
 *   which would receive the selected words in an Intent) and for the text
 *   classifier's "smart" actions. A request for one of them through
 *   [performAccessibilityAction] does nothing, whether or not it was offered.
 *   The other actions a screen reader needs (focus, click, selection, paste,
 *   set text, the keyboard action, ...) are kept.
 * - **Clipboard, undo and menus**: copy, cut, share, autofill, undo and redo
 *   are refused. In the platform's TextView the floating menu, the right-click
 *   menu and the hardware keyboard shortcuts (Ctrl+C, Ctrl+Z, ...) all go
 *   through [onTextContextMenuItem], where they are refused; the accessibility
 *   copy, cut and share actions are refused before they reach it (above).
 *   Undo is refused because the undo history keeps the text an edit removed:
 *   emptying the field and then undoing would bring the words back. The
 *   selection, insertion and right-click menus show only paste and select all.
 *   Paste stays: it brings nothing out of the field.
 * - **Drag and drop**: a long press, or a mouse drag, on selected text starts a
 *   drag that another app's window (split screen, freeform) could take as a
 *   drop. The field cancels any drag right after one of those two gestures; the
 *   text reaches a receiver only on a drop, which then never comes.
 * - **Host window**: once attached, the field checks that its window has
 *   FLAG_SECURE, and sets it if not (with a warning in the log). This is a
 *   fallback: the screen should set it itself in `onCreate`
 *   ([rs.readahead.washington.mobile.views.base_ui.refuseScreenCapture]),
 *   because the window may already have drawn a frame when the field is
 *   attached, and on API 29 Content Capture is only turned off by that call.
 *
 * What this does NOT guarantee:
 *
 * - The keyboard is a separate app that receives every keystroke and can read
 *   the field's whole text through its input connection. The input type and
 *   IME flags only ask it not to suggest, learn or show the text elsewhere; a
 *   keyboard that ignores them, or that is malicious, is not stopped by this
 *   view. The structural answer would be an in-app keypad, as the PIN screens
 *   have; there is none for the phrase today.
 * - `accessibilityDataSensitive` does nothing below API 34, and on API 34+ it
 *   still lets through any accessibility service that declares itself an
 *   accessibility tool.
 * - The refused accessibility ids for share, PROCESS_TEXT and smart actions
 *   are private values of TextView, read in one version of its sources; a
 *   platform build that numbered them otherwise would offer those actions
 *   again. The instrumented test checks the share and PROCESS_TEXT ids against
 *   the TextView of the device it runs on. It does not check the smart ones
 *   there: with the field's no-op classifier, TextView (in those sources)
 *   adds no smart action to the node, so the device shows none to compare,
 *   and only the values read in the sources are tested.
 * - Autofill and Content Capture exclusions are honoured by the system
 *   framework of the device, not enforced by this view.
 * - Cancelling a drag is done by the field after the platform started it; a
 *   drag started some other way than the two gestures above is not watched.
 * - The undo history still records edits in memory; only layouts can turn it
 *   off (`android:allowUndo="false"`, which the secret layouts set).
 * - The text lives in the field's buffer and in the `String`s the code reads
 *   from it; neither is wiped by this view.
 */
class SecretEditText : AppCompatEditText {

    constructor(context: Context) : super(context)
    constructor(context: Context, attrs: AttributeSet?) : super(context, attrs)
    constructor(context: Context, attrs: AttributeSet?, defStyleAttr: Int) :
        super(context, attrs, defStyleAttr)

    init {
        // Each call goes through the overrides below, which apply the
        // protections whatever value is passed. The overrides may already have
        // run during the superclass constructor (the layout's attributes are
        // applied there): they read no field of this class, so that is safe.
        setRawInputType(inputType)
        setImeOptions(imeOptions)
        isSaveEnabled = false
        isSaveFromParentEnabled = false
        customSelectionActionModeCallback = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            customInsertionActionModeCallback = null
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setTextClassifier(TextClassifier.NO_OP)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
    }

    // ---- what the keyboard is told ----

    override fun setInputType(type: Int) {
        super.setInputType(secureInputType(type))
    }

    override fun setRawInputType(type: Int) {
        super.setRawInputType(secureInputType(type))
    }

    /**
     * TextView takes the input type of the new listener without going through
     * a setter, and the spell checker reads that type. A null listener makes
     * the field non-editable (no input type at all), which is left as is.
     */
    override fun setKeyListener(input: KeyListener?) {
        super.setKeyListener(input)
        if (input != null) setRawInputType(inputType)
    }

    override fun setImeOptions(imeOptions: Int) {
        super.setImeOptions(imeOptions or SECURE_IME_FLAGS)
    }

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        val connection = super.onCreateInputConnection(outAttrs)
        outAttrs.inputType = secureInputType(outAttrs.inputType)
        outAttrs.imeOptions = outAttrs.imeOptions or SECURE_IME_FLAGS
        return connection
    }

    // ---- saved state ----

    override fun setSaveEnabled(enabled: Boolean) {
        super.setSaveEnabled(false)
    }

    override fun setSaveFromParentEnabled(enabled: Boolean) {
        super.setSaveFromParentEnabled(false)
    }

    /** An EditText answers true here, which puts its text in its saved state. */
    override fun getFreezesText(): Boolean = false

    // ---- autofill, content capture, text classification ----

    @RequiresApi(Build.VERSION_CODES.O)
    override fun setImportantForAutofill(mode: Int) {
        super.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun getAutofillType(): Int = View.AUTOFILL_TYPE_NONE

    @RequiresApi(Build.VERSION_CODES.O)
    override fun getAutofillValue(): AutofillValue? = null

    @RequiresApi(Build.VERSION_CODES.R)
    override fun setImportantForContentCapture(mode: Int) {
        super.setImportantForContentCapture(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun setTextClassifier(textClassifier: TextClassifier?) {
        super.setTextClassifier(TextClassifier.NO_OP)
    }

    // ---- accessibility ----

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun setAccessibilityDataSensitive(accessibilityDataSensitive: Int) {
        super.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
    }

    /** What accessibility services are offered, without the refused actions. */
    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        for (action in info.actionList.filter { isRefusedAccessibilityAction(it.id) }) {
            info.removeAction(action)
        }
    }

    /**
     * A refused action is turned down here, before TextView or an
     * accessibility delegate sees it. TextView runs a PROCESS_TEXT action,
     * which starts the other app with the selected text, ahead of everything
     * else, [onTextContextMenuItem] included. It keeps the ids of those
     * actions in a list of its own, filled when the field gets accessibility
     * focus, so a service can ask for one that the node above no longer shows.
     */
    override fun performAccessibilityAction(action: Int, arguments: Bundle?): Boolean =
        if (isRefusedAccessibilityAction(action)) false else super.performAccessibilityAction(action, arguments)

    // ---- host window ----

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        val root = rootView
        val params = root.layoutParams as? WindowManager.LayoutParams ?: return
        if (params.flags and WindowManager.LayoutParams.FLAG_SECURE != 0) return
        Timber.w("SecretEditText attached to a window without FLAG_SECURE: setting it")
        params.flags = params.flags or WindowManager.LayoutParams.FLAG_SECURE
        (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).updateViewLayout(root, params)
    }

    // ---- clipboard, undo and menus ----

    /**
     * Every copy, cut, share, autofill, undo or redo request from a menu or a
     * key ends here: the floating menu, the right-click menu and a hardware
     * keyboard shortcut all call this method. TextView would also route the
     * accessibility copy, cut and share actions here; [performAccessibilityAction]
     * refuses them first. Answering false performs nothing.
     */
    override fun onTextContextMenuItem(id: Int): Boolean =
        if (id in REFUSED_ITEMS) false else super.onTextContextMenuItem(id)

    override fun setCustomSelectionActionModeCallback(actionModeCallback: ActionMode.Callback?) {
        super.setCustomSelectionActionModeCallback(MenuFilter.around(actionModeCallback))
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun setCustomInsertionActionModeCallback(actionModeCallback: ActionMode.Callback?) {
        super.setCustomInsertionActionModeCallback(MenuFilter.around(actionModeCallback))
    }

    /**
     * The right-click menu (mouse or trackpad, API 24+) is built by the
     * platform without the callbacks above; its clicks already reach
     * [onTextContextMenuItem]. Hiding the refused items keeps it from offering
     * actions that do nothing.
     */
    override fun onCreateContextMenu(menu: ContextMenu) {
        super.onCreateContextMenu(menu)
        hideRefused(menu)
    }

    // ---- drag and drop ----

    override fun performLongClick(): Boolean {
        val couldDrag = canStartDrag()
        val handled = super.performLongClick()
        if (couldDrag && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) cancelDragAndDrop()
        return handled
    }

    /** The click itself is left to TextView, as is the rest of the gesture. */
    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        val couldDrag = canStartDrag() &&
            event.actionMasked == MotionEvent.ACTION_MOVE && event.isFromSource(InputDevice.SOURCE_MOUSE)
        val handled = super.onTouchEvent(event)
        if (couldDrag && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) cancelDragAndDrop()
        return handled
    }

    /**
     * The platform starts a drag of the selected text from a long press inside
     * the selection, or from a mouse drag over it, synchronously in the two
     * methods above; the drag is cancelled before either returns. Whether
     * there was a selection is read before: starting the drag closes the
     * selection menu, which collapses the selection. When no drag started, the
     * cancel only logs "No active drag to cancel". Below API 24 a drag cannot
     * leave the window, and there is nothing to cancel.
     */
    private fun canStartDrag(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && isAttachedToWindow && hasSelection()

    /**
     * Hands over to the callback the code set, if any, then hides every menu
     * item but [ALLOWED_ITEMS], and swallows a click on any other item. Hiding
     * by allow-list also removes the items other apps add to the menu
     * ("Translate" and the like receive the selected text) and the assist
     * items, which have no fixed id to refuse. The platform adds some of them
     * after `onCreateActionMode` and before `onPrepareActionMode`: both hide.
     * For the other apps' items, hiding is the protection: the platform runs
     * a click on one of them before it asks this callback.
     */
    private class MenuFilter private constructor(private val inner: ActionMode.Callback?) :
        ActionMode.Callback {

        override fun onCreateActionMode(mode: ActionMode?, menu: Menu?): Boolean {
            val keep = inner?.onCreateActionMode(mode, menu) ?: true
            menu?.let { hideRefused(it) }
            return keep
        }

        override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?): Boolean {
            inner?.onPrepareActionMode(mode, menu)
            menu?.let { hideRefused(it) }
            return true
        }

        override fun onActionItemClicked(mode: ActionMode?, item: MenuItem?): Boolean {
            if (item == null || item.itemId !in ALLOWED_ITEMS) return true
            return inner?.onActionItemClicked(mode, item) ?: false
        }

        override fun onDestroyActionMode(mode: ActionMode?) {
            inner?.onDestroyActionMode(mode)
        }

        companion object {
            fun around(callback: ActionMode.Callback?): ActionMode.Callback =
                callback as? MenuFilter ?: MenuFilter(callback)
        }
    }

    internal companion object {
        // The constants below are inlined at compile time. A device older than
        // the API that introduced one never sends that id, and a keyboard that
        // does not know an IME flag ignores it.

        @SuppressLint("InlinedApi")
        const val SECURE_IME_FLAGS = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
            EditorInfo.IME_FLAG_NO_EXTRACT_UI or
            EditorInfo.IME_FLAG_NO_FULLSCREEN

        @SuppressLint("InlinedApi")
        val REFUSED_ITEMS = setOf(
            android.R.id.copy,
            android.R.id.cut,
            android.R.id.shareText,
            android.R.id.autofill,
            android.R.id.undo,
            android.R.id.redo,
        )

        @SuppressLint("InlinedApi")
        val ALLOWED_ITEMS = setOf(
            android.R.id.paste,
            android.R.id.pasteAsPlainText,
            android.R.id.selectAll,
        )

        /**
         * The accessibility actions TextView adds under ids of its own (private
         * constants of TextView, values read in the android-36.1 sources): share
         * at 0x10000000, then two ranges numbered up from a start, one id per
         * action. The PROCESS_TEXT actions of other apps start at 0x10000100,
         * up to the next range, which starts at 0x10001000 with the text
         * classifier's "smart" actions. TextView sets no end to that one; a
         * classification carries a handful of actions, far fewer than the 4096
         * ids taken here. Every other id is left alone: the standard actions,
         * the framework's `android.R.id` ones, and the app's own resource ids,
         * which androidx uses for custom actions.
         */
        private const val A11Y_SHARE = 0x10000000
        private val A11Y_PROCESS_TEXT = 0x10000100 until 0x10001000
        private val A11Y_SMART = 0x10001000 until 0x10002000

        fun isRefusedAccessibilityAction(id: Int): Boolean =
            id == AccessibilityNodeInfo.ACTION_COPY ||
                id == AccessibilityNodeInfo.ACTION_CUT ||
                id == A11Y_SHARE ||
                id in A11Y_PROCESS_TEXT ||
                id in A11Y_SMART

        private const val KEPT_FLAGS =
            InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_IME_MULTI_LINE

        /** Text, visible password, no suggestions; only the multi-line flags survive. */
        fun secureInputType(requested: Int): Int =
            InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                (requested and KEPT_FLAGS)

        fun hideRefused(menu: Menu) {
            for (i in 0 until menu.size()) {
                val item = menu.getItem(i)
                if (item.itemId !in ALLOWED_ITEMS) item.isVisible = false
            }
        }
    }
}
