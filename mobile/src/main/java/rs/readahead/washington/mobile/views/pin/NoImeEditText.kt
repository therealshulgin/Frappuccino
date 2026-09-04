package rs.readahead.washington.mobile.views.pin

import android.content.Context
import android.util.AttributeSet
import android.view.inputmethod.InputMethodManager

/**
 * An EditText that never raises the soft keyboard. Do not drop the two
 * overrides below and do not swap this view for a plain AppCompatEditText:
 * it is only the "dots" display, the digits of the PIN come from the in-app
 * keypad [org.hzontal.shared_ui.pinview.PinLockView], never from the IME: both
 * consumers only mirror the digits in here with setText.
 *
 * This is a verbatim copy of a component of the `tella-locking-ui` module,
 * removed since (it was `com.hzontal.tella_locking_ui.ui.pin.edit_text.NoImeEditText`,
 * relocated here in 6.1.16). It is upstream Tella code rather than something
 * written for this app, and that fully-qualified name is the only remaining
 * link to its history. Its only consumers are the two V2 PIN screens,
 * PinUnlockActivity and OnBoardSetPinFragment, both of which reach it through
 * their layouts as well as their imports.
 */
class NoImeEditText @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : androidx.appcompat.widget.AppCompatEditText(context, attrs, defStyleAttr) {

    /**
     * Called before the keyboard appears when text is selected — hide it.
     */
    override fun onCheckIsTextEditor(): Boolean {
        hideKeyboard()
        return super.onCheckIsTextEditor()
    }

    /**
     * Called when text selection changes — hide the keyboard to prevent it
     * from appearing.
     */
    override fun onSelectionChanged(selStart: Int, selEnd: Int) {
        super.onSelectionChanged(selStart, selEnd)
        hideKeyboard()
    }

    private fun hideKeyboard() {
        val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        imm.hideSoftInputFromWindow(windowToken, 0)
    }
}
