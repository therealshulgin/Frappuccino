package rs.readahead.washington.mobile.views.activity.onboarding

import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import rs.readahead.washington.mobile.R

/**
 * The confirmation screen of the recovery phrase (three words typed back) and
 * its error message. A message about earlier words must not stay on screen
 * once the words change or pass: shown above emptied boxes when the witness
 * comes back from the PIN screen, it reads as "the phrase you wrote down is
 * wrong".
 *
 * The screen is put on the onboarding activity directly, as the generation
 * screen does, with a known phrase in [MnemonicHolder].
 *
 * The screen hides the error in two places: when a box is typed in, and when
 * a confirmation passes. Removing the first, for any one of the three boxes,
 * makes the second test fail, removing the second makes the third fail; the
 * first test, the path a witness takes, fails only when both are gone, since
 * on that path the correct words are typed in before the confirmation.
 */
@RunWith(AndroidJUnit4::class)
class OnBoardMnemonicConfirmInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @After
    fun dropThePhrase() {
        MnemonicHolder.clear()
    }

    @Test
    fun back_from_the_pin_screen_shows_no_error_over_the_emptied_boxes() {
        onConfirmScreen { scenario, screen ->
            scenario.onActivity {
                screen.type(listOf("faux", "faux", "faux"))
                screen.confirm.performClick()
                assertEquals("the error never showed: the test reaches nothing", View.VISIBLE, screen.error.visibility)
            }
            scenario.onActivity {
                screen.type(screen.expected())
                screen.confirm.performClick()
                it.supportFragmentManager.executePendingTransactions()
                assertTrue("the PIN screen did not open", it.supportFragmentManager.fragments.any { f -> f is OnBoardSetPinFragment })
                assertTrue("the confirmation screen is still shown", screen.fragment.isHidden)
            }
            instrumentation.waitForIdleSync()
            scenario.onActivity {
                // What the PIN screen's back button does.
                @Suppress("DEPRECATION")
                it.onBackPressed()
                it.supportFragmentManager.executePendingTransactions()
            }
            instrumentation.waitForIdleSync()
            scenario.onActivity {
                assertFalse("the confirmation screen is not back", screen.fragment.isHidden)
                assertEquals("boxes not emptied", listOf("", "", ""), screen.inputs.map { box -> box.text.toString() })
                assertEquals("the error is still shown", View.GONE, screen.error.visibility)
            }
        }
    }

    @Test
    fun the_error_goes_as_soon_as_a_box_is_typed_in_again() {
        onConfirmScreen { scenario, screen ->
            scenario.onActivity {
                // Each box on its own: the error must go whichever one is
                // typed in, not only the one a test happens to use.
                for ((i, box) in screen.inputs.withIndex()) {
                    screen.type(listOf("faux", "faux", "faux"))
                    screen.confirm.performClick()
                    assertEquals("box ${i + 1}: the error never showed: the test reaches nothing", View.VISIBLE, screen.error.visibility)

                    // Emptying a box is not typing a new word: the error stays.
                    box.setText("")
                    assertEquals("box ${i + 1}: emptying it removed the error", View.VISIBLE, screen.error.visibility)
                    box.append("a")
                    assertEquals("box ${i + 1}: the error stayed after it was typed in", View.GONE, screen.error.visibility)
                }
            }
        }
    }

    @Test
    fun a_confirmation_that_passes_hides_an_error_left_on_screen() {
        onConfirmScreen { scenario, screen ->
            scenario.onActivity {
                screen.type(screen.expected())
                // Stands for a message an earlier attempt left on screen: the
                // boxes are then emptied, which does not count as typing.
                screen.error.visibility = View.VISIBLE
                screen.confirm.performClick()
                assertEquals("boxes not emptied", listOf("", "", ""), screen.inputs.map { box -> box.text.toString() })
                assertEquals("the error is still shown", View.GONE, screen.error.visibility)
            }
        }
    }

    // ---- helpers ----

    private class Screen(val fragment: OnBoardMnemonicConfirmFragment) {
        private val view = fragment.requireView()
        val inputs: List<EditText> = listOf(R.id.wordInput1, R.id.wordInput2, R.id.wordInput3).map { view.findViewById(it) }
        val labels: List<TextView> = listOf(R.id.wordLabel1, R.id.wordLabel2, R.id.wordLabel3).map { view.findViewById(it) }
        val error: TextView = view.findViewById(R.id.errorText)
        val confirm: View = view.findViewById(R.id.confirmBtn)

        /** The words the screen asks for, read from its labels ("Mot #N"). */
        fun expected(): List<String> = labels.map { label ->
            PHRASE[label.text.toString().substringAfter('#').trim().toInt() - 1]
        }

        fun type(words: List<String>) {
            inputs.zip(words).forEach { (box, word) -> box.setText(word) }
        }
    }

    private fun onConfirmScreen(block: (ActivityScenario<OnBoardingActivity>, Screen) -> Unit) {
        MnemonicHolder.set(PHRASE.joinToString(" ").toByteArray(Charsets.UTF_8))
        val scenario = ActivityScenario.launch(OnBoardingActivity::class.java)
        try {
            lateinit var screen: Screen
            scenario.onActivity { activity ->
                val fragment = OnBoardMnemonicConfirmFragment()
                activity.addFragment(fragment, R.id.rootOnboard)
                activity.supportFragmentManager.executePendingTransactions()
                screen = Screen(fragment)
            }
            block(scenario, screen)
        } finally {
            scenario.close()
        }
    }

    private companion object {
        /** Twelve words in ASCII, so that what is typed equals what is held. */
        val PHRASE = listOf(
            "abaisser", "abandon", "abdiquer", "abeille", "abolir", "aborder",
            "aboutir", "aboyer", "abrasif", "abreuver", "abriter", "abroger",
        )
    }
}
