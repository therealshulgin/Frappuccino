package rs.readahead.washington.mobile.views

import android.app.Activity
import android.os.Bundle

/**
 * Stands for another app's "process text" action (a translator, say), declared
 * in the androidTest manifest. The tests intercept its launch before it
 * happens; if it ever starts, it closes at once.
 */
class ProcessTextFixtureActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
