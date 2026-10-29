package rs.readahead.washington.mobile.diagnostics

import timber.log.Timber

/**
 * The Timber tree of a pre-release test build: every log call of the app, at
 * every priority including VERBOSE and DEBUG, with its tag, message and stack
 * trace, handed to [DiagnosticsLog] (which redacts and stores it off the
 * calling thread). It writes nothing to logcat.
 *
 * An untagged call is tagged with the calling class's simple name, found by
 * walking the stack past Timber's own frames ([callerTag]); the walk costs a
 * stack trace per untagged call, on the calling thread. Do not swap it for
 * Timber.DebugTree's tag: that one reads a fixed stack depth, which R8's
 * inlining in a release build changes, and it throws when the stack comes out
 * shorter than it expects. On a minified release build the name found is the
 * obfuscated one; the build's R8 mapping file
 * (mobile/build/outputs/mapping/release/mapping.txt) turns it, and the stack
 * traces, back into source names.
 *
 * Lines tagged [OWN_TAG] are ignored: the diagnostics code logs through
 * android.util.Log under that tag, and a line of its own coming back here
 * could loop (a write failure logged, stored, failing again).
 */
internal class DiagnosticsTree(private val log: DiagnosticsLog) : Timber.Tree() {

    override fun isLoggable(tag: String?, priority: Int): Boolean = tag != OWN_TAG

    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (tag == OWN_TAG) return
        log.submit(Entry(System.currentTimeMillis(), priority, tag ?: callerTag(), Thread.currentThread().name, message))
    }

    // Runtime names, so that they still match once R8 has renamed the classes.
    private val timberClasses = setOf(
        Timber::class.java.name,
        Timber.Tree::class.java.name,
        Timber.asTree().javaClass.name,
        DiagnosticsTree::class.java.name,
    )

    private fun callerTag(): String {
        for (frame in Throwable().stackTrace) {
            if (frame.className in timberClasses) continue
            return frame.className.substringAfterLast('.').substringBefore('$')
        }
        return "-"
    }

    companion object {
        const val OWN_TAG = "FrappDiag"
    }
}
