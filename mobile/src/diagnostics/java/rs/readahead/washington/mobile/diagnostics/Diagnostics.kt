package rs.readahead.washington.mobile.diagnostics

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.os.Build
import android.util.Log
import org.stream.crypto.DetachedDirs
import org.stream.crypto.SecureDirWiper
import rs.readahead.washington.mobile.BuildConfig
import timber.log.Timber
import java.io.File

/**
 * Diagnostics of a pre-release test build. mobile/build.gradle compiles this
 * source set only for a version name ending in -testN; a production version
 * gets the facade of src/diagnosticsOff/java instead, with the same three
 * calls and none of what follows.
 *
 * A temporary, deliberate exception to "everything leaves the phone and a
 * seizure exposes nothing", for test builds: the app's complete log, its own
 * logcat and a description of the phone go to the test relay, so that a
 * problem seen on a tester's phone can be diagnosed. Bounded by what follows.
 *
 *  - Every line is redacted before it is stored or sent ([LogRedactor]).
 *  - On the phone: `filesDir/diag/`, at most 2 MiB ([SpillStore]), sent
 *    and then deleted.
 *  - Sent without any credential and without anything from the witness's
 *    identity, under a random install id ([InstallId], [DiagnosticsHttp]).
 *  - The emergency wipe erases the directory as plaintext, forgets the install
 *    id and stops collection until the process restarts ([detachForPanic]).
 *  - Nothing is sent from the Android Emulator (other emulators are not
 *    detected): a CI run or a developer's emulator would otherwise post its
 *    logs to the test relay at every test run.
 *
 * The diagnostics code logs through android.util.Log under
 * [DiagnosticsTree.OWN_TAG], never through Timber (hence LogNotTimber off).
 */
@SuppressLint("LogNotTimber")
object Diagnostics {

    private class Runtime(
        val store: SpillStore,
        val log: DiagnosticsLog,
        val tree: DiagnosticsTree,
        val previousHandler: Thread.UncaughtExceptionHandler?,
    )

    @Volatile
    private var runtime: Runtime? = null

    @Volatile
    private var wipedInThisProcess = false

    // One pass at a time across the one-time and the periodic work, and one
    // more after a recording that ends during a pass.
    private val passes = UploadPasses()

    /** Plant the tree, install the crash recorder, schedule the uploads. */
    fun install(app: Application) {
        synchronized(this) {
            if (runtime != null) return
            try {
                // An erase that a process death interrupted.
                SecureDirWiper.finishLeftovers(app.filesDir, listOf(DiagnosticsNames.DIR))
                val store = SpillStore(File(app.filesDir, DiagnosticsNames.DIR), SecureDirWiper::detach)
                val log = DiagnosticsLog(store)
                val tree = DiagnosticsTree(log)
                val previous = Thread.getDefaultUncaughtExceptionHandler()
                Timber.plant(tree)
                Thread.setDefaultUncaughtExceptionHandler(CrashRecorder(log, previous))
                runtime = Runtime(store, log, tree, previous)
            } catch (t: Throwable) {
                Log.w(DiagnosticsTree.OWN_TAG, "diagnostics not installed", t)
                return
            }
        }
        try {
            DiagnosticsUploadWorker.schedule(app)
        } catch (e: Exception) {
            Log.w(DiagnosticsTree.OWN_TAG, "diagnostics upload not scheduled", e)
        }
    }

    /**
     * Request an upload once a recording's teardown is over, so that the
     * lines of a recording that failed to start leave without waiting for the
     * periodic pass. A pass running now is followed by one more
     * ([UploadPasses]).
     */
    fun onRecordingFinished(context: Context) {
        if (runtime == null || wipedInThisProcess) return
        passes.requestRerun()
        try {
            DiagnosticsUploadWorker.requestUpload(context)
        } catch (e: Exception) {
            Log.w(DiagnosticsTree.OWN_TAG, "diagnostics upload not requested", e)
        }
    }

    /**
     * Emergency wipe: renames the diagnostics directory out of reach, now,
     * and hands it over as plaintext for the wipe's single erase pass. Also
     * forgets the install id, drops what is queued, and stops collecting and
     * sending for the rest of this process, so that nothing logged after the
     * wipe (the wipe itself, to begin with) is stored. Its `afterErase` clears
     * the app's own logcat entries, best effort ([LogcatCapture.clearOwn]).
     */
    fun detachForPanic(context: Context): DetachedDirs {
        wipedInThisProcess = true
        val rt = runtime
        rt?.log?.stopForWipe()
        // The store renames under its lock, after any write in progress.
        val moved = rt?.store?.detach() ?: SecureDirWiper.detach(File(context.filesDir, DiagnosticsNames.DIR))
        try {
            InstallId.forget(context)
        } catch (e: Exception) {
            Log.w(DiagnosticsTree.OWN_TAG, "install id not forgotten", e)
        }
        return DetachedDirs(
            plaintext = listOfNotNull(moved),
            afterErase = { LogcatCapture.clearOwn() },
        )
    }

    /**
     * One upload pass, for [DiagnosticsUploadWorker]. True when done (or
     * nothing to do), false to be retried.
     */
    internal fun uploadPass(context: Context): Boolean {
        val rt = runtime ?: return true
        if (wipedInThisProcess) return true
        if (runsOnEmulator()) {
            Log.i(DiagnosticsTree.OWN_TAG, "emulator: diagnostics are kept on the device, not sent")
            return true
        }
        return passes.run {
            DiagnosticsUploader(
                store = rt.store,
                installId = { InstallId.get(context) },
                profile = { DeviceProfile.collect(context) },
                logcat = { LogcatCapture.capture() },
                send = { body, id -> DiagnosticsHttp.post(body, id, BuildConfig.VERSION_NAME) },
            ).run()
        }
    }

    /** The store of this process, for the instrumented tests. */
    internal val storeForTest: SpillStore? get() = runtime?.store

    /**
     * What a process restart does after a wipe: a fresh store, log and tree.
     * For the instrumented tests, which run in a single process and must not
     * leave diagnostics stopped for the tests that follow.
     */
    internal fun restartForTest(app: Application) {
        synchronized(this) {
            runtime?.let { rt ->
                Timber.uproot(rt.tree)
                Thread.setDefaultUncaughtExceptionHandler(rt.previousHandler)
            }
            runtime = null
            wipedInThisProcess = false
        }
        install(app)
    }

    /** The Android Emulator's virtual boards (goldfish, then ranchu). */
    internal fun runsOnEmulator(): Boolean = Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish"
}
