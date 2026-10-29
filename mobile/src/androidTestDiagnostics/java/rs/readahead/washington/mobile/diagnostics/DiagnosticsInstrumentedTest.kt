package rs.readahead.washington.mobile.diagnostics

import android.app.Application
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.Configuration
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.stream.crypto.SecureDirWiper
import rs.readahead.washington.mobile.BuildConfig
import rs.readahead.washington.mobile.util.AppPanicDirs
import timber.log.Timber
import java.io.File
import java.util.UUID

/**
 * The diagnostics on a live Android system, in the app's own process (the
 * test runs inside the app, so MyApplication has installed them). What a JVM
 * test cannot stand in for: the platform APIs of the device profile, the
 * app's own logcat, and the emergency wipe going through the real call the
 * settings screen makes ([AppPanicDirs.detach]).
 *
 * Nothing is sent: on an emulator the upload pass stops before the network
 * ([Diagnostics.runsOnEmulator]).
 */
@RunWith(AndroidJUnit4::class)
class DiagnosticsInstrumentedTest {

    private val app: Application = ApplicationProvider.getApplicationContext()

    @Test
    fun the_device_profile_describes_the_phone_without_failing_a_section() {
        val profile = DeviceProfile.collect(app)
        Log.i("DiagTest", profile)
        for (key in listOf("build.model=", "build.sdk=", "app.version_name=${BuildConfig.VERSION_NAME}",
                "camera.ids=", "state.camera_permission=")) {
            assertTrue("$key missing from:\n$profile", profile.contains(key))
        }
        assertTrue("an encoder line", profile.contains("codec.video/avc name="))
        for (section in listOf("build", "app", "codec", "state")) {
            assertFalse("$section failed:\n$profile", profile.contains("$section.error="))
        }
    }

    @Test
    fun the_logcat_capture_has_the_app_s_own_lines_redacted() {
        val marker = "diagtest-" + UUID.randomUUID().toString().take(8)
        Log.i("DiagTest", "$marker session 0123456789abcdef0123456789abcdef")
        // logd stores the line asynchronously, and a loaded emulator can take
        // a while: capture again until it is there. The app itself captures
        // at upload time, long after its lines were logged.
        var capture = ""
        waitFor("the marker to reach logcat", timeoutMs = 20_000) {
            capture = LogcatCapture.capture()
            capture.lines().any { it.contains(marker) }
        }
        val line = capture.lines().firstOrNull { it.contains(marker) }
        assertNotNull("marker not in the capture", line)
        assertTrue(line, line!!.contains("session <hex>"))
        assertFalse(capture.contains("0123456789abcdef0123456789abcdef"))
    }

    @Test
    fun the_emergency_wipe_takes_the_diagnostics_log_and_the_install_id() {
        val store = Diagnostics.storeForTest
        assertNotNull("diagnostics not installed by MyApplication", store)
        val marker = "before-wipe-" + UUID.randomUUID().toString().take(8)
        Timber.tag("DiagTest").i(marker)
        waitFor("the line to be stored") { stored(store!!.dir).contains(marker) }
        val oldId = InstallId.get(app)
        val prefs = File(app.filesDir.parentFile, "shared_prefs/${DiagnosticsNames.PREFS}.xml")
        waitFor("the install id to be written") { prefs.exists() } // apply(), not commit()
        try {
            val detached = AppPanicDirs.detach(app)

            assertFalse("the directory is still under its name", store!!.dir.exists())
            val moved = detached.plaintext.single { it.name.startsWith(DiagnosticsNames.DIR + ".wipe-") }
            assertTrue("handed over as plaintext, with the line", stored(moved).contains(marker))
            assertFalse("the install id file is still there", prefs.exists())

            // Nothing logged after the wipe is stored, the wipe included.
            Timber.tag("DiagTest").i("after-wipe")
            Thread.sleep(500)
            assertFalse(store.dir.exists())

            detached.plaintext.forEach(SecureDirWiper::wipeTree)
            assertFalse(moved.exists())
            assertNotEquals("a fresh install id after the wipe", oldId, InstallId.get(app))
        } finally {
            Diagnostics.restartForTest(app)
        }
    }

    @Test
    fun an_emulator_sends_nothing() {
        assumeTrue("not an emulator", Diagnostics.runsOnEmulator())
        val store = Diagnostics.storeForTest!!
        Timber.tag("DiagTest").i("emulator-pass")
        waitFor("the line to be stored") { stored(store.dir).contains("emulator-pass") }
        InstallId.forget(app)
        val before = store.dir.listFiles()!!.map { it.name to it.length() }.toSet()
        assertTrue(Diagnostics.uploadPass(app))
        // A pass that went on would have drawn an install id and closed the
        // current file for sending.
        val prefs = File(app.filesDir.parentFile, "shared_prefs/${DiagnosticsNames.PREFS}.xml")
        Thread.sleep(300)
        assertFalse("an install id was drawn", prefs.exists())
        assertEquals(before, store.dir.listFiles()!!.map { it.name to it.length() }.toSet())
    }

    @Test
    fun uploads_are_unique_work_kept_across_triggers() {
        WorkManagerTestInitHelper.initializeTestWorkManager(
            app, Configuration.Builder().setExecutor(SynchronousExecutor()).build(),
        )
        val wm = WorkManager.getInstance(app)
        DiagnosticsUploadWorker.schedule(app)
        val first = wm.getWorkInfosForUniqueWork(DiagnosticsNames.UPLOAD_WORK).get().single().id
        DiagnosticsUploadWorker.schedule(app)
        DiagnosticsUploadWorker.requestUpload(app)
        assertEquals(first, wm.getWorkInfosForUniqueWork(DiagnosticsNames.UPLOAD_WORK).get().single().id)
        assertEquals(1, wm.getWorkInfosForUniqueWork(DiagnosticsNames.PERIODIC_WORK).get().size)
        assertTrue(wm.getWorkInfosByTag(DiagnosticsUploadWorker.TAG).get().isNotEmpty())
    }

    private fun stored(dir: File): String =
        (dir.listFiles() ?: emptyArray()).sortedBy { it.name }.joinToString("") { it.readText() }

    private fun waitFor(what: String, timeoutMs: Long = 5_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!condition()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("timed out waiting for $what")
            Thread.sleep(50)
        }
    }
}
