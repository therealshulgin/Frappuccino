package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import rs.readahead.washington.mobile.BuildConfig
import rs.readahead.washington.mobile.views.SourceText
import java.io.File

/**
 * The diagnostics are a pre-release test build's and nobody else's, and the
 * app reaches them where it must. Runs in both channels: in a production
 * build it is what proves the uploader is absent.
 *
 * The wiring checks read the source (comments blanked, see [SourceText]):
 * the calls sit in an Application, an Activity dialog and a Service teardown,
 * none of which a JVM test can drive.
 */
class DiagnosticsChannelTest {

    @Test
    fun `the diagnostics flag follows the version name`() {
        assertEquals(Regex(""".*-test\d+""").matches(BuildConfig.VERSION_NAME), BuildConfig.PREPROD_DIAGNOSTICS)
    }

    @Test
    fun `the uploader is compiled into a test build and only there`() {
        for (name in listOf("DiagnosticsUploadWorker", "DiagnosticsHttp", "DiagnosticsTree")) {
            val present = try {
                Class.forName("rs.readahead.washington.mobile.diagnostics.$name")
                true
            } catch (e: ClassNotFoundException) {
                false
            }
            assertEquals("$name present", BuildConfig.PREPROD_DIAGNOSTICS, present)
        }
    }

    @Test
    fun `the emergency wipe hands the app's directories to panicWipe`() {
        val code = code("rs.readahead.washington.mobile.views.activity.StreamSettingsActivity")
        assertTrue(
            "the panicWipe lambda must return AppPanicDirs.detach(...)",
            Regex("""panicWipe\s*\{[^}]*\bAppPanicDirs\.detach\(""").containsMatchIn(code),
        )
    }

    @Test
    fun `the app's directories include the diagnostics log and the archive viewer's`() {
        val code = code("rs.readahead.washington.mobile.util.AppPanicDirs")
        val detach = code.substringAfter("fun detach(").substringBefore("fun combine(")
        assertTrue("Diagnostics.detachForPanic missing", detach.contains("Diagnostics.detachForPanic(context)"))
        assertTrue("ArchiveLocalData.detachForPanic missing", detach.contains("ArchiveLocalData.detachForPanic(context)"))
    }

    @Test
    fun `the application installs the diagnostics and the recording teardown requests an upload`() {
        val app = code("rs.readahead.washington.mobile.MyApplication")
        assertTrue(Regex("""\bDiagnostics\.INSTANCE\.install\(this\)""").containsMatchIn(app))
        val service = code("rs.readahead.washington.mobile.service.StreamRecordingService")
        val teardown = service.substringAfter("private fun finishTeardown(").substringBefore("override fun onDestroy(")
        assertTrue(teardown.contains("Diagnostics.onRecordingFinished(this)"))
    }

    @Test
    fun `the production facade removes what a test build left`() {
        // Read from its directory, since a test build does not compile it.
        val main = SourceText.paths(SourceText.SRC_DIRS_PROPERTY).single {
            SourceText.moduleOf(it) == "mobile" && it.name == "java" && it.parentFile?.name == "main"
        }
        val src = main.parentFile?.parentFile ?: throw AssertionError("$main is not under src/main")
        val file = File(src, "diagnosticsOff/java/rs/readahead/washington/mobile/diagnostics/Diagnostics.kt")
        val install = SourceText.strip(file.readText(), nested = true)
            .substringAfter("fun install(").substringBefore("fun onRecordingFinished(")
        for (call in listOf(
            "cancelUniqueWork(DiagnosticsNames.UPLOAD_WORK)",
            "cancelUniqueWork(DiagnosticsNames.PERIODIC_WORK)",
            "DiagnosticsLeftovers.detach(app.filesDir)",
            "SecureDirWiper.wipeInBackground(dirs",
        )) {
            assertTrue("$call missing from the production install()", install.contains(call))
        }
    }

    private fun code(className: String): String =
        SourceText.sources().singleOrNull { it.className == className }?.code
            ?: throw AssertionError("no single source for $className")
}
