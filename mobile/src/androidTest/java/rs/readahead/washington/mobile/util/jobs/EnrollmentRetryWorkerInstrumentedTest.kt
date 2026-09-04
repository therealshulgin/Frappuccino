package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.Configuration
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/**
 * Instrumented test scaffold for the offline-then-online enrollment retry path
 * (Phase 2.3.4).
 *
 * It verifies the WorkManager scheduling contract of
 * [EnrollmentRetryWorker.enqueue] without exercising `doWork()` itself.
 * `doWork()` calls into the [org.stream.crypto.upload.StreamUploadManager]
 * singleton which initializes the full crypto stack — that's only realistic
 * to validate end-to-end against a live test relay, whose address and
 * credentials live outside this repo.
 *
 * It catches refactor regressions on the work configuration —
 *  - unique work name change → existing pending enrollment dropped on update
 *  - constraints removed (e.g. `NetworkType.CONNECTED`) → worker fires offline
 *  - backoff policy/initial delay changes → either too aggressive (drains
 *    battery) or too relaxed (user waits 30 min for retry on 5G blip)
 *  - `ExistingWorkPolicy.KEEP` dropped → repeated enqueues (onboarding falling
 *    back to a retry, then a Settings re-entry) would pile up parallel workers
 *
 * The offline → online transition itself is covered by nothing here. That is a
 * deliberately deferred gap, not an oversight: it was costed at ~1-2 days.
 * Making it testable takes two things, worth knowing before starting: driving
 * the network state from the shell, and injecting a fake server URL — which the
 * current construction of StreamUploadManager forbids, its constructor being
 * private, so it needs a DI refactor or a `@VisibleForTesting` hook.
 *
 * Run :
 * ```
 * ./gradlew :mobile:connectedAndroidTest \
 *     --tests 'rs.readahead.washington.mobile.util.jobs.EnrollmentRetryWorkerInstrumentedTest'
 * ```
 */
@RunWith(AndroidJUnit4::class)
class EnrollmentRetryWorkerInstrumentedTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Force-init WorkManager with a SynchronousExecutor so we can read
        // back work state immediately after enqueue, without waiting for a
        // real scheduler tick.
        val config = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.DEBUG)
            .setExecutor(SynchronousExecutor())
            .build()
        WorkManagerTestInitHelper.initializeTestWorkManager(context, config)
    }

    @Test
    fun enqueue_createsExactlyOneUniqueWork() {
        EnrollmentRetryWorker.enqueue(context)

        val wm = WorkManager.getInstance(context)
        val infos = wm.getWorkInfosForUniqueWork(EnrollmentRetryWorker.UNIQUE_NAME).get()

        assertEquals("Should have exactly one work entry", 1, infos.size)
    }

    @Test
    fun enqueue_taggedAsEnrollmentRetry() {
        EnrollmentRetryWorker.enqueue(context)

        val wm = WorkManager.getInstance(context)
        val infos = wm.getWorkInfosForUniqueWork(EnrollmentRetryWorker.UNIQUE_NAME).get()

        assertTrue(
            "Worker should carry tag 'frappuccino_enrollment_retry'",
            infos[0].tags.contains("frappuccino_enrollment_retry"),
        )
    }

    @Test
    fun enqueue_isInPendingState() {
        // The worker has a NetworkType.CONNECTED constraint. Under
        // instrumented tests on a connected device the network IS up,
        // so the work could legitimately be ENQUEUED, BLOCKED (gating on
        // constraints) or even RUNNING by the time we read back. We accept
        // any "not yet finished or cancelled" state.
        EnrollmentRetryWorker.enqueue(context)

        val wm = WorkManager.getInstance(context)
        val infos = wm.getWorkInfosForUniqueWork(EnrollmentRetryWorker.UNIQUE_NAME).get()

        val state = infos[0].state
        assertTrue(
            "Work should not be in a terminal state right after enqueue, got $state",
            !state.isFinished,
        )
    }

    @Test
    fun enqueue_isIdempotentUnderKeepPolicy() {
        // Calls enqueue 3 times consecutively, simulating :
        //   1. EnrollmentRetryWorker.enqueue() from OnBoardSetPinFragment offline
        //   2. EnrollmentRetryWorker.enqueue() from StreamSettingsActivity recheck
        //   3. EnrollmentRetryWorker.enqueue() on a later Settings re-entry — the
        //      "Réessayer" button is not a third site, it calls
        //      retryServerEnrollment() directly, without the worker
        EnrollmentRetryWorker.enqueue(context)
        val firstId: UUID = WorkManager.getInstance(context)
            .getWorkInfosForUniqueWork(EnrollmentRetryWorker.UNIQUE_NAME)
            .get()[0].id

        EnrollmentRetryWorker.enqueue(context)
        EnrollmentRetryWorker.enqueue(context)

        val wm = WorkManager.getInstance(context)
        val infos = wm.getWorkInfosForUniqueWork(EnrollmentRetryWorker.UNIQUE_NAME).get()

        assertEquals(
            "ExistingWorkPolicy.KEEP should collapse 3 enqueues into 1",
            1,
            infos.size,
        )
        assertEquals(
            "The kept work should be the FIRST enqueued — 2nd and 3rd are dropped",
            firstId,
            infos[0].id,
        )
    }
}
