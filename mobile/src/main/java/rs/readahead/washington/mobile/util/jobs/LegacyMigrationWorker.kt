package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.BackoffPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequest
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import org.stream.crypto.upload.LegacyReportMigration
import rs.readahead.washington.mobile.service.StreamRecordingService
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Runs the one-time move from the legacy report scheme
 * ([LegacyReportMigration]) off the main thread, after an unlock.
 *
 * It needs the PIN session, so a run on a locked device ends at once and the
 * next unlock enqueues it again. A run that stopped part way (space, I/O)
 * retries with backoff while the device stays unlocked; an unlock replaces a
 * retry still waiting out its backoff, so it resumes right away rather than
 * after a delay that can reach hours. The migration itself is idempotent.
 *
 * A recording that starts before the report state exists only waits for the
 * migration's first steps ([ensureStateBlocking]), not for its conversions:
 * once the state is written a report can be opened, and the rest goes on here.
 */
@HiltWorker
class LegacyMigrationWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
) : Worker(context, params) {

    override fun doWork(): Result =
        when (runBlocking(applicationContext)) {
            LegacyReportMigration.Outcome.STOPPED -> Result.retry()
            else -> Result.success()
        }

    companion object {
        private const val UNIQUE_NAME = "frappuccino-legacy-report-migration"

        /** The tags the old upload paths used: cancelled by the migration. */
        private val LEGACY_TAGS = listOf(
            "stream_chunk_upload",
            "stream_directory_entry",
            "stream_provenance_upload",
        )
        private const val LEGACY_TIMESTAMP_TAG = "stream_provenance_timestamp"

        /**
         * Enqueue the migration if one is needed. REPLACE, not KEEP: a run
         * waiting out its retry backoff (which grows to hours after a few
         * stops) is replaced by one that starts now. A run already in progress
         * is not interrupted by the replacement (WorkManager does not
         * interrupt a running Worker's thread); the new one waits for it on
         * the migration's own lock, then finds it done or resumes it.
         */
        fun start(context: Context) {
            if (!LegacyReportMigration.isNeeded(context)) return
            val request = OneTimeWorkRequest.Builder(LegacyMigrationWorker::class.java)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork(UNIQUE_NAME, ExistingWorkPolicy.REPLACE, request)
        }

        /** Run the migration on the calling (background) thread. */
        fun runBlocking(context: Context): LegacyReportMigration.Outcome {
            val outcome = LegacyReportMigration.run(context, hooks(context.applicationContext))
            Timber.i("legacy report migration: %s", outcome)
            return outcome
        }

        /**
         * Only the steps a recording needs (the report state), on the calling
         * (background) thread. Returns whether the report state exists.
         */
        fun ensureStateBlocking(context: Context): Boolean =
            LegacyReportMigration.ensureState(context, hooks(context.applicationContext))

        private fun hooks(context: Context) = object : LegacyReportMigration.Hooks {
            override fun cancelLegacyWork(): Int {
                val wm = WorkManager.getInstance(context)
                // Timestamp submissions not answered yet: the proofs they would
                // have produced are lost (the video is not), and the witness is
                // told how many. A legacy submission job waits for this count
                // instead of failing on its own (ProvenanceTimestampWorker).
                val waiting = try {
                    wm.getWorkInfosByTag(LEGACY_TIMESTAMP_TAG).get()
                        .count { !it.state.isFinished }
                } catch (e: Exception) {
                    Timber.w(e, "legacy timestamp work not counted")
                    0
                }
                for (tag in LEGACY_TAGS + LEGACY_TIMESTAMP_TAG) {
                    try {
                        wm.cancelAllWorkByTag(tag).result.get()
                    } catch (e: Exception) {
                        Timber.w(e, "legacy work cancel failed")
                    }
                }
                return waiting
            }

            override fun scheduleEnvelopes(wipeGeneration: Int) {
                try {
                    ChunkUploadWorker.scheduleAll(
                        context, StreamRecordingService.DEFAULT_SERVER_URL, wipeGeneration,
                    )
                } catch (e: Exception) {
                    Timber.w(e, "envelope scheduling after migration failed (the sweep retries)")
                }
            }
        }
    }
}
