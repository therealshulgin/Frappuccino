package rs.readahead.washington.mobile.diagnostics

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Sends the diagnostics log to the test relay ([Diagnostics.uploadPass]).
 *
 * Enqueued at app start, at the end of each recording, and every
 * [PERIOD_MINUTES] by a periodic work; all of them unique and KEEP, so a
 * trigger that finds one already waiting adds nothing. It can run during a
 * recording, and is built not to compete with the chunk uploads: never
 * expedited, one request at a time, a body of at most 1 MiB.
 *
 * The emergency wipe cancels it with every other job; one that still runs
 * afterwards in the same process does nothing ([Diagnostics.uploadPass]).
 */
class DiagnosticsUploadWorker(
    context: Context,
    params: WorkerParameters,
) : Worker(context, params) {

    override fun doWork(): Result =
        if (Diagnostics.uploadPass(applicationContext)) Result.success() else Result.retry()

    companion object {
        const val TAG = "frappuccino_diag_upload"
        const val PERIOD_MINUTES = 60L

        private fun constraints() =
            Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        /** The periodic upload (kept if already scheduled) and one upload now. */
        fun schedule(context: Context) {
            // First run a period from now: the one-time upload below covers
            // the start, and the two would otherwise start together.
            val periodic = PeriodicWorkRequestBuilder<DiagnosticsUploadWorker>(PERIOD_MINUTES, TimeUnit.MINUTES)
                .setInitialDelay(PERIOD_MINUTES, TimeUnit.MINUTES)
                .setConstraints(constraints())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
                .addTag(TAG)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                DiagnosticsNames.PERIODIC_WORK, ExistingPeriodicWorkPolicy.KEEP, periodic,
            )
            requestUpload(context)
        }

        /** One upload as soon as there is a network, unless one is already waiting. */
        fun requestUpload(context: Context) {
            val request = OneTimeWorkRequestBuilder<DiagnosticsUploadWorker>()
                .setConstraints(constraints())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .addTag(TAG)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                DiagnosticsNames.UPLOAD_WORK, ExistingWorkPolicy.KEEP, request,
            )
        }
    }
}
