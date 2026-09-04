package rs.readahead.washington.mobile.util.jobs

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import org.stream.crypto.StreamPreferences
import org.stream.crypto.upload.StreamUploadManager
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Auto-retries the V2 server enrollment when the network becomes available
 * after an offline onboarding (Phase 2.3.2).
 *
 * This worker does NOT consume any ratchet slot — it's a pure
 * `POST /auth/v2/enroll`, idempotent server-side (returns `AlreadyEnrolled`
 * if the server already saw this identity). That idempotence is what makes
 * retrying blindly acceptable, so don't cap the attempts or add a give-up
 * budget: a device that onboarded offline would then stop trying and stay
 * un-enrolled.
 *
 * Being enqueued repeatedly is expected, not accidental: onboarding enqueues
 * it, and the Settings screen re-enqueues it every time the user lands there
 * while an enrollment is still pending. The unique work name plus
 * `ExistingWorkPolicy.KEEP` is what keeps those repeat calls harmless;
 * switching to REPLACE would cancel the in-flight or backing-off attempt on
 * each visit to Settings.
 *
 * If the user completed the local enrollment with no network,
 * [StreamUploadManager.enrollFromMnemonic] persisted the proof to
 * [org.stream.crypto.StreamPreferences], the toast warned the user the
 * enrollment is queued, and this worker is enqueued (by the onboarding
 * fragment, or manually from Settings).
 *
 * WorkManager supplies the rest: the `NetworkType.CONNECTED` constraint, so
 * the worker only runs when there's actually network to talk to, and the
 * retry backoff. This file sets only the 30 s initial delay
 * (`setBackoffCriteria(EXPONENTIAL, 30, SECONDS)`); the delay doubles per
 * attempt and WorkManager caps it at `WorkRequest.MAX_BACKOFF_MILLIS` (5 h).
 */
class EnrollmentRetryWorker(
    context: Context,
    params: WorkerParameters,
) : Worker(context, params) {

    override fun doWork(): Result {
        val manager = StreamUploadManager.getInstance(applicationContext)
        if (!manager.hasPendingServerEnrollment()) {
            Timber.d("EnrollmentRetryWorker: no pending enrollment, nothing to do")
            return Result.success()
        }
        val ok = try {
            manager.retryServerEnrollment()
        } catch (e: Exception) {
            Timber.e(e, "EnrollmentRetryWorker: exception during retry")
            false
        }
        return if (ok) {
            Timber.i("EnrollmentRetryWorker: server enrollment confirmed")
            // Set le flag one-shot pour que la prochaine
            // activity foregroundée affiche "Enrôlement serveur confirmé"
            // (le worker est en background, pas de Toast direct propre).
            StreamPreferences.markEnrollmentSucceeded(applicationContext)
            Result.success()
        } else {
            Timber.w("EnrollmentRetryWorker: server still unreachable, will retry")
            Result.retry()
        }
    }

    companion object {
        /** Unique work name so duplicate enqueue calls collapse into one. */
        const val UNIQUE_NAME = "frappuccino-enrollment-retry"

        /**
         * Enqueue (or no-op if already enqueued) a single worker that will
         * retry the server enrollment as soon as the network is up.
         * Safe to call from any thread; idempotent under
         * [ExistingWorkPolicy.KEEP].
         */
        fun enqueue(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = OneTimeWorkRequestBuilder<EnrollmentRetryWorker>()
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    30,
                    TimeUnit.SECONDS,
                )
                .addTag("frappuccino_enrollment_retry")
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                UNIQUE_NAME,
                ExistingWorkPolicy.KEEP,
                request,
            )
            Timber.d("EnrollmentRetryWorker enqueued (KEEP policy)")
        }
    }
}
