package rs.readahead.washington.mobile;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.hilt.work.HiltWorkerFactory;
import androidx.lifecycle.ProcessLifecycleOwner;
import androidx.multidex.MultiDexApplication;
import androidx.work.Configuration;

import org.hzontal.shared_ui.data.CommonPrefs;

import javax.inject.Inject;

import dagger.hilt.android.HiltAndroidApp;
import rs.readahead.washington.mobile.data.sharedpref.Preferences;
import rs.readahead.washington.mobile.data.sharedpref.SharedPrefs;
import rs.readahead.washington.mobile.util.LocaleManager;
import rs.readahead.washington.mobile.util.V2LockTimeoutController;
import rs.readahead.washington.mobile.views.activity.ExitActivity;
import rs.readahead.washington.mobile.views.activity.StreamActivity;
import org.stream.crypto.upload.StreamUploadManager;
import rs.readahead.washington.mobile.views.activity.onboarding.OnBoardingActivity;
import timber.log.Timber;

/**
 * Never bring back the legacy Tella key/unlock infrastructure — TellaKeysUI,
 * MainKey, MainKeyStore, UnlockRegistry, PBEKeyWrapper, the Tella unlock
 * activities. It has been removed, and putting any of it back would mean a
 * second source of truth for the lock alongside the ratchet state, plus a key
 * store persisted on the device. The likely way back in is a contributor
 * porting a piece of upstream Tella code, or hunting for somewhere to hook an
 * unlock screen.
 *
 * The lock model is 100% V2: the ratchet state in
 * {@link org.stream.crypto.upload.StreamUploadManager} is the single source of
 * truth (isLocked / isUnlocked), the lock screen is the V2
 * {@code PinUnlockActivity}, and the lock-timeout / upload-JWT auto-clear lives
 * in {@link V2LockTimeoutController}. (Phase 6.1.16.)
 */
@HiltAndroidApp
public class MyApplication extends MultiDexApplication implements Configuration.Provider {
    // Phase 6.1.16 — pure-V2 lock-timeout observer; owns the upload-JWT
    // auto-clear (Phase 1.14 / 3.38-D). Held in a static so it isn't GC'd; it
    // also self-registers as a ProcessLifecycle observer.
    @SuppressLint("StaticFieldLeak")
    private static V2LockTimeoutController v2LockTimeoutController;
    @Inject
    public HiltWorkerFactory workerFactory;

    public static void startMainActivity(@NonNull Context context) {
        Intent intent;
        if (Preferences.isFirstStart()) {
            intent = new Intent(context, OnBoardingActivity.class);
        } else {
            intent = new Intent(context, StreamActivity.class);
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        context.startActivity(intent);
    }

    /**
     * Phase 6.1.16 — pure-V2 onboarding completion. Replaces the old path
     * through the Tella CredentialsCallback (onLockConfirmed ->
     * onSuccessfulUnlock). Called by OnBoardAllDoneFragment once the V2
     * enrollment (BIP-39 mnemonic + PIN) is done: marks first-start complete,
     * ensures the StreamUploadManager singleton exists, then opens the main
     * (recording) screen.
     */
    public static void completeOnboarding(@NonNull Context context) {
        Preferences.setFirstStart(false);
        try {
            StreamUploadManager.Companion.getInstance(context);
        } catch (Exception e) {
            Timber.e(e, "completeOnboarding: StreamUploadManager init failed");
        }
        startMainActivity(context);
    }

    public static boolean isConnectedToInternet(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        NetworkInfo networkInfo = cm.getActiveNetworkInfo();
        return networkInfo != null && networkInfo.isConnected();
    }

    public static void exit(Context context) {
        Intent intent = new Intent(context, ExitActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NO_ANIMATION | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS);
        context.startActivity(intent);
    }

    // BT-HIGH-09 — maybeExcludeIntentFromRecents removed (was gated on
    // Preferences.isSecretModeActive which was dead code, always false).
    // FLAG_SECURE (BT-HIGH-08, unconditional) handles screenshot/overview
    // suppression for the threat model we care about.

    @Override
    protected void attachBaseContext(Context newBase) {
        CommonPrefs.getInstance().init(newBase);
        SharedPrefs.getInstance().init(newBase);
        super.attachBaseContext(LocaleManager.getInstance().getLocalizedContext(newBase));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void onCreate() {
        super.onCreate();

        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);

        if (BuildConfig.DEBUG) {
            Timber.plant(new Timber.DebugTree());
            // Plant this tree on debug builds only (audit 2026-06-26,
            // R-CR-1 / B-1). In a release build the file is a persistent
            // recording timeline that survives panicWipe and embeds the raw
            // sessionId, which is the blob-name prefix on the relay
            // (.../file/<report_id>/<sessionId>_<seq>.strm). A seized device
            // (AFU, ratchet wiped) + relay access could match metrics.log ->
            // relay blobs -> report_id, defeating the relay-blind unlinkability
            // device-side. Field telemetry runs on debug builds, so gating the
            // plant here keeps the field-test workflow while keeping the
            // released binary clean.
            //
            // The file must equally stay at /data/data/<pkg>/files/metrics.log,
            // i.e. under filesDir. It was moved there from getExternalFilesDir
            // to close the world-readable side channel — do not move it back
            // out (see KDoc on MetricsFileLogger). That is also why it is
            // pulled with run-as rather than a plain adb pull:
            //   adb exec-out run-as org.hzontal.tellaFOSS cat files/metrics.log > metrics.log
            //
            // What it buys: StreamMetrics tag lines mirrored to a persistent
            // file, which survives logcat buffer rollover during field tests.
            // (Phase 3.34; path moved in Phase 3.39.)
            try {
                Timber.plant(new rs.readahead.washington.mobile.util.MetricsFileLogger(this));
            } catch (Throwable t) {
                Timber.w(t, "MetricsFileLogger plant failed (non-fatal)");
            }
        }
        CommonPrefs.getInstance().init(this);
        SharedPrefs.getInstance().init(this);

        // Phase 6.1.16 — pure-V2 lock-timeout controller. Owns the upload-JWT
        // auto-clear (Phase 1.14 / 3.38-D) on a dedicated ProcessLifecycle
        // observer. The Tella key/unlock infra that used to be initialised here
        // is gone; the V2 ratchet (StreamUploadManager) is the lock source of
        // truth and the V2 PinUnlockActivity is the lock screen.
        v2LockTimeoutController = new V2LockTimeoutController(
                ProcessLifecycleOwner.get().getLifecycle(), this);

        // Schedule the periodic OrphanSweepWorker.
        // PeriodicWork is idempotent under ExistingPeriodicWorkPolicy.KEEP
        // (handled inside schedulePeriodicWork) so we re-call this on
        // every process start safely.
        try {
            rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker
                .Companion.schedulePeriodicWork(this);
        } catch (Throwable t) {
            Timber.w(t, "OrphanSweepWorker schedule failed (non-fatal)");
        }

        // App-level "network is back" trigger: drain the
        // orphan backlog (resetting WorkManager's grown upload backoff) as
        // soon as a validated network returns, between recording sessions.
        // Idempotent; registered for the process lifetime.
        try {
            rs.readahead.washington.mobile.util.jobs.OrphanSweepWorker
                .Companion.registerNetworkRescueTrigger(this);
        } catch (Throwable t) {
            Timber.w(t, "OrphanSweepWorker network trigger registration failed (non-fatal)");
        }
    }

    @NonNull
    @Override
    public Configuration getWorkManagerConfiguration() {
        return new Configuration.Builder().setMinimumLoggingLevel(android.util.Log.DEBUG).setWorkerFactory(workerFactory).build();
    }
}
