package rs.readahead.washington.mobile.util

import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import org.stream.crypto.upload.EnvelopeQueue
import org.stream.crypto.upload.StreamUploadManager
import rs.readahead.washington.mobile.archive.ArchiveLocalData
import rs.readahead.washington.mobile.data.sharedpref.Preferences
import rs.readahead.washington.mobile.service.StreamRecordingService
import rs.readahead.washington.mobile.util.jobs.UploadAuthHolder
import timber.log.Timber
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Pure-V2 lock-timeout controller: it owns the background timers, the
 * upload-JWT auto-clear, the ratchet inactivity auto-lock and the purge of
 * the archive rescue's local copies.
 *
 * Never re-wire this onto the Tella key/unlock infrastructure — `MainKey`,
 * `MainKeyStore`, `UnlockRegistry`, `PBEKeyWrapper`, `LifecycleMainKey`, the
 * Tella unlock activities. Phase 6.1.16 removed all of it from the repo: no
 * `LifecycleMainKey` class is declared anywhere any more, and the name now
 * survives only in prose, including the KDoc on [NO_TIMEOUT] below. The
 * V2 lock gate is 100 % ratchet-based
 * ([org.stream.crypto.upload.StreamUploadManager.isLocked] / `isUnlocked`),
 * so the Tella `MainKey` was dead weight; the JWT clear that used to hang off
 * `LifecycleMainKey`'s timer (wired in `MyApplication` as an
 * `addOnClearListener`) was the one load-bearing piece, and it lives here
 * now, on a dedicated [androidx.lifecycle.ProcessLifecycleOwner] observer
 * that knows nothing about Tella.
 *
 * `ON_PAUSE` arms the timers below and `ON_RESUME` cancels them all:
 *  - the JWT clear, from [Preferences.getLockTimeout] → [fire]:
 *      - `NO_TIMEOUT` (-1) → never auto-clear;
 *      - `0` (IMMEDIATE_SHUTDOWN, the default) → clear synchronously;
 *      - `> 0` → clear after `timeout` ms unless `ON_RESUME` cancels first.
 *  - the ratchet inactivity auto-lock, from [Preferences.getRatchetAutoLockMs]
 *    (15 min by default, `-1` or `0` disable it) → [fireRatchetLock];
 *  - with the same delay, and disabled with it, the purge of the archive
 *    rescue's local copies → [fireArchivePurge].
 *
 * The JWT timeout is read straight from [Preferences.getLockTimeout], so the
 * legacy "temporary timeout" bumps (`BaseActivity.maybeChangeTemporaryTimeout`,
 * which only ever pushed into `LifecycleMainKey.timeout`) no longer delay the
 * JWT clear. That is intentional and benign in V2: **this** timer does not
 * wipe the ratchet, so clearing the JWT merely forces the next upload to
 * re-authenticate silently via `initServerSession`. It never strands footage
 * (see the [fire] gates) and never forces a re-PIN. The ratchet is locked by
 * the separate timer above — [fireRatchetLock] calls
 * `StreamUploadManager.lock()` once nothing is recording or sealing and no
 * queued envelope still needs a bearer — and by an explicit `lock()` /
 * `panicWipe()`; those are what force a re-PIN.
 */
class V2LockTimeoutController(
    lifecycle: Lifecycle,
    context: Context,
) : DefaultLifecycleObserver {

    private val appContext: Context = context.applicationContext

    private val executor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "v2-lock-timeout").apply { isDaemon = true }
    }

    @Volatile
    private var scheduled: ScheduledFuture<*>? = null

    // A separate timer for the ratchet inactivity auto-lock (re-PIN
    // on return), independent of the JWT-clear [scheduled] above so the
    // field-tuned JWT timing (lock_timeout default 0 + the 1.14/2.2.6/3.38-D
    // gates) is left untouched.
    @Volatile
    private var ratchetScheduled: ScheduledFuture<*>? = null

    // The archive rescue's background purge. A future of its own: it is
    // re-armed from the main thread while a download batch runs, and sharing
    // [ratchetScheduled] would let one re-arm overwrite (and orphan) the
    // other's pending future.
    @Volatile
    private var archiveScheduled: ScheduledFuture<*>? = null

    // True between ON_PAUSE and ON_RESUME. [fireRatchetLock] checks it so a
    // fire that races a foregrounding (or a recording-deferred reschedule)
    // can't lock the ratchet once the user is back in the app.
    @Volatile
    private var backgrounded = false

    init {
        lifecycle.addObserver(this)
    }

    override fun onResume(owner: LifecycleOwner) {
        backgrounded = false
        cancel()
    }

    override fun onPause(owner: LifecycleOwner) {
        backgrounded = true
        schedule()
    }

    @Synchronized
    private fun schedule() {
        cancel()
        // JWT clear (existing, field-critical — unchanged).
        when (val timeout = Preferences.getLockTimeout()) {
            NO_TIMEOUT -> Unit // never auto-clear
            0L -> fire() // IMMEDIATE_SHUTDOWN — clear now (on the lifecycle thread, as before)
            else -> scheduled = executor.schedule({ fire() }, timeout, TimeUnit.MILLISECONDS)
        }
        // Ratchet inactivity auto-lock. -1 / 0 = disabled.
        val ratchetMs = Preferences.getRatchetAutoLockMs()
        if (ratchetMs > 0L) {
            ratchetScheduled = executor.schedule({ fireRatchetLock() }, ratchetMs, TimeUnit.MILLISECONDS)
            archiveScheduled = executor.schedule({ fireArchivePurge() }, ratchetMs, TimeUnit.MILLISECONDS)
        }
    }

    @Synchronized
    private fun cancel() {
        scheduled?.cancel(false)
        scheduled = null
        ratchetScheduled?.cancel(false)
        ratchetScheduled = null
        archiveScheduled?.cancel(false)
        archiveScheduled = null
    }

    /**
     * Drop the upload JWT, unless something still needs it. Each gate below
     * guards footage, and a clear that slips past one loses it without
     * anything failing loudly.
     *
     * Never while a recording session is live or tearing down. Field forensics
     * 2026-05-21, report `e0201e07`: the screen turned off mid-recording, the
     * lock timeout fired, the JWT was wiped, and every chunk produced after
     * that looped on `no_auth_token` until the session ended. Gate on the SAME
     * `isRunning || isShuttingDown` window the upload workers use (see the
     * `StreamRecordingService` companion doc) rather than on a neighbouring
     * condition of your own, so the JWT survives the whole session plus its
     * teardown.
     *
     * Never while a chunk is being sealed (not in the queue yet), nor while a
     * queued envelope may need the bearer to go: the first object of a report,
     * a directory entry, or one the relay answered 425 for. Those are the only
     * envelopes that need a bearer; every other one goes on its signature
     * alone, so a queue that holds only those does not keep the JWT alive. The
     * 24 h JWT expiry and the 401 → clear path still bound the window in the
     * "record, stop, leave the app forever" case.
     *
     * Each background fire also purges the archive rescue's local copies and
     * secrets if nothing uses them any more: no download batch running and no
     * archive screen attached ([ArchiveLocalData.purgeIfIdle]). With the
     * default delay of 0 this runs at the very instant the app leaves the
     * foreground, which the export's folder picker also causes, hence that
     * stricter rule. A screen left open behind Home is purged by
     * [fireArchivePurge].
     */
    private fun fire() {
        try {
            ArchiveLocalData.purgeIfIdle(appContext)
        } catch (t: Throwable) {
            Timber.w(t, "archive view purge failed")
        }
        val reason = busyReason()
        if (reason != null) {
            Timber.d("skipping UploadAuthHolder.clear (%s)", reason)
            rescheduleJwtClear()
            return
        }
        UploadAuthHolder.clear()
    }

    /**
     * Why the bearer (and the unlocked state that can renew it) must stay, or
     * null if nothing needs it: a recording live or tearing down, a chunk
     * being sealed, or a queued envelope that may need the bearer.
     */
    private fun busyReason(): String? {
        if (StreamRecordingService.isRunning || StreamRecordingService.isShuttingDown) {
            return "recording live or tearing down"
        }
        val sealing = StreamRecordingService.encryptionsInFlight()
        if (sealing > 0) return "$sealing chunk(s) being sealed"
        val bearerDependent = try {
            EnvelopeQueue.get(appContext).hasBearerDependent()
        } catch (t: Throwable) {
            false // fail-open: clear on error
        }
        return if (bearerDependent) "an envelope may need the bearer" else null
    }

    /**
     * Retry the JWT clear every [JWT_CLEAR_RETRY_MS] when [fire] defers it
     * because a recording, a seal or a bearer-dependent envelope is pending at
     * background time, instead of giving up.
     *
     * The retry is deliberately unbounded — no attempt counter, no maximum
     * delay — and its only exit is the user coming back: `onResume` clears
     * [backgrounded] and cancels the pending future. Do not add an attempt
     * cap for safety's sake, because that brings back the one-shot behaviour
     * it replaced, which left the bearer reachable in the JVM heap for the
     * full 24 h TTL in the "record, stop, background mid-drain" case
     * (confirmed by on-device heap dumps, 10.6 forensic 2026-06-13). The loop
     * stays harmless because every actual clear still goes through the gates
     * in [fire].
     */
    @Synchronized
    private fun rescheduleJwtClear() {
        if (!backgrounded) return
        scheduled = executor.schedule({ fire() }, JWT_CLEAR_RETRY_MS, TimeUnit.MILLISECONDS)
    }

    /**
     * **Never interrupts a recording.** The app recording in the background
     * with the screen off is how a witness captures testimony, not an edge
     * case. So while a recording is live or tearing down, a chunk is being
     * sealed, or a queued envelope may need the bearer (which only an unlocked
     * device can renew), this defers rather than gives up: it reschedules one
     * more interval so the lock still lands once the device is idle. The
     * [backgrounded] guard stops a deferred fire from locking after the user
     * has returned to the foreground.
     *
     * The rest of the queue does not hold the lock back: every envelope was
     * signed when produced, and goes without the PIN.
     *
     * Ratchet inactivity auto-lock. Fires after
     * [Preferences.getRatchetAutoLockMs] in the background and wipes the
     * ratchet from RAM ([StreamUploadManager.lock]), so the next return to
     * [rs.readahead.washington.mobile.views.activity.StreamActivity] forces a
     * re-PIN (its onResume → maybeLaunchPinUnlock → isLocked gate).
     */
    private fun fireRatchetLock() {
        if (!backgrounded) return
        val reason = busyReason()
        if (reason != null) {
            synchronized(this) {
                if (!backgrounded) return
                val ms = Preferences.getRatchetAutoLockMs()
                if (ms > 0L) {
                    ratchetScheduled = executor.schedule({ fireRatchetLock() }, ms, TimeUnit.MILLISECONDS)
                }
            }
            Timber.d("Ratchet auto-lock deferred (%s); rescheduled", reason)
            return
        }
        StreamUploadManager.getInstance(appContext).lock()
        Timber.tag("StreamMetrics").i("ratchetAutoLock fired (idle timeout)")
    }

    /**
     * Once the app has stayed in the background for the auto-lock delay,
     * purge the archive rescue's local copies and secrets unless a download
     * batch runs, even under an archive screen left open behind Home
     * ([ArchiveLocalData.purgeOnBackgroundTimer]). While a batch runs, the
     * purge comes back after one more delay. With the auto-lock disabled
     * (`-1` or `0`) this timer is not armed, and only [fire]'s stricter purge
     * remains.
     */
    private fun fireArchivePurge() {
        if (!backgrounded) return
        try {
            ArchiveLocalData.purgeOnBackgroundTimer(appContext, { backgrounded }) { rearmArchivePurge() }
        } catch (t: Throwable) {
            Timber.w(t, "archive view purge failed")
        }
    }

    @Synchronized
    private fun rearmArchivePurge() {
        if (!backgrounded) return
        val ms = Preferences.getRatchetAutoLockMs()
        if (ms > 0L) {
            archiveScheduled = executor.schedule({ fireArchivePurge() }, ms, TimeUnit.MILLISECONDS)
        }
    }

    companion object {
        /** Matches `LifecycleMainKey.NO_TIMEOUT` — "never auto-clear". */
        const val NO_TIMEOUT: Long = -1L

        /** 10.6 forensic - retry interval for a deferred JWT clear (drain in flight). */
        const val JWT_CLEAR_RETRY_MS: Long = 10_000L
    }
}
