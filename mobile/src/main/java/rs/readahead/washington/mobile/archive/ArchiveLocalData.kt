package rs.readahead.washington.mobile.archive

import android.content.ContentUris
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import org.stream.crypto.DetachedDirs
import org.stream.crypto.upload.ArchiveSession
import rs.readahead.washington.mobile.service.ArchiveDownloadService
import rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder
import timber.log.Timber
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The rescue's data on this phone, and every way it is erased.
 *
 * Recovered recordings land in `noBackupFilesDir/archive_view/` (excluded from
 * backups, private to the app), never in shared storage: the verified ones and,
 * in a directory of their own, the legacy ones kept apart as not verifiable
 * ([ReportDir]). Both go by the same purges. Erasing always starts
 * with a synchronous rename of the directory: an FFI call still writing into it
 * then fails instead of recreating a file that was meant to be gone, and the
 * name the data had disappears at once. The content itself is secure-deleted
 * afterwards on a background thread, plaintext first. A rename that cannot be
 * done falls back to erasing in place.
 *
 * Secure deletion overwrites then unlinks, which is best effort on flash
 * storage (wear levelling can keep an old copy of a block); the rename-first
 * order is what keeps the window short.
 *
 * Earlier versions of the app wrote decrypted recordings to the public
 * `Download/Frappuccino/` folder; this version never writes there. The
 * emergency wipe ([detachForPanic]) removes what this installation put there.
 */
object ArchiveLocalData {

    private const val VIEW_DIR = "archive_view"

    /** The decrypt buffer of earlier versions, under `cacheDir`. */
    private const val LEGACY_RECOVERY_DIR = "archive_recovery"

    /** The public export folder of earlier versions, under Downloads. */
    private const val LEGACY_EXPORT_DIR = "Frappuccino"

    /** Broadcast (confined to the app's package) that closes the archive
     *  screens after an emergency wipe. */
    const val ACTION_ARCHIVE_WIPED = "org.stream.ARCHIVE_WIPED"

    private const val ERASE_PASSES = 3
    private const val ERASE_PASS_DELAY_MS = 2_000L

    private val eraser: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "archive-eraser").apply { isDaemon = true }
    }

    /** `noBackupFilesDir/archive_view`. */
    fun viewRoot(context: Context): File = File(context.applicationContext.noBackupFilesDir, VIEW_DIR)

    /** Create a new report directory with a fresh random token. */
    fun newReportDir(context: Context): ReportDir {
        val token = RescueNames.newToken()
        val dir = ReportDir(token, File(viewRoot(context), token))
        for (sub in listOf(dir.incoming, dir.enc, dir.unverifiable, dir.plain)) {
            if (!sub.isDirectory && !sub.mkdirs()) {
                throw java.io.IOException("cannot create the rescue directory")
            }
        }
        return dir
    }

    // ------------------------------------------------------------------
    // Entry points called from outside the rescue (emergency wipe, startup,
    // background lock timer). Their signatures are relied upon elsewhere.
    // ------------------------------------------------------------------

    /**
     * Emergency wipe, first half: stop the rescue now. Cancels the running
     * batch, stops [ArchiveDownloadService], wipes the secrets held in RAM
     * ([ArchiveAuthHolder.clear]) and tells the archive screens to close.
     * Synchronous and quick: no disk work here, see [detachForPanic].
     */
    fun stopAndClearForPanic(context: Context) {
        val app = context.applicationContext
        ArchiveDownloadService.stop(app)
        ArchiveAuthHolder.clear()
        broadcastWiped(app)
    }

    /**
     * Emergency wipe, second half: the rescue's files, for the single erase
     * pass of `StreamUploadManager.panicWipe`, which calls this in its
     * synchronous step, right after renaming its own directories.
     *
     * Renames the view directory and the decrypt buffer of earlier versions
     * to trash names now, synchronously, and erases nothing itself. Once it
     * returns, the names the data had are gone and an FFI call still writing
     * into them fails. What it returns tells the pass what to erase, split by
     * [ArchivePurgeRules.panicSplit]: the plaintext (the decrypt buffer, every
     * report's `plain` directory) among the plaintext of the whole app,
     * before any ciphertext; then the trash directories themselves. Its
     * `afterErase` makes the passes of [eraseTrees] over what a write in
     * flight may still have put there, and last removes the recordings
     * earlier versions of this installation exported to
     * `Download/Frappuccino/`. Files the witness exported through the system
     * file picker are outside the app's reach and are not touched.
     */
    fun detachForPanic(context: Context): DetachedDirs {
        val app = context.applicationContext
        val roots = (renameForPanic(viewRoot(app), File(app.cacheDir, LEGACY_RECOVERY_DIR)) +
            leftovers(app)).distinct()
        val (plaintext, ciphertext) = ArchivePurgeRules.panicSplit(roots, ::isPlaintextRoot)
        return DetachedDirs(
            plaintext = plaintext,
            ciphertext = ciphertext,
            afterErase = {
                try {
                    eraseTrees(roots)
                } catch (t: Throwable) {
                    Timber.w(t, "ArchiveLocalData: emergency erase incomplete")
                }
                purgeLegacyExports(app)
            },
        )
    }

    /** The rename step of [detachForPanic], on explicit directories: returns
     *  the trash directories it made (or the directories themselves where a
     *  rename failed), and nothing for a directory that does not exist, so a
     *  second call renames only what was recreated since. */
    internal fun renameForPanic(view: File, recovery: File): List<File> =
        renameAway(view) + renameAway(recovery)

    /**
     * At process start: nothing of a previous rescue may survive it (the
     * secrets did not). Renames the view directory synchronously, then
     * erases it, any leftover of an interrupted erase, and the decrypt buffer
     * of earlier versions, off the main thread.
     */
    fun purgeOnStartup(context: Context) {
        val app = context.applicationContext
        val renamed = renameAway(viewRoot(app)) + renameAway(File(app.cacheDir, LEGACY_RECOVERY_DIR))
        eraser.execute { eraseTrees((renamed + leftovers(app)).distinct()) }
    }

    /**
     * Purge if nothing uses the rescue any more: no batch running and no
     * archive screen attached ([ArchivePurgeRules.shouldPurge]). Also wipes
     * the secrets in that case, since nobody is left to need them.
     *
     * Safe at the instant the app leaves the foreground, which the export's
     * folder picker also causes: with a screen attached it does nothing. For
     * the same reason it almost never finds anything to purge, since every
     * screen and the service already purge on their way out when nobody is
     * left. A screen left open behind Home is purged by
     * [purgeOnBackgroundTimer] instead.
     */
    fun purgeIfIdle(context: Context) {
        if (!ArchivePurgeRules.shouldPurge(
                if (ArchiveAuthHolder.activityAlive) 1 else 0,
                ArchiveDownloadService.isRunning,
            )
        ) {
            return
        }
        ArchiveAuthHolder.clear()
        purgeAll(context)
    }

    /**
     * The background lock timer's purge
     * ([ArchivePurgeRules.shouldPurgeOnBackgroundTimer]): once the app has
     * stayed in the background for the timer's delay, the secrets and every
     * local copy go if no batch runs, even under an archive screen left open
     * behind Home, and the archive screens are told to close. Without it, such
     * a screen keeps the identity, the rescue context and the encrypted copies
     * for as long as the process lives, and reopens unlocked.
     *
     * For a timer with a delay only, never at the instant the app leaves the
     * foreground: the export's folder picker does that, and a purge then
     * would erase the report being exported. [purgeIfIdle] is the call for
     * that instant.
     *
     * The decision runs on the main thread, where the screens and the service
     * make their own purge checks, so it cannot interleave with theirs.
     * [stillBackgrounded] is asked again there, since the app may have come
     * back meanwhile. While a batch runs nothing is purged and [rearm] is
     * called instead: the service, ending with a screen still attached,
     * leaves the purge to the screens, so the timer must come back after it.
     */
    fun purgeOnBackgroundTimer(context: Context, stillBackgrounded: () -> Boolean, rearm: () -> Unit) {
        val app = context.applicationContext
        Handler(Looper.getMainLooper()).post {
            if (!stillBackgrounded()) return@post
            val batch = ArchiveDownloadService.isRunning || ArchiveDownloadService.isShuttingDown
            val screens = if (ArchiveAuthHolder.activityAlive) 1 else 0
            if (!ArchivePurgeRules.shouldPurgeOnBackgroundTimer(screens, batch)) {
                rearm()
                return@post
            }
            ArchiveAuthHolder.clear()
            purgeAll(app)
            if (screens > 0) broadcastWiped(app)
        }
    }

    // ------------------------------------------------------------------
    // Used by the rescue itself.
    // ------------------------------------------------------------------

    /** Purge every local copy of the rescue: rename now, erase later. */
    fun purgeAll(context: Context) {
        val app = context.applicationContext
        val renamed = renameAway(viewRoot(app))
        val leftovers = leftovers(app)
        if (renamed.isEmpty() && leftovers.isEmpty()) return
        eraser.execute { eraseTrees((renamed + leftovers).distinct()) }
    }

    /** Purge one report directory (a verification that failed half-way). */
    fun purgeDir(dir: ReportDir) {
        val renamed = renameAway(dir.root)
        if (renamed.isNotEmpty()) eraser.execute { eraseTrees(renamed) }
    }

    /** Secure-delete [files] on the background eraser, in order. */
    fun eraseLater(files: Collection<File>) {
        if (files.isEmpty()) return
        val copy = files.toList()
        eraser.execute { copy.forEach { ArchiveSession.secureDelete(it) } }
    }

    // ------------------------------------------------------------------

    /** Rename [dir] to a trash name next to it; returns what is to be erased
     *  (the renamed directory, or [dir] itself if the rename failed). */
    private fun renameAway(dir: File): List<File> {
        if (!dir.exists()) return emptyList()
        val parent = dir.parentFile ?: return listOf(dir)
        val trash = File(parent, ArchivePurgeRules.trashName(dir.name, RescueNames.newToken()))
        return if (dir.renameTo(trash)) {
            listOf(trash)
        } else {
            Timber.w("ArchiveLocalData: rename before erase failed, erasing in place")
            listOf(dir)
        }
    }

    /** Trash directories an interrupted erase left behind. */
    private fun leftovers(app: Context): List<File> {
        val out = ArrayList<File>()
        for ((parent, base) in listOf(
            app.noBackupFilesDir to VIEW_DIR,
            app.cacheDir to LEGACY_RECOVERY_DIR,
        )) {
            parent.listFiles()?.filterTo(out) { ArchivePurgeRules.isTrashOf(base, it.name) }
        }
        val root = viewRoot(app)
        root.listFiles()?.filterTo(out) { ArchivePurgeRules.isTrashOf(it.name.substringBefore('.'), it.name) }
        return out
    }

    private fun broadcastWiped(app: Context) {
        try {
            app.sendBroadcast(Intent(ACTION_ARCHIVE_WIPED).setPackage(app.packageName))
        } catch (e: Exception) {
            Timber.w(e, "ArchiveLocalData: wipe broadcast failed")
        }
    }

    /** Whether [root] is the decrypt buffer of earlier versions, as is or
     *  renamed to a trash name: plaintext through and through. */
    private fun isPlaintextRoot(root: File): Boolean =
        root.name == LEGACY_RECOVERY_DIR || ArchivePurgeRules.isTrashOf(LEGACY_RECOVERY_DIR, root.name)

    /**
     * Secure-delete every file under [roots], the plaintext of all of them
     * first ([ArchivePurgeRules.eraseOrder]), then the directories. A write
     * that was in flight when a directory was renamed can still land in it,
     * so a tree that is not empty after a pass gets another one shortly
     * after. [delete] and [pause] are the secure deletion and the wait
     * between passes (false: stop), passed in by the tests.
     */
    internal fun eraseTrees(
        roots: List<File>,
        delete: (File) -> Unit = { ArchiveSession.secureDelete(it) },
        pause: (Long) -> Boolean = ::pauseBetweenPasses,
    ) {
        for (pass in 1..ERASE_PASSES) {
            val remaining = roots.filter { it.exists() }
            if (remaining.isEmpty()) return
            if (pass > 1 && !pause(ERASE_PASS_DELAY_MS)) return
            ArchivePurgeRules.eraseOrder(remaining, ::isPlaintextRoot).forEach(delete)
            for (root in remaining) {
                root.walkBottomUp().filter { it.isDirectory }.forEach { it.delete() }
            }
        }
    }

    private fun pauseBetweenPasses(millis: Long): Boolean = try {
        Thread.sleep(millis)
        true
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    /**
     * Remove what earlier versions of this installation exported to
     * `Download/Frappuccino/`: overwrite, then delete, each entry. From
     * Android 10 the query only returns the entries this app created; an
     * entry another app owns is left alone.
     */
    private fun purgeLegacyExports(app: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            purgeLegacyExportsMediaStore(app)
            // The folders themselves (named after report ids) may survive
            // their entries; remove them where the platform lets us.
            @Suppress("DEPRECATION")
            val folder = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), LEGACY_EXPORT_DIR)
            try {
                folder.walkBottomUp().filter { it.isDirectory }.forEach { it.delete() }
            } catch (e: Exception) {
                Timber.w(e, "ArchiveLocalData: legacy export folders not removable")
            }
        } else {
            purgeLegacyExportsFiles(app)
        }
    }

    private fun purgeLegacyExportsMediaStore(app: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val resolver = app.contentResolver
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val ids = ArrayList<Long>()
        try {
            resolver.query(
                collection,
                arrayOf(MediaStore.MediaColumns._ID),
                "${MediaStore.MediaColumns.RELATIVE_PATH} LIKE ?",
                arrayOf("${Environment.DIRECTORY_DOWNLOADS}/$LEGACY_EXPORT_DIR/%"),
                null,
            )?.use { c ->
                while (c.moveToNext()) ids.add(c.getLong(0))
            }
        } catch (e: Exception) {
            Timber.w(e, "ArchiveLocalData: legacy export query failed")
            return
        }
        var removed = 0
        for (id in ids) {
            val uri = ContentUris.withAppendedId(collection, id)
            overwrite(app, uri)
            try {
                if (resolver.delete(uri, null, null) > 0) removed++
            } catch (e: Exception) {
                Timber.w(e, "ArchiveLocalData: legacy export entry not deletable")
            }
        }
        Timber.i("ArchiveLocalData: %d legacy export entr(ies) removed of %d", removed, ids.size)
    }

    private fun purgeLegacyExportsFiles(app: Context) {
        @Suppress("DEPRECATION")
        val folder = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), LEGACY_EXPORT_DIR)
        if (!folder.exists()) return
        val resolver = app.contentResolver
        try {
            folder.walkBottomUp().forEach { f ->
                if (f.isFile) {
                    val path = f.absolutePath
                    ArchiveSession.secureDelete(f)
                    // Also drop the MediaStore row and the thumbnail the
                    // provider derived from it: a bare file delete leaves a
                    // recoverable preview of decrypted footage behind.
                    try {
                        @Suppress("DEPRECATION")
                        resolver.delete(
                            MediaStore.Files.getContentUri("external"),
                            "${MediaStore.MediaColumns.DATA} = ?",
                            arrayOf(path),
                        )
                    } catch (e: Exception) {
                        Timber.w(e, "ArchiveLocalData: MediaStore row of a legacy export not removable")
                    }
                } else {
                    f.delete()
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "ArchiveLocalData: legacy export purge failed")
        }
    }

    /** Overwrite a MediaStore entry with zeros before it is deleted. Best
     *  effort: a provider that refuses the write mode is skipped. */
    private fun overwrite(app: Context, uri: Uri) {
        try {
            app.contentResolver.openFileDescriptor(uri, "rw")?.use { pfd ->
                val size = pfd.statSize
                if (size <= 0) return
                FileOutputStream(pfd.fileDescriptor).use { out ->
                    val zeros = ByteArray(64 * 1024)
                    var left = size
                    while (left > 0) {
                        val n = minOf(left, zeros.size.toLong()).toInt()
                        out.write(zeros, 0, n)
                        left -= n
                    }
                    out.flush()
                    out.fd.sync()
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "ArchiveLocalData: overwrite of a legacy export skipped")
        }
    }
}
