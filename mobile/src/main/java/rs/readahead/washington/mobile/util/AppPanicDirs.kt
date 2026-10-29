package rs.readahead.washington.mobile.util

import android.content.Context
import org.stream.crypto.DetachedDirs
import rs.readahead.washington.mobile.archive.ArchiveLocalData
import rs.readahead.washington.mobile.diagnostics.Diagnostics
import timber.log.Timber

/**
 * The app's own directories for the emergency wipe, handed to
 * `StreamUploadManager.panicWipe` by the settings screen: the internal archive
 * viewer's ([ArchiveLocalData.detachForPanic]) and, in a pre-release test
 * build, the diagnostics log ([Diagnostics.detachForPanic]; nothing in a
 * production build). A new part of the app that keeps files of its own joins
 * the list here, so the wipe call site never has to change.
 */
object AppPanicDirs {

    fun detach(context: Context): DetachedDirs = combine(
        { ArchiveLocalData.detachForPanic(context) },
        { Diagnostics.detachForPanic(context) },
    )

    /**
     * Every part is called, in order, even when an earlier one throws: a
     * failure in one part must not leave another part's files unrenamed. The
     * lists are concatenated in the same order, and the combined `afterErase`
     * runs each part's own, each guarded the same way.
     */
    internal fun combine(vararg parts: () -> DetachedDirs): DetachedDirs {
        val detached = parts.map { part ->
            try {
                part()
            } catch (t: Throwable) {
                Timber.w(t, "AppPanicDirs: a part failed to detach its directories")
                DetachedDirs()
            }
        }
        return DetachedDirs(
            plaintext = detached.flatMap { it.plaintext },
            ciphertext = detached.flatMap { it.ciphertext },
            afterErase = {
                for (d in detached) {
                    try {
                        d.afterErase()
                    } catch (t: Throwable) {
                        Timber.w(t, "AppPanicDirs: an after-erase step failed")
                    }
                }
            },
        )
    }
}
