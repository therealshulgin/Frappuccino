package rs.readahead.washington.mobile.service

import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.delay
import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.upload.ArchiveSession
import timber.log.Timber
import java.io.File
import java.io.FileInputStream
import java.io.IOException

/**
 * UI-free download core for archive rescue.
 *
 * A plain [Context] must stay enough: every method here uses only generic
 * Context APIs (`contentResolver`, `Environment`, `File`, `cacheDir`) — no
 * Activity resources, no Views, no `getString` — and progress is surfaced
 * via a callback (the service turns it into a broadcast) rather than by
 * touching the UI. Reaching for an Activity resource here, because it is
 * shorter, makes the class unusable inside [ArchiveDownloadService], the
 * foreground service that keeps the rescue alive across screen-off and
 * backgrounding; the download then becomes killable by a screen-off again,
 * which is the bug that service was added to fix (Phase 4.4.8).
 *
 * `moveToPublicDownloads`, `writePlaylistM3u` and `clearReportFolder` were
 * extracted from `ArchiveModeActivity` (Phase 4.4.2/4.4.5/4.4.6) and now
 * live here only — the activity goes through [ArchiveDownloadService]. They
 * have moved on since: see the provenance-artifact branch and the MediaStore
 * idempotence field-fix inside [moveToPublicDownloads]. The surrounding loop
 * ([downloadReport]) is the old `downloadOne` without its `progressView` /
 * `reportsAdapter` / `getString` calls.
 */
class ArchiveDownloader(context: Context) {

    private val appContext: Context = context.applicationContext

    /** Outcome of a single report download. */
    sealed class ReportOutcome {
        data class Success(val publicDir: String, val blobCount: Int) : ReportOutcome()
        object Empty : ReportOutcome()
        data class Failure(val message: String) : ReportOutcome()
    }

    /**
     * Result of a single move operation. Carries enough
     * metadata for the playlist generator to decide whether the moved
     * file is a playable MP4 chunk (→ appears in `playlist.m3u`). It is
     * not one, and is skipped from the playlist, both for the session
     * manifest (`*.json`) and for the provenance artifacts
     * (`.fpm` / `.manifest` / `.ots` / `.otssalt`).
     */
    private data class MoveResult(
        val path: String,
        val displayName: String,
        val isMp4: Boolean,
    )

    /**
     * [onBlob] is invoked on the caller's coroutine — the service's
     * `Dispatchers.IO` — so do no UI work inside it. The service translates
     * it into a broadcast, which is safe from any thread.
     *
     * Downloads and decrypts every blob of [reportId] into the PUBLIC
     * `Downloads/Frappuccino/<rid>/` folder, writes a `playlist.m3u` there
     * listing the recovered MP4 chunks (the session manifest and the
     * provenance artifacts are kept out of it), and reports per-blob
     * progress as `(filename, index, total)`.
     */
    suspend fun downloadReport(
        reportId: String,
        identity: ArchiveIdentity,
        session: ArchiveSession,
        // §10.11 Phase B — phrase-derived signer to re-derive the OTS salt for the
        // disclosure bundle (null on a pure-archive rescue → salt export skipped).
        provenanceSigner: uniffi.frappuccino.ProvenanceSigner?,
        onBlob: (filename: String, index: Int, total: Int) -> Unit,
    ): ReportOutcome {
        val blobs = try {
            session.listBlobs(reportId)
        } catch (e: Exception) {
            Timber.e(e, "ArchiveDownloader: listBlobs failed for %s", reportId)
            return ReportOutcome.Failure(e.message ?: "listBlobs error")
        }
        // Phase C — null = 404 (the record vanished between enumeration and this
        // download, e.g. a server-side reap); [] = a report with no blobs. Both
        // = nothing to fetch.
        if (blobs.isNullOrEmpty()) return ReportOutcome.Empty

        // Transient buffer dir. Each blob writes here first via the FFI
        // then immediately moves to public Downloads.
        val cacheRoot = File(appContext.cacheDir, "archive_recovery/$reportId").apply { mkdirs() }
        var lastPublicPath: String? = null
        // Collect the MP4 displayNames that landed in public
        // Downloads so we can write a playlist.m3u afterwards. Manifest
        // JSONs are excluded (moveToPublicDownloads marks them isMp4=false).
        val savedMp4Names = mutableListOf<String>()

        try {
            var i = 0
            for (blob in blobs) {
                i += 1
                // M-1 (WP-C): the relay supplies blob.filename and we join it onto
                // cacheRoot below; a coerced/seized relay must not path-traverse
                // out of the cache dir. Validate with the SHARED guard (exact same
                // rule as the CLI fetch-archive and the FFI download backstop).
                // Skip a poisoned name and keep going so one bad entry can't deny
                // the witness the rest of the recovery; the FFI download would
                // reject it too (InvalidBlob), this is the clean pre-check.
                if (!uniffi.frappuccino.archiveBlobFilenameIsSafe(blob.filename)) {
                    Timber.e(
                        "ArchiveDownloader: refusing unsafe relay filename %s — skipping",
                        blob.filename,
                    )
                    continue
                }
                val cacheTarget = File(cacheRoot, blob.filename)
                onBlob(blob.filename, i, blobs.size)

                // §10.11 — non-STRM raw blobs: the `.ots` timestamp proof, plus any
                // legacy `.fpm` (sealed manifest; no longer produced, but an old
                // report may still hold one). Fetch them RAW — STRM-decrypting them
                // would fail the header parse and abort the whole report.
                val isRawBlob = blob.filename.endsWith(".ots", ignoreCase = true) ||
                    blob.filename.endsWith(".fpm", ignoreCase = true)

                // Download with a few retries : a transient WiFi/cellular
                // blip (handoff, brief power-save) shouldn't kill the whole
                // report. The service's WifiLock prevents the sustained
                // screen-off stall ; this covers residual transients + slow
                // / degraded networks (the rescue flow's whole point).
                var attempt = 0
                var lastError: Exception? = null
                var ok = false
                while (attempt < MAX_BLOB_ATTEMPTS) {
                    attempt++
                    try {
                        if (isRawBlob) {
                            session.downloadRaw(
                                reportId, blob.filename, cacheTarget.absolutePath
                            )
                        } else {
                            session.downloadAndDecrypt(
                                reportId, blob.filename, cacheTarget.absolutePath, identity
                            )
                        }
                        ok = true
                        break
                    } catch (e: Exception) {
                        lastError = e
                        Timber.w(
                            e, "ArchiveDownloader: blob %s attempt %d/%d failed",
                            blob.filename, attempt, MAX_BLOB_ATTEMPTS,
                        )
                        try {
                            uniffi.frappuccino.secureDeleteFile(cacheTarget.absolutePath)
                        } catch (_: Exception) {
                            cacheTarget.delete()
                        }
                        if (attempt < MAX_BLOB_ATTEMPTS) delay(BLOB_RETRY_BACKOFF_MS * attempt)
                    }
                }
                if (!ok) {
                    Timber.e(
                        lastError, "ArchiveDownloader: blob %s failed after %d attempts",
                        blob.filename, MAX_BLOB_ATTEMPTS,
                    )
                    return ReportOutcome.Failure("${blob.filename}: ${lastError?.message}")
                }

                // §10.11 (lean "hash + Bitcoin") — for the `.ots` timestamp proof,
                // re-derive the per-recording OTS salt from the phrase-derived
                // signer and export it next to the proof, so the verifier can
                // recompute the salted commitment (SHA-256(salt ‖ media root)).
                // The salt is NEVER on the relay (re-derived here from the seed);
                // exported only when the signer is available (present iff the
                // rescue had the phrase). No manifest, no cert — attribution is
                // on-demand at disclosure, never a stored artifact. Best-effort.
                if (blob.filename.endsWith(".ots", ignoreCase = true) && provenanceSigner != null) {
                    try {
                        val sid = blob.filename.substringBeforeLast('.')
                        val salt = provenanceSigner.otsSalt(recordingIdFor(sid))
                        val saltHex = salt.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                        val saltCache = File(cacheRoot, "$sid.otssalt")
                        saltCache.writeText(saltHex)
                        moveToPublicDownloads(saltCache, reportId, saltCache.name)
                        Timber.i("Provenance OTS salt exported for %s", sid)
                    } catch (e: Exception) {
                        Timber.w(e, "OTS salt export during rescue failed (non-fatal) for %s", blob.filename)
                    }
                }

                // Capture size BEFORE the move : moveToPublicDownloads
                // secure-deletes the cache source, so length() after = 0.
                val sizeBytes = cacheTarget.length()
                val moved = moveToPublicDownloads(cacheTarget, reportId, blob.filename)
                if (moved != null) {
                    lastPublicPath = moved.path
                    if (moved.isMp4) savedMp4Names.add(moved.displayName)
                }
                Timber.d(
                    "Recovered %s -> %s (%d bytes)",
                    blob.filename, moved?.path ?: "(move failed)", sizeBytes,
                )
            }

            // Write playlist.m3u inside the same public
            // folder. Non-fatal if it fails (the MP4s are still there).
            if (savedMp4Names.isNotEmpty()) {
                try {
                    writePlaylistM3u(reportId, savedMp4Names.sorted())
                } catch (e: Exception) {
                    Timber.w(e, "playlist.m3u generation failed for %s (non-fatal)", reportId)
                }
            }

            val parentDir = lastPublicPath?.substringBeforeLast('/')
                ?: "Download/Frappuccino/$reportId"
            return ReportOutcome.Success(parentDir, blobs.size)
        } finally {
            // Sweep the transient cacheDir buffer. Each source is
            // secure-deleted right after a successful move; this clears
            // any partial leftover on early exit (failure / cancellation).
            try {
                cacheRoot.listFiles()?.forEach { f ->
                    try {
                        uniffi.frappuccino.secureDeleteFile(f.absolutePath)
                    } catch (_: Exception) {
                        f.delete()
                    }
                }
                cacheRoot.delete()
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Purge any MediaStore entries (or legacy
     * files) under `Downloads/Frappuccino/<rid>/` before a re-download.
     * Without this, a second pass on an already-saved report would create
     * suffixed duplicates (`chunk_000001 (1).mp4`, `(2).mp4`, …) via
     * MediaStore's collision policy. Non-fatal on failure.
     */
    fun clearReportFolder(rid: String) {
        val relativeDir = "${Environment.DIRECTORY_DOWNLOADS}/Frappuccino/$rid"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val resolver = appContext.contentResolver
                val sel = "${MediaStore.Downloads.RELATIVE_PATH} = ?"
                val args = arrayOf("$relativeDir/")
                var deleted = 0
                resolver.query(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    arrayOf(MediaStore.Downloads._ID),
                    sel, args, null,
                )?.use { c ->
                    while (c.moveToNext()) {
                        val id = c.getLong(0)
                        val uri = ContentUris.withAppendedId(
                            MediaStore.Downloads.EXTERNAL_CONTENT_URI, id,
                        )
                        if (resolver.delete(uri, null, null) > 0) deleted++
                    }
                }
                Timber.i("clearReportFolder: purged %d entries for %s", deleted, rid)
            } catch (e: Exception) {
                Timber.w(e, "clearReportFolder failed for %s (non-fatal)", rid)
            }
        } else {
            @Suppress("DEPRECATION")
            val publicDir = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS
            )
            val targetDir = File(publicDir, "Frappuccino/$rid")
            if (targetDir.isDirectory) {
                // Purge each file's MediaStore entry (and the
                // system thumbnail the provider derived from it) by path before
                // the raw delete. A bare File.delete() orphans the thumbnail in
                // the media-provider cache, leaving a recoverable preview of
                // decrypted footage the user believes erased — the secure-delete
                // promise must cover the thumbnail too. On pre-Q the provider
                // owns the file so this also removes it; the raw delete stays as
                // a fallback for any file never scanned into MediaStore.
                val resolver = appContext.contentResolver
                @Suppress("DEPRECATION")
                val dataSel = "${MediaStore.MediaColumns.DATA} = ?"
                targetDir.listFiles()?.forEach { f ->
                    try {
                        resolver.delete(
                            MediaStore.Files.getContentUri("external"),
                            dataSel,
                            arrayOf(f.absolutePath),
                        )
                    } catch (e: Exception) {
                        Timber.w(e, "clearReportFolder <Q: MediaStore purge failed for %s", f.name)
                    }
                    f.delete()
                }
            }
        }
    }

    /**
     * Recompute the manifest's 16-byte recording id from the session id (the
     * `.fpm` filename stem). This has to stay exactly the derivation
     * `StreamRecordingService` used at record time — `SHA-256(sessionId)[..16]`
     * — because the OTS salt re-derived from it has to match what the manifest
     * committed. A different derivation here breaks nothing visible: the
     * disclosure bundle simply stops verifying (§10.11 Phase B).
     */
    private fun recordingIdFor(sessionId: String): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(sessionId.toByteArray(Charsets.UTF_8))
            .copyOf(16)

    /**
     * Copy a decrypted plaintext from `cacheDir/...` to public
     * `Downloads/Frappuccino/<rid>/`. On success, secure-deletes the cacheDir
     * source. Sniffs the first byte to route the session manifest
     * (`{` → `<base>.json`, `application/json`) away from MP4, so Android
     * Photos doesn't choke on an unplayable JSON masked as `.mp4`
     * (Phase 4.4.2/4.4.6).
     */
    private fun moveToPublicDownloads(
        srcFile: File,
        rid: String,
        originalFilename: String,
    ): MoveResult? {
        // §10.11 — provenance artifacts (.fpm sealed manifest, .manifest unsealed,
        // .ots timestamp proof, .otssalt blinding salt) keep their verbatim name +
        // a binary mime; never sniffed, never an MP4 (excluded from playlist.m3u
        // via isMp4=false below).
        val isProvenanceArtifact = originalFilename.endsWith(".fpm", ignoreCase = true) ||
            originalFilename.endsWith(".manifest", ignoreCase = true) ||
            originalFilename.endsWith(".ots", ignoreCase = true) ||
            originalFilename.endsWith(".otssalt", ignoreCase = true)

        // Sniff first byte. `{` (0x7B) → JSON manifest. Skipped
        // for every provenance artifact listed above: a `.fpm` is a
        // `crypto_box_seal` envelope starting with a random ephemeral public
        // key, so no first byte identifies it.
        val isJsonManifest: Boolean = if (isProvenanceArtifact) false else try {
            FileInputStream(srcFile).use { input ->
                val b = input.read()
                b >= 0 && b.toByte() == '{'.code.toByte()
            }
        } catch (e: Exception) {
            Timber.w(e, "moveToPublicDownloads: first-byte sniff failed, defaulting to MP4")
            false
        }

        val displayName: String
        val mime: String
        val countsAsMp4: Boolean
        when {
            isProvenanceArtifact -> {
                // Keep the original <sessionId>.fpm name verbatim.
                displayName = originalFilename
                mime = "application/octet-stream"
                countsAsMp4 = false
            }
            else -> {
                val base = originalFilename
                    .removeSuffix(".strm")
                    .removeSuffix(".mp4")
                    .removeSuffix(".json")
                displayName = if (isJsonManifest) "$base.json" else "$base.mp4"
                mime = if (isJsonManifest) "application/json" else "video/mp4"
                countsAsMp4 = !isJsonManifest
            }
        }
        val relativeDir = "${Environment.DIRECTORY_DOWNLOADS}/Frappuccino/$rid"

        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Keep this purge: it is what makes the per-chunk publish
                // idempotent, and dropping it can make a recovered testimony
                // disappear from the gallery without any error. A re-rescue of an
                // already-recovered report runs with clearFirst=false
                // (cross-session re-tap, or a bulk resume), so clearReportFolder
                // never ran and the same <sid>_NNNNNN.mp4 is still on disk. A bare
                // insert then collides, and how it collides depends on the
                // MediaStore provider: AOSP suffixes a `(1)`/`(2)` duplicate
                // (OnePlus), while the MediaTek provider mis-types the stale row
                // as application/octet-stream and refuses to index it into
                // video/media (Seeker → invisible in gallery). Dropping any prior
                // entry for this exact display name first makes the fresh insert
                // REPLACE rather than duplicate, and clears a mis-typed stale row
                // so the clean video/mp4 insert lands (field-fix 2026-06-29).
                purgeExistingDownloadEntry(rid, displayName)
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, displayName)
                    put(MediaStore.Downloads.MIME_TYPE, mime)
                    put(MediaStore.Downloads.RELATIVE_PATH, relativeDir)
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val resolver = appContext.contentResolver
                val uri = resolver.insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI, values
                ) ?: throw IOException("MediaStore.insert returned null")
                resolver.openOutputStream(uri)?.use { out ->
                    FileInputStream(srcFile).use { it.copyTo(out) }
                } ?: throw IOException("MediaStore openOutputStream returned null")
                val publishValues = ContentValues().apply {
                    put(MediaStore.Downloads.IS_PENDING, 0)
                }
                resolver.update(uri, publishValues, null, null)
                try {
                    uniffi.frappuccino.secureDeleteFile(srcFile.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "moveToPublicDownloads: secureDelete cache failed")
                    srcFile.delete()
                }
                MoveResult(
                    path = "$relativeDir/$displayName",
                    displayName = displayName,
                    isMp4 = countsAsMp4,
                )
            } else {
                @Suppress("DEPRECATION")
                val publicDir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS
                )
                val targetDir = File(publicDir, "Frappuccino/$rid").apply { mkdirs() }
                val target = File(targetDir, displayName)
                srcFile.copyTo(target, overwrite = true)
                try {
                    uniffi.frappuccino.secureDeleteFile(srcFile.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "moveToPublicDownloads: secureDelete cache failed (legacy)")
                    srcFile.delete()
                }
                MoveResult(
                    path = target.absolutePath,
                    displayName = displayName,
                    isMp4 = countsAsMp4,
                )
            }
        } catch (e: Exception) {
            Timber.e(e, "moveToPublicDownloads failed for %s", displayName)
            null
        }
    }

    /**
     * Delete any existing MediaStore entry at
     * `Downloads/Frappuccino/<rid>/<displayName>` so a re-publish replaces it
     * instead of letting the provider auto-suffix a `(1)`/`(2)` duplicate.
     * Shared by [moveToPublicDownloads] and [writePlaylistM3u].
     *
     * The Q+ guard below is not a coverage hole waiting to be filled: the
     * pre-Q branch of [moveToPublicDownloads] writes through
     * `copyTo(overwrite = true)`, so the file is overwritten in place and no
     * duplicate can appear. Do not read that as "pre-Q files are not in
     * MediaStore" : they can well be, which is why the pre-Q branch of
     * [clearReportFolder] purges their entries — and the thumbnails the
     * provider derived from them — before deleting. And do not turn the catch
     * into a rethrow — a query/delete failure has to fall through to the
     * insert, which at worst duplicates, the behaviour that predates this
     * fix. Throwing here would instead be caught by [moveToPublicDownloads],
     * which returns null, and that chunk would never reach public Downloads
     * at all: a MediaStore provider hiccup would cost a piece of the rescued
     * footage (field-fix 2026-06-29).
     */
    private fun purgeExistingDownloadEntry(rid: String, displayName: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        val relativeDir = "${Environment.DIRECTORY_DOWNLOADS}/Frappuccino/$rid"
        val resolver = appContext.contentResolver
        try {
            val sel = "${MediaStore.Downloads.RELATIVE_PATH} = ? AND " +
                "${MediaStore.Downloads.DISPLAY_NAME} = ?"
            val args = arrayOf("$relativeDir/", displayName)
            resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                arrayOf(MediaStore.Downloads._ID),
                sel, args, null,
            )?.use { c ->
                while (c.moveToNext()) {
                    val id = c.getLong(0)
                    val uri = ContentUris.withAppendedId(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI, id,
                    )
                    resolver.delete(uri, null, null)
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "purgeExistingDownloadEntry: query/delete failed for %s (non-fatal)", displayName)
        }
    }

    /**
     * Write a `playlist.m3u` next to the downloaded MP4
     * chunks so VLC / MX Player / Plex can chain them as one virtual
     * movie without re-encoding. Relative filenames (same directory), so
     * it survives a copy/move of the whole folder. Any pre-existing
     * playlist for this rid is deleted first.
     */
    private fun writePlaylistM3u(rid: String, mp4Filenames: List<String>) {
        if (mp4Filenames.isEmpty()) return
        val playlistName = "playlist.m3u"
        val relativeDir = "${Environment.DIRECTORY_DOWNLOADS}/Frappuccino/$rid"
        val content = buildString {
            append("#EXTM3U\n")
            append("# Frappuccino archive — report ")
            append(rid)
            append(" — ")
            append(mp4Filenames.size)
            append(" chunks\n")
            for (name in mp4Filenames) {
                append("#EXTINF:5,")
                append(name)
                append('\n')
                append(name)
                append('\n')
            }
        }.toByteArray(Charsets.UTF_8)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = appContext.contentResolver
            // Idempotent: drop a stale playlist for this rid before re-inserting.
            purgeExistingDownloadEntry(rid, playlistName)

            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, playlistName)
                put(MediaStore.Downloads.MIME_TYPE, "audio/x-mpegurl")
                put(MediaStore.Downloads.RELATIVE_PATH, relativeDir)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = resolver.insert(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI, values,
            ) ?: throw IOException("MediaStore.insert returned null for playlist")
            resolver.openOutputStream(uri)?.use { it.write(content) }
                ?: throw IOException("MediaStore openOutputStream returned null for playlist")
            val publishValues = ContentValues().apply {
                put(MediaStore.Downloads.IS_PENDING, 0)
            }
            resolver.update(uri, publishValues, null, null)
        } else {
            @Suppress("DEPRECATION")
            val publicDir = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS
            )
            val targetDir = File(publicDir, "Frappuccino/$rid").apply { mkdirs() }
            File(targetDir, playlistName).writeBytes(content)
        }
    }

    companion object {
        private const val MAX_BLOB_ATTEMPTS = 3
        private const val BLOB_RETRY_BACKOFF_MS = 1000L
    }
}
