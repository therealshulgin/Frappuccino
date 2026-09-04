package org.stream.crypto.capture

import android.content.Context
import android.content.pm.ApplicationInfo
import timber.log.Timber
import java.io.File

/**
 * Les deux endroits où de la vidéo EN CLAIR peut survivre à une session de
 * capture, et de quoi les effacer. Sur un appareil saisi, ces résidus se
 * lisent sans la phrase BIP-39.
 *
 *   1. **`filesDir/debug_raw*`** : copies en clair des MP4, écrites dès qu'un
 *      operator a activé le toggle `isDebugBitrateEnabled` (calibration
 *      fixed-bitrate) ou les boutons de test DEBUG (HEVC / rolling). Aucun TTL
 *      ne les reprend. Adversaire qui confisque le device en mode "lock" : si
 *      le toggle a été actif sur n'importe quelle session passée, la vidéo est
 *      lisible sans BIP-39 (audit Red Team 2026-05-18, R-H1 / R-E-1).
 *
 *   2. **MP4 orphelins dans `cacheDir/stream_chunks/`** : le `MediaMuxer`
 *      écrit le chunk EN CLAIR (`chunk-NNN.mp4`) sur disque, puis
 *      `StreamChunkEncryptor` le chiffre en `.strm` et le secure-delete. Deux
 *      familles d'orphelins, et la distinction compte :
 *        - **0-octet** : un swap qualité discard le preallocated next-chunk
 *          avant tout sample (fix in-bundle B-H3 à `stop()` ; ce cleaner
 *          couvre le legacy).
 *        - **non-vide** (F-01, cross-audit 2026-06-30) : un chunk finalisé
 *          dont le chiffrement a été interrompu par une mort ANORMALE du
 *          process (kill / OOM-kill / coupure batterie) ou un `panicWipe`
 *          survenu pendant le chiffrement. L'ancien cleaner ne purgeait que
 *          les 0-octet, donc ce MP4 en clair survivait sur device saisi.
 *      Ne pas compter sur le sweeper pour rattraper ça : `OrphanSweepWorker`
 *      (TTL 48 h) ne balaie que les `.strm` de la queue d'upload
 *      (`filesDir/stream_chunk_queue`), jamais ces `.mp4`.
 *
 * `purgeOrphanChunks` secure-delete **tout** `.mp4` orphelin, quelle que soit
 * sa taille, via `secureDeleteFile` Rust (overwrite + fsync + truncate +
 * unlink) ; `purgeDebugRaw` utilise le même primitive. Honnêteté du contrôle :
 * sur FBE / Flash NAND, **FBE reste le contrôle at-rest porteur**, l'overwrite
 * est de la défense en profondeur, pas un effacement garanti. Deux des trois
 * moments d'appel tournent hors capture : service start (pré-bind) et
 * `onDestroy` (post-drain). Le `panicWipe`, lui, court DÉLIBÉRÉMENT contre la
 * capture vivante — device saisi, on jette tout, y compris le chunk en cours
 * de chiffrement. Hors panic, ce n'est donc pas le choix du moment qui protège
 * le chunk live, c'est le paramètre `exceptCurrentPaths` de
 * [purgeOrphanChunks]. (Mis en place en H2-B.11, 2026-05-18.)
 */
object CaptureScratchCleaner {

    /**
     * `true` si le manifest a `android:debuggable="true"` (auto-set par
     * AGP en build debug, jamais en release). Defense-in-depth contre
     * un `BuildConfig.DEBUG` qui pourrait être tampered : on lit le flag
     * directement depuis `ApplicationInfo`.
     */
    fun isDebuggable(context: Context): Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    /**
     * Gate centralisé pour `saveRawDebugCopyIfEnabled` et tout futur
     * code qui voudrait écrire du plaintext sur disque pour calibration.
     * Retourne `false` en release builds même si la pref runtime est
     * active.
     */
    fun debugRawAllowed(context: Context): Boolean = isDebuggable(context)

    /**
     * All plaintext debug-capture dirs under `filesDir`. `debug_raw` is the
     * fixed-bitrate mirror (normal recording path); `debug_raw_hevc` and
     * `debug_rolling` are written by the DEBUG settings test buttons (HEVC /
     * rolling). All three are dev-only and must never survive on a seized
     * device — audit R-E-1 sibling finding (the test-button dirs were never
     * purged: panicWipe + service-start housekeeping only covered debug_raw).
     */
    private val PLAINTEXT_DEBUG_DIRS = listOf("debug_raw", "debug_raw_hevc", "debug_rolling")

    /**
     * Purge `filesDir/debug_raw*` : secure_delete chaque MP4 + delete
     * le dir. No-op si dir absent. Idempotent.
     */
    fun purgeDebugRaw(context: Context) {
        PLAINTEXT_DEBUG_DIRS.forEach { securePurgeDir(context, it) }
    }

    private fun securePurgeDir(context: Context, dirName: String) {
        val dir = File(context.filesDir, dirName)
        if (!dir.exists() || !dir.isDirectory) return
        var deleted = 0
        var failed = 0
        dir.listFiles()?.forEach { file ->
            try {
                uniffi.frappuccino.secureDeleteFile(file.absolutePath)
                deleted++
            } catch (e: Exception) {
                Timber.w(e, "secureDelete failed on %s/%s, fallback delete()", dirName, file.name)
                if (file.delete()) deleted++ else failed++
            }
        }
        // Remove the dir itself once empty so a future toggle-on triggers
        // a fresh mkdirs(). delete() is a no-op if dir still has entries
        // (failed wipe path) — that's fine, next purge will retry. Logging
        // keeps the audit trail.
        val dirRemoved = try {
            dir.delete()
        } catch (e: Exception) {
            Timber.w(e, "%s dir delete failed", dirName)
            false
        }
        Timber.tag("StreamMetrics").i(
            "debugRawPurged dir=%s deleted=%d failed=%d dirRemoved=%b",
            dirName, deleted, failed, dirRemoved
        )
    }

    /**
     * Secure-delete **chaque** `*.mp4` de [chunkDir] dont le chemin absolu
     * n'est PAS dans [exceptCurrentPaths], **quelle que soit sa taille**
     * (F-01, cross-audit 2026-06-30 — l'ancien filtre 0-octet laissait un
     * chunk finalisé-mais-non-chiffré récupérable en clair sur device saisi).
     * FBE reste le contrôle at-rest porteur ; ceci est de la défense en
     * profondeur sur le scénario « saisi pendant l'enregistrement ».
     *
     * Utilise `secureDeleteFile` Rust (overwrite + fsync + truncate + unlink)
     * avec un fallback `delete()` pour qu'un échec de wipe ne laisse jamais le
     * fichier en clair ; un fallback sur du plaintext est rendu observable via
     * `StreamMetrics` (F-06) plutôt qu'avalé silencieusement.
     *
     * L'appelant DOIT garantir qu'aucun recorder live n'écrit un fichier à
     * préserver : passer son chemin dans [exceptCurrentPaths], ou n'appeler
     * que hors capture (service start, pré-bind ; `onDestroy`, post-stop) ou
     * quand le nuke complet est voulu (`panicWipe`). Retourne le nombre de
     * fichiers supprimés.
     */
    fun purgeOrphanChunks(chunkDir: File, exceptCurrentPaths: Set<String> = emptySet()): Int {
        if (!chunkDir.exists() || !chunkDir.isDirectory) return 0
        var secure = 0
        var fallback = 0
        var failed = 0
        chunkDir.listFiles { _, name -> name.endsWith(".mp4") }?.forEach { file ->
            if (file.absolutePath in exceptCurrentPaths) return@forEach
            try {
                uniffi.frappuccino.secureDeleteFile(file.absolutePath)
                secure++
            } catch (e: Exception) {
                Timber.w(e, "secureDelete failed on orphan chunk %s, fallback delete()", file.name)
                if (file.delete()) fallback++ else failed++
            }
        }
        if (secure + fallback + failed > 0) {
            Timber.tag("StreamMetrics").i(
                "orphanChunksPurged dir=%s secure=%d plaintextFallback=%d failed=%d",
                chunkDir.name, secure, fallback, failed
            )
        }
        return secure + fallback
    }

    /**
     * Path conventionnel du chunkDir (cacheDir/stream_chunks). Exposé
     * pour les callsites (panicWipe, teardown) qui n'ont pas de
     * référence vers le recorder en cours. Reste internal-namespace —
     * toute reconfiguration du path devrait passer par ce helper pour
     * rester cohérente.
     */
    fun defaultChunkDir(context: Context): File =
        File(context.cacheDir, "stream_chunks")

    /**
     * Purge complète : miroirs plaintext debug + **tous** les MP4 orphelins
     * (toute taille, via secure-delete). À utiliser au `panicWipe` (device
     * saisi → on jette tout, y compris un chunk en cours de chiffrement) et
     * comme filet post-recording. PAS en cours de capture, sauf à passer le
     * chunk live du recorder dans [exceptCurrentPaths].
     */
    fun purgeAll(context: Context, chunkDir: File?, exceptCurrentPaths: Set<String> = emptySet()) {
        purgeDebugRaw(context)
        chunkDir?.let { purgeOrphanChunks(it, exceptCurrentPaths) }
    }

    /** Convenience overload using the default chunkDir path (nuke-all). */
    fun purgeAll(context: Context) {
        purgeAll(context, defaultChunkDir(context))
    }
}
