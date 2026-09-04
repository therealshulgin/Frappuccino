package rs.readahead.washington.mobile.util.jobs

import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Circuit breaker en mémoire pour les uploads chunks : un compteur de 5xx
 * consécutifs unique, partagé par tous les workers.
 *
 * Tant que le circuit est ouvert, un worker qui démarre doit rendre la main
 * immédiatement par `Result.retry()`, sans envoyer la moindre requête, et
 * jamais par `Result.failure()` : échouer définitivement laisse sur
 * l'appareil un blob que le relais aurait accepté un peu plus tard.
 *
 * Ce n'est pas un doublon du backoff EXPONENTIAL de WorkManager, et le
 * retirer sous ce motif rouvre le problème qu'il traite. Ce backoff est
 * par-worker et ne se coordonne pas entre workers : chacun a sa propre
 * courbe. Après une coupure serveur (genre relay 502 pendant 5 min), tous
 * les workers en queue (potentiellement 100+ chunks accumulés sur 5G
 * fluctuante) re-tapent le serveur en cluster dès qu'il revient, ce qui peut
 * le réabattre. Le backoff gère "n'attaque pas le réseau trop souvent depuis
 * CE worker", le circuit gère "n'attaque pas le serveur depuis AUCUN worker
 * s'il est down".
 *
 * Singleton `object` kotlin, qui vit dans le main process de l'app, là où
 * WorkManager run par défaut. L'état est perdu au process death : ne pas le
 * persister sur disque, un cold start doit rester une opportunité fraîche de
 * re-tenter plutôt que de prolonger une ouverture de circuit au-delà de sa
 * raison d'être.
 */
object UploadCircuitBreaker {
    /** 3x 5xx consécutifs → on considère le serveur down. */
    private const val THRESHOLD = 3

    /** Durée de l'état OPEN avant un essai HALF-OPEN. */
    private const val COOLDOWN_MS = 60_000L  // 1 min

    /**
     * Phase 1.12 — cooldown spécifique au disk-full (HTTP 507). Plus long
     * que [COOLDOWN_MS] : un disque plein ne se vide pas en 60 s (il faut
     * une action admin ou la purge TTL des vieux blobs), donc on évite de
     * re-sonder en boucle un serveur physiquement incapable de stocker.
     * Le blob reste sur le device (le worker return Result.retry(), jamais
     * failure) et remonte dès qu'il y a de la place.
     */
    private const val DISK_FULL_COOLDOWN_MS = 5 * 60_000L  // 5 min

    /**
     * Bound on a stuck probe. If the worker that won the half-open CAS
     * never reports success or failure (e.g. process killed mid-PUT,
     * NetworkCallback silent death), the in-flight flag would block all
     * subsequent workers indefinitely, leaving their chunks on the
     * device. After this timeout we re-allow probing (Blue HIGH-5 fix,
     * 2026-05-18).
     *
     * This 90 s no longer bounds what it was sized against, and the
     * value needs re-deciding. Where the number came from : 60 s plus a
     * margin, the 60 s credited to an OkHttp callTimeout — a value this
     * client does not carry (its 60 s is the writeTimeout), so take the
     * 60 s as the origin of the figure, not as a derivation to redo.
     * Meanwhile the chunk PUT left OkHttp for the Rust transports, which
     * bound one PUT at 120 s (`upload.rs`, `quic.rs`).
     * A slow-but-alive probe can therefore be declared stuck here and a
     * second worker released onto a relay that may still be down. Do not
     * re-derive the value from the OkHttp callTimeout : it is 120 s in
     * [UploadHttpClient], and it is not on the chunk path anyway.
     */
    private const val PROBE_TIMEOUT_MS = 90_000L

    @Volatile private var consecutive5xx: Int = 0
    @Volatile private var openUntilMs: Long = 0L

    /**
     * Phase 1.12 — set when the server last returned HTTP 507 (disk-full),
     * cleared on the next successful upload (space freed) or [reset]. Read
     * by the foreground notification (StreamRecordingService) to surface a
     * "serveur plein — contacte l'admin" message to the user.
     */
    @Volatile private var diskFull: Boolean = false

    /**
     * Half-open probe gate. Without it, when the cooldown elapses with N
     * workers in queue (all blocked at isOpen()=true during the
     * cooldown), they all see isOpen()=false simultaneously and tap the
     * still-down server together : a fresh burst of PUTs on a relay that
     * may still be 5xx-ing, before the first reportServerError() can
     * re-OPEN the circuit. That burst is the very herd the breaker
     * exists to prevent, reintroduced at the exit of the cooldown, and
     * it is why this flag is not redundant with openUntilMs.
     *
     * The gate lets exactly ONE worker through at a time after the
     * cooldown ; others see isOpen()=true until that worker reports. No
     * ratchet auth slot is at stake here : the fallback re-auth is
     * serialised by ChunkUploadWorker.authFallbackLock, it runs before
     * this gate, and only the creation chunk needs a bearer
     * (Blue HIGH-5 fix, Phase H2-B.13).
     */
    private val halfOpenProbeInFlight = AtomicBoolean(false)
    @Volatile private var halfOpenProbeStartMs: Long = 0L

    /**
     * Ce n'est pas une lecture d'état, c'est une opération qui le mute : en
     * half-open, seul le worker qui gagne le CAS sur
     * [halfOpenProbeInFlight] obtient `false` et consomme la sonde ; les
     * autres voient `true` (circuit still open) jusqu'à ce qu'il appelle
     * `reportSuccess()` ou `reportServerError()` (Phase H2-B.13). Ne pas
     * ajouter d'appel de confort — log, badge d'UI, garde défensive en
     * amont : il volerait le slot de sonde au worker qui allait vraiment
     * tenter le PUT.
     *
     * `true` veut dire différer par `Result.retry()` sans taper le serveur,
     * jamais `Result.failure()` : le blob doit rester sur l'appareil pour
     * repartir plus tard. `false` ne dit pas que le relais va bien,
     * seulement que l'appelant est autorisé à essayer (CLOSED, ou cooldown
     * expiré et c'est vous la sonde).
     */
    @Synchronized
    fun isOpen(): Boolean {
        val now = System.currentTimeMillis()
        if (now < openUntilMs) return true
        // Cooldown elapsed → transition to half-open phase.
        if (openUntilMs > 0L) {
            Timber.i("[Phase 2.4.4] Circuit cooldown écoulé, half-open")
            openUntilMs = 0L
            consecutive5xx = 0
            // Mark the start of the half-open phase.
            // halfOpenProbeStartMs > 0L is the indicator that the
            // probe gate is active. It stays > 0 until the next
            // reportSuccess() or reportServerError() exits the phase.
            halfOpenProbeStartMs = now
            halfOpenProbeInFlight.set(false)
        }
        // CLOSED steady state : not in half-open phase, no gate.
        if (halfOpenProbeStartMs == 0L) {
            return false
        }
        // Stuck probe protection : if a previous probe never reported
        // success/failure (process killed mid-PUT, NetworkCallback
        // silent death), allow the next worker to retry after the
        // timeout. Reset the start window so the timeout restarts.
        if (halfOpenProbeInFlight.get()
            && (now - halfOpenProbeStartMs) > PROBE_TIMEOUT_MS
        ) {
            Timber.w(
                "[Phase H2-B.13] half-open probe stuck for %d ms, clearing",
                now - halfOpenProbeStartMs,
            )
            halfOpenProbeInFlight.set(false)
            halfOpenProbeStartMs = now
        }
        // Win the CAS = you're the probe, isOpen() returns false ; lose =
        // isOpen() returns true, the circuit stays OPEN from your point of
        // view until the probe reports. Single worker per half-open cycle.
        if (halfOpenProbeInFlight.compareAndSet(false, true)) {
            Timber.i("[Phase H2-B.13] half-open probe acquired")
            return false
        }
        return true
    }

    /** Appelé après chaque upload réussi (HTTP 2xx). */
    @Synchronized
    fun reportSuccess() {
        if (consecutive5xx > 0 || openUntilMs > 0L) {
            Timber.d("[Phase 2.4.4] Upload OK — reset compteurs (était %d/%d, openUntil=%d)",
                consecutive5xx, THRESHOLD, openUntilMs)
        }
        consecutive5xx = 0
        openUntilMs = 0L
        diskFull = false  // Phase 1.12 — a success means space is available again
        // Release the probe slot. The next worker that
        // hits isOpen() will see CLOSED directly (no probe needed).
        halfOpenProbeInFlight.set(false)
        halfOpenProbeStartMs = 0L
    }

    /** Appelé sur HTTP 5xx (ou network error qui ressemble à serveur down). */
    @Synchronized
    fun reportServerError(httpCode: Int) {
        consecutive5xx++
        Timber.w("[Phase 2.4.4] Server error %d (consecutive=%d/%d)",
            httpCode, consecutive5xx, THRESHOLD)
        if (consecutive5xx >= THRESHOLD) {
            openUntilMs = System.currentTimeMillis() + COOLDOWN_MS
            Timber.w("[Phase 2.4.4] Circuit OPEN — cooldown %ds", COOLDOWN_MS / 1000)
        }
        // Release the probe slot whether we re-OPEN or
        // not. If we re-OPEN, subsequent workers see openUntilMs in
        // the future and return true at the isOpen() entry guard. If
        // we don't (consecutive5xx < THRESHOLD), halfOpenProbeStartMs goes
        // back to 0, so the gate is disarmed rather than re-armed for one
        // worker : every waiting worker passes again until THRESHOLD
        // consecutive 5xx re-OPEN the circuit. The multi-error tolerance
        // is intentional, but this is not a single-probe path.
        halfOpenProbeInFlight.set(false)
        halfOpenProbeStartMs = 0L
    }

    /**
     * Server returned HTTP 507 (MinIO disk-full). The caller returns
     * Result.retry() (NEVER failure) so the blob is preserved on-device and
     * uploads once an admin frees space or the blob TTL purges old data ;
     * on the creation chunk (seq 0) a permanent failure would additionally
     * strand every later chunk of the report on 425. [isDiskFull] then
     * drives the user-facing notification.
     *
     * Distinct from a transient 5xx because retrying on the next backoff
     * bucket is futile : the disk won't free itself, it takes an admin
     * action or the TTL purge. Hence the immediate open, without waiting
     * for [THRESHOLD] consecutive errors, and the longer
     * [DISK_FULL_COOLDOWN_MS] (Phase 1.12).
     */
    @Synchronized
    fun reportDiskFull() {
        diskFull = true
        consecutive5xx = THRESHOLD  // reflect "tripped" for state()/debug
        openUntilMs = System.currentTimeMillis() + DISK_FULL_COOLDOWN_MS
        halfOpenProbeInFlight.set(false)
        halfOpenProbeStartMs = 0L
        Timber.w("[Phase 1.12] Circuit OPEN (disk-full 507) — cooldown %ds",
            DISK_FULL_COOLDOWN_MS / 1000)
    }

    /** Phase 1.12 — true since the last HTTP 507, until the next success. */
    fun isDiskFull(): Boolean = diskFull

    /** Reset complet, exposé pour les tests + debug. */
    @Synchronized
    fun reset() {
        consecutive5xx = 0
        openUntilMs = 0L
        diskFull = false
        halfOpenProbeInFlight.set(false)
        halfOpenProbeStartMs = 0L
    }

    /**
     * État grossier pour debug/UI éventuelle : OPEN tant que
     * `now < openUntilMs`, CLOSED sinon. [state] ne regarde ni
     * consecutive5xx ni la phase half-open — pendant celle-ci il peut
     * renvoyer CLOSED alors que [isOpen] gate encore les workers qui ne
     * sont pas la sonde.
     */
    enum class State { CLOSED, OPEN }

    @Synchronized
    fun state(): State =
        if (System.currentTimeMillis() < openUntilMs) State.OPEN else State.CLOSED
}
