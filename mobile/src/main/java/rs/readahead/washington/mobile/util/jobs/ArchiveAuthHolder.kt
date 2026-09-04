package rs.readahead.washington.mobile.util.jobs

import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.upload.ArchiveSession
import uniffi.frappuccino.ProvenanceSigner as FfiProvenanceSigner

/**
 * Process-local RAM holder that hands the unlocked archive identity and the
 * authenticated session from `ArchiveModeActivity` to
 * `ArchiveDownloadService` (Phase 4.4.8).
 *
 * Never carry these secrets any other way — not an Intent extra, not a
 * Bundle, not a persisted field — even though parcelling them is the obvious
 * Android reflex for replacing a singleton like this one. The
 * [ArchiveIdentity] wraps the x25519 secret key (mlock'd + ZeroizeOnDrop on
 * the Rust side) and the [provenanceSigner] holds the seed-derived provenance
 * secret; sending either across Binder would expose a secret to a
 * device-seizure adversary, exactly the leak class [UploadAuthHolder] (audit
 * R-01) exists to avoid. Only public report ids belong in the Intent. (Phase C
 * relay-blind: the [ArchiveSession] is now identity-free — no bearer, no cached
 * mnemonic — so it carries no secret itself, but it rides along here too since
 * the activity hands the whole rescue context to the service at once.)
 *
 * Ownership and wipe, "last one alive wipes": by default the activity owns
 * the identity, the session and the provenance signer, and wipes them in its
 * `onDestroy`. While a batch runs, the service borrows them through this
 * holder. The [activityAlive] flag arbitrates who performs the final wipe:
 *   - activity destroyed mid-batch  → `activityAlive=false` → the
 *     service calls [clear] when it stops (the activity can't, it's gone).
 *   - batch finishes, activity alive → the service leaves them; the
 *     activity wipes on its own `onDestroy`.
 * Without that arbitration, either the secrets stay alive in RAM with nobody
 * left to call [clear], or the service wipes while the activity is still
 * downloading and the batch dies asking for the twelve words again. The wipe
 * calls behind [clear] are idempotent, so a race between the two paths is a
 * harmless double no-op.
 *
 * The references are RAM-only and lost at process death. Do not repair that
 * by persisting them: the loss is intended and costs nothing, since the
 * identity can't be reconstructed without re-entering the phrase anyway.
 */
object ArchiveAuthHolder {

    @Volatile
    private var identity: ArchiveIdentity? = null

    @Volatile
    private var session: ArchiveSession? = null

    // §10.11 Phase B — the phrase-derived provenance signer, held alongside the
    // identity so the rescue download can re-derive the per-recording OTS salt
    // (HKDF(provenance seed, recording_id)) to export into the disclosure bundle.
    // Same RAM-only, never-serialised, last-one-alive-wipes lifecycle as above.
    @Volatile
    private var provenanceSigner: FfiProvenanceSigner? = null

    /**
     * True while an `ArchiveModeActivity` instance is alive. Read by
     * `ArchiveDownloadService` to decide whether IT must perform the
     * final secret wipe (the activity is gone) or leave it to the
     * still-living activity.
     */
    @Volatile
    var activityAlive: Boolean = false
        private set

    /**
     * Hand the unlocked identity + authenticated session (+ optional provenance
     * signer for §10.11 Phase B OTS-salt re-derivation) to the service.
     */
    fun set(id: ArchiveIdentity, sess: ArchiveSession, provSigner: FfiProvenanceSigner?) {
        identity = id
        session = sess
        provenanceSigner = provSigner
    }

    fun getIdentity(): ArchiveIdentity? = identity

    fun getSession(): ArchiveSession? = session

    /** §10.11 Phase B — the phrase-derived provenance signer (null if the rescue
     *  device couldn't derive it), for re-deriving the OTS salt at disclosure. */
    fun getProvenanceSigner(): FfiProvenanceSigner? = provenanceSigner

    fun setActivityAlive(alive: Boolean) {
        activityAlive = alive
    }

    /**
     * Wipe the held secrets (session, identity, provenance signer) and drop
     * the references. Idempotent: the underlying `close()` / `destroy()`
     * calls are no-ops once already called, so the activity and the service
     * can both call this without harm.
     */
    fun clear() {
        try {
            session?.close()
        } catch (_: Exception) {
        }
        session = null
        try {
            identity?.close()
        } catch (_: Exception) {
        }
        identity = null
        // §10.11 Phase B — wipe the provenance signer (mlock'd seed) too.
        try {
            provenanceSigner?.destroy()
        } catch (_: Exception) {
        }
        provenanceSigner = null
    }
}
