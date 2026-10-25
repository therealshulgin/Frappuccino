package rs.readahead.washington.mobile.util.jobs

import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.upload.ArchiveSession
import rs.readahead.washington.mobile.archive.RescueSession
import java.util.concurrent.atomic.AtomicInteger
import uniffi.frappuccino.ProvenanceSigner as FfiProvenanceSigner

/**
 * Process-local RAM holder of the rescue secrets, shared by the archive
 * screens (`ArchiveModeActivity`, `ArchivePlayerActivity`) and
 * `ArchiveDownloadService`.
 *
 * Never carry these secrets any other way — not an Intent extra, not a
 * Bundle, not a persisted field — even though parcelling them is the obvious
 * Android reflex for replacing a singleton like this one. The
 * [ArchiveIdentity] wraps the x25519 secret key (mlock'd + ZeroizeOnDrop on
 * the Rust side), the provenance signer holds the seed-derived provenance
 * secret, and the [ArchiveSession] holds the links of the report key chain;
 * sending any of them across Binder would expose a secret to a device-seizure
 * adversary, exactly the leak class [UploadAuthHolder] exists to avoid. Only
 * public values (a report's position in the list, a random directory name)
 * belong in an Intent.
 *
 * Ownership and wipe, "the last one alive wipes": every archive screen
 * [attachActivity]s in `onCreate` and [detachActivity]s in `onDestroy`; the
 * service runs batches with what it borrows from here. Whoever ends while the
 * other side is gone performs the final [clear] (and the purge of the local
 * copies, see `ArchiveLocalData`):
 *   - a screen destroyed while a batch runs leaves everything to the service,
 *     which clears when the batch ends if no screen is attached by then;
 *   - a batch that ends while a screen is attached leaves everything to the
 *     screens, the last of which clears when it goes.
 * A counter rather than a flag, because the player is a second screen on top
 * of the rescue screen: with a flag, closing the player would wipe the
 * identity from under the screen below. The calls behind [clear] are
 * idempotent, so a race between the two paths is a harmless double no-op.
 *
 * The references are RAM-only and lost at process death. Do not repair that
 * by persisting them: the loss is intended and costs nothing, since nothing
 * here can be reconstructed without re-entering the phrase anyway.
 */
object ArchiveAuthHolder {

    @Volatile
    private var identity: ArchiveIdentity? = null

    @Volatile
    private var session: ArchiveSession? = null

    // The phrase-derived provenance signer, held so the rescue can re-derive
    // the per-recording timestamp salt (HKDF(provenance seed, recording_id)).
    // Null when its derivation failed: the timestamp check is then skipped.
    @Volatile
    private var provenanceSigner: FfiProvenanceSigner? = null

    private val attached = AtomicInteger(0)

    /** True while at least one archive screen is alive. */
    val activityAlive: Boolean get() = attached.get() > 0

    /** Register an archive screen (from its `onCreate`). */
    fun attachActivity() {
        attached.incrementAndGet()
    }

    /** Unregister an archive screen (from its `onDestroy`); returns how many
     *  are still alive. Never goes below zero. */
    fun detachActivity(): Int {
        // A compare-and-set loop rather than updateAndGet, which needs API 24.
        while (true) {
            val now = attached.get()
            val next = if (now > 0) now - 1 else 0
            if (attached.compareAndSet(now, next)) return next
        }
    }

    /** Install the secrets derived at unlock. Replaces (and wipes) any
     *  previous set. */
    fun set(id: ArchiveIdentity, sess: ArchiveSession, provSigner: FfiProvenanceSigner?) {
        if (identity !== id || session !== sess) clear()
        identity = id
        session = sess
        provenanceSigner = provSigner
    }

    /** Whether a phrase has been unlocked and not wiped since. */
    fun isUnlocked(): Boolean = identity?.isClosed == false && session != null

    fun getIdentity(): ArchiveIdentity? = identity

    fun getSession(): ArchiveSession? = session

    fun getProvenanceSigner(): FfiProvenanceSigner? = provenanceSigner

    /**
     * Wipe the held secrets (rescue context, identity, provenance signer) and
     * the rescue's in-memory state, and drop the references. Idempotent: the
     * underlying `close()` / `destroy()` calls are no-ops once already
     * called, so every screen and the service can call this without harm.
     * It does not touch the files on disk: that is `ArchiveLocalData`'s job.
     */
    fun clear() {
        val sess = session
        val id = identity
        val signer = provenanceSigner
        session = null
        identity = null
        provenanceSigner = null
        RescueSession.reset()
        try {
            sess?.close()
        } catch (_: Exception) {
        }
        try {
            id?.close()
        } catch (_: Exception) {
        }
        try {
            signer?.destroy()
        } catch (_: Exception) {
        }
    }
}
