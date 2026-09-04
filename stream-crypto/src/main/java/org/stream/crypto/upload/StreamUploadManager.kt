package org.stream.crypto.upload

import android.content.Context
import org.stream.crypto.StreamIdentity
import org.stream.crypto.StreamPreferences
import uniffi.frappuccino.RatchetSignature
import uniffi.frappuccino.RotationProof
import uniffi.frappuccino.pinSessionPopulate
import uniffi.frappuccino.pinSessionOpenRatchet
import uniffi.frappuccino.pinSessionOpenProvenanceSigner
import uniffi.frappuccino.pinSessionOpenReportKeyring
import uniffi.frappuccino.pinSessionClear
import timber.log.Timber
import uniffi.frappuccino.EnrollResult as FfiEnrollResult
import uniffi.frappuccino.EphemeralRatchet as FfiRatchet
import uniffi.frappuccino.EnrollmentKit as FfiEnrollmentKit
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.StreamServerClient as FfiServerClient
import uniffi.frappuccino.ProvenanceSigner as FfiProvenanceSigner
import uniffi.frappuccino.ReportKeyring as FfiReportKeyring
import java.io.File

/**
 * StreamUploadManager — Coordinateur V2 du chiffrement + signature des uploads.
 *
 * Toute la chaîne crypto est passée côté Rust (migration UniFFI S8c.1 → S8c.5,
 * terminée) : enrôlement, ratchet, client serveur, chiffrement des chunks et
 * fast-reseal. Ce qui reste dans `stream-crypto/` sans passer par UniFFI
 * n'implémente plus aucune primitive : `Bip39.kt` se réduit à `stripAccents`,
 * `SecureWipe` / `StreamIdentity` / `StreamPreferences` sont du JVM pur.
 *
 * Ne plus faire de crypto n'est pas la même chose que ne plus toucher au
 * secret. `stripAccents` reçoit trois mots de la phrase en `String` JVM à la
 * confirmation d'onboarding (`OnBoardMnemonicConfirmFragment`), et une `String`
 * ne se wipe pas. Même résidu côté UDL : `bip39_normalize_word_fr` est resté en
 * `string` (`crypto-rs/ffi/src/frappuccino.udl:33`) là où `bip39_generate_fr`
 * et `bip39_validate_fr` sont passés en `bytes` — sans appelant de production
 * aujourd'hui, mais lui en écrire un ramènerait un mot de la phrase dans le
 * pool d'intern.
 *
 * Le fast-reseal passe par le holder de session PIN côté Rust
 * (`pinSession*` / `resealSessionBlob`) : la clé dérivée ne traverse plus la
 * FFI (R-CR-1).
 *
 * Cycle de vie :
 *   UNENROLLED → (enrollFromMnemonic) → UNLOCKED
 *   UNLOCKED → (lock) → LOCKED → (initializeWithPin) → UNLOCKED
 */
class StreamUploadManager private constructor(private val context: Context) {

    companion object {
        @Volatile private var instance: StreamUploadManager? = null

        fun getInstance(context: Context): StreamUploadManager =
            instance ?: synchronized(this) {
                instance ?: StreamUploadManager(context.applicationContext).also { instance = it }
            }

        /** Returns the current singleton, or null if [getInstance] has never been called. */
        fun getInstance(): StreamUploadManager? = instance
    }

    // -- État persistant (disque, cache RAM) --
    @Volatile var identity: StreamIdentity? = null
        private set

    /** Ratchet courant (UniFFI) si l'app est UNLOCKED. null si LOCKED ou UNENROLLED. */
    @Volatile var ratchet: FfiRatchet? = null
        private set

    /**
     * §10.11 — clé de signature de provenance dédiée (UniFFI), vivante si l'app
     * est UNLOCKED ET la provenance activée dans les réglages. null sinon.
     * Reconstruite au unlock depuis le seed PIN-scellé ; jamais en clair sur
     * disque, wipe au lock comme le ratchet.
     */
    @Volatile var provenanceSigner: FfiProvenanceSigner? = null
        private set

    /**
     * The report capability keyring (UniFFI), for relay-blind reports. Each
     * report's address + signing key `R_n` derives from the phrase through a
     * dedicated HKDF context, never from the identity, so the relay only ever
     * stores `report_id → report_pk` and never learns who.
     *
     * Its lifecycle must be the [provenanceSigner]'s and NOT the upload
     * bearer's: a seed-derived secret reconstructed at unlock from the
     * PIN-sealed `report_master`, wiped at [lock]. The bearer is wiped in the
     * background by a timer and is re-derivable; `report_master` is seed-derived
     * and not re-derivable without the PIN, so wiping it in the background would
     * break signing chunks during screen-off recording — unrecoverable data
     * loss. The provenance signer is field-proven to survive background
     * recording under exactly this lifecycle.
     */
    @Volatile var reportKeyring: FfiReportKeyring? = null
        private set

    // S8c.5 : toute la chaîne est désormais 100% UniFFI — plus aucun
    // `LazySodiumAndroid`, plus de `SecureMemory`, plus de `PinProtectedStore`.

    // Matériel pour fast-reseal : évite un Argon2id à chaque signature (~1 s).
    // La clé dérivée par Argon2id ne revient plus dans un ByteArray JVM
    // (invariant no-export, R-CR-1) : elle vit dans un holder process-global
    // Zeroizing côté Rust (PIN_SESSION, calque du holder de bearer upload).
    // Les appels combinés `pinSessionOpenRatchet` / `resealSessionBlob` /
    // `pinSessionOpen*` / `sealWithSession` ouvrent et scellent entièrement
    // côté Rust : ni la clé, ni le blob ratchet 50-sk, ni les seeds secondaires
    // ne traversent la FFI. `pinSessionClear()` zéroïse le holder — au lock, au
    // panic et à l'auto-lock drain-safe, JAMAIS sur un 401 (la raison est
    // écrite dans `lock()` : la clé n'est pas re-dérivable sans le PIN).

    // -- V2 HTTP client (UniFFI — configuré via setServerUrl) --
    @Volatile private var serverClient: FfiServerClient? = null
    @Volatile private var serverUrl: String? = null

    // -- Locks internes --
    private val ratchetLock = Any()

    // =========================================================================
    // ÉTATS & TRANSITIONS
    // =========================================================================

    fun isEnrolled(): Boolean = StreamPreferences.hasIdentity(context) &&
                                 StreamPreferences.hasRatchetBlob(context)

    fun isUnlocked(): Boolean = ratchet != null && identity != null

    fun isLocked(): Boolean = isEnrolled() && !isUnlocked()

    // =========================================================================
    // ENRÔLEMENT & UNLOCK
    // =========================================================================

    /**
     * Résultat d'un enrôlement — à envoyer au serveur via `POST /auth/v2/enroll`.
     */
    data class EnrollmentProof(
        val identity: StreamIdentity,
        val batch0PublicKeys: List<ByteArray>,  // 50 × 32 bytes
        val enrollmentSignature: ByteArray       // 64 bytes, signé par ed25519_sk
    )

    /**
     * Premier setup : dérive tout depuis la phrase BIP-39, initialise le ratchet,
     * stocke l'identité + le blob ratchet PIN-wrappé. Wipe toutes les clés privées.
     *
     * À appeler UNE FOIS au bout de l'onboarding.
     */
    @Synchronized
    fun enrollFromMnemonic(mnemonic: ByteArray, pin: ByteArray): EnrollmentProof {
        require(pin.isNotEmpty()) { "PIN must not be empty" }

        // `pin` ET `mnemonic` sont maintenant des
        // ByteArray, jamais convertis en String. Aucune fuite dans le pool
        // JVM. Les callers (OnBoardSetPinFragment) wipent leur copie dans
        // leur finally. Côté Rust, FfiEnrollmentKit.fromMnemonic prend
        // bytes et wrap immédiatement le mnemonic en Zeroizing<Vec<u8>>.
        val kit = FfiEnrollmentKit.fromMnemonic(mnemonic, byteArrayOf())
        try {
            // 1. Initialiser le ratchet depuis chain_0 (consume-once côté Rust).
            val ratchet = FfiRatchet.fromKit(kit)

            // 2. Signer batch_0 avec ed25519_sk (via EnrollmentKit).
            val batch0Pks = ratchet.batchPublicKeys()
            val batch0Concat = concatPublicKeys(batch0Pks)
            val enrollSig = kit.signEnrollment(batch0Concat)

            // 3. Snapshot public identity.
            val uniffiIdentity = kit.identity()
            val kotlinIdentity = StreamIdentity(
                ed25519PublicKey = uniffiIdentity.ed25519Pk(),
                x25519PublicKey = uniffiIdentity.x25519Pk()
            )
            uniffiIdentity.destroy()

            // 4. Persister : identity (publiques) + ratchet blob PIN-wrappé.
            StreamPreferences.saveIdentity(context, kotlinIdentity)
            // Lot 4b : sérialise + scelle (Argon2id) ENTIÈREMENT côté Rust — le
            // blob 50-sk ne traverse jamais la JVM (remplace serialize +
            // pinStoreSeal + wipe).
            val sealed = ratchet.sealWithPin(pin)
            StreamPreferences.saveRatchetBlob(context, sealed)

            // 5. Cache RAM pour utilisation immédiate (fast-reseal).
            //    Lot 4b : Argon2id une fois, le derived_key + salt sont stashés
            //    dans le holder Rust (jamais de retour ByteArray vers la JVM). Le
            //    ratchet est déjà en mémoire (issu du kit) ; le holder sert au
            //    fast-reseal + au scellement des seeds secondaires ci-dessous.
            pinSessionPopulate(pin, sealed)
            this.identity = kotlinIdentity
            this.ratchet = ratchet

            // §10.11 — dérive la clé de provenance dédiée depuis la même phrase
            // et scelle son seed 32 o avec la clé PIN du ratchet (nonce frais,
            // pas de second Argon2id). Toujours fait à l'enrôlement pour que
            // l'activation ultérieure de la provenance ne demande pas de
            // re-enroll. Best-effort : un échec ici ne doit JAMAIS casser
            // l'onboarding (la provenance est opt-in, non critique).
            try {
                val provSigner = FfiProvenanceSigner.fromMnemonic(mnemonic, byteArrayOf())
                // Tenu pour la session courante (juste enrôlé = déverrouillé), pour
                // que la provenance marche dès le 1er enregistrement post-onboarding
                // SANS lock/unlock. Wipe au lock comme le ratchet.
                this.provenanceSigner = provSigner
                // §10.11 (lean "hash + Bitcoin") — NO mini-cert. Attribution is
                // on-demand at disclosure, never baked into a stored, seizable
                // artifact (motto: a seizure exposes nothing). The provenance seed
                // is kept only to derive the per-recording OTS blinding salt.
                // Lot 4b (OPTION B) : le seed est scellé ENTIÈREMENT côté Rust
                // (lu dans le signer, scellé avec la clé du holder) — il ne
                // traverse jamais la JVM.
                StreamPreferences.saveProvenanceSeedBlob(
                    context, provSigner.sealWithSession()
                )
            } catch (e: Exception) {
                Timber.w(e, "provenance seed setup failed at enrollment (non-fatal)")
            }

            // Phase C (relay-blind reports) — derive the report capability
            // master seed from the same phrase and PIN-seal it with the ratchet
            // key (fresh nonce, no second Argon2id), exactly like the provenance
            // seed above. Held live for the current session so the first
            // post-onboarding recording addresses + signs its report without a
            // lock/unlock. Best-effort: a failure here must never break
            // onboarding (uploads degrade gracefully if the keyring is absent).
            try {
                val keyring = FfiReportKeyring.fromMnemonic(mnemonic, byteArrayOf())
                this.reportKeyring = keyring
                // Lot 4b (OPTION B) : le report_master est scellé ENTIÈREMENT côté
                // Rust (lu dans le keyring, scellé avec la clé du holder) — il ne
                // traverse jamais la JVM.
                StreamPreferences.saveReportMasterBlob(
                    context, keyring.sealWithSession()
                )
            } catch (e: Exception) {
                Timber.w(e, "report keyring setup failed at enrollment (non-fatal)")
            }

            Timber.d("V2 enrollment complete. Fingerprint: %s",
                kotlinIdentity.readableFingerprint())

            // Persist the proof BEFORE the network call so a
            // server-side failure during onboarding doesn't leave the
            // device permanently stuck in the "local enrolled, server
            // unknown" half-state. enrollOnServer() clears the entry on
            // success; the manual retry button + EnrollmentRetryWorker
            // read it back when the server becomes reachable.
            StreamPreferences.savePendingEnrollment(
                context,
                kotlinIdentity.ed25519PublicKeyHex(),
                batch0Pks,
                enrollSig,
            )

            return EnrollmentProof(
                identity = kotlinIdentity,
                batch0PublicKeys = batch0Pks,
                enrollmentSignature = enrollSig
            )
        } finally {
            kit.wipe()
            kit.destroy()
        }
    }

    /**
     * Déverrouille le ratchet depuis le PIN.
     *
     * @throws uniffi.frappuccino.FfiException.WrongPin si PIN incorrect
     * @throws IllegalStateException si pas enrôlé
     */
    @Synchronized
    fun initializeWithPin(pin: ByteArray) {
        require(pin.isNotEmpty()) { "PIN must not be empty" }
        val id = StreamPreferences.getIdentity(context)
            ?: throw IllegalStateException("Device not enrolled — no identity")
        val blob = StreamPreferences.getRatchetBlob(context)
            ?: throw IllegalStateException("Device not enrolled — no ratchet blob")

        // Le `pin` est un ByteArray, jamais converti en String : aucune copie
        // n'atterrit dans le pool d'intern de la JVM. Il appartient à
        // l'appelant, qui doit le wiper lui-même — rien ici ne le fait.
        // PinUnlockActivity.tryUnlock (le seul appelant) le wipe sur chacune
        // de ses sorties : succès, WrongPin, autre erreur, lockout. Il n'y a
        // pas de `finally`, donc un nouveau `return` anticipé ou un nouveau
        // `catch` sauterait le wipe.
        // `FfiException.WrongPin` est la source de vérité de l'échec, catchée
        // directement par PinUnlockActivity. Un seul Argon2id ici : ouverture
        // du holder et désérialisation du ratchet se font côté Rust, sous
        // l'invariant no-export décrit plus haut.
        val ratchet = pinSessionOpenRatchet(pin, blob)
        this.identity = id
        this.ratchet = ratchet

        Timber.d("Ratchet unlocked (UniFFI).")

        // §10.11 — recharge la clé de provenance via une ouverture RAPIDE par-clé
        // (réutilise la clé Argon2id du holder → AUCUN 2e Argon2id, pas de
        // re-PIN). Chargée inconditionnellement si un seed scellé existe, pour
        // que le toggle prenne effet immédiatement, sans lock/unlock.
        // Best-effort : un device enrôlé AVANT la feature n'a pas de seed →
        // provenance indisponible, jamais un brick.
        this.provenanceSigner = null
        val provBlob = StreamPreferences.getProvenanceSeedBlob(context)
        if (provBlob != null) {
            try {
                // Lot 4b (OPTION B) : descellé + reconstruit côté Rust ; le seed
                // ne traverse jamais la JVM.
                this.provenanceSigner = pinSessionOpenProvenanceSigner(provBlob)
                Timber.d("Provenance signer loaded.")
            } catch (e: Exception) {
                Timber.w(e, "provenance signer load failed at unlock (non-fatal)")
            }
        }

        // Phase C (relay-blind reports) — reload the report keyring via the same
        // fast per-key open (reuses the holder's Argon2id key, no 2nd Argon2id).
        // Reconstructed unconditionally if a sealed master exists. Best-effort: a
        // device enrolled before the feature has no sealed master → keyring stays
        // null (uploads degrade gracefully).
        this.reportKeyring = null
        val reportBlob = StreamPreferences.getReportMasterBlob(context)
        if (reportBlob != null) {
            try {
                // Lot 4b (OPTION B) : descellé + reconstruit côté Rust ; le master
                // ne traverse jamais la JVM.
                this.reportKeyring = pinSessionOpenReportKeyring(reportBlob)
                Timber.d("Report keyring loaded.")
            } catch (e: Exception) {
                Timber.w(e, "report keyring load failed at unlock (non-fatal)")
            }
        }
    }

    /**
     * Verrouille le ratchet : wipe la RAM, laisse le blob sur disque.
     */
    @Synchronized
    fun lock() {
        ratchet?.wipe()
        ratchet?.destroy()
        ratchet = null
        // §10.11 — wipe the session provenance signer alongside the ratchet.
        provenanceSigner?.destroy()
        provenanceSigner = null
        // Phase C — wipe the session report keyring alongside the ratchet.
        // (Drain asymmetry §3.3: a later refinement defers this until the
        // post-stop upload drain completes — report_master is NOT re-derivable,
        // so a wipe mid-drain loses the pending chunks; for now it mirrors the
        // provenance signer's lifecycle, which auto-lock already defers while a
        // recording is running.)
        reportKeyring?.destroy()
        reportKeyring = null
        // Lot 4b : la clé Argon2id vit désormais dans le holder Rust (PIN_SESSION,
        // Zeroizing) ; on la zéroïse là. NON câblé sur un 401 (contrairement au
        // bearer upload) — la clé n'est pas re-dérivable sans le PIN, la vider en
        // plein drain orphelinerait les chunks.
        pinSessionClear()
        Timber.d("Ratchet locked")
    }

    /**
     * Panic wipe : efface tout ce que l'appareil garde en local — l'état crypto
     * en RAM (ratchet, signer de provenance, report keyring, holder PIN), les
     * préférences (identité + ratchet blob + mappings de session), le scratch
     * de capture (copies debug_raw et tout chunk MP4 orphelin de
     * `cacheDir/stream_chunks`, quelle que soit sa taille), la file d'upload
     * `.strm` en attente, les preuves de provenance
     * `filesDir/stream_provenance` (fichiers `.ots`), les marqueurs
     * `cacheDir/directory_entries` et le bearer d'upload rangé côté Rust.
     *
     * C'est un disk-clean complet et pas un simple key-destroy, et ça doit le
     * rester (forensic Surface 6). L'argument inverse est tentant :
     * historiquement panicWipe laissait `filesDir/stream_chunk_queue/` (les
     * `.strm`) sur disque, au motif que ces blobs sont chiffrés E2E, donc
     * déchiffrables seulement par l'identité qu'on vient d'effacer. Il est
     * faux : sur un device saisi, leur simple présence est une preuve
     * forensique — nombre de chunks, tailles, et surtout `sessionId` +
     * `nonce_prefix` dans les noms de fichiers permettent la corrélation de
     * session (le risque que `enqueue()` documente déjà). panicWipe est le
     * chemin "le device est en train d'être saisi". Les call-sites présument
     * déjà ce comportement, cf. StreamSettingsActivity confirmLock.
     */
    @Synchronized
    fun panicWipe() {
        lock()
        identity = null
        StreamPreferences.wipeAll(context)
        // Also purge the capture scratch paths: debug_raw plaintext MP4 copies
        // (Red Team R-H1) and every orphan MP4 chunk in cacheDir/stream_chunks,
        // whatever its size — including one being encrypted right now. This is
        // the "device is being seized" path, so nothing in cleartext may
        // linger: a chunk finalized mid-encryption when the panic fires used to
        // survive it, the old purge only catching 0-byte files (F-01). FBE
        // stays the load-bearing at-rest control; this overwrite is
        // defense-in-depth. (Phase H2-B.11, 2026-05-18 ; F-01, cross-audit
        // 2026-06-30.)
        try {
            org.stream.crypto.capture.CaptureScratchCleaner.purgeAll(context)
        } catch (e: Exception) {
            Timber.w(e, "CaptureScratchCleaner.purgeAll failed in panicWipe")
        }
        // Secure-delete the pending STRM upload queue
        // (les fichiers `.strm` de `filesDir/stream_chunk_queue`). clear() iterates
        // queueDir.listFiles() and Rust-secure_delete's every entry; it is
        // idempotent and race-safe (secureDeleteFile no-ops on a file a
        // concurrent upload remove() already deleted, so it can't throw).
        // ChunkUploadQueue is a stateless wrapper over the fixed queue
        // path, hence constructed ad-hoc here — StreamUploadManager holds
        // no queue instance (same pattern as CaptureScratchCleaner above).
        try {
            ChunkUploadQueue(context).clear()
        } catch (e: Exception) {
            Timber.w(e, "ChunkUploadQueue.clear failed in panicWipe")
        }
        // §10.11 — secure-delete the local provenance artifacts
        // (les `.ots` de `filesDir/stream_provenance`, the opt-in timestamp proofs).
        // ProvenanceUploadWorker already deletes each one after a confirmed
        // upload, but the build→upload window and any never-uploaded orphan can
        // linger ; the seized-device path should leave nothing behind.
        try {
            val provDir = File(context.filesDir, "stream_provenance")
            provDir.listFiles()?.forEach { f ->
                try {
                    uniffi.frappuccino.secureDeleteFile(f.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "panicWipe: secureDelete provenance %s failed, fallback delete()", f.name)
                    f.delete()
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "stream_provenance purge failed in panicWipe")
        }
        // Phase C — secure-delete the report-directory entry blobs
        // (the contents of `cacheDir/directory_entries`, the tiny per-session markers that
        // back the rescue's authoritative n_max). DirectoryEntryWorker deletes
        // each after a confirmed upload, but the build→upload window or a
        // never-uploaded orphan can linger; the blob NAME is the report index (a
        // recording count), so the seized-device path purges them too.
        try {
            val dirEntries = File(context.cacheDir, "directory_entries")
            dirEntries.listFiles()?.forEach { f ->
                try {
                    uniffi.frappuccino.secureDeleteFile(f.absolutePath)
                } catch (e: Exception) {
                    Timber.w(e, "panicWipe: secureDelete directory entry %s failed, fallback delete()", f.name)
                    f.delete()
                }
            }
        } catch (e: Exception) {
            Timber.w(e, "directory_entries purge failed in panicWipe")
        }
        // §10.6 (2026-06-13) — zeroize the upload bearer held in Rust. The
        // seized-device path must not leave the 24 h JWT reachable; clearing
        // it here makes panicWipe self-contained (the StreamSettingsActivity
        // panic path also calls UploadAuthHolder.clear(), but we don't rely on
        // the caller). Drops/zeroizes the Zeroizing<String> in the FFI holder.
        try {
            uniffi.frappuccino.uploadAuthClear()
        } catch (e: Exception) {
            Timber.w(e, "uploadAuthClear failed in panicWipe")
        }
        // Re-clear orphan deletion alerts as late as possible.
        // wipeAll() above already drops them, but a giveup sweep that slipped
        // past its isUnlocked() gate before lock() could addOrphanDeletion()
        // concurrently and re-create the key after wipeAll. The events are only
        // non-secret metadata (count + date, no sessionId), yet the seized-
        // device path should leave nothing behind; this final clear wins the
        // realistic race.
        try {
            StreamPreferences.clearOrphanDeletions(context)
        } catch (e: Exception) {
            Timber.w(e, "clearOrphanDeletions failed in panicWipe")
        }
        Timber.w("PANIC WIPE — all local crypto state + pending queue erased")
    }

    // =========================================================================
    // SIGNATURES (via ratchet)
    // =========================================================================

    fun signChallenge(nonce: ByteArray): ByteArray =
        signChallengeFull(nonce).signature

    /**
     * Signe via ratchet + retourne la preuve complète (sig + batch + index + ephemeral_pk).
     * Auto-persiste l'état ratchet après la signature.
     */
    fun signChallengeFull(nonce: ByteArray): RatchetSignature {
        synchronized(ratchetLock) {
            val r = ratchet ?: throw IllegalStateException("Ratchet locked — call initializeWithPin")
            val sig = r.signAndAdvance(nonce)
            persistRatchet(r)
            return sig
        }
    }

    // `rotateBatch()` REMOVED (2026-09-04). It advanced the ratchet and handed the
    // proof back to the caller WITHOUT persisting it, which is exactly the shape
    // that loses an enrollment: advanceBatch wipes the batch that signed the
    // proof, so a caller whose network send failed could never produce it again.
    // It had no caller, so it broke nothing; it was a loaded trap for the next
    // person to wire it up. Rotation goes through `maybeAutoRotate` or
    // `rotateBatchOnServer`, both of which queue the proof before the network
    // call. Do not reintroduce a method that returns a RotationProof.

    fun remainingKeysInBatch(): Int {
        val r = ratchet ?: return 0
        // RT-07 fix : EphemeralRatchet.remainingInBatch() expose maintenant le
        // vrai compteur (50 → 0 au fur et à mesure des consume). Avant, on
        // retournait pks.size = 50 constant, ce qui désactivait l'auto-rotate.
        return try {
            r.remainingInBatch().toInt()
        } catch (e: Exception) {
            Timber.w(e, "remainingInBatch failed, returning 0")
            0
        }
    }

    fun currentBatchNumber(): Int {
        // Lot 4b : EphemeralRatchet.batchNumber() exposé via UDL — plus besoin de
        // sérialiser le blob 50-sk juste pour lire l'en-tête (TODO S8c.2 résolu ;
        // le plaintext ne traverse plus pour une lecture non-secrète).
        // Le call-site StreamSettingsActivity accepte -1 et affiche "—".
        val r = ratchet ?: return -1
        return cachedBatchNumber ?: run {
            try {
                val bn = r.batchNumber().toInt()
                cachedBatchNumber = bn
                bn
            } catch (_: Exception) { -1 }
        }
    }

    @Volatile private var cachedBatchNumber: Int? = null

    // =========================================================================
    // API V1 COMPAT
    // =========================================================================

    /** Ed25519 public key en hex (utilisé par ReportsRepositoryImp). */
    fun getEd25519PublicKeyHex(): String {
        val id = checkNotNull(identity) { "Not initialized" }
        return id.ed25519PublicKeyHex()
    }

    /**
     * Helper pour [rs.readahead.washington.mobile.views.activity.ArchiveModeActivity] :
     * crée un [org.stream.crypto.ArchiveIdentity] depuis une phrase BIP-39.
     *
     * S8c.4 : `ArchiveIdentity` délègue maintenant à `uniffi.frappuccino.
     * ArchiveIdentity` — zéro lazysodium sur ce path.
     */
    fun createArchiveIdentity(
        mnemonic: ByteArray,
        passphrase: ByteArray = ByteArray(0)
    ): org.stream.crypto.ArchiveIdentity {
        // ByteArray au lieu de CharArray. Le mnemonic ne
        // touche jamais le pool intern Java côté Kotlin.
        return org.stream.crypto.ArchiveIdentity.fromMnemonic(mnemonic, passphrase)
    }

    // =========================================================================
    // V2 SERVER INTERACTION
    // =========================================================================

    fun setServerUrl(url: String) {
        serverUrl = url
        serverClient = FfiServerClient(url)
        StreamPreferences.saveServerUrl(context, url)
    }

    fun getServerUrl(): String? =
        serverUrl ?: StreamPreferences.getServerUrl(context)

    /**
     * POST /auth/v2/enroll — envoie la preuve d'enrôlement au serveur.
     *
     * @return true si l'enrollement est accepté (ou déjà existant). Sur
     *         succès, efface l'éventuelle proof persistée dans
     *         StreamPreferences (Phase 2.3.1 : retry du serveur).
     */
    fun enrollOnServer(proof: EnrollmentProof): Boolean {
        val client = serverClient
            ?: throw IllegalStateException("Server URL not set — call setServerUrl() first")
        val result = try {
            client.enroll(
                proof.identity.ed25519PublicKeyHex(),
                proof.batch0PublicKeys,
                proof.enrollmentSignature
            )
        } catch (e: FfiException) {
            Timber.e(e, "V2 server enrollment network error")
            return false
        }
        return when (result) {
            is FfiEnrollResult.Success -> {
                Timber.d("V2 server enrollment OK")
                StreamPreferences.clearPendingEnrollment(context)
                true
            }
            is FfiEnrollResult.AlreadyEnrolled -> {
                Timber.d("V2 server already enrolled (idempotent)")
                StreamPreferences.clearPendingEnrollment(context)
                true
            }
            is FfiEnrollResult.Failed -> {
                Timber.e("V2 server enrollment failed: %d %s", result.code.toInt(), result.body)
                false
            }
        }
    }

    /**
     * Re-sends the enrollment proof persisted at onboarding time. Idempotent:
     * true when there is nothing pending or when the server confirms (Success /
     * AlreadyEnrolled), false whenever a proof is still waiting and the send
     * did not go through — relay unreachable, no server URL configured, or the
     * relay rejecting the proof (`FfiEnrollResult.Failed`). The Boolean does
     * not separate those three; a rejection logs `V2 server enrollment failed`
     * with the status, and that line is what tells it apart from an outage a
     * retry would fix.
     *
     * Called from the manual button in StreamSettingsActivity and from
     * EnrollmentRetryWorker, which fires on network connect.
     */
    fun retryServerEnrollment(): Boolean {
        val pending = StreamPreferences.getPendingEnrollment(context)
            ?: run {
                Timber.d("retryServerEnrollment: no pending proof, nothing to do")
                return true
            }
        val identity = StreamPreferences.getIdentity(context) ?: run {
            // Defensive: pending without identity is a corrupted state
            // (panicWipe should have cleared both). Give up cleanly.
            Timber.w("retryServerEnrollment: pending exists but identity missing — clearing")
            StreamPreferences.clearPendingEnrollment(context)
            return true
        }

        // Lazy-init the server client if needed (e.g. boot-time worker
        // before any UI activity has touched setServerUrl).
        if (serverClient == null) {
            val url = getServerUrl() ?: return false
            setServerUrl(url)
        }

        val proof = EnrollmentProof(
            identity = identity,
            batch0PublicKeys = pending.batch0Pks,
            enrollmentSignature = pending.enrollmentSignature,
        )
        Timber.i("retryServerEnrollment: attempting %s", identity.readableFingerprint())
        return enrollOnServer(proof)
    }

    /** True iff a server enrollment is queued waiting for network. */
    fun hasPendingServerEnrollment(): Boolean =
        StreamPreferences.hasPendingEnrollment(context)

    /**
     * Flow complet V2 : challenge + verify avec une clé éphémère. Consomme UNE
     * clé éphémère du batch courant.
     *
     * Un échec de verify ne se désambiguïse PAS par une sonde réseau. Si une
     * preuve d'enrôlement est encore en attente localement, on re-enroll puis
     * on re-tente l'auth une seule fois — `alreadyTriedReEnroll` borne la
     * récursion. Sur un device établi (aucune preuve en attente), un échec
     * verify ne déclenche aucun re-enroll et ne brûle donc pas un 2ᵉ slot de
     * ratchet : la death-spiral de slots est évitée par l'état local, pas par
     * une sonde serveur. L'oracle réseau `/auth/v2/status` n'est plus consulté,
     * la route ayant été retirée le 2026-06-27 (l'ancien probe 404'ait et
     * mal-déclenchait à chaque échec). Voir BT-05, et la chaîne de défaillance
     * détaillée au site de décision, plus bas dans le corps.
     *
     * @return true si l'auth a réussi (le bearer est rangé côté Rust par
     *   verify(), jamais retourné ici), false sinon. §10.6.
     */
    fun authenticateV2(alreadyTriedReEnroll: Boolean = false): Boolean {
        val client = serverClient
            ?: throw IllegalStateException("Server URL not set — call setServerUrl() first")
        val id = identity ?: throw IllegalStateException("Not enrolled")

        val challenge = try {
            client.challenge()
        } catch (e: FfiException) {
            Timber.e(e, "V2 challenge failed")
            return false
        }
        val nonceBytes = challenge.nonce
        val nonceHex = nonceBytes.joinToString("") { "%02x".format(it) }

        // S9-pre-audit pt2 : the ratchet signs `nonce || timestamp_BE_u64`
        // (40 bytes) so the server can reject replays outside a ±30 s window.
        // `ts` comes from the server itself via /auth/challenge — the device
        // clock is never trusted for this binding.
        val ts = challenge.timestamp
        val tsLong = ts.toLong()
        val message = ByteArray(40)
        System.arraycopy(nonceBytes, 0, message, 0, 32)
        for (i in 0 until 8) {
            message[32 + i] = ((tsLong shr (56 - 8 * i)) and 0xFF).toByte()
        }

        // A rotation that never reached the relay leaves this device on batch
        // N+1 and the relay on N, and the relay then refuses every auth for good.
        // Replay the unconfirmed proofs before anything else: each stays valid
        // while the relay is on the batch it starts from (the slot it consumes is
        // still unconsumed there), and none can be regenerated, advanceBatch
        // having wiped the batch that signed it.
        //
        // The auth below then runs whatever the outcome, and that is deliberate.
        // If the rotations had in fact landed and only their responses were lost,
        // the replay is refused, and blocking on that refusal would strand the
        // device forever on a rotation that already succeeded. Running the auth
        // costs one slot when the relay really is behind, and the reserve bounds
        // that bleed; refusing to auth would cost the enrollment.
        retryPendingRotations(client)

        // If the batch is down to its reserved slot, rotate BEFORE signing.
        //
        // `signAndAdvance` refuses that last slot (crypto-rs ratchet.rs), which
        // is what stops a run of failed authentications from draining the batch
        // to zero and stranding the enrollment: at zero the device can neither
        // sign nor rotate, and the relay refuses to re-enroll an identity it
        // already knows. But the post-verify `maybeAutoRotate` below only runs
        // after a SUCCESSFUL verify, so a device that keeps failing would sit at
        // the reserve forever, unable to sign and never rotating: the reserve
        // would create the very deadlock it exists to prevent.
        //
        // Rotating here works precisely because `/auth/v2/rotate-batch` needs no
        // JWT: the signature by a slot of the current batch IS the
        // authentication, so a device that cannot authenticate can still rotate.
        // Do not move this after the verify.
        if (remainingKeysInBatch() <= 1) {
            Timber.w("Ratchet at its reserved slot - rotating before signing")
            maybeAutoRotate(client)
        }

        // Sign with ratchet (auto-consume + persist).
        val ephemSig: RatchetSignature = synchronized(ratchetLock) {
            val r = ratchet ?: throw IllegalStateException("Ratchet locked")
            val sig = r.signAndAdvance(message)
            persistRatchet(r)
            sig
        }

        // Rebuild the UniFFI StreamIdentity from the persisted pubs — the
        // server's verify() only reads ed25519_pk/x25519_pk, no secrets
        // required.
        val ffiIdentity = try {
            uniffi.frappuccino.StreamIdentity.fromPublicKeys(
                id.ed25519PublicKey,
                id.x25519PublicKey
            )
        } catch (e: FfiException) {
            Timber.e(e, "rebuild FFI StreamIdentity failed")
            return false
        }

        // §10.6 — verify() now stashes the bearer in the Rust-side holder and
        // returns a Boolean; the JWT never crosses the FFI as a String.
        val authed: Boolean = try {
            val ok = client.verify(ffiIdentity, ephemSig, nonceHex, ts)
            if (!ok) {
                Timber.e("V2 verify failed")
            } else {
                // An accepted auth proves the relay is on the same batch as
                // this device, so every proof still queued did land. This is the
                // only reliable signal available: the rotation endpoint answers
                // one opaque 401 for every refusal and will not say which batch it
                // is on, that oracle having been removed (R-SRV-1 / BT-05).
                if (StreamPreferences.hasPendingRotations(context)) {
                    StreamPreferences.clearPendingRotations(context)
                    Timber.i("Auth accepted, pending rotation confirmed landed")
                }
                maybeAutoRotate(client)
            }
            ok
        } catch (e: FfiException) {
            Timber.e(e, "verify network error")
            false
        } finally {
            ffiIdentity.destroy()
        }

        // A verify failure is disambiguated from LOCAL state, never from a
        // network probe. The `/auth/v2/status` route was deleted server-side
        // (2026-06-27, R-SRV-1), so `client.getStatus` always 404'd → null → the
        // old code treated every verify failure as "server lost my identity",
        // re-enrolled, and re-ran authenticateV2 — burning a second ratchet slot
        // on every failed auth, signature and clock failures included. A
        // re-enroll can only help while we still hold a pending enrollment proof
        // (device enrolled offline, never confirmed server-side); an established
        // device whose proof was cleared has nothing to re-enroll and must not
        // spend a second slot. That pending case is also covered by
        // EnrollmentRetryWorker (on network connect) and the Settings button, so
        // this inline retry only makes recovery one round faster;
        // `alreadyTriedReEnroll` bounds it to one. It sits outside the try{}
        // because Kotlin doesn't allow `return@try` on un-labeled try-blocks.
        // (Phase 3.42 / BUG-R2-2 → BT-05, cross-audit 2026-06-30.)
        if (!authed && !alreadyTriedReEnroll && hasPendingServerEnrollment()) {
            Timber.w("BT-05: verify failed with a pending enrollment proof — re-enrolling once")
            val reEnrolled = try {
                retryServerEnrollment()
            } catch (e: Exception) {
                Timber.e(e, "retryServerEnrollment threw on verify-failure recovery")
                false
            }
            if (reEnrolled) {
                Timber.i("re-enrollment OK, retrying authenticateV2 once")
                return authenticateV2(alreadyTriedReEnroll = true)
            }
            Timber.e("re-enrollment failed — auth will need a manual Settings retry")
        }
        return authed
    }

    /**
     * Replays the rotation proofs the relay never confirmed, oldest first.
     *
     * Each proof is signed by a slot of the batch it advances FROM, so the relay
     * applies the ones that start where it actually is and refuses the rest. That
     * is why a refusal does not stop the loop: it only means this particular proof
     * does not apply here, not that the relay is unreachable. An exception does
     * stop it, since nothing further can be delivered anyway.
     *
     * Everything up to and including the last accepted proof is then dropped: the
     * relay has moved past those batches, and a proof that starts from a batch it
     * has left can never apply again.
     *
     * Silent and best-effort: a failure here is not the caller's problem, it only
     * means the desync outlives this attempt. Deliberately not wired to a
     * WorkManager job, unlike the enrollment retry: a pending rotation only
     * matters when the device tries to authenticate, and that is exactly when
     * this runs.
     */
    private fun retryPendingRotations(client: FfiServerClient) {
        val pending = StreamPreferences.getPendingRotations(context)
        if (pending.isEmpty()) return
        val id = identity ?: return
        Timber.w("%d unconfirmed rotation(s), replaying", pending.size)
        var lastAccepted = -1
        for ((i, p) in pending.withIndex()) {
            val accepted = try {
                client.rotateBatch(id.ed25519PublicKeyHex(), toRotationProof(p))
            } catch (e: Exception) {
                Timber.w(e, "Rotation replay unreachable, queue kept")
                break
            }
            if (accepted) lastAccepted = i
        }
        if (lastAccepted >= 0) {
            StreamPreferences.setPendingRotations(context, pending.drop(lastAccepted + 1))
            Timber.i("Relay caught up to batch #%d", pending[lastAccepted].newBatchNumber)
        }
    }

    private fun toRotationProof(p: StreamPreferences.PendingRotation) =
        uniffi.frappuccino.RotationProof(
            newBatchNumber = p.newBatchNumber.toUInt(),
            newBatchPublicKeys = p.newBatchPks,
            signerPublicKey = p.signerPk,
            signerBatchNumber = p.signerBatchNumber.toUInt(),
            signerKeyIndex = p.signerKeyIndex.toUInt(),
            signature = p.signature,
        )

    /**
     * Si le batch courant a <= 5 clés restantes (hors la clé signataire),
     * déclenche une rotation automatique vers batch_{N+1}.
     *
     * Silencieux en cas d'échec — on réessaiera à la prochaine session.
     */
    private fun maybeAutoRotate(client: FfiServerClient) {
        val id = identity ?: return
        val proof: uniffi.frappuccino.RotationProof?
        synchronized(ratchetLock) {
            val r = ratchet ?: return
            val remaining = remainingKeysInBatch()
            // RT-07 fix : remainingKeysInBatch() retourne maintenant le vrai
            // compteur via EphemeralRatchet.remainingInBatch(). Trigger : reste
            // 1-5 clés. 5 = alerte précoce ; 1 = la réserve, le seul slot que
            // `signAndAdvance` refuse désormais, donc le seul état d'où la rotation
            // est la seule sortie. Laisser la fenêtre à 2..5 rendrait ce dernier
            // état inatteignable par la rotation automatique, et la réserve
            // créerait l'impasse qu'elle existe pour empêcher.
            val shouldRotate = remaining in 1..5
            proof = if (shouldRotate) {
                try {
                    // Check the queue has room BEFORE advancing. advanceBatch is
                    // irreversible and wipes the batch that could re-sign, so
                    // advancing without somewhere to keep the proof would produce
                    // exactly the unrecoverable state this queue exists to avoid.
                    if (StreamPreferences.getPendingRotations(context).size
                        >= StreamPreferences.MAX_PENDING_ROTATIONS
                    ) {
                        // Reachable only after ~400 answered-but-failed auths with
                        // no successful one in between, which already means the
                        // enrollment is lost. Refusing to advance does not save it;
                        // it stops the ratchet burning further batches for nothing.
                        Timber.e("Rotation queue full, not advancing")
                        return
                    }
                    val p = r.advanceBatch()
                    persistRatchet(r)
                    // Persist the proof BEFORE the network call, like the
                    // enrollment proof and for the same reason, one step further
                    // in the same state machine: advanceBatch has already moved
                    // this device to batch N+1 and wiped batch N, so if the call
                    // below never reaches the relay, the relay stays on N and
                    // refuses every future auth (`is_ephemeral_key_valid`
                    // compares batch_number) with no re-enrollment route to
                    // recover through. The proof is the only thing that can still
                    // repair that, and it cannot be regenerated: the batch that
                    // signed it is gone.
                    StreamPreferences.appendPendingRotation(
                        context,
                        StreamPreferences.PendingRotation(
                            newBatchNumber = p.newBatchNumber.toInt(),
                            newBatchPks = p.newBatchPublicKeys,
                            signerPk = p.signerPublicKey,
                            signerBatchNumber = p.signerBatchNumber.toInt(),
                            signerKeyIndex = p.signerKeyIndex.toInt(),
                            signature = p.signature,
                        ),
                    )
                    p
                } catch (e: Exception) {
                    Timber.w(e, "Ratchet advance failed")
                    null
                }
            } else null
        }
        if (proof != null) {
            try {
                val ok = client.rotateBatch(id.ed25519PublicKeyHex(), proof)
                if (ok) {
                    // The relay accepted the newest proof, so it is on this
                    // device's batch and every older proof in the queue starts
                    // from a batch it has left.
                    StreamPreferences.clearPendingRotations(context)
                    Timber.i("Auto-rotated to batch #%d", proof.newBatchNumber.toInt())
                } else {
                    // Kept pending on purpose. The relay answers a single opaque
                    // 401 for every rotation refusal (anti-oracle, R-SRV-1), so
                    // "you are already on N+1" and "this proof is invalid" are
                    // indistinguishable here. Deciding from local state instead is
                    // the same answer BT-05 reached for failed auths: an accepted
                    // auth later is what proves the relay caught up, and that is
                    // where the proof is cleared.
                    Timber.w("Server rejected rotation, queued for replay")
                }
            } catch (e: Exception) {
                Timber.e(e, "Auto-rotate network error, queued for replay")
            }
        }
    }

    /**
     * Rotation manuelle (ex : depuis Settings). Consomme 1 clé pour signer le nouveau batch.
     */
    fun rotateBatchOnServer(): Boolean {
        val client = serverClient
            ?: throw IllegalStateException("Server URL not set")
        val id = identity ?: throw IllegalStateException("Not enrolled")

        // Replay first: the queue may hold a rotation the relay never confirmed,
        // and a second manual rotation should finish that one rather than pile an
        // unconfirmed advance on top of it.
        //
        // Note for whoever wires this up: it currently has NO caller. It is the
        // entry point a Settings action would use, not one that exists. An
        // earlier version of this comment said "pressing this button", which
        // asserted a button that is not there.
        retryPendingRotations(client)

        val proof: RotationProof = synchronized(ratchetLock) {
            val r = ratchet ?: throw IllegalStateException("Ratchet locked")
            // Same rule as the automatic path: never advance without room to keep
            // the proof. advanceBatch wipes the batch that signed it, so a proof
            // dropped here cannot be produced again.
            if (StreamPreferences.getPendingRotations(context).size
                >= StreamPreferences.MAX_PENDING_ROTATIONS
            ) {
                Timber.e("Rotation queue full, not advancing")
                return false
            }
            val p = r.advanceBatch()
            persistRatchet(r)
            StreamPreferences.appendPendingRotation(
                context,
                StreamPreferences.PendingRotation(
                    newBatchNumber = p.newBatchNumber.toInt(),
                    newBatchPks = p.newBatchPublicKeys,
                    signerPk = p.signerPublicKey,
                    signerBatchNumber = p.signerBatchNumber.toInt(),
                    signerKeyIndex = p.signerKeyIndex.toInt(),
                    signature = p.signature,
                ),
            )
            p
        }
        return try {
            val ok = client.rotateBatch(id.ed25519PublicKeyHex(), proof)
            if (ok) {
                // The relay accepted the newest proof, so it is on this device's
                // batch and every older proof starts from a batch it has left.
                StreamPreferences.clearPendingRotations(context)
            }
            ok
        } catch (e: FfiException) {
            Timber.e(e, "rotateBatch network error, queued for replay")
            false
        }
    }

    /**
     * Crée un [org.stream.crypto.capture.StreamChunkEncryptor] lié à l'identité courante.
     *
     * **S8c.2** : le chunk encryptor utilise maintenant directement
     * `uniffi.frappuccino.strmEncrypt` — plus aucune dépendance lazysodium
     * sur le chemin chunk encryption.
     */
    fun createChunkEncryptor(outputDir: File): org.stream.crypto.capture.StreamChunkEncryptor {
        val id = checkNotNull(identity) { "Not initialized" }
        return org.stream.crypto.capture.StreamChunkEncryptor(id, outputDir)
    }

    // =========================================================================
    // Helpers internes
    // =========================================================================

    /**
     * Re-sérialise le ratchet et ré-écrit le blob sur disque en réutilisant la
     * clé Argon2id du holder (fast reseal, ~ms). Pas thread-safe : à appeler
     * depuis un `synchronized(ratchetLock)`.
     *
     * `resealSessionBlob()` sérialise ET scelle entièrement côté Rust avec la
     * clé du holder PIN-session — ni le plaintext 50-sk ni la clé ne traversent
     * la JVM. Il throw `Internal` si le holder est vide (pas de session) ;
     * l'exception est captée et logguée ici plutôt que propagée, parce que le
     * slot ratchet est déjà consommé côté Rust et que le serveur se re-sync via
     * rotation_proof : la divergence RAM/disque est un état connu et
     * forward-secure, pas un oubli à réparer.
     */
    private fun persistRatchet(r: FfiRatchet) {
        try {
            val newBlob = r.resealSessionBlob()
            StreamPreferences.saveRatchetBlob(context, newBlob)
            cachedBatchNumber = null  // invalidate cache
        } catch (e: Exception) {
            Timber.e(e, "Failed to persist ratchet state")
        }
    }

    private fun concatPublicKeys(keys: List<ByteArray>): ByteArray {
        val result = ByteArray(keys.size * 32)
        for (i in keys.indices) {
            System.arraycopy(keys[i], 0, result, i * 32, 32)
        }
        return result
    }
}

// The S9 String.zero() reflection helper was removed here.
// It is non-functional on Android P+ (java.lang.String.value is a hidden-API
// non-SDK field, so the reflective char[] wipe silently no-ops on every target
// device) and had no callers. Immutable Strings carrying secrets are an
// accepted, GC-bounded residual; real secrets use ByteArray/CharArray +
// SecureWipe/Zeroizing. See FORENSIC_VALIDATION_PLAN.md finding #6.

