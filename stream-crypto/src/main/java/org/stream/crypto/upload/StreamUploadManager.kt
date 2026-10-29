package org.stream.crypto.upload

import android.content.Context
import org.stream.crypto.StreamIdentity
import org.stream.crypto.StreamPreferences
import uniffi.frappuccino.RatchetSignature
import uniffi.frappuccino.RotationProof
import uniffi.frappuccino.pinSessionPopulate
import uniffi.frappuccino.pinSessionOpenRatchet
import uniffi.frappuccino.pinSessionOpenProvenanceSigner
import uniffi.frappuccino.pinSessionClear
import timber.log.Timber
import uniffi.frappuccino.EnrollResult as FfiEnrollResult
import uniffi.frappuccino.EphemeralRatchet as FfiRatchet
import uniffi.frappuccino.EnrollmentKit as FfiEnrollmentKit
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.StreamServerClient as FfiServerClient
import uniffi.frappuccino.ProvenanceSigner as FfiProvenanceSigner
import uniffi.frappuccino.ReportWriter as FfiReportWriter
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

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

        /**
         * Bumped at the start of every emergency wipe. A recording session
         * reads it when it starts and compares before writing anything that
         * would outlive the wipe (an alert, a timestamp ticket): if it moved,
         * the session's leftovers belong to an identity that no longer exists
         * and are dropped silently.
         */
        private val wipeGenerationCounter = AtomicInteger(0)

        // Makes "check the generation, then write" one step with respect to
        // the bump that starts a wipe. See [unlessWipedSince].
        private val wipeLock = Any()

        fun wipeGeneration(): Int = wipeGenerationCounter.get()

        /**
         * Mark the start of an emergency wipe: bump the generation. The wipe
         * calls this first, before it aborts the writer or cancels any job, so
         * that a write guarded by [unlessWipedSince] that has not happened yet
         * by then never happens. Returns the new generation.
         */
        fun beginWipe(): Int = synchronized(wipeLock) { wipeGenerationCounter.incrementAndGet() }

        /**
         * Run [block] only if no emergency wipe began since generation [gen],
         * and as one step with respect to [beginWipe]: either the block runs
         * entirely before the wipe's bump (and the wipe, which comes after it,
         * erases or cancels what the block wrote or scheduled), or it does not
         * run at all. A plain "compare, then write" leaves a gap between the
         * two in which the wipe can start and finish. Returns the block's
         * result, or null when a wipe began.
         *
         * For writes that would outlive the wipe: a WorkManager row, an alert,
         * a file under the app's directories. Keep the block short (the wipe
         * waits for it), and never take the manager's monitor in it: the wipe
         * holds that monitor when it calls [beginWipe].
         */
        fun <T> unlessWipedSince(gen: Int, block: () -> T): T? =
            synchronized(wipeLock) {
                if (wipeGenerationCounter.get() != gen) null else block()
            }

        // Every authentication of the process runs under this lock, and so do
        // the rotation calls: one need never spends two ratchet slots, and the
        // queue of rotation proofs is only read and rewritten by one caller at
        // a time. See [authenticateIfAbsent].
        private val authLock = Any()
        private val authGate = SingleFlightAuth(authLock)

        /** File name of the report state, under `filesDir`. Owned by Rust. */
        const val REPORT_STATE_FILE = "report_state.bin"

        /**
         * Directory names [panicWipe] detaches under `filesDir` and `cacheDir`,
         * so that the next process start can finish a background wipe a
         * process death interrupted (SecureDirWiper.finishLeftovers).
         */
        fun wipeableDirNames(): List<String> =
            EnvelopeQueue.ALL_DIRS + listOf(
                LegacyReportMigration.PROVENANCE_DIR, ChunkUploadQueue.DIR_NAME, "stream_migration",
                "stream_encrypted", "directory_entries", "stream_chunks",
                "debug_raw", "debug_raw_hevc", "debug_rolling",
            )
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

    // Reports. The report keys are not held here: the state they derive from
    // lives in `filesDir/report_state.bin`, written and sealed by Rust under
    // the PIN-session key, and never crosses into the JVM. Opening a report at
    // the start of a recording ([openReportWriter]) needs the PIN session; the
    // writer it returns then holds that one report's key by itself, in Rust,
    // until the report is closed. So a lock during a recording does not stop
    // the recording from being sealed and closed, and nothing in the upload
    // queue needs the PIN to leave: every envelope was signed when produced.

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
     * crée l'état des rapports et la clé de file, stocke l'identité + le blob
     * ratchet PIN-wrappé. Wipe toutes les clés privées.
     *
     * À appeler UNE FOIS au bout de l'onboarding.
     *
     * L'état des rapports et la clé de file sont créés AVANT que l'identité et
     * le ratchet ne soient persistés, et leur échec fait échouer l'enrôlement :
     * un appareil inscrit doit pouvoir enregistrer. Dans l'ordre inverse, un
     * échec laisserait un appareil « enrôlé » (isEnrolled vrai) incapable
     * d'ouvrir un rapport, sans que rien ne le signale avant le premier REC.
     */
    @Synchronized
    fun enrollFromMnemonic(mnemonic: ByteArray, pin: ByteArray): EnrollmentProof {
        require(pin.isNotEmpty()) { "PIN must not be empty" }

        // `pin` ET `mnemonic` sont des ByteArray, jamais convertis en String.
        // Aucune fuite dans le pool JVM. Les callers (OnBoardSetPinFragment)
        // wipent leur copie dans leur finally. Côté Rust, FfiEnrollmentKit
        // .fromMnemonic prend bytes et wrap immédiatement le mnemonic en
        // Zeroizing<Vec<u8>>.
        val kit = FfiEnrollmentKit.fromMnemonic(mnemonic, byteArrayOf())
        var ratchet: FfiRatchet? = null
        var persisted = false
        val queueKeyExisted = QueueKeyStore.exists(context)
        try {
            // 1. Initialiser le ratchet depuis chain_0 (consume-once côté Rust).
            val r = FfiRatchet.fromKit(kit)
            ratchet = r

            // 2. Signer batch_0 avec ed25519_sk (via EnrollmentKit).
            val batch0Pks = r.batchPublicKeys()
            val batch0Concat = concatPublicKeys(batch0Pks)
            val enrollSig = kit.signEnrollment(batch0Concat)

            // 3. Snapshot public identity.
            val uniffiIdentity = kit.identity()
            val kotlinIdentity = StreamIdentity(
                ed25519PublicKey = uniffiIdentity.ed25519Pk(),
                x25519PublicKey = uniffiIdentity.x25519Pk()
            )
            uniffiIdentity.destroy()

            // 4. Scelle le ratchet (Argon2id, entièrement côté Rust : le blob
            //    50-sk ne traverse jamais la JVM) et ouvre la session PIN : le
            //    holder Rust garde la clé dérivée pour le fast-reseal et pour
            //    sceller l'état des rapports juste après.
            val sealed = r.sealWithPin(pin)
            pinSessionPopulate(pin, sealed)

            // 5. État des rapports (index 0, dérivé de la phrase ; le master
            //    intermédiaire est effacé côté Rust) et clé de file. Fatal :
            //    l'exception remonte et rien n'est persisté côté identité.
            uniffi.frappuccino.pinSessionCreateReportState(
                mnemonic, byteArrayOf(), reportStatePath()
            )
            QueueKeyStore.createOrInstall(context, replaceUnreadable = true)

            // 6. Persister : identity (publiques) + ratchet blob PIN-wrappé.
            StreamPreferences.saveIdentity(context, kotlinIdentity)
            StreamPreferences.saveRatchetBlob(context, sealed)
            persisted = true

            // 7. Cache RAM pour utilisation immédiate.
            this.identity = kotlinIdentity
            this.ratchet = r

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
                // Le seed est scellé ENTIÈREMENT côté Rust (lu dans le signer,
                // scellé avec la clé du holder) — il ne traverse jamais la JVM.
                StreamPreferences.saveProvenanceSeedBlob(
                    context, provSigner.sealWithSession()
                )
            } catch (e: Exception) {
                Timber.w(e, "provenance seed setup failed at enrollment (non-fatal)")
            }

            // No fingerprint, nor anything else from the identity, in a log
            // line: a test build sends its log to the relay, which holds the
            // identity's public key and could match the two.
            Timber.d("V2 enrollment complete")

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
        } catch (e: Exception) {
            if (!persisted) {
                // Rien de l'identité n'est sur disque : on défait le reste pour
                // qu'un nouvel essai reparte de zéro.
                ratchet?.let { it.wipe(); it.destroy() }
                pinSessionClear()
                try {
                    uniffi.frappuccino.reportStateWipe(reportStatePath())
                } catch (wipeError: Exception) {
                    Timber.w(wipeError, "report state cleanup after a failed enrollment")
                }
                if (!queueKeyExisted) QueueKeyStore.wipe(context)
            }
            throw e
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

        // La clé de file est normalement installée au démarrage du processus ;
        // la réinstaller ici ne coûte rien si c'est déjà fait et couvre un
        // démarrage où le Keystore n'était pas prêt. Elle n'est pas créée ici :
        // seuls l'enrôlement et la migration en créent une.
        QueueKeyStore.ensureInstalled(context)
    }

    /**
     * Verrouille le ratchet : wipe la RAM, laisse le blob sur disque.
     *
     * N'avorte PAS l'écrivain d'un enregistrement en cours : il tient lui-même
     * la clé de son rapport, côté Rust, et doit pouvoir sceller ses derniers
     * morceaux et sa clôture après un verrouillage. Seul l'effacement d'urgence
     * l'avorte.
     */
    @Synchronized
    fun lock() {
        ratchet?.wipe()
        ratchet?.destroy()
        ratchet = null
        // §10.11 — wipe the session provenance signer alongside the ratchet.
        provenanceSigner?.destroy()
        provenanceSigner = null
        // Lot 4b : la clé Argon2id vit désormais dans le holder Rust (PIN_SESSION,
        // Zeroizing) ; on la zéroïse là. NON câblé sur un 401 (contrairement au
        // bearer upload) : la clé n'est pas re-dérivable sans le PIN.
        pinSessionClear()
        Timber.d("Ratchet locked")
    }

    /**
     * Panic wipe, partie stream-crypto (l'orchestration complète, services et
     * WorkManager compris, est côté app : StreamSettingsActivity). Dans l'ordre :
     *
     *  1. avorte l'écrivain vivant (sa clé de rapport est effacée sans clôture)
     *     et détruit le trousseau legacy d'une migration en cours
     *     ([LegacyReportMigration.destroyLiveKeyring]) ;
     *  2. verrouille (ratchet, signer de provenance, holder PIN), efface le
     *     bearer d'upload rangé côté Rust, les préférences (identité, ratchet
     *     scellé, graine de provenance, reliquats du schéma de rapports
     *     précédent, alertes), la clé de file et le fichier d'état des
     *     rapports ;
     *  3. renomme d'un coup les répertoires qui portent quelque chose de ces
     *     enregistrements (scratch de capture en clair, miroirs debug, file
     *     d'enveloppes, répertoire d'échecs, marqueurs, tickets et preuves
     *     d'horodatage, files du schéma précédent), puis ceux que l'appelant
     *     détache par [extra], et efface le tout en arrière-plan, en une seule
     *     passe ordonnée : tout le clair d'abord, le chiffré ensuite.
     *
     * La génération d'effacement est avancée en tout premier ([beginWipe]).
     * L'orchestrateur côté app l'avance lui aussi avant même d'avorter
     * l'écrivain et d'annuler les jobs ; l'avancer deux fois est sans effet
     * de bord.
     *
     * C'est un disk-clean complet et pas un simple key-destroy, et ça doit le
     * rester (forensic Surface 6). L'argument inverse est tentant : les
     * enveloppes sont chiffrées E2E, donc déchiffrables seulement par l'identité
     * qu'on vient d'effacer. Il est faux : sur un device saisi, leur simple
     * présence est une preuve forensique (nombre d'objets, tailles, noms locaux
     * portant l'identifiant de session), et la clé de file, si elle survivait,
     * rendrait lisibles les adresses de rapports de leurs trailers.
     */
    @Synchronized
    fun panicWipe(extra: () -> org.stream.crypto.DetachedDirs = { org.stream.crypto.DetachedDirs() }) {
        beginWipe()
        // 1. The live writer first, synchronously: its key must not outlive
        //    the wipe, and from here on it seals nothing more.
        try {
            uniffi.frappuccino.reportWriterAbortLive()
        } catch (e: Exception) {
            Timber.w(e, "reportWriterAbortLive failed in panicWipe")
        }
        //    So does the legacy keyring of a migration in progress: it is
        //    destroyed here, not by the migration's cleanup, and the migration
        //    signs nothing more with it.
        LegacyReportMigration.destroyLiveKeyring()
        // 2. Keys and preferences.
        lock()
        identity = null
        // §10.6 — zeroize the upload bearer held in Rust. The seized-device
        // path must not leave the 24 h JWT reachable; clearing it here makes
        // panicWipe self-contained (the app-side caller also clears it, for the
        // OkHttp connection pool).
        try {
            uniffi.frappuccino.uploadAuthClear()
        } catch (e: Exception) {
            Timber.w(e, "uploadAuthClear failed in panicWipe")
        }
        StreamPreferences.wipeAll(context)
        QueueKeyStore.wipe(context)
        try {
            uniffi.frappuccino.reportStateWipe(reportStatePath())
        } catch (e: Exception) {
            Timber.w(e, "reportStateWipe failed in panicWipe")
        }
        // 3. Directories: renamed now, overwritten in the background. The
        //    plaintext ones (capture scratch, debug mirrors) are detached and
        //    wiped first: they are readable without any key.
        val plaintext = org.stream.crypto.capture.CaptureScratchCleaner.plaintextDirs(context)
        val ciphertext = EnvelopeQueue.ALL_DIRS.map { File(context.filesDir, it) } + listOf(
            File(context.filesDir, LegacyReportMigration.PROVENANCE_DIR),
            File(context.filesDir, ChunkUploadQueue.DIR_NAME),
            File(context.filesDir, "stream_migration"),
            File(context.cacheDir, "stream_encrypted"),
            File(context.cacheDir, "directory_entries"),
        )
        val detach = { dirs: List<File> ->
            dirs.mapNotNull { dir ->
                try {
                    org.stream.crypto.SecureDirWiper.detach(dir)
                } catch (e: Exception) {
                    Timber.w(e, "panicWipe: detach failed")
                    dir
                }
            }
        }
        val streamPlain = detach(plaintext)
        val streamCipher = detach(ciphertext)
        // The caller's directories (the archive viewer's) are renamed in the
        // same synchronous step, before any overwrite starts.
        val others = try {
            extra()
        } catch (e: Exception) {
            Timber.w(e, "panicWipe: extra detach failed")
            org.stream.crypto.DetachedDirs()
        }
        org.stream.crypto.SecureDirWiper.wipeInBackground(
            org.stream.crypto.SecureDirWiper.panicOrder(
                streamPlain, others.plaintext, streamCipher, others.ciphertext,
            ),
            "panic-wipe",
            others.afterErase,
        )
        // A sweep that read the alerts before the wipe could write them back
        // after it; clearing once more, last, wins that race.
        try {
            StreamPreferences.clearReportAlerts(context)
        } catch (e: Exception) {
            Timber.w(e, "clearReportAlerts failed in panicWipe")
        }
        // Not EnvelopeQueue.get(): it would recreate the queue directories
        // that were just renamed away.
        EnvelopeQueue.forgetForWipe(context)
        Timber.w("PANIC WIPE — local crypto state, report state and queues erased")
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

    // L'identité de déchiffrement du secours ne passe pas par ici :
    // ArchiveModeActivity appelle `ArchiveIdentity.fromMnemonic` directement.

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
        Timber.i("retryServerEnrollment: attempting")
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
     * Tourne sous le verrou d'authentification du processus : deux appels
     * concurrents (service, balayage, workers) s'exécutent l'un après l'autre,
     * et la file des preuves de rotation n'est lue et réécrite que par un seul
     * à la fois. Sans ce verrou, un verify accepté pouvait vider une preuve
     * qu'une rotation concurrente venait d'ajouter et n'avait pas encore
     * livrée.
     *
     * @return true si l'auth a réussi (le bearer est rangé côté Rust par
     *   verify(), jamais retourné ici), false sinon. §10.6.
     */
    fun authenticateV2(alreadyTriedReEnroll: Boolean = false): Boolean =
        synchronized(authLock) { authenticateV2Locked(alreadyTriedReEnroll) }

    /**
     * Authenticate only if [bearerPresent] says no bearer is held, single-flight
     * with every other authentication of the process: a caller that finds an
     * attempt under way waits for it and reuses its bearer instead of spending
     * a second slot. [mayAuthenticate] is evaluated under the same lock, right
     * before the attempt (recording running, device locked, no network: no
     * attempt). Returns whether a bearer is held at the end. Never throws.
     */
    fun authenticateIfAbsent(bearerPresent: () -> Boolean, mayAuthenticate: () -> Boolean): Boolean =
        authGate.ensure(bearerPresent) {
            mayAuthenticate() && try {
                authenticateV2()
            } catch (e: Exception) {
                Timber.w(e, "authentication threw")
                false
            }
        }

    private fun authenticateV2Locked(alreadyTriedReEnroll: Boolean): Boolean {
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
                return authenticateV2Locked(alreadyTriedReEnroll = true)
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
            // No batch number in the line: the relay stores each identity's
            // batch, and a test build sends its log to the relay.
            Timber.i("Relay caught up with the queued rotations")
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
                    Timber.i("Auto-rotated to the next batch")
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
     * Sous le verrou d'authentification, comme [authenticateV2] : les deux
     * lisent et réécrivent la file des preuves de rotation.
     */
    fun rotateBatchOnServer(): Boolean = synchronized(authLock) { rotateBatchOnServerLocked() }

    private fun rotateBatchOnServerLocked(): Boolean {
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

    // =========================================================================
    // RAPPORTS
    // =========================================================================

    /** Chemin du fichier d'état des rapports (écrit et scellé par Rust). */
    fun reportStatePath(): String = File(context.filesDir, REPORT_STATE_FILE).absolutePath

    fun hasReportState(): Boolean = File(reportStatePath()).exists()

    /** Vrai tant que la migration depuis le schéma de rapports précédent n'a pas fini. */
    fun needsLegacyMigration(): Boolean = LegacyReportMigration.isNeeded(context)

    /**
     * Ouvre le rapport suivant pour un enregistrement et rend son écrivain.
     * Rust avance l'état et l'écrit durablement AVANT de rendre l'écrivain ;
     * en cas d'erreur il n'y a pas d'écrivain et l'état est inchangé. Exige la
     * session PIN (appareil déverrouillé). Un seul écrivain vivant par
     * processus : un second appel pendant un enregistrement lève WriterBusy.
     */
    fun openReportWriter(): FfiReportWriter {
        val id = checkNotNull(identity) { "Not unlocked" }
        val author = uniffi.frappuccino.StreamIdentity.fromPublicKeys(
            id.ed25519PublicKey, id.x25519PublicKey
        )
        try {
            return uniffi.frappuccino.pinSessionOpenReport(reportStatePath(), author)
        } finally {
            author.destroy()
        }
    }

    /**
     * L'identité publique vers laquelle tout objet est chiffré, en objet FFI.
     * L'appelant le libère (`destroy`). Null si l'identité n'est pas chargée.
     */
    fun authorIdentity(): uniffi.frappuccino.StreamIdentity? {
        val id = identity ?: StreamPreferences.getIdentity(context) ?: return null
        return uniffi.frappuccino.StreamIdentity.fromPublicKeys(id.ed25519PublicKey, id.x25519PublicKey)
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

