package org.stream.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.stream.crypto.capture.StreamQuality

/**
 * StreamPreferences — Stockage persistant des données non-secrètes + blob ratchet
 * (schéma de prefs `stream_identity_v2`).
 *
 * La phrase BIP-39 n'est JAMAIS écrite sur disque, et rien ne doit l'y écrire : le
 * témoin doit l'avoir notée sur papier, sans quoi le mode archive lui est fermé.
 * C'est une absence : aucune ligne de code ne rappellera la règle à qui ajouterait
 * ici un `saveMnemonic()` pour éviter de la redemander à l'utilisateur.
 *
 * Sont persistés l'identité publique (ed25519_pk, x25519_pk), non scellée — elle
 * n'est pas secrète, l'enveloppe chiffrée est de la défense en profondeur — et le
 * batch ratchet, comme blob scellé par le PIN (Argon2id + XChaCha20).
 *
 * EncryptedSharedPreferences chiffre les valeurs en AES-256-GCM sous une clé du
 * KeyStore Android (TEE sur Seeker) : protection AU REPOS seulement. Sur un
 * processus vivant, cette couche-là ne protège plus rien — d'où le second sceau
 * PIN sur le blob ratchet, la graine de provenance et le master report, qui eux
 * restent scellés tant que le PIN n'a pas été saisi.
 */
object StreamPreferences {

    private const val PREFS_NAME = "stream_identity_v2"
    private const val KEY_ED25519_PK = "ed25519_pk_hex"
    private const val KEY_X25519_PK = "x25519_pk_hex"
    private const val KEY_RATCHET_BLOB = "ratchet_blob_b64"
    private const val KEY_INVITE_CODE = "invite_code"
    private const val KEY_SERVER_URL = "server_url"
    private const val KEY_PENDING_ENROLLMENT = "pending_enrollment_v1"
    private const val KEY_PENDING_ROTATIONS = "pending_rotations_v1"
    private const val KEY_ENROLLMENT_JUST_SUCCEEDED = "enrollment_just_succeeded_oneshot"
    // Phase 3.26 — orphan sweep mappings + toggle.
    private const val KEY_SESSION_REPORTS = "session_reports_v1"
    // Phase C (relay-blind reports) — monotone report-index counter. Each new
    // session allocates the next index n; its report_id = reportKeyring
    // .reportIdHex(n). Persistent + atomic so a retry/restart never reuses an
    // index for a different session. Reset on panic wipe (fresh identity = fresh
    // index space). The rescue tolerates skipped indices (gap tolerance), so a
    // crash that advances the counter without saving the mapping is harmless.
    private const val KEY_NEXT_REPORT_INDEX = "next_report_index_v1"
    private const val KEY_AUTO_UPLOAD_ORPHANS = "auto_upload_orphans"
    // User-configurable max recording quality cap ("FHD"|"HD"|"SD").
    private const val KEY_MAX_QUALITY_CAP = "max_quality_cap"
    // Shake-to-record toggle + sensitivity ("LOW"|"MED"|"HIGH").
    private const val KEY_SHAKE_ENABLED = "shake_to_record_enabled"
    private const val KEY_SHAKE_SENSITIVITY = "shake_sensitivity"
    // Debug calibration (2026-05-16) — fixed-bitrate mode for face-legibility testing.
    private const val KEY_DEBUG_BITRATE_ENABLED = "debug_bitrate_enabled"
    private const val KEY_DEBUG_BITRATE_QUALITY = "debug_bitrate_quality" // "HD" or "SD"
    private const val KEY_DEBUG_BITRATE_KBPS = "debug_bitrate_kbps"
    // Debug (2026-06-02) — squish root-cause harness. Cycles the HEVC
    // capture through 5 modes (aspect x GL correction) so the operator can
    // measure the matrix + the principled fix across devices, no rebuild :
    //   0 = A : 4:3  + fudge    (ANAMORPHIC_VSCALE 0.75 + 1.2x zoom) [legacy]
    //   1 = B : 16:9 + identity (vscale 1.0, zoom 1.0)
    //   2 = D : 4:3  + identity
    //   3 = E : 16:9 + fudge
    //   4 = F : 16:9 + derived vscale = rotatedSrcW/rotatedSrcH [DEFAULT — shipped fix]
    private const val KEY_DEBUG_ASPECT_MODE = "debug_aspect_mode"
    // Phase 3a (transport plan §10.9) — debug toggle routing the chunk PUT
    // through the QUIC/h3 transport (quinn-BBR) instead of DirectTls. Off by
    // default; only set during on-device QUIC reliability validation.
    private const val KEY_DEBUG_QUIC_TRANSPORT = "debug_quic_transport"
    // §10.11 — provenance : graine de la clé de signature dédiée (PIN-scellée,
    // même format que le ratchet) + toggle (défaut ON, décision therealshulgin 2026-06-24).
    private const val KEY_PROVENANCE_SEED_BLOB = "provenance_seed_blob_b64"
    private const val KEY_PROVENANCE_ENABLED = "provenance_enabled"

    // Phase C (relay-blind reports) — the report capability master seed
    // (report_master, 32 bytes), PIN-sealed exactly like the provenance seed.
    // Persisted at enrollment, reloaded at unlock to reconstruct the
    // ReportKeyring that addresses + signs each report by a key derived from
    // the phrase (never the identity). Wiped on panic.
    private const val KEY_REPORT_MASTER_BLOB = "report_master_blob_b64"
    // §10.11 Phase B — opt-in trustless OTS timestamp toggle (défaut OFF : un
    // .ots est une miette publique Bitcoin permanente).
    private const val KEY_PROVENANCE_TIMESTAMP_ENABLED = "provenance_timestamp_enabled"

    @Volatile
    private var cachedPrefs: SharedPreferences? = null

    private fun getPrefs(context: Context): SharedPreferences {
        cachedPrefs?.let { return it }
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context, PREFS_NAME, masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ).also { cachedPrefs = it }
    }

    // -- Identité publique --

    fun saveIdentity(context: Context, identity: StreamIdentity) {
        getPrefs(context).edit()
            .putString(KEY_ED25519_PK, bytesToHex(identity.ed25519PublicKey))
            .putString(KEY_X25519_PK, bytesToHex(identity.x25519PublicKey))
            .apply()
    }

    fun getIdentity(context: Context): StreamIdentity? {
        val prefs = getPrefs(context)
        val edHex = prefs.getString(KEY_ED25519_PK, null) ?: return null
        val xHex = prefs.getString(KEY_X25519_PK, null) ?: return null
        return try {
            StreamIdentity(hexToBytes(edHex), hexToBytes(xHex))
        } catch (e: Exception) {
            null
        }
    }

    fun hasIdentity(context: Context): Boolean =
        getPrefs(context).getString(KEY_ED25519_PK, null) != null

    // -- Ratchet state (PIN-wrapped blob) --

    fun saveRatchetBlob(context: Context, blob: ByteArray) {
        val b64 = Base64.encodeToString(blob, Base64.NO_WRAP)
        getPrefs(context).edit().putString(KEY_RATCHET_BLOB, b64).apply()
    }

    fun getRatchetBlob(context: Context): ByteArray? {
        val b64 = getPrefs(context).getString(KEY_RATCHET_BLOB, null) ?: return null
        return try {
            Base64.decode(b64, Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }

    fun hasRatchetBlob(context: Context): Boolean =
        getPrefs(context).getString(KEY_RATCHET_BLOB, null) != null

    // -- §10.11 Provenance : graine de signature (PIN-scellée) + toggle --
    //
    // Le Base64 stocké ici n'est pas la graine en clair : c'est le seed 32 o de la
    // clé de provenance dédiée, scellé comme le blob ratchet (Argon2id + XChaCha20)
    // par `ProvenanceSigner.sealWithSession()`, qui scelle in-crate avec la clé PIN
    // que tient le holder de session — la clé dérivée ne traverse pas la FFI
    // (R-CR-1). Écrit à l'enrôlement, rechargeable seulement au unlock, pour
    // reconstruire le ProvenanceSigner.
    //
    // Le toggle est ON par défaut (décision therealshulgin 2026-06-24) alors que l'app
    // minimise ses métadonnées, et c'est tenable : le manifeste est scellé E2E
    // (relais aveugle, seul le témoin l'ouvre) et le lieu reste un opt-in séparé,
    // donc chaque enregistrement est prouvable sans rien fuiter. Le témoin peut
    // toujours le désactiver dans les réglages.

    fun saveProvenanceSeedBlob(context: Context, blob: ByteArray) {
        val b64 = Base64.encodeToString(blob, Base64.NO_WRAP)
        getPrefs(context).edit().putString(KEY_PROVENANCE_SEED_BLOB, b64).apply()
    }

    fun getProvenanceSeedBlob(context: Context): ByteArray? {
        val b64 = getPrefs(context).getString(KEY_PROVENANCE_SEED_BLOB, null) ?: return null
        return try {
            Base64.decode(b64, Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }

    fun hasProvenanceSeedBlob(context: Context): Boolean =
        getPrefs(context).getString(KEY_PROVENANCE_SEED_BLOB, null) != null

    // Phase C (relay-blind reports) — report_master seed blob, PIN-sealed.

    fun saveReportMasterBlob(context: Context, blob: ByteArray) {
        val b64 = Base64.encodeToString(blob, Base64.NO_WRAP)
        getPrefs(context).edit().putString(KEY_REPORT_MASTER_BLOB, b64).apply()
    }

    fun getReportMasterBlob(context: Context): ByteArray? {
        val b64 = getPrefs(context).getString(KEY_REPORT_MASTER_BLOB, null) ?: return null
        return try {
            Base64.decode(b64, Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }

    fun hasReportMasterBlob(context: Context): Boolean =
        getPrefs(context).getString(KEY_REPORT_MASTER_BLOB, null) != null

    fun isProvenanceEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_PROVENANCE_ENABLED, true)

    fun setProvenanceEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_PROVENANCE_ENABLED, enabled).apply()
    }

    // §10.11 Phase B — opt-in OTS timestamp toggle. Default OFF: a .ots is a
    // permanent public Bitcoin breadcrumb, so the witness opts in deliberately.
    fun isProvenanceTimestampEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_PROVENANCE_TIMESTAMP_ENABLED, false)

    fun setProvenanceTimestampEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_PROVENANCE_TIMESTAMP_ENABLED, enabled).apply()
    }

    // -- Wipe complet (panic button) --

    /**
     * Efface toute trace de l'identité et du ratchet.
     * Équivalent d'un factory reset du chiffrement.
     */
    fun wipeAll(context: Context) {
        getPrefs(context).edit()
            .remove(KEY_ED25519_PK)
            .remove(KEY_X25519_PK)
            .remove(KEY_RATCHET_BLOB)
            .remove(KEY_PENDING_ENROLLMENT)
            .remove(KEY_PENDING_ROTATIONS)
            .remove(KEY_ENROLLMENT_JUST_SUCCEEDED)
            // Phase 3.26 — session→report mappings are user data too.
            .remove(KEY_SESSION_REPORTS)
            // Phase C — reset the report-index counter (fresh identity at
            // re-enroll = fresh index space).
            .remove(KEY_NEXT_REPORT_INDEX)
            // Orphan deletion alerts (counts/dates, not secret
            // but still user data tied to this identity).
            .remove(KEY_ORPHAN_DELETIONS)
            // §10.11 — provenance signing seed (PIN-sealed) + opt-in toggle. The
            // seed is key material tied to this identity → must go on panic wipe.
            .remove(KEY_PROVENANCE_SEED_BLOB)
            .remove(KEY_PROVENANCE_ENABLED)
            .remove(KEY_PROVENANCE_TIMESTAMP_ENABLED)
            // Phase C — report capability master seed (key material tied to this
            // identity) must go on panic wipe.
            .remove(KEY_REPORT_MASTER_BLOB)
            .commit()
    }

    // -- Config diverse (inchangée) --

    fun saveInviteCode(context: Context, code: String) {
        getPrefs(context).edit().putString(KEY_INVITE_CODE, code).apply()
    }

    fun getInviteCode(context: Context): String? =
        getPrefs(context).getString(KEY_INVITE_CODE, null)

    fun saveServerUrl(context: Context, url: String) {
        getPrefs(context).edit().putString(KEY_SERVER_URL, url).apply()
    }

    fun getServerUrl(context: Context): String? =
        getPrefs(context).getString(KEY_SERVER_URL, null)

    // -- Pending enrollment: server enrollment retry on reconnect --
    //
    // This proof holds ONLY public material: the long-term ed25519 pk, the 50
    // batch_0 pubs, and the long-term ed25519 signature over their concatenation.
    // Nothing secret goes in here — not a seed, not the PIN — not even to make the
    // retry more reliable: reading the file must leak nothing. It still goes through
    // EncryptedSharedPreferences for defense-in-depth, matching the identity record
    // convention.
    //
    // It is written by StreamUploadManager.enrollFromMnemonic right after the local
    // enrollment and BEFORE the server call, so that a server failure during
    // onboarding cannot strand the device in the dead state "enrolled locally,
    // unknown to the server". Cleared by enrollOnServer on success, read back by
    // retryServerEnrollment (manual button + EnrollmentRetryWorker). The JSON shape
    // is in savePendingEnrollment just below, minus the widths, which are part of
    // the on-disk contract : ed25519_pk_hex 64 hex, batch_0_pks 50 × 64 hex,
    // enrollment_signature_hex 128 hex. Nothing checks them on the way back in —
    // getPendingEnrollment only catches a malformed JSON.

    fun savePendingEnrollment(
        context: Context,
        ed25519PkHex: String,
        batch0Pks: List<ByteArray>,
        enrollmentSignature: ByteArray,
    ) {
        val obj = org.json.JSONObject()
        obj.put("ed25519_pk_hex", ed25519PkHex)
        val arr = org.json.JSONArray()
        for (pk in batch0Pks) {
            arr.put(bytesToHex(pk))
        }
        obj.put("batch_0_pks", arr)
        obj.put("enrollment_signature_hex", bytesToHex(enrollmentSignature))
        getPrefs(context).edit().putString(KEY_PENDING_ENROLLMENT, obj.toString()).apply()
    }

    /** Holder for the deserialized pending enrollment proof. */
    data class PendingEnrollment(
        val ed25519PkHex: String,
        val batch0Pks: List<ByteArray>,
        val enrollmentSignature: ByteArray,
    )

    fun getPendingEnrollment(context: Context): PendingEnrollment? {
        val raw = getPrefs(context).getString(KEY_PENDING_ENROLLMENT, null) ?: return null
        return try {
            val obj = org.json.JSONObject(raw)
            val pksJson = obj.getJSONArray("batch_0_pks")
            val pks = ArrayList<ByteArray>(pksJson.length())
            for (i in 0 until pksJson.length()) {
                pks.add(hexToBytes(pksJson.getString(i)))
            }
            PendingEnrollment(
                ed25519PkHex = obj.getString("ed25519_pk_hex"),
                batch0Pks = pks,
                enrollmentSignature = hexToBytes(obj.getString("enrollment_signature_hex")),
            )
        } catch (e: Exception) {
            // Malformed payload — treat as if absent.
            null
        }
    }

    fun hasPendingEnrollment(context: Context): Boolean =
        getPrefs(context).getString(KEY_PENDING_ENROLLMENT, null) != null

    fun clearPendingEnrollment(context: Context) {
        getPrefs(context).edit().remove(KEY_PENDING_ENROLLMENT).apply()
    }

    // -- Rotations de batch en attente de confirmation serveur --
    //
    // Même dispositif que la preuve d'enrôlement ci-dessus, et pour la même
    // raison, un cran plus loin dans la même machine à états. `advanceBatch()`
    // fait avancer le ratchet LOCAL et le persiste ; si l'appel
    // `/auth/v2/rotate-batch` qui suit échoue, l'appareil est sur le batch N+1
    // et le relais sur le batch N. Le serveur compare `batch_number` à chaque
    // auth (`is_ephemeral_key_valid`), donc il refuse tout, définitivement : il
    // n'y a ni route de ré-enrôlement (409 sur une identité connue) ni route de
    // révocation. L'enrôlement serait perdu, et avec lui l'annuaire de reports.
    //
    // Une preuve reste valable tant que le relais n'a pas avancé : elle ne
    // contient que du public (les 50 nouvelles pk, la pk du signataire, sa
    // signature), et le slot qu'elle consomme n'est pas encore consommé côté
    // serveur. La renvoyer répare la désynchro sans rien re-signer, ce qui tombe
    // bien puisque advanceBatch a déjà wipé le batch qui pourrait la produire.
    //
    // POURQUOI UNE FILE ET PAS UNE SEULE PREUVE. Le relais rend un 401 unique
    // pour tout refus de rotation (anti-oracle, R-SRV-1), donc un refus ne dit
    // pas s'il n'a jamais reçu la rotation ou s'il l'a déjà appliquée et refuse
    // un rejeu (`rotate_batch` compare lui aussi `batch_number`). Impossible,
    // depuis l'appareil, de savoir dans lequel des deux états il se trouve : on
    // garde donc toutes les preuves et on les rejoue dans l'ordre, chacune étant
    // signée par un slot du batch dont elle part. Le relais applique celles qui
    // partent de là où il est vraiment et refuse les autres, sans que personne
    // n'ait eu à deviner. Avec une seule preuve, la rotation suivante écrasait
    // la seule capable de réparer, et la désynchro devenait définitive.
    //
    // Rien de secret ici non plus : lire le fichier n'apprend rien qu'une écoute
    // du réseau n'apprendrait. EncryptedSharedPreferences quand même, par
    // convention avec le reste.

    /**
     * Plafond de la file. Une entrée de plus par avancée de batch, et la file est
     * vidée dès qu'une auth passe : y arriver demande environ 50 x 8 auths
     * refusées d'affilée, sans une seule réussie. Un appareil dans cet état a
     * déjà perdu son enrôlement ; le plafond ne le sauve pas, il borne
     * simplement ce que le fichier peut grossir.
     */
    const val MAX_PENDING_ROTATIONS = 8

    /** Une preuve de rotation désérialisée. */
    data class PendingRotation(
        val newBatchNumber: Int,
        val newBatchPks: List<ByteArray>,
        val signerPk: ByteArray,
        val signerBatchNumber: Int,
        val signerKeyIndex: Int,
        val signature: ByteArray,
    )

    /**
     * Ajoute une preuve à la file.
     *
     * @return false si la file est pleine (rien n'est écrit) : l'appelant ne doit
     *   alors PAS faire avancer le ratchet, faute de quoi il produirait une preuve
     *   que plus rien ne conserve, et casserait la chaîne.
     */
    fun appendPendingRotation(context: Context, rotation: PendingRotation): Boolean {
        val current = getPendingRotations(context)
        if (current.size >= MAX_PENDING_ROTATIONS) return false
        val arr = org.json.JSONArray()
        for (r in current) {
            arr.put(rotationToJson(r))
        }
        arr.put(rotationToJson(rotation))
        getPrefs(context).edit().putString(KEY_PENDING_ROTATIONS, arr.toString()).apply()
        return true
    }

    /** La file, du plus ancien au plus récent. Vide si absente ou illisible. */
    fun getPendingRotations(context: Context): List<PendingRotation> {
        val raw = getPrefs(context).getString(KEY_PENDING_ROTATIONS, null) ?: return emptyList()
        return try {
            val arr = org.json.JSONArray(raw)
            val out = ArrayList<PendingRotation>(arr.length())
            for (i in 0 until arr.length()) {
                out.add(rotationFromJson(arr.getJSONObject(i)))
            }
            out
        } catch (e: Exception) {
            // Contenu illisible : traité comme absent. Perdre la file coûte
            // l'enrôlement si une rotation était vraiment en vol, mais une file
            // à moitié lue serait rejouée dans le désordre, ce qui est pire.
            emptyList()
        }
    }

    /** Réécrit la file, typiquement pour retirer les preuves devenues inutiles. */
    fun setPendingRotations(context: Context, rotations: List<PendingRotation>) {
        if (rotations.isEmpty()) {
            clearPendingRotations(context)
            return
        }
        val arr = org.json.JSONArray()
        for (r in rotations) {
            arr.put(rotationToJson(r))
        }
        getPrefs(context).edit().putString(KEY_PENDING_ROTATIONS, arr.toString()).apply()
    }

    fun hasPendingRotations(context: Context): Boolean =
        getPrefs(context).getString(KEY_PENDING_ROTATIONS, null) != null

    fun clearPendingRotations(context: Context) {
        getPrefs(context).edit().remove(KEY_PENDING_ROTATIONS).apply()
    }

    private fun rotationToJson(r: PendingRotation): org.json.JSONObject {
        val obj = org.json.JSONObject()
        obj.put("new_batch_number", r.newBatchNumber)
        val pks = org.json.JSONArray()
        for (pk in r.newBatchPks) {
            pks.put(bytesToHex(pk))
        }
        obj.put("new_batch_pks", pks)
        obj.put("signer_pk_hex", bytesToHex(r.signerPk))
        obj.put("signer_batch_number", r.signerBatchNumber)
        obj.put("signer_key_index", r.signerKeyIndex)
        obj.put("signature_hex", bytesToHex(r.signature))
        return obj
    }

    private fun rotationFromJson(obj: org.json.JSONObject): PendingRotation {
        val pksJson = obj.getJSONArray("new_batch_pks")
        val pks = ArrayList<ByteArray>(pksJson.length())
        for (i in 0 until pksJson.length()) {
            pks.add(hexToBytes(pksJson.getString(i)))
        }
        return PendingRotation(
            newBatchNumber = obj.getInt("new_batch_number"),
            newBatchPks = pks,
            signerPk = hexToBytes(obj.getString("signer_pk_hex")),
            signerBatchNumber = obj.getInt("signer_batch_number"),
            signerKeyIndex = obj.getInt("signer_key_index"),
            signature = hexToBytes(obj.getString("signature_hex")),
        )
    }

    // -- One-shot flag : "l'enrôlement vient de réussir, prévenir l'utilisateur" --
    //
    // L'EnrollmentRetryWorker tourne en background, sans accès propre au Toast ni
    // au thread UI : il ne peut pas prévenir l'utilisateur lui-même. Il pose donc
    // ce flag, que la prochaine activity foregroundée consomme pour afficher le
    // toast à sa place.

    fun markEnrollmentSucceeded(context: Context) {
        getPrefs(context).edit()
            .putBoolean(KEY_ENROLLMENT_JUST_SUCCEEDED, true)
            .apply()
    }

    /**
     * One-shot : lit le flag et l'efface, en deux opérations. Retourne true si une
     * réussite d'enrôlement attendait d'être affichée, false sinon. Non
     * synchronisé, ce qui est sans conséquence ici : les deux seuls consommateurs
     * sont StreamActivity.onResume et StreamSettingsActivity.onResume, donc le
     * main thread : le premier qui passe gagne, l'autre voit false.
     */
    fun consumeEnrollmentSucceededFlag(context: Context): Boolean {
        val prefs = getPrefs(context)
        val v = prefs.getBoolean(KEY_ENROLLMENT_JUST_SUCCEEDED, false)
        if (v) {
            prefs.edit().remove(KEY_ENROLLMENT_JUST_SUCCEEDED).apply()
        }
        return v
    }

    // -- Orphan upload sweep state --
    //
    // A persisted map of {sessionId → (reportId, retryCount)} so the
    // OrphanSweepWorker can re-authenticate and finish uploading blobs whose
    // recording session stopped before the queue drained. Stored as a JSON object :
    //   { "<sessionId>": {"r": "<reportId>", "n": <retryCount>}, ... }
    //
    // retryCount is only bumped when a real upload attempt was made on a reachable
    // server : network-absent skips must not burn the budget, because once it is
    // spent (OrphanSweepWorker.MAX_RETRIES) the sweeper secure-deletes those blobs.
    // A device kept out of network for a long time would otherwise lose fragments
    // it never had a chance to upload.
    //
    // The four mutating helpers below are called from at least two threads :
    //   - StreamRecordingService.initServerSession (allocateReportIndexForSession)
    //   - OrphanSweepWorker.doWork (increment / remove, and
    //     allocateReportIndexForSession too on the offline-start rescue path)
    //   - StreamPreferences.wipeAll on panic-wipe (removes the key)
    // Hence the lock. Without it the read-modify-write pattern
    // (`getSessionReports().toMutableMap()` then `writeSessionReports`) is a classic
    // lost-update race : a concurrent `removeSessionReport` and
    // `incrementSessionReportRetry` both read the same snapshot, mutate
    // independently and write back, and one of the changes is silently lost. The
    // two symptoms are an orphan that retries indefinitely, or a freshly-saved
    // session that goes missing.
    //
    // Writes are `.commit()` (sync), not `.apply()` (async), so a process kill
    // landing between the in-RAM Map update and the disk flush cannot lose the
    // mapping (orphan blobs nothing ever picks up again) nor the bumped counter (an
    // unbounded upload loop on an unrecoverable session). It costs ~5-30 ms on a
    // healthy device and fires at most once per chunk session start plus once per
    // 30 min sweep tick, which is what makes it affordable.

    /** Guards the read-modify-write of session_reports. */
    private val sessionReportsLock = Any()

    // Phase C — `reportIndex` is the report's derivation index n (report_id =
    // reportKeyring.reportIdHex(n)). Defaults to -1 for legacy entries written
    // before the relay-blind migration (those carry a server-assigned reportId
    // and no index); a -1 index means "not a derived report".
    data class SessionReportEntry(
        val reportId: String,
        val retryCount: Int,
        val reportIndex: Int = -1,
    )

    fun saveSessionReport(context: Context, sessionId: String, reportId: String) {
        synchronized(sessionReportsLock) {
            val map = getSessionReportsLocked(context).toMutableMap()
            // If the entry already exists we keep its retryCount + index — we
            // may be re-saving the same mapping after a process restart.
            val existing = map[sessionId]
            map[sessionId] = SessionReportEntry(
                reportId, existing?.retryCount ?: 0, existing?.reportIndex ?: -1
            )
            writeSessionReports(context, map)
        }
    }

    /**
     * Atomic and idempotent on [sessionId] : allocates (or reuses) the
     * relay-blind report derivation index `n` and returns its
     * [SessionReportEntry]. Call it once at session
     * start, before any chunk is enqueued: a re-allocation after a crash can then
     * never diverge from an already-uploaded chunk, since none exist yet.
     *
     * The counter is committed BEFORE the mapping, and the two writes must not be
     * merged into a single edit. A crash between them only SKIPS an index, which is
     * harmless because the rescue path tolerates gaps; what the order rules out is
     * the same n being handed to two different sessions. Same n means same
     * report_id, so two distinct recordings would end up glued under one report at
     * the blind relay.
     *
     * A session that already has a mapping gets it back verbatim: a retry or a
     * process restart reuses its n, never a 2nd report. Otherwise the next index
     * comes off the monotone counter and its report_id is derived by
     * [deriveReportId] (the caller passes `reportKeyring.reportIdHex(n)`).
     */
    fun allocateReportIndexForSession(
        context: Context,
        sessionId: String,
        deriveReportId: (Int) -> String,
    ): SessionReportEntry {
        synchronized(sessionReportsLock) {
            val map = getSessionReportsLocked(context).toMutableMap()
            map[sessionId]?.let { return it }
            val prefs = getPrefs(context)
            val n = prefs.getInt(KEY_NEXT_REPORT_INDEX, 0)
            val entry = SessionReportEntry(deriveReportId(n), 0, n)
            // Counter first (durable), then the mapping (see fn doc).
            prefs.edit().putInt(KEY_NEXT_REPORT_INDEX, n + 1).commit()
            map[sessionId] = entry
            writeSessionReports(context, map)
            return entry
        }
    }

    fun getSessionReports(context: Context): Map<String, SessionReportEntry> {
        // Read path is safe under the same lock — guarantees we never
        // observe a torn JSON (impossible in practice because the
        // underlying SharedPreferences is internally synchronized, but
        // taking the lock here also keeps a writer from racing the
        // post-read mutation in `incrementSessionReportRetry`).
        synchronized(sessionReportsLock) {
            return getSessionReportsLocked(context)
        }
    }

    /**
     * Caller must already hold [sessionReportsLock]. Centralises the
     * JSON deserialisation so the synchronized public API and the
     * internal mutate-then-write helpers share one implementation.
     */
    private fun getSessionReportsLocked(context: Context): Map<String, SessionReportEntry> {
        val raw = getPrefs(context).getString(KEY_SESSION_REPORTS, null) ?: return emptyMap()
        return try {
            val obj = org.json.JSONObject(raw)
            val out = mutableMapOf<String, SessionReportEntry>()
            val keys = obj.keys()
            while (keys.hasNext()) {
                val sid = keys.next()
                val entry = obj.getJSONObject(sid)
                out[sid] = SessionReportEntry(
                    reportId = entry.getString("r"),
                    retryCount = entry.optInt("n", 0),
                    reportIndex = entry.optInt("i", -1),
                )
            }
            out
        } catch (e: Exception) {
            emptyMap()
        }
    }

    fun removeSessionReport(context: Context, sessionId: String) {
        synchronized(sessionReportsLock) {
            val map = getSessionReportsLocked(context).toMutableMap()
            map.remove(sessionId)
            writeSessionReports(context, map)
        }
    }

    /** Returns the new count after increment. */
    fun incrementSessionReportRetry(context: Context, sessionId: String): Int {
        synchronized(sessionReportsLock) {
            val map = getSessionReportsLocked(context).toMutableMap()
            val existing = map[sessionId] ?: return 0
            val next = SessionReportEntry(
                existing.reportId, existing.retryCount + 1, existing.reportIndex
            )
            map[sessionId] = next
            writeSessionReports(context, map)
            return next.retryCount
        }
    }

    private fun writeSessionReports(
        context: Context,
        map: Map<String, SessionReportEntry>,
    ) {
        val obj = org.json.JSONObject()
        for ((sid, entry) in map) {
            val e = org.json.JSONObject()
            e.put("r", entry.reportId)
            e.put("n", entry.retryCount)
            e.put("i", entry.reportIndex)  // Phase C — derivation index n
            obj.put(sid, e)
        }
        // .commit() (sync + fsync) instead of .apply()
        // (async). Guarantees the retryCount increment and the
        // {sessionId → reportId} mapping are durable before we return,
        // so a process kill landing right after this point can't
        // silently lose either the new session mapping or the bumped
        // retry counter (the latter would re-allow an unbounded upload
        // loop on an unrecoverable session).
        getPrefs(context).edit().putString(KEY_SESSION_REPORTS, obj.toString()).commit()
    }

    // -- Phase 3.26 — auto-upload orphans toggle --
    //
    // Default ON. The OrphanSweepWorker checks this flag at each tick
    // and returns success-no-op when OFF, so the user can disable the
    // background upload without disturbing the WorkManager schedule.

    fun isAutoUploadOrphansEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_AUTO_UPLOAD_ORPHANS, true)

    fun setAutoUploadOrphansEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_AUTO_UPLOAD_ORPHANS, enabled).apply()
    }

    // -- Orphan deletion alerts: in-app only, never a system notification --
    //
    // These alerts must never be surfaced through a system notification
    // (threat-model choice, therealshulgin 2026-06-18). A notification would force
    // POST_NOTIFICATIONS app-wide, and that permission also un-hides the recording
    // foreground-service notification: a witness filming covertly would light up
    // their own status bar. The app declares no notification permission today, so
    // nothing shows. The in-app banner is read AFTER unlock, so the detail never
    // leaks on a locked screen either.
    //
    // Why the events exist at all: when the rescue path gives up (OrphanSweepWorker
    // MAX_RETRIES) or the 48 h TTL sweep (ChunkUploadQueue.sweepStaleChunks)
    // secure-deletes orphan blobs, we append a small event here, so that the next
    // time the user opens the app the StreamActivity banner can surface "N
    // fragments were deleted (never uploaded)" instead of the video vanishing in
    // silence.
    //
    // Stored encrypted and bounded to the most recent MAX_DELETION_EVENTS; the JSON
    // shape is in writeOrphanDeletions.

    private const val KEY_ORPHAN_DELETIONS = "orphan_deletions_v1"
    private const val MAX_DELETION_EVENTS = 20

    /** Guards the read-modify-write of orphan_deletions. */
    private val orphanDeletionsLock = Any()

    /** reason is "expired" (48 h TTL) or "unrecoverable" (rescue gave up). */
    data class OrphanDeletionEvent(
        val count: Int,
        val oldestBlobMs: Long,
        val reason: String,
        val recordedAtMs: Long,
    )

    fun addOrphanDeletion(context: Context, count: Int, oldestBlobMs: Long, reason: String) {
        if (count <= 0) return
        synchronized(orphanDeletionsLock) {
            val events = getOrphanDeletionsLocked(context).toMutableList()
            events.add(
                OrphanDeletionEvent(count, oldestBlobMs, reason, System.currentTimeMillis())
            )
            writeOrphanDeletions(context, events.takeLast(MAX_DELETION_EVENTS))
        }
    }

    fun getOrphanDeletions(context: Context): List<OrphanDeletionEvent> {
        synchronized(orphanDeletionsLock) { return getOrphanDeletionsLocked(context) }
    }

    fun clearOrphanDeletions(context: Context) {
        synchronized(orphanDeletionsLock) {
            getPrefs(context).edit().remove(KEY_ORPHAN_DELETIONS).commit()
        }
    }

    private fun getOrphanDeletionsLocked(context: Context): List<OrphanDeletionEvent> {
        val raw = getPrefs(context).getString(KEY_ORPHAN_DELETIONS, null) ?: return emptyList()
        return try {
            val arr = org.json.JSONArray(raw)
            val out = ArrayList<OrphanDeletionEvent>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                out.add(
                    OrphanDeletionEvent(
                        count = o.getInt("c"),
                        oldestBlobMs = o.optLong("o", 0L),
                        reason = o.optString("r", "expired"),
                        recordedAtMs = o.optLong("t", 0L),
                    )
                )
            }
            out
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun writeOrphanDeletions(context: Context, events: List<OrphanDeletionEvent>) {
        val arr = org.json.JSONArray()
        for (e in events) {
            val o = org.json.JSONObject()
            o.put("c", e.count)
            o.put("o", e.oldestBlobMs)
            o.put("r", e.reason)
            o.put("t", e.recordedAtMs)
            arr.put(o)
        }
        getPrefs(context).edit().putString(KEY_ORPHAN_DELETIONS, arr.toString()).commit()
    }

    // -- Phase 7.3 — max recording quality cap --
    //
    // Ceiling the AdaptiveQualityManager never climbs above. FHD (default)
    // = no cap = legacy behaviour ; HD / SD bound per-chunk size + data
    // usage on metered/flaky links (the adaptive ladder still drops BELOW
    // the cap as the network degrades). Stored as the StreamQuality name so
    // an unknown/legacy value degrades gracefully to FHD (= no cap).

    fun getMaxQualityCap(context: Context): StreamQuality =
        when (getPrefs(context).getString(KEY_MAX_QUALITY_CAP, "FHD")) {
            "SD" -> StreamQuality.SD
            "HD" -> StreamQuality.HD
            else -> StreamQuality.FHD
        }

    fun setMaxQualityCap(context: Context, cap: StreamQuality) {
        getPrefs(context).edit().putString(KEY_MAX_QUALITY_CAP, cap.name).apply()
    }

    // -- Phase 7.3 — shake-to-record (start a recording by shaking) --
    //
    // The accelerometer "frappuccino shake" gesture starts a recording when
    // the app is idle (a quick panic-record affordance). Enabled by default.
    // Sensitivity ("LOW"|"MED"|"HIGH", default MED) maps to the ShakeDetector
    // jolt threshold via ShakeDetector.thresholdFor.

    fun isShakeToRecordEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_SHAKE_ENABLED, true)

    fun setShakeToRecordEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_SHAKE_ENABLED, enabled).apply()
    }

    /** "LOW" | "MED" | "HIGH". Default "MED" (the historical hard-coded value). */
    fun getShakeSensitivity(context: Context): String =
        getPrefs(context).getString(KEY_SHAKE_SENSITIVITY, "MED") ?: "MED"

    fun setShakeSensitivity(context: Context, sensitivity: String) {
        getPrefs(context).edit().putString(KEY_SHAKE_SENSITIVITY, sensitivity).apply()
    }

    // -- Debug calibration : fixed-bitrate mode (2026-05-16) --
    //
    // Disables AdaptiveQualityManager and locks MediaCodec to a fixed
    // resolution + bitrate so an operator can record short clips at
    // controlled paliers and judge subjectively where face legibility
    // breaks. Off by default — only operators in calibration sessions
    // should ever flip this.

    fun isDebugBitrateEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_DEBUG_BITRATE_ENABLED, false)

    fun setDebugBitrateEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_DEBUG_BITRATE_ENABLED, enabled).apply()
    }

    /** "HD" (720p) or "SD" (480p). Default "HD". */
    fun getDebugBitrateQuality(context: Context): String =
        getPrefs(context).getString(KEY_DEBUG_BITRATE_QUALITY, "HD") ?: "HD"

    fun setDebugBitrateQuality(context: Context, quality: String) {
        getPrefs(context).edit().putString(KEY_DEBUG_BITRATE_QUALITY, quality).apply()
    }

    /** kbps. Default 800. */
    fun getDebugBitrateKbps(context: Context): Int =
        getPrefs(context).getInt(KEY_DEBUG_BITRATE_KBPS, 800)

    fun setDebugBitrateKbps(context: Context, kbps: Int) {
        getPrefs(context).edit().putInt(KEY_DEBUG_BITRATE_KBPS, kbps).apply()
    }

    // -- Debug (2026-06-02) — squish harness (mode 0=A 1=B 2=D 3=E 4=F) --

    /**
     * 0=A 1=B 2=D 3=E 4=F (see KEY_DEBUG_ASPECT_MODE). Default 4 = F = the
     * SHIPPED production config (16:9 + derived vscale). Modes 0-3 are
     * diagnostic variants the operator can cycle to via the Settings toggle.
     */
    fun getDebugAspectMode(context: Context): Int =
        getPrefs(context).getInt(KEY_DEBUG_ASPECT_MODE, 4)

    fun setDebugAspectMode(context: Context, mode: Int) {
        getPrefs(context).edit().putInt(KEY_DEBUG_ASPECT_MODE, ((mode % 5) + 5) % 5).apply()
    }

    // -- QUIC transport debug toggle --
    //
    // This pref is inert on its own: the only thing that applies it is
    // StreamSettingsActivity, which re-pushes it to RustUploadTransport.mode
    // whenever the settings screen opens, and the upload worker reads that field
    // directly. Changing the stored value and then recording without reopening
    // Settings changes nothing — which is not QUIC being broken.
    //
    // When ON, ChunkUploadWorker routes the chunk PUT through the QUIC/h3 transport
    // (TransportMode.OBF_QUIC) instead of DirectTls, and the choice survives
    // restarts. Default ON since the 2-device Gate-3 A/B (2026-06-20 d): debug
    // builds dogfood QUIC. Both reads are BuildConfig.DEBUG-gated, which is what
    // makes a default ON tolerable here; release takes RustUploadTransport.mode's
    // own default, which is OBF_QUIC too since the D-1 closure
    // (RustUploadTransport.kt:46).

    fun isDebugQuicTransport(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_DEBUG_QUIC_TRANSPORT, true)

    fun setDebugQuicTransport(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_DEBUG_QUIC_TRANSPORT, enabled).apply()
    }

    // -- Helpers internes --

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex length must be even" }
        return ByteArray(hex.length / 2) { i ->
            ((Character.digit(hex[i * 2], 16) shl 4) or
             Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
    }
}
