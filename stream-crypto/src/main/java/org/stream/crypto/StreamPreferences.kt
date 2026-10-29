package org.stream.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.stream.crypto.capture.StreamQuality
import org.stream.crypto.upload.ReportAlerts

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
 * PIN sur le blob ratchet et la graine de provenance, qui eux restent scellés
 * tant que le PIN n'a pas été saisi.
 *
 * L'état des rapports n'est PAS ici : il vit dans `filesDir/report_state.bin`,
 * écrit et scellé par Rust, et ne traverse jamais la JVM. Ce qui reste ici du
 * schéma de rapports précédent (master report scellé, correspondances
 * session → index, compteur d'index) n'est lu que par la migration, qui
 * l'efface une fois terminée.
 */
object StreamPreferences {

    private const val PREFS_NAME = "stream_identity_v2"
    private const val KEY_ED25519_PK = "ed25519_pk_hex"
    private const val KEY_X25519_PK = "x25519_pk_hex"
    private const val KEY_RATCHET_BLOB = "ratchet_blob_b64"
    // Retired: the invitation code of the V1 onboarding. It named the
    // organisation behind the witness, nothing read it, and the relay no longer
    // has an invite route. Phones that stored it erase it (forgetRetiredKeys).
    // Do not reuse the key.
    private const val KEY_RETIRED_INVITE_CODE = "invite_code"
    private const val KEY_SERVER_URL = "server_url"
    private const val KEY_PENDING_ENROLLMENT = "pending_enrollment_v1"
    private const val KEY_PENDING_ROTATIONS = "pending_rotations_v1"
    private const val KEY_ENROLLMENT_JUST_SUCCEEDED = "enrollment_just_succeeded_oneshot"
    // Legacy report scheme (read by the migration only, then deleted): the
    // session → legacy index mappings and the legacy index counter.
    private const val KEY_SESSION_REPORTS = "session_reports_v1"
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
    // même format que le ratchet) + toggle (défaut ON, décision de projet du 2026-06-24).
    private const val KEY_PROVENANCE_SEED_BLOB = "provenance_seed_blob_b64"
    private const val KEY_PROVENANCE_ENABLED = "provenance_enabled"

    // Legacy report scheme: the report master seed, PIN-sealed. A device
    // enrolled under the chained scheme never has it. Its presence is what
    // tells that the migration has not finished; the migration deletes it last.
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
        ).also {
            forgetRetiredKeys(it)
            cachedPrefs = it
        }
    }

    /**
     * Erases what an earlier version stored and no version reads any more. It
     * runs once per process, on the first access, before anything reads the
     * prefs: today that is the invitation code ([KEY_RETIRED_INVITE_CODE]),
     * which named the organisation behind the witness. `commit()`, so the file
     * no longer holds it when this returns; if the write fails, the key is
     * still there and the next process tries again.
     */
    internal fun forgetRetiredKeys(prefs: SharedPreferences) {
        if (prefs.contains(KEY_RETIRED_INVITE_CODE)) {
            prefs.edit().remove(KEY_RETIRED_INVITE_CODE).commit()
        }
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
    // Le toggle est ON par défaut (décision de projet du 2026-06-24) alors que l'app
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

    // Legacy report master (migration only). Never written any more: a device
    // enrolled now gets its report state from Rust at enrollment.

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
            // Legacy session → report mappings and index counter: user data.
            .remove(KEY_SESSION_REPORTS)
            .remove(KEY_NEXT_REPORT_INDEX)
            // Report alerts (counts and dates, not secret but still user data
            // tied to this identity).
            .remove(KEY_REPORT_ALERTS)
            // §10.11 — provenance signing seed (PIN-sealed) + opt-in toggle. The
            // seed is key material tied to this identity → must go on panic wipe.
            .remove(KEY_PROVENANCE_SEED_BLOB)
            .remove(KEY_PROVENANCE_ENABLED)
            .remove(KEY_PROVENANCE_TIMESTAMP_ENABLED)
            // Legacy report master (key material) if the migration never ran.
            .remove(KEY_REPORT_MASTER_BLOB)
            // Erased at the first access already; listed so the wipe does not
            // depend on that having succeeded.
            .remove(KEY_RETIRED_INVITE_CODE)
            .commit()
    }

    // -- Config diverse (inchangée) --

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

    // -- Legacy report bookkeeping (migration only) --
    //
    // Before the chained report scheme, each recording session got a legacy
    // index `n` from a counter here, and a {sessionId → n} mapping kept the
    // pending blobs of a session addressed to its report. The migration reads
    // both to sign the blobs still pending with the right legacy key, then
    // deletes them (clearLegacyReportState). Nothing else reads or writes them
    // any more, and nothing may allocate a legacy index once the migration has
    // written the report state: legacy indices live below the state's first
    // index, and the rescue enumerates them there only.
    //
    // Stored JSON shape: { "<sessionId>": {"r": "<reportId>", "n": <retries>,
    // "i": <index>}, ... }; only "i" is still read (-1 or absent = no usable
    // index, as written by builds from before relay-blind reports).
    //
    // Writes are `.commit()`: the migration relies on an allocation being
    // durable before it signs anything with it.

    /** Guards the read-modify-write of session_reports. */
    private val sessionReportsLock = Any()

    /** {sessionId → legacy index}; sessions with no usable index are absent. */
    fun getLegacySessionIndices(context: Context): Map<String, Int> {
        synchronized(sessionReportsLock) {
            return readSessionReportsLocked(context)
                .mapNotNull { (sid, i) -> if (i >= 0) sid to i else null }
                .toMap()
        }
    }

    /** The legacy index counter (the next index the old scheme would have used). */
    fun getNextLegacyReportIndex(context: Context): Int =
        getPrefs(context).getInt(KEY_NEXT_REPORT_INDEX, 0)

    /**
     * Migration only: the legacy index of [sessionId], allocating the next one
     * if the session has none (an orphan whose mapping was lost, or one from a
     * build that predates indices). Idempotent per session.
     *
     * The counter is committed BEFORE the mapping, and the two writes must not
     * be merged: a crash between them only skips an index (the rescue tolerates
     * gaps), while the other order could hand one index to two sessions, gluing
     * two recordings under one report.
     */
    fun ensureLegacyIndexForSession(context: Context, sessionId: String): Int {
        synchronized(sessionReportsLock) {
            val map = readSessionReportsLocked(context).toMutableMap()
            map[sessionId]?.let { if (it >= 0) return it }
            val prefs = getPrefs(context)
            val n = prefs.getInt(KEY_NEXT_REPORT_INDEX, 0)
            if (!prefs.edit().putInt(KEY_NEXT_REPORT_INDEX, n + 1).commit()) {
                throw java.io.IOException("legacy index counter not persisted")
            }
            map[sessionId] = n
            val obj = org.json.JSONObject()
            for ((sid, i) in map) {
                obj.put(sid, org.json.JSONObject().put("i", i))
            }
            if (!prefs.edit().putString(KEY_SESSION_REPORTS, obj.toString()).commit()) {
                throw java.io.IOException("legacy session mapping not persisted")
            }
            return n
        }
    }

    /**
     * The migration's last step: delete the legacy master and bookkeeping.
     * Returns whether the deletion reached the disk.
     */
    fun clearLegacyReportState(context: Context): Boolean {
        synchronized(sessionReportsLock) {
            return getPrefs(context).edit()
                .remove(KEY_REPORT_MASTER_BLOB)
                .remove(KEY_SESSION_REPORTS)
                .remove(KEY_NEXT_REPORT_INDEX)
                .commit()
        }
    }

    private fun readSessionReportsLocked(context: Context): Map<String, Int> {
        val raw = getPrefs(context).getString(KEY_SESSION_REPORTS, null) ?: return emptyMap()
        return try {
            val obj = org.json.JSONObject(raw)
            val out = mutableMapOf<String, Int>()
            val keys = obj.keys()
            while (keys.hasNext()) {
                val sid = keys.next()
                out[sid] = obj.getJSONObject(sid).optInt("i", -1)
            }
            out
        } catch (e: Exception) {
            emptyMap()
        }
    }

    // -- Auto-upload toggle --
    //
    // Default ON. When OFF, OrphanSweepWorker re-schedules nothing: envelopes
    // already scheduled still go, the others wait in the queue (nothing is
    // deleted) until the toggle is back on or a recording schedules them.

    fun isAutoUploadOrphansEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_AUTO_UPLOAD_ORPHANS, true)

    fun setAutoUploadOrphansEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_AUTO_UPLOAD_ORPHANS, enabled).apply()
    }

    // -- Report alerts: in-app only, never a system notification --
    //
    // See org.stream.crypto.upload.ReportAlerts for what each alert means and
    // why it never becomes a notification. Stored encrypted, merged per reason.
    // The key keeps its historical name so that the deletion events of older
    // builds (reasons "expired" and "unrecoverable") are still shown.

    private const val KEY_REPORT_ALERTS = "orphan_deletions_v1"

    /** Guards the read-modify-write of the alerts. */
    private val reportAlertsLock = Any()

    fun addReportAlert(context: Context, count: Int, oldestMs: Long, reason: String) {
        if (count <= 0) return
        synchronized(reportAlertsLock) {
            val merged = ReportAlerts.merge(
                readReportAlertsLocked(context), count, oldestMs, reason, System.currentTimeMillis()
            )
            writeReportAlerts(context, merged)
        }
    }

    fun getReportAlerts(context: Context): List<ReportAlerts.Alert> {
        synchronized(reportAlertsLock) { return readReportAlertsLocked(context) }
    }

    fun clearReportAlerts(context: Context) {
        synchronized(reportAlertsLock) {
            getPrefs(context).edit().remove(KEY_REPORT_ALERTS).commit()
        }
    }

    private fun readReportAlertsLocked(context: Context): List<ReportAlerts.Alert> {
        val raw = getPrefs(context).getString(KEY_REPORT_ALERTS, null) ?: return emptyList()
        return try {
            val arr = org.json.JSONArray(raw)
            val out = ArrayList<ReportAlerts.Alert>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                out.add(
                    ReportAlerts.Alert(
                        count = o.getInt("c"),
                        oldestMs = o.optLong("o", 0L),
                        reason = o.optString("r", ReportAlerts.Reason.EXPIRED),
                        recordedAtMs = o.optLong("t", 0L),
                    )
                )
            }
            out
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun writeReportAlerts(context: Context, alerts: List<ReportAlerts.Alert>) {
        val arr = org.json.JSONArray()
        for (a in alerts) {
            val o = org.json.JSONObject()
            o.put("c", a.count)
            o.put("o", a.oldestMs)
            o.put("r", a.reason)
            o.put("t", a.recordedAtMs)
            arr.put(o)
        }
        getPrefs(context).edit().putString(KEY_REPORT_ALERTS, arr.toString()).commit()
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
