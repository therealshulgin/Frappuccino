package rs.readahead.washington.mobile.service

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.SecureWipe
import org.stream.crypto.upload.ArchiveSession
import rs.readahead.washington.mobile.archive.ArchiveLocalData
import rs.readahead.washington.mobile.archive.ExportOutcome
import rs.readahead.washington.mobile.archive.ExportPlan
import rs.readahead.washington.mobile.archive.ExportRun
import rs.readahead.washington.mobile.archive.ObjectPlacement
import rs.readahead.washington.mobile.archive.RescueCallRunner
import rs.readahead.washington.mobile.archive.ReportDir
import rs.readahead.washington.mobile.archive.RescueNames
import rs.readahead.washington.mobile.archive.RescueSession
import rs.readahead.washington.mobile.archive.TimestampCheck
import timber.log.Timber
import uniffi.frappuccino.ObjectStatus
import uniffi.frappuccino.OtsStatus
import uniffi.frappuccino.ReportCheck
import uniffi.frappuccino.ReportScheme
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import uniffi.frappuccino.ProvenanceSigner as FfiProvenanceSigner

/**
 * The rescue's work on one report, without any UI: fetch and verify every
 * stored object, check the timestamp proof, and export what verified (or, on
 * an explicit request, what was kept apart as not verifiable).
 *
 * A plain [Context] must stay enough: progress goes out through callbacks and
 * [RescueSession], never through a View or an Activity resource, so the class
 * keeps running inside [ArchiveDownloadService], the foreground service that
 * survives screen-off and backgrounding.
 *
 * The order is fixed by the verification and is not a matter of taste: the
 * closure is checked before any object of a chained report (Rust refuses the
 * objects otherwise), and each object is classified by Rust as it lands, then
 * placed by [ObjectPlacement]. Whatever is excluded is deleted by Rust and only
 * counted.
 *
 * A legacy object the relay stored before it kept signatures (UNVERIFIABLE) is
 * neither excluded nor verified: it is kept apart, in its own directory, as the
 * desktop CLI does. Nothing proves it is the witness's, yet it may be the
 * only copy left of a recording made before this version, so it stays readable
 * in the internal player and exportable, both from a separate section under a
 * "not verified" label. It never enters the verified testimony: not the
 * verified count, not its playback, not the nominal export, not the timestamp
 * check.
 */
class ArchiveDownloader(context: Context) {

    private val appContext: Context = context.applicationContext

    /**
     * Fetch and verify every object of [entry] into a fresh local directory.
     * On success the entry is VERIFIED with its verdict; on a failure the
     * partial directory is purged and the error is rethrown.
     *
     * @param onObject `(done, total)` after each object.
     */
    suspend fun verifyReport(
        entry: RescueSession.Entry,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        provenanceSigner: FfiProvenanceSigner?,
        directory: ReportCheck?,
        runner: RescueCallRunner,
        isActive: () -> Boolean,
        onObject: (done: Int, total: Int) -> Unit,
    ) {
        val check = entry.check
        val dir = ArchiveLocalData.newReportDir(appContext)
        entry.dir = dir
        entry.verifiedFiles = emptyMap()
        entry.unverifiableFiles = emptyMap()
        entry.otsProof = null
        entry.fetched = 0
        try {
            if (check.hasClosure()) {
                val scratch = File(dir.incoming, "closure.bin")
                runner.run { check.verifyClosure(scratch.path) }
            }
            val names = check.objectNames()
            val placed = ObjectPlacement.placeAll(
                names, dir,
                fetch = { name, landing -> runner.run { check.fetchObject(name, landing.path) } },
                isActive = isActive,
            ) { done ->
                entry.fetched = done
                onObject(done, names.size)
            }
            entry.verifiedFiles = placed.verified
            entry.unverifiableFiles = placed.unverifiable
            val verdict = check.verdict()
            entry.verdict = verdict
            entry.ots = when (entry.scheme) {
                ReportScheme.CHAIN -> chainTimestamp(entry, session, identity, provenanceSigner, directory, runner, dir)
                ReportScheme.LEGACY -> legacyTimestamp(entry, session, identity, provenanceSigner, dir)
                ReportScheme.DIRECTORY -> null
            }
            entry.state = RescueSession.EntryState.VERIFIED
        } catch (e: Throwable) {
            entry.verifiedFiles = emptyMap()
            entry.unverifiableFiles = emptyMap()
            entry.otsProof = null
            entry.dir = null
            ArchiveLocalData.purgeDir(dir)
            throw e
        }
    }

    /**
     * The timestamp proof of a chained report: fetched from the directory
     * (where it is stored under the report's proof name), verified like any
     * object, decrypted, then compared ([TimestampCheck]). A proof the
     * directory does not hold is ABSENT; one that does not verify, or that
     * verifies but does not decrypt, is a MISMATCH, as in the CLI. Null when
     * the provenance signer could not be derived: the check was not made,
     * and the screen shows nothing rather than a verdict.
     */
    private suspend fun chainTimestamp(
        entry: RescueSession.Entry,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        signer: FfiProvenanceSigner?,
        directory: ReportCheck?,
        runner: RescueCallRunner,
        dir: ReportDir,
    ): OtsStatus? {
        val otsName = entry.check.otsName() ?: return OtsStatus.ABSENT
        if (directory == null || otsName !in directory.objectNames()) return OtsStatus.ABSENT
        if (signer == null) return null
        val sealed = File(dir.incoming, "ots.bin")
        val status = runner.run { directory.fetchObject(otsName, sealed.path) }
        if (status != ObjectStatus.VERIFIED) {
            sealed.delete()
            return OtsStatus.MISMATCH
        }
        val outcome = timestampCheck(session, identity, signer).checkSealed(
            sealed, File(dir.plain, "ots.proof"), verifiedMetadata(entry), entry.playableFiles(), dir.plain,
        )
        return keep(entry, outcome)
    }

    /**
     * The timestamp proof of a legacy report: a `<sessionId>.ots` object of
     * the report itself, stored as is (not encrypted). Only a VERIFIED one is
     * considered (signed at the migration); a legacy proof stored without a
     * signature is as unverifiable as the recordings of its time. Null when
     * the report holds no verified proof.
     */
    private fun legacyTimestamp(
        entry: RescueSession.Entry,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        signer: FfiProvenanceSigner?,
        dir: ReportDir,
    ): OtsStatus? {
        val names = entry.verdict?.verifiedNames ?: return null
        val name = names.firstOrNull { it.endsWith(".ots") } ?: return null
        val proof = entry.verifiedFiles[name] ?: return null
        if (signer == null) return null
        val outcome = timestampCheck(session, identity, signer).checkStored(
            proof, verifiedMetadata(entry), entry.playableFiles(), dir.plain,
        )
        return keep(entry, outcome)
    }

    /** The VERIFIED metadata object (seq 0) of [entry], still encrypted. */
    private fun verifiedMetadata(entry: RescueSession.Entry): File? {
        val names = entry.verdict?.verifiedNames ?: return null
        val metadataName = RescueNames.metadataName(names) ?: return null
        return entry.verifiedFiles[metadataName]
    }

    /** On MATCH, keep the proof and the recording id its salt is derived
     *  from, for the export. */
    private fun keep(entry: RescueSession.Entry, outcome: TimestampCheck.Outcome): OtsStatus {
        if (outcome.status == OtsStatus.MATCH) {
            entry.otsProof = outcome.proof
            entry.recordingId = outcome.recordingId
        }
        return outcome.status
    }

    private fun timestampCheck(
        session: ArchiveSession,
        identity: ArchiveIdentity,
        signer: FfiProvenanceSigner,
    ) = TimestampCheck(
        decrypt = { input, output -> session.decryptToFile(input, output, identity) },
        hashPlaintext = { input, scratch -> session.plaintextHash(input, scratch, identity) },
        commitment = { hashes, recordingId -> uniffi.frappuccino.provenanceOtsCommitment(hashes, recordingId, signer) },
        proofStatus = { proof, commitment -> uniffi.frappuccino.otsProofStatus(proof.path, commitment) },
        secureDelete = { ArchiveSession.secureDelete(it) },
        wipe = { SecureWipe.wipe(it) },
    )

    /**
     * Export the VERIFIED content of [entry] to a folder created in the tree
     * the witness picked. Each object is decrypted to a private file, copied,
     * and the private file secure-deleted before the next one; nothing is
     * decrypted straight into the destination, which the app cannot erase
     * if the copy is interrupted. An object that does not decrypt is excluded
     * and counted, and the rest is exported ([ExportRun]). A failed or
     * cancelled export removes the folder it created, as far as the
     * destination's provider allows, and so does one in which no object
     * decrypted.
     *
     * @param onItem `(done, total)` after each planned file.
     */
    fun exportReport(
        entry: RescueSession.Entry,
        treeUri: Uri,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        provenanceSigner: FfiProvenanceSigner?,
        isActive: () -> Boolean,
        onItem: (done: Int, total: Int) -> Unit,
    ): ExportOutcome {
        val verdict = entry.verdict ?: throw IOException("report not verified")
        val dir = entry.dir ?: throw IOException("report not verified")
        val plan = ExportPlan.plan(verdict.verifiedNames, entry.otsProof != null && entry.recordingId != null)
        return exportItems(
            entry, plan, entry.verifiedFiles, RescueNames.exportFolderName(entry.ordinal), dir, treeUri,
            session, identity, provenanceSigner, isActive, onItem,
        )
    }

    /**
     * Export the objects of [entry] kept apart as not verifiable, to a folder
     * of their own whose name, like every file in it, carries
     * [RescueNames.UNVERIFIED_LABEL]. Same handling as [exportReport]: private
     * decryption, copy, secure deletion, exclusion of what does not decrypt,
     * removal of a partial folder. Never writes into the verified export's
     * folder, and never adds a verified object to this one.
     */
    fun exportUnverifiable(
        entry: RescueSession.Entry,
        treeUri: Uri,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        isActive: () -> Boolean,
        onItem: (done: Int, total: Int) -> Unit,
    ): ExportOutcome {
        val verdict = entry.verdict ?: throw IOException("report not verified")
        val dir = entry.dir ?: throw IOException("report not verified")
        val plan = ExportPlan.planUnverifiable(verdict.unverifiableNames)
        if (plan.isEmpty()) throw IOException("nothing kept apart to export")
        return exportItems(
            entry, plan, entry.unverifiableFiles, RescueNames.exportUnverifiedFolderName(entry.ordinal), dir,
            treeUri, session, identity, provenanceSigner = null, isActive = isActive, onItem = onItem,
        )
    }

    /** Write [plan] into a new folder [folderName] of [treeUri], each object
     *  read from [sources] (relay name → local encrypted file). The proof and
     *  salt items come from [entry] and only [ExportPlan.plan] lists them. */
    private fun exportItems(
        entry: RescueSession.Entry,
        plan: List<ExportPlan.Item>,
        sources: Map<String, File>,
        folderName: String,
        dir: ReportDir,
        treeUri: Uri,
        session: ArchiveSession,
        identity: ArchiveIdentity,
        provenanceSigner: FfiProvenanceSigner?,
        isActive: () -> Boolean,
        onItem: (done: Int, total: Int) -> Unit,
    ): ExportOutcome {
        val resolver = appContext.contentResolver
        val parent = DocumentsContract.buildDocumentUriUsingTree(
            treeUri, DocumentsContract.getTreeDocumentId(treeUri),
        )
        val folder = DocumentsContract.createDocument(
            resolver, parent, DocumentsContract.Document.MIME_TYPE_DIR, folderName,
        ) ?: throw IOException("cannot create the export folder")
        val destination = object : ExportRun.Destination<Uri> {
            override fun create(item: ExportPlan.Item): Uri =
                DocumentsContract.createDocument(resolver, folder, item.mimeType, item.targetName)
                    ?: throw IOException("cannot create an export file")

            override fun copy(plain: File, target: Uri): Long = copyFile(resolver, plain, target)

            override fun writeTimestamp(item: ExportPlan.Item, target: Uri) {
                when (item.kind) {
                    ExportPlan.Kind.OTS_PROOF -> {
                        val proof = entry.otsProof ?: throw IOException("timestamp proof missing")
                        copyFile(resolver, proof, target)
                    }
                    ExportPlan.Kind.OTS_SALT -> {
                        val signer = provenanceSigner ?: throw IOException("salt not derivable")
                        val recordingId = entry.recordingId ?: throw IOException("salt not derivable")
                        writeSaltHex(resolver, signer.otsSalt(recordingId), target)
                    }
                    ExportPlan.Kind.VIDEO, ExportPlan.Kind.METADATA ->
                        throw IllegalArgumentException("not a timestamp item")
                }
            }
        }
        var keep = false
        try {
            val outcome = ExportRun(
                decrypt = { sealed, plain -> session.decryptToFile(sealed, plain, identity) },
                secureDelete = { ArchiveSession.secureDelete(it) },
                destination = destination,
            ).run(plan, sources, File(dir.plain, "export.tmp"), isActive, onItem)
            // A folder in which nothing decrypted holds nothing for anyone.
            keep = !outcome.nothingWritten
            return outcome
        } finally {
            if (!keep) {
                try {
                    DocumentsContract.deleteDocument(resolver, folder)
                } catch (e: Exception) {
                    Timber.w(e, "ArchiveDownloader: partial export not removable")
                }
            }
        }
    }

    /** Copy [source] into [target]; returns the number of bytes written. */
    private fun copyFile(resolver: ContentResolver, source: File, target: Uri): Long {
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        try {
            var total = 0L
            val out = resolver.openOutputStream(target, "w") ?: throw IOException("export destination refused")
            out.use { stream ->
                FileInputStream(source).use { input ->
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        stream.write(buffer, 0, n)
                        total += n
                    }
                }
                stream.flush()
            }
            return total
        } finally {
            SecureWipe.wipe(buffer)
        }
    }

    /** Write the salt as lowercase hex (the format `verify-provenance`
     *  reads), without going through a `String`. Wipes [salt]. */
    private fun writeSaltHex(resolver: ContentResolver, salt: ByteArray, target: Uri) {
        val hex = ByteArray(salt.size * 2)
        try {
            for ((i, b) in salt.withIndex()) {
                val v = b.toInt() and 0xFF
                hex[2 * i] = HEX_DIGITS[v ushr 4]
                hex[2 * i + 1] = HEX_DIGITS[v and 0x0F]
            }
            val out = resolver.openOutputStream(target, "w") ?: throw IOException("export destination refused")
            out.use { it.write(hex) }
        } finally {
            SecureWipe.wipe(salt)
            SecureWipe.wipe(hex)
        }
    }

    companion object {
        private const val COPY_BUFFER_BYTES = 64 * 1024
        private val HEX_DIGITS = "0123456789abcdef".toByteArray(Charsets.US_ASCII)
    }
}
