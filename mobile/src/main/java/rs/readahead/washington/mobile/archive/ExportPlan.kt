package rs.readahead.washington.mobile.archive

/**
 * What an export of one report writes, and under which names.
 *
 * Two exports, never mixed in one folder:
 * - [planJoined], the nominal one: the VERIFIED objects only. Anything
 *   excluded by the verification never leaves the app. The chunks are joined
 *   into videos ([JoinPlanner]); on request, the chunks themselves also go,
 *   as recorded, to a subfolder ([RescueNames.EXPORT_RAW_FOLDER_NAME]). The
 *   timestamp proof and its salt go only to that subfolder, and only when the
 *   proof matched the commitment recomputed from the verified chunks: the
 *   proof commits to the chunks as recorded, which a joined video is not, and
 *   exporting a proof that does not match would hand a third party a "proof"
 *   of nothing.
 * - [planUnverifiable]: the legacy objects kept apart as not verifiable (see
 *   [ObjectPlacement]), in a folder of their own, every name carrying
 *   [RescueNames.UNVERIFIED_LABEL]. Recordings only (session metadata and video
 *   chunks, as recorded): no timestamp proof, since none was checked against
 *   them here.
 *
 * The names are neutral (see [RescueNames]): no `report_id`, no session id,
 * nothing that points back to the relay.
 */
object ExportPlan {

    enum class Kind { VIDEO, METADATA, OTS_PROOF, OTS_SALT }

    /**
     * One file to write. [sourceName] is the relay object name the content
     * comes from (null for the timestamp proof, kept apart from the objects,
     * and for the salt, which is derived from the phrase). [inRawFolder]: the
     * file goes to the raw chunks' subfolder rather than to the report's
     * folder.
     */
    data class Item(
        val kind: Kind,
        val sourceName: String?,
        val targetName: String,
        val mimeType: String,
        val inRawFolder: Boolean = false,
    )

    /**
     * One chunk of the nominal export, in reading order. [seq] decides
     * whether it joins the previous chunk ([JoinPlanner]); [raw] is its copy
     * as recorded, in the raw chunks' subfolder, when the witness asked for
     * the raw chunks.
     */
    data class Chunk(val seq: Int, val sourceName: String, val raw: Item?)

    /**
     * The nominal export of a report: [metadata] in the report's folder, the
     * [chunks] joined into videos named after [ordinal], and the [timestamp]
     * proof and salt in the raw chunks' subfolder (empty unless the raw
     * chunks are exported and the proof matched). [missingSeqs] are the seqs
     * the verification found missing on the relay: they tell a jump over a
     * missing chunk from one the recorder made ([Cut.MISSING]).
     */
    data class Joined(
        val ordinal: Int,
        val metadata: Item?,
        val chunks: List<Chunk>,
        val timestamp: List<Item>,
        val missingSeqs: Set<Int>,
    ) {
        /** The steps the progress counts: one per object, one per timestamp file. */
        val size: Int get() = (if (metadata != null) 1 else 0) + chunks.size + timestamp.size
    }

    /**
     * The nominal export of the VERIFIED objects [verifiedNames] of the
     * [ordinal]-th report. With [includeRaw], each chunk is also exported as
     * recorded, under the names [plan] gives, and the timestamp proof and its
     * salt with them when [otsMatched]. Without it, neither the proof nor the
     * salt is exported: they commit to the chunks as recorded, and nothing in
     * the export could be checked against them. [missingSeqs] comes from the
     * same verdict as [verifiedNames].
     */
    fun planJoined(
        verifiedNames: List<String>,
        missingSeqs: Set<Int>,
        otsMatched: Boolean,
        includeRaw: Boolean,
        ordinal: Int,
    ): Joined {
        val nominal = plan(verifiedNames, otsMatched && includeRaw)
        val chunks = nominal.filter { it.kind == Kind.VIDEO }.map { item ->
            val name = checkNotNull(item.sourceName)
            Chunk(
                seq = checkNotNull(RescueNames.parseSeq(name)),
                sourceName = name,
                raw = if (includeRaw) item.copy(inRawFolder = true) else null,
            )
        }
        return Joined(
            ordinal = ordinal,
            metadata = nominal.firstOrNull { it.kind == Kind.METADATA },
            chunks = chunks,
            timestamp = nominal
                .filter { it.kind == Kind.OTS_PROOF || it.kind == Kind.OTS_SALT }
                .map { it.copy(inRawFolder = true) },
            missingSeqs = missingSeqs,
        )
    }

    /**
     * The verified objects as recorded, under neutral names: the metadata,
     * then the chunks in reading order numbered from 1, then the timestamp
     * proof and its salt when [otsMatched]. [planJoined] takes the names of
     * the raw chunks' subfolder from here.
     */
    fun plan(verifiedNames: List<String>, otsMatched: Boolean): List<Item> {
        val items = ArrayList<Item>()
        RescueNames.metadataName(verifiedNames)?.let {
            items.add(Item(Kind.METADATA, it, RescueNames.EXPORT_METADATA_NAME, MIME_JSON))
        }
        RescueNames.playbackOrder(verifiedNames).forEachIndexed { i, name ->
            items.add(Item(Kind.VIDEO, name, RescueNames.exportVideoName(i + 1), MIME_MP4))
        }
        if (otsMatched) {
            items.add(Item(Kind.OTS_PROOF, null, RescueNames.EXPORT_OTS_NAME, MIME_BINARY))
            // Not text/plain: a provider may append ".txt" to the name.
            items.add(Item(Kind.OTS_SALT, null, RescueNames.EXPORT_OTS_SALT_NAME, MIME_BINARY))
        }
        return items
    }

    /** The export of the objects kept apart as not verifiable. */
    fun planUnverifiable(unverifiableNames: List<String>): List<Item> {
        val items = ArrayList<Item>()
        RescueNames.metadataName(unverifiableNames)?.let {
            items.add(Item(Kind.METADATA, it, RescueNames.EXPORT_UNVERIFIED_METADATA_NAME, MIME_JSON))
        }
        RescueNames.playbackOrder(unverifiableNames).forEachIndexed { i, name ->
            items.add(Item(Kind.VIDEO, name, RescueNames.exportUnverifiedVideoName(i + 1), MIME_MP4))
        }
        return items
    }

    private const val MIME_JSON = "application/json"
    /** The type of every exported video, joined or as recorded. */
    const val MIME_MP4 = "video/mp4"
    private const val MIME_BINARY = "application/octet-stream"
}
