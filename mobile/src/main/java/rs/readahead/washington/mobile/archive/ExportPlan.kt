package rs.readahead.washington.mobile.archive

/**
 * What an export of one report writes, and under which names.
 *
 * Two exports, never mixed in one folder:
 * - [plan], the nominal one: the VERIFIED objects only. Anything excluded by
 *   the verification never leaves the app. The timestamp proof and its salt
 *   are added only when the proof matched the commitment recomputed from the
 *   verified chunks: exporting a proof that does not match would hand a third
 *   party a "proof" of nothing.
 * - [planUnverifiable]: the legacy objects kept apart as not verifiable (see
 *   [ObjectPlacement]), in a folder of their own, every name carrying
 *   [RescueNames.UNVERIFIED_LABEL]. Recordings only (session metadata and video
 *   chunks): no timestamp proof, since none was checked against them here.
 *
 * The names are neutral (see [RescueNames]): no `report_id`, no session id,
 * nothing that points back to the relay.
 */
object ExportPlan {

    enum class Kind { VIDEO, METADATA, OTS_PROOF, OTS_SALT }

    /**
     * One file to write. [sourceName] is the relay object name the content
     * comes from (null for the salt, which is derived from the phrase).
     */
    data class Item(val kind: Kind, val sourceName: String?, val targetName: String, val mimeType: String)

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
    private const val MIME_MP4 = "video/mp4"
    private const val MIME_BINARY = "application/octet-stream"
}
