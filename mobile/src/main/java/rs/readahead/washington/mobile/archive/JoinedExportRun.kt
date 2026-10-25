package rs.readahead.washington.mobile.archive

import java.io.File
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException

/**
 * The loop of the nominal export ([ExportPlan.planJoined]): the verified
 * chunks joined into videos without re-encoding, the session metadata, and
 * on request the chunks as recorded with the timestamp proof and its salt.
 * Kept apart from Android and from the FFI, which are passed in, so the rule
 * is testable on a plain JVM; [Mp4ChunkMedia] is the Android side of [Media].
 *
 * One pass. Each chunk, in reading order, is decrypted to a private file,
 * copied as recorded to the raw chunks' subfolder when the plan asks for it,
 * read ([Media.probe]) and placed by [JoinPlanner]: appended to the open
 * video, or the open video is closed and a new one starts with it. The open
 * video is written to a private file of its own and reaches the destination
 * only once it is closed, so its name is known by then: `prise-NN.mp4` when
 * the whole report is one video, `prise-NN-partie-MM.mp4` otherwise. A chunk
 * that cannot be read for a join, or whose codec this phone's muxer does not
 * write, is never dropped: it is a video of its own, copied as recorded.
 *
 * The open video holds a plaintext copy of the chunks joined so far, next to
 * their encrypted copies. [JoinPlanner] bounds it: it closes the video
 * before it grows past [JoinPlanner.MAX_PART_BYTES] or past what the free
 * space ([freeSpace]) leaves room to copy out.
 *
 * The rules of [ExportRun] hold here too. An object that does not decrypt is
 * excluded and counted, and the rest of the report is exported; an excluded
 * chunk also ends the open video, since a joined video never hides a gap.
 * Every private plaintext file, the chunk's and the open video's, is
 * secure-deleted once copied and in every outcome, the private chunk after
 * each object. Anything else stops the export and is rethrown, for the
 * caller to remove the folder: a write to the destination or to the private
 * video, a copy shorter than its private file, a cancellation, any error
 * that does not say the object itself does not decrypt. Cancellation is
 * checked again after every chunk and every copy, so one seen while a file
 * was being written still removes the folder.
 *
 * The timestamp proof and its salt are written last, in the raw chunks'
 * subfolder, and left out once a chunk is excluded, as in [ExportRun]: they
 * commit to every verified chunk, and the subfolder no longer holds them all.
 *
 * @param decrypt decrypts the STRM file `sealed` to `plain`.
 * @param secureDelete overwrites then unlinks a private plaintext file; a
 *   no-op on a missing file.
 * @param media reads chunks and writes the joined videos.
 * @param destination where the files go.
 * @param sdkInt the Android version of this phone (`Build.VERSION.SDK_INT`),
 *   which decides the codecs [media]'s muxer writes ([JoinPlanner.muxerWrites]).
 * @param freeSpace the free space, in bytes, on the storage that holds the
 *   given private file; 0 when it cannot be told, which joins nothing.
 */
internal class JoinedExportRun<D, V>(
    private val decrypt: (sealed: File, plain: File) -> Unit,
    private val secureDelete: (File) -> Unit,
    private val media: Media<V>,
    private val destination: Destination<D>,
    private val sdkInt: Int,
    // usableSpace leaves out cached data the system could clear, so it can
    // only under-state the room: the planner then cuts sooner, never later.
    @Suppress("UsableSpace")
    private val freeSpace: (File) -> Long = { it.absoluteFile.parentFile?.usableSpace ?: 0L },
    private val undecryptable: (Throwable) -> Boolean = RescueFailures::isUndecryptable,
) {

    /** Reads chunks and writes a joined video, of handle type [V]. */
    interface Media<V> {
        /** What the decrypted chunk [chunk] holds. Never throws for a file
         *  it cannot read: that is [ChunkProbe.UNREADABLE]. */
        fun probe(chunk: File): ChunkProbe

        /** Start a video in the private file [file], with the tracks of
         *  [first], the chunk it starts with. */
        fun open(file: File, first: ChunkProbe): V

        /** Append every sample of the decrypted chunk [chunk] to [video],
         *  shifted by [offsetUs]. */
        fun append(video: V, chunk: File, offsetUs: Long)

        /** Finish [video] so its file is complete, and release it; it is
         *  released even when finishing throws. */
        fun finish(video: V)

        /** Release [video] after a failure; never throws. */
        fun abandon(video: V)
    }

    /** Where the files go: in the app, documents of the folder the witness
     *  picked. [create] places an item in the raw chunks' subfolder when the
     *  item says so ([ExportPlan.Item.inRawFolder]). */
    interface Destination<D> : ExportRun.Destination<D> {
        /** Create the joined video [name] in the report's folder. */
        fun createVideo(name: String): D
    }

    /** The video being written: its [handle], null for a chunk copied as
     *  recorded, whose private file is the video itself. */
    private class OpenVideo<V>(val number: Int, val handle: V?)

    /**
     * Write [plan]. Each object comes from [sources] (relay object name →
     * local encrypted file) and is decrypted to [chunkPlain]; the open video
     * is written to [videoPlain]. Both are private files.
     *
     * @param onItem `(done, total)` after each step of [ExportPlan.Joined.size],
     *   written or excluded.
     */
    fun run(
        plan: ExportPlan.Joined,
        sources: Map<String, File>,
        chunkPlain: File,
        videoPlain: File,
        isActive: () -> Boolean,
        onItem: (done: Int, total: Int) -> Unit,
    ): ExportOutcome {
        val total = plan.size
        val planner = JoinPlanner(sdkInt, plan.missingSeqs)
        var done = 0
        var written = 0
        var excluded = 0
        var chunkExcluded = false
        var videosWritten = 0
        var open: OpenVideo<V>? = null

        /** Close the open video and copy it out. [more]: another video
         *  follows, so even the first one is a numbered part. */
        fun closeVideo(more: Boolean) {
            val video = open ?: return
            open = null
            video.handle?.let { media.finish(it) }
            val name = RescueNames.exportJoinedVideoName(
                plan.ordinal,
                if (video.number == 1 && !more) null else video.number,
                maxParts = plan.chunks.size,
            )
            copyOut(videoPlain, destination.createVideo(name), isActive)
            secureDelete(videoPlain)
            written++
            videosWritten++
        }

        try {
            plan.metadata?.let { item ->
                checkActive(isActive)
                try {
                    if (decrypts(source(sources, item.sourceName), chunkPlain)) {
                        copyOut(chunkPlain, destination.create(item), isActive)
                        written++
                    } else {
                        excluded++
                    }
                } finally {
                    secureDelete(chunkPlain)
                }
                onItem(++done, total)
            }
            for (chunk in plan.chunks) {
                checkActive(isActive)
                try {
                    if (!decrypts(source(sources, chunk.sourceName), chunkPlain)) {
                        excluded++
                        chunkExcluded = true
                        planner.excluded(chunk.seq)
                    } else {
                        chunk.raw?.let {
                            copyOut(chunkPlain, destination.create(it), isActive)
                            written++
                        }
                        val probe = media.probe(chunkPlain)
                        val placement = planner.place(chunk.seq, probe, chunkPlain.length(), freeSpace(videoPlain))
                        when (placement) {
                            is JoinPlacement.Join -> {
                                val handle = checkNotNull(open?.handle) { "no video to join" }
                                media.append(handle, chunkPlain, placement.offsetUs)
                            }
                            is JoinPlacement.NewVideo -> {
                                closeVideo(more = true)
                                val handle = media.open(videoPlain, probe)
                                open = OpenVideo(planner.videos, handle)
                                media.append(handle, chunkPlain, 0L)
                            }
                            is JoinPlacement.AsRecorded -> {
                                closeVideo(more = true)
                                if (!chunkPlain.renameTo(videoPlain)) throw IOException("private video not writable")
                                open = OpenVideo(planner.videos, null)
                            }
                        }
                        // A close or an emergency wipe erases the private
                        // copy in place while it is being read: a chunk read
                        // into one is not trusted.
                        checkActive(isActive)
                    }
                } finally {
                    secureDelete(chunkPlain)
                }
                onItem(++done, total)
            }
            closeVideo(more = false)

            var timestampLeftOut = false
            for (item in plan.timestamp) {
                checkActive(isActive)
                if (chunkExcluded) {
                    timestampLeftOut = true
                } else {
                    destination.writeTimestamp(item, destination.create(item))
                    checkActive(isActive)
                    written++
                }
                onItem(++done, total)
            }
            return ExportOutcome(
                written = written,
                undecryptable = excluded,
                timestampLeftOut = timestampLeftOut,
                videos = videosWritten,
                cuts = planner.cuts,
            )
        } finally {
            open?.handle?.let { media.abandon(it) }
            secureDelete(videoPlain)
            secureDelete(chunkPlain)
        }
    }

    private fun source(sources: Map<String, File>, name: String?): File =
        name?.let { sources[it] } ?: throw IOException("object to export missing")

    /** Copy the private [plain] into [target], whole, and check that the
     *  export is still wanted. */
    private fun copyOut(plain: File, target: D, isActive: () -> Boolean) {
        val expected = plain.length()
        if (destination.copy(plain, target) != expected) throw IOException("export copy incomplete")
        checkActive(isActive)
    }

    private fun checkActive(isActive: () -> Boolean) {
        if (!isActive()) throw CancellationException("export cancelled")
    }

    /** True when [sealed] decrypted to [plain], false when it does not
     *  decrypt; any other failure is rethrown. */
    private fun decrypts(sealed: File, plain: File): Boolean = try {
        decrypt(sealed, plain)
        true
    } catch (e: Exception) {
        if (!undecryptable(e)) throw e
        false
    }
}
