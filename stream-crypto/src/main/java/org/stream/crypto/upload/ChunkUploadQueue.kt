package org.stream.crypto.upload

import android.content.Context
import java.io.File

/**
 * The upload queue of builds from before the queue envelopes:
 * `filesDir/stream_chunk_queue/`, one `.strm` blob per pending object, named
 * `<sessionId>_<seq6>.strm`, unsigned (the old upload path signed at send
 * time, with a key the device no longer keeps).
 *
 * Nothing adds to it any more. What is left in it is read once by the
 * migration ([LegacyReportMigration]), which signs each blob with the legacy
 * key of its report and turns it into an envelope of [EnvelopeQueue], and
 * cleared by the emergency wipe. Only the directory survives here: the live
 * queue, and its durability test (`EnvelopeQueueDurabilityTest`), is
 * [EnvelopeQueue].
 */
class ChunkUploadQueue(context: Context) {

    val queueDir: File = File(context.filesDir, DIR_NAME).also { it.mkdirs() }

    companion object {
        const val DIR_NAME = "stream_chunk_queue"
    }
}
