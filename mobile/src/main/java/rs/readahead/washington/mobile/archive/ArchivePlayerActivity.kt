package rs.readahead.washington.mobile.archive

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.media.MediaPlayer
import android.os.Bundle
import android.view.View
import android.widget.MediaController
import android.widget.TextView
import android.widget.VideoView
import androidx.appcompat.app.AppCompatActivity
import org.stream.crypto.ArchiveIdentity
import org.stream.crypto.upload.ArchiveSession
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.service.ArchiveDownloadService
import rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder
import timber.log.Timber
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import rs.readahead.washington.mobile.views.base_ui.refuseScreenCapture

/**
 * Internal player of the rescue: plays the chunks of one report, in seq order,
 * without ever writing a decrypted copy outside the app.
 *
 * One section per screen, chosen by the caller and never mixed: the VERIFIED
 * chunks (the testimony), or, from the separate "not verifiable" section, the
 * legacy chunks kept apart ([ObjectPlacement]). The latter play under a
 * permanent banner that says nothing proves they are the witness's.
 *
 * Plaintext exists only for a sliding window ([PlaybackWindow]): the chunk on
 * screen and a few after it, decrypted by Rust into the report's private
 * `plain/` directory. A chunk is secure-deleted as soon as playback leaves the
 * window, the whole window when the screen goes to the background, and
 * everything when it closes. The window is decrypted again on return.
 *
 * Screen capture is refused twice: FLAG_SECURE on the window, and
 * `setSecure(true)` on the VideoView's surface, set before the view is
 * attached (a SurfaceView ignores the flag once attached).
 *
 * The player is a second archive screen: it attaches to [ArchiveAuthHolder]
 * like the rescue screen, so closing it never wipes the identity from under
 * the screen below, and the last one to go purges. It listens for the
 * emergency wipe for its whole life, in the background too ([ArchiveWipeWatch]),
 * and closes when it arrives.
 */
class ArchivePlayerActivity : AppCompatActivity() {

    private lateinit var videoView: VideoView
    private lateinit var partView: TextView
    private lateinit var messageView: TextView
    private lateinit var prevBtn: TextView
    private lateinit var nextBtn: TextView

    private var chunks: List<File> = emptyList()
    private var plainDir: File? = null
    private var playback = PlaybackWindow(0)
    private var identity: ArchiveIdentity? = null
    private var session: ArchiveSession? = null

    // Decryption state, shared with the decrypt thread, guarded by [lock].
    // Its generation changes each time the window is wiped (screen hidden):
    // a decryption started before that erases its own output instead of
    // recording it, and the window is decrypted again on return even while
    // such a decryption is still running (see [PlayerDecryptions]).
    private val lock = Any()
    private val decryptions = PlayerDecryptions()
    private var decryptor: ExecutorService? = null

    /** Position inside the current chunk to resume at after a background trip. */
    private var resumeAtMs = 0
    private var attached = false
    private var visible = false

    @SuppressLint("InflateParams") // the root is attached by setContentView below
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        refuseScreenCapture()
        ArchiveWipeWatch.attach(this) { finish() }

        // Inflate, flag the surface, THEN attach: setSecure is ignored on a
        // SurfaceView already attached to its window.
        val root = layoutInflater.inflate(R.layout.activity_archive_player, null)
        videoView = root.findViewById(R.id.archivePlayerVideo)
        videoView.setSecure(true)
        setContentView(root)

        partView = root.findViewById(R.id.archivePlayerPart)
        messageView = root.findViewById(R.id.archivePlayerMessage)
        prevBtn = root.findViewById(R.id.archivePlayerPrev)
        nextBtn = root.findViewById(R.id.archivePlayerNext)
        root.findViewById<View>(R.id.archivePlayerClose).setOnClickListener { finish() }
        prevBtn.setOnClickListener {
            resumeAtMs = 0
            if (playback.back()) onPositionChanged()
        }
        nextBtn.setOnClickListener {
            resumeAtMs = 0
            if (playback.advance()) onPositionChanged()
        }

        ArchiveAuthHolder.attachActivity()
        attached = true

        val token = intent.getStringExtra(EXTRA_TOKEN)
        val entry = token?.let { RescueSession.entryByToken(it) }
        identity = ArchiveAuthHolder.getIdentity()
        session = ArchiveAuthHolder.getSession()
        val dir = entry?.dir
        if (entry == null || dir == null || identity == null || session == null) {
            finish()
            return
        }
        val unverifiable = intent.getBooleanExtra(EXTRA_UNVERIFIABLE, false)
        chunks = if (unverifiable) entry.unverifiablePlayableFiles() else entry.playableFiles()
        plainDir = dir.plain
        playback = PlaybackWindow(chunks.size, AHEAD)
        root.findViewById<View>(R.id.archivePlayerUnverifiedBanner).visibility =
            if (unverifiable) View.VISIBLE else View.GONE

        val controller = MediaController(this)
        controller.setAnchorView(videoView)
        videoView.setMediaController(controller)
        videoView.setOnCompletionListener {
            resumeAtMs = 0
            if (playback.advance()) onPositionChanged() else showMessage(getString(R.string.archive_player_end))
        }
        videoView.setOnErrorListener { _: MediaPlayer, what: Int, extra: Int ->
            Timber.w("ArchivePlayerActivity: playback error %d/%d", what, extra)
            showMessage(getString(R.string.archive_player_error))
            true
        }
        updateControls()
        if (chunks.isEmpty()) {
            showMessage(getString(if (unverifiable) R.string.archive_play_none_unverifiable else R.string.archive_play_none))
        }
    }

    override fun onStart() {
        super.onStart()
        // A second guard behind the wipe watch: once the secrets are gone
        // (emergency wipe), nothing here can be decrypted any more.
        if (!ArchiveAuthHolder.isUnlocked()) {
            finish()
            return
        }
        if (chunks.isEmpty()) return
        visible = true
        decryptor = Executors.newSingleThreadExecutor { r -> Thread(r, "archive-player-decrypt") }
        onPositionChanged()
    }

    override fun onStop() {
        // Leaving the screen: no plaintext stays on disk while it is not shown.
        if (visible) {
            visible = false
            try {
                resumeAtMs = videoView.currentPosition
            } catch (_: Exception) {
            }
            videoView.stopPlayback()
            wipeWindow()
        }
        super.onStop()
    }

    override fun onDestroy() {
        wipeWindow()
        if (attached) {
            attached = false
            val stillAttached = ArchiveAuthHolder.detachActivity()
            // A recreation for a configuration change is not a close: the
            // new instance attaches right after.
            if (!isChangingConfigurations &&
                ArchivePurgeRules.shouldPurge(stillAttached, ArchiveDownloadService.isRunning)
            ) {
                ArchiveAuthHolder.clear()
                ArchiveLocalData.purgeAll(this)
            }
        }
        super.onDestroy()
    }

    // ---- playback ----

    /** The position moved: erase what left the window, play the current
     *  chunk if it is ready, schedule the rest of the window. */
    private fun onPositionChanged() {
        updateControls()
        val (erase, ready) = synchronized(lock) {
            val gone = playback.toErase(decryptions.decryptedIndices()).mapNotNull { decryptions.remove(it) }
            gone to decryptions.ready(playback.current)
        }
        ArchiveLocalData.eraseLater(erase)
        if (ready != null) {
            play(ready)
        } else {
            videoView.stopPlayback()
            showMessage(getString(R.string.archive_player_decrypting))
        }
        for (i in playback.wanted()) schedule(i)
    }

    private fun schedule(index: Int) {
        val executor = decryptor ?: return
        val gen = synchronized(lock) { decryptions.claim(index) } ?: return
        // A name of its own for each decryption: an erase still queued for
        // an earlier decryption of this chunk cannot reach this one.
        val out = File(plainDir, RescueNames.newPlainFileName(index))
        val task = Runnable {
            var written: File? = null
            try {
                val id = identity
                val sess = session
                if (id != null && sess != null) {
                    sess.decryptToFile(chunks[index], out, id)
                    written = out
                }
            } catch (e: Exception) {
                Timber.w(e, "ArchivePlayerActivity: a chunk did not decrypt")
                runOnUiThread { if (index == playback.current && visible) showMessage(getString(R.string.archive_player_error)) }
            } finally {
                val recorded = synchronized(lock) { decryptions.finish(index, gen, written) }
                if (recorded) runOnUiThread { onDecrypted(index) } else ArchiveSession.secureDelete(out)
            }
        }
        try {
            executor.execute(task)
        } catch (e: RejectedExecutionException) {
            synchronized(lock) { decryptions.finish(index, gen, null) }
        }
    }

    private fun onDecrypted(index: Int) {
        if (!visible || isFinishing || isDestroyed) return
        // Decrypted after the window moved on: erase it at once.
        if (index !in playback.wanted()) {
            val gone = synchronized(lock) { decryptions.remove(index) }
            gone?.let { ArchiveLocalData.eraseLater(listOf(it)) }
            return
        }
        if (index == playback.current && !videoView.isPlaying) {
            synchronized(lock) { decryptions.ready(index) }?.let { play(it) }
        }
    }

    private fun play(file: File) {
        hideMessage()
        videoView.setVideoPath(file.path)
        if (resumeAtMs > 0) {
            videoView.seekTo(resumeAtMs)
            resumeAtMs = 0
        }
        videoView.start()
    }

    private fun updateControls() {
        partView.text = if (chunks.isEmpty()) "" else getString(R.string.archive_player_part, playback.current + 1, chunks.size)
        prevBtn.alpha = if (playback.hasPrevious) 1f else 0.3f
        nextBtn.alpha = if (playback.hasNext) 1f else 0.3f
    }

    private fun showMessage(text: String) {
        messageView.text = text
        messageView.visibility = View.VISIBLE
    }

    private fun hideMessage() {
        messageView.visibility = View.GONE
    }

    /** Stop decrypting and secure-delete every decrypted chunk. A decryption
     *  still running sees the generation change and erases its own output;
     *  one still queued never runs, and its claim goes with the wipe. */
    private fun wipeWindow() {
        decryptor?.shutdownNow()
        decryptor = null
        val files = synchronized(lock) { decryptions.wipe() }
        ArchiveLocalData.eraseLater(files)
    }

    companion object {
        private const val EXTRA_TOKEN = "token"
        private const val EXTRA_UNVERIFIABLE = "unverifiable"

        /** Chunks decrypted ahead of the one on screen. */
        private const val AHEAD = 2

        /**
         * [token] is the report's random local directory name: it says
         * nothing about the report on the relay. [unverifiable] plays the
         * chunks kept apart as not verifiable instead of the verified ones.
         */
        fun intent(context: Context, token: String, unverifiable: Boolean = false): Intent =
            Intent(context, ArchivePlayerActivity::class.java)
                .putExtra(EXTRA_TOKEN, token)
                .putExtra(EXTRA_UNVERIFIABLE, unverifiable)
    }
}
