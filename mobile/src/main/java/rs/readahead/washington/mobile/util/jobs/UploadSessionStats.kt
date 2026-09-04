package rs.readahead.washington.mobile.util.jobs

import timber.log.Timber
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * Lightweight per-recording-session upload counters. **Logging-only, zero
 * behavioural effect** — nothing in the app may branch on them. Gating an
 * upload on `peakBacklog`, say, would turn a field measurement into a critical
 * component.
 *
 * The counters are process-global, and that is only unambiguous because exactly
 * one recording session is active at a time: [OrphanSweepWorker] gates itself
 * out while [rs.readahead.washington.mobile.service.StreamRecordingService]
 * runs. If that gate ever goes away the counters become silently wrong. They
 * reset at session start and are lost at process death, which is acceptable for
 * a field measurement instrument and would not be for durable accounting. Late
 * losses (orphan-sweep abandonment, the 48 h on-device TTL sweep — not the
 * relay-side TTL) keep their own existing log lines.
 *
 * This is a temporary investigation instrument, and the question it answers is
 * its exit condition: is the chunk loss / retry pressure observed in the field
 * actually congestion-control bound (TCP `cubic` collapsing under packet
 * loss), or caused by something else — disk-full, process death, ratchet wipe,
 * the causes already root-caused in 1.12 / 1.14 (ROADMAP §10.9 Gate 0,
 * transport plan `docs/TRANSPORT_PLAN.md`)? The PoC measurements (netem) show
 * `cubic` losing 6–15× of goodput under loss, and upload CC is governed by the
 * sender, i.e. the phone, so the single most important datum is which CC the
 * upload path actually uses on each device — and whether `bbr` is even
 * available there. This instrument logs that, plus a per-session upload rollup,
 * so a cubic-vs-bbr field comparison has numbers on both arms.
 *
 * The bbr arm is no longer the `setsockopt(bbr)` stopgap: that one is installed
 * on the OkHttp client and only in debug builds (see [UploadHttpClient]), and
 * the chunk PUTs counted here go through the Rust transport instead. Porting it
 * to that transport was abandoned, QUIC carrying BBR in userspace everywhere.
 * The arm today is the transport itself: DirectTls on the kernel CC versus
 * QUIC/h3, whose BBR runs in userspace. [RustUploadTransport] defaults to
 * `OBF_QUIC`, and the debug QUIC toggle is what switches arms.
 *
 * All output uses the existing `StreamMetrics` Timber tag, so the field
 * capture is one grep: `adb logcat -s StreamMetrics:I`.
 */
object UploadSessionStats {

    private val uploaded = AtomicInteger(0)
    private val peakBacklog = AtomicInteger(0)

    @Volatile private var sessionId: String = ""
    @Volatile private var startedAtMs: Long = 0L
    @Volatile private var cc: String = "unknown"

    /**
     * Called once by the recording service as soon as the sessionId is
     * known. Resets the counters and logs whatever [readCc] returns for this
     * device: the native probe's `default=…;bbr=ok|unavailable`, or the
     * procfs fallback's `default=…;available=…`, or `unknown`.
     */
    fun startSession(id: String) {
        uploaded.set(0)
        peakBacklog.set(0)
        sessionId = id
        startedAtMs = System.currentTimeMillis()

        cc = readCc()

        // The Gate-0 datum: the sender governs upload CC. This reads the
        // kernel TCP CC, so it describes the DirectTls path (the fallback
        // taken when QUIC can't establish); on the default OBF_QUIC path the
        // congestion control runs in userspace and this figure doesn't
        // describe it. The native probe reports the default CC and whether
        // bbr is settable on this device (Seeker bbr=unavailable, OnePlus
        // bbr=ok), which is why the setsockopt(bbr) stopgap is not portable
        // and QUIC's userspace CC is the uniform fix.
        Timber.tag("StreamMetrics").i("tcpCC sessionId=%s %s", id, cc)
    }

    /** [ChunkUploadWorker] — one real 2xx chunk PUT succeeded. */
    fun onUploaded() {
        uploaded.incrementAndGet()
    }

    /**
     * [ChunkUploadWorker] — report the current per-session backlog so we
     * keep the high-water mark. A ballooning backlog under loss is the
     * visible symptom of a collapsing upload CC.
     */
    fun reportBacklog(backlog: Int) {
        if (backlog < 0) return
        while (true) {
            val cur = peakBacklog.get()
            if (backlog <= cur) return
            if (peakBacklog.compareAndSet(cur, backlog)) return
        }
    }

    /**
     * `uploaded` and `pendingAtStop` are an **at-stop snapshot**, not the
     * final drained state: the background drain (WorkManager) keeps running
     * after this call, so `uploaded` below the session total is expected here
     * and is not a chunk loss. Don't move the call after the drain either —
     * the snapshot is exactly the comparative signal we want (how far behind
     * was the upload when the user stopped, cubic vs bbr, same recording
     * length).
     *
     * Called by the recording service at stop, after the final
     * `scheduleUpload()`, with the at-stop pending snapshot.
     */
    fun summarize(pendingAtStop: Int, networkType: String) {
        if (startedAtMs == 0L) return
        val durationMs = System.currentTimeMillis() - startedAtMs
        Timber.tag("StreamMetrics").i(
            "sessionSummary sessionId=%s durationMs=%d uploaded=%d pendingAtStop=%d peakBacklog=%d cc=\"%s\" netType=%s",
            sessionId, durationMs, uploaded.get(), pendingAtStop,
            peakBacklog.get(), cc, networkType,
        )
    }

    /**
     * Native probe first (works in the app domain via a socket getsockopt);
     * procfs fallback for ROMs that allow untrusted_app to read it (denied on
     * the Seeker). Returns "default=...;bbr=..." (native) or
     * "default=...;available=..." (procfs), or "unknown".
     */
    private fun readCc(): String {
        val native = TcpCongestion.probe()
        if (native != "unknown") return native
        val def = readProcLine("/proc/sys/net/ipv4/tcp_congestion_control")
        val avail = readProcLine("/proc/sys/net/ipv4/tcp_available_congestion_control")
        if (def == "unknown" && avail == "unknown") return "unknown"
        return "default=$def;available=$avail"
    }

    /**
     * Best-effort read of a one-line procfs entry. These specific procfs
     * entries under `/proc/sys/net/ipv4/` are world-readable in DAC terms,
     * but the `untrusted_app` SELinux policy denies the read on the devices
     * tested (Seeker), so this fallback usually just logs "unknown". The JNI
     * getsockopt probe, which reads the per-socket value, is the main path
     * here rather than a complement.
     */
    private fun readProcLine(path: String): String =
        try {
            File(path).readText().trim().ifEmpty { "unknown" }
        } catch (e: Exception) {
            "unknown"
        }
}
