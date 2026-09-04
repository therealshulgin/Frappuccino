package rs.readahead.washington.mobile.util.jobs

import okhttp3.CertificatePinner
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Protocol
import rs.readahead.washington.mobile.BuildConfig
import java.util.concurrent.TimeUnit

/**
 * Shared OkHttpClient for the Frappuccino V2 calls that still go through the
 * JVM HTTP stack.
 *
 * Chunk PUTs are not among them, and must not be moved back here. Every PUT
 * needs capability headers signed by the reportKeyring, which is the FFI, so
 * [ChunkUploadWorker] uploads through `uniffi.frappuccino.uploadPutReportChunk`
 * and deliberately has no OkHttp fallback that could sign. What is left on this
 * client is the provenance timestamp POST, whose `.ots` response body has to be
 * read in the JVM ([ProvenanceTimestampWorker]), and the `/health` reachability
 * probe, which derives a 3 s-callTimeout client from this one
 * ([rs.readahead.washington.mobile.service.StreamRecordingService]).
 * [UploadAuthHolder] also evicts this pool on clear, because OkHttp's HTTP/2
 * layer keeps bearer copies on the pooled connections.
 *
 * One shared client rather than one per call: a fresh `OkHttpClient()` has its
 * own connection and thread pools, so it pays a full TLS 1.3 handshake (2 RTT)
 * plus TCP slow-start every time — ~400 ms on a cellular link with ~200 ms RTT
 * before a single byte of body goes on the wire — and HTTP/2 multiplexing
 * requires a shared client (RFC 7540 §5.1.1). Lazy-init, process-wide, HTTP/2
 * negotiated via ALPN with an HTTP/1.1 fallback.
 *
 * `retryOnConnectionFailure(false)` is a safety choice, not a tuning knob:
 * WorkManager already retries via `Result.retry()`, and OkHttp's internal retry
 * would resend the body without informing the caller, conflating with our
 * circuit-breaker. It used to double the blob on the server side.
 *
 * `pingInterval(15 s)` makes OkHttp emit an HTTP/2 PING frame on an idle stream
 * and close the connection if the peer doesn't reply within 2× the interval, so
 * a silent peer death (gateway crash without RST) surfaces as an IOException in
 * ≤ 30 s instead of waiting out the 120 s `callTimeout`. 15 s also sits under
 * the usual 30 s cellular CGNAT keep-alive, so the socket doesn't get silently
 * rebound to a fresh NAT mapping.
 *
 * `callTimeout(120 s)` is the hard ceiling on the total wallclock of one call
 * made through this client. It does not bound the [UploadConcurrencyLimiter]
 * permit any more: that permit is taken and released around the Rust PUT in
 * [ChunkUploadWorker], and what bounds it is reqwest's own 120 s timeout in
 * `crypto-rs/stream/src/upload.rs`. The silent-stall starvation path from audit
 * R-04 is closed there, not here. The other timeouts stay sized for slow
 * uplinks.
 *
 * Connection pool of 8, keep-alive 5 min. The 8 was sized when parallel chunk
 * PUTs shared this pool ([UploadConcurrencyLimiter] MAX_CAP = 6, plus the auth
 * and report-creation calls) and for the HTTP/1.1 fallback case — corporate
 * MITM, captive portal that intercepts ALPN — where each parallel request needs
 * its own socket. Those PUTs no longer ride this pool, so today the figure is
 * headroom rather than a constraint.
 *
 * The [CertificatePinner] carries the same three SPKI pins as
 * [res/xml/network_security_config.xml]; CertificatePinner accepts the union,
 * so a rotation onto a break-glass key is an overlap and not a flag day.
 * For the calls that go through this client, the XML pin-set is the
 * system-level guarantee and this in-code pinner is defense in depth: it stays
 * visible in an audit and catches a build variant shipped without the XML.
 * Do not read the Rust verifier the XML names (`crypto-rs/stream/src/pin.rs`)
 * as covering this path — it is a rustls verifier, installed on the reqwest
 * and quinn clients, and never sits in this OkHttp stack. Drop the XML pin-set
 * and these calls are unpinned.
 *
 * Lifetime is process-wide; the connection pool drains automatically after the
 * configured idle timeout, and [UploadAuthHolder] evicts it earlier on clear.
 */
object UploadHttpClient {

    private const val SERVER_HOST = "relay.shake-document-protect.org"

    /**
     * SHA-256 SPKI hash of the Frappuccino V2 server certificate.
     * Must stay in sync with [res/xml/network_security_config.xml].
     * Cert rotated 2026-05-14, valid until 2036-05-11.
     */
    private const val SPKI_PIN = "sha256/QnGK0KvRC1vt2C4rrxwHIj0/pUbogVtTCesBK3sZXKY="

    /**
     * Break-glass / future-LE SPKI pin, pre-seeded 2026-06-27 (audit 2026-06-26
     * D-2). A SECOND pinned key WE control (not a CA fallback): [CertificatePinner]
     * accepts the UNION, so a future cert rotation (key loss/compromise or the
     * LE/domain cutover via certbot --reuse-key) is a graceful overlap, not a
     * flag-day brick. Mirrors the 2nd <pin> in network_security_config.xml and
     * PIN_NEXT_B64 in crypto-rs/stream/src/pin.rs.
     */
    private const val NEXT_PIN = "sha256/AmIDSglLpedq4J2LANgQ6s5+uKFEuuaNSGLjHOZkhok="

    /**
     * Off-host break-glass SPKI pin, pre-seeded 2026-06-28 (audit 2026-06-26 D-2).
     * A THIRD pinned key WE control, with its private half kept OFF-HOST and never
     * on the relay: the recovery path for a SEIZED relay (both served keys live on
     * the relay and fall together). DORMANT until a seizure cutover; [CertificatePinner]
     * accepts the UNION so the cutover needs no APK push. Mirrors the 3rd <pin> in
     * network_security_config.xml and PIN_NEXT2_B64 in crypto-rs/stream/src/pin.rs.
     */
    private const val NEXT2_PIN = "sha256/MUb4HHlUfj3c6cCQYuQMeeiWkcHga46OCZqVLuY9eCk="

    val instance: OkHttpClient by lazy { build() }

    private fun build(): OkHttpClient {
        val pinner = CertificatePinner.Builder()
            .add(SERVER_HOST, SPKI_PIN)
            .add(SERVER_HOST, NEXT_PIN)
            .add(SERVER_HOST, NEXT2_PIN)
            .build()

        return OkHttpClient.Builder()
            // Slow-link friendly timeouts, sized back when a 1 MB chunk
            // body rode this client (~16 s nominal over 500 kbps, plus
            // auth/header overhead, plus a margin for cellular jitter).
            // Chunk PUTs are on the Rust path now, with their own timeouts;
            // 60 s write remains the sweet spot between fail-fast on dead
            // links and tolerance of slow legit links.
            .connectTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            // Hard ceiling on a single call's total wallclock through this
            // client. It does not bound the concurrency permit: that permit
            // wraps the Rust PUT and is bounded by the Rust transport's own
            // timeout.
            .callTimeout(120, TimeUnit.SECONDS)
            // HTTP/2 keep-alive ping every 15 s. OkHttp
            // closes the connection if no response within 2× this
            // interval, so a silent dead peer surfaces as an
            // IOException in ≤ 30 s instead of waiting for the 120 s
            // callTimeout. The caller fails fast instead of hanging
            // behind a ghost connection.
            .pingInterval(15, TimeUnit.SECONDS)
            // Reuse sockets across calls. cap 8 was sized on MAX_CAP (6)
            // + 2 for auth/report-creation, back when those
            // PUTs rode this client; they are on the Rust path now, so 8
            // is headroom. On HTTP/2 a single socket multiplexes every
            // stream so this cap is mostly about the HTTP/1.1 fallback
            // case (server / proxy that doesn't negotiate H2). keep-alive
            // 5 min comfortably outlives the gaps between the calls that
            // do still ride it.
            .connectionPool(ConnectionPool(8, 5, TimeUnit.MINUTES))
            // HTTP/2 preferred — multiplexes multiple streams on a
            // single TCP connection so concurrent calls share TLS state.
            // Fallback to HTTP/1.1 if the server doesn't negotiate H2.
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            // We retry at the WorkManager layer. Disable OkHttp's
            // implicit retry so a failed request doesn't silently resend
            // before the worker even knows.
            .retryOnConnectionFailure(false)
            // Defense in depth. On this JVM path the authoritative gate
            // is the network_security_config pin-set, not the Rust
            // verifier; this one catches the case where someone forgets
            // to ship network_security_config on a new build variant.
            .certificatePinner(pinner)
            // Phase 0a-2 — install the bbr stopgap socket factory in DEBUG
            // builds only. Release uploads use the platform default factory and
            // are fully unaffected. Best-effort + gated by BbrStopgap; it only
            // adds a post-connect setsockopt, never changes how sockets connect.
            .apply { if (BuildConfig.DEBUG) socketFactory(BbrSocketFactory()) }
            .build()
    }
}
