package rs.readahead.washington.mobile.util.jobs

/**
 * Transport selector for the chunk PUT.
 *
 * Never reintroduce a Java HTTP path (OkHttp) as a safety net for the chunk PUT.
 * An OkHttp PUT would be identity-based and rejected by the blind relay — and
 * the very failure that would trigger such a fallback, a broken native binding,
 * also disables the FFI keyring that signs the capability headers, so the
 * fallback would have nothing to sign with. The chunk upload is **Rust-only by
 * construction** (locked design): [ChunkUploadWorker] never reads a Java HTTP
 * path, and a sick native binding surfaces as a `Throwable` → `Result.retry()`
 * (the blob stays on disk for the next attempt), not as a transport switch.
 *
 * A flag of exactly that kind used to live here, with zero readers anywhere in
 * the repo; it and its "OkHttp safety net" KDoc were removed (audit 2026-06-26,
 * R-CR-5).
 */
object RustUploadTransport {

    /**
     * Which Rust transport the chunk PUT uses. `OBF_QUIC` for BOTH debug and
     * release: this is the D-1 closure (transport plan §10.9). The release
     * binary used to speak plain pinned TLS to the raw relay IP, so a DPI saw
     * *that* and *when* you upload; putting DIRECT_TLS back as the default "to
     * simplify" or "to debug" undoes that, and no test fails. ObfQuic targets
     * the production Salamander obfs front (`:8445`), which de-XORs and forwards
     * to Caddy h3 (`:8444`); on the wire every packet looks like uniform random
     * UDP and the relay is a dead port to any prober without the PSK. This
     * default is not untried: field-validated against prod on 2 chipsets
     * (OnePlus CPH2653 + MediaTek), `transport=obfquic`, 0 fallback, 0 error.
     * The obfs PSK is re-provisioned at publication (separate gated step).
     *
     * Automatic QUIC->DirectTls fallback inside Rust (same bearer, heap-0): if
     * QUIC can't ESTABLISH (UDP-blocked network) the chunk rides DirectTls, and
     * a latch skips QUIC until the next auth clear (lock / auto-lock / 401 /
     * panic) or the next recording start, whichever comes first. The
     * per-recording re-arm is [uniffi.frappuccino.uploadTransportRearm], called
     * by StreamRecordingService when a session begins.
     *
     * That re-arm used to be a side effect of `uploadCreateReport`, and it
     * stopped firing when report creation became lazy (minted by the seq-0 PUT)
     * and that call lost its last caller: the latch then outlived several
     * recordings, lengthening the exposure of the residual below, and nothing
     * failed to say so. It is its own entry point now, because a side effect
     * nobody invokes is not a behaviour.
     *
     * Documented residual (D-1): on a UDP-blocked path the fallback re-exposes
     * the direct-IP signal — but 0 data loss, and
     * [uniffi.frappuccino.PutOutcome.transportUsed] surfaces it
     * (`directtls_degraded`) in the `StreamMetrics transport=` field, so the
     * fallback is never silent.
     *
     * Read live at PUT time by the upload workers (chunk, directory entry,
     * provenance), never captured once at construction. That live read is what
     * makes the app's single writer work: after a process restart the field is
     * back to its compiled-in value, and opening the debug Settings screen
     * re-pushes the persisted choice ([StreamPreferences.isDebugQuicTransport]),
     * which is also the toggle that flips it to DirectTls and back. Caching the
     * mode in a worker would silently break both that restoration and the
     * toggle.
     */
    @Volatile
    var mode: uniffi.frappuccino.TransportMode = uniffi.frappuccino.TransportMode.OBF_QUIC
}
