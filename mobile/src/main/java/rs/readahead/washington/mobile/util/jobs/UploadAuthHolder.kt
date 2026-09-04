package rs.readahead.washington.mobile.util.jobs

import timber.log.Timber

/**
 * Process-local accessor for the V2 upload bearer.
 *
 * There is intentionally **no `set`**, and adding one is a regression, not a
 * convenience: it puts a long-lived, non-wipeable Java String back in the JVM
 * heap, where it survives a lock or a panic-wipe — the on-device heap-dump
 * finding (`Bearer eyJ` reachable after a panicWipe) that §10.6 (2026-06-13)
 * closed. Nor may the bearer travel through WorkManager's `InputData`, or
 * through any state WorkManager persists: those Data are written in clear to
 * disk in androidx.work.workdb, and the token would then survive a lock, a
 * panicWipe, and a seizure of the device. `verify()` stashes the bearer in Rust
 * directly, so the JWT never crosses the FFI as a Kotlin String at all.
 *
 * The token itself NO LONGER lives in the JVM. It is held in a `Zeroizing`
 * holder inside Rust (stashed by `StreamServerClient.verify`), and this object
 * is a thin facade over that holder:
 *  - [get] returns a transient `"Bearer <jwt>"` copy for a single request. The
 *    caller drops it right after the PUT; keeping it in a field would undo the
 *    whole arrangement and nothing would flag it;
 *  - [clear] zeroizes the Rust holder (lock / panic / drain-complete).
 *
 * It used to live in WorkManager's on-disk `Data`, then in an in-process
 * `AtomicReference<String>` (Phase 3.13); §10.6 moved it one step further —
 * out of the JVM heap entirely, into Rust where it can be deterministically
 * wiped.
 */
object UploadAuthHolder {
    /** Transient `"Bearer <jwt>"` for one request, or null if no session. */
    fun get(): String? = uniffi.frappuccino.uploadAuthHeader()

    /**
     * Phase 1 — whether a session bearer is held, WITHOUT pulling a copy into
     * the JVM. The Rust transport gates on this (only the existence bit crosses
     * the FFI; the bearer itself stays in Rust = heap-0 on the chunk path).
     */
    fun isPresent(): Boolean = uniffi.frappuccino.uploadAuthPresent()

    /** Zeroize the Rust-held bearer. Call on lock / panicWipe / drain-complete. */
    fun clear() {
        uniffi.frappuccino.uploadAuthClear()
        // §10.6 — the Rust zeroize above can't reach the bearer copies that
        // OkHttp's HTTP/2 layer retains for each request (the HPACK dynamic
        // table + per-request Headers live on the pooled connection, in the
        // JVM heap). On-device heap dumps confirmed the token survived a
        // panicWipe there, held by the keep-alive connection (5 min). Evict
        // the pool so those connections — and the bearer copies they hold —
        // are torn down now and become GC-eligible, instead of lingering for
        // the keep-alive window. Swapping OkHttp for another client without
        // replicating this eviction reopens that finding.
        // Not every caller waits for a drain: only the V2LockTimeoutController
        // path defers while a recording, an encryption or a queue drain is
        // still in flight; an explicit Lock and a panicWipe clear right after
        // stopService(), and the 401 paths clear mid-flight. So the pool is
        // not guaranteed idle here — accepted, because dropping the bearer
        // copies is the point, and a call cut short comes back as a
        // Result.retry() at the WorkManager layer, blob preserved.
        try {
            UploadHttpClient.instance.connectionPool.evictAll()
        } catch (e: Exception) {
            Timber.w(e, "UploadAuthHolder.clear: connectionPool.evictAll failed")
        }
    }
}
