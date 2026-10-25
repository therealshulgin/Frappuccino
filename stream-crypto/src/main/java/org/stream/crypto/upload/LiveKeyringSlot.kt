package org.stream.crypto.upload

/**
 * Where the legacy migration publishes the keyring it holds open, so that the
 * emergency wipe can destroy it synchronously, as it aborts the live report
 * writer, instead of leaving it to the migration's own cleanup.
 *
 * The keyring is a native handle. UniFFI hands an object passed as an argument
 * to Rust by cloning its native pointer, without the guard its own methods
 * take, so a handle destroyed before such a call starts would hand Rust a
 * freed pointer. Every use therefore goes through [withLive], and destruction
 * waits for the calls in flight: [destroyLive] never blocks, it releases the
 * handle at once when no call runs with it, otherwise as soon as the last one
 * returns (Rust holds its own reference during the call, so the key would
 * outlive the destroy until then anyway). From the moment [destroyLive]
 * returns, no new call can start: [withLive] throws [Closed] without running
 * its block.
 *
 * Generic over the handle, with its destruction passed in, so the rules are
 * testable on a plain JVM without the native library.
 *
 * @param destroy releases one handle; called at most once per published handle.
 */
class LiveKeyringSlot<T : Any>(private val destroy: (T) -> Unit) {

    /** The handle is gone (destroyed by a wipe, retired, or never published):
     *  stop, nothing more may be signed with it. */
    class Closed : IllegalStateException("legacy keyring closed")

    private class Held<T>(val handle: T) {
        var calls = 0
        var closing = false
        var destroyed = false
    }

    private val lock = Any()
    private var current: Held<T>? = null

    /** Set by [destroyLive] and never cleared: once an emergency wipe has
     *  run, nothing more is published in this process. A migration that read
     *  its wipe generation after the wipe began passes that check, so the
     *  generation alone would not keep it from publishing a keyring the wipe
     *  already went past. After a wipe the legacy master is gone, so no
     *  migration can legitimately need the slot again. */
    private var sealed = false

    /**
     * Publish [handle] unless an emergency wipe began since [wipeGeneration]
     * ([StreamUploadManager.unlessWipedSince], so the check and the
     * publication are one step with respect to the wipe's start), or ran at
     * all in this process ([destroyLive] seals the slot). Returns false, with
     * [handle] destroyed at once, when a wipe began or ran, or another handle
     * is already published.
     */
    fun publishUnlessWipedSince(handle: T, wipeGeneration: Int): Boolean {
        val published = StreamUploadManager.unlessWipedSince(wipeGeneration) {
            synchronized(lock) {
                if (sealed || current != null) {
                    false
                } else {
                    current = Held(handle)
                    true
                }
            }
        } == true
        if (!published) release(handle)
        return published
    }

    /**
     * Run [block] with the published handle. The handle cannot be released
     * while [block] runs.
     *
     * @throws Closed when no handle is published any more.
     */
    fun <R> withLive(block: (T) -> R): R {
        val held = synchronized(lock) {
            val h = current
            if (h == null || h.closing) throw Closed()
            h.calls++
            h
        }
        try {
            return block(held.handle)
        } finally {
            val release = synchronized(lock) {
                held.calls--
                takeForRelease(held)
            }
            if (release) release(held.handle)
        }
    }

    /**
     * The migration's own cleanup: retire [handle] and destroy it, now or
     * once its last call returns. A no-op when the wipe already took it.
     */
    fun retire(handle: T) {
        val held = synchronized(lock) {
            val h = current?.takeIf { it.handle === handle } ?: return
            current = null
            h.closing = true
            h.takeIf { takeForRelease(it) }
        }
        held?.let { release(it.handle) }
    }

    /**
     * The emergency wipe: retire the published handle, if any, and destroy it
     * now, or once the call in flight returns, and seal the slot so that no
     * handle is published after it. Never blocks; idempotent. Returns whether
     * a handle was published.
     */
    fun destroyLive(): Boolean {
        val (had, held) = synchronized(lock) {
            sealed = true
            val h = current ?: return false
            current = null
            h.closing = true
            Pair(true, h.takeIf { takeForRelease(it) })
        }
        held?.let { release(it.handle) }
        return had
    }

    /** Whether a handle is published (and not closing). */
    fun isLive(): Boolean = synchronized(lock) { current?.closing == false }

    /** Under [lock]: whether [held] must be destroyed now, marking it so. */
    private fun takeForRelease(held: Held<T>): Boolean {
        if (!held.closing || held.calls > 0 || held.destroyed) return false
        held.destroyed = true
        return true
    }

    private fun release(handle: T) {
        try {
            destroy(handle)
        } catch (_: Exception) {
            // The handle is unusable either way; a failed release must not
            // stop a wipe or hide the error that ended the migration.
        }
    }
}
