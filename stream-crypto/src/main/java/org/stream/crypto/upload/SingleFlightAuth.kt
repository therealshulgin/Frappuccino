package org.stream.crypto.upload

/**
 * "Get a bearer if none is held", single-flight across every caller that
 * shares [lock].
 *
 * Each authentication spends one ephemeral ratchet slot. Two callers that
 * find no bearer at the same moment must not both spend one: the second has
 * to wait for the first and reuse what it published. That only works if they
 * wait on the SAME lock; two components each guarding their own attempt with
 * a lock of their own still authenticate twice when they meet.
 *
 * Pure JVM: unit-tested without the native library.
 */
class SingleFlightAuth(private val lock: Any) {

    /**
     * Returns whether a bearer is held when this returns. Under [lock]:
     * [present] first (another caller may just have published one), then
     * [attempt] only if it is still missing. [attempt] returns whether it
     * authenticated; [present] is asked again afterwards, because an
     * authentication that "succeeded" without publishing a bearer helps
     * nobody.
     */
    fun ensure(present: () -> Boolean, attempt: () -> Boolean): Boolean =
        synchronized(lock) {
            if (present()) return true
            attempt() && present()
        }
}
