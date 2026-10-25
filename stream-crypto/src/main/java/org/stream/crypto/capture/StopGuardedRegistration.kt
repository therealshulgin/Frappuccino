package org.stream.crypto.capture

/**
 * A registration (a system callback, say) that a session makes on one thread
 * and its stop undoes on another, whichever comes first.
 *
 * Registering late, after the stop has already run its unregister, would
 * leave a callback nobody removes: it would outlive the session, keep it
 * reachable and keep acting for it. Both sides run under one lock, so either
 * the registration happens first and the stop removes it, or the stop happens
 * first and the registration does not happen.
 *
 * Pure JVM: unit-tested without the Android framework.
 */
class StopGuardedRegistration<T : Any> {
    private val lock = Any()
    private var current: T? = null
    private var stopped = false

    /**
     * Register with [register] unless [stop] already ran. Returns whether it
     * registered. [register] runs under the lock.
     */
    fun registerUnlessStopped(register: () -> T?): Boolean = synchronized(lock) {
        if (stopped) return false
        current = register()
        current != null
    }

    /**
     * From now on nothing registers; undo what was registered with
     * [unregister] (under the lock). Idempotent.
     */
    fun stop(unregister: (T) -> Unit) = synchronized(lock) {
        stopped = true
        current?.let(unregister)
        current = null
    }
}
