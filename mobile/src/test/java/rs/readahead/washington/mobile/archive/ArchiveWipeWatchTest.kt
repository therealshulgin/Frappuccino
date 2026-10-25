package rs.readahead.washington.mobile.archive

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.mock

/**
 * How long an archive screen hears the emergency wipe. The case that matters
 * is the screen in the background: the wipe is started from another screen
 * of the app, and a screen that stopped listening at ON_STOP comes back
 * afterwards, still open on a rescue whose secrets are gone.
 *
 * Driven by a real [LifecycleRegistry]; the subscription is counted instead
 * of registering a receiver, which the JVM cannot build.
 */
class ArchiveWipeWatchTest {

    // Held strongly: the registry keeps only a weak reference to its owner.
    private val owner: LifecycleOwner = mock(LifecycleOwner::class.java)

    private var subscribes = 0
    private var unsubscribes = 0

    private fun watched(unsubscribe: () -> Unit = { unsubscribes++ }): Pair<ArchiveWipeWatch, LifecycleRegistry> {
        val watch = ArchiveWipeWatch(subscribe = { subscribes++ }, unsubscribe = unsubscribe)
        val registry = LifecycleRegistry.createUnsafe(owner)
        registry.addObserver(watch)
        return watch to registry
    }

    @Test
    fun `the wipe is heard from creation to destruction, in the background too`() {
        val (watch, lifecycle) = watched()
        assertFalse(watch.isSubscribed)

        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_CREATE)
        assertTrue(watch.isSubscribed)

        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_START)
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_RESUME)
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_PAUSE)
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        assertTrue("a screen in the background must still hear the wipe", watch.isSubscribed)

        // Back to the foreground and away again: still one subscription.
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_START)
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        assertTrue(watch.isSubscribed)
        assertEquals(1, subscribes)
        assertEquals(0, unsubscribes)

        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        assertFalse(watch.isSubscribed)
        assertEquals(1, subscribes)
        assertEquals(1, unsubscribes)
    }

    @Test
    fun `a screen that finishes in onCreate still unsubscribes`() {
        val (watch, lifecycle) = watched()
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_CREATE)
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        assertFalse(watch.isSubscribed)
        assertEquals(1, subscribes)
        assertEquals(1, unsubscribes)
    }

    @Test
    fun `a receiver the platform no longer knows does not break the teardown`() {
        val (watch, lifecycle) = watched(unsubscribe = { throw IllegalArgumentException("Receiver not registered") })
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_CREATE)
        lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        assertFalse(watch.isSubscribed)
    }
}
