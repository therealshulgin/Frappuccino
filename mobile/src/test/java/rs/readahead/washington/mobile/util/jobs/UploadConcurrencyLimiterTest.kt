package rs.readahead.washington.mobile.util.jobs

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the network-recovery cap re-arm
 * ([UploadConcurrencyLimiter.bumpCapForRecovery]).
 *
 * `UploadConcurrencyLimiter` is a Kotlin singleton with no public cap reset
 * (only [resetSamples] clears the rolling window, not the cap), so a test
 * starts on whatever cap the previous one left. Each test therefore SATURATES
 * the cap to a known bound instead of assuming a starting value: the window is
 * SAMPLE_WINDOW=8 and the cap moves one step per full window, so 48 samples =
 * 6 windows always reaches the bound (floor MIN_CAP=1 from the MAX_CAP=6
 * ceiling needs 5; ceiling from the floor needs 5); extra windows are harmless
 * no-ops at the bound. Trimming the `repeat(48)` runs down to a window or two
 * would make the suite pass or fail depending on test order.
 *
 * The famine state is reached only through the public measurement path
 * ([UploadConcurrencyLimiter.reportUploadTime]), never by touching the
 * semaphore or pendingShrink directly: setting the internal state by hand
 * would test something other than the mechanism production actually runs. And
 * in a unit test no permit is ever held, so every shrink reclaims cleanly
 * (pendingShrink stays 0) and availablePermits() tracks the active cap — which
 * is what makes the assertions on availablePermits() legitimate. A test that
 * held a permit would break that equivalence, with nothing to point at the
 * cause.
 *
 * This is the deterministic proof of the Phase 3.49 fix's core, which the
 * field can't easily reproduce at home: it needs a slow-but-connected link to
 * make the cap fall to 1. It drives the cap to the MIN_CAP=1 floor — the
 * famine state — then asserts the recovery re-arm lifts it back to INITIAL_CAP
 * with a coherent permit count.
 */
class UploadConcurrencyLimiterTest {

    @Before
    fun setUp() {
        UploadConcurrencyLimiter.resetSamples()
    }

    @Test
    fun bumpCapForRecovery_rearms_cap_to_initial_from_the_floor() {
        // Sustained slow uploads (ratio 10 >> SLOW_RATIO=0.70) drive the cap
        // down to MIN_CAP=1 — the famine state where the café session got
        // stuck for ~14 min because nothing re-armed the cap on WiFi return.
        repeat(48) { UploadConcurrencyLimiter.reportUploadTime(50_000) }
        assertEquals("cap must reach the MIN_CAP floor", 1, UploadConcurrencyLimiter.currentCap())
        assertEquals("one permit at the floor", 1, UploadConcurrencyLimiter.availablePermits())

        // Network recovery re-arms the cap to INITIAL_CAP via the grow path
        // (release one net permit), breaking the starvation deadlock.
        UploadConcurrencyLimiter.bumpCapForRecovery()

        assertEquals("recovery re-arms to INITIAL_CAP", 2, UploadConcurrencyLimiter.currentCap())
        assertEquals("the re-armed permit is granted back", 2, UploadConcurrencyLimiter.availablePermits())
    }

    @Test
    fun bumpCapForRecovery_never_lowers_a_healthy_cap() {
        // Sustained fast uploads (ratio 0.02 << FAST_RATIO=0.25) climb the cap
        // to the MAX_CAP=6 ceiling.
        repeat(48) { UploadConcurrencyLimiter.reportUploadTime(100) }
        val healthy = UploadConcurrencyLimiter.currentCap()
        assertTrue("cap must have grown above INITIAL_CAP", healthy > 2)

        // Monotonic-up : a recovery hint on an already-healthy cap must never
        // shrink it (it only wipes the stale sample window).
        UploadConcurrencyLimiter.bumpCapForRecovery()

        assertEquals("recovery never lowers a healthy cap", healthy, UploadConcurrencyLimiter.currentCap())
    }
}
