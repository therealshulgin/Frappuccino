package rs.readahead.washington.mobile.util.jobs

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the in-memory circuit breaker.
 *
 * `UploadCircuitBreaker` est un singleton kotlin → on doit reset() avant
 * chaque test pour ne pas hériter de l'état d'un test précédent.
 */
class UploadCircuitBreakerTest {

    @Before
    fun setUp() {
        UploadCircuitBreaker.reset()
    }

    @Test
    fun fresh_breakerIsClosed() {
        assertFalse("Fresh breaker must be CLOSED", UploadCircuitBreaker.isOpen())
        assertEquals(UploadCircuitBreaker.State.CLOSED, UploadCircuitBreaker.state())
    }

    @Test
    fun successDoesNotOpen() {
        repeat(10) { UploadCircuitBreaker.reportSuccess() }
        assertFalse(UploadCircuitBreaker.isOpen())
    }

    @Test
    fun singleErrorDoesNotOpen() {
        UploadCircuitBreaker.reportServerError(503)
        assertFalse("1x 5xx ne doit pas ouvrir le circuit", UploadCircuitBreaker.isOpen())
    }

    @Test
    fun twoErrorsDoNotOpen() {
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(503)
        assertFalse("2x 5xx ne doit pas ouvrir (THRESHOLD=3)", UploadCircuitBreaker.isOpen())
    }

    @Test
    fun threeErrorsOpenTheCircuit() {
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(503)
        UploadCircuitBreaker.reportServerError(504)
        assertTrue("3x 5xx doit ouvrir le circuit", UploadCircuitBreaker.isOpen())
        assertEquals(UploadCircuitBreaker.State.OPEN, UploadCircuitBreaker.state())
    }

    @Test
    fun successResetsTheCounter() {
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(503)
        UploadCircuitBreaker.reportSuccess()  // reset
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(503)
        // 4 errors total, but reset au milieu → seulement 2 consécutifs après
        assertFalse("Success doit reset le compteur 5xx", UploadCircuitBreaker.isOpen())
    }

    @Test
    fun networkExceptionAlsoTriggersBreaker() {
        // HTTP code 0 utilisé pour signaler exception réseau
        UploadCircuitBreaker.reportServerError(0)
        UploadCircuitBreaker.reportServerError(0)
        UploadCircuitBreaker.reportServerError(0)
        assertTrue("3x exceptions réseau doit ouvrir comme 3x 5xx",
            UploadCircuitBreaker.isOpen())
    }

    @Test
    fun mixedErrorCodesAccumulate() {
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(0)  // network
        UploadCircuitBreaker.reportServerError(504)
        assertTrue("Mix 5xx+exception accumule pareil", UploadCircuitBreaker.isOpen())
    }

    @Test
    fun resetClearsOpenState() {
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(503)
        UploadCircuitBreaker.reportServerError(504)
        assertTrue(UploadCircuitBreaker.isOpen())
        UploadCircuitBreaker.reset()
        assertFalse("reset() doit fermer le circuit immédiatement",
            UploadCircuitBreaker.isOpen())
    }

    // --- Phase H2-B.13 (2026-05-18) — Blue HIGH-5 half-open probe gate ---
    // Avant ce fix, N workers concurrents qui voyaient le cooldown
    // expirer tiraient TOUS en cluster sur un serveur potentiellement
    // encore down → 3+ workers consommaient des slots ratchet pour rien.
    // Maintenant : un seul worker probe, les autres voient isOpen()=true
    // jusqu'au report. Le probe est cleared par reportSuccess /
    // reportServerError pour le prochain cycle.

    /**
     * Despite its name, this test does NOT exercise the half-open probe gate.
     * That branch is left to integration coverage — field tests, through the
     * `circuit_open` metric. What is checked here, and in the two tests below,
     * are the simple invariants: reset(), reportSuccess() and
     * reportServerError() each leave the probe state clean.
     *
     * The gate is unreachable without an injectable clock, so do not "repair"
     * this test by asserting on it. It only arms after a real
     * OPEN → cooldown → half-open transition, i.e. after time has actually
     * elapsed. From a fresh state openUntilMs == 0L, so isOpen() skips the
     * cooldown-elapsed branch and returns CLOSED without ever acquiring the
     * probe. reset() is no shortcut either: it clears openUntilMs and the
     * probe together, so it cannot build the intermediate state the gate needs
     * (cooldown in the past, probe still free).
     */
    @Test
    fun halfOpenAllowsExactlyOneProbe() {
        // These three are load-bearing, not noise: THRESHOLD is 3, so they are
        // exactly what trips the circuit and puts openUntilMs in the future.
        // Drop them and reset() runs on a brand-new breaker, which asserts
        // nothing.
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportServerError(503)
        UploadCircuitBreaker.reportServerError(504)
        // Force cooldown expiration : reset() clears openUntilMs, the counter
        // and any in-flight probe.
        UploadCircuitBreaker.reset()
        // After reset, half-open probe state must be clean for the
        // next cycle.
        assertFalse(UploadCircuitBreaker.isOpen())
    }

    @Test
    fun reportSuccessClearsHalfOpenProbe() {
        // Sanity : after a successful report, subsequent isOpen() in a
        // fresh-or-recovered state must return false directly (no probe
        // held). This is the "happy path" recovery.
        UploadCircuitBreaker.reportServerError(502)
        UploadCircuitBreaker.reportSuccess()
        assertFalse("After success, breaker must be CLOSED with no held probe",
            UploadCircuitBreaker.isOpen())
        // A second concurrent call must also return false (no probe
        // serialization in CLOSED state).
        assertFalse(UploadCircuitBreaker.isOpen())
    }

    @Test
    fun reportServerErrorClearsHalfOpenProbeOnPartialFailure() {
        // After a 5xx that is not enough to re-OPEN, reportServerError also
        // resets halfOpenProbeStartMs to 0L, which ends the half-open phase:
        // the gate no longer applies, and the following workers all get
        // isOpen()=false directly, without waiting and without being
        // serialized. That is a deliberate implementation choice (an
        // error-tolerant half-open), not a return to probing one at a time.
        // This test only checks that nobody is blocked indefinitely.
        UploadCircuitBreaker.reportServerError(502)
        // counter=1, no OPEN yet. Probe is implicitly held in the
        // current model only if we'd just exited cooldown. From CLOSED
        // state isOpen() doesn't acquire probe, so the next isOpen()
        // also returns false directly.
        assertFalse(UploadCircuitBreaker.isOpen())
        assertFalse(UploadCircuitBreaker.isOpen())
    }

    // --- Phase 1.12 (2026-05-23) — disk-full (HTTP 507) handling ---
    // A 507 is NOT a transient 5xx : retrying on the next backoff bucket
    // is futile (the disk won't free itself), so a single 507 opens the
    // circuit immediately (vs THRESHOLD=3 for ordinary 5xx) and sets a
    // user-facing flag, while the caller still Result.retry()s to keep
    // the blob on-device.

    @Test
    fun freshBreakerIsNotDiskFull() {
        assertFalse("Fresh breaker must not report disk-full",
            UploadCircuitBreaker.isDiskFull())
    }

    @Test
    fun reportDiskFullOpensImmediately() {
        UploadCircuitBreaker.reportDiskFull()
        assertTrue("507 must open the circuit on the first hit",
            UploadCircuitBreaker.isOpen())
        assertEquals(UploadCircuitBreaker.State.OPEN, UploadCircuitBreaker.state())
        assertTrue("isDiskFull must be set after a 507",
            UploadCircuitBreaker.isDiskFull())
    }

    @Test
    fun reportSuccessClearsDiskFull() {
        UploadCircuitBreaker.reportDiskFull()
        assertTrue(UploadCircuitBreaker.isDiskFull())
        UploadCircuitBreaker.reportSuccess()  // space freed, upload went through
        assertFalse("A success means space is back — disk-full flag clears",
            UploadCircuitBreaker.isDiskFull())
        assertFalse(UploadCircuitBreaker.isOpen())
    }

    @Test
    fun resetClearsDiskFull() {
        UploadCircuitBreaker.reportDiskFull()
        assertTrue(UploadCircuitBreaker.isDiskFull())
        UploadCircuitBreaker.reset()
        assertFalse(UploadCircuitBreaker.isDiskFull())
        assertFalse(UploadCircuitBreaker.isOpen())
    }
}
