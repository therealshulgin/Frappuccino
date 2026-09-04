package org.stream.crypto.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [AdaptiveQualityManager].
 *
 * Chunk interval: 5000 ms throughout. Slow threshold = 0.80 → uploadMs > 4000.
 * Fast threshold = 0.60 → uploadMs < 3000. Mid-band: 3000..4000 inclusive.
 */
class AdaptiveQualityManagerTest {

    private val intervalMs = 5000L

    @Test
    fun starts_at_HD_by_default() {
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = {})
        assertEquals(StreamQuality.HD, mgr.currentQuality)
    }

    @Test
    fun three_slow_ticks_downgrade_HD_to_SD() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = { changes += it })

        // 4500ms upload = ratio 0.90 = slow
        repeat(3) { mgr.reportChunkUploadTime(4500) }

        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.SD), changes)
    }

    @Test
    fun two_slow_ticks_alone_dont_downgrade() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = { changes += it })

        repeat(2) { mgr.reportChunkUploadTime(4500) }

        assertEquals(StreamQuality.HD, mgr.currentQuality)
        assertTrue(changes.isEmpty())
    }

    @Test
    fun mid_band_tick_is_fully_neutral_does_not_reset_counters() {
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = {})

        // 2 slow ticks bring slowTicks to 2 (need 3 for downgrade)
        mgr.reportChunkUploadTime(4500) // slow tick 1
        mgr.reportChunkUploadTime(4500) // slow tick 2
        // Mid-band tick — Phase 3.3 fix : no counter mutation, so the
        // slow streak survives and the next slow tick triggers the
        // downgrade.
        mgr.reportChunkUploadTime(3500) // mid-band, neutral
        mgr.reportChunkUploadTime(4500) // slow tick 3 → downgrade

        assertEquals(StreamQuality.SD, mgr.currentQuality)
    }

    @Test
    fun fast_streak_survives_mid_band_during_recovery() {
        // Repro of the bug therealshulgin reported 2026-05-10 : after a downgrade
        // to SD, network recovers but stays just below the wifi burst
        // (some chunks land in 0.60..0.80 mid-band), and the previous
        // logic would reset fastTicks on every mid-band tick — silently
        // preventing any upgrade.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.SD,
        )

        // FAST_HYSTERESIS = 10, so we need 10 net fast
        // ticks (interspersed mid-band ticks neutral). Phase 3.3 fix
        // is unchanged ; this still demonstrates the mid-band-neutral
        // invariant.
        repeat(5) { mgr.reportChunkUploadTime(1500) } // 5 fast
        mgr.reportChunkUploadTime(3500)               // mid, neutral
        repeat(3) { mgr.reportChunkUploadTime(1500) } // 8 fast total
        mgr.reportChunkUploadTime(3500)               // mid, neutral
        repeat(2) { mgr.reportChunkUploadTime(1500) } // 10 fast → upgrade

        assertEquals(StreamQuality.HD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.HD), changes)
    }

    @Test
    fun slow_tick_still_resets_fast_streak() {
        // A slow tick mid-streak is a real signal that the network just
        // degraded — fastTicks must reset (otherwise we'd upgrade on a
        // network that's just about to drop the quality back).
        // FAST_HYSTERESIS raised from 5 to 10.
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            initialQuality = StreamQuality.SD,
        )

        repeat(9) { mgr.reportChunkUploadTime(1500) } // 9 fast (FAST_HYST - 1)
        mgr.reportChunkUploadTime(4500) // slow → fastTicks=0
        repeat(9) { mgr.reportChunkUploadTime(1500) } // 9 fast again

        // Only 9 fast ticks since the last slow → no upgrade
        assertEquals(StreamQuality.SD, mgr.currentQuality)
    }

    @Test
    fun ten_fast_ticks_from_SD_upgrade_to_HD() {
        // FAST_HYSTERESIS raised 5 → 10 to reduce the
        // chance of a premature upgrade right before a network drop.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.SD,
        )

        // 1500ms upload = ratio 0.30 = fast
        repeat(10) { mgr.reportChunkUploadTime(1500) }

        assertEquals(StreamQuality.HD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.HD), changes)
    }

    @Test
    fun nine_fast_ticks_alone_dont_upgrade() {
        // Boundary check just below FAST_HYSTERESIS = 10.
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            initialQuality = StreamQuality.SD,
        )

        repeat(9) { mgr.reportChunkUploadTime(1500) }

        assertEquals(StreamQuality.SD, mgr.currentQuality)
    }

    @Test
    fun cannot_downgrade_below_SD() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.SD,
        )

        repeat(20) { mgr.reportChunkUploadTime(4800) }

        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertTrue("no change emitted at floor", changes.isEmpty())
    }

    @Test
    fun cannot_upgrade_above_FHD() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.FHD,
        )

        repeat(20) { mgr.reportChunkUploadTime(1000) }

        assertEquals(StreamQuality.FHD, mgr.currentQuality)
        assertTrue("no change emitted at ceiling", changes.isEmpty())
    }

    // User-configurable max-quality cap.

    @Test
    fun cap_at_HD_blocks_upgrade_above_HD() {
        // Start at HD, cap at HD : a sustained fast streak that would
        // normally climb HD → FHD must stay pinned at HD.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.HD,
            maxQuality = StreamQuality.HD,
        )

        repeat(20) { mgr.reportChunkUploadTime(1000) } // would be FHD without cap

        assertEquals(StreamQuality.HD, mgr.currentQuality)
        assertTrue("no upgrade past the cap", changes.isEmpty())
    }

    @Test
    fun cap_clamps_initial_quality_down() {
        // initialQuality defaults to HD but the cap is SD → the manager
        // must start at SD (the cap also lowers the starting point).
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            initialQuality = StreamQuality.HD,
            maxQuality = StreamQuality.SD,
        )

        assertEquals(StreamQuality.SD, mgr.currentQuality)
    }

    @Test
    fun cap_at_HD_still_allows_downgrade_to_SD() {
        // The cap only bounds the TOP. A capped manager must still drop
        // below the cap when the network degrades (that's the whole point
        // of keeping the adaptive ladder alive under the ceiling).
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.HD,
            maxQuality = StreamQuality.HD,
        )

        repeat(3) { mgr.reportChunkUploadTime(4500) } // 3 slow → HD → SD

        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.SD), changes)
    }

    @Test
    fun reset_re_clamps_to_cap() {
        // reset(quality = HD) on an SD-capped manager must re-clamp to SD,
        // not snap back up to HD.
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            initialQuality = StreamQuality.SD,
            maxQuality = StreamQuality.SD,
        )

        mgr.reset(quality = StreamQuality.HD)

        assertEquals(StreamQuality.SD, mgr.currentQuality)
    }

    @Test
    fun reset_clears_state() {
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = {})

        mgr.reportChunkUploadTime(4500)
        mgr.reportChunkUploadTime(4500)
        mgr.reset() // back to HD, counters cleared

        // Now only 2 more slow → still on HD
        mgr.reportChunkUploadTime(4500)
        mgr.reportChunkUploadTime(4500)

        assertEquals(StreamQuality.HD, mgr.currentQuality)
    }

    @Test
    fun negative_upload_time_is_ignored() {
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = {})

        repeat(10) { mgr.reportChunkUploadTime(-1) }

        assertEquals(StreamQuality.HD, mgr.currentQuality)
    }

    @Test
    fun downgrade_happens_only_once_per_three_ticks_window() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = { changes += it })

        // 3 slow → HD→SD (one event, since downgrade(HD)=SD)
        repeat(3) { mgr.reportChunkUploadTime(4500) }
        assertEquals(listOf(StreamQuality.SD), changes)

        // 3 more slow → SD→SD (no event, floor)
        repeat(3) { mgr.reportChunkUploadTime(4500) }
        assertEquals(listOf(StreamQuality.SD), changes)
    }

    // -------------------------------------------------------------------
    // Phase H2-B adaptive VBR↔CBR (2026-05-17) — backlog-driven mode ladder.
    // VBR is default ; switch to CBR at backlog ≥ 3 ; back to VBR at ≤ 1.
    // Cooldown 30 s between transitions.
    // -------------------------------------------------------------------

    @Test
    fun starts_in_VBR_by_default() {
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = {})
        assertEquals(ChunkEncoderBundle.BitrateMode.VBR, mgr.currentBitrateMode)
    }

    @Test
    fun mode_callback_null_disables_adaptation() {
        // Legacy CameraX path : no mode callback → setBacklog never
        // flips the mode even on heavy backlog. Ladder must short-circuit.
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            onBitrateModeChange = null,
        )

        mgr.setBacklog(20) // way above CBR threshold

        assertEquals(ChunkEncoderBundle.BitrateMode.VBR, mgr.currentBitrateMode)
    }

    @Test
    fun backlog_above_CBR_threshold_promotes_VBR_to_CBR() {
        val modes = mutableListOf<ChunkEncoderBundle.BitrateMode>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            onBitrateModeChange = { modes += it },
        )

        mgr.setBacklog(3) // equals threshold → fire

        assertEquals(ChunkEncoderBundle.BitrateMode.CBR, mgr.currentBitrateMode)
        assertEquals(listOf(ChunkEncoderBundle.BitrateMode.CBR), modes)
    }

    @Test
    fun backlog_below_threshold_does_not_promote() {
        val modes = mutableListOf<ChunkEncoderBundle.BitrateMode>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            onBitrateModeChange = { modes += it },
        )

        mgr.setBacklog(2) // below CBR threshold

        assertEquals(ChunkEncoderBundle.BitrateMode.VBR, mgr.currentBitrateMode)
        assertTrue("no mode change emitted", modes.isEmpty())
    }

    @Test
    fun once_CBR_backlog_at_two_keeps_CBR_hysteresis_band() {
        // No man's land at backlog == 2 : neither edge fires.
        val modes = mutableListOf<ChunkEncoderBundle.BitrateMode>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            onBitrateModeChange = { modes += it },
            initialBitrateMode = ChunkEncoderBundle.BitrateMode.CBR,
        )

        mgr.setBacklog(2)

        assertEquals(ChunkEncoderBundle.BitrateMode.CBR, mgr.currentBitrateMode)
        assertTrue("no transition mid-band", modes.isEmpty())
    }

    @Test
    fun forced_mode_skips_bitrate_mode_adaptation() {
        // Debug calibration path : mode ladder is also frozen alongside
        // the quality ladder.
        val modes = mutableListOf<ChunkEncoderBundle.BitrateMode>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            forced = true,
            onBitrateModeChange = { modes += it },
        )

        mgr.setBacklog(20)

        assertEquals(ChunkEncoderBundle.BitrateMode.VBR, mgr.currentBitrateMode)
        assertTrue("forced mode silenced the callback", modes.isEmpty())
    }

    // --- Phase 3.49 (2026-06-23) — network-recovery hint ---
    // onNetworkRecovered() clears the SLOW/FAST tick streak so the fresh
    // post-recovery samples decide the next transition, breaking the field
    // bug where the cap/quality stayed pinned low after a cellular→WiFi
    // switch. It must NOT force a step (hysteresis + BACKLOG_FREEZE stay in
    // charge) and must no-op in forced calibration mode.

    @Test
    fun on_network_recovered_clears_slow_streak() {
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = {})
        mgr.reportChunkUploadTime(4500) // slow 1 (ratio 0.90)
        mgr.reportChunkUploadTime(4500) // slow 2 (need 3 to downgrade)
        mgr.onNetworkRecovered()        // streak reset
        mgr.reportChunkUploadTime(4500) // fresh slow 1
        mgr.reportChunkUploadTime(4500) // fresh slow 2
        // Without the reset, 2+2 = 4 >= SLOW_HYSTERESIS would have stepped to
        // SD ; with it, only 2 fresh slow ticks → still HD.
        assertEquals(StreamQuality.HD, mgr.currentQuality)
    }

    @Test
    fun on_network_recovered_does_not_force_a_step() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.SD,
        )
        mgr.onNetworkRecovered()
        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertTrue("recovery hint never forces a transition", changes.isEmpty())
    }

    @Test
    fun forced_mode_ignores_network_recovery() {
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.SD,
            forced = true,
        )
        mgr.onNetworkRecovered()
        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertTrue("forced mode silences the recovery hint", changes.isEmpty())
    }

    @Test
    fun mode_cooldown_blocks_second_transition_within_30_s() {
        // Once a transition fires, lastBitrateModeTransitionMs is stamped.
        // A reverse-direction trigger immediately after must NOT fire
        // until BITRATE_MODE_COOLDOWN_MS has elapsed. We can't easily
        // mock System.currentTimeMillis here ; instead we verify that
        // back-to-back setBacklog calls produce only one transition.
        val modes = mutableListOf<ChunkEncoderBundle.BitrateMode>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = {},
            onBitrateModeChange = { modes += it },
        )

        mgr.setBacklog(3) // → CBR
        mgr.setBacklog(0) // would normally trigger CBR→VBR, but cooldown
        mgr.setBacklog(0)

        assertEquals(ChunkEncoderBundle.BitrateMode.CBR, mgr.currentBitrateMode)
        assertEquals(listOf(ChunkEncoderBundle.BitrateMode.CBR), modes)
    }

    // --- Phase H2-B.10 (2026-05-18) — anti yo-yo cooldown ---
    // Field-test 2026-05-18 Seeker session 19:58→20:28 observed ~20 cycles
    // `fast_hyst 720→1080` / `slow_hyst 1080→720` in 8 min. The cooldown
    // breaks the loop by forcing a 60 s gap between any two hysteresis
    // transitions (counters PRESERVED so reactivity post-cooldown is high).

    @Test
    fun hysteresis_cooldown_blocks_slow_hyst_after_fresh_fast_hyst_stepUp() {
        // 1. Start at SD so a stepUp is allowed (otherwise HD is the ceiling).
        // 2. 10 fast ticks → stepUp SD → HD (lastQualityTransitionMs stamped).
        // 3. 3 slow ticks immediately after should TRY to stepDown but be
        //    blocked by the 60 s cooldown — quality must stay HD.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(
            intervalMs,
            onQualityChange = { changes += it },
            initialQuality = StreamQuality.SD,
        )

        repeat(10) { mgr.reportChunkUploadTime(2000) } // ratio 0.40, fast
        assertEquals(StreamQuality.HD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.HD), changes)

        repeat(3) { mgr.reportChunkUploadTime(4500) } // ratio 0.90, slow

        assertEquals(StreamQuality.HD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.HD), changes) // still just one
    }

    @Test
    fun hysteresis_cooldown_blocks_fast_hyst_after_fresh_slow_hyst_stepDown() {
        // 1. 3 slow ticks → stepDown HD → SD.
        // 2. 10 fast ticks immediately after should TRY to stepUp but be
        //    blocked — quality must stay SD.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = { changes += it })

        repeat(3) { mgr.reportChunkUploadTime(4500) } // slow
        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.SD), changes)

        repeat(10) { mgr.reportChunkUploadTime(2000) } // fast

        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.SD), changes) // still just one
    }

    @Test
    fun forced_backlog_stamps_hysteresis_cooldown() {
        // A forced_backlog stepDown also stamps lastQualityTransitionMs,
        // so a subsequent fast_hyst stepUp respects the cooldown.
        // Without this, a recovery 10 chunks after an urgent downgrade
        // would immediately step back up, defeating the urgency signal.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = { changes += it })

        mgr.setBacklog(10) // > FORCE_DOWNGRADE_BACKLOG=6 → forced_backlog
        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.SD), changes)

        // 10 fast ticks should NOT stepUp because the cooldown is fresh
        repeat(10) { mgr.reportChunkUploadTime(2000) }

        assertEquals(StreamQuality.SD, mgr.currentQuality)
        assertEquals(listOf(StreamQuality.SD), changes)
    }

    @Test
    fun reset_clears_hysteresis_cooldown_so_first_transition_can_fire_again() {
        // After a session ends, reset() must clear the cooldown so the
        // next session can have its first hysteresis transition without
        // any artificial delay. Same expectation as the bitrate mode
        // cooldown.
        val changes = mutableListOf<StreamQuality>()
        val mgr = AdaptiveQualityManager(intervalMs, onQualityChange = { changes += it })

        repeat(3) { mgr.reportChunkUploadTime(4500) } // SD via slow_hyst
        assertEquals(StreamQuality.SD, mgr.currentQuality)

        mgr.reset() // back to defaults, cooldown wiped

        repeat(3) { mgr.reportChunkUploadTime(4500) } // can re-trigger immediately
        assertEquals(StreamQuality.SD, mgr.currentQuality)
        // 2 transitions total : HD→SD, then HD→SD again after reset
        assertEquals(listOf(StreamQuality.SD, StreamQuality.SD), changes)
    }
}
