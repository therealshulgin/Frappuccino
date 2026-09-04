package org.stream.crypto.capture

/**
 * Stream recording quality levels: resolution, bitrate target, and the
 * approximate per-chunk size at a 5-second interval. Lower = more resilient
 * on a flaky network (3G, congested Wi-Fi, low-bandwidth Tor exit) at the
 * cost of fewer pixels. See [AdaptiveQualityManager] for the runtime
 * auto-adjust logic.
 *
 * Keep this enum pure Kotlin, with no Android type in it — no
 * androidx.camera.video.Quality, no MediaCodec type. The module's unit
 * tests (StreamQualityTest, AdaptiveQualityManagerTest) run on a plain JVM,
 * and mapping a quality to a camera or codec type "right here in the enum,
 * where it belongs" is what would break them. There is no such mapping to
 * isolate today anyway: capture runs on MediaCodec rather than the CameraX
 * Recorder, and the translation to pixel dimensions lives with the consumer
 * (`StreamRecordingService.buildHevcVideoConfigFor`).
 *
 * The default is [HD] (720p) rather than the maximum: it uploads reliably
 * on most cellular networks while keeping faces and signage legible.
 */
enum class StreamQuality(
    val displayLabel: String,
    /**
     * Target video encoding bitrate in bits/s. Without an explicit cap,
     * CameraX picks aggressive defaults (FHD ~5-8 Mbps, HD ~3-5 Mbps) that
     * flood mobile uplinks and bloat .strm chunks beyond what the
     * AdaptiveQualityManager expects (~1 MB / 5 s at HD). Capping here
     * keeps the bitrate aligned with the doc'd targets : ~2 Mbps for FHD,
     * ~1 Mbps for HD, ~500 kbps for SD.
     */
    val targetBitrateBps: Int,
) {
    /**
     * These values sit above a hardware floor, they are not comfort
     * settings. The original caps of 500 kbps / 1 Mbps / 2 Mbps made the
     * Seeker's hardware encoder fail outright with ERROR_NO_VALID_DATA
     * (code 8) : below its operational floor it could not produce a single
     * valid frame inside the chunk window, so the outcome was lost
     * testimony, not a degraded picture. Revised upward after in-vivo
     * 2026-05-14. They still stay well under what the Seeker produces
     * uncapped — ~10 Mbps in HD, chunk #1 measured at 3.8 MB for 5 s —
     * while staying high enough not to trip the codec floor.
     */
    /** 1080p 30fps — ~2.5 MB / 5s chunk at 4 Mbps. */
    FHD("1080p", 4_000_000),

    /** 720p 24fps — ~1.25 MB / 5s chunk at 2 Mbps. Default. */
    HD("720p", 2_000_000),

    /** 480p 24fps — ~0.625 MB / 5s chunk at 1 Mbps. */
    SD("480p", 1_000_000);

    /** Step down one level. Floor at SD (no further degradation possible). */
    fun downgrade(): StreamQuality = when (this) {
        FHD -> HD
        HD -> SD
        SD -> SD
    }

    /** Step up one level. Ceiling at FHD. */
    fun upgrade(): StreamQuality = when (this) {
        SD -> HD
        HD -> FHD
        FHD -> FHD
    }

    /**
     * Height rank for ceiling/floor comparisons. The enum is DECLARED
     * high→low (FHD, HD, SD), so the built-in `ordinal` is the inverse of
     * visual quality; this explicit rank reads the natural way
     * (SD < HD < FHD).
     */
    val rank: Int
        get() = when (this) {
            SD -> 0
            HD -> 1
            FHD -> 2
        }

    /**
     * Clamp to a ceiling. Returns `this` when already at or below
     * [ceiling], else [ceiling]. Backs the user-configurable "max quality"
     * cap, so [AdaptiveQualityManager] never climbs above the operator's
     * chosen resolution (the adaptive ladder still drops BELOW the cap as
     * the network degrades).
     */
    fun coerceAtMost(ceiling: StreamQuality): StreamQuality =
        if (rank <= ceiling.rank) this else ceiling
}
