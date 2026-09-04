package rs.readahead.washington.mobile.util.jobs

import rs.readahead.washington.mobile.BuildConfig

/**
 * Runtime gate for the bbr [BbrSocketFactory]. Transport stopgap,
 * `docs/TRANSPORT_PLAN.md` (Phase 0a-2).
 *
 * Default ON in debug, OFF in release. The factory itself is installed only in
 * debug builds (see [UploadHttpClient]), so in release this is doubly inert —
 * either guard alone keeps the hook out: [BbrSocketFactory] returns on the
 * first line of its apply step when [enabled] is false, and with the factory
 * uninstalled no socket goes through it at all.
 *
 * The stopgap is best-effort and a no-op on devices without bbr (the Seeker:
 * `reno cubic`); it only helps bbr-capable kernels (OnePlus: `reno bbr cubic`),
 * which is why it is a partial interim measure and QUIC's userspace CC remains
 * the uniform fix.
 *
 * For the cubic-vs-bbr A/B on a bbr-capable device, flip [enabled] between
 * recording sessions, never during one: [BbrSocketFactory] re-reads the flag on
 * every connect, so a mid-session flip mixes both arms of the measurement.
 * Nothing in the repo ever assigns [enabled], so there is no toggle to press:
 * the switch is still to be added (a debug Settings toggle, or build-vs-build)
 * when the OnePlus is on the bench.
 */
object BbrStopgap {
    @Volatile
    var enabled: Boolean = BuildConfig.DEBUG
}
