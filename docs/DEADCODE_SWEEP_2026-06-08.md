# Dead-code sweep — JVM app (2026-06-08)

**Scope:** JVM modules only — `mobile`, `shared-ui`, `tella-vault`, `stream-crypto`. Strict definition of dead = **provably unreachable** (zero references after checking Hilt DI / UniFFI-JNA FFI / AndroidManifest / WorkManager-by-class / resources-by-name / reflection). `crypto-rs` (Rust) and `server` (Python) **out of scope**. Report-only; removals are gated, batch-by-batch, each = 1 commit + build (+ device smoke for field-critical).

**Method:** dynamic multi-agent workflow — Roots (entry-point + module-graph map) → Discover (8 agents over 152 files) → **adversarial Verify** (2 perspective-diverse skeptics per candidate, each trying to *refute* deadness) → Synthesize.

**Run note:** Run 1 fully serialized **34 confirmed-dead (2-skeptic)**. The resume that verified the remaining ~50 ran to completion but its assembled return did not serialize cleanly, so those ~50 are treated here as **discovery candidates to direct-verify before removal** (Android Lint `unusedResources` / targeted grep). Corroboration of accuracy: `PinPadView` and `CalculatorKeyView`, found dead by hand earlier, were both independently reconfirmed by the workflow.

---

## Batch 1 — DONE ✅ (`36b7080`)

- **`tella-vault` module** — 33 tracked files, −3272 lines. Off the build graph since Phase 5 (not in `settings.gradle`, no `project(':tella-vault')` dependency, zero live source refs). Verified 3 ways (2 skeptics risk=none + manual sweep + green build). No runtime change.

---

## Confirmed dead — 2-skeptic verified (run 1), ready to remove

### Batch 2a — mobile Tella leftovers (5 files)
| Item | Path |
|---|---|
| `C.java` (constants holder) | `mobile/.../util/C.java` |
| `Server.java` | `mobile/.../domain/entity/Server.java` |
| `ServerType.kt` | `mobile/.../domain/entity/ServerType.kt` |
| `Settings.java` | `mobile/.../domain/entity/Settings.java` |
| `PinPadView.kt` (dead PIN pad; live one = `PinLockView`) | `mobile/.../views/pin/PinPadView.kt` |

### Batch 2b — `mobile/util/Extensions.kt` dead extension functions (8, edit file — keep the live ones)
`invisible`, `show`, `configureAppBar`, `changeStatusColor`, `setCheckDrawable`, `navigateSafe`, `fitSystemWindows`, `setMargins`

### Batch 2c — shared-ui dead UI (≈20 files)
- **appbar:** `CollapsableAppBar`, `ToolbarComponent`
- **buttons:** `HomeButton`, `PanelToggleButton`
- **breadcrumb (whole pkg, 10):** `BreadcrumbsView`, `BreadcrumbsAdapter`, `BreadcrumbsCallback`, `BreadcrumbsDiffCallback`, `BreadcrumbsLayoutManager`, `BreadcrumbsUtil`, `DefaultBreadcrumbsCallback`, `ViewUtils`, `model/IBreadcrumbItem`, `model/Item`
- **pinview:** `CalculatorKeyView`, `CalculatorThemeStyle`, `ResultListener`
- **dropdownlist (whole pkg, 3):** `CustomDropdownList`, `DropdownListAdapter`, `DropDownItem`

> shared-ui is a library consumed by `mobile` → the build (`:mobile:assembleDebug`) is the safety net for each shared-ui removal.

---

## Discovery candidates — DIRECT-VERIFY before removal (resume increment not serialized)

### Batch 3 — dead resources (bulk, low risk — confirm with Android Lint `unusedResources`)
- **Drawables:** `countdown_0..5`, `{blue,green,orange,yellow}_skin_calculator`, `ic_menu_camera`, `frappuccino_white`, `blue_gradient_background`, shared-ui Tella icon set (≈18), camouflage drawables, drawables referenced only by dead styles/layouts. ⚠️ verify `frappuccino_icon` layer-list carefully (launcher).
- **Layouts:** shared-ui dead layouts (≈8), `calculator_keys_view`.
- **Menus:** `bottom_nav`.
- **Anim/animator:** mobile dead anims (≈7) + shared-ui slide_* (verify none are referenced by a live transition).
- **Font:** `roboto_regular`.
- **Colors:** mobile (≈9) + shared-ui (≈12) + selectors `bottom_nav_item_color`, `dialog_white_tint`.
- **Dimens:** mobile (≈32) + shared-ui (≈5).
- **Styles:** mobile (≈73) + `Calculator_*`.
- **Strings:** mobile (≈16), shared-ui (≈11), `Util_ellapsedTime_*` plurals (5), empty files `vault_strings.xml` / `consts.xml`. ⚠️ verify `stream_settings` ratchet/debug strings (3) — keep any still wired to the (kept) DEBUG section.

### Batch 4 — dead Gradle deps + dead methods
- Deps: `joda-time:joda-time:2.9.9`, `io.reactivex.rxjava2:rxandroid:2.1.1` (per §16; require refactoring `SharedPrefs`/`LocaleManager`/`Preferences.shouldShowImprovementBanner` first — defer).
- Methods: `LockTimeoutManager.getOptionsList()` + `getSelectedStringRes()` + the `settings.sec_lock_timeout_*` strings they reference (5).

### Batch 5 — orphan classes (direct-verify each)
`TopSheetBehavior`, `TopSheetUtils`, `SubmittedItem`, `SubmittingItem`, `TellaSwitchWithMessage`, `CenterMessageTextView`, `InfoSettingsView`, `CustomDropdownItemClickListener`, `CalculatorTheme`

### ⚠️ DO NOT TOUCH without FFI-aware verification — almost certainly LIVE false-positives
`signChallenge`, `signChallengeFull`, `rotateBatch`, `hasAv1HardwareEncoder` — these are core ratchet/auth FFI + server API + codec detection. Discovery flagged them because they look unreferenced from the Kotlin side, but they cross the UniFFI/JNA boundary. **Expected verdict: KEEP.** *(`getServerStatus` was REMOVED 2026-06-30, BT-05: its `/auth/v2/status` route is gone, and `authenticateV2`'s direct `get_status` probe — the actual runtime caller this list missed — was replaced by a local pending-enrollment check; the Rust/FFI/UDL `get_status` + CLI `protocol_probe --pk` were removed in the same sweep.)*

---

## Keep — audit/test/debug infra (preserved by design, never removed)
- All test code (`src/test`, `src/androidTest`, `src/androidTestRust`).
- The `— DEBUG (CALIBRATION) —` section + harness in `StreamSettingsActivity` (codec probe, HEVC/rolling tests, bitrate/aspect toggles) + the debug-raw capture paths — **kept, to be gated behind `BuildConfig.DEBUG` per roadmap §8.2.8**, not removed.
- `ShakeDetector`, `ChunkEncoderBundle`, `AdaptiveQualityManager`, the crypto FFI surface.

---

## Removal order
1. ✅ Batch 1 `tella-vault` (done, `36b7080`).
2. Batch 2a/2b/2c — confirmed-dead classes/methods (2-skeptic). Build between sub-batches.
3. Batch 3 — resources (gate on Android Lint `unusedResources`).
4. Batch 4 — dead methods now; deps after the rxjava/joda refactor.
5. Batch 5 — orphan classes (direct-verify each).
6. Re-confirm the crypto/FFI five are LIVE → document as KEEP.

Each removal batch: build `:mobile:assembleDebug` green before commit; no device smoke needed (none of these touch the camera/lock/auth/recording runtime paths — they're already-unreachable code).
