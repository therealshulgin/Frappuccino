# Frappuccino — Device Test Matrix & Reproducible Test Protocol
## ROADMAP audit item 8.1.4 — PLAN ONLY (pre-wide-release field-test cohort)

> ⚠️ **Ce plan date du 2026-05-31 et trois de ses prémisses ont changé depuis.** Le corps
> n'est pas réécrit - c'est un instantané - mais lisez-le avec ces corrections :
>
> - **Le `0.75` anamorphique n'est plus le facteur expédié.** Le mode livré dérive la
>   correction verticale des dimensions négociées (`rotatedSrcW / rotatedSrcH`) ; le mode
>   par défaut du réglage d'aspect active cette dérivation et ne lit jamais
>   `ANAMORPHIC_VSCALE`, qui n'est plus que la valeur initiale d'un mode de diagnostic. La
>   règle de décision du §4.2 (« si le facteur n'est pas constant, passer en dérivation du
>   HAL ») a donc **déjà été exécutée**. Ce qui reste à mesurer sur un parc large, c'est
>   que la dérivation tient sur des HAL non testés, pas qu'un fudge constant tienne.
> - **Le toggle `useHevcPipeline` n'existe plus** : le pipeline legacy a été retiré, le
>   wedge GL/MediaCodec est le seul chemin, donc il est exercé par tout enregistrement.
> - **`pin_store_seal` n'est plus un export FFI** (retiré le 2026-09-03, faute d'appelant
>   Kotlin). Le protocole d'onboarding du §Protocol doit s'observer par son effet - une
>   identité scellée, pas de `mlock failed` ni de `DerivationFailed` - et non en guettant
>   ce nom d'appel.

**Status:** Plan. The deliverable is the *matrix + protocol a field-tester cohort runs*, not results. Today only 2 physical devices are on hand (Seeker MTK + OnePlus 13 SD8 Gen 3).
**Date:** 2026-05-31 · **Tip:** worktree `xenodochial-morse` (`d84ee2b`) · **Toggle under test:** `useHevcPipeline` (default OFF; the GL/MediaCodec wedge is exercised only when ON).
**Scope note / correction vs intake brief:** The intake hypotheses repeatedly asserted that `ArchiveDownloadService` is *not declared in the manifest* and called it a P0 blocker. **This is false as of this tip.** `mobile/src/main/AndroidManifest.xml` declares **both** services with correct types — `StreamRecordingService` `foregroundServiceType="camera|microphone"` (line 117-119) and `ArchiveDownloadService` `foregroundServiceType="dataSync"` (line 120-123) — and `ArchiveDownloadService` already holds `FOREGROUND_SERVICE_TYPE_DATA_SYNC` + `WifiLock` HIGH_PERF + PARTIAL_WAKE_LOCK (Phase 4.4.8). The one **genuine** residual manifest/runtime gap is **`POST_NOTIFICATIONS`** (absent from the manifest, never requested at runtime; minSdk=21 / targetSdk=34). The protocol below tests the real gap, not the phantom one.

---

## 1. Scope & Intent

**Goal:** de-risk a *wide* release across the Android ecosystem. Two devices proved the pipeline works on **one** MediaTek and **one** Qualcomm SoC; they cannot tell us whether the most device-coupled parts survive other HALs, GPU drivers, OEM skins, and OS versions.

**The two things that scare us most** (detailed in §4):
1. **The GL ES → MediaCodec capture wedge across HALs/GPU drivers.** EGL surface creation, `EGL_RECORDABLE_ANDROID`, `EGL_NO_SURFACE` rebinding, and hardware-HEVC availability are all driver/SoC-specific. We have a PBuffer fallback (H2-B.12) and an HEVC→H.264 fallback (H2-B.17) precisely because we already hit driver-specific breakage on one device.
2. **The empirical `0.75` anamorphic vertical correction** (`ANAMORPHIC_VSCALE = 0.75f`, `GlVideoPipeline.kt:864`). It is a *measured fudge*, validated objectively on exactly **one** device geometry (OnePlus 13, cv2 `h/w=0.996`). Its root cause is undiagnosed (suspected HAL crop / multi-cam-zoom squeeze of 4:3↔9:16). A different sensor/HAL may squish by a *different* factor or not at all — meaning `0.75` could **over- or under-correct** and ship visibly-distorted video to users we never tested.

**What "covered" means today:**

| | MediaTek | Qualcomm |
|---|---|---|
| **Covered by on-hand device** | Seeker (Helio-class MTK, activeArray **4000×3000**, default `aeFpsRange 5..30`) | OnePlus 13 (Snapdragon 8 Gen 3, activeArray **4096×3072**, default `aeFpsRange 15..30`) |
| **Android version** | ~11–12 | ~14–15 |
| **Pipeline path validated** | HEVC GL wedge + H.264 fallback | HEVC GL wedge + H.264 fallback |

Everything outside those two cells is **unverified** for the HAL-coupled axes.

**Out of scope for this plan:** server-side behavior, crypto correctness, upload-protocol semantics (those are covered by other 8.1.x items and existing field tests). This item is the **device fleet**.

---

## 2. The Device Matrix

### 2.1 The full problem space (why a cartesian product is the wrong answer)

The naive matrix is `{Samsung, Pixel, Xiaomi, low-end, old} × {MediaTek, Qualcomm} × {Android 8, 10, 12, 13, 14} × {HEVC, H.264}` = up to **100 configurations**. That is neither affordable nor necessary: many cells are redundant (H.264 path is largely OS/OEM-independent; Android 8 and 10 differ less than 8-vs-13 for our risks; Exynos vs Qualcomm-Samsung is the real Samsung fork, not "Samsung" as a brand).

We instead **bin by the dimension that actually moves our failure modes** (GPU driver family + HAL camera stack + FGS/notification OS tier) and pick a short list that maximizes *distinct risk coverage per device*.

### 2.2 Risk-coverage axes that each device must be chosen to exercise

- **GPU/driver family:** Adreno (Qualcomm) ✅ covered · **Mali** (MediaTek Dimensity, Exynos, Kirin) ⚠️ *partially* — Seeker is MTK but we have not confirmed its GPU is Mali vs PowerVR · **PowerVR / Img** ❌ uncovered.
- **Camera HAL geometry** (the 0.75 risk): each new sensor/HAL combo is a fresh data point. Front cameras and multi-cam-zoom wrappers (Xiaomi, Samsung) are the highest-variance.
- **OS FGS/notification tier:** API ≤25 (no FGS type, no runtime notif) · API 28-30 (FGS, scoped storage begins, Doze enforced) · API 31-32 (FGS type mandatory, 5 s `ForegroundServiceDidNotStartInTimeException`) · **API 33+** (POST_NOTIFICATIONS runtime — our real gap).
- **OEM background-killer aggressiveness:** Stock/Pixel (lenient) · OnePlus/Oppo ColorOS ✅ · **Samsung One UI** ❌ · **Xiaomi MIUI/HyperOS** ❌ (both notoriously aggressive; MIUI also routes battery-exemption to a hidden menu).
- **Form factor / density** (onboarding usability): small/low-dpi, very-high-dpi, notch/cutout.

### 2.3 PRIORITIZED SHORT LIST (~7 devices to acquire/borrow)

Ordered by risk-coverage-per-dollar. Acquire top-down; stop when budget runs out — the first 4 buy down ~80% of the risk.

| # | Device class | SoC / GPU | Android tier to target | Why this device (distinct risk it covers) | Est. cost (used) |
|---|---|---|---|---|---|
| **1** | **Samsung Galaxy A-series mid** (e.g. A54/A34) | **Exynos + Mali** | **13/14** | Mali GPU driver (EGL recovery, PBuffer) + One UI aggressive Doze killer + **fresh HAL geometry** (Exynos camera stack) + API 33+ POST_NOTIFICATIONS. Single highest-value add: 4 distinct risks. | $$ |
| **2** | **Xiaomi / Redmi mid** (e.g. Redmi Note 13 / Poco) | **MediaTek Dimensity + Mali** (or SD + Adreno variant — pick the MTK SKU) | **13/14** | MIUI/HyperOS killer (worst-case background survival) + battery-exemption hidden-menu flow + **multi-cam-zoom wrapper** (top suspect for a *different* anamorphic factor) + Mali. | $$ |
| **3** | **Google Pixel** (e.g. Pixel 6a/7a, Tensor) | **Tensor + Mali** | **14 (and updatable to latest)** | Reference/"clean" Android baseline to **isolate OEM-skin effects from OS effects**; GCam-tuned HAL = another distinct geometry; canary for newest API behavior. | $$ |
| **4** | **Cheap / low-end current** (e.g. Moto G / Samsung A0x / Redmi A-series) | **entry MediaTek Helio A/G or SD 4-gen, low RAM, often Mali/PowerVR** | **12/13** | Weakest GPU driver + possible **software-only HEVC** (forces the H.264-fallback path in the field) + small RAM (largeHeap pressure) + small/low-dpi screen for onboarding layout. | $ |
| **5** | **Old device** (5–7 yrs, e.g. Pixel 2 / Galaxy S8 / a Helio-P) | older Adreno **or** Mali, **PowerVR** if obtainable | **8 or 10** | Legacy EGL driver + **pre-FGS-type / pre-runtime-notif** permission model + scoped-storage boundary (API 29) + 32-bit-capable (armeabi-v7a `.so`). Tests the *floor* of minSdk=21. | $ |
| **6** | **Second Qualcomm, non-OnePlus** (e.g. Motorola/Asus SD 7-/8-gen) | Adreno | **12** | Confirms Adreno findings generalize beyond OxygenOS; isolates "Adreno" from "OnePlus". | $$ |
| **7 (opt.)** | **x86_64 emulator / ChromeOS** | host CPU | **10–14 (API 29-34)** | Free. Validates the **x86_64 `.so` ABI** (never field-tested) + reduced-syscall `mlock` behavior. Not a substitute for a phone but catches ABI/link regressions in CI. | free |

**Already on hand (do not re-buy):** Seeker (MTK, Android ~11-12) and OnePlus 13 (Adreno/SD8Gen3, Android ~14-15). Between them they cover the **Adreno + OxygenOS** and **one-MTK** cells and the HEVC+H.264 paths.

**Coverage after the short list (target):**

| Risk dimension | Covered by |
|---|---|
| Adreno GPU | OnePlus 13 ✅, device #6 |
| Mali GPU | #1 Samsung, #2 Xiaomi, #3 Pixel |
| PowerVR GPU | #4 / #5 (best-effort — hardest to source) |
| Software-only HEVC → forces H.264 path | #4 cheap, #5 old |
| Multi-cam-zoom anamorphic variance | #2 Xiaomi, #1 Samsung, plus front cams everywhere |
| Samsung One UI killer | #1 |
| Xiaomi MIUI killer + hidden battery menu | #2 |
| API 33+ POST_NOTIFICATIONS | #1, #2, #3 |
| Pre-FGS-type / pre-runtime-notif (≤API 30) | #5 old |
| Scoped-storage boundary (API 29) | #5 (and #4 if API 29-shipped) |
| armeabi-v7a 32-bit `.so` | #5 |
| x86_64 `.so` | #7 emulator |
| Small/low-dpi + notch onboarding | #4 + any notched unit |

---

## 3. Per-Axis Test Protocol (a tester can run cold)

**Universal pre-flight (every device, once):**
```
# Identify the device — record this in the result sheet header
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release   # Android version
adb shell getprop ro.build.version.sdk       # API level
adb shell dumpsys media.camera | grep -iE "activeArray|pixelArray|facing"   # sensor geometry
adb shell getprop ro.hardware.egl ; adb shell dumpsys SurfaceFlinger | grep -i "GLES"   # GPU/driver
# Install + clean state
adb install -r frappuccino-debug.apk
adb shell pm path org.hzontal.tellaFOSS    # CONFIRM install (gradlew installDebug lies on Seeker)
adb shell pm clear org.hzontal.tellaFOSS
# Confirm the .so for THIS abi is present
adb shell run-as org.hzontal.tellaFOSS ls -la lib/ 2>/dev/null || \
  adb shell ls -la /data/app/*/org.hzontal.tellaFOSS*/lib/*/ | grep libuniffi
```
**Build:** install **two** builds per device — one with `useHevcPipeline=true` (GL wedge, P0/P1 capture axes) and one with it `false` (legacy CameraX H.264, for the fallback-vs-native A/B). Where a `debug_raw` (unencrypted, fixed-bitrate-off) build exists, use it for cv2 frame analysis (mémoire: cut BITRATE FIXE ⇒ debug_raw NOT encrypted).

**Tag filter used throughout:**
```
adb logcat -v threadtime -s StreamMetrics StreamRecordingService ArchiveDownloadService \
  GlVideoPipeline HevcMediaCodecEncoder RollingChunkRecorder | tee device_<MODEL>_<api>.log
```

---

### GROUP P0 — release-blocking

---

#### AXIS P0-A — GL ES + MediaCodec encoder + surface multiplexer (HEVC capture wedge)
*(Highest-risk — see §4.1 for the deep dive; this is the runnable protocol.)*

**Why device-dependent (short):** EGL context creation, `EGL_RECORDABLE_ANDROID` (0x3142), `EGL_NO_SURFACE` rebinding, hardware-HEVC availability, and surface color-format acceptance are all GPU-driver/SoC-specific.

**Setup:** HEVC build installed; logcat tee running; if testing the MTK dark-throttle sub-case, room <30 lux.

**Phase 1 — encoder init.** Launch → record 15 s → stop.
- Capture: `hevcEncoderInit component=… bitrateRange=[…]`; `glPipelineStart w=… h=…`; EGL/PBuffer creation lines.
- **PASS:** component is vendor-prefixed (`c2.qti.*`, `c2.mtk.*`, `c2.exynos.*`, `c2.imgtec.*`) — **not** `c2.android.*` (software); no EGL ERROR/WARN; encoder dims = expected resolution.
- **FAIL signatures:** `eglCreateWindowSurface failed`; `eglMakeCurrent EGL_BAD_MATCH`; `component=c2.android.hevc` (no hw HEVC → device belongs in the H.264-fallback cohort); `ExceptionInInitializerError`.

**Phase 2 — AE/fps stability (overlaps P0-C, run once, score both).** Record 30 s lit → switch to dark mid-record → back to lit → stop.
- Capture: `glFrameRate fps=…` every 5 s; `deviceTelemetry thermal=… aeFpsRange=…`.
- **PASS:** fps never sustained <24 in dark; no >200 ms hiccup on light change. (`Range(24,30)` is forced at `StreamRecordingService.kt:909-911`.)
- **FAIL:** fps floor drops to ~5–10 in dark → HAL ignoring the forced AE range.

**Phase 3 — HEVC error → H.264 fallback.** Record 5 rolling chunks (≈25 s). If a test-harness build is available, inject a `CodecException` in the HEVC drain loop; otherwise rely on devices that fail HEVC naturally.
- Capture: `hevcCodecError`; `hevcFallbackScheduled fromMime=video/hevc toMime=video/avc`; `rollingSwapConfig newSeq=…`; verify no zero-byte/truncated MP4 in chunk dir.
- **PASS:** first error triggers fallback; subsequent chunks are valid H.264; the in-flight chunk is still delivered via `onChunkReady`; one-shot guard (`hevcFallbackAttempted`) prevents a loop.
- **FAIL:** both HEVC *and* H.264 fail (second `hevcCodecError` with `attemptedFallback=true`) → unbounded data loss on that device.

**Phase 4 — anamorphic + preview geometry (overlaps P0-B / §4.2).** Enable preview SurfaceView; record 10 s with a **round physical reference** (coin/ball/clock) held perpendicular, then tilt to prove it's 3-D not a flat image.
- Capture: `previewCoverFitDims … contentRatio=… viewportRatio=…` (`GlVideoPipeline.kt:629-638`); `previewStMatrix col0=… col1=…`; then `ffprobe -show_entries stream=width,height,r_frame_rate chunk.mp4`.
- **PASS:** see §4.2 cv2 thresholds.
- **FAIL:** see §4.2.

**Phase 5 — EGL surface swap (rolling chunks).** Rolling 5 s chunks; record 30 s (6 chunks).
- Capture: `glFrameRate` max `maxEncSwapMs` / `maxPreviewSwapMs`; `glPipelineSwapSurface ok`.
- **PASS:** `maxEncSwapMs ≤ 5 ms` (H2-B.4 target); no frame gap at boundaries.
- **FAIL:** `maxEncSwapMs > 10 ms` sustained (marginal driver / contention); `glPipelineSwapSurface failed` (new Surface rejected mid-swap → recording stops).

**Phase 6 — FGS + wake-lock, screen-off.** Record → screen off 10 s → screen on → stop.
- Capture: `dumpsys power | grep mWakeLocks` shows `frappuccino:stream`; no `Service.startForeground()` error; no MediaCodec error during the dark window; MP4 has no gap across it.
- **PASS:** recording continues uninterrupted; chunk finalizes cleanly on resume.

**Priority:** **P0.**

---

#### AXIS P0-C — AE/fps ranges + thermal throttling under sustained recording
**Why device-dependent:** HAL AE target-fps defaults differ (MTK `5..30`, SD8Gen3 `15..30`) and the HAL may throttle lower in dark scenes; thermal response is OEM-specific. We force `Range(24,30)` but OEMs may honor it differently. Code: `StreamRecordingService.kt:909-911` (force) and `:1663-1665` (re-apply across quality swaps); telemetry `deviceTelemetry thermal=%s aeFpsRange=%s` at `:445`.

**Setup:** battery ≥80%; background apps cleared; HEVC build; baseline `adb shell dumpsys thermalservice` and (if exposed) `cat /sys/class/thermal/thermal_zone*/temp`.

**Action:** record **continuously 60 min**, one run per condition: (a) daylight >500 lux, (b) dark <10 lux, (c) thermal stress (record + a CPU-burn loop to push thermal MODERATE/SEVERE).

**Capture:** every 30 s log `deviceTelemetry thermal=X aeFpsRange=Y..Z` + `glFrameRate fps=…`; snapshot thermal at 10/20/40/60 min; record per-chunk file sizes (`onChunkReady`).

**Expected pass:**
- `aeFpsRange` lower bound stays ≥24 for ≥95% of 60 min; transient dips <15 s tolerated.
- Computed fps ≥22 for ≥95%.
- Chunk sizes within ±15% after warm-up.
- Thermal NONE→MODERATE/SEVERE must **not** by itself drop the fps floor (the contract is in code design, not test tolerance).

**Failure signatures:**
- AE floor ≤10 fps for >15 s in daylight/normal-thermal → HAL ignoring `Range(24,30)`.
- AE floor drops to `[5,30]`/`[15,30]` the instant thermal enters MODERATE → OEM thermal policy overrides Camera2 request.
- Chunk size drops >20% in a single 5-min window with no quality-pref change → encoder starved by silent fps drop.
- `aeFpsRange` stuck at HAL default (`[5,30]`/`[15,30]`) → `setCaptureRequestOption` silently no-op'd on this firmware.
- Dark scene floor <24 fps even though code intends 24 as "perceived-fluid floor."
- MP4 glitch/stutter/AV-desync despite stable logged fps → muxer PTS skew (timestamp sourced from `SurfaceTexture` `CLOCK_BOOTTIME` may skew on long sessions).

**Priority:** **P0.**

---

#### AXIS P0-D — Screen-off Doze / OEM background kill
**Why device-dependent:** OEM battery policies vary wildly (OnePlus/Samsung/Xiaomi aggressive). Field evidence: `no_auth_token` spikes on OnePlus 13 traced to screen-off teardown (root-caused & fixed: Phase 1.14 + H2-B.16 `isShuttingDown`; download survival fixed by `WifiLock` HIGH_PERF in Phase 4.4.8, `ArchiveDownloadService.kt:113-126`).

**Variations:** Seeker MTK · OnePlus 13 · **Samsung One UI** · **Xiaomi MIUI/HyperOS** — each with battery-optimization exemption **granted** *and* a second pass with it **denied** (worst case).

**Protocol — recording leg:** grant battery exemption when prompted → unlock → REC → confirm FGS (`dumpsys activity services | grep StreamRecordingService`) → **user powers screen OFF** → wait ≥5 min (≥30 min for the killer-OEMs) → user powers ON → stop. **Archive leg:** unlock → "TOUT TÉLÉCHARGER" a multi-chunk report → confirm `ArchiveDownloadService` FGS + `dumpsys wifi | grep -i "WiFi locks"` shows `frappuccino:archive-wifi` → screen OFF → wait → ON → verify download completed, no "Stoppé".

**Capture:** `dumpsys power | grep mWakeLocks` (PARTIAL_WAKE_LOCK held); `dumpsys deviceidle | grep -i whitelist` (exemption state); logcat for `Killing … org.hzontal` (adj 2 empty) and for `no_auth_token` / `circuit_open`.

**Expected pass:** counters keep incrementing across the dark window; no app kill; recording gapless; download completes; **zero `no_auth_token`**.

**Failure signatures:** `no_auth_token` spike · `circuit_open` · auth holder empty · `WifiLock held=false` during download · FGS timeout · `Killing … (adj 2): empty for Xms`.

**Priority:** **P0.**

---

#### AXIS P0-E — Foreground-service types + Android 13/14 FGS & notification restrictions
**Why device-dependent:** API 31+ enforces FGS type + 5 s `ForegroundServiceDidNotStartInTimeException`; API 33+ requires runtime `POST_NOTIFICATIONS`. **Verified state at this tip:** both services declared with correct types (manifest 117-123); `startForeground` is called first in both `onStartCommand`s with try/catch→`stopSelf` on `ForegroundServiceStartNotAllowed`; channels are IMPORTANCE_LOW. **Genuine gap:** `POST_NOTIFICATIONS` is **not** in the manifest and **not** requested at runtime (the runtime request flow only asks CAMERA + RECORD_AUDIO). On API 33+ the FGS still runs but its notification can be silently suppressed. *(A spin-off task to add the permission + runtime request has been filed.)*

**Protocol:**
1. **FGS launch latency (both services):** `adb logcat -c` → tap REC → grep `startForeground|ForegroundServiceDidNotStartInTimeException`. **PASS:** "startForeground OK" <5 s, no crash. Repeat for "TOUT TÉLÉCHARGER" → `ArchiveDownloadService`.
2. **API 33+ notification gap:** `adb shell pm revoke org.hzontal.tellaFOSS android.permission.POST_NOTIFICATIONS` → start recording → `adb shell cmd notification list | grep -i frapp`. **Document:** is the FGS notification visible? **Current expected (pre-fix):** notification may be **absent** while the service still records — this is the gap to close, log it explicitly. **No `SecurityException` should crash the service.**
3. **Re-entrant REC (debounce):** tap REC then within <800 ms tap to stop, wait 500 ms, REC again. **PASS:** debounce + `isStopping`/`isShuttingDown` block concurrent `startForegroundService`; no `ForegroundServiceDidNotStartInTimeException`.
4. **Doze exemption prompt (API 23+):** first REC on a fresh install → system "ignore battery optimization?" dialog appears → Allow → `dumpsys deviceidle | grep -i whitelist` shows the package. **FAIL:** dialog never appears, or Allow doesn't actually whitelist.
5. **`RECEIVER_NOT_EXPORTED` (API 33+):** broadcasts in `ArchiveModeActivity` must register with the not-exported flag; **FAIL** = runtime exception on register.

**Failure signatures:** `ForegroundServiceDidNotStartInTimeException`; `ForegroundServiceStartNotAllowed` then recording doesn't start; FGS notification silently absent on API 33+ (the known gap); PARTIAL_WAKE_LOCK / WifiLock not held; `isShuttingDown` race → `no_auth_token` loop; NPE in `buildNotification` fallback.

**Priority:** **P0.**

---

#### AXIS P0-F — Runtime permissions + onboarding across Android versions & screen sizes
**Why device-dependent:** permission UI/timing varies (API 23 vs 33/34); battery-exemption dialog is OEM-intercepted (Samsung/Xiaomi route to hidden menus); `POST_NOTIFICATIONS` runtime only on 33+; scoped storage (API 29) changes archive-rescue file paths; onboarding layout uses percent-height ConstraintLayout (`PinLockView height_percent=0.45`) that scales badly on tiny / very-high-dpi / notched screens; onboarding has **4 PINs** + a **BIP-39** French mnemonic.

**Protocol (in order):**
- **A. First-launch perms:** clear state → tap REC → confirm `requestPermissions([CAMERA, RECORD_AUDIO])` (**both**) → grant → recording proceeds. **FAIL:** only one perm asked; or deny → recording starts but audio/video missing → chunk encryption fails.
- **B. Battery-exemption dialog:** appears with Configurer/Plus tard → Configurer launches `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` → Allow → `dumpsys deviceidle` confirms. **FAIL:** OEM throws/no dialog (catch path), or Xiaomi routes to MIUI permission center (user can't find it).
- **C. FGS startup:** covered in P0-E.
- **D. POST_NOTIFICATIONS (API 33+):** covered in P0-E item 2.
- **E. Onboarding PIN flow:** uninstall→reinstall → walk the 4-PIN sequence → BIP-39 12-word FR generate/confirm. **PASS:** ÉTAPE 1/2 → enter 6 digits → CONFIRM step → match → next fragment. **FAIL:** "Retour" button off-screen on small displays (height_percent 0.45 + absolute 64dp top margin); PIN mismatch not flagged; CharArray mnemonic not wiped on an exception path.
- **F. Scoped storage archive rescue (API 29+):** download a small report → file lands in `Downloads/Frappuccino/…mp4` via MediaStore without legacy WRITE perm; survives 30 s screen-off (WifiLock). 
- **G. Screen size/density:** run onboarding on small/low-dpi, very-high-dpi, tablet, and notched units; `dumpsys display | grep -E "Width|Height|Density"`; screenshot to verify nothing clipped/off-screen/under-notch.
- **H. OEM permission-dialog variants:** stock vs One UI vs ColorOS vs MIUI — `getprop ro.build.fingerprint`, screenshot each; behavior must stay consistent (grant→record, deny→toast+fail).

**Failure signatures (priority-tagged):**
- **P0:** onboarding buttons off-frame on <4.6″ screens → user can't finish PIN setup.
- **P0:** `POST_NOTIFICATIONS` missing on 33+ → FGS notification suppressed (known gap; fix filed).
- **P1:** battery dialog never appears / exemption not actually applied → screen-off upload stall.
- **P1:** only one of CAMERA/RECORD_AUDIO requested.
- **P1:** CharArray mnemonic not wiped on exception → secret lingers in heap.
- **P1:** MIUI/One UI hidden-menu routing → silent setup failure.
- **P1:** scoped-storage archive write fails on API 29+.
- **P2:** PIN keypad text size too small/large at xxxhdpi.
- **P2:** wordmark clipped under notch.

**Priority:** **P0** (onboarding/permission blockers) with P1/P2 sub-items as tagged.

---

### GROUP P1 — important, not strictly release-blocking

---

#### AXIS P1-B — Aspect ratio / sensor geometry / the 0.75 anamorphic correction
*(Co-highest-risk — full measurement protocol in §4.2; summarized here for grouping.)* **Priority P1** as an axis but it gates "looks-right video," so a hard failure here blocks release for the affected device class. See §4.2.

---

#### AXIS P1-G — Rust `.so` load across ABI + Android version
**Why device-dependent:** `libuniffi_frappuccino.so` is per-ABI (arm64-v8a / armeabi-v7a / x86_64), built at `--platform 21`; JNA dispatches on runtime ABI (mismatch → `UnsatisfiedLinkError`); `mlock` (`memsec::mlock`, `crypto-rs/core/src/secret.rs`) depends on kernel + `RLIMIT_MEMLOCK` (Knox/locked-down kernels may cap it, failing `LockedSecret::new_zeroed` → `CryptoError::DerivationFailed`); SELinux/file-perm differences across OS versions. ⚠️ The arm64 `.so` is gitignored and was rebuilt 2026-05-31 (was stale 05-19 vs `pin.rs` 05-24) — **ensure the cohort build embeds a current `.so`**, and watch for stale-SPKI TLS pin failures as a tell.

**Setup:** confirm the right ABI `.so` is in the APK: `adb shell unzip -l app.apk | grep libuniffi` (or the `lib/<abi>/` listing from pre-flight).

**Protocol:**
1. **Smoke test:** `adb shell am instrument -w -r org.hzontal.tellaFOSS.test/androidx.test.runner.AndroidJUnitRunner org.stream.crypto.rust.RustSmokeTest` → expect `hello_world()` + non-empty `core_version()`. **(Run this on the x86_64 emulator #7 and the 32-bit old device #5 — neither ABI has ever been field-tested.)**
2. **Onboarding crypto:** generate mnemonic (`bip39_generate_fr`) + set a PIN through the onboarding screens → watch for `mlock failed` / `DerivationFailed`. Observe the *effect*, a sealed identity: `pin_store_seal` is no longer an FFI export (removed 2026-09-03), so grepping for that call name will find nothing.
3. **Record 10 s** → `dumpsys meminfo | grep libuniffi` (resident, no SIGSEGV).
4. **Archive auth+decrypt** (if test server reachable) → no heap exposure, no TLS pin error.

**Failure signatures:** `UnsatisfiedLinkError: …libuniffi_frappuccino.so` (wrong/missing ABI); `mlock failed — RLIMIT_MEMLOCK`; `CryptoError::DerivationFailed`; SIGSEGV in the `.so`; `UniFFI API checksum mismatch` (bindings/`.so` skew — the stale-`.so` tell); `ExceptionInInitializerError`; ANR during Argon2id on a capped-mlock kernel; `dlopen EPERM/EACCES` (SELinux); Rust panic backtrace; `FfiError::Network: tls: rustls error` (stale-SPKI pin in an old `.so`).

**Priority:** **P1** (arm64 already proven on both on-hand devices; risk is the *untested* ABIs/kernels — emulator + old/cheap units).

---

## 4. The Two Highest-Risk Axes (called out explicitly)

### 4.1 (a) The GL/MediaCodec wedge across HALs — *why it's the #1 risk*

The capture pipeline does something CameraX alone cannot: it inserts a **GL ES surface multiplexer** between the camera and a **MediaCodec** HEVC encoder so we get true codec/bitrate control and a tear-free rolling-chunk swap. Every layer of that is driver-coupled:

- **EGL config + `EGL_RECORDABLE_ANDROID` (0x3142)** must be accepted as a MediaCodec-input config; some drivers don't advertise it cleanly.
- **`EGL_NO_SURFACE` detach** corrupts context state on Adreno-legacy and some Mali — which is *exactly* why **PBuffer fallback** exists (H2-B.12). We have direct evidence one device needed it; we don't know how many others do.
- **Hardware HEVC** is not guaranteed: a device may *list* HEVC but fail at runtime (stale C2 vendor blobs on older MTK/Samsung-A), which is why **HEVC→H.264 runtime fallback** exists (H2-B.17). On a software-only-HEVC device the fallback is the *only* viable path and must be exercised.
- **Surface color-format** acceptance of raw sensor buffers (`COLOR_FormatSurface`) is what failed on the original MTK H1 (`endConfigure: Unsupported set of inputs/outputs`).

**Why two devices are not enough:** we have Adreno (OnePlus) and one MTK (Seeker). We have **zero** confirmed Mali, **zero** PowerVR, **zero** software-only-HEVC, and **zero** legacy-EGL coverage. A single un-handled driver quirk = a black/green/torn recording or a hard recording-stop for an entire SoC family.

**Run:** AXIS P0-A in full on devices #1 (Mali/Exynos), #2 (Mali/MTK-Dimensity), #4 (weak driver / sw-HEVC), #5 (legacy EGL). The fallback paths (PBuffer, H.264) are the *features under test* here — a device that *needs* a fallback and gets it cleanly is a **pass**; a device that needs one and still breaks is the finding.

### 4.2 (b) The empirical `0.75` anamorphic aspect fudge — *validated on ONE device*

`ANAMORPHIC_VSCALE = 0.75f` (`GlVideoPipeline.kt:864`) multiplies the vertical scale in `drawFullscreenQuad` (`scaleY = (fitMag/magY) * ANAMORPHIC_VSCALE * ZOOM_IN`, line 797; `ZOOM_IN = 1.2f`, line 869). It exists to undo a **~1.33× vertical stretch** the HAL bakes into the buffer (a 16:9-encoded frame read as 4:3), and it is applied to **both** the encoder and preview passes. Its root cause is **undiagnosed** (mémoire: signature of a 4:3↔9:16 squeeze; suspects = `setDefaultBufferSize` not reconciled to negotiated resolution, or a `RATIO_4_3` request ignored by the HAL). The juge-de-paix datum is `contentRatio` logged at `GlVideoPipeline.kt:629` (this is the "hevcPreviewNegotiated" value: `rotSrcW/rotSrcH` → ~1.778 means our request was ignored, ~1.333 means HAL squeeze).

**The danger:** `0.75` was tuned to `h/w=0.996` on **one** geometry (OnePlus 13, 4096×3072). A different HAL might squeeze by 1.2× or 1.5× — or not at all — in which case `0.75` ships **over- or under-corrected** (eggs and ovals) to users we never tested. This is the most likely "looks broken on a phone we don't own" failure.

**Measurement protocol (the cv2 / cropdetect / metrics datum, runnable cold):**

*Capture on device:*
1. Use the `debug_raw` (unencrypted, fixed-bitrate-off) build so frames are directly analyzable.
2. Film a **perfectly round physical object** (coin/ball/clock face, ~10 cm) filling ~60% of frame, perpendicular, steady 5 s; then **tilt it** to prove it's a 3-D object (perspective ≠ anamorphic). Then film a **16:9 reference card** (SMPTE bars) for 5 s. Airplane mode, brightness fixed.
3. Grab the metrics line:
```
adb logcat -s StreamMetrics | grep -E "previewCoverFitDims|previewStMatrix|drawFullscreenQuad"
# record contentRatio, viewportRatio, the 16-float stMatrix, and effective GL viewport
```
4. Pull the chunk and measure offline:
```python
import cv2
cap = cv2.VideoCapture('chunk.mp4'); frames=[]
while True:
    ok,f = cap.read()
    if not ok: break
    frames.append(f)
cap.release()
for i in (10,20,30):                      # round-object frames
    g = cv2.cvtColor(frames[i], cv2.COLOR_BGR2GRAY)
    _,b = cv2.threshold(g,100,255,cv2.THRESH_BINARY)
    cnts,_ = cv2.findContours(b, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    c = max(cnts, key=cv2.contourArea)
    (cx,cy),(w,h),ang = cv2.fitEllipse(c)
    print(f"frame {i}: w={w:.1f} h={h:.1f}  h/w={h/w:.3f}")
```
   Cross-check with ffmpeg `cropdetect` (expect square-pixel dims like `720:1280`, not a `720:864`-style squish) on the raw frame.

*Expected pass (per device):*
- Round object `fitEllipse h/w` = **0.95–1.05** (target ~0.996).
- 16:9 card measured aspect = **1.77–1.79** (not ~1.33 over-squashed, not >2.0 under-corrected).
- `contentRatio` ≈ the expected rotated-sensor aspect (≈0.5625 for 4:3→portrait, or 0.75 native 3:4) — **not** a flat `1.333` for every device.
- `previewStMatrix` is essentially a pure rotation (off-diagonal terms < 0.1) → no HAL crop/multi-cam biasing.
- Effective GL viewport == requested (no driver clamp / black bars).

*Failure signatures:*
- `h/w` 1.20–1.40 → still squashed (0.75 too high for this HAL).
- `h/w` 0.70–0.85 → over-corrected, now wide/flat (0.75 too low).
- 16:9 card < 1.50 or > 2.00.
- `contentRatio` logs `1.333`/`0.75` identically across all devices → resolution negotiation failing.
- `previewStMatrix` off-diagonal > 0.1 → multi-cam crop/zoom detected — **log the full matrix** (this is the root-cause lead).
- Preview looks round but the **recording** is squashed (or vice-versa) → encoder-vs-preview scaling diverged asymmetrically.
- Recording stops on aspect change mid-stream (`CodecException`).

**Decision rule:** if the cohort shows the squeeze factor is **not** constant across HALs, `0.75` cannot ship as a global constant — it must become **HAL-derived** (size SurfaceTexture to `surfaceRequest.resolution`; derive the transform from HAL-provided crop) per the gated H2-B.25 plan. The matrix's job is to produce exactly that go/no-go data point.

---

## 5. Lightweight Telemetry Ask (turn the matrix into data without owning the devices)

The capture pipeline **already logs**, per device, the exact datums this matrix needs — they currently live in logcat / `metrics.log`. A distributed field-test cohort (trusted testers running real sessions on their own phones) can auto-collect these and ship them back, converting "devices we'd have to buy" into "data we already have."

**Already emitted (just collect + parse):**

| Datum | Source | Tells us |
|---|---|---|
| `previewCoverFitDims … contentRatio viewportRatio` | `GlVideoPipeline.kt:629-638` | the **0.75 risk** per HAL (the "hevcPreviewNegotiated" ratio) |
| `previewStMatrix` (16 floats) | `GlVideoPipeline.kt:641` | HAL crop / multi-cam squeeze fingerprint |
| `hevcEncoderInit component bitrateRange` | `HevcMediaCodecEncoder` | hw vs sw codec, per SoC |
| `hevcCodecError` / `hevcFallbackScheduled` | `RollingChunkRecorder` | fallback firing rate in the wild |
| `glFrameRate fps maxEncSwapMs maxPreviewSwapMs` | `GlVideoPipeline` (5 s window) | fps stability + EGL swap latency per driver |
| `deviceTelemetry thermal=… aeFpsRange=…` | `StreamRecordingService.kt:445` | AE-floor honoring + thermal behavior per OEM |
| `no_auth_token`, circuit-breaker, report counts | server `metrics.log` / audit CSV | screen-off survival per OEM (already field-proven via the audit cron) |

**What to ADD (small, high-leverage):**
1. **A device-fingerprint header line** emitted once per session: `manufacturer, model, SoC, GPU renderer (GLES `glGetString`), Android release, API, activeArray W×H, default aeFpsRange, useHevcPipeline`. This makes every other datum self-describing and lets us **bin telemetry by the exact matrix cell**.
2. **A one-line per-session "geometry verdict":** the app already computes `contentRatio`; add a derived `anamorphicResidual = measured_circle_h_w` only on a *self-test screen* (show an on-screen circle the tester films once) — or simpler, just always emit `contentRatio` + `stMatrix` det/off-diagonal so we can flag "this HAL's squeeze ≠ 0.75-assumption" **without** a physical reference object.
3. **EGL path taken:** emit `eglPath=window|pbuffer-fallback` and `codecPath=hevc|h264-fallback` once per session → instantly maps which driver families need which fallback across the whole cohort.
4. **An opt-in `metrics.log` upload** (encrypted, same channel as reports; testers consent): turns the existing logcat datums into a collected dataset. Privacy: scrub IP/precise-location (this dovetails with audit item 8.1.3 metadata).
5. **`mlock`/crypto-init outcome flag** (`mlockOk=true|false`, `argon2Ms=…`) once at first run → catches the locked-down-kernel `.so` risk (P1-G) across the fleet without instrumenting each device by hand.

With (1)–(5), a ~20-tester cohort running normal sessions yields the bulk of the matrix's evidence — physical-device acquisition then targets only the cells the telemetry flags as *anomalous* (a different squeeze factor, a fallback firing, an AE floor violation).

---

## 6. Entry / Exit Criteria — "device-matrix passed, ready for wide release"

### Entry criteria (start the cohort run)
- [ ] Field test 1.11 long-haul **finished** (it is, 2026-05-31) so devices/code are editable — do **not** run this while phones are at the field site.
- [ ] Cohort builds produced: a **HEVC** build, an **H.264/legacy** build, and a **`debug_raw`** build, each embedding a **current** arm64 + armeabi-v7a + x86_64 `.so` (verify `.so` freshness check passes; the arm64 `.so` was just rebuilt — confirm it's the one bundled).
- [ ] Telemetry additions §5(1)–(3) landed (device-fingerprint header, geometry verdict, EGL/codec path) so results are auto-binnable.
- [ ] `POST_NOTIFICATIONS` fix (manifest + runtime request) landed *or* explicitly accepted as a known-limit for the cohort (the spin-off task is filed).
- [ ] Short-list devices #1–#4 acquired/borrowed (minimum bar); #5–#7 best-effort.
- [ ] Result sheet template ready (one row per matrix cell × axis, with the pre-flight fingerprint header).

### Exit criteria (declare the matrix passed)
**Hard gates — every short-list device #1–#5 (and the emulator #7 for ABI) must pass:**
- [ ] **P0-A wedge:** encoder init uses a *working* codec path (hw HEVC **or** clean H.264 fallback); no EGL init/swap failure; `maxEncSwapMs ≤ 5 ms`; screen-off recording gapless.
- [ ] **§4.2 / P1-B geometry:** round-object `fitEllipse h/w ∈ [0.95,1.05]` **and** 16:9 card `∈ [1.77,1.79]` on **every** device — *or*, if any device deviates, the team has the data to switch to HAL-derived correction (H2-B.25) and re-validates. **No device ships with `h/w` outside [0.90,1.10].**
- [ ] **P0-C AE/thermal:** AE floor ≥24 fps ≥95% over 60 min in daylight on every device; no thermal-triggered floor collapse, or the deviation is root-caused and accepted.
- [ ] **P0-D Doze:** zero `no_auth_token`, zero `circuit_open`, recording gapless and archive download completes across screen-off on **Samsung One UI and Xiaomi MIUI** specifically (the aggressive OEMs), with battery exemption granted; behavior with exemption *denied* is documented (degraded-but-safe).
- [ ] **P0-E/F FGS + onboarding:** no `ForegroundServiceDidNotStartInTimeException` / `ForegroundServiceStartNotAllowed` on any device; FGS notification visible on API 33+ (post-`POST_NOTIFICATIONS` fix); the 4-PIN + BIP-39 onboarding completes with all controls on-screen on the **smallest** and **highest-dpi** and **notched** units; no CharArray-mnemonic leak on the exception path.
- [ ] **P1-G `.so`:** `RustSmokeTest` green on arm64, **armeabi-v7a (old device)**, and **x86_64 (emulator)**; no `mlock`/`UnsatisfiedLinkError`/checksum-mismatch on any.

**Soft gates (track, fix or explicitly waive before wide release):**
- [ ] P2 onboarding cosmetics (keypad text size at xxxhdpi; notch margin) triaged.
- [ ] Telemetry §5(4)-(5) (opt-in `metrics.log` upload, mlock flag) live so post-release we keep widening coverage.
- [ ] Any device that needed a fallback (PBuffer / H.264) is recorded in a **known-good fallback table** shipped with release notes.

**Release scope rule:** wide release is gated to the **SoC/GPU/OS-tier classes that passed**. A device class with no representative tested (e.g. PowerVR if device #4/#5 couldn't source one) is shipped **conditionally** — flagged as "untested HAL class, telemetry-monitored" — not silently. The cohort + telemetry (§5) then closes those cells post-launch with real-world data instead of guesswork.

---

**Cost realism:** the 4-device hard-minimum (#1 Samsung-Exynos-Mali, #2 Xiaomi-MTK-Mali, #3 Pixel-clean-baseline, #4 cheap-weak-driver/sw-HEVC) plus the free x86_64 emulator buys down the dominant risks (Mali drivers, multi-cam anamorphic variance, aggressive OEM killers, software-HEVC fallback, ABI) for roughly the price of three mid-range phones. #5 (old/legacy) and #6 (second Adreno) are the next increment if budget allows. Beyond that, **telemetry, not hardware, is the cheapest way to widen the matrix.**

---

**Relevant files referenced (absolute paths):**
- `stream-crypto/src/main/java/org/stream/crypto/capture/GlVideoPipeline.kt` (ANAMORPHIC_VSCALE=0.75 @864, ZOOM_IN=1.2 @869, contentRatio/previewCoverFitDims @629-638, previewStMatrix @641)
- `mobile/src/main/java/rs/readahead/washington/mobile/service/StreamRecordingService.kt` (Range(24,30) @909-911 and @1663-1665, deviceTelemetry @445)
- `mobile/src/main/java/rs/readahead/washington/mobile/service/ArchiveDownloadService.kt` (FGS DATA_SYNC @84, WifiLock HIGH_PERF @113-126)
- `mobile/src/main/AndroidManifest.xml` (both services declared @116-123; POST_NOTIFICATIONS absent — the real gap)
- `stream-crypto/src/main/java/org/stream/crypto/capture/HevcMediaCodecEncoder.kt`, `…\RollingChunkRecorder.kt` (codec init + HEVC→H.264 fallback)

**Note for the caller:** one intake assertion was corrected — `ArchiveDownloadService` **is** properly declared in the manifest with `foregroundServiceType="dataSync"` (not the missing-declaration P0 blocker the brief claimed). The genuine residual gap is `POST_NOTIFICATIONS` (Android 13+); a spin-off task to add it has been filed.