# Frappuccino TLS Pinning + Key-Rotation Runbook

**ROADMAP audit item 8.1.2 · For: external auditor + operator (therealshulgin)**
> ⚠️ **RE-ANCRAGE 2026-09-03 : la bascule au domaine a eu lieu.** Ce runbook a été
> écrit quand le client épinglait l'IP brute. Depuis le 2026-06-27 il épingle le
> **domaine** `relay.shake-document-protect.org` (`PINNED_HOST`,
> `crypto-rs/stream/src/pin.rs`), et **trois** pins SPKI sont acceptés en union par
> `PinnedCertVerifier::new`. Deux conséquences pour l'opérateur :
> - Le certificat effectivement servi est celui du pin `AmIDSg…`, le seul à porter
>   un SAN domaine. Le pin historique `QnGK0K…` a un SAN IP seul et ne peut plus
>   être présenté sous le nom épinglé ; le troisième (`MUb4HH…`) est dormant,
>   hors-hôte, pour un relais saisi.
> - La section « SNI-leak regression » plus bas décrit la régression **au futur**.
>   Elle est arrivée : le SNI part en clair sur le plan de contrôle DirectTls.
>   Ce qui reste à faire est Let's Encrypt lui-même (le relais sert toujours un
>   certificat auto-signé). Voir `docs/METADATA_EXPOSURE_MAP.md` §7-P3-7.

Worktree of record: `xenodochial-morse` @ `d84ee2b` (live tip). Verified on-disk 2026-05-31. All file:line and pin values below were read from this worktree, not from memory.

> **One-sentence verdict.** The pinning *crypto* is sound (constant-time SPKI-SHA256, RT-01 signature verification wired, all five production endpoints in sync), but the *rotation architecture is single-pin / compile-time only*: there is **no second pin anywhere**, so any SPKI change is a forced, synchronized APK rebuild with **zero grace period** — a brick risk for field devices. The "zero-downtime rotation" goal claimed in the brief is **FALSE end-to-end today**. The single highest-leverage fix is to **pre-seed a second (empty/next) pin slot NOW**, before any rotation is needed.

---

> ## ⚠️ STATUT 2026-06-27 — LE 2ᵉ PIN BREAK-GLASS EST IMPLÉMENTÉ (les §1-§3/§6 ci-dessous décrivent l'état AVANT ce lot)
>
> La recommandation centrale de ce runbook (§6 « pré-semer un 2ᵉ pin pendant que le parc est sain ») est **LIVRÉE** (Lot 3 Workstream A, plan `docs/PLAN_LOT3_TRANSPORT_DOMAINE.md`). L'état réel du code **prime** sur les sections ci-dessous :
> - **Rust** `pin.rs` : `pins: Vec<[u8;32]>` (plus un `[u8;32]` unique), `const PIN_NEXT_B64 = "AmIDSglLpedq4J2LANgQ6s5+uKFEuuaNSGLjHOZkhok="`, `new()` charge **primaire + break-glass**, acceptation de l'**union** en constant-time (`spki_matches_any`, OR sans early-exit) ; RT-01 inchangé.
> - **Android NSC** : 2ᵉ `<pin>` **+ 2ᵉ ancre embarquée** `@raw/frappuccino_ca_next` (le cert break-glass auto-signé doit chaîner à sa propre ancre — un pin seul échouerait la validation de chaîne). **OkHttp** : 2ᵉ `CertificatePinner.add`.
> - Les **6 emplacements client + les 3 `.so`** portent les 2 pins ; le gate `checkRustSoFresh` est étendu à un **value-grep** (le build échoue si un `.so` n'embarque pas chaque pin déclaré dans `pin.rs` — comble le « freshness = mtime only » du §4/§6-risque-4).
> - **Clé unifiée** : `AmIDSg…` est le SPKI d'une clé EC P-256 générée + backupée off-host, qui portera **aussi** le futur cert LE (`certbot --reuse-key`) ⇒ le cutover domaine (1.2/1.3) se fait **sans changement de pin**. Le cert break-glass a `serverAuth` EKU + `keyUsage` (profil identique au primaire) pour passer la validation NSC quand il sera servi.
>
> ### MAJ 2026-06-28 — 3ᵉ pin off-host (récupération de relais SAISI)
> Un **3ᵉ pin** est pré-semé : `const PIN_NEXT2_B64 = "MUb4HHlUfj3c6cCQYuQMeeiWkcHga46OCZqVLuY9eCk="` (NSC 3ᵉ `<pin>` + 3ᵉ ancre `@raw/frappuccino_ca_next2` ; OkHttp 3ᵉ `.add` ; `quic.rs` ; `checkRustSoFresh` exige désormais **3** pins). **Pourquoi** : `QnGK0K` (primaire, backupé `.primary-bak`) **et** `AmIDSg` (next, live) ont **tous deux leur clé sur le relais** ⇒ une **saisie** les compromet ensemble ; sans 3ᵉ pin il faudrait un push APK (flag-day impossible en urgence). La 3ᵉ clé EC P-256 est **générée off-host, clé privée JAMAIS sur le relais ni dans le repo**, cert **dormant** (embarqué, non servi). SAN = **domaine seul** (l'IP du relais de secours est inconnue ; joint par le même nom).
>
> **Procédure de cutover après saisie** (geste opérateur) :
> 1. Monter un **nouveau** relais (nouvelle IP), y déposer `next2.key` + `next2.crt` (depuis le backup off-host), le servir sur :8443 (nginx) + :8444 (Caddy) — garde-fou cert↔clé MATCH avant reload, comme Lot 3 C.1.
> 2. **Re-pointer le DNS** `relay.shake-document-protect.org` → la nouvelle IP.
> 3. Rien à pousser au parc : il épingle + ancre déjà `next2` ⇒ les clients basculent dès propagation DNS. Vérifier en reads (`transport=obfquic`/`directtls`, 0 erreur pin).
> 4. Générer + pré-semer une **4ᵉ** clé off-host au prochain APK pour reconstituer la réserve.
> Portée : récupère d'une **saisie relais** (même domaine, nouvelle clé). Un **domaine brûlé** (DNS bloqué/saisi) nécessite toujours un push APK (`PINNED_HOST` change) — hors périmètre break-glass.
>
> Donc ci-dessous : « single-pin / no 2-pin model / zero PIN_NEXT in code / FALSE end-to-end / 2-pin? = single » décrivent l'état **AVANT** ce lot. La **séquence d'adoption du §6 reste la référence** pour la suite : rotation planifiée (a), compromission (c), réinstall (d) et cutover LE/DNS (§5) sont désormais des **bascules gracieuses**, plus des flag-days. Reste à faire avant de s'appuyer dessus : servir le cert break-glass au moment voulu (geste opérateur) et garder la clé privée off-host (jamais dans le repo).

---

## 1. Scope + the two failure modes that matter equally

**Scope.** TLS to the Vultr relay `136.244.101.236:8443` (nginx, self-signed EC P-256). Client trust is established by **SPKI-SHA256 pinning** in two independent layers:

- **Rust/rustls** — `crypto-rs/stream/src/pin.rs` (`PinnedCertVerifier`), the sole gate for the streaming upload/auth path. Compiled into `libuniffi_frappuccino.so`.
- **Android/OkHttp** — `network_security_config.xml` (system-enforced) + `UploadHttpClient.kt` (`CertificatePinner`, defense-in-depth).

Plus two embedded cert fixtures and one stale test fixture. The server side is nginx + a private key on disk at `/opt/frappuccino/tls/` with **no backup**.

This runbook treats two failure modes as **equally fatal**, because for a field activist both end in lost footage:

| Failure mode | Cause | Consequence |
|---|---|---|
| **MITM** | Pin too weak / fail-open / signature not verified | Adversary intercepts the live stream, reads/forges traffic. |
| **BRICK** | Pin too rigid / rotation cuts the field off | Old APK can no longer reach the relay → uploads silently fail → recordings stay on a seizable device, or are lost. |

A control that fixes one by worsening the other is not acceptable. The current design is **strong on MITM, weak on BRICK** — this document is mostly about closing the BRICK gap *without* re-opening MITM.

---

## 2. Current-state table

Pin value live in all production endpoints: **`QnGK0KvRC1vt2C4rrxwHIj0/pUbogVtTCesBK3sZXKY=`** (cert valid `2026-05-14 18:24:45Z → 2036-05-11 18:24:45Z`, EC P-256, CN=Frappuccino Relay, SAN IP:136.244.101.236).

| # | Surface | Mechanism (file:line) | 2-pin? | Forces APK rebuild on rotation? | Residual (verdict-adjusted) | Status |
|---|---|---|---|---|---|---|
| 1 | Rust rustls verifier | `crypto-rs/stream/src/pin.rs:36` const `PIN_SHA256_B64`; `:59` `pin_sha256:[u8;32]`; `:136` `ct_eq`; `:146-167` sig verify | **single** | **YES** (const baked into `.so`) | **HIGH** (no grace, brick on any SPKI change) | In sync `QnGK0K` |
| 2 | RT-01 MITM defense | `pin.rs:146-167` delegates to `rustls::crypto::verify_tls1{2,3}_signature`; E2E regression test `pin.rs:328-431` | n/a | n/a | **LOW** (control confirmed, test live) | ✅ wired + tested |
| 3 | Android NSC pin-set | `network_security_config.xml`, `<pin-set>` **sans attribut `expiration`** (retiré depuis, cf. §4e) ; trois `<pin>` | **trois** | **YES** | **LOW** (le piège d'expiration est fermé) | Trois pins en union |
| 4 | OkHttp programmatic pin | `UploadHttpClient.kt:69` `SPKI_PIN`; `:74-75` `CertificatePinner.add()` | **single** | **YES** | **MEDIUM** (defense-in-depth, no fallback) | In sync `QnGK0K` |
| 5 | Embedded cert (Rust fixture) | `crypto-rs/stream/assets/frappuccino_ca.crt` (test-only, `include_str!` at `pin.rs:42`) | **single** | **YES** | **LOW** (test asserts SPKI==pin, `pin.rs:268`) | In sync `QnGK0K` |
| 6 | Embedded cert (Android trust-anchor) | `mobile/src/main/res/raw/frappuccino_ca.crt` (referenced by NSC `:20`) | **single** | **YES** | **LOW** | In sync `QnGK0K` |
| 7 | Compiled native lib | `mobile/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libuniffi_frappuccino.so` | **single** | **YES** | **MEDIUM** (freshness guarded by timestamp only, not value) | In sync `QnGK0K` (1 match, 0 `zgsMr0`/`mGGCW`) |
| 8 | Stale test fixture | `stream-crypto/src/androidTest/res/raw/frappuccino_ca.crt` (`mGGCW…`, `2026-04-17→2028-04-16`) + `…/androidTest/res/xml/network_security_config_test.xml:15` | n/a | n/a | **LOW** (instrumented tests only; never shipped) | ⚠️ **DRIFT** — pre-May-14 |
| 9 | nginx server posture | `server/deploy/nginx/relay.conf.template:22` `TLSv1.2 TLSv1.3`; `:23` ECDHE-only AEAD ciphers; `:33` `ssl_session_tickets on`; `:14` `:8443 ssl http2`; `:101` `:80` open | n/a | n/a | **LOW** (modern TLS; `:80`/tickets noted, see §3 + cross-ref metadata audit 8.1.3) | OK |
| 10 | Server key on disk | `/opt/frappuccino/tls/frappuccino_ca.key` (perms 600), **no backup** (`pin.rs:32-35`, ROADMAP §1) | n/a | n/a | **HIGH** (reinstall ⇒ forced new SPKI ⇒ brick) | ⚠️ no backup |
| 11 | Rotation tooling | `server/deploy/tls/update-spki-pin.sh` (seds `pin.rs` only); `server/deploy/tls/gen-self-signed.sh:32` (always `genkey`, no `--reuse-key`) | n/a | — | **MEDIUM** (3 of 6 client locations un-automated; no key-reuse path) | Partial (ROADMAP 1.6) |

**Reconciling the conflicting audit inputs.** Several findings reported the production pin as `zgsMr0+…` (May 4) or `mGGCW…` (Apr 17), and claimed cross-endpoint drift, `notAfter=2036-05-01`, and `ssl_session_tickets OFF`. **Those readings came from the stale `main` branch (~40 commits behind) or from `docs/` archives, not from the live worktree.** On `xenodochial-morse` today: all five production endpoints **and** the `.so` are byte-identical at `QnGK0K…`; cert `notAfter` is **`2036-05-11`**; tickets are **ON**. The only genuine drift is the **androidTest** fixture (#8), which is test-only and never ships. Where this document and an individual finding disagree on a value, **this document's on-disk reading is authoritative.**

---

## 3. Is the 2-pin model REALLY wired end-to-end? — Definitive resolution

**No. There is no 2-pin model in any layer. Not even a first "primary + empty secondary" scaffold.** The brief's premise ("`pin.rs` has `PIN_PRIMARY` + `PIN_SECONDARY`(empty), compile-time guard, `Zeroizing` pins, `tests/pin_mitm.rs`") describes code that **does not exist**. Verified:

- **Rust** (`pin.rs`): struct holds exactly `pin_sha256: [u8; 32]` (`:59`) — a single array, not a `Vec`/slice. The check at `:136` is one `ct_eq`; on mismatch it returns `Err` at `:137-142` (hard fail, no fallback to a second pin, no system-root fallback). `grep` for `PIN_SECONDARY|PIN_PRIMARY|PIN_NEXT` across the repo → **zero** hits in code (only `docs/` archives and session notes).
- **Android NSC**: `<pin-set>` contains exactly one `<pin>` (`network_security_config.xml:24`). *(Note: a `<pin-set>` may legally hold multiple `<pin>` elements — Android OkHttp accepts the union — but only one is present.)*
- **OkHttp code**: one `.add(SERVER_HOST, SPKI_PIN)` (`UploadHttpClient.kt:74-75`). *(`CertificatePinner` also accepts multiple `.add()` calls for the same host — only one is present.)*
- **Embedded certs / `.so`**: one cert, one embedded pin (`.so` shows 1 occurrence of `QnGK0K`, 0 of any other pin).

**Therefore the "zero-downtime rotation" claim is FALSE end-to-end.** Even if *one* layer accepted two pins, zero-downtime requires *every* enforcing layer (Rust verifier **and** Android NSC **and** OkHttp `CertificatePinner`) to accept both old and new during the overlap window. Today **all three enforce exactly one pin**, so the moment the server presents a new SPKI, every already-installed client fails the handshake. The MITM signature defense (#2) is correctly wired and tested — that is the one genuinely solid control — but it does nothing for the brick problem.

**Consequence for rotation:** every SPKI change is, today, a **synchronized flag-day**: server swap and APK update must land together, and any client that hasn't updated is cut off with no warning.

---

## 4. Brick scenarios + operator runbook

### Conventions used below

- **"Pre-seed N"** = add the *next* SPKI as an accepted pin in all enforcing layers, ship that APK, and only *then* swap the server cert. This is the only way to get a grace period. **It requires the 2-pin capability from §6, which is not yet built** — so for scenarios (a)/(c)/(d) *as the code stands today*, the realistic procedure is the **flag-day** path, and the pre-seed path is what becomes possible once §6 lands. Both are given.
- **Client edit set (the 6 client locations that must all carry the pin):**
  1. `crypto-rs/stream/src/pin.rs:36`
  2. `mobile/src/main/res/xml/network_security_config.xml:24`
  3. `mobile/src/main/java/rs/readahead/washington/mobile/util/jobs/UploadHttpClient.kt:69`
  4. `crypto-rs/stream/assets/frappuccino_ca.crt`
  5. `mobile/src/main/res/raw/frappuccino_ca.crt`
  6. `mobile/src/main/jniLibs/*/libuniffi_frappuccino.so` (regenerated, not hand-edited)
  *(Also keep #8 — the androidTest fixture — in sync to keep instrumented tests honest; it does not ship.)*
- **Rebuild sequence (the canonical "client rebuild"):**
  ```bash
  bash server/deploy/tls/update-spki-pin.sh <cert-or-host:port>   # prints the sed for pin.rs
  # apply the sed to pin.rs; manually edit NSC, UploadHttpClient.kt, copy the 2 .crt fixtures
  cd crypto-rs && cargo test --workspace --release                # embedded_cert_spki_matches_pin must pass
  TARGETS=arm64-v8a,armeabi-v7a,x86_64 bash crypto-rs/build-android.sh   # regenerate .so with new pin
  ./gradlew :mobile:assembleRelease                               # checkRustSoFresh gate runs at preBuild
  ```
- **Verify-before-ship gate (run every time):**
  ```bash
  # 1. all client locations carry the new pin
  rg -n "<NEW_PIN>" crypto-rs/stream/src/pin.rs mobile/src/main/res/xml/network_security_config.xml \
       mobile/src/main/java/.../UploadHttpClient.kt
  # 2. the .so actually embeds it (the checkRustSoFresh guard only checks mtime, NOT the value)
  grep -c "<NEW_PIN_PREFIX>" mobile/src/main/jniLibs/arm64-v8a/libuniffi_frappuccino.so   # must be 1
  grep -c "<OLD_PIN_PREFIX>" mobile/src/main/jniLibs/arm64-v8a/libuniffi_frappuccino.so   # must be 0
  # 3. embedded cert SPKI == pin
  cd crypto-rs && cargo test embedded_cert_spki_matches_pin --release
  # 4. live server actually presents the new SPKI
  bash server/deploy/tls/update-spki-pin.sh 136.244.101.236:8443
  ```

---

### (a) Planned key rotation (you choose to change the keypair)

**Today (single-pin, flag-day):**
1. On the server, generate the new cert+key (`gen-self-signed.sh`). **Do not deploy it yet.** Capture the new SPKI.
2. Do the full client edit set + rebuild + verify gate against the **new cert file** (not the live server, which still serves the old cert).
3. Ship the new APK to all users. **Wait the grace period** (see §4 grace note) so the field updates *before* the server changes.
4. Swap the cert on the server (`nginx -t && systemctl reload nginx`), and confirm `update-spki-pin.sh 136.244.101.236:8443` returns the new SPKI.
5. **Skip-a-step brick:** if you do step 4 before step 3 propagates → every not-yet-updated client bricks instantly.

**After §6 lands (2-pin, zero-downtime):**
1. Pre-seed the new SPKI as the *secondary* pin in all enforcing layers; ship. Clients now accept **old OR new**.
2. After the grace period, swap the server cert. No client notices.
3. In the *next* APK, promote new→primary and drop the old pin. Brick-free.

---

### (b) Cert expiry — 2036-05-11

The cert is valid until **2036-05-11 18:24:45Z**. Two independent clocks fire, **asymmetrically**:

- **Android/OkHttp** (*le paragraphe qui suit décrit l'état d'avant le retrait de l'attribut `expiration` ; il n'y a plus de date côté NSC, cf. §4e*) : NSC `expiration="2036-05-10"` — **one day before** the cert's `notAfter`. On 2036-05-10 OkHttp **stops enforcing the pin-set** and falls back to trust-anchor validation. The NSC trust-anchors include `@raw/frappuccino_ca` (the self-signed cert itself, `:20`) **and** `system` (`:21`). So after the pin-set lapses, OkHttp validates the chain against the embedded self-signed cert — which is still valid until 2036-05-11 — i.e. it does **not** instantly brick on 2036-05-10, but it **loses pin enforcement** (downgrades to "trust this embedded cert or any system CA"). The day after (2036-05-11) the embedded cert itself expires → hard failure.
  > **Operator note / falsifiable:** the precise post-expiration behavior (silent un-pin vs. hard reject) depends on the OkHttp/Android version's NSC handling; the embedded self-signed trust-anchor means the dominant near-term effect is **loss of pinning**, not an immediate outage. **Validate on the target Android versions before relying on either reading** (this is exactly the kind of thing 8.1.4 device-matrix testing should cover).
- **Rust/rustls**: ignores cert validity entirely — `verify_server_cert`'s `_now: UnixTime` is intentionally unused (`pin.rs:113`). The Rust path will keep accepting the expired cert **indefinitely**, as long as the SPKI still matches. So the streaming path does **not** self-brick at expiry, but it also gives you **no expiry safety net**.

**Runbook:** treat 2036-05-11 as a hard deadline to ship a renewed cert. Renew **under the same keypair** (so SPKI is unchanged → no client rebuild needed for the Rust path) — but note the **embedded Android trust-anchor cert and NSC expiration date are themselves a client artifact**, so an Android client rebuild is still required to refresh the embedded cert, even with a stable key (il n'y a plus de `expiration` NSC à bumper). **This is a reason to migrate to a CA-issued cert (LE, §5) well before 2036**, which removes the embedded-cert refresh problem.
**Skip-a-step brick:** let 2036-05-10 pass with no new APK → Android clients lose pin enforcement (MITM exposure), then lose connectivity on 2036-05-11.

---

### (c) Emergency key compromise (private key leaked **today**)

This is the worst case: the key has no backup *and* compromise means you must rotate *fast*, but a fast rotation bricks the field.

1. **Immediately** generate a fresh keypair+cert on the server (`gen-self-signed.sh`); capture new SPKI. **Hold deployment.**
2. **Decision the operator must make consciously:** until the new APK reaches the field, you are choosing between
   - **(i) keep the compromised cert live** → field keeps uploading, but an adversary holding the key can MITM (note: RT-01 means the adversary needs the *private key* to MITM, not just the public cert — with a leaked key they fully can), or
   - **(ii) swap to the new cert now** → MITM closed instantly, but every not-yet-updated client bricks.
   There is **no third option today** because there is no pre-seeded second pin. **This is the core reason §6 must be done in advance** — with a pre-seeded "break-glass" pin you could swap immediately *and* keep the field connected.
3. Do the full client edit set + rebuild + verify gate; ship as a **high-priority** update with an in-band user signal (§4 grace note).
4. Swap the server cert once adoption is acceptable (compromise severity dictates how short you cut the grace period).

---

### (d) Server reinstall that loses the key (the realized 2026-05-14 event)

The key at `/opt/frappuccino/tls/` is **not backed up** (`pin.rs:32-35`). A Vultr "Reinstall OS" already did this once (May 14 2026: `zgsMr0…` → `QnGK0K…`), forcing the current pin. **Any future reinstall repeats it.**

**Preventive (do this now, costs minutes):**
```bash
# Back up the keypair OFF the VM so a reinstall is recoverable without an SPKI bump.
# The cert is public; the .key is the secret — store it encrypted (e.g. age/gpg) off-host.
scp root@136.244.101.236:/opt/frappuccino/tls/frappuccino_ca.key  ./frappuccino_ca.key.bak
scp root@136.244.101.236:/opt/frappuccino/tls/frappuccino_ca.crt  ./frappuccino_ca.crt.bak
age -p -o frappuccino_ca.key.bak.age frappuccino_ca.key.bak && shred -u frappuccino_ca.key.bak
```
With this backup, a reinstall restores the same key → **same SPKI → no client rebuild, no brick.** This single action neutralizes scenario (d) and most of (a).
**Reactive (no backup existed):** identical to scenario (c) flag-day — full client rebuild + grace period.
**Skip-a-step brick:** reinstall without restoring the key → new SPKI → entire field bricked until the next APK ships.

---

### (e) NSC pin-set expiration : **l'attribut a été retiré, ne le remettez pas**

**Cette section disait l'inverse de la règle actuelle, et c'est corrigé ici.** L'attribut `expiration` a été **retiré** du `<pin-set>`, et l'en-tête de `mobile/src/main/res/xml/network_security_config.xml` interdit explicitement de le remettre. La raison : un pin-set expiré ne fait pas échouer la connexion, il fait **taire l'enforcement** — Android retombe sur la validation par ancres de confiance, sans rien signaler. Une date choisie pour servir de rappel de rotation devient donc une date où le pinning s'éteint tout seul.

**Règle opérateur, aujourd'hui :** ne réintroduisez jamais `expiration`. L'expiration du certificat est surveillée **côté relais** par `render-relay-conf.sh` (`openssl checkend` : refus de rendre une conf avec un cert déjà expiré, avertissement sous 30 jours), et l'enforcement primaire est le vérifieur Rust de `pin.rs`, qui épingle la **clé** et n'expire à aucune date.

---

### Grace-period & user-signal note (applies to a, b, c, d)

- **There is no in-app rotation signal today.** A failed handshake surfaces as upload failures, not a user-actionable message. Until §6 + a notification exist, the grace period is *purely* "time for F-Droid/sideload adoption", blind.
- **Recommended grace window:** **7–14 days** for FOSS/F-Droid adoption (ROADMAP 1.3/1.6), shortened only under active compromise (c).
- **Recommended signal (pre-audit work item 1.6):** when the relay is reachable on `:8443` but the *pin* fails, show an explicit "app update required to keep uploading" banner rather than a generic network error — so a field user knows the footage is **not** being relayed and can act (or at least knows to keep the device safe).

---

## 5. LE/DNS migration (ROADMAP 1.2 / 1.3 / 1.6) — does "no APK rebuild" actually hold?

**Short answer: only conditionally, and not with the tooling as written.** The "reuse keypair ⇒ stable SPKI ⇒ no rebuild" reasoning is correct *in principle* because **the pin is on the SPKI (public key), not on the certificate**. A cert renewal that keeps the same public key produces the same SPKI hash, so the Rust verifier (`pin.rs` hashes `subject_pki.raw`) and OkHttp's SPKI pin both still match. But three things must hold, and today they don't:

1. **`certbot` must reuse the key.** `gen-self-signed.sh:32` **always** runs `openssl ecparam -genkey` — a fresh key every time, no `--reuse-key`. ROADMAP 1.2's note ("clé persistante = pas de SPKI bump") is an *intention with no enforcing code*. For LE you must invoke certbot with **`--reuse-key`** (and a pre-generated EC P-256 key via `--csr` or `certbot certonly --key-type ecdsa --elliptic-curve secp256r1 --reuse-key`). If 1.2 is deployed naïvely (`certbot certonly --nginx` with default key rotation), **every ~90-day renewal mints a new key → new SPKI → forced APK rebuild every quarter** — strictly worse than the current 10-year self-signed cert.
2. **DNS must come first, or stay pinned-to-IP.** The host is hard-coded to the IP in three places: `pin.rs:39` `PINNED_HOST`, `UploadHttpClient.kt:62` `SERVER_HOST`, and `network_security_config.xml:18` `<domain>`. LE **cannot issue for a bare IP** over the standard path — it needs a domain (1.3). So 1.2 *depends on* 1.3. And once you move to a domain, **all three host constants change → APK rebuild anyway** for that one transition. Net: the LE/DNS cutover itself is a one-time rebuild; the *benefit* is that **subsequent** cert renewals are rebuild-free (if #1 holds).
3. **Pin-on-SPKI survives CA changes only if the key survives.** If you ever let LE rotate the key (or switch ACME providers in a way that regenerates it), the SPKI changes. So the operational discipline is: **generate the EC keypair once, back it up off-host (scenario d), and pin certbot to it forever with `--reuse-key`.** Then the pin is stable across renewals and even across CA migrations.

**SNI-leak regression (cross-ref metadata audit 8.1.3).** Today the client sends SNI = the **IP** (`ServerName::IpAddress`), and the server is on a non-standard port `:8443` with a self-signed cert — there is little hostname signal on the wire beyond the destination IP itself. Moving to LE+DNS means the client will send **SNI = `relay.frappuccino.app`** in cleartext on every handshake (unless ECH is available, which it generally is not here). That is a **metadata regression**: a network observer who couldn't previously attribute the destination to "Frappuccino" by name now can, by the SNI string, even though the IP was always visible. **This must be weighed in 8.1.3** — the IP is already a sink; adding a self-identifying domain name to the TLS ClientHello broadens fingerprintability. Mitigations to evaluate: a generic/neutral domain name, ECH where supported, or keeping IP-pinning for the high-risk profile. The `:80` listener (`relay.conf.template:101`, currently open) will be used for the ACME http-01 challenge and HTTPS redirect during LE — **audit its access-log as an additional IP sink** (already flagged for 8.1.3).

**Concrete LE/DNS migration steps (rebuild-minimizing order):**
1. **1.3 first:** buy a domain, set an A record → `136.244.101.236`. (Consider a neutral name for SNI hygiene — coordinate with 8.1.3.)
2. **Pre-generate + back up** an EC P-256 keypair off-host (this is also scenario-(d) insurance).
3. **certbot with key reuse:** issue against the domain using that fixed key, e.g. `certbot certonly --webroot -d relay.frappuccino.app --key-type ecdsa --elliptic-curve secp256r1 --reuse-key` (or supply a CSR built from the fixed key). Confirm the issued cert's SPKI == the pinned SPKI you will ship.
4. **One-time client rebuild** for the host change (IP→domain in `pin.rs:39`, `UploadHttpClient.kt:62`, `network_security_config.xml:18`) **and** the SPKI (which will be the SPKI of your fixed keypair). If you keep the *current* keypair as the fixed key, you can even keep the **same SPKI** and only change the host — minimizing churn. Ship with grace period.
5. **Switch nginx** to the LE cert + add HSTS (1.2). Keep `--reuse-key` wired into the renewal timer so future renewals are SPKI-stable.
6. **Verify** the renewal path: force-renew once in staging and confirm the SPKI is unchanged (`update-spki-pin.sh relay.frappuccino.app:443`). If it changed, `--reuse-key` is not effective — fix before relying on rebuild-free renewals.

---

## 6. Top risks + the single highest-leverage change

### Top risks (ranked)

1. **No pre-seeded second pin (architecture).** Every SPKI change is a flag-day with zero grace; under compromise (c) you must choose between MITM exposure and bricking the field. **Residual HIGH.** *Surfaces 1, 3, 4.*
2. **Server key has no backup.** A Vultr reinstall (already happened once) forces a new SPKI → full-field brick. **Residual HIGH.** *Surface 10.* — *cheapest to fix: scenario (d) backup.*
3. **~~NSC expiration trap~~ + Rust expiry-blindness.** La moitié NSC est **fermée** : l'attribut `expiration` a été retiré et son retour est interdit (§4e). Reste l'asymétrie côté Rust, qui accepte un certificat expiré indéfiniment tant que le SPKI correspond (`_now` délibérément inutilisé dans `verify_server_cert`) ; l'expiration est surveillée côté relais par `openssl checkend`. **Residual LOW/MEDIUM**, plus une échéance 2036 pour le certificat lui-même. *Surfaces 3, 1.*
4. **`.so` freshness guarded by timestamp, not value.** `checkRustSoFresh` (`build.gradle:30-62`) only compares mtimes; a stale-but-newer `.so`, or a hand-built `.so` with the wrong pin, passes. The 2026-05-15 "stale .so for ~a day" incident is the precedent. **Residual MEDIUM.** Add the value grep from §4's verify gate to CI. *Surface 7.*
5. **LE-without-`--reuse-key` footgun.** If 1.2 ships naïvely, quarterly renewals brick the field — worse than status quo. **Residual MEDIUM (latent).** *Surface 11 + §5.*
6. **androidTest fixture drift.** Test-only (`mGGCW…`, surface 8); instrumented tests against the live server would fail, masking real regressions. **Residual LOW.** Re-sync + add a CI check that all six client locations + the test fixture share one SPKI.

### The ONE change that most reduces brick risk

**Pre-seed a second pin slot in all three enforcing layers NOW, while the field is still healthy on `QnGK0K…` — before any rotation is needed.** Concretely:

- **Rust** (`pin.rs`): change `pin_sha256: [u8; 32]` → a small fixed set (e.g. `pins: Vec<[u8;32]>` or `[[u8;32]; 2]`) built from `const PIN_PRIMARY` + `const PIN_SECONDARY` (the latter may start empty/ignored). In `verify_server_cert`, accept if the peer SPKI `ct_eq`-matches **any** configured pin; keep the hard-fail when none match. Preserve constant-time semantics (compare against each, don't early-exit on length). Keep the RT-01 signature verification exactly as-is.
- **Android NSC**: add a second `<pin>` element inside the existing `<pin-set>` (OkHttp accepts the union).
- **OkHttp code**: add a second `CertificatePinner.add(SERVER_HOST, SECONDARY_PIN)`.
- **Ship one APK** carrying `{ current, next }` (next can initially equal current, or be a real pre-generated "break-glass" key's SPKI).

**Why this is the highest-leverage move:** it converts every future rotation — planned (a), compromise (c), reinstall (d), and the LE/DNS cutover (§5) — from a **flag-day brick** into a **graceful overlap**: the trusted anchor for the *next* cert is **already in the field** before the server changes, so you can swap the server cert first and let clients catch up, or vice-versa, without ever cutting anyone off. It is the prerequisite that makes the "pre-seed" branch of every §4 runbook actually executable. It does **not** weaken MITM resistance (you're adding a *second pinned key you control*, not a CA fallback), so it improves BRICK without regressing MITM — the core requirement from §1.

**Sequence to adopt safely:** (1) generate + back up the "next" keypair off-host; (2) implement the 2-pin acceptance + ship with `next` pre-seeded; (3) add the CI value-grep so the `.so` and all six locations are checked to carry both pins; (4) *then* you are free to rotate, migrate to LE/DNS, or recover from a reinstall with zero field brick.

---

### Appendix — verified facts (on-disk, `xenodochial-morse`, 2026-05-31)

- Live production pin, all 5 client endpoints + `.so`: `QnGK0KvRC1vt2C4rrxwHIj0/pUbogVtTCesBK3sZXKY=` (`.so`: 1 occurrence, 0 of `zgsMr0`/`mGGCW`).
- Cert: EC P-256, `notBefore=2026-05-14 18:24:45Z`, `notAfter=2036-05-11 18:24:45Z`, CN=Frappuccino Relay, SAN IP:136.244.101.236.
- NSC : plus d'attribut `expiration` sur le `<pin-set>` (retiré ; le remettre éteindrait silencieusement le pinning, cf. §4e).
- Rust ignores cert validity: `_now` unused at `pin.rs:113`.
- Constant-time compare: `subtle::ConstantTimeEq` at `pin.rs:22`, used `pin.rs:136`.
- RT-01 fix wired: `pin.rs:146-167`; E2E regression test `rt01_mitm_forged_certificate_verify_is_rejected` at `pin.rs:328-431` (asserts `BadSignature`).
- nginx: `TLSv1.2 TLSv1.3` (`relay.conf.template:22`), ECDHE-only AEAD ciphers (`:23`), `ssl_session_tickets on` (`:33`), `:8443 ssl http2` (`:14`), `:80` open (`:101`).
- `gen-self-signed.sh:32` always `genkey` (no `--reuse-key`); `update-spki-pin.sh` seds only `pin.rs` (3 of 6 client locations un-automated).
- `checkRustSoFresh` (`build.gradle:30-62`) compares **mtime only**, not embedded pin value.
- Single-pin everywhere: zero `PIN_SECONDARY`/`PIN_PRIMARY`/`PIN_NEXT` in code (only `docs/` archives).
- Only drift: `stream-crypto/src/androidTest/res/raw/frappuccino_ca.crt` = `mGGCW…`, `2026-04-17→2028-04-16` (test-only, never shipped).