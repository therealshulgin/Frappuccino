# Plan d'exécution — Port Rust `stream-crypto/` → `frappuccino-crypto-rs/`

> **Snapshot** : 2026-04-17, post-commit `c0905cf` (P1 audit-remediation terminée, 72/72 tests Android verts).
> **Stratégie haut-niveau, mapping Kotlin→Rust, choix d'archi** : voir [`PORT_RUST_OPTION_B.md`](PORT_RUST_OPTION_B.md).
> **Ce document** : ordonnancement opérationnel, tâches atomiques, DoD par sprint, checklist de démarrage immédiate.

---

## 0. Pourquoi un deuxième document

`PORT_RUST_OPTION_B.md` répond à **"quoi porter et pourquoi"**. Ce doc répond à **"comment exécuter, dans quel ordre, avec quel critère de sortie"**. Les deux sont à jour ensemble — tout changement de scope met à jour les deux.

Règle d'or du port : **jamais de régression protocolaire**. Le code Rust doit produire et consommer des blobs byte-identiques à ce que la version Kotlin actuelle produit et consomme, sinon les identités déjà enrôlées sont cassées.

---

## 1. Invariants immuables (snapshot 2026-04-17)

Toute divergence = incompatibilité serveur + perte d'accès aux archives existantes. Ces valeurs sont des **contrats figés** du protocole, pas des paramètres d'implémentation.

### 1.1 BIP-39 (`stream-crypto/.../Bip39.kt`)
- `WORD_COUNT = 12`
- `ENTROPY_BITS = 128`, `ENTROPY_BYTES = 16`
- `CHECKSUM_BITS = 4`, `TOTAL_BITS = 132`
- `PBKDF2_ITERATIONS = 2048`
- `SEED_BYTES = 64`
- Algo : `PBKDF2-HMAC-SHA512`
- Sel : `"mnemonic" + passphrase` (UTF-8, canonique BIP-39)
- Wordlist FR : `stream-crypto/src/main/resources/bip39_fr.txt` (2048 mots)
- Normalisation : NFD, strip combining marks, lowercase, map stripped→canonical
- **BT-HIGH-10** : `normalizeWord` **throw** sur mot inconnu (plus de fallback silencieux)

### 1.2 Dérivation d'identité (`ArchiveIdentity.kt`, `EnrollmentKit.kt`)
- `HKDF_CONTEXT_IDENTITY = "stream.identity.ed25519.v1"`
- `HKDF_CONTEXT_ENCRYPTION = "stream.encryption.x25519.v1"`
- `HKDF_CONTEXT_CHAIN0 = "stream.ratchet.chain0.v2"`
- HKDF : RFC 5869 SHA-256, no salt (IKM = seed BIP-39 64 bytes)
- Ed25519 seed = 32 bytes → `sodium.crypto_sign_seed_keypair`
- X25519 : dérivé séparément (32 bytes) → curve25519 scalar clamping côté public
- Chain_0 : 32 bytes dérivés via HKDF context `chain0.v2`

### 1.3 Ratchet éphémère V2 (`ratchet/EphemeralRatchet.kt`)
- `BATCH_SIZE = 50`
- `CHAIN_KEY_BYTES = 32`
- `MASK_BYTES = 7` (56 bits, 50 utilisés LSB)
- `CTX_BATCH_SEEDS = "frappuccino-v2-ratchet-batch-seeds"` (HKDF → 50·32 bytes)
- `CTX_NEXT_CHAIN = "frappuccino-v2-ratchet-next-chain"` (HKDF → 32 bytes)
- `CTX_BLOB_MAC = "frappuccino-v2-ratchet-blob-mac"` (HKDF → 32 bytes HMAC key, **BT-HIGH-07**)
- Blob V2 :
  - `SERIALIZED_HEADER_SIZE = 44` (version 1B + batch_num 4B + mask 7B + chain 32B)
  - `SERIALIZED_PER_SLOT_SIZE = 96` (pk 32B + sk 64B)
  - `SERIALIZED_PAYLOAD_SIZE = 44 + 50·96 = 4844`
  - `MAC_BYTES = 32`
  - `SERIALIZED_SIZE = 4876`
  - `VERSION_V2 = 2` (byte 0)
  - HMAC-SHA256 sur `[0..4844[` avec key = HKDF(chain, CTX_BLOB_MAC)
  - Legacy `VERSION_V1 = 1` : accepté en lecture (4844 bytes), re-sérialisé en V2 au prochain `serialize()`

### 1.4 Format STRM v1 (`SovereignEncryptor.kt`, `ArchiveDecryptor.kt`)
- Magic : `"STRM"` (4 bytes)
- Version byte, mode byte (`SINGLE = 1`, `CHUNKED = 2`)
- Session key `K_s` enveloppée via `crypto_box_seal` (X25519 ephemeral + Blake2b + XSalsa20-Poly1305, spec libsodium)
- Chunks : `XChaCha20-Poly1305`, nonce 24B random par chunk, AAD = header bytes
- Tout paramètre numérique de header est little-endian (à confirmer en lisant le parser Kotlin actuel — cf. §5.1 du plan stratégique)

### 1.5 PinProtectedStore (`secure/PinProtectedStore.kt`)
- Argon2id params : `m = 256 MiB`, `ops = 4`, `p = 1`, `tagLen = 32`
- Salt : 16 bytes random par seal
- AEAD : `XChaCha20-Poly1305`
- Nonce : 24 bytes random par seal
- AAD base : `"frappuccino-v2-pin-store-v1"` (UTF-8)
- Layout : `salt (16) || nonce (24) || ciphertext+tag (var)`

### 1.6 PIN attempt counter (`PinAttemptTracker.kt`, **BT-HIGH-15**)
- SharedPreferences `pin_attempt_tracker`
- `DELAY_MS_SCHEDULE = [0, 0, 0, 5_000, 15_000, 60_000, 120_000, 300_000, 600_000, 600_000]`
- `apply()` → `commit()` après P1 (survit au force-kill)
- Cette logique reste **côté Kotlin** (SharedPreferences Android-specific). Rust fournit seulement la fonction pure `open()` qui throw sur mauvais PIN ; le tracker Kotlin encadre les appels.

### 1.7 Serveur V2 — routes à conserver
- `POST /auth/v2/enroll` body = `{ed_pk_hex, batch0_public_keys[50], enroll_sig}`
- `POST /auth/challenge` → `{nonce_hex}`
- `POST /auth/v2/verify` body = `{ed_pk_hex, nonce_hex, batch_number, key_index, ephemeral_pk_hex, signature_hex}`
- `POST /auth/v2/rotate-batch` body = `{ed_pk_hex, signer_key_index, new_batch_public_keys[50], new_batch_signature}`
- `GET /auth/v2/status?pk=...`
- Nonce TTL = 120s, cache persistant sur disque via `NONCE_CACHE_FILE` (**BT-HIGH-13**)

### 1.8 TLS + cert pinning (**CRIT-01**)
- Endpoint prod : `https://136.244.101.236:8443`
- SPKI SHA-256 pin : `mGGCWQNvYxXBlHTDUzRgdB1GSJQnnwP0gw5gUmokBOA=`
- Trust-anchor : cert self-signed embarqué `mobile/src/main/res/raw/frappuccino_ca.crt`
- En Rust : `reqwest` + `rustls-tls` avec custom `RootCertStore` + pin check manuel (ou via `rustls::client::ServerCertVerifier` custom)

---

## 2. Stratégie d'exécution

### 2.1 Principes non-négociables

1. **Port incrémental, module par module.** Chaque primitive passe du statut "porté, mais Kotlin encore en prod" à "porté + consommé par mobile/" individuellement. Pas de big-bang.
2. **Parité bit-exact avant suppression du Kotlin.** Pour chaque module porté, un test `parity.rs` consomme des vecteurs JSON/binaires produits par le Kotlin actuel et échoue au moindre écart.
3. **Coexistence temporaire.** Pendant le port, `stream-crypto/` (Kotlin) **et** `frappuccino-crypto-rs/` (Rust via UniFFI) coexistent dans le build. Feature flag côté Kotlin pour switcher l'impl active pendant la phase de validation.
4. **Invariants crypto = read-only.** Les constantes du §1 ne changent pas. Toute découverte qui suggérerait un changement = STOP, discussion explicite avec 0xmah avant de toucher.
5. **Zero nouvelle dépendance C.** RustCrypto pur, pas de FFI vers libsodium/sodiumoxide/ring. Si une primitive n'existe pas en pure Rust : on réfléchit avant d'introduire une dep native.

### 2.2 Ordre d'attaque (rationnel)

De la primitive la plus pure (sans état, facile à tester bit-exact) vers la plus intégrée :

```
BIP-39  →  HKDF  →  SecretBytes  →  Identity derivation
                                 →  PinProtectedStore
                                 →  EphemeralRatchet V2
                                 →  STRM v1 (encrypt+decrypt)
                                 →  HTTP client + CertPin
                                 →  UniFFI exposition
                                 →  Migration mobile/ (call-sites)
                                 →  CLI Rust (remplace server-tools/*.py)
                                 →  Hardening + audit prep
```

### 2.3 Découpage sprints

Chaque sprint = **unité d'engagement cohérente** : un objectif, des tâches atomiques, un critère de sortie mesurable. Taille visée : 2–7 jours-dev solo. Pas de timeline calendaire figée (démo reportée sine die, on privilégie la qualité).

Les sprints ci-dessous mappent sur les phases P0..P8 du plan stratégique mais avec un grain plus fin (S0–S9, parfois découpés).

---

## 3. Layout workspace Cargo cible

```
Frappuccino/
├── crypto-rs/                         # Nouveau workspace Cargo
│   ├── Cargo.toml                     # [workspace] members = [...]
│   ├── Cargo.lock                     # committed
│   ├── rust-toolchain.toml            # stable pinné (ex: 1.80.0)
│   ├── deny.toml                      # cargo-deny config
│   ├── core/                          # crate frappuccino-crypto-core
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── bip39.rs
│   │       ├── hkdf.rs
│   │       ├── identity.rs            # StreamIdentity, EnrollmentKit, ArchiveIdentity
│   │       ├── pin_store.rs
│   │       ├── ratchet.rs             # EphemeralRatchet V2 (V1 legacy-read only)
│   │       ├── secret.rs              # SecretBytes, LockedSecret
│   │       └── error.rs               # CryptoError (thiserror)
│   ├── stream/                        # crate frappuccino-crypto-stream
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── header.rs              # STRM parser/serializer
│   │       ├── encrypt.rs             # SovereignEncryptor (modes SINGLE + CHUNKED)
│   │       ├── decrypt.rs             # ArchiveDecryptor
│   │       ├── seal.rs                # crypto_box_seal reproduction
│   │       └── protocol.rs            # StreamServerClient + upload state machine
│   ├── ffi/                           # crate frappuccino-crypto-ffi (UniFFI)
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   ├── frappuccino.udl
│   │   └── src/lib.rs                 # re-exports + scaffolding UniFFI
│   ├── cli/                           # crate frappuccino-cli (binaire)
│   │   ├── Cargo.toml
│   │   └── src/main.rs                # clap subcommands
│   ├── parity-vectors/                # JSON/binary fixtures, partagés Kotlin/Rust/Python
│   │   ├── bip39/
│   │   ├── identity/
│   │   ├── ratchet/
│   │   ├── pin_store/
│   │   ├── strm_blobs/
│   │   └── protocol/
│   └── fuzz/                          # cargo-fuzz workspace
│       ├── Cargo.toml
│       └── fuzz_targets/
│           ├── decrypt_blob.rs
│           ├── parse_strm_header.rs
│           ├── ratchet_deserialize.rs
│           └── bip39_normalize.rs
├── stream-crypto/                     # Kotlin legacy — supprimé progressivement
└── mobile/                            # UI Kotlin — call-sites migrés un par un
```

Noms de crates : `frappuccino-crypto-core`, `frappuccino-crypto-stream`, `frappuccino-crypto-ffi`, `frappuccino-cli`. Préfixe `frappuccino-` pour éviter collision écosystème cargo.

---

## 4. Dépendances figées

Aligné sur §3.8 du plan stratégique. MSRV = Rust 1.80.0 stable (à pinner dans `rust-toolchain.toml`).

```toml
# crypto-rs/core/Cargo.toml
[dependencies]
ed25519-dalek = { version = "2.1", features = ["rand_core", "zeroize"] }
x25519-dalek = { version = "2.0", features = ["zeroize", "static_secrets"] }
chacha20poly1305 = { version = "0.10", features = ["alloc"] }
argon2 = { version = "0.5", features = ["zeroize"] }
hkdf = "0.12"
sha2 = "0.10"
hmac = "0.12"
pbkdf2 = { version = "0.12", features = ["simple"] }
blake2 = "0.10"

zeroize = { version = "1.7", features = ["derive"] }
secrecy = "0.8"
subtle = "2.5"
memsec = "0.7"

rand_core = "0.6"
getrandom = "0.2"

bip39 = { version = "2.0", features = ["french"] }
unicode-normalization = "0.1"

thiserror = "1.0"
log = "0.4"

[dev-dependencies]
proptest = "1.4"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```toml
# crypto-rs/stream/Cargo.toml
[dependencies]
frappuccino-crypto-core = { path = "../core" }
reqwest = { version = "0.11", features = ["blocking", "json", "rustls-tls-manual-roots"], default-features = false }
rustls = "0.22"
rustls-pemfile = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```toml
# crypto-rs/ffi/Cargo.toml
[dependencies]
frappuccino-crypto-core = { path = "../core" }
frappuccino-crypto-stream = { path = "../stream" }
uniffi = { version = "0.28", features = ["build"] }
thiserror = "1"

[build-dependencies]
uniffi = { version = "0.28", features = ["build"] }
```

Toutes les versions sont à **valider en S0** par un `cargo tree` qui doit :
- Ne pas introduire de crate dépréciée
- Produire un graphe résolu avec 0 conflit de version transitive
- `cargo deny check licenses` passe (pas de GPL incompat avec AGPLv3)

---

## 5. Vecteurs de parité — à produire **avant** tout port

Règle : on **n'écrit pas de code Rust avant d'avoir le vecteur** qui prouvera la parité. Sinon on porte à l'aveugle et on découvre les divergences trop tard.

### 5.1 Comment les produire

**Le dumper est déjà écrit** : [`stream-crypto/src/androidTest/java/org/stream/crypto/parity/ParityVectorsDumper.kt`](stream-crypto/src/androidTest/java/org/stream/crypto/parity/ParityVectorsDumper.kt).

Un `@Test fun dumpAll()` qui :
- Utilise 1 mnémonique fixée (`MN_FIXED` = "abaisser abandon ... abroger") + 2 générées via `Bip39.generate("fr")`
- Dumpe dans `getExternalFilesDir(null)/parity-dump/` (pullable sans root)
- Produit JSON indenté déterministe via un `JsonBuilder` interne

Procédure d'exécution :

```bash
# 1. Depuis Android Studio (ou Gradle avec JDK correct) :
./gradlew :stream-crypto:connectedAndroidTest \
    --tests 'org.stream.crypto.parity.ParityVectorsDumper'

# 2. Pull les fixtures (le test print le chemin exact en fin de run) :
adb pull /sdcard/Android/data/org.stream.crypto.test/files/parity-dump/ \
    ./crypto-rs/parity-vectors/

# 3. Commit les fixtures dans crypto-rs/parity-vectors/
git add crypto-rs/parity-vectors/
git commit -m "chore(rust): capture parity vectors from Kotlin reference impl"
```

Le test reste dans le repo : il peut être relancé à chaque fois qu'un invariant Kotlin bouge (ce qui DOIT casser les tests Rust de parité → forcer un review dual-impl).

Note environnement : si `./gradlew` échoue avec `JdkImageTransform / jlink.exe` (bug JBR+android-34), utiliser Android Studio qui embarque un JDK compatible, ou installer OpenJDK 17 externe et pointer `JAVA_HOME` dessus.

### 5.2 Vecteurs minimums

```
parity-vectors/
├── bip39/
│   ├── generate.json           # entropy hex → mnemonic words[12]
│   ├── normalize.json          # input (sale accents/case) → output canonique
│   ├── normalize-invalid.json  # mots inconnus → doit throw
│   └── seed.json               # mnemonic+passphrase → seed hex (64B)
├── identity/
│   └── derive.json             # mnemonic+passphrase → {ed_pk, x25519_pk, chain_0, fingerprint}
├── ratchet/
│   ├── init.json               # chain_0 → batch_pks[50] + chain_1
│   ├── sign.json               # batch_num, key_idx, msg → signature
│   ├── rotate.json             # chain_n → {signer_idx, sig, new_batch_pks[50], chain_{n+1}}
│   ├── blob_v2.bin             # state → 4876 bytes canoniques
│   └── blob_v1_legacy.bin      # ancien état V1 → 4844 bytes (acceptance test)
├── pin_store/
│   ├── seal.json               # {pin, plaintext, salt, nonce} → blob hex
│   └── open.json               # idem reverse
├── strm_blobs/
│   ├── single_small.strm       # 50 bytes PT mode SINGLE
│   ├── single_large.strm       # 5 MB PT mode SINGLE
│   ├── chunked_3mb.strm        # 3 MB PT mode CHUNKED
│   ├── empty.strm              # 0 byte PT edge case
│   └── vectors.json            # mnémonique + session_id + seq_num par fichier
└── protocol/
    ├── enroll_req.json         # canonical body attendu
    └── verify_req.json
```

Chaque JSON a un champ `schema_version` pour permettre d'évoluer si jamais.

---

## 6. Sprints S0 → S9

Pour chaque sprint : **objectif**, **tâches**, **livrables**, **DoD (Definition of Done)**, **tests**.

### S0 — Bootstrap workspace (~2 j)

**Objectif** : workspace Cargo compile sur host dev, produit `.so` ARM64 via `cargo-ndk`, expose un `hello_world()` appelable depuis un test Kotlin.

**Tâches** :
1. `mkdir crypto-rs`, `cargo new --lib core/stream/ffi`, `cargo new cli`, `Cargo.toml` workspace root
2. `rust-toolchain.toml` pinne `1.80.0`
3. `cargo install cargo-ndk` + doc install NDK r26 dans `BUILD.md`
4. `frappuccino.udl` minimal : `namespace frappuccino { string hello_world(); };`
5. `build.rs` dans `ffi/` : `uniffi::generate_scaffolding("frappuccino.udl")`
6. Script `crypto-rs/build-android.sh` : `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 build --release -p frappuccino-crypto-ffi`
7. Gradle : nouvelle task dans `mobile/build.gradle` qui invoque le script et copie les `.so` dans `mobile/src/main/jniLibs/{abi}/`
8. UniFFI Kotlin scaffolding généré dans `mobile/build/generated/source/uniffi/`
9. Test Android instrumenté : `org.stream.crypto.rust.SmokeTest` appelle `Frappuccino.helloWorld()` et asserte `== "hello from rust"`
10. CI GitHub Actions (stub) : `cargo test -p frappuccino-crypto-core`, `cargo clippy --all -- -D warnings`, `cargo fmt --check`, `cargo deny check`

**Livrables** :
- Workspace cargo compilable
- `.so` ARM64 copiés dans `mobile/src/main/jniLibs/arm64-v8a/`
- Test smoke Kotlin→Rust vert
- `BUILD.md` mis à jour

**DoD** :
- `./gradlew :mobile:connectedAndroidTest --tests org.stream.crypto.rust.SmokeTest` **vert** sur Solana Seeker
- `cargo test --workspace` **vert** sur host
- Taille APK delta mesurée et documentée (attendu : +2 à +4 MB)
- Aucun Kotlin existant modifié fonctionnellement (seul Gradle touché pour brancher le build)

---

### S1 — BIP-39 parité bit-exact (~3 j)

**Objectif** : `frappuccino-crypto-core::bip39` produit des sorties strictement identiques à `Bip39.kt` sur tous les vecteurs.

**Tâches** :
1. Dumper côté Kotlin les vecteurs `parity-vectors/bip39/*.json` (§5)
2. `core/src/bip39.rs` :
   - `pub fn generate_fr() -> String` (interne : entropy OsRng + SHA-256 checksum)
   - `pub fn from_entropy(entropy: &[u8; 16]) -> String` pour tests (entropy connue)
   - `pub fn normalize_word(input: &str, lang: Language) -> Result<String, CryptoError>` — throw si inconnu (BT-HIGH-10)
   - `pub fn normalize_mnemonic(input: &str, lang: Language) -> Result<String, CryptoError>`
   - `pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64]`
3. Wordlist FR embarquée en `include_str!` ou via crate `bip39` (features=["french"]) — **à comparer bit-pour-bit** avec `bip39_fr.txt` Kotlin
4. Tests unitaires Rust : vecteurs BIP-39 officiels (Trezor test vectors si dispo en FR) + nos vecteurs Kotlin
5. Test intégration `core/tests/parity_bip39.rs` : lit `parity-vectors/bip39/*.json`, compare byte-exact
6. Handling CharArray : Rust utilise `&str` (pas de CharArray JVM), mais on zeroize le `String` temporaire via `secrecy::SecretString`

**DoD** :
- Test Kotlin qui prend un mnémonique, appelle Rust (via UniFFI stub temporaire), vérifie seed == seed Kotlin : **vert**
- 100% vecteurs parity-vectors/bip39/*.json passent en Rust
- `normalize_word("aïeul_inexistant", FR)` throw `CryptoError::InvalidMnemonic` (pas de fallback silencieux)

**Tests à ajouter** :
- `normalize_word_unknownWord_throws` côté Rust
- `mnemonic_seed_matches_kotlin_vector_for_all_fixtures`

---

### S2 — HKDF + SecretBytes + LockedSecret (~2 j)

**Objectif** : primitives de gestion des secrets et dérivation, prêtes à être consommées par identity/ratchet.

**Tâches** :
1. `core/src/hkdf.rs` : wrapper thin autour de `hkdf = "0.12"` → `fn hkdf_sha256(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8>` (no salt, aligné sur l'usage Kotlin)
2. `core/src/secret.rs` :
   - `pub struct SecretBytes` wrap `Secret<Vec<u8>>` (`secrecy` crate)
   - `SecretBytes::new(size)`, `from_slice(&[u8])`, `with_bytes<R>(f)`, `with_bytes_mut<R>(f)`
   - Derive `ZeroizeOnDrop` via `zeroize::ZeroizeOnDrop`
   - `LockedSecret` : wrap `SecretBytes` + `memsec::mlock` sur le buffer sous-jacent
3. Tests unitaires :
   - `SecretBytes::new(32)` puis drop → vérifier que le buffer est zeroisé (via pointer tracking unsafe en test uniquement)
   - `LockedSecret` : `mlock` retourne OK, `munlock` au drop
4. Property test : `hkdf_sha256(ikm, info, len)` == précomputé pour 100 triplets aléatoires

**DoD** :
- `cargo test -p frappuccino-crypto-core` vert
- `cargo clippy -- -D warnings` propre
- Benchmarks Criterion initiaux : `hkdf_sha256` ≤ 10 µs sur 32B output (sanity)

---

### S3 — Identity derivation (~3 j)

**Objectif** : `StreamIdentity`, `EnrollmentKit`, `ArchiveIdentity` en Rust, parité totale avec Kotlin.

**Tâches** :
1. Dumper vecteurs `parity-vectors/identity/derive.json` côté Kotlin (mnemonic+passphrase → ed25519_pk hex, x25519_pk hex, chain_0 hex, fingerprint hex)
2. `core/src/identity.rs` :
   - `pub struct StreamIdentity { ed25519_pk: [u8; 32], x25519_pk: [u8; 32] }`
   - `impl StreamIdentity { fn from_seed(seed: &[u8; 64]) -> Self }`
     - HKDF seed + `"stream.identity.ed25519.v1"` → 32B Ed25519 seed → `SigningKey::from_bytes` (ed25519-dalek)
     - HKDF seed + `"stream.encryption.x25519.v1"` → 32B → `StaticSecret` (x25519-dalek)
   - `pub struct EnrollmentKit { identity, signing_key: SecretBytes, chain_0: SecretBytes }`
     - `fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self>`
     - `fn sign_once(&mut self, msg: &[u8]) -> Result<Signature>` (consume-once contract)
     - `fn ratchet_chain_zero(&mut self) -> Result<SecretBytes>` (consume-once)
     - `Drop` zeroize tous les SecretBytes
   - `pub struct ArchiveIdentity { identity, decryption_sk: SecretBytes }`
     - `fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self>`
3. Tests parité (`core/tests/parity_identity.rs`) : charge `derive.json`, pour chaque ligne vérifie byte-exact
4. Tests unitaires :
   - `sign_once` deux fois → 2e appel throw `AlreadyConsumed`
   - `ratchet_chain_zero` deux fois → 2e appel throw `AlreadyConsumed`
   - Drop d'un `EnrollmentKit` → memory pointer zeroisé (test unsafe)

**DoD** :
- 100% vecteurs identity passent
- Test cross-language : Kotlin produit `Signature` sur un message → Rust verify avec ed_pk → OK (et vice-versa)

---

### S4 — PinProtectedStore + glue PinAttemptTracker (~2 j)

**Objectif** : `PinProtectedStore` Rust bit-identique au Kotlin actuel. **PinAttemptTracker reste Kotlin** (SharedPreferences Android-specific).

**Tâches** :
1. Dumper vecteurs `parity-vectors/pin_store/{seal,open}.json` avec `{pin, plaintext, salt, nonce, blob_hex}` (salt+nonce fixés pour déterminisme)
2. `core/src/pin_store.rs` :
   - `pub fn seal(pin: &str, plaintext: &[u8]) -> Result<Vec<u8>>` (salt+nonce random via OsRng)
   - `pub fn seal_deterministic(pin: &str, plaintext: &[u8], salt: [u8; 16], nonce: [u8; 24]) -> Result<Vec<u8>>` (pour tests)
   - `pub fn open(pin: &str, blob: &[u8]) -> Result<Vec<u8>>`
   - Argon2id params explicites : `Params::new(262_144 /* kiB = 256 MiB */, 4, 1, Some(32))`
   - AAD = `b"frappuccino-v2-pin-store-v1"` + version byte éventuel (à vérifier côté Kotlin)
3. Tests parité byte-exact sur les vecteurs
4. Tests unitaires :
   - Seal→open roundtrip avec PIN correct → OK
   - Open avec PIN incorrect → `CryptoError::WrongPin`
   - Open avec blob corrompu (1 bit flip dans ciphertext) → `WrongPin` (AEAD rejette)
   - Open avec blob tronqué → `InvalidBlob`

**DoD** :
- Vecteurs Kotlin déchiffrables en Rust et vice-versa
- Benchmark : `seal` ≤ 2× temps Kotlin sur Solana Seeker (Argon2id dominate)

**Note glue** : `PinAttemptTracker` Kotlin reste en l'état. Il appelle `PinProtectedStore::open` via FFI. Sur `WrongPin` exception, il incrémente son compteur et `commit()`. Sur succès, il reset.

---

### S5 — EphemeralRatchet V2 (~5 j)

**Le sprint critique.** Tout écart sur ratchet casse les identités déjà enrôlées sur serveur.

**Objectif** : `EphemeralRatchet` Rust produit des blobs V2 byte-identiques + verify les blobs V1 legacy.

**Tâches** :
1. Dumper vecteurs ratchet :
   - `init.json` : `chain_0` (32B) → `batch_pks[50]` + `chain_1`
   - `sign.json` : état ratchet + message → signature hex + key_index consommé + mask post-sign
   - `rotate.json` : chain_n → {signer_idx, sig_of_new_pks, new_batch_pks[50], chain_{n+1}}
   - `blob_v2.bin` : état canonique → 4876 bytes (inclut HMAC)
   - `blob_v1_legacy.bin` : ancien blob → 4844 bytes (doit être lu, converti en V2 au serialize suivant)
2. `core/src/ratchet.rs` :
   - Constantes figées (§1.3)
   - `pub struct EphemeralRatchet { batch_num: u32, mask: [u8; 7], chain: SecretBytes, pks: [[u8; 32]; 50], sks: [SecretBytes; 50], consumed: [bool; 50] }`
     - `sks` ne peut pas être `[SecretBytes; 50]` littéral (SecretBytes n'a pas Copy) → utiliser `Vec<SecretBytes>` avec `len == 50` asserted ou `heapless::Vec`
   - `fn initialize(chain_0: &[u8; 32]) -> Self` : HKDF `CTX_BATCH_SEEDS` + `CTX_NEXT_CHAIN`
   - `fn batch_public_keys(&self) -> &[[u8; 32]; 50]`
   - `fn sign_and_advance(&mut self, msg: &[u8]) -> Result<RatchetSignature>`
     - Trouve premier slot non consommé (`consumed[i] == false`)
     - Sign avec `sks[i]`
     - Mark `consumed[i] = true`, update mask
     - Zeroize `sks[i]`
   - `fn prepare_rotation(&mut self) -> Result<BatchRotation>`
     - Consume slot courant pour signer les nouveaux pks
     - Dérive nouveau batch depuis `chain_{n+1}`
     - Retourne `{signer_idx, sig, new_batch_pks, new_batch_sig}`
   - `fn advance_batch(&mut self, rotation: BatchRotation) -> Result<()>` (apply rotation localement)
   - `fn serialize(&self) -> Vec<u8>` → 4876 bytes :
     - Build 4844 payload bytes
     - HMAC-SHA256(HKDF(chain, CTX_BLOB_MAC, 32), payload) → 32B MAC appended
   - `fn deserialize(blob: &[u8]) -> Result<Self>` :
     - version byte check : V2 (4876) → verify MAC or throw ; V1 (4844) → accept, no MAC check
     - Parse header (mask, chain, batch_num)
     - Parse 50 slots (pk + sk)
3. Tests parité : chaque vecteur de `ratchet/*.{json,bin}` passe
4. Tests unitaires :
   - `deserialize(v2 payload tampered)` → throw `InvalidBlob` (HMAC mismatch)
   - `deserialize(v2 MAC tampered)` → throw
   - `deserialize(v2 chain tampered)` → throw (chain → clé MAC différente)
   - `deserialize(v1 legacy)` → OK, next `serialize()` produit V2 (migration auto)
   - `sign_and_advance` 51 fois → 51e throw `BatchExhausted`
5. Property test : serialize→deserialize roundtrip 1000 états aléatoires

**DoD** :
- Vecteur Kotlin-produced V2 (4876B) déchiffrable et vérifiable en Rust byte-exact
- Vecteur Rust-produced V2 déchiffrable en Kotlin (verify via AndroidTest)
- Legacy V1 auto-migre en V2 sur re-serialize

---

### S6 — Format STRM v1 + crypto_box_seal (~7 j)

**Sprint le plus volumineux**, à cause de la surface format + modes SINGLE/CHUNKED + reproduction de `crypto_box_seal`.

**Objectif** : `SovereignEncryptor` et `ArchiveDecryptor` Rust produisent/consomment des blobs STRM byte-identiques au Kotlin.

**Tâches** :
1. Dumper vecteurs `strm_blobs/*.strm` avec mnémonique + session_id + seq_num dans `vectors.json`
2. Lire le parser Kotlin actuel (`ArchiveDecryptor.kt`, `SovereignEncryptor.kt`) pour documenter précisément l'endianness et le layout header — **à faire en S6.1, avant de coder**
3. `stream/src/seal.rs` : reproduction pure Rust de `crypto_box_seal` (libsodium)
   - Algo : ephemeral X25519 keypair, Blake2b(epk||recipient_pk)=nonce, XSalsa20-Poly1305
   - Teste bit-exact contre output libsodium sur vecteurs Kotlin (vecteurs Kotlin utilisent `sodium.crypto_box_seal`, Rust doit produire identique pour mêmes inputs déterministes)
   - **ATTENTION** : `crypto_box_seal` utilise XSalsa20-Poly1305, PAS XChaCha20-Poly1305. Vérifier dans les crates RustCrypto :
     - `xsalsa20poly1305 = "0.9"` (existe)
     - `salsa20 = "0.10"`
4. `stream/src/header.rs` : parser/serializer header STRM
5. `stream/src/encrypt.rs` : `SovereignEncryptor`
   - Mode SINGLE : tout plaintext en un XChaCha20-Poly1305 chunk, nonce random, AAD = header
   - Mode CHUNKED : chunks fixes (taille = lu dans header), chaque chunk nonce random, AAD = header+seq
6. `stream/src/decrypt.rs` : `ArchiveDecryptor` symétrique
7. Tests parité : chaque `strm_blobs/*.strm` déchiffrable en Rust byte-exact (plaintext identique)
8. Tests cross-platform :
   - Rust encrypt → écrit fichier → Kotlin decrypt (AndroidTest) → plaintext OK
   - Kotlin encrypt → Rust decrypt → plaintext OK
9. Fuzzing : `cargo fuzz run decrypt_blob` 10M iter en sprint (100M visé en S9)

**DoD** :
- 100% vecteurs STRM déchiffrables byte-exact
- Round-trip Kotlin↔Rust OK sur SINGLE et CHUNKED
- Fuzz 10M iter sans crash

**Risque principal** : `crypto_box_seal` est rarement porté pure Rust. Si la reproduction pose problème :
- Plan B : utiliser `sodiumoxide` **uniquement pour `crypto_box_seal`** isolé dans un `feature = "libsodium-seal"`, piste à éviter sauf si bloquant (rompt l'objectif "0 dep C")
- Plan C (recommandé) : composer `x25519-dalek` + `blake2` + `xsalsa20poly1305` à la main (algo public, ~50 lignes)

---

### S7 — StreamServerClient + CertPin (~3 j)

**Objectif** : client HTTP Rust authentifie contre serveur Vultr prod **avec cert pinning actif**.

**Tâches** :
1. Dumper vecteurs `protocol/{enroll_req,verify_req}.json` (body canoniques attendus par serveur)
2. `stream/src/protocol.rs` :
   - `pub struct StreamServerClient { base_url: String, http: reqwest::blocking::Client }`
   - `new(base_url: &str) -> Result<Self>` :
     - Lit cert embarqué (`include_bytes!("../../../mobile/src/main/res/raw/frappuccino_ca.crt")` ou équivalent pour crate Rust — préférer embed dans `ffi/`)
     - Construit `RootCertStore` custom
     - Custom `ServerCertVerifier` qui vérifie aussi le pin SPKI SHA-256 = `mGGCW...BOA=` (défense en profondeur, comme Kotlin)
   - Méthodes : `enroll`, `challenge`, `verify`, `rotate_batch`, `get_status`
3. Tests E2E contre serveur Vultr :
   - Run bypass clippy/ci (requiert network)
   - Nouveau mnémonique → enroll → challenge → verify → status
   - Identique au test Kotlin `e2eEnrollAndAuthenticate_againstLiveServer`
4. Test defense-in-depth : wrong pin → `reqwest::Error` (équivalent `SSLPeerUnverifiedException`)

**DoD** :
- Rust authentifie contre serveur prod (même identité enrôlée utilisable par Kotlin et Rust)
- Wrong-pin negative test passe

---

### S8 — UniFFI complet + migration `mobile/` (~5 j)

**Objectif** : tous les call-sites Kotlin de `stream-crypto/` passent par la lib Rust via UniFFI. Le module `stream-crypto/` Kotlin peut être supprimé.

**Tâches** :
1. Compléter `frappuccino.udl` (voir §4.3 du plan stratégique)
2. `ffi/src/lib.rs` : re-exports avec types UniFFI-friendly (conversion `Vec<u8>` ↔ `bytes`, `String` ↔ `string`, `Result<T,E>` → exceptions typées)
3. Mapping Kotlin → bindings UniFFI :
   - `EnrollmentKit.fromMnemonic(...)` → `uniffi.frappuccino.EnrollmentKit.fromMnemonic(...)`
   - `EphemeralRatchet(...)` → `uniffi.frappuccino.EphemeralRatchet(...)`
   - `ArchiveDecryptor(...)` → `uniffi.frappuccino.ArchiveDecryptor(...)`
   - `StreamServerClient(...)` → `uniffi.frappuccino.StreamServerClient(...)`
4. Migration call-sites `mobile/` :
   - `OnBoardSetPinFragment.enrollWithPin()`
   - `PinUnlockActivity.tryUnlock()`
   - `ArchiveModeActivity.tryUnlock()`
   - `StreamSettingsActivity.*`
   - `StreamRecordingService.onChunkReady()`
   - `MyApplication.initStreamUploadManager()`
5. Garder un feature flag `USE_RUST_CRYPTO = true` pour pouvoir toggler si bug critique
6. Tous les tests instrumentés `stream-crypto/androidTest/` rejoués contre la lib Rust via FFI (adapter les tests au fur et à mesure, ou créer un miroir temporaire)
7. Suppression progressive `stream-crypto/src/main/java/org/stream/crypto/` (fichier par fichier, au fur et à mesure qu'il est supplanté)

**DoD** :
- 72/72 tests instrumentés passent avec `USE_RUST_CRYPTO = true`
- Onboarding complet + enregistrement stream + archive decrypt : E2E manuel OK sur Solana Seeker
- Module Gradle `stream-crypto/` supprimable (toggle pour valider)
- Mesure APK : delta net (Rust .so +N MB, suppression Kotlin -M MB)

---

### S9 — CLI Rust + hardening + audit prep (~5 j)

**Objectif** : remplacer les 3 scripts Python par un binaire `frappuccino-cli`, terminer le hardening, générer l'audit scope.

**Tâches** :
1. `cli/src/main.rs` avec `clap` :
   - `frappuccino-cli decrypt --mnemonic "..." blob.strm -o out.bin`
   - `frappuccino-cli decrypt --inspect blob.strm`
   - `frappuccino-cli decrypt --reassemble session_dir/ --mnemonic "..." -o final.mp4` (ffmpeg via `std::process::Command`)
   - `frappuccino-cli archive --server URL --session-id SID --mnemonic "..." -o out.mp4`
   - `frappuccino-cli parity-test` (run tous les vecteurs)
2. CI : build binaires Linux x86_64, macOS aarch64, Windows x86_64
3. Suppression `server-tools/stream_decrypt.py`, `stream_archive.py`, `test_stream.py` (garder 1 trimestre en archive git, supprimer du tip)
4. Hardening :
   - `cargo audit` : 0 vuln
   - `cargo deny check` : OK licenses + bans
   - `cargo tarpaulin` : ≥ 90% coverage sur `core` + `stream`
   - `cargo fuzz run decrypt_blob` : 100M iter sans crash
   - `cargo fuzz run parse_strm_header` : 50M iter
   - `cargo fuzz run ratchet_deserialize` : 100M iter
5. Doc :
   - `cargo doc --document-private-items` généré dans `crypto-rs/target/doc`
   - `AUDIT_SCOPE_RUST.md` décrit périmètre, invariants, crates, surface FFI, checklist audit
   - `THREAT_MODEL.md` mis à jour : crypto core = Rust (ex : sections GC orphans → "N/A, Rust")
6. Build reproductible :
   - `cargo build --release` 2× → `diff target/release/libfrappuccino_crypto_ffi.so` = 0 bytes

**DoD** :
- Binaire CLI fonctionne sur 3 OS cibles
- Tous les fuzz targets ≥ cible d'itérations sans crash
- Coverage ≥ 90%
- `AUDIT_SCOPE_RUST.md` écrit et relu

---

## 7. Coexistence Kotlin/Rust pendant la transition

Entre S0 et S8, les deux implémentations cohabitent. Stratégie :

1. **Pas de double-chiffrement.** Un stream enregistré utilise *une* impl (Kotlin ou Rust). On ne chiffre pas en Kotlin puis redéchiffre pour re-chiffrer en Rust.
2. **Feature flag Gradle `useRustCrypto`** dans `mobile/build.gradle` :
   - `buildConfigField 'boolean', 'USE_RUST_CRYPTO', useRustCrypto.toString()`
   - Par défaut `false` pendant S0-S7, `true` à partir de S8
3. **Les blobs ratchet sérialisés sont interopérables** par construction (même format V2). Donc si on migre un device Kotlin vers Rust, le blob V2 sur disque est consommé par les deux sans migration applicative.
4. **Tests parity.rs protègent le cas pivot** : à chaque commit, on vérifie que les vecteurs Kotlin sont déchiffrables en Rust et vice-versa. Toute régression casse la CI avant merge.
5. **Pas de branch de feature longue.** Sprints mergés en `main` au fil de l'eau, cachés derrière le flag. Trunk-based.

---

## 8. Gates de non-régression (par sprint)

Chaque sprint doit passer ces gates avant d'être déclaré terminé :

| Gate | S0 | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 |
|---|---|---|---|---|---|---|---|---|---|---|
| `cargo build --workspace --release` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cargo test --workspace` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cargo clippy -- -D warnings` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cargo fmt --check` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cargo deny check` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cargo audit` | — | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Parity vectors du sprint | — | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cross-lang roundtrip | — | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 72/72 AndroidTest (Kotlin legacy path) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 72/72 AndroidTest (Rust path) | — | — | — | — | — | — | — | — | ✅ | ✅ |
| Coverage ≥ 80% (core+stream) | — | — | — | — | — | — | ✅ | ✅ | ✅ | ✅ |
| Fuzz 1M iter (decrypt_blob) | — | — | — | — | — | — | ✅ | ✅ | ✅ | ✅ |
| Fuzz 100M iter | — | — | — | — | — | — | — | — | — | ✅ |
| `AUDIT_SCOPE_RUST.md` | — | — | — | — | — | — | — | — | — | ✅ |
| Reproducible build | — | — | — | — | — | — | — | — | — | ✅ |

---

## 9. Risques opérationnels et mitigations

### 9.1 Divergence wordlist BIP-39 FR

**Risque** : la crate `bip39` v2 utilise une wordlist FR qui diverge d'un caractère de `stream-crypto/src/main/resources/bip39_fr.txt`.
**Mitigation** : S1 jour 1, `diff` des deux wordlists. Si divergence → embarquer la wordlist Kotlin en `include_str!` au lieu d'utiliser la feature `french` de la crate.

### 9.2 Reproduction `crypto_box_seal` en pure Rust

**Risque** : aucune crate RustCrypto ne fournit `crypto_box_seal` identique à libsodium (XSalsa20-Poly1305 + Blake2b nonce derivation).
**Mitigation** : composer à la main avec `x25519-dalek` + `xsalsa20poly1305` + `blake2`. Si échec parité bit-exact → plan B : `sodiumoxide` isolé via feature gate (dernier recours, rompt partiellement l'objectif "0 dep C").

### 9.3 UniFFI Kotlin API cassée pour types complexes

**Risque** : UniFFI 0.28 génère du Kotlin bizarre pour `sequence<bytes>` ou `dictionary` imbriqués.
**Mitigation** : S0 inclut un test UniFFI non-trivial (pas juste `hello_world`), au minimum une struct avec `bytes` + `u32`. Si API générée trop moche → encapsuler derrière un wrapper Kotlin manuel dans un module `stream-crypto-rust-wrapper/`.

### 9.4 Performance Argon2id ARM64

**Risque** : Argon2id pure Rust mesuré 5-15% plus lent que libsodium sur ARM. Sur Argon2 256 MiB ops=4, ça peut faire passer l'unlock de ~2.5s à ~3s sur Seeker.
**Mitigation** : bench dès S4 sur Seeker. Si > 20% régression → augmenter la parallélisation (`p > 1`) après validation que l'utilisateur ne perd pas de sécurité. **Ne pas baisser** ops ou mem sans discussion explicite.

### 9.5 Taille APK

**Risque** : `.so` par ABI + runtime Rust alourdit l'APK de 3-8 MB.
**Mitigation** :
- `strip` des symbols dans `.so` release
- `[profile.release] lto = "fat"`, `codegen-units = 1`, `opt-level = "s"` (size optimization)
- Mesure APK delta à chaque sprint, report dans `BUILD.md`
- Si > 10 MB : split per-ABI APK (bundle)

### 9.6 Dérive d'implémentation pendant le port

**Risque** : pendant S1-S7 (porting), une PR Kotlin change discrètement un comportement (ex: nouveau AAD byte ajouté à un blob). Rust, fixé sur les vecteurs d'un snapshot précédent, diverge.
**Mitigation** :
- **Freeze crypto côté Kotlin** pendant le port (pas de nouveau format sans synchronisation avec la version Rust)
- Les CI parity tests Kotlin-Rust sont le canari — ils fail dès qu'un côté dérive
- Tout changement d'invariant §1 = PR explicite qui touche **les deux impls + les vecteurs** en même temps

### 9.7 Temps de build Android

**Risque** : ajouter un build Rust dans Gradle augmente le temps de CI de 3-5 min par ABI (9-15 min pour 3 ABI).
**Mitigation** :
- Cache Gradle + cache cargo (sccache ou rust-cache GitHub Action)
- Ne builder `x86_64` qu'en CI (émulateur), ARM64 en local dev
- Build Rust en parallèle des autres tasks Gradle si possible

---

## 10. Checklist démarrage immédiat (S0 jour 1)

Ordre exact, aucune étape skippable :

- [ ] Installer Rust 1.80.0 (`rustup install 1.80.0`, `rustup default 1.80.0`)
- [ ] Installer `cargo-ndk` : `cargo install cargo-ndk`
- [ ] Installer `cargo-deny`, `cargo-audit`, `cargo-tarpaulin`, `cargo-fuzz`
- [ ] Vérifier NDK r26 installé dans `~/Android/Sdk/ndk/26.x.x`
- [ ] `git checkout -b claude/rust-port-s0` (nouveau worktree)
- [ ] Créer `crypto-rs/` avec `Cargo.toml` workspace
- [ ] Créer les 4 crates : `core`, `stream`, `ffi`, `cli`
- [ ] `rust-toolchain.toml` pinne 1.80.0
- [ ] `deny.toml` : bans sur GPL, OpenSSL, ring (si pas voulu)
- [ ] `.github/workflows/rust.yml` : CI basique (test + clippy + fmt)
- [ ] `frappuccino.udl` minimal avec `hello_world()`
- [ ] `build-android.sh` testé localement → produit `.so` ARM64
- [ ] Task Gradle `:mobile:copyRustLibs` qui copie les `.so` dans `jniLibs/`
- [ ] Test Kotlin `SmokeTest.kt` appelle `Frappuccino.helloWorld()` → vert sur Seeker
- [ ] `BUILD.md` : section "Rust build prerequisites" + commandes
- [ ] Commit unique : `feat(rust): S0 bootstrap workspace + UniFFI smoke test`
- [ ] PR draft (ou push direct main selon préférence) → passe CI

Si tout OK après S0 jour 1 : S0 terminé le jour 2 (finalisation CI multi-ABI + doc), S1 démarre jour 3.

---

## 11. Critères d'arrêt global

Le port est "terminé" quand **tous** ces critères sont remplis :

### 11.1 Techniques
- [ ] `stream-crypto/` Kotlin supprimé du repo (ou réduit à un tombstone deprecated)
- [ ] `frappuccino-crypto-ffi` exporte 100% des API consommées par `mobile/`
- [ ] 72/72 AndroidTest historiques verts avec `USE_RUST_CRYPTO=true`
- [ ] 0 dépendance C dans `crypto-rs/` (`cargo tree | grep -iE "sys$"` vide ou justifié)
- [ ] `frappuccino-cli` remplace les 3 scripts Python (supprimés)
- [ ] CI verte sur Linux x86_64, macOS arm64, Windows x86_64

### 11.2 Parité
- [ ] 100% vecteurs `parity-vectors/` passent byte-exact
- [ ] Cross-platform encrypt/decrypt roundtrip Kotlin↔Rust OK sur STRM, PinStore, Ratchet
- [ ] Authent serveur Vultr prod OK avec une identité enrôlée par Kotlin

### 11.3 Qualité
- [ ] Coverage ≥ 90% sur `core` + `stream`
- [ ] Fuzz 100M iter sans crash sur chaque target
- [ ] `cargo audit` : 0 vuln
- [ ] `cargo deny check` : OK
- [ ] Build reproductible : diff 0 bytes sur 2 builds release successifs

### 11.4 Audit-ready
- [ ] `AUDIT_SCOPE_RUST.md` rédigé
- [ ] `THREAT_MODEL.md` mis à jour (crypto core = Rust)
- [ ] `cargo doc` publiable
- [ ] README du workspace `crypto-rs/README.md` avec invariants §1 résumés

Tant que ces critères ne sont pas tous cochés, le port est "en cours". On peut `main` avec `USE_RUST_CRYPTO=false` par défaut indéfiniment, le flag est le kill-switch.

---

## 12. Documents liés

- [`PORT_RUST_OPTION_B.md`](PORT_RUST_OPTION_B.md) — plan stratégique (archi, mapping, justifications)
- `HARDENING_KOTLIN.md` (non conserve au depot) — Option A, déjà faite (P0 + P1 remediation)
- `SESSION_CONTEXT_COMPACT_V2.md` (non conserve au depot) — contexte projet post-P1
- [`ROADMAP.md`](../../ROADMAP.md) — vue d'ensemble produit
- `ARCHITECTURE_V2.md`, `CRYPTOGRAPHIE.md`, `ARCHITECTURE_TECHNIQUE.md` — références internes

---

*Dernière mise à jour : 2026-04-17. Mettre à jour avec le commit hash quand S0 démarre.*
