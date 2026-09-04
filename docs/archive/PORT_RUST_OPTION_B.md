# Frappuccino — Plan détaillé Option B : port Rust de `stream-crypto/`

> Plan de migration de la couche cryptographique Kotlin vers Rust, exposée à `mobile/` (Android Kotlin) et au CLI via UniFFI. UI Android reste Kotlin.
> Snapshot au 16 avril 2026, post-commit `f019431`.
> Préalable : `HARDENING_KOTLIN.md` (option A) — le port Rust n'a de sens qu'après l'audit V2 Kotlin durci.
> Suite : audit RED TEAM / BLUE TEAM du nouveau cœur Rust.

---

## Table des matières

1. [Vue d'ensemble et objectifs](#1-vue-densemble-et-objectifs)
2. [Périmètre du port](#2-périmètre-du-port)
3. [Choix techniques fondamentaux](#3-choix-techniques-fondamentaux)
4. [Architecture cible](#4-architecture-cible)
5. [Mapping Kotlin → Rust (module par module)](#5-mapping-kotlin--rust-module-par-module)
6. [Phases du port](#6-phases-du-port)
7. [Stratégie de tests et parité binaire](#7-stratégie-de-tests-et-parité-binaire)
8. [Intégration Android (NDK + UniFFI)](#8-intégration-android-ndk--uniffi)
9. [CLI Python → binaire Rust unifié](#9-cli-python--binaire-rust-unifié)
10. [Préparation audit RED TEAM / BLUE TEAM](#10-préparation-audit-red-team--blue-team)
11. [Calendrier et jalons](#11-calendrier-et-jalons)
12. [Risques et mitigations](#12-risques-et-mitigations)
13. [Critères d'acceptation](#13-critères-dacceptation)

---

## 1. Vue d'ensemble et objectifs

### 1.1 Pourquoi Option B après Option A

L'option A (hardening Kotlin) fait passer la V2 d'**auditable** à **production-grade**. Mais elle n'élimine pas trois limitations structurelles documentées dans `HARDENING_KOTLIN.md §1.2` :

1. **GC orphans** : un secret en `ByteArray` peut être copié par le GC à tout moment ; `Arrays.fill(0)` n'atteint que la copie courante.
2. **JIT dead-store elimination** : mitigation H1.1 partielle, jamais formellement vérifiable au niveau bytecode.
3. **Pas de pinning natif** : `mlock` via JNI ne couvre pas les `ByteArray` JVM, seulement les `ByteBuffer.allocateDirect`.

Le port Rust ferme ces trois trous **structurellement** (pas de GC, RAII déterministe, allocation native par construction).

Bénéfices secondaires :
- **CLI Python déprécié** : `stream_decrypt.py`, `stream_archive.py`, `test_stream.py` deviennent un binaire Rust unique compilé pour Linux/macOS/Windows. Une seule source de vérité pour la crypto, plus de divergence accent BIP-39 / format STRM.
- **Préparation iOS** : la même crate Rust peut être exposée à Swift via UniFFI sans réécriture.
- **Audit externe simplifié** : surface réduite à ~5-7 K lignes Rust pure (vs ~15 K Kotlin + Python aujourd'hui), formellement vérifiable par sections (HACL\*, Trail of Bits typestate patterns).
- **Build reproductible natif** : `cargo` + `Cargo.lock` plus déterministe que Gradle.

### 1.2 Ce que l'option B n'est PAS

- ❌ Une réécriture de l'app Android. UI, CameraX, WorkManager, Hilt, ExoPlayer, services Tella legacy résiduels : **tout reste Kotlin**.
- ❌ Une migration big-bang. Le port se fait **module par module** avec parité testée à chaque étape.
- ❌ Un changement du protocole V2 ou du format STRM v1. Le wire format reste **byte-pour-byte identique**. Les blobs produits par la version Rust se déchiffrent par la version Kotlin et inversement, jusqu'à la complétion.
- ❌ Une dépendance à libsodium. Le port utilise [RustCrypto](https://github.com/RustCrypto) (pur Rust, audité), pas de FFI vers libsodium-native. Réduit la surface d'attaque supply chain à un seul écosystème (cargo).

### 1.3 Objectif quantifié

À la fin du port :
- 100% des primitives `stream-crypto/` exécutées en Rust, exposées à Kotlin via UniFFI
- 0 dépendance à `lazysodium-android`, `libsodium-jni`, JNA dans `stream-crypto/`
- `mobile/` consomme `stream-crypto-rust` via interface Kotlin auto-générée par UniFFI
- CLI binaire `frappuccino-cli` remplace les 3 scripts Python
- Tests parité 100% : tous les vecteurs de `test_stream.py` passent en Rust
- Build APK reproductible (diff = 0 bytes entre 2 builds dans environnement contrôlé)

---

## 2. Périmètre du port

### 2.1 Modules à porter (IN SCOPE)

Tous les fichiers de `stream-crypto/src/main/java/org/stream/crypto/` :

| Fichier Kotlin actuel | Crate / module Rust cible |
|---|---|
| `Bip39.kt` | `frappuccino-bip39` (crate dédiée) |
| `StreamIdentity.kt` | `frappuccino-identity` |
| `EnrollmentKit.kt` | `frappuccino-identity::enrollment` |
| `ArchiveIdentity.kt` | `frappuccino-identity::archive` |
| `ArchiveDecryptor.kt` | `frappuccino-strm::decrypt` |
| `SovereignEncryptor.kt` | `frappuccino-strm::encrypt` |
| `secure/SecureMemory.kt` | `frappuccino-secure::SecretBytes` (via `zeroize` + `secrecy`) |
| `secure/PinProtectedStore.kt` | `frappuccino-secure::pin_store` |
| `ratchet/EphemeralRatchet.kt` | `frappuccino-ratchet` (crate dédiée) |
| `ratchet/Hkdf.kt` | utilise `hkdf` crate RustCrypto |
| `upload/StreamUploadManager.kt` | `frappuccino-protocol::upload_manager` (états + lifecycle) |
| `upload/StreamServerClient.kt` | `frappuccino-protocol::server_client` (HTTP via `reqwest`) |
| `upload/ChunkUploadQueue.kt` | reste partiellement Kotlin (intégration WorkManager) ou exposé via FFI |
| `upload/EncryptedBlobRequestBody.kt` | reste Kotlin (OkHttp specific) |
| `upload/VaultFileStreamProvider.kt` | obsolète (legacy V1), à supprimer |
| `capture/StreamChunkEncryptor.kt` | reste Kotlin (intégration CameraX) |
| `capture/StreamChunkCapture.kt` | reste Kotlin (CameraX specific) |
| `capture/ShakeDetector.kt` | reste Kotlin (SensorManager Android) |
| `StreamPreferences.kt` | reste Kotlin (SharedPreferences Android) |

### 2.2 Modules qui restent Kotlin (OUT OF SCOPE)

Tout ce qui touche aux APIs Android natives :
- CameraX integration
- WorkManager / ChunkUploadWorker
- SharedPreferences storage (le **blob** chiffré est produit par Rust mais persisté par Kotlin)
- SensorManager (shake detector)
- Intent / Activity lifecycle
- OkHttp request body construction

### 2.3 Glue zone

Une fine couche Kotlin orchestre le call vers Rust :

```kotlin
// mobile/.../service/StreamRecordingService.kt (inchangé sauf appels)
private fun onChunkReady(chunkFile: File, seqNum: Int) {
    val blob = FrappuccinoCrypto.encryptChunk(  // UniFFI-generated
        sessionId = sessionId,
        seqNum = seqNum,
        plaintextPath = chunkFile.absolutePath,
        outputPath = blobFile.absolutePath
    )
    uploadQueue.enqueue(blobFile)
    scheduleUpload()
}
```

Le secret n'apparaît jamais côté Kotlin : path d'entrée → path de sortie, traitement intégral en Rust.

---

## 3. Choix techniques fondamentaux

### 3.1 Bindings : UniFFI (recommandé) vs JNI manuel

**UniFFI** ([uniffi-rs](https://mozilla.github.io/uniffi-rs/), Mozilla) :

✅ Pour :
- Génère automatiquement les bindings Kotlin (et Swift, Python) depuis un fichier UDL
- Gère le lifecycle des objets cross-language (pas de fuites GlobalRef)
- Type system unifié : `Result<T, E>` Rust → exception Kotlin typée
- Utilisé en prod par Firefox Mobile (Mozilla Application Services)
- Documentation et écosystème mature en 2026

❌ Contre :
- Overhead léger (sérialisation cross-FFI à chaque call)
- Pas adapté pour les APIs très chatty (mais notre cas est coarse-grained)

**JNI manuel** :

✅ Pour :
- Contrôle total de la surface FFI
- Pas de sérialisation intermédiaire (zero-copy possible)

❌ Contre :
- Code boilerplate massif (chaque méthode = 50-100 lignes de Rust JNI)
- Lifecycle GlobalRef/LocalRef à gérer manuellement → bugs subtils
- Refactor coûteux à chaque changement d'API
- Maintenance pénible solo dev

**Décision** : **UniFFI**. Le surcoût performance (~µs par call) est négligeable pour notre cas (call rate < 100/s même en stream). Le gain en maintenabilité et sécurité (pas de bugs JNI manuels) est massif.

### 3.2 Crypto primitives : RustCrypto (recommandé) vs sodiumoxide vs ring

**RustCrypto** (pure Rust, audité) :

| Primitive | Crate | Audit |
|---|---|---|
| Ed25519 | `ed25519-dalek` 2.x | Oui (Trail of Bits 2019, NCC 2022) |
| X25519 | `x25519-dalek` 2.x | Oui (idem) |
| XChaCha20-Poly1305 | `chacha20poly1305` 0.10+ | Oui (NCC 2021) |
| Argon2id | `argon2` 0.5+ | Oui (cure53 2021 sur reference impl) |
| HKDF-SHA256 | `hkdf` 0.12+ | Trivial, audité |
| BLAKE2b | `blake2` 0.10+ | Oui |
| SecureRandom | `rand_core` + `OsRng` | Wrappe `getrandom()` |
| BIP-39 | `bip39` 2.x | Bitcoin community-reviewed |

✅ Pour :
- 0 dépendance C / FFI
- Surface d'attaque supply chain réduite (cargo-vet existing reviews)
- Compatible `no_std` (pour cas extrême embedded futur)
- Constant-time par design dans la plupart des crates

❌ Contre :
- Performance : 5-15% plus lent que libsodium sur ARM (mesuré sur ed25519)
- Maturité moindre que libsodium pour quelques primitives exotiques (mais pas un problème pour notre stack)

**sodiumoxide** : bindings Rust de libsodium.
- Reproduit l'écosystème Kotlin actuel
- Nécessite encore libsodium native → on garde la dépendance C qu'on voulait éliminer
- ❌ Rejeté

**ring** (BoringSSL bindings) :
- Excellent CT et perf
- ❌ N'a pas Argon2id ni BIP-39 idiomatique
- Rejeté pour scope incomplet

**Décision** : **RustCrypto** pur. Acceptable perte de perf vs gain en simplicité supply chain et auditabilité.

### 3.3 Gestion des secrets : `secrecy` + `zeroize`

**Crates** :
- [`zeroize`](https://docs.rs/zeroize/) : zeroize garantie via `compiler_fence(SeqCst)` + writes volatils. Survives à dead-store elimination.
- [`secrecy`](https://docs.rs/secrecy/) : wrapper `Secret<T>` qui empêche `Debug` (pas de leak via `println!`), `Clone` opt-in explicite, `Drop` zeroize automatique.

**Pattern type** :

```rust
use secrecy::{Secret, ExposeSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct Ed25519SecretKey {
    bytes: [u8; 64],
}

pub struct Ratchet {
    chain_key: Secret<[u8; 32]>,
    ephemeral_keys: Vec<Option<Ed25519SecretKey>>,
}

impl Ratchet {
    pub fn sign(&mut self, idx: usize, msg: &[u8]) -> Result<Signature, RatchetError> {
        let sk = self.ephemeral_keys[idx].take()  // consume + zeroize on drop
            .ok_or(RatchetError::AlreadyConsumed)?;
        let sig = ed25519_dalek::SigningKey::from_keypair_bytes(&sk.bytes)?
            .sign(msg);
        Ok(sig)
        // sk drop → zeroize automatique
    }
}
```

### 3.4 Mémoire pinnée : `memsec` + `region`

**Crates** :
- [`memsec`](https://docs.rs/memsec/) : `mlock`, `munlock`, guard pages
- [`region`](https://docs.rs/region/) : abstraction multi-OS pour `mlock`/`madvise`

**Pattern** :

```rust
use memsec::{mlock, munlock};

pub struct LockedSecret<const N: usize> {
    ptr: *mut u8,
    len: usize,
}

impl<const N: usize> LockedSecret<N> {
    pub fn new() -> Result<Self, std::io::Error> {
        let ptr = unsafe { libc::malloc(N) as *mut u8 };
        if ptr.is_null() { return Err(...); }
        unsafe { mlock(ptr, N); }  // empêche swap
        Ok(Self { ptr, len: N })
    }
}

impl<const N: usize> Drop for LockedSecret<N> {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr, 0, self.len);  // zeroize
            munlock(self.ptr, self.len);
            libc::free(self.ptr as *mut libc::c_void);
        }
    }
}
```

### 3.5 Async runtime : tokio vs async-std vs blocking

`StreamServerClient` Kotlin actuel utilise des appels HTTP synchrones bloquants (sur thread background). Pour le port Rust :

**Décision** : utiliser `reqwest` en mode **blocking** (`reqwest = { features = ["blocking"] }`). Évite d'introduire tokio dans la stack mobile (binaire plus gros, complexité runtime). Les appels HTTP sont déjà invoqués depuis un thread Kotlin background, blocking côté Rust = pas de problème.

### 3.6 MSRV (Minimum Supported Rust Version)

**Cible** : Rust **1.75** stable (minimum). Permet `async fn in trait`, GAT stables, Cell improvements. Largement supporté NDK 25+.

### 3.7 Edition

**Rust 2021 edition** (passer à 2024 si stable au moment du port).

### 3.8 Dépendances de la crate principale (manifeste prévisionnel)

```toml
[dependencies]
# Crypto primitives
ed25519-dalek = { version = "2.1", features = ["rand_core", "zeroize"] }
x25519-dalek = { version = "2.0", features = ["zeroize"] }
chacha20poly1305 = { version = "0.10", features = ["alloc"] }
argon2 = { version = "0.5", features = ["zeroize"] }
hkdf = "0.12"
sha2 = "0.10"
blake2 = "0.10"

# Secret handling
zeroize = { version = "1.7", features = ["derive"] }
secrecy = "0.8"
subtle = "2.5"
memsec = "0.7"

# RNG
rand_core = "0.6"
getrandom = "0.2"

# BIP-39
bip39 = { version = "2.0", features = ["french"] }

# Error handling
thiserror = "1.0"

# Logging (optionnel, abstraction)
log = "0.4"

# UniFFI (à exposer côté Android/CLI)
uniffi = { version = "0.27", features = ["build"] }

# HTTP client (server protocol)
reqwest = { version = "0.11", features = ["blocking", "json", "rustls-tls"], default-features = false }

# JSON
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[build-dependencies]
uniffi = { version = "0.27", features = ["build"] }
```

Total ~30 dépendances directes, ~150 transitives. Toutes auditables via `cargo vet`.

---

## 4. Architecture cible

### 4.1 Structure du repo après port

```
Frappuccino/
├── mobile/                       # Android UI (Kotlin) — inchangé sauf imports
├── stream-crypto/                # Wrapper Kotlin minimal (deprecated post-port)
│   └── (vide ou tombstone)
├── stream-crypto-rust/           # ⭐ Nouveau : crate principale Rust
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs                # Re-exports + UniFFI scaffolding
│   │   ├── bip39/                # mod bip39
│   │   ├── identity/             # mod identity
│   │   │   ├── mod.rs
│   │   │   ├── enrollment.rs
│   │   │   ├── archive.rs
│   │   │   └── stream_identity.rs
│   │   ├── secure/               # mod secure
│   │   │   ├── mod.rs
│   │   │   ├── secret_bytes.rs
│   │   │   ├── locked_secret.rs
│   │   │   └── pin_store.rs
│   │   ├── ratchet/              # mod ratchet
│   │   │   ├── mod.rs
│   │   │   └── ephemeral.rs
│   │   ├── strm/                 # mod strm (format binaire)
│   │   │   ├── mod.rs
│   │   │   ├── encrypt.rs
│   │   │   ├── decrypt.rs
│   │   │   ├── header.rs
│   │   │   └── modes.rs
│   │   ├── protocol/             # mod protocol (V2 server)
│   │   │   ├── mod.rs
│   │   │   ├── server_client.rs
│   │   │   ├── auth_v2.rs
│   │   │   └── upload_manager.rs
│   │   └── ffi.rs                # UniFFI exports
│   ├── frappuccino.udl           # UniFFI interface definition
│   ├── tests/                    # Tests intégration
│   │   ├── parity.rs             # Parité avec vecteurs Python
│   │   ├── strm_format.rs        # Tests format binaire
│   │   ├── ratchet.rs
│   │   └── protocol.rs
│   ├── benches/                  # Criterion benchmarks
│   │   └── primitives.rs
│   └── fuzz/                     # cargo-fuzz harnesses
│       ├── Cargo.toml
│       └── fuzz_targets/
│           ├── decrypt_blob.rs
│           ├── parse_header.rs
│           └── ratchet_deserialize.rs
├── frappuccino-cli/              # ⭐ Nouveau : CLI Rust (remplace server-tools/*.py)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs               # subcommands : decrypt, archive, demo
├── server/                       # FastAPI (inchangé)
└── server-tools/                 # ⚠️ deprecated, remplacé par frappuccino-cli
```

### 4.2 Diagramme de dépendances

```
┌──────────────────────────────────────────────────┐
│ mobile/ (Android Kotlin)                         │
│  ├── StreamActivity, PinUnlockActivity, ...      │
│  ├── StreamRecordingService                      │
│  ├── ChunkUploadWorker                           │
│  └── (UniFFI-generated FrappuccinoCrypto.kt)     │
└──────────────────┬───────────────────────────────┘
                   │ FFI (UniFFI scaffolding)
┌──────────────────▼───────────────────────────────┐
│ stream-crypto-rust (libfrappuccino_crypto.so)    │
│  ├── identity (Ed25519, X25519, BIP-39 derive)   │
│  ├── secure (SecretBytes, LockedSecret, PinStore)│
│  ├── ratchet (EphemeralRatchet)                  │
│  ├── strm (encrypt/decrypt, format v1)           │
│  └── protocol (V2 server client, upload manager) │
└──────────────────┬───────────────────────────────┘
                   │ uses
┌──────────────────▼───────────────────────────────┐
│ RustCrypto + secrecy + zeroize + memsec + reqwest│
└──────────────────────────────────────────────────┘
```

### 4.3 Couche FFI : UniFFI surface

Fichier `frappuccino.udl` (interface Kotlin/Swift/Python générée) :

```
namespace frappuccino {
    // BIP-39
    [Throws=CryptoError]
    sequence<string> generate_mnemonic_fr();

    [Throws=CryptoError]
    string normalize_mnemonic(string raw);
};

interface StreamIdentity {
    [Throws=CryptoError]
    constructor(string mnemonic, string passphrase);
    string ed25519_pk_hex();
    string x25519_pk_hex();
    string fingerprint();
};

interface EnrollmentKit {
    [Throws=CryptoError, Name=from_mnemonic]
    constructor(string mnemonic, string passphrase);
    StreamIdentity identity();
    [Throws=CryptoError]
    bytes sign_once(bytes message);
    bytes ratchet_chain_zero();  // returns the chain_0 (consumed-once)
    void close();
};

interface PinProtectedStore {
    [Throws=CryptoError]
    constructor();
    [Throws=CryptoError]
    bytes seal(string pin, bytes plaintext);
    [Throws=CryptoError]
    bytes open(string pin, bytes blob);
    [Throws=CryptoError]
    bytes seal_with_key(bytes key, bytes salt, bytes plaintext);
};

interface EphemeralRatchet {
    [Throws=CryptoError, Name=from_chain]
    constructor(bytes master_chain_key);
    [Throws=CryptoError, Name=deserialize]
    constructor(bytes blob);
    bytes serialize();
    u32 batch_number();
    u32 remaining_keys();
    [Throws=CryptoError]
    SignedMessage sign_and_advance(bytes message);
    [Throws=CryptoError]
    BatchRotation prepare_rotation();
};

dictionary SignedMessage {
    bytes ephemeral_pk;
    u32 key_index;
    u32 batch_number;
    bytes signature;
};

dictionary BatchRotation {
    u32 signer_key_index;
    bytes signer_public_key;
    sequence<bytes> new_batch_public_keys;
    bytes new_batch_signature;
};

interface SovereignEncryptor {
    [Throws=CryptoError]
    constructor(StreamIdentity identity);
    [Throws=CryptoError]
    void encrypt_chunk_to_file(
        string plaintext_path,
        string output_path,
        string session_id,
        u32 seq_num
    );
};

interface ArchiveDecryptor {
    [Throws=CryptoError]
    constructor(string mnemonic, string passphrase);
    [Throws=CryptoError]
    void decrypt_blob_to_file(string blob_path, string output_path);
    void close();
};

[Error]
enum CryptoError {
    "InvalidMnemonic",
    "DerivationFailed",
    "InvalidBlob",
    "DecryptionFailed",
    "BatchExhausted",
    "AlreadyConsumed",
    "WrongPin",
    "InvalidSignature",
    "IoError",
};
```

UniFFI génère depuis ce fichier :
- `mobile/build/generated/.../FrappuccinoCrypto.kt` (Kotlin bindings)
- `frappuccino-cli/.../bindings.rs` (Rust scaffolding)
- (Futur iOS) `Frappuccino.swift`

---

## 5. Mapping Kotlin → Rust (module par module)

Pour chaque module Kotlin, on liste : équivalent Rust, particularités d'API, gains de sécurité, points de vigilance.

### 5.1 `Bip39.kt` → `frappuccino-bip39`

**API Kotlin actuelle** :
- `generateMnemonic(): String` (12 mots FR)
- `mnemonicToSeed(mnemonic, passphrase): ByteArray` (PBKDF2-HMAC-SHA512, 2048 iter)
- `normalizePhrase(s: String): String` (NFD + strip accents + wordlist lookup)
- `normalizeWord(w: String): String`

**Crate Rust** : `bip39 = { version = "2.0", features = ["french"] }`

**Mapping** :
```rust
use bip39::{Mnemonic, Language};

pub fn generate_mnemonic_fr() -> Result<Vec<String>, CryptoError> {
    let mnemonic = Mnemonic::generate_in(Language::French, 12)?;
    Ok(mnemonic.word_iter().map(String::from).collect())
}

pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64], CryptoError> {
    let m = Mnemonic::parse_in(Language::French, mnemonic)?;
    Ok(m.to_seed(passphrase))
}

pub fn normalize_mnemonic(raw: &str) -> Result<String, CryptoError> {
    use unicode_normalization::UnicodeNormalization;
    let normalized: String = raw.nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect::<String>()
        .to_lowercase();
    let words: Vec<&str> = normalized.split_whitespace().collect();
    let wordlist = Language::French.word_list();
    // Map stripped → canonical via lookup
    let canonical: Vec<String> = words.iter().map(|w| {
        wordlist.iter()
            .find(|cw| {
                let stripped: String = cw.nfd()
                    .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
                    .collect();
                stripped == *w
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| w.to_string())
    }).collect();
    Ok(canonical.join(" "))
}
```

**Gain sécurité** : 0 (BIP-39 est déterministe, pas de secret manipulé directement). Mais consolide la normalisation accents : **une seule** implémentation au lieu de 2 (Kotlin + Python).

**Vigilance** : la wordlist FR de la crate `bip39` doit matcher exactement celle de `stream-crypto/src/main/resources/bip39_fr.txt`. Test parité critique (voir §7).

### 5.2 `SecureMemory.kt` → `frappuccino-secure::SecretBytes` + `LockedSecret`

**API Kotlin actuelle** :
- `SecureMemory(size: Int) : AutoCloseable`
- `bytes(): ByteArray`
- `withBytes(action: (ByteArray) -> R): R`
- `close()` (fill 0)

**Mapping Rust** : deux niveaux selon criticité.

**Niveau 1 : `SecretBytes` (général)** — wrapper `secrecy::Secret` :
```rust
use secrecy::{Secret, ExposeSecret};
use zeroize::Zeroize;

pub struct SecretBytes {
    inner: Secret<Vec<u8>>,
}

impl SecretBytes {
    pub fn new(size: usize) -> Self {
        Self { inner: Secret::new(vec![0u8; size]) }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self { inner: Secret::new(data.to_vec()) }
    }

    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.inner.expose_secret())
    }

    pub fn with_bytes_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        // Secret::expose_secret_mut not available, manual workaround
        unsafe { f(self.inner.expose_secret() as *const Vec<u8> as *mut Vec<u8> as &mut Vec<u8>) }
    }
}
// Drop auto via Secret = zeroize sur le Vec
```

**Niveau 2 : `LockedSecret<N>` (clés crypto)** — alloc native + mlock :
```rust
use memsec::{mlock, munlock};

pub struct LockedSecret<const N: usize> {
    ptr: std::ptr::NonNull<u8>,
}

impl<const N: usize> LockedSecret<N> {
    pub fn new() -> std::io::Result<Self> {
        let layout = std::alloc::Layout::array::<u8>(N).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = std::ptr::NonNull::new(ptr).ok_or(std::io::Error::last_os_error())?;
        unsafe { mlock(ptr.as_ptr() as *mut _, N); }
        Ok(Self { ptr })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), N) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), N) }
    }
}

impl<const N: usize> Drop for LockedSecret<N> {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr.as_ptr(), 0, N);
            // compiler_fence(SeqCst) déjà dans zeroize
            munlock(self.ptr.as_ptr() as *mut _, N);
            let layout = std::alloc::Layout::array::<u8>(N).unwrap();
            std::alloc::dealloc(self.ptr.as_ptr(), layout);
        }
    }
}
```

**Gain sécurité** :
- ✅ Wipe **garanti** (zeroize compiler_fence + dealloc)
- ✅ Pages mlockées non swappables (vs Kotlin où GC peut déplacer)
- ✅ Déterministe (RAII, pas de GC)
- ✅ `Send` mais pas `Sync` par défaut → impossible de partager entre threads sans `Mutex`
- ✅ `Debug` impl → `***SECRET***` (pas le contenu) via `secrecy`

**Vigilance** : `LockedSecret` alloue page par page (4 KB min). Pour des secrets de 32 ou 64 bytes, c'est wasteful. Acceptable pour sécurité prioritaire ; sinon utiliser `SecretBytes` qui n'a pas mlock mais a zeroize.

### 5.3 `PinProtectedStore.kt` → `frappuccino-secure::pin_store`

**API Kotlin actuelle** :
- `seal(pin: CharArray, plaintext: ByteArray): ByteArray`
- `open(pin: CharArray, blob: ByteArray): ByteArray`
- `sealWithKey(key: ByteArray, salt: ByteArray, plaintext: ByteArray): ByteArray`

**Constantes** : Argon2id ops=4, memLimit=256 MB, salt=16, key=32, AAD=`"frappuccino-v2-pin-store-v1"`.

**Mapping Rust** :
```rust
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadInPlace, XNonce};
use rand_core::{OsRng, RngCore};

const VERSION: u8 = 0x01;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const HEADER_SIZE: usize = 1 + SALT_BYTES + NONCE_BYTES;
const MEM_KIB: u32 = 256 * 1024; // 256 MB
const ITERS: u32 = 4;
const AAD_BASE: &[u8] = b"frappuccino-v2-pin-store-v1";

pub struct PinProtectedStore;

impl PinProtectedStore {
    pub fn seal(pin: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut salt = [0u8; SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);

        let key = Self::derive_key(pin.as_bytes(), &salt)?;
        let cipher = XChaCha20Poly1305::new(key.as_slice().into());

        let mut buffer = plaintext.to_vec();
        let aad: Vec<u8> = AAD_BASE.iter().chain(&[VERSION]).copied().collect();
        cipher.encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut buffer)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        // key drop → zeroize (LockedSecret<32>)

        let mut blob = Vec::with_capacity(HEADER_SIZE + buffer.len());
        blob.push(VERSION);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend(buffer);
        Ok(blob)
    }

    fn derive_key(pin_bytes: &[u8], salt: &[u8; SALT_BYTES])
        -> Result<LockedSecret<KEY_BYTES>, CryptoError>
    {
        let params = Params::new(MEM_KIB, ITERS, 1, Some(KEY_BYTES))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = LockedSecret::<KEY_BYTES>::new()?;
        argon2.hash_password_into(pin_bytes, salt, key.as_mut_slice())?;
        Ok(key)
    }

    pub fn open(pin: &str, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Mirror seal logic, return WrongPin on AEAD failure
        ...
    }

    pub fn seal_with_key(key: &[u8; KEY_BYTES], salt: &[u8; SALT_BYTES], plaintext: &[u8])
        -> Result<Vec<u8>, CryptoError>
    {
        // Skip Argon2id, reuse cached key
        ...
    }
}
```

**Gain sécurité** :
- ✅ `LockedSecret<32>` pour la clé Argon2id-derived → pages pinned + zeroize garanti
- ✅ Type `&str` pour le PIN (immutable, slice plutôt que CharArray-passing)
- ✅ Cipher state zeroize automatique via `chacha20poly1305` crate

**Vigilance** : la conversion `&str` → `&[u8]` pour le PIN est une copie. Idéalement le PIN devrait être un `SecretBytes` dès l'entrée FFI. À adresser dans la couche UniFFI (passer `Vec<u8>` plutôt que `String`).

### 5.4 `EphemeralRatchet.kt` → `frappuccino-ratchet`

**API Kotlin actuelle** :
- Constants : `BATCH_SIZE = 50`, `CHAIN_KEY_BYTES = 32`, `MASK_BYTES = 7`, `SERIALIZED_HEADER_SIZE = 44`, `SERIALIZED_PER_SLOT_SIZE = 96`, `SERIALIZED_SIZE = 4844`
- HKDF info strings exacts : `CTX_BATCH_SEEDS = "frappuccino-v2-ratchet-batch-seeds"`, `CTX_NEXT_CHAIN = "frappuccino-v2-ratchet-next-chain"`
- `signAndAdvance(message): SignedMessage`
- `advanceBatch()`
- `serialize() / deserialize()`

**Mapping Rust** :
```rust
use ed25519_dalek::{SigningKey, Signature, Signer};
use hkdf::Hkdf;
use sha2::Sha256;

const BATCH_SIZE: usize = 50;
const CHAIN_KEY_BYTES: usize = 32;
const MASK_BYTES: usize = 7;
const SERIALIZED_HEADER_SIZE: usize = 1 + 4 + MASK_BYTES + CHAIN_KEY_BYTES; // 44
const SERIALIZED_PER_SLOT_SIZE: usize = 32 + 64; // pk + sk
const SERIALIZED_SIZE: usize = SERIALIZED_HEADER_SIZE + BATCH_SIZE * SERIALIZED_PER_SLOT_SIZE; // 4844
const VERSION: u8 = 1;

const CTX_BATCH_SEEDS: &[u8] = b"frappuccino-v2-ratchet-batch-seeds";
const CTX_NEXT_CHAIN: &[u8] = b"frappuccino-v2-ratchet-next-chain";

pub struct EphemeralRatchet {
    batch_number: u32,
    keypairs: [Option<SigningKey>; BATCH_SIZE],
    consumed: [bool; BATCH_SIZE],
    chain_key: LockedSecret<CHAIN_KEY_BYTES>,
}

#[derive(Debug)]
pub struct SignedMessage {
    pub ephemeral_pk: [u8; 32],
    pub key_index: u32,
    pub batch_number: u32,
    pub signature: [u8; 64],
}

impl EphemeralRatchet {
    pub fn from_chain(master_chain_key: &[u8; CHAIN_KEY_BYTES]) -> Result<Self, CryptoError> {
        let mut chain = LockedSecret::<CHAIN_KEY_BYTES>::new()?;
        chain.as_mut_slice().copy_from_slice(master_chain_key);
        let mut ratchet = Self {
            batch_number: 0,
            keypairs: std::array::from_fn(|_| None),
            consumed: [false; BATCH_SIZE],
            chain_key: chain,
        };
        ratchet.derive_batch_from_chain()?;
        Ok(ratchet)
    }

    fn derive_batch_from_chain(&mut self) -> Result<(), CryptoError> {
        // HKDF-SHA256(chain, info=CTX_BATCH_SEEDS, len=50*32)
        let mut seeds = [0u8; BATCH_SIZE * 32];
        let hk = Hkdf::<Sha256>::new(None, self.chain_key.as_slice());
        hk.expand(CTX_BATCH_SEEDS, &mut seeds)?;

        for i in 0..BATCH_SIZE {
            let seed: [u8; 32] = seeds[i*32..(i+1)*32].try_into().unwrap();
            self.keypairs[i] = Some(SigningKey::from_bytes(&seed));
        }
        seeds.zeroize();

        // Derive next chain
        let mut next_chain = [0u8; CHAIN_KEY_BYTES];
        hk.expand(CTX_NEXT_CHAIN, &mut next_chain)?;
        // Stocké pour rotation future, mais on garde aussi current chain pour resume
        // (À voir : strict forward security ou pas)

        Ok(())
    }

    pub fn sign_and_advance(&mut self, message: &[u8]) -> Result<SignedMessage, CryptoError> {
        let idx = self.consumed.iter().position(|&c| !c)
            .ok_or(CryptoError::BatchExhausted)?;

        let sk = self.keypairs[idx].take()
            .ok_or(CryptoError::AlreadyConsumed)?;
        let pk_bytes = sk.verifying_key().to_bytes();
        let sig = sk.sign(message);

        // sk drop → zeroize via SigningKey impl ZeroizeOnDrop
        self.consumed[idx] = true;

        Ok(SignedMessage {
            ephemeral_pk: pk_bytes,
            key_index: idx as u32,
            batch_number: self.batch_number,
            signature: sig.to_bytes(),
        })
    }

    pub fn advance_batch(&mut self) -> Result<(), CryptoError> {
        // Re-derive seeds avec next_chain
        // wipe ancien batch, install nouveau
        // batch_number += 1
        // consumed.fill(false)
        ...
    }

    pub fn serialize(&self) -> [u8; SERIALIZED_SIZE] {
        // Format binaire identique au Kotlin
        let mut blob = [0u8; SERIALIZED_SIZE];
        blob[0] = VERSION;
        blob[1..5].copy_from_slice(&self.batch_number.to_be_bytes());
        // consumed mask (bit i set if consumed[i])
        for i in 0..BATCH_SIZE {
            if self.consumed[i] {
                blob[5 + i / 8] |= 1 << (i % 8);
            }
        }
        blob[12..44].copy_from_slice(self.chain_key.as_slice());
        let mut offset = SERIALIZED_HEADER_SIZE;
        for i in 0..BATCH_SIZE {
            if let Some(sk) = &self.keypairs[i] {
                let pk = sk.verifying_key().to_bytes();
                blob[offset..offset+32].copy_from_slice(&pk);
                let sk_bytes = sk.to_keypair_bytes();
                blob[offset+32..offset+96].copy_from_slice(&sk_bytes);
            }
            // Si consumed : laisser à zéro (pk + sk)
            offset += SERIALIZED_PER_SLOT_SIZE;
        }
        blob
    }

    pub fn deserialize(blob: &[u8; SERIALIZED_SIZE]) -> Result<Self, CryptoError> {
        // Parse header, verify version, reconstruct keypairs depuis sk bytes
        ...
    }
}

impl Drop for EphemeralRatchet {
    fn drop(&mut self) {
        // chain_key wipe via LockedSecret Drop
        // keypairs wipe via SigningKey Drop
    }
}
```

**Gain sécurité** :
- ✅ `keypairs[i]: Option<SigningKey>` — `take()` consume the key (le slot devient `None`), impossible de re-signer avec le même slot par accident type-level
- ✅ `Drop` automatique zeroize chaque `SigningKey`
- ✅ `chain_key` mlocked via `LockedSecret<32>`
- ✅ `batch_number: u32` - overflow checked en debug builds

**Vigilance** :
- Le format binaire (4844 bytes) doit être **byte-pour-byte identique** au Kotlin actuel pour que la transition soit transparente. Test parité obligatoire (§7).
- HKDF info strings doivent matcher exactement (`CTX_BATCH_SEEDS`, `CTX_NEXT_CHAIN`).
- L'API Kotlin actuelle expose `peekNextBatchKeys()` pour rotation. À reproduire en Rust avec sémantique claire (read-only de chain dérivé, pas de mutation).

### 5.5 `SovereignEncryptor.kt` + `ArchiveDecryptor.kt` → `frappuccino-strm`

**API Kotlin actuelle** :
- `SovereignEncryptor.encryptChunk(plaintext: File, sessionId: String, seqNum: Int): File`
- `ArchiveDecryptor.decryptBlob(input: InputStream, output: OutputStream)`

**Format STRM v1** (rappel) :
- Magic `"STRM"` (4)
- Version `0x01` (1)
- Author Ed25519 pk (32)
- Sealed session key (80) = `crypto_box_seal(K_s, x25519_pk)`
- Grant count (2 BE)
- Grants (N × 112)
- Mode (1) : 0x01 single ou 0x02 chunked
- Payload selon mode

**Mapping Rust** :
```rust
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadInPlace, XNonce};
use x25519_dalek::{StaticSecret, PublicKey};
// crypto_box_seal équivalent : x25519 + chacha20poly1305 + nonce déterministe BLAKE2b

pub const MAGIC: [u8; 4] = *b"STRM";
pub const VERSION: u8 = 0x01;
pub const MODE_SINGLE: u8 = 0x01;
pub const MODE_CHUNKED: u8 = 0x02;
pub const SESSION_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const SEALED_BOX_OVERHEAD: usize = 48;
pub const SEALED_ENVELOPE_SIZE: usize = SESSION_KEY_BYTES + SEALED_BOX_OVERHEAD; // 80
pub const SINGLE_THRESHOLD: usize = 10 * 1024 * 1024;
pub const CHUNK_SIZE: usize = 1024 * 1024;

pub struct SovereignEncryptor {
    identity: StreamIdentity,
}

impl SovereignEncryptor {
    pub fn encrypt_chunk(
        &self,
        plaintext: &[u8],
        session_id: &str,
        seq_num: u32,
        out: &mut impl std::io::Write,
    ) -> Result<(), CryptoError> {
        // 1. K_s = random 32 bytes (mlocked)
        let mut session_key = LockedSecret::<32>::new()?;
        OsRng.fill_bytes(session_key.as_mut_slice());

        // 2. Header (writes simultaneously to out + AAD buffer)
        let mut aad = Vec::with_capacity(120);
        Self::write_both(out, &mut aad, &MAGIC)?;
        Self::write_both(out, &mut aad, &[VERSION])?;
        Self::write_both(out, &mut aad, &self.identity.ed25519_pk_bytes)?;

        // 3. Sealed envelope vers self
        let sealed = crypto_box_seal(session_key.as_slice(), &self.identity.x25519_pk_bytes)?;
        Self::write_both(out, &mut aad, &sealed)?;

        // 4. Grant count = 0
        Self::write_both(out, &mut aad, &0u16.to_be_bytes())?;

        // 5. Mode + payload
        if plaintext.len() <= SINGLE_THRESHOLD {
            Self::write_single(out, &aad, session_key.as_slice(), plaintext)?;
        } else {
            Self::write_chunked(out, &aad, session_key.as_slice(), plaintext)?;
        }
        // session_key drop → zeroize + munlock
        Ok(())
    }

    fn crypto_box_seal(plaintext: &[u8], recipient_pk: &[u8; 32]) -> Result<[u8; 80], CryptoError> {
        // 1. Generate ephemeral keypair X25519
        let eph_sk = StaticSecret::random_from_rng(OsRng);
        let eph_pk = PublicKey::from(&eph_sk);

        // 2. Compute deterministic nonce: BLAKE2b(eph_pk || recipient_pk)[:24]
        use blake2::{Blake2b, Digest};
        let mut hasher = Blake2b::<digest::consts::U24>::new();
        hasher.update(eph_pk.as_bytes());
        hasher.update(recipient_pk);
        let nonce: [u8; 24] = hasher.finalize().into();

        // 3. Shared secret + chacha20poly1305 encrypt
        let recipient = PublicKey::from(*recipient_pk);
        let shared = eph_sk.diffie_hellman(&recipient);

        let cipher = XChaCha20Poly1305::new(shared.as_bytes().into());
        let mut buffer = plaintext.to_vec();
        cipher.encrypt_in_place(XNonce::from_slice(&nonce), b"", &mut buffer)?;

        // 4. Output: eph_pk (32) || ciphertext+tag (32+16 = 48)
        let mut out = [0u8; 80];
        out[..32].copy_from_slice(eph_pk.as_bytes());
        out[32..].copy_from_slice(&buffer);
        Ok(out)
        // eph_sk + shared drop → zeroize
    }
}

pub struct ArchiveDecryptor {
    archive_identity: ArchiveIdentity,
}

impl ArchiveDecryptor {
    pub fn decrypt_blob(&self, blob: &[u8], out: &mut impl std::io::Write) -> Result<(), CryptoError> {
        // 1. Parse header
        let header = Header::parse(blob)?;

        // 2. Try self-decrypt first (sealed envelope to self)
        let session_key = self.try_self_decrypt(&header)
            .or_else(|_| self.try_grants(&header))?;

        // 3. AAD = full header
        let aad = &blob[..header.payload_offset];

        // 4. Mode-dependent decrypt
        match header.mode {
            MODE_SINGLE => self.decrypt_single(blob, header.payload_offset, &aad, session_key.as_slice(), out)?,
            MODE_CHUNKED => self.decrypt_chunked(blob, header.payload_offset, &aad, session_key.as_slice(), out)?,
            _ => return Err(CryptoError::InvalidBlob),
        }
        // session_key drop → zeroize
        Ok(())
    }
}
```

**Gain sécurité** :
- ✅ `K_s` mlocked, drop déterministe
- ✅ Pas de copie orpheline du plaintext (in-place encrypt si possible)
- ✅ Header parsing fortement typé (struct `Header` avec validation à la construction)
- ✅ Erreurs typées (`CryptoError::InvalidBlob` vs panic non-recouvrable)

**Vigilance** :
- L'AAD (header complet) doit être identique byte-pour-byte au Kotlin pour que les blobs Rust soient déchiffrables Kotlin et vice-versa.
- `crypto_box_seal` n'a pas d'équivalent direct en RustCrypto. À implémenter manuellement (voir code ci-dessus). Tests cross-platform critiques avec libsodium pour vérifier compatibilité.

### 5.6 `StreamIdentity.kt` + `EnrollmentKit.kt` + `ArchiveIdentity.kt` → `frappuccino-identity`

**Mapping** :
```rust
const HKDF_CTX_IDENTITY: &[u8] = b"stream.identity.ed25519.v1";
const HKDF_CTX_ENCRYPTION: &[u8] = b"stream.encryption.x25519.v1";
const HKDF_CTX_CHAIN0: &[u8] = b"stream.ratchet.chain0.v2";

pub struct StreamIdentity {
    pub(crate) ed25519_pk_bytes: [u8; 32],
    pub(crate) x25519_pk_bytes: [u8; 32],
    pub(crate) fingerprint: String,
}

impl StreamIdentity {
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, CryptoError> {
        let ed_seed = hkdf_sha256(seed, None, HKDF_CTX_IDENTITY, 32)?;
        let ed_signing = SigningKey::from_bytes(&ed_seed.try_into().unwrap());
        let ed25519_pk_bytes = ed_signing.verifying_key().to_bytes();
        // ed_signing drop → zeroize

        let x_seed = hkdf_sha256(seed, None, HKDF_CTX_ENCRYPTION, 32)?;
        let x_static = StaticSecret::from(<[u8; 32]>::try_from(x_seed.as_slice()).unwrap());
        let x25519_pk_bytes = PublicKey::from(&x_static).to_bytes();
        // x_static drop → zeroize

        let fingerprint = compute_fingerprint(&ed25519_pk_bytes);
        Ok(Self { ed25519_pk_bytes, x25519_pk_bytes, fingerprint })
    }
}

pub struct EnrollmentKit {
    pub identity: StreamIdentity,
    ed25519_sk: LockedSecret<64>,
    pub master_chain_key: LockedSecret<32>,
}

impl EnrollmentKit {
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, CryptoError> {
        let seed = mnemonic_to_seed(mnemonic, passphrase)?;
        let identity = StreamIdentity::from_seed(&seed)?;

        let mut ed25519_sk = LockedSecret::<64>::new()?;
        let ed_seed = hkdf_sha256(&seed, None, HKDF_CTX_IDENTITY, 32)?;
        let signing = SigningKey::from_bytes(&ed_seed.try_into().unwrap());
        ed25519_sk.as_mut_slice().copy_from_slice(&signing.to_keypair_bytes());

        let mut master_chain_key = LockedSecret::<32>::new()?;
        let chain = hkdf_sha256(&seed, None, HKDF_CTX_CHAIN0, 32)?;
        master_chain_key.as_mut_slice().copy_from_slice(&chain);
        // seed (Vec) drop → zeroize via SecretBytes

        Ok(Self { identity, ed25519_sk, master_chain_key })
    }

    pub fn sign_once(self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        // CONSUME self → can't be reused
        let signing = SigningKey::from_keypair_bytes(self.ed25519_sk.as_slice().try_into()?)?;
        Ok(signing.sign(message).to_bytes())
        // self drop → ed25519_sk + master_chain_key wipe
    }
}

pub struct ArchiveIdentity {
    pub identity: StreamIdentity,
    x25519_sk: LockedSecret<32>,
}

impl ArchiveIdentity {
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, CryptoError> {
        let seed = mnemonic_to_seed(mnemonic, passphrase)?;
        let identity = StreamIdentity::from_seed(&seed)?;
        let mut x25519_sk = LockedSecret::<32>::new()?;
        let x_seed = hkdf_sha256(&seed, None, HKDF_CTX_ENCRYPTION, 32)?;
        x25519_sk.as_mut_slice().copy_from_slice(&x_seed);
        Ok(Self { identity, x25519_sk })
    }

    pub fn decrypt_session_key(&self, sealed_envelope: &[u8; 80]) -> Result<[u8; 32], CryptoError> {
        // crypto_box_seal_open: extract eph_pk, recompute shared, decrypt
        ...
    }
}
// Drop → zeroize
```

**Gain sécurité majeur** :
- `EnrollmentKit::sign_once(self, ...)` consume `self` → impossible de réutiliser. **Le borrow checker garantit l'invariant que Kotlin maintenait par convention** (`signedOnce: Boolean`).
- `ArchiveIdentity::Drop` wipe `x25519_sk` automatiquement à la sortie de scope, pas besoin d'`onDestroy()` explicite côté UI.

### 5.7 `StreamUploadManager.kt` → `frappuccino-protocol::upload_manager`

**API Kotlin actuelle** : machine à états `UNENROLLED → LOCKED → UNLOCKED`, `enrollFromMnemonic`, `initializeWithPin`, `lock`, `panicWipe`, `authenticateV2`, `rotateBatchOnServer`.

**Mapping Rust** : enum d'état + transitions typées :

```rust
pub enum ManagerState {
    Unenrolled,
    Locked { identity: StreamIdentity, ratchet_blob: Vec<u8>, salt: [u8; 16] },
    Unlocked { identity: StreamIdentity, ratchet: EphemeralRatchet, derived_key: LockedSecret<32>, salt: [u8; 16] },
}

pub struct StreamUploadManager {
    state: ManagerState,
    server_url: String,
    jwt: Option<String>,
}

impl StreamUploadManager {
    pub fn enroll_from_mnemonic(&mut self, mnemonic: &str, pin: &str) -> Result<StreamIdentity, CryptoError> {
        // ...
    }

    pub fn initialize_with_pin(&mut self, pin: &str) -> Result<(), CryptoError> {
        // Transition Locked → Unlocked, run Argon2id, deserialize ratchet
    }

    pub fn lock(&mut self) {
        // Transition Unlocked → Locked, wipe ratchet + derived_key
    }

    pub fn panic_wipe(&mut self) {
        // Transition * → Unenrolled, wipe everything
    }

    pub fn authenticate_v2(&mut self) -> Result<String, CryptoError> {
        let ratchet = match &mut self.state {
            ManagerState::Unlocked { ratchet, .. } => ratchet,
            _ => return Err(CryptoError::NotUnlocked),
        };
        // Get challenge from server, sign_and_advance, post verify, get JWT
        ...
    }
}
```

**Gain sécurité** :
- ✅ Le compilateur empêche l'appel `authenticate_v2` quand l'état n'est pas `Unlocked`
- ✅ `lock()` transition force le `Drop` de `ratchet` + `derived_key` → wipe garanti
- ✅ `Send` mais pas `Sync` par défaut → contrainte explicite si shared between threads

### 5.8 `StreamServerClient.kt` → `frappuccino-protocol::server_client`

**Mapping Rust** : utiliser `reqwest::blocking` :

```rust
use reqwest::blocking::Client;
use serde::{Serialize, Deserialize};

pub struct ServerClient {
    client: Client,
    base_url: String,
}

#[derive(Serialize)]
struct V2EnrollRequest {
    ed25519_pk: String,
    batch_0_public_keys: Vec<String>,
    batch_0_signature: String,
}

#[derive(Deserialize)]
struct V2EnrollResponse {
    enrolled: bool,
    ed25519_pk: String,
    batch_number: u32,
}

impl ServerClient {
    pub fn enroll(&self, req: V2EnrollRequest) -> Result<V2EnrollResponse, CryptoError> {
        let resp = self.client
            .post(format!("{}/auth/v2/enroll", self.base_url))
            .json(&req)
            .send()?;
        Ok(resp.json()?)
    }

    pub fn challenge(&self) -> Result<String, CryptoError> { ... }
    pub fn verify(&self, ...) -> Result<String, CryptoError> { ... }  // returns JWT
    pub fn rotate_batch(&self, ...) -> Result<u32, CryptoError> { ... }
    pub fn status(&self, pk: &str) -> Result<V2IdentityStatus, CryptoError> { ... }
}
```

**Gain sécurité** :
- ✅ `rustls-tls` au lieu d'OpenSSL natif (memory safe)
- ✅ Désérialisation JSON via `serde` typée — impossible d'oublier un champ
- ✅ `reqwest` avec `default-features = false` minimise la surface

---

## 6. Phases du port

### 6.1 Phase P0 — Bootstrap et infrastructure (~1 semaine)

**Objectif** : avoir un squelette compilable qui produit une `.so` ARM64 + `.aar` Kotlin via UniFFI.

Tâches :
1. Créer `stream-crypto-rust/` avec `Cargo.toml`
2. Setup NDK toolchain dans CI (`cargo-ndk`)
3. Setup UniFFI : `frappuccino.udl` minimal (1 fonction `hello_world`), generation Kotlin
4. Wrapper Gradle qui appelle `cargo-ndk` et package les `.so` dans `mobile/src/main/jniLibs/`
5. Test : appel `Frappuccino.helloWorld()` depuis Kotlin retourne une `String`
6. CI : build ARM64-v8a, ARMv7, x86_64 (pour émulateur)

Livrables :
- `stream-crypto-rust/Cargo.toml`
- `stream-crypto-rust/build-android.sh`
- `mobile/build.gradle` updated
- Doc setup dans `BUILD.md`

### 6.2 Phase P1 — Primitives crypto (~2 semaines)

**Objectif** : porter les modules sans état (pures fonctions).

Ordre :
1. `bip39` (générer, normaliser, dériver seed)
2. `secure::SecretBytes` + `LockedSecret`
3. HKDF helper (utilise crate `hkdf`)
4. `identity::StreamIdentity::from_seed`
5. `identity::EnrollmentKit::from_mnemonic`
6. `identity::ArchiveIdentity::from_mnemonic`

Pour chaque module :
- Tests unitaires Rust (valeurs hardcodées)
- Test parité : valeur Rust == valeur Kotlin pour entrée identique
- Documentation inline `///`

### 6.3 Phase P2 — PinProtectedStore + EphemeralRatchet (~2 semaines)

**Objectif** : porter les deux briques avec état (les plus critiques).

Tâches :
1. `secure::pin_store::PinProtectedStore` (Argon2id + AEAD)
2. Test : seal Rust → open Kotlin (et vice-versa) sur un blob fixé
3. `ratchet::EphemeralRatchet` + tous ses helpers
4. Test parité format binaire 4844 bytes
5. Test : sign Kotlin batch_5 key_42 → verify Rust avec batch_keys publics

### 6.4 Phase P3 — Format STRM v1 (~2-3 semaines)

**Objectif** : port complet du format binaire avec tests cross-platform exhaustifs.

Tâches :
1. `strm::header` parser/serializer
2. `strm::encrypt::SovereignEncryptor` mode SINGLE
3. `strm::encrypt::SovereignEncryptor` mode CHUNKED
4. `strm::decrypt::ArchiveDecryptor` symétrique
5. `crypto_box_seal` + `crypto_box_seal_open` reproductions
6. Tests parité : 100% des vecteurs de `test_stream.py`
7. Fuzzing : `cargo fuzz` sur `parse_header` + `decrypt_blob`

Critère : un blob produit par Kotlin V2 actuel se déchiffre par Rust et vice-versa, byte-pour-byte identique.

### 6.5 Phase P4 — Protocole serveur V2 (~1-2 semaines)

**Objectif** : port du `StreamServerClient` + `StreamUploadManager`.

Tâches :
1. `protocol::server_client` (reqwest blocking, sérialisation serde)
2. `protocol::upload_manager` (états + transitions)
3. Tests E2E : authenticate Rust contre serveur Vultr réel
4. Test : ratchet rotation Rust → serveur accepte → batch_number incrémenté

### 6.6 Phase P5 — Exposition UniFFI complète (~1 semaine)

**Objectif** : finaliser `frappuccino.udl` avec toutes les API publiques, générer bindings Kotlin propres.

Tâches :
1. Compléter `frappuccino.udl`
2. Wrapper Kotlin dans `stream-crypto-rust-android/` qui re-export les bindings UniFFI sous noms cohérents
3. Tests instrumentés Android : appels via FFI fonctionnent sur Seeker
4. Benchmarks comparatifs Rust vs Kotlin actuel (Argon2id, ratchet sign, encrypt 1 MB)

### 6.7 Phase P6 — Migration `mobile/` (~2-3 semaines)

**Objectif** : remplacer dans `mobile/` tous les imports `org.stream.crypto.*` par les bindings UniFFI.

Tâches :
1. `MyApplication.initStreamUploadManager()` utilise nouveau client
2. `OnBoardSetPinFragment.enrollWithPin()` appelle Rust
3. `PinUnlockActivity.tryUnlock()` appelle Rust
4. `ArchiveModeActivity.tryUnlock()` appelle Rust
5. `StreamSettingsActivity` (fingerprint, batch info, lock, panic wipe)
6. `StreamRecordingService.onChunkReady()` chiffre via Rust
7. Suppression `stream-crypto/` Kotlin (module Gradle entier)
8. Tests instrumentés Android existants doivent passer (refactor minimal)

Critère : `./gradlew :mobile:assembleDebug` réussit, app démarre, onboarding + stream + déchiffrement fonctionnent end-to-end.

### 6.8 Phase P7 — CLI binaire `frappuccino-cli` (~1 semaine)

**Objectif** : remplacer `server-tools/{stream_decrypt,stream_archive,test_stream}.py` par un binaire Rust unique.

Subcommands :
```
frappuccino-cli decrypt --inspect blob.strm
frappuccino-cli decrypt --mnemonic "..." blob.strm -o out.bin
frappuccino-cli decrypt --reassemble session_dir/ --mnemonic "..." -o final.mp4
frappuccino-cli archive --server URL --session ID --mnemonic "..." -o out.mp4
frappuccino-cli demo --session latest --mnemonic "..."
frappuccino-cli test  # run all parity tests
```

Tâches :
1. `clap` pour parsing CLI
2. Réutilise `stream-crypto-rust` directement
3. Pour `--reassemble` : invoque `ffmpeg` via `std::process::Command`
4. CI : build binaire pour Linux x86_64, macOS aarch64, Windows x86_64

### 6.9 Phase P8 — Hardening et préparation audit (~2 semaines)

**Objectif** : finaliser pour audit RED/BLUE.

Tâches :
1. Audit transitif des dépendances : `cargo audit`, `cargo vet`, `cargo deny`
2. Bench performance : Rust ≥ 80% perf Kotlin actuel sur Argon2id, encrypt 1 MB
3. Coverage tests : `cargo tarpaulin` ≥ 90% sur `stream-crypto-rust/`
4. Fuzzing étendu : 100 M iterations sur `decrypt_blob`, `parse_header`, `ratchet_deserialize`
5. Build reproductible : 2 builds successifs → diff = 0 bytes
6. Documentation API : `cargo doc --document-private-items`
7. Threat model update : `THREAT_MODEL.md` mention que crypto core est Rust
8. Préparer `AUDIT_SCOPE_RUST.md`

---

## 7. Stratégie de tests et parité binaire

### 7.1 Trois niveaux de tests

**Niveau 1 — Tests unitaires Rust** (`stream-crypto-rust/src/**/tests`) :
- Tests internes par module
- Vecteurs hardcodés validés par calcul à la main ou contre référence externe
- Run via `cargo test`

**Niveau 2 — Tests d'intégration Rust** (`stream-crypto-rust/tests/`) :
- `parity.rs` : compare valeurs Rust avec vecteurs JSON exportés depuis Kotlin/Python
- `strm_format.rs` : encrypt → decrypt round-trip + cross-platform
- `protocol.rs` : tests E2E HTTP contre serveur de test

**Niveau 3 — Tests instrumentés Android** (`mobile/src/androidTest/`) :
- Reproduit la suite de tests `stream-crypto/androidTest/` actuelle (58 tests)
- Doit passer **identiquement** sur la nouvelle implémentation Rust via FFI
- Garantit qu'aucune régression user-visible n'est introduite

### 7.2 Vecteurs de test parité

Créer un fichier `test-vectors/` à la racine du repo, partagé entre Kotlin/Rust/Python :

```
test-vectors/
├── bip39_normalize.json        # input → output normalisé
├── identity_derivation.json    # mnemonic + passphrase → ed25519_pk + x25519_pk + fingerprint
├── ratchet_batch_0.json        # chain_0 → 50 keypairs publiques + chain_1
├── ratchet_serialized.json     # state → 4844 bytes blob (hex)
├── pin_store_seal.json         # pin + plaintext + salt + nonce → blob
├── strm_blobs/                 # binary fixtures
│   ├── single_small.strm       # 50 bytes plaintext, mode SINGLE
│   ├── single_large.strm       # 5 MB plaintext, mode SINGLE
│   ├── chunked_3mb.strm        # 3 MB plaintext, mode CHUNKED
│   ├── grant_3_recipients.strm # multi-grants
│   └── empty_plaintext.strm    # edge case
└── protocol/
    ├── enroll_request.json     # canonical request body
    └── verify_request.json
```

Chaque implémentation (Kotlin / Rust / Python) lit ces fixtures et vérifie identité. Les tests CI échouent à la moindre divergence.

### 7.3 Test cross-platform encrypt/decrypt

Test critique :
1. Kotlin V2 encrypt blob → fichier `kotlin_output.strm`
2. Rust decrypt `kotlin_output.strm` → vérifie plaintext identique
3. Rust encrypt même plaintext + même session → fichier `rust_output.strm`
4. Kotlin decrypt `rust_output.strm` → vérifie plaintext identique
5. (Bonus) Python decrypt les deux

Ce test garantit **wire compatibility** absolue.

### 7.4 Property-based testing

Avec [`proptest`](https://docs.rs/proptest/) :

```rust
#[proptest]
fn ratchet_serialize_deserialize_roundtrip(blob: [u8; 4844]) {
    if let Ok(ratchet) = EphemeralRatchet::deserialize(&blob) {
        let serialized = ratchet.serialize();
        prop_assert_eq!(blob, serialized);
    }
}

#[proptest]
fn strm_encrypt_decrypt_roundtrip(plaintext: Vec<u8>, mnemonic: ValidMnemonicStrategy) {
    let identity = StreamIdentity::from_mnemonic(&mnemonic, "")?;
    let archive = ArchiveIdentity::from_mnemonic(&mnemonic, "")?;
    let encryptor = SovereignEncryptor::new(identity);
    let mut blob = vec![];
    encryptor.encrypt_chunk(&plaintext, "test", 0, &mut blob)?;
    let decryptor = ArchiveDecryptor::new(archive);
    let mut output = vec![];
    decryptor.decrypt_blob(&blob, &mut output)?;
    prop_assert_eq!(plaintext, output);
}
```

### 7.5 Fuzzing

`cargo fuzz` harnesses :

```rust
// fuzz/fuzz_targets/decrypt_blob.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use stream_crypto_rust::strm::ArchiveDecryptor;

fuzz_target!(|data: &[u8]| {
    // Crash freedom: any input, no panic
    let archive = ArchiveIdentity::from_mnemonic("abandon ... about", "").unwrap();
    let decryptor = ArchiveDecryptor::new(archive);
    let mut output = vec![];
    let _ = decryptor.decrypt_blob(data, &mut output);
});
```

Cible : ≥ 100 M iterations en CI sans crash ni panic.

### 7.6 Differential fuzzing Kotlin vs Rust

Idée : fuzzer Jazzer (Kotlin) et libFuzzer (Rust) avec **les mêmes vecteurs**. Si l'un accepte un blob et l'autre le rejette → divergence d'implémentation = potentiel finding sécurité.

Implémentation : harness Jazzer qui dump les blobs traités vers un fichier, harness Rust qui les rejoue. Compare les comportements.

**Effort** : ~10 h setup, run en continu en CI.

---

## 8. Intégration Android (NDK + UniFFI)

### 8.1 Toolchain NDK

**Cible NDK** : version 25c LTS minimum (compatible avec AGP 7.2.2 et Rust 1.75+).

**Setup** :
```bash
# Install Rust targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Install cargo-ndk
cargo install cargo-ndk

# Build .so files
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o ../mobile/src/main/jniLibs build --release
```

**Architectures cibles** :
- `arm64-v8a` (priorité 1 — Solana Seeker, smartphones modernes)
- `armeabi-v7a` (compatibilité devices anciens)
- `x86_64` (émulateur)
- (Optionnel) `x86` pour anciens émulateurs

### 8.2 Gradle integration

`mobile/build.gradle` ajout :

```groovy
android {
    // ...
    ndkVersion "25.2.9519653"

    // Auto-build Rust avant compilation Kotlin
    sourceSets {
        main {
            jniLibs.srcDirs += '../stream-crypto-rust/target/jniLibs'
            // UniFFI generated bindings
            kotlin.srcDirs += '../stream-crypto-rust/build/generated/uniffi'
        }
    }

    splits {
        abi {
            enable true
            reset()
            include 'arm64-v8a', 'armeabi-v7a', 'x86_64'
            universalApk false
        }
    }
}

// Tâche Gradle qui invoque cargo-ndk
task buildRustLib(type: Exec) {
    workingDir '../stream-crypto-rust'
    commandLine 'cargo', 'ndk',
        '-t', 'arm64-v8a',
        '-t', 'armeabi-v7a',
        '-t', 'x86_64',
        '-o', './target/jniLibs',
        'build', '--release'
}

task generateUniFFIBindings(type: Exec, dependsOn: buildRustLib) {
    workingDir '../stream-crypto-rust'
    commandLine 'cargo', 'run', '--release', '--bin', 'uniffi-bindgen',
        '--', 'generate', 'src/frappuccino.udl', '--language', 'kotlin',
        '--out-dir', './build/generated/uniffi'
}

preBuild.dependsOn generateUniFFIBindings
```

### 8.3 Initialisation côté Kotlin

`MyApplication.onCreate()` charge la lib native :

```java
static {
    System.loadLibrary("frappuccino_crypto");  // libfrappuccino_crypto.so
}
```

UniFFI fait le reste : `org.frappuccino.crypto.FrappuccinoCrypto.kt` est généré et utilisable directement.

### 8.4 Lifecycle des objets cross-FFI

**Pattern recommandé UniFFI** :
- Objets stateful : `interface` UDL → handle Rust côté Kotlin
- Objets stateless : fonctions UDL → call direct
- Lifecycle : Kotlin garbage-collecte le handle, UniFFI déclenche `Drop` Rust côté natif

**Exemple `EnrollmentKit`** :
```kotlin
// Kotlin (généré par UniFFI)
val kit = EnrollmentKit.fromMnemonic(mnemonic, passphrase)
val identity = kit.identity()
val signature = kit.signOnce(message)  // consume le kit côté Rust
// Si on essaie kit.signOnce() à nouveau → CryptoException("AlreadyConsumed")
```

### 8.5 Threading

**Règle** : tous les appels FFI depuis Kotlin se font sur un thread background (jamais main thread). UniFFI n'impose pas, mais nos opérations Argon2id, encrypt, etc. bloquent.

**Implémentation** : wrapper Kotlin qui force `withContext(Dispatchers.IO)` :
```kotlin
suspend fun enrollAsync(mnemonic: String, pin: String): StreamIdentity =
    withContext(Dispatchers.IO) {
        manager.enrollFromMnemonic(mnemonic, pin)
    }
```

### 8.6 Taille de l'APK

**Estimation** :
- `libfrappuccino_crypto.so` ARM64 release strippé : ~800 KB - 1.5 MB
- Idem ARMv7 : ~700 KB
- Idem x86_64 : ~1 MB
- Total APK overhead : ~3-4 MB (vs ~0 actuel — lazysodium est déjà natif et pèse autant)

**Mitigation** : Android App Bundle (`.aab`) pour delivery par-architecture (chaque user télécharge seulement sa cible).

### 8.7 Symbols stripping et obfuscation

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true     # supprime symbols
panic = "abort"  # binaire plus petit, pas d'unwind
```

**Vérification** : `nm libfrappuccino_crypto.so` ne doit pas exposer les symboles internes.

---

## 9. CLI Python → binaire Rust unifié

### 9.1 Justification du remplacement

Aujourd'hui, `server-tools/` contient :
- `stream_decrypt.py` (388 lignes) : déchiffrement offline
- `stream_archive.py` (296 lignes) : client V2 ratchet
- `test_stream.py` (322 lignes) : 35 tests parité

**Problèmes** :
- Implémentation Python séparée → divergence possible avec Kotlin (déjà arrivé sur normalisation BIP-39)
- Maintenance double : tout fix doit être appliqué Python + Kotlin
- Distribution : nécessite Python 3.12 + pip install pynacl httpx

**Avec port Rust** :
- Une seule source de vérité (la crate `stream-crypto-rust`)
- Binaire portable (Linux x86_64, macOS aarch64, Windows x86_64)
- 0 dépendance runtime (musl-static linkable)
- Tests parité : la même crate qui tourne sur Android tourne en CLI

### 9.2 Architecture du CLI

`frappuccino-cli/Cargo.toml` :
```toml
[package]
name = "frappuccino-cli"

[dependencies]
stream-crypto-rust = { path = "../stream-crypto-rust" }
clap = { version = "4.5", features = ["derive"] }
anyhow = "1.0"
indicatif = "0.17"   # Progress bars
```

`src/main.rs` :
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "frappuccino-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Decrypt a STRM blob
    Decrypt {
        #[arg(long)]
        mnemonic: Option<String>,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        inspect: bool,
        #[arg(long)]
        as_recipient: bool,
        #[arg(long)]
        reassemble: bool,
        #[arg(short, long)]
        output: Option<String>,
        input: String,
    },

    /// V2 ratchet client: enroll, authenticate, download archive
    Archive {
        #[arg(long, default_value = "https://relay.frappuccino.app")]
        server: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        mnemonic: String,
        #[arg(short, long)]
        output: String,
    },

    /// Generate or display identity
    Identity {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Run all parity tests
    Test,

    /// Demo one-liner: download + decrypt + open video
    Demo {
        #[arg(long)]
        session: String,
        #[arg(long)]
        mnemonic: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Decrypt { .. } => decrypt::run(...),
        Cmd::Archive { .. } => archive::run(...),
        Cmd::Identity { .. } => identity::run(...),
        Cmd::Test => test::run_all(),
        Cmd::Demo { .. } => demo::run(...),
    }
}
```

### 9.3 Migration des tests

`server-tools/test_stream.py` (35 tests) → `frappuccino-cli/tests/parity.rs` :

```rust
#[test]
fn determinism_ed25519() {
    let identity1 = StreamIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let identity2 = StreamIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    assert_eq!(identity1.ed25519_pk_bytes, identity2.ed25519_pk_bytes);
}

#[test]
fn passphrase_changes_keys() {
    let i1 = StreamIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let i2 = StreamIdentity::from_mnemonic(TEST_MNEMONIC, "decoy").unwrap();
    assert_ne!(i1.ed25519_pk_bytes, i2.ed25519_pk_bytes);
}

// ... 33 autres tests
```

Tous run via `cargo test --release`.

### 9.4 Reproducibility

`frappuccino-cli` distribué avec :
- Binaire signé (PGP)
- SHA-256 publié
- Build instructions reproductibles via `Cargo.lock`

### 9.5 Période de transition

- Phase P7 : `frappuccino-cli` exists, tests parité OK
- Phase P8 (concurrente) : `server-tools/` Python encore présent, marqué deprecated
- Post-V3 : suppression `server-tools/*.py`

---

## 10. Préparation audit RED TEAM / BLUE TEAM

### 10.1 Documents à fournir

En plus des documents existants (post-Option A) :

| Document | Statut Option B | Action |
|---|---|---|
| `ARCHITECTURE_TECHNIQUE.md` | ✅ existe | Update : crypto layer = Rust |
| `CRYPTOGRAPHIE.md` | ✅ existe | Réécrire §3-§7 pour refléter Rust |
| `THREAT_MODEL.md` | ✅ post-Option A | Update : `LockedSecret` + `secrecy` mitigations |
| `SUPPLY_CHAIN.md` | ✅ post-Option A | Réécrire : cargo deps + cargo vet output |
| `AUDIT_SCOPE_RUST.md` | ❌ à créer | Voir §10.2 |
| `BUILD_REPRODUCIBLE.md` | ❌ à créer | Comment auditeur rebuild .so + APK |
| `RUST_PORT_RATIONALE.md` | ❌ à créer | Pourquoi Rust, ce qui change vs Kotlin |
| `crate doc rendered HTML` | À générer | `cargo doc --no-deps` archive HTML |

### 10.2 `AUDIT_SCOPE_RUST.md`

**IN SCOPE (priorité haute)** :
- `stream-crypto-rust/src/identity/` (BIP-39, Ed25519, X25519 derivation)
- `stream-crypto-rust/src/secure/` (`LockedSecret`, `PinProtectedStore`)
- `stream-crypto-rust/src/ratchet/` (forward security)
- `stream-crypto-rust/src/strm/` (parser/serializer format binaire)
- `stream-crypto-rust/src/protocol/` (V2 server client + upload manager)
- Le fichier `frappuccino.udl` (UniFFI surface)
- Cargo.lock (versions exactes des dépendances)

**IN SCOPE (priorité moyenne)** :
- `frappuccino-cli/src/` (CLI subcommands)
- Build scripts (`build-android.sh`, `Cargo.toml`)

**OUT OF SCOPE** :
- RustCrypto crates upstream (audités séparément, on liste les versions + audits)
- `mobile/` Kotlin (UI, CameraX, WorkManager) — partie auditée en Option A
- `server/` Python (couvert audit séparé)
- Code Tella legacy résiduel
- iOS port futur

### 10.3 RED TEAM brief

**Goals** (par ordre de criticité) :
1. **Goal critique** : extraire le contenu d'un blob STRM v1 sans la phrase BIP-39
2. **Goal critique** : forger une signature batch_N[i] sans posséder eph_N_i_sk
3. **Goal critique** : prédire la prochaine clé éphémère depuis les clés consommées
4. **Goal high** : provoquer un crash exploitable dans le parser STRM
5. **Goal high** : extraire un secret de la RAM d'un device non-rooted via app process
6. **Goal high** : extraire un secret après panic wipe (résidu)
7. **Goal medium** : downgrader le protocole V2 pour forcer un fallback non-existant
8. **Goal medium** : provoquer une collision batch_number côté serveur

**Setup fourni** :
- Repo Rust + Kotlin source complet, accès lecture
- APK debug signé
- Solana Seeker root + accès adb
- Clone du serveur Vultr en environnement isolé
- Vecteurs de test
- Threat model + architecture

**Méthodes interdites** :
- Pas d'attaque physique sur l'auditeur
- Pas de zero-day non-divulgué dans Rust toolchain ou RustCrypto crates (mais analyse statique de ces crates OK)
- Pas de BGP hijacking ni MITM réseau (TLS doit être assumé)

**Livrable attendu** : rapport détaillé avec PoC exécutables pour chaque finding.

### 10.4 BLUE TEAM brief

**Focus** : revue ligne par ligne de `stream-crypto-rust/`.

**Checklist suggérée** :
1. **Composition primitives** : chaque appel à RustCrypto utilise les bonnes options (par ex. `XChaCha20Poly1305::new` n'appelle pas un mode CTR sans MAC par accident)
2. **Lifecycle des secrets** :
   - Tout `LockedSecret` est-il drop avant la fin de scope ?
   - Tout `Secret<T>` est-il bien utilisé (pas d'`expose_secret().clone()` dans une `String` qui finit dans un log) ?
   - Tout `SigningKey` éphémère est-il `take()` exactement une fois ?
3. **Erreurs typées** :
   - Aucun `.unwrap()` dans le code de production sur des inputs externes
   - `Result<T, CryptoError>` partout où nécessaire
   - Pas de leak d'info via le type d'erreur (ex: `WrongPin` vs `InvalidBlob` distinct → potentiel oracle)
4. **Format binaire** :
   - Validation exhaustive : magic, version, longueurs
   - Bornes vérifiées partout (pas de `&buf[42..58]` sans `if buf.len() >= 58`)
   - AAD inclut bien tous les bytes du header
5. **FFI surface** :
   - Tous les types UDL ont une représentation safe (pas de raw pointer)
   - Erreurs Rust propagées proprement vers Kotlin exceptions
6. **Cargo.lock** :
   - Versions explicites, pas de `*`
   - `cargo audit` sans HIGH/CRITICAL
   - `cargo vet` reviews à jour

**Outils suggérés** :
- `cargo clippy --all -- -D warnings` (lints stricts)
- `cargo audit` (CVE check)
- `cargo deny check` (license + duplicate deps)
- `cargo geiger` (count `unsafe` blocks)
- [`miri`](https://github.com/rust-lang/miri) pour détecter UB dans les blocs `unsafe`
- Semgrep avec rules Rust crypto

**Livrable attendu** : rapport SARIF + writeup des findings + recommendations.

### 10.5 Spécificités Rust à auditer

Points qui n'existaient pas en Kotlin et qu'il faut auditer en plus :

1. **Tous les blocs `unsafe`** : enumérés, justifiés, documentés. Cible : ≤ 5 blocs `unsafe`, tous dans `secure::locked_secret`.
2. **FFI boundary** : audit que les `extern "C"` UniFFI ne leak pas de Rust panic dans la JVM (panic = abort, pas unwind).
3. **Lifetimes des references** : pas de `&'static` qui maintient un secret en vie au-delà du scope souhaité.
4. **`Send`/`Sync` derivations** : tout type contenant un secret ne doit pas être `Sync` sans wrapper.
5. **Const-time operations** : grep `==` sur types secrets, vérifier qu'on utilise `subtle::ConstantTimeEq`.

### 10.6 Comparaison Kotlin vs Rust pour l'audit

Le RED TEAM va probablement lancer le même set d'attaques que sur la version Kotlin (Option A). On documente explicitement quelles attaques sont **closes structurellement** par le port Rust :

| Attaque | Kotlin V2 | Rust V3 |
|---|---|---|
| Extract secret post-saisie via memory dump | Possible (GC orphans) | Très difficile (`LockedSecret` zeroize + munlock) |
| JIT élimine wipe → secret persiste | Mitigation H1.1 partielle | N/A (pas de JIT) |
| Confusion type pk/sk | Possible (ByteArray) | Impossible (value class typed) |
| Réutilisation clé éphémère consommée | Bug runtime possible | Compile-time error (`Option::take`) |
| Use-after-close de SecureMemory | Exception runtime | Compile-time error (move semantics) |
| Data race sur ratchet shared | Possible | Compile-time error (`Send`/`Sync`) |
| Buffer overrun parser | Possible (manual bounds check) | Panic safe par défaut, `unsafe` audited |

---

## 11. Calendrier et jalons

### 11.1 Estimation par phase

| Phase | Description | Effort solo dev |
|---|---|---|
| P0 | Bootstrap + UniFFI infrastructure | 1 semaine |
| P1 | Primitives crypto (BIP-39, identity, secure) | 2 semaines |
| P2 | PinProtectedStore + EphemeralRatchet | 2 semaines |
| P3 | Format STRM v1 complet + crypto_box_seal | 2-3 semaines |
| P4 | Protocole V2 serveur (client HTTP + upload manager) | 1-2 semaines |
| P5 | Exposition UniFFI complète + benches | 1 semaine |
| P6 | Migration `mobile/` (replace imports + tests instrumentés) | 2-3 semaines |
| P7 | CLI binaire `frappuccino-cli` | 1 semaine |
| P8 | Hardening + préparation audit | 2 semaines |

**Total** : 14-17 semaines (~3.5-4 mois temps plein, ~6-9 mois à temps partiel).

### 11.2 Pré-requis avant démarrage

- Option A (hardening Kotlin) terminée et auditée
- V2 Kotlin en production stable depuis ≥ 3 mois
- Format STRM v1 et protocole V2 figés (pas de breaking change pendant le port)
- Compétence Rust minimale du dev (équivalent Rust Book + 2-3 projets)

Si le dev (toi) n'a pas l'expérience Rust : ajouter 4 semaines pour montée en compétence. Cibler des ressources :
- *The Rust Programming Language* (the book, ~30 h)
- *Rust for Rustaceans* (Jon Gjengset, intermediate, ~20 h)
- Pratique : 2-3 mini-projets non-crypto pour les patterns

### 11.3 Jalons trimestriels (assumption : début septembre 2026 post-audit Option A)

| Jalon | Date cible | Livrable |
|---|---|---|
| **J0** | Sept 2026 | Décision GO Option B basée sur findings audit Option A |
| **J1** | Oct 2026 | P0-P2 complets : primitives + ratchet en Rust, parité 100% |
| **J2** | Déc 2026 | P3-P5 complets : format STRM + protocole + UniFFI exposé |
| **J3** | Fév 2027 | P6 complet : `mobile/` migré, app fonctionnelle bout-en-bout |
| **J4** | Mars 2027 | P7-P8 complets : CLI + hardening, prêt pour audit Rust |
| **J5** | Avr-Mai 2027 | Audit RED/BLUE TEAM Rust |
| **J6** | Juin 2027 | V3 release (AGPLv3 + F-Droid) |

### 11.4 Découplage et parallélisation

Les phases ne sont pas toutes séquentielles :
- P1, P2, P3 peuvent avancer en parallèle (modules indépendants)
- P4 (serveur) peut commencer dès P1 fini
- P7 (CLI) peut commencer dès P3 fini
- Documentation et threat model update peuvent se faire en continu

Avec 1 dev solo : séquentialité forcée. Avec 2 devs : possible compresser à 10-12 semaines.

---

## 12. Risques et mitigations

### 12.1 Risques techniques

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| Divergence wire format Kotlin/Rust détectée tard | Moyenne | Critique (incompatibilité) | Tests parité dès P1, fixtures partagées (`test-vectors/`) |
| Performance Rust < Kotlin sur ARMv7 | Faible | Moyen | Benches comparatifs P5, optim `target-cpu` si nécessaire |
| `LockedSecret` allocations 4 KB par secret 32 bytes = waste mémoire | Certaine | Faible | Acceptable (sécurité prioritaire), ou pool d'allocations |
| UniFFI bug ou limitation pour notre API | Faible | Moyen | Issue tracker UniFFI actif, fallback JNI manuel pour cas spécifiques |
| Crate RustCrypto majeure release breaking | Faible | Moyen | Pin version exacte dans Cargo.lock, audit avant update |
| `cargo-ndk` ou toolchain NDK breaking | Faible | Moyen | Pin version NDK dans `local.properties` + CI |

### 12.2 Risques projet

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| Dev ralenti par courbe d'apprentissage Rust | Moyenne | Élevé | Pré-requis 4 semaines formation, P0 court pour valider compétence |
| Scope creep (réécrire UI Android en Rust aussi) | Moyenne | Critique | Périmètre strictement défini §2 |
| Audit trouve majeurs bugs nécessitant refactor | Moyenne | Élevé | P8 hardening + fuzzing 100M iter avant audit |
| Migration `mobile/` introduit régression UX | Faible | Élevé | P6 graduel, tests instrumentés Android existants doivent passer |
| Disponibilité Cure53/Trail of Bits | Moyenne | Faible | Réserver 6 mois à l'avance, alternatives : NCC, Doyensec |

### 12.3 Risques sécurité

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| Bug zero-day dans `ed25519-dalek` ou `chacha20poly1305` | Faible | Critique | Suivi CVE, deploy patch urgent |
| Supply chain attack sur crates.io | Faible | Critique | `cargo vet` avant chaque update, mirror local des crates |
| Audit révèle problème de design (pas d'impl) | Moyenne | Critique | Threat model exhaustif AVANT port |
| Format STRM v1 lui-même a un défaut latent | Faible | Critique | Audit Option A doit l'avoir levé ; si non, c'est un finding partagé V2/V3 |

---

## 13. Critères d'acceptation

### 13.1 Critères techniques (GO release V3)

- ✅ `cargo test --release` 100% green sur les 3 architectures Android
- ✅ Tests instrumentés Android existants : 58/58 verts (parité avec V2 Kotlin)
- ✅ Tests parité `test-vectors/` : 100% match Kotlin ↔ Rust ↔ Python
- ✅ Fuzzing : ≥ 100 M iterations sans crash sur tous les harnesses
- ✅ `cargo audit` : 0 vulnerability HIGH ou CRITICAL
- ✅ `cargo clippy --all -- -D warnings` : pass
- ✅ `cargo geiger` : ≤ 5 `unsafe` blocs documentés
- ✅ Build APK release reproductible : 2 builds identiques byte-pour-byte
- ✅ Performance : ≥ 80% perf V2 Kotlin sur Argon2id, encrypt 1 MB, sign Ed25519
- ✅ APK release size : ≤ V2 + 5 MB (overhead .so)

### 13.2 Critères audit (GO publication AGPLv3 / F-Droid)

- ✅ 0 finding CRITICAL
- ✅ 0 finding HIGH non résolu (ou justification risk-accepted documentée)
- ✅ ≥ 80% findings MEDIUM résolus
- ✅ Documentation crypto complète et à jour
- ✅ Threat model validé par les auditeurs
- ✅ Build reproductible vérifié par les auditeurs

### 13.3 Critères UX (GO production)

- ✅ App démarre, onboarding complet en < 30 s sur Seeker
- ✅ Argon2id PIN derive en < 2 s (vs ~1.2 s V2 Kotlin — légère régression acceptable si gain sécurité)
- ✅ Encrypt 5 s chunk vidéo en < 50 ms (idem Kotlin)
- ✅ Pas de crash dans logcat sur scénario démo complet
- ✅ Mode Archive : déchiffre 1 session de 10 chunks en < 10 s

---

## 14. Conclusion

Le port Rust de `stream-crypto/` (Option B) est un projet **de 14-17 semaines** qui apporte des garanties que Kotlin ne peut pas fournir structurellement :

- **Memory hygiene déterministe** : `LockedSecret` + `secrecy` + `zeroize` = pas de GC orphans, pas de JIT dead-store, pages pinned.
- **Type-level invariants** : single-use éphémère, distinction pk/sk, état machine de l'upload manager — encodés dans le compilateur, pas en convention.
- **Réduction de la surface supply chain** : 0 dépendance à libsodium native, 0 JNI manuel, écosystème cargo unifié.
- **Build reproductible natif** : critère essentiel pour F-Droid et auditabilité utilisateur.
- **CLI Python éliminé** : une seule source de vérité pour la crypto, plus de divergence Kotlin/Python.

Le port **n'est pas** une réécriture de l'app Android. Il cible spécifiquement **la couche cryptographique** (~5-7 K lignes), exposée à `mobile/` via UniFFI. UI, services Android, intégrations système restent Kotlin — c'est là que Kotlin gagne.

**Conditions de succès** :
- Option A (hardening Kotlin) terminée et auditée
- Format STRM v1 et protocole V2 figés
- Compétence Rust minimale acquise
- 14-17 semaines dédiées (ou ~6-9 mois à temps partiel)

**À l'issue du port + audit RED/BLUE Rust**, Frappuccino V3 dispose d'une couche cryptographique de **niveau audit professionnel** comparable à Signal Protocol Rust impl, à Tor Arti, ou aux modules crypto de Mozilla Application Services. C'est le niveau requis pour une app distribuée à des militants en contexte hostile et soumise à des audits de niveau gouvernemental.

---

*Document rédigé le 16 avril 2026, basé sur le commit `f019431`.*
*Compagnon de `HARDENING_KOTLIN.md` (option A pré-audit), `ARCHITECTURE_TECHNIQUE.md`, `CRYPTOGRAPHIE.md`, `ROADMAP_DETAILLEE.md`.*
*Préalable au double audit RED TEAM / BLUE TEAM de la couche Rust V3.*
