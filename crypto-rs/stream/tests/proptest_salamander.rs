//! Property-based tests for the Salamander packet obfuscation (Phase 3b brick 1,
//! ROADMAP §10.10 T1).
//!
//! Salamander is OBFUSCATION, not confidentiality. The target here is therefore
//! **correctness** (a de-obfuscated datagram is byte-exact the original) and
//! **robustness** (`deobfuscate_in_place` never panics on a hostile datagram, the
//! untrusted-UDP surface the obfs proxy exposes to the internet). It is
//! deliberately NOT a secrecy property: the security of the upload path is the
//! pinned TLS + ratchet underneath, proven elsewhere (suite ①→⑤).
//!
//! Complements the in-module unit tests with randomized inputs + deterministic
//! shrinking. The no-panic of the parser is also proven *exhaustively* (bounded)
//! by Kani (§10.10 T2, `run-kani.sh`).

use frappuccino_crypto_stream::salamander::{deobfuscate_in_place, obfuscate_into, SALT_LEN};
use proptest::prelude::*;

proptest! {
    // Deterministic (fixed seed); failures persisted + shrunk to a minimal case.
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// P1 - round-trip: for any (psk, payload, salt),
    /// `deobfuscate(obfuscate(payload)) == payload`, the output is exactly
    /// `SALT_LEN` longer, and the salt is carried verbatim in the clear prefix.
    #[test]
    fn obfuscate_deobfuscate_roundtrips(
        psk in proptest::collection::vec(any::<u8>(), 0..64),
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
        salt in any::<[u8; SALT_LEN]>(),
    ) {
        let mut buf = Vec::new();
        obfuscate_into(&mut buf, &payload, &psk, salt);
        prop_assert_eq!(buf.len(), SALT_LEN + payload.len());
        prop_assert_eq!(&buf[..SALT_LEN], &salt[..]); // salt verbatim, in the clear
        let n = buf.len();
        let plain_len = deobfuscate_in_place(&mut buf, n, &psk)
            .expect("a freshly obfuscated datagram is always >= SALT_LEN");
        prop_assert_eq!(plain_len, payload.len());
        prop_assert_eq!(&buf[..plain_len], &payload[..]);
    }

    /// P2 - robustness: `deobfuscate_in_place` never panics on an arbitrary
    /// datagram (any content, any `n` within the caller's `n <= buf.len()`
    /// recv contract), including `n < SALT_LEN` -> `None`. This is the hostile
    /// untrusted-input path; a panic here would be a remote DoS of the proxy.
    #[test]
    fn deobfuscate_never_panics(
        buf in proptest::collection::vec(any::<u8>(), 0..2048),
        n_raw in any::<usize>(),
        psk in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut buf = buf;
        let n = n_raw % (buf.len() + 1); // 0..=buf.len(), the recv() contract
        let _ = deobfuscate_in_place(&mut buf, n, &psk); // Some or None, never a panic
    }

    /// P3a - determinism: obfuscation is a pure function of (payload, psk, salt).
    #[test]
    fn obfuscation_is_deterministic(
        psk in proptest::collection::vec(any::<u8>(), 0..64),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
        salt in any::<[u8; SALT_LEN]>(),
    ) {
        let mut a = Vec::new();
        let mut b = Vec::new();
        obfuscate_into(&mut a, &payload, &psk, salt);
        obfuscate_into(&mut b, &payload, &psk, salt);
        prop_assert_eq!(a, b);
    }

    /// P3b - distinct salts give distinct datagrams (the per-packet random salt
    /// is what makes each packet look independently random). Guaranteed by the
    /// verbatim salt prefix, so it holds even for a 0-byte payload.
    #[test]
    fn distinct_salts_give_distinct_datagrams(
        psk in proptest::collection::vec(any::<u8>(), 0..64),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
        salt_a in any::<[u8; SALT_LEN]>(),
        salt_b in any::<[u8; SALT_LEN]>(),
    ) {
        prop_assume!(salt_a != salt_b);
        let mut a = Vec::new();
        let mut b = Vec::new();
        obfuscate_into(&mut a, &payload, &psk, salt_a);
        obfuscate_into(&mut b, &payload, &psk, salt_b);
        prop_assert_ne!(a, b);
    }
}
