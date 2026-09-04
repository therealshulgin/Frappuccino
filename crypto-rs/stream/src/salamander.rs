//! Salamander packet obfuscation for the QUIC transport — Phase 3b brick 1
//! (transport plan `docs/TRANSPORT_PLAN.md` Phase 3, ROADMAP §10.9).
//!
//! A stateless, per-packet XOR scrambler keyed by a pre-shared key (PSK),
//! byte-identical to `Hysteria2`'s "salamander" obfuscation so a Go / `sing-box`
//! terminator and this Rust client interoperate exactly. Each obfuscated
//! datagram is `[8-byte random salt][payload XOR keystream]`, where the
//! keystream is `BLAKE2b-256(PSK || salt)` repeated over the payload
//! (`payload[i] ^= keystream[i % 32]`).
//!
//! This is OBFUSCATION, not authentication or confidentiality: the security of
//! the upload path is the ratchet auth + the pinned TLS underneath. Salamander
//! exists only to (a) defeat passive QUIC fingerprinting — every packet looks
//! like uniform random bytes — and (b) make the server appear as a dead UDP
//! port to any prober without the PSK: an un-keyed packet de-obfuscates to
//! garbage, yields no valid QUIC header, and is dropped silently. The PSK is
//! therefore a shared, app-embedded obfs secret (like `Hysteria2`'s obfs
//! password), NOT a per-user key.
//!
//! It wraps the QUIC *datagram* layer (via the `AsyncUdpSocket` shim in
//! `quic.rs`), so everything above is unchanged: h3 / ratchet / BBR never see it.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// Length of the random salt prepended to every obfuscated datagram. The QUIC
/// transport caps MTU discovery `SALT_LEN` below the path ceiling (see
/// `quic::client_config`) so a salted packet never exceeds the path MTU and gets
/// DF-dropped.
pub const SALT_LEN: usize = 8;

/// `BLAKE2b-256` keystream length (one digest).
const KEYSTREAM_LEN: usize = 32;

type Blake2b256 = Blake2b<U32>;

/// Derive the 32-byte keystream for one packet: `BLAKE2b-256(psk || salt)`.
/// Plain (un-keyed) `BLAKE2b` over the concatenation — matches `Hysteria2`'s
/// `blake2b.Sum256(key ++ salt)` byte-for-byte.
fn keystream(psk: &[u8], salt: [u8; SALT_LEN]) -> [u8; KEYSTREAM_LEN] {
    let mut h = Blake2b256::new();
    h.update(psk);
    h.update(salt);
    let digest = h.finalize();
    let mut ks = [0u8; KEYSTREAM_LEN];
    ks.copy_from_slice(&digest);
    ks
}

/// XOR `data` in place with the salt-derived keystream (`data[i] ^= ks[i % 32]`).
fn xor_in_place(data: &mut [u8], ks: &[u8; KEYSTREAM_LEN]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= ks[i % KEYSTREAM_LEN];
    }
}

/// Obfuscate one QUIC datagram into `out`: writes `[salt][payload XOR keystream]`.
/// `salt` is caller-supplied (the socket draws fresh random bytes per packet) so
/// this stays deterministic and unit-testable. `out` is cleared first.
pub fn obfuscate_into(out: &mut Vec<u8>, packet: &[u8], psk: &[u8], salt: [u8; SALT_LEN]) {
    let ks = keystream(psk, salt);
    out.clear();
    out.reserve(SALT_LEN + packet.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(packet);
    xor_in_place(&mut out[SALT_LEN..], &ks);
}

/// De-obfuscate a received datagram in place. `buf[..n]` holds
/// `[salt][ciphertext]`; on success the recovered QUIC packet is moved to the
/// front of `buf` and its length returned. Returns `None` if the datagram is too
/// short to carry a salt — the caller drops it (the spec's "any invalid packet
/// MUST be discarded", which is also the dead-port property). Caller's contract:
/// `n <= buf.len()`.
#[must_use]
pub fn deobfuscate_in_place(buf: &mut [u8], n: usize, psk: &[u8]) -> Option<usize> {
    if n < SALT_LEN {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buf[..SALT_LEN]);
    let ks = keystream(psk, salt);
    xor_in_place(&mut buf[SALT_LEN..n], &ks);
    buf.copy_within(SALT_LEN..n, 0);
    Some(n - SALT_LEN)
}

#[cfg(test)]
mod tests {
    use super::{deobfuscate_in_place, obfuscate_into, SALT_LEN};

    #[test]
    fn roundtrip_recovers_original() {
        let psk = b"frappuccino-obfs-psk";
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let packet = b"\xc0\x00\x00\x00\x01 a QUIC-ish long-header packet payload";
        let mut obf = Vec::new();
        obfuscate_into(&mut obf, packet, psk, salt);
        // Salt preserved verbatim; payload scrambled; 8 bytes larger.
        assert_eq!(&obf[..SALT_LEN], &salt);
        assert_ne!(&obf[SALT_LEN..], &packet[..]);
        assert_eq!(obf.len(), SALT_LEN + packet.len());
        // De-obfuscation recovers the original bytes exactly.
        let mut buf = obf.clone();
        let n = buf.len();
        let plain_len = deobfuscate_in_place(&mut buf, n, psk).expect("deobf");
        assert_eq!(&buf[..plain_len], &packet[..]);
    }

    #[test]
    fn wrong_psk_yields_garbage_not_plaintext() {
        let salt = [9u8; SALT_LEN];
        let packet = b"the original QUIC packet bytes go here";
        let mut obf = Vec::new();
        obfuscate_into(&mut obf, packet, b"correct-psk", salt);
        let mut buf = obf.clone();
        let n = buf.len();
        // Wrong PSK -> wrong keystream -> not the plaintext. The caller's QUIC
        // parser then rejects this garbage and drops it (dead-port property).
        let plain_len = deobfuscate_in_place(&mut buf, n, b"WRONG-psk").expect("runs");
        assert_ne!(&buf[..plain_len], &packet[..]);
    }

    #[test]
    fn too_short_for_salt_is_rejected() {
        let mut buf = [0u8; SALT_LEN - 1];
        assert_eq!(deobfuscate_in_place(&mut buf, SALT_LEN - 1, b"psk"), None);
    }

    #[test]
    fn distinct_salts_give_distinct_ciphertext() {
        // The per-packet random salt is what makes each packet look
        // independently random; the same packet under two salts must not collide.
        let psk = b"psk";
        let packet = b"same packet under two salts";
        let mut a = Vec::new();
        let mut b = Vec::new();
        obfuscate_into(&mut a, packet, psk, [0u8; SALT_LEN]);
        obfuscate_into(&mut b, packet, psk, [1u8; SALT_LEN]);
        assert_ne!(a[SALT_LEN..], b[SALT_LEN..]);
    }

    #[test]
    fn empty_payload_roundtrips() {
        // A 0-byte QUIC datagram (degenerate) must still salt + survive.
        let psk = b"psk";
        let salt = [7u8; SALT_LEN];
        let mut obf = Vec::new();
        obfuscate_into(&mut obf, b"", psk, salt);
        assert_eq!(obf.len(), SALT_LEN);
        let mut buf = obf.clone();
        let n = buf.len();
        assert_eq!(deobfuscate_in_place(&mut buf, n, psk), Some(0));
    }
}
