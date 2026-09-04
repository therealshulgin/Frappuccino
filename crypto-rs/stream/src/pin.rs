//! Pinned-cert TLS verifier — CRIT-01 defense-in-depth.
//!
//! `rustls`'s normal verifier walks a trust store; we intentionally bypass it
//! because the Vultr relay uses a self-signed cert that no real CA signed.
//! Instead, we:
//!
//! 1. Verify the live peer cert's `SubjectPublicKeyInfo` (SPKI) SHA-256 matches
//!    the hard-coded pin [`PIN_SHA256_B64`] — the sole enforcement gate.
//!    Cert rotation under a stable private key is supported by design.
//!
//! This replicates the Kotlin `CertificatePinner`+`network_security_config`
//! pair used in `StreamServerClient.kt`. Swap for proper CA validation when
//! the relay migrates to Let's Encrypt post-démo.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

/// SPKI SHA-256 pin (base64) of the relay cert.
///
/// Corresponds to the public key embedded in the test-server cert at
/// `136.244.101.236:8443`. Any attacker rotating the cert would need access
/// to the same EC private key to reproduce this hash.
///
/// Rotated 2026-05-14 after a Vultr "Reinstall OS" on the same IP — the
/// previous privkey was not backed up, so the new cert is fresh (still EC
/// P-256, 10-year validity, SAN: IP:136.244.101.236, valid 2026-05-14 →
/// 2036-05-11). The previous pin (`zgsMr0+...`) is dead with the old VM.
pub const PIN_SHA256_B64: &str = "QnGK0KvRC1vt2C4rrxwHIj0/pUbogVtTCesBK3sZXKY=";

/// Break-glass / future-LE SPKI pin (base64). Pre-seeded 2026-06-27 while the
/// fleet is healthy on [`PIN_SHA256_B64`], so a future cert rotation (key loss,
/// compromise, or the LE/domain cutover) is a graceful overlap instead of a
/// flag-day brick (audit 2026-06-26 D-2; runbook §6). This is the SPKI of an
/// EC P-256 key generated + backed up off-host; the same key will back the
/// Let's Encrypt cert via `certbot --reuse-key`, so this pin stays valid across
/// the domain migration with no further client change. A SECOND pin WE control,
/// not a CA fallback — it does not weaken MITM resistance.
pub const PIN_NEXT_B64: &str = "AmIDSglLpedq4J2LANgQ6s5+uKFEuuaNSGLjHOZkhok=";

/// Off-host break-glass SPKI pin (base64). Pre-seeded 2026-06-28 (audit
/// 2026-06-26 D-2; runbook §6). Unlike [`PIN_NEXT_B64`] (`AmIDSg`, the cert the
/// relay currently SERVES — so its key lives on the relay), this third key's
/// private half is generated + kept **off-host and NEVER placed on the relay**.
/// It is DORMANT: its cert is embedded (pin + NSC anchor) but not served, so it
/// is the recovery path for a **seized relay** — both currently-served keys
/// (`QnGK0K` backed up on the relay, `AmIDSg` live on the relay) are compromised
/// together by a seizure, which would otherwise force a flag-day APK push. At a
/// real seizure we stand up a NEW relay, deposit this key there, re-point the DNS
/// to it, and the fleet ALREADY pins + trusts this key, so the cutover needs no
/// APK push. The cert SAN is the **domain only** (no IP — the replacement relay's
/// IP is unknown; it is reached by the same name). A third pin WE control, not a
/// CA fallback — it does not weaken MITM resistance. Scope: recovers from a relay
/// seizure (same domain, new key), NOT a burned domain (that needs an APK push).
pub const PIN_NEXT2_B64: &str = "MUb4HHlUfj3c6cCQYuQMeeiWkcHga46OCZqVLuY9eCk=";

/// Host we expect inside the TLS SNI / URL (the SNI host-check). Must match the
/// pin above. Lot 3 C: migrated from the raw IP to the domain (DNS A-record ->
/// 136.244.101.236); the relay serves the break-glass cert ([`PIN_NEXT_B64`],
/// dual SAN domain+IP) so the field reaches it by name. The host-check is strict,
/// so the upload URL (the Kotlin `DEFAULT_SERVER_URL`) MUST use this same host.
pub const PINNED_HOST: &str = "relay.shake-document-protect.org";

#[cfg(test)]
const EMBEDDED_CERT_PEM: &str = include_str!("../assets/frappuccino_ca.crt");

#[cfg(test)]
const EMBEDDED_NEXT_CERT_PEM: &str = include_str!("../assets/frappuccino_ca_next.crt");

#[cfg(test)]
const EMBEDDED_NEXT2_CERT_PEM: &str = include_str!("../assets/frappuccino_ca_next2.crt");

/// `ServerCertVerifier` that enforces a hard-coded SPKI SHA-256 pin against
/// the peer cert's `SubjectPublicKeyInfo`. Cert rotation under a stable
/// private key is supported by design.
///
/// The `verify_tls1[23]_signature` callbacks delegate to the helpers in
/// [`rustls::crypto`], using the algorithm set from `ring::default_provider()`
/// stored at construction time. This is the RT-01 BLOCKER fix: prior to this,
/// the callbacks returned `Ok(HandshakeSignatureValid::assertion())` without
/// verifying anything, allowing an MITM holding only the public cert to forge
/// a `CertificateVerify` signature with any private key and pass the SPKI pin
/// check unscathed.
///
/// Construct via [`PinnedCertVerifier::new`].
#[derive(Debug)]
pub struct PinnedCertVerifier {
    /// Accepted SPKI SHA-256 pins. The peer must match ANY (constant-time OR):
    /// the live primary plus the pre-seeded break-glass / future-LE pin
    /// (audit 2026-06-26 D-2; runbook §6). A 2nd pin WE control, not a CA
    /// fallback — adding it does not weaken MITM resistance.
    pins: Vec<[u8; 32]>,
    expected_host: String,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    /// Build a verifier from the embedded PEM + base64 SPKI pin.
    ///
    /// # Errors
    /// Returns [`Error::General`] if the embedded PEM can't be parsed or the
    /// base64 pin has wrong length.
    pub fn new() -> Result<Self, Error> {
        Self::with_pins_and_host(&[PIN_SHA256_B64, PIN_NEXT_B64, PIN_NEXT2_B64], PINNED_HOST)
    }

    /// Build a verifier with a caller-chosen SPKI pin, for defense-in-depth
    /// negative tests (feed a wrong pin → observe the handshake fail).
    ///
    /// Production code should use [`Self::new`] which hard-codes the real pin.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn with_pin_b64(pin_b64: &str) -> Result<Self, Error> {
        Self::with_pins_and_host(&[pin_b64], PINNED_HOST)
    }

    /// Build a verifier for a caller-chosen SPKI pin **and** expected host.
    ///
    /// The QUIC transport (Phase 3a) pins a *second* endpoint (the HTTP/3
    /// front) which may live on a different host/SNI than the `DirectTls` relay,
    /// so the per-transport verifier needs both the pin and the host. Also used
    /// by the local h3 integration test (127.0.0.1 + the test cert's pin).
    ///
    /// # Errors
    /// See [`Self::with_pin_b64`].
    pub fn with_pin_and_host(pin_b64: &str, host: &str) -> Result<Self, Error> {
        Self::with_pins_and_host(&[pin_b64], host)
    }

    /// Build a verifier accepting a SET of SPKI pins for a chosen host — the
    /// peer cert is accepted if its SPKI matches ANY of them (constant-time).
    /// Production [`Self::new`] passes the live primary + the pre-seeded
    /// break-glass pin; the QUIC prod target passes the same set. Tests pass a
    /// single self-signed pin.
    ///
    /// # Errors
    /// Returns [`Error::General`] if `pins_b64` is empty or any entry is not a
    /// 32-byte base64 SHA-256.
    pub fn with_pins_and_host(pins_b64: &[&str], host: &str) -> Result<Self, Error> {
        if pins_b64.is_empty() {
            return Err(Error::General("at least one SPKI pin is required".into()));
        }
        let mut pins = Vec::with_capacity(pins_b64.len());
        for pin_b64 in pins_b64 {
            let pin_bytes = B64
                .decode(pin_b64)
                .map_err(|e| Error::General(format!("pin base64 decode: {e}")))?;
            let pin: [u8; 32] = pin_bytes
                .try_into()
                .map_err(|_| Error::General("pin SHA-256 must be 32 bytes".into()))?;
            pins.push(pin);
        }
        // Snapshot the ring-backed signature algorithm set once. Cloning a
        // `WebPkiSupportedAlgorithms` is cheap (it's just &'static slices).
        let algs = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        Ok(Self {
            pins,
            expected_host: host.to_string(),
            algs,
        })
    }

    /// Extract SPKI DER bytes from a full X.509 DER cert.
    fn extract_spki_der(cert_der: &[u8]) -> Result<&[u8], Error> {
        let (_, parsed) = X509Certificate::from_der(cert_der)
            .map_err(|e| Error::General(format!("x509 parse: {e}")))?;
        Ok(parsed.tbs_certificate.subject_pki.raw)
    }

    /// Constant-time: does this peer SPKI DER hash to ANY configured pin?
    /// ORs the `ct_eq` results over every pin WITHOUT early-exit, so timing
    /// reveals neither which pin matched nor whether a match occurred before the
    /// loop ends. (The pin-set size is a public build-time constant and both
    /// operands are public hashes, so this is hygiene, not load-bearing.)
    fn spki_matches_any(&self, spki_der: &[u8]) -> bool {
        let got = Sha256::digest(spki_der);
        let mut matched = subtle::Choice::from(0u8);
        for pin in &self.pins {
            matched |= got.as_slice().ct_eq(&pin[..]);
        }
        bool::from(matched)
    }
}

/// Compute the base64 SPKI SHA-256 pin of a DER cert — the exact value
/// [`PinnedCertVerifier`] checks the peer against (same extraction path).
///
/// Exposed for the QUIC integration test, which self-signs a throwaway cert and
/// must pin it; computing the pin through the *same* extraction guarantees the
/// test pin can never silently diverge from what the verifier enforces.
/// Returns `None` if the cert can't be parsed.
#[must_use]
pub fn spki_pin_b64(cert_der: &[u8]) -> Option<String> {
    let spki = PinnedCertVerifier::extract_spki_der(cert_der).ok()?;
    Some(B64.encode(Sha256::digest(spki)))
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Host check — belt alongside the pin. `ServerName` is an enum, so
        //    we stringify for a stable comparison.
        let sni = match server_name {
            ServerName::DnsName(d) => d.as_ref().to_string(),
            ServerName::IpAddress(ip) => ip_to_string(ip),
            _ => {
                return Err(Error::General(format!(
                    "unsupported ServerName variant: {server_name:?}"
                )))
            }
        };
        if sni != self.expected_host {
            return Err(Error::General(format!(
                "SNI {sni:?} != pinned host {:?}",
                self.expected_host
            )));
        }

        // 2. SPKI SHA-256 pin — the authoritative defense-in-depth check.
        //    Accept if the peer matches ANY configured pin (primary or
        //    break-glass), constant-time (see `spki_matches_any`).
        let spki = Self::extract_spki_der(end_entity.as_ref())?;
        if !self.spki_matches_any(spki) {
            return Err(Error::General(format!(
                "SPKI pin mismatch: peer SHA-256 {} matched none of {} configured pin(s)",
                hex::encode(Sha256::digest(spki)),
                self.pins.len(),
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // RT-01 fix — actually verify the `CertificateVerify` signature.
        // Delegating to the rustls helper means an MITM that re-presents the
        // pinned cert but signs with a different key gets rejected here, as
        // the threat model expects.
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // RT-01 fix — see `verify_tls12_signature` above.
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // ECDSA P-256 (what the relay uses) + the common RSA schemes for
        // future-proofing.
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Minimal PEM → DER decoder. Accepts a single `-----BEGIN CERTIFICATE-----`
/// block; anything more elaborate (multi-cert bundles, encrypted blocks) is
/// rejected on purpose.
#[cfg(test)]
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let mut body = String::with_capacity(pem.len());
    let mut in_block = false;
    for line in pem.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            in_block = true;
            continue;
        }
        if l == "-----END CERTIFICATE-----" {
            in_block = false;
            continue;
        }
        if in_block {
            body.push_str(l);
        }
    }
    if body.is_empty() {
        return Err("PEM did not contain a CERTIFICATE block".into());
    }
    B64.decode(body.as_bytes())
        .map_err(|e| format!("PEM body base64 decode: {e}"))
}

fn ip_to_string(ip: &rustls::pki_types::IpAddr) -> String {
    match ip {
        rustls::pki_types::IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.as_ref();
            format!("{a}.{b}.{c}.{d}")
        }
        rustls::pki_types::IpAddr::V6(v6) => {
            let bytes: &[u8; 16] = v6.as_ref();
            // Lossy but enough to compare against an IPv6-literal string — the
            // project only ever pins an IPv4, so this branch is effectively dead.
            let groups: [u16; 8] = [
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
            ];
            groups
                .iter()
                .map(|g| format!("{g:x}"))
                .collect::<Vec<_>>()
                .join(":")
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_cert_decodes() {
        let der = pem_to_der(EMBEDDED_CERT_PEM).expect("pem decode");
        assert!(
            der.len() > 100,
            "DER cert suspiciously short: {}",
            der.len()
        );
        // First two bytes of a DER cert are 0x30 0x82 (SEQUENCE, long form length).
        assert_eq!(der[0], 0x30, "DER must start with SEQUENCE tag");
    }

    #[test]
    fn embedded_cert_spki_matches_pin() {
        // This is the whole point of the module — if this ever fails, the
        // cert and the pin have diverged and the relay will be unreachable.
        let der = pem_to_der(EMBEDDED_CERT_PEM).unwrap();
        let spki = PinnedCertVerifier::extract_spki_der(&der).unwrap();
        let got = Sha256::digest(spki);
        let pin = B64.decode(PIN_SHA256_B64).unwrap();
        assert_eq!(
            got.as_slice(),
            pin.as_slice(),
            "embedded cert's SPKI SHA-256 does not match PIN_SHA256_B64"
        );
    }

    #[test]
    fn verifier_new_succeeds() {
        let v = PinnedCertVerifier::new().expect("verifier build");
        assert_eq!(v.expected_host, PINNED_HOST);
        // Primary + the two pre-seeded break-glass pins (live next + off-host next2).
        assert_eq!(v.pins.len(), 3);
        assert!(v.pins.iter().all(|p| p.len() == 32));
    }

    #[test]
    fn next_cert_spki_matches_pin_next() {
        // The embedded break-glass cert's SPKI must equal PIN_NEXT_B64 — if this
        // fails, the pre-seeded pin and the break-glass key have diverged and a
        // rotation to that key would brick the field.
        let der = pem_to_der(EMBEDDED_NEXT_CERT_PEM).unwrap();
        let spki = PinnedCertVerifier::extract_spki_der(&der).unwrap();
        let got = Sha256::digest(spki);
        let pin = B64.decode(PIN_NEXT_B64).unwrap();
        assert_eq!(
            got.as_slice(),
            pin.as_slice(),
            "embedded next cert's SPKI SHA-256 does not match PIN_NEXT_B64"
        );
    }

    #[test]
    fn next2_cert_spki_matches_pin_next2() {
        // The embedded off-host break-glass cert's SPKI must equal PIN_NEXT2_B64 —
        // if this fails, the pre-seeded 3rd pin and the off-host key have diverged
        // and a seizure-recovery cutover to that key would brick the field.
        let der = pem_to_der(EMBEDDED_NEXT2_CERT_PEM).unwrap();
        let spki = PinnedCertVerifier::extract_spki_der(&der).unwrap();
        let got = Sha256::digest(spki);
        let pin = B64.decode(PIN_NEXT2_B64).unwrap();
        assert_eq!(
            got.as_slice(),
            pin.as_slice(),
            "embedded next2 cert's SPKI SHA-256 does not match PIN_NEXT2_B64"
        );
    }

    #[test]
    fn union_accepts_any_configured_pin() {
        let primary_der = pem_to_der(EMBEDDED_CERT_PEM).unwrap();
        let primary_spki = PinnedCertVerifier::extract_spki_der(&primary_der).unwrap();
        let next_der = pem_to_der(EMBEDDED_NEXT_CERT_PEM).unwrap();
        let next_spki = PinnedCertVerifier::extract_spki_der(&next_der).unwrap();
        let third_der = pem_to_der(EMBEDDED_NEXT2_CERT_PEM).unwrap();
        let third_spki = PinnedCertVerifier::extract_spki_der(&third_der).unwrap();

        // A verifier carrying ALL pins accepts any of the three certs' SPKI.
        let all = PinnedCertVerifier::new().unwrap();
        assert!(all.spki_matches_any(primary_spki));
        assert!(all.spki_matches_any(next_spki));
        assert!(all.spki_matches_any(third_spki));

        // A single-primary verifier rejects both break-glass certs — the union is
        // what makes the secondaries acceptable, nothing else.
        let only_primary = PinnedCertVerifier::with_pin_b64(PIN_SHA256_B64).unwrap();
        assert!(only_primary.spki_matches_any(primary_spki));
        assert!(!only_primary.spki_matches_any(next_spki));
        assert!(!only_primary.spki_matches_any(third_spki));

        // No configured pin matches unrelated bytes.
        assert!(!all.spki_matches_any(b"not a valid spki"));

        // Empty pin set is rejected at construction (defense against a misbuild).
        assert!(PinnedCertVerifier::with_pins_and_host(&[], PINNED_HOST).is_err());
    }

    #[test]
    fn pem_rejects_empty_input() {
        let err = pem_to_der("").unwrap_err();
        assert!(err.contains("CERTIFICATE block"));
    }

    #[test]
    fn pem_rejects_garbage() {
        let err =
            pem_to_der("-----BEGIN CERTIFICATE-----\nnot-base64!!\n-----END CERTIFICATE-----")
                .unwrap_err();
        assert!(err.contains("base64"));
    }

    #[test]
    fn rt01_verifier_initializes_with_signature_algorithms() {
        // Sanity check that the post-RT-01 verifier carries the
        // ring-backed signature algorithm set. If `new()` ever stops
        // populating `algs` (e.g. someone reverts to the old struct shape),
        // this fails before the binary ships.
        let v = PinnedCertVerifier::new().expect("verifier");
        assert!(
            !v.algs.mapping.is_empty(),
            "RT-01 regression: WebPkiSupportedAlgorithms.mapping must be \
             non-empty — the verifier would silently accept any signature \
             without it"
        );
    }

    // RT-01 end-to-end regression (Phase 4.1.5). A `DigitallySignedStruct`
    // can't be built outside rustls (crate-private ctor), so we drive a real
    // in-memory TLS 1.3 handshake instead: a server that presents the *real
    // pinned cert* but signs the `CertificateVerify` with a *different* P-256
    // key (the MITM that only ever had the public cert). Because the cert,
    // the SPKI pin and the host all match the real ones, the SPKI + host
    // checks PASS — so the only thing that can fail is the signature, which
    // is exactly the RT-01 path. Pre-fix (callbacks returned `Ok(assertion)`)
    // this handshake completed; post-fix it must abort with `BadSignature`.
    #[test]
    fn rt01_mitm_forged_certificate_verify_is_rejected() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use rustls::server::{ClientHello, ResolvesServerCert};
        use rustls::sign::CertifiedKey;
        use rustls::{
            CertificateError, ClientConfig, ClientConnection, ServerConfig, ServerConnection,
        };
        use std::sync::Arc;

        // Hands out a CertifiedKey WITHOUT the cert/key consistency check that
        // `ServerConfig::with_single_cert` performs — i.e. the MITM combo of a
        // real cert + an attacker key.
        #[derive(Debug)]
        struct MitmResolver(Arc<CertifiedKey>);
        impl ResolvesServerCert for MitmResolver {
            fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                Some(Arc::clone(&self.0))
            }
        }

        let provider = rustls::crypto::ring::default_provider();

        // Real pinned cert + a freshly generated (wrong) P-256 key.
        let pinned_cert = CertificateDer::from(pem_to_der(EMBEDDED_CERT_PEM).unwrap());
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate wrong key");
        let wrong_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()));
        let signing_key = provider
            .key_provider
            .load_private_key(wrong_key)
            .expect("load wrong key");
        let forged = CertifiedKey::new(vec![pinned_cert], signing_key);

        let provider = Arc::new(provider);

        let server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(MitmResolver(Arc::new(forged))));

        let client_config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new().unwrap()))
            .with_no_client_auth();

        // Connect to the *pinned host* so SNI/host + SPKI both pass.
        let server_name = ServerName::try_from(PINNED_HOST).unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let mut client_err: Option<Error> = None;
        for _ in 0..30 {
            let mut to_server = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut to_server).unwrap();
            }
            if !to_server.is_empty() {
                let mut rd: &[u8] = &to_server;
                while !rd.is_empty() {
                    server.read_tls(&mut rd).unwrap();
                }
                server
                    .process_new_packets()
                    .expect("server side should not error");
            }

            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).unwrap();
            }
            if !to_client.is_empty() {
                let mut rd: &[u8] = &to_client;
                while !rd.is_empty() {
                    client.read_tls(&mut rd).unwrap();
                }
                if let Err(e) = client.process_new_packets() {
                    client_err = Some(e);
                    break;
                }
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }

        let err = client_err.expect(
            "RT-01 regression: client ACCEPTED a CertificateVerify signed with a key \
             that does not match the pinned cert — MITM would succeed",
        );
        assert!(
            matches!(
                err,
                Error::InvalidCertificate(CertificateError::BadSignature)
            ),
            "expected BadSignature on the forged CertificateVerify, got: {err:?}"
        );
    }
}
