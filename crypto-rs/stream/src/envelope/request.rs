//! The relay request an envelope stands for.
//!
//! Every part of it comes from the verified trailer: the URL (`PUT
//! /file/{rid}/{name}` for an object, `POST /close/{rid}` for a closure), the
//! capability headers, and the body, which is the payload range of the file
//! with its verified hash, so the transport re-checks the bytes as it sends
//! them. Nothing is signed here.

use super::{EnvelopeError, EnvelopeKind, VerifiedEnvelope};
use crate::file_range::FileRange;
use crate::transport::{self, Method, OutgoingRequest, SendOutcome, Transport};
use std::fmt;
use zeroize::Zeroizing;

/// A request built from a [`VerifiedEnvelope`], ready to send.
pub struct EnvelopeRequest {
    method: Method,
    url: String,
    headers: Vec<(&'static str, Zeroizing<String>)>,
    body: FileRange,
}

impl fmt::Debug for EnvelopeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The URL carries the report's address and a header may carry the
        // bearer: neither belongs in a log.
        f.debug_struct("EnvelopeRequest")
            .field("method", &self.method)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedEnvelope {
    /// The relay request for this envelope against `base_url` (scheme, host
    /// and port, as in `https://relay.example:8443`).
    ///
    /// `creation_bearer` asks for creation mode: the request then also
    /// carries the envelope's `X-Report-Create-Sig` and this value as
    /// `Authorization`. Without it the request carries only the per-object
    /// capability.
    ///
    /// # Errors
    /// [`EnvelopeError::CreationNotApplicable`] for creation mode on a
    /// closure, [`EnvelopeError::NoCreateSig`] for creation mode on an
    /// envelope that carries no creation signature.
    pub fn request(
        &self,
        base_url: &str,
        creation_bearer: Option<&str>,
    ) -> Result<EnvelopeRequest, EnvelopeError> {
        let trailer = self.trailer();
        let base = base_url.trim_end_matches('/');
        let rid = trailer.report_id_hex();
        let mut headers: Vec<(&'static str, Zeroizing<String>)> = vec![(
            "X-Report-PK",
            Zeroizing::new(hex::encode(trailer.report_pk())),
        )];
        let (method, url) = if trailer.kind() == EnvelopeKind::Closure {
            if creation_bearer.is_some() {
                return Err(EnvelopeError::CreationNotApplicable);
            }
            headers.push((
                "X-Report-Close-Sig",
                Zeroizing::new(hex::encode(trailer.signature())),
            ));
            headers.push((
                "X-Report-Close-Seq-Limit",
                Zeroizing::new(trailer.seq_limit().to_string()),
            ));
            (Method::Post, format!("{base}/close/{rid}"))
        } else {
            headers.push((
                "X-Report-Write-Sig",
                Zeroizing::new(hex::encode(trailer.signature())),
            ));
            if let Some(bearer) = creation_bearer {
                let create_sig = trailer.create_sig().ok_or(EnvelopeError::NoCreateSig)?;
                headers.push((
                    "X-Report-Create-Sig",
                    Zeroizing::new(hex::encode(create_sig)),
                ));
                headers.push(("Authorization", Zeroizing::new(bearer.to_owned())));
            }
            (
                Method::Put,
                format!("{base}/file/{rid}/{}", trailer.filename()),
            )
        };
        Ok(EnvelopeRequest {
            method,
            url,
            headers,
            body: self.payload_range(),
        })
    }
}

impl EnvelopeRequest {
    /// The HTTP method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// The full URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The value of header `name` (exact name), if the request carries it.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| *header == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body: the envelope's payload range, with its verified hash.
    #[must_use]
    pub fn body(&self) -> &FileRange {
        &self.body
    }

    /// Send over `transport` (same dispatch, latch and fallback as every
    /// other relay write, see [`transport::send`]).
    pub fn send(&self, transport: Transport) -> SendOutcome {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        transport::send(
            transport,
            &OutgoingRequest {
                method: self.method,
                url: &self.url,
                headers: &headers,
                body: Some(&self.body),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::{open_envelope, write_envelope, QueueKey};
    use super::*;

    fn key() -> QueueKey {
        QueueKey::from_bytes(&[0x31u8; 32]).unwrap()
    }

    fn verified(
        name: &str,
        payload: &[u8],
        fields: super::super::EnvelopeFields,
    ) -> VerifiedEnvelope {
        let dir = std::env::temp_dir().join(format!("frap_envreq_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        write_envelope(&path, payload, fields, &key()).unwrap();
        open_envelope(&path, &key()).unwrap()
    }

    #[test]
    fn an_object_becomes_a_put_with_its_capability() {
        let payload = b"chunk";
        let env = verified(
            "put.fqe",
            payload,
            object_fields(EnvelopeKind::Chunk, "000001.strm", payload, true),
        );
        let trailer = env.trailer();
        let rid = trailer.report_id_hex();

        let plain = env.request("https://relay.example:8443/", None).unwrap();
        assert_eq!(plain.method(), Method::Put);
        assert_eq!(
            plain.url(),
            format!("https://relay.example:8443/file/{rid}/000001.strm")
        );
        assert_eq!(
            plain.header("X-Report-PK"),
            Some(hex::encode(trailer.report_pk()).as_str())
        );
        assert_eq!(
            plain.header("X-Report-Write-Sig"),
            Some(hex::encode(trailer.signature()).as_str())
        );
        assert_eq!(plain.header("X-Report-Create-Sig"), None);
        assert_eq!(plain.header("Authorization"), None);
        assert_eq!(plain.body().len(), payload.len() as u64);
        assert_eq!(plain.body().expected_sha256(), Some(&sha256(payload)));

        let creating = env
            .request("https://relay.example:8443", Some("Bearer jwt"))
            .unwrap();
        assert_eq!(
            creating.header("X-Report-Create-Sig"),
            Some(hex::encode(trailer.create_sig().unwrap()).as_str())
        );
        assert_eq!(creating.header("Authorization"), Some("Bearer jwt"));
        assert!(!format!("{creating:?}").contains("jwt"));
        assert!(!format!("{creating:?}").contains(&rid));
        let _ = std::fs::remove_file(env.path());
    }

    #[test]
    fn creation_needs_a_create_sig() {
        let payload = b"entry";
        let env = verified(
            "nocreate.fqe",
            payload,
            object_fields(EnvelopeKind::DirectoryEntry, "abcdef", payload, false),
        );
        assert_eq!(
            env.request("https://r", Some("Bearer x")).unwrap_err(),
            EnvelopeError::NoCreateSig
        );
        assert!(env.request("https://r", None).is_ok());
        let _ = std::fs::remove_file(env.path());
    }

    #[test]
    fn a_closure_becomes_a_post_and_never_creates() {
        let (manifest, fields) = closure_fields();
        let env = verified("close.fqe", &manifest, fields);
        let request = env.request("https://relay.example", None).unwrap();
        assert_eq!(request.method(), Method::Post);
        assert_eq!(
            request.url(),
            format!(
                "https://relay.example/close/{}",
                env.trailer().report_id_hex()
            )
        );
        assert_eq!(request.header("X-Report-Close-Seq-Limit"), Some("5"));
        assert_eq!(
            request.header("X-Report-Close-Sig"),
            Some(hex::encode(env.trailer().signature()).as_str())
        );
        assert_eq!(request.header("X-Report-Write-Sig"), None);
        assert_eq!(request.body().len(), manifest.len() as u64);
        assert_eq!(
            env.request("https://relay.example", Some("Bearer x"))
                .unwrap_err(),
            EnvelopeError::CreationNotApplicable
        );

        let (empty, legacy) = legacy_closure_fields();
        let env = verified("legacy_close.fqe", &empty, legacy);
        let request = env.request("https://relay.example", None).unwrap();
        assert_eq!(request.header("X-Report-Close-Seq-Limit"), Some("0"));
        let _ = std::fs::remove_file(env.path());
    }
}
