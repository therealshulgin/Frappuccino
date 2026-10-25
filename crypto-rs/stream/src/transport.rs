//! One send primitive for every relay write, over either transport.
//!
//! [`send`] takes a method, a URL, headers and an optional body read from a
//! file range, and delivers it over `DirectTls` (pinned TLS over TCP) or
//! `ObfQuic` (pinned HTTP/3 under the Salamander obfuscation). The dispatch
//! is the one the capability PUT of the FFI applies:
//!
//! - `DirectTls` sends over TLS.
//! - `ObfQuic` sends over QUIC unless QUIC is latched as unable to establish
//!   on this network, in which case it goes straight to TLS. A QUIC attempt
//!   that fails without an HTTP status, for a reason that is not local to the
//!   device (the file, the URL), is sent again over TLS in the same call. The
//!   latch itself is set by the QUIC transport when a connection cannot be
//!   established, and cleared by `clear_quic_degraded` / `reset_quic_client`.
//! - A build without the `quic` feature sends `ObfQuic` requests over TLS.
//!
//! A failure comes back as a [`PutResult`] with `http_status == 0` and a short
//! machine tag, not as an error type. `"file_missing"` means the body file
//! does not exist, and nothing else; see [`RangeFailure`] for the other local
//! tags. A response carries no tag, except
//! [`REPORT_CLOSED_TAG`](crate::upload::REPORT_CLOSED_TAG) on the relay's
//! closure refusal, over either transport.

use crate::file_range::{FileRange, RangeFailure};
use crate::upload::PutResult;
use std::fmt;

/// HTTP method of a relay write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `PUT`, an object write.
    Put,
    /// `POST`, a closure.
    Post,
}

/// Which transport to send over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Pinned TLS over TCP.
    DirectTls,
    /// Pinned HTTP/3 over obfuscated QUIC, falling back to `DirectTls` as
    /// described in the module documentation.
    ObfQuic,
}

/// Which transport actually carried the request, for observability: a field
/// test must be able to see whether the wire was obfuscated or quietly fell
/// back to the direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportUsed {
    /// QUIC established and the request got a response over it (or failed
    /// locally before any fallback could help).
    ObfQuic,
    /// TLS was asked for, or QUIC is not compiled in.
    DirectTls,
    /// QUIC was tried and failed to deliver; the request was re-sent over TLS.
    DirectTlsFallback,
    /// QUIC is latched as unable to establish; TLS was used directly.
    DirectTlsDegraded,
}

impl TransportUsed {
    /// The tag the app's metrics already use for this case.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObfQuic => "obfquic",
            Self::DirectTls => "directtls",
            Self::DirectTlsFallback => "directtls_fallback",
            Self::DirectTlsDegraded => "directtls_degraded",
        }
    }
}

/// A relay write to send.
#[derive(Clone, Copy)]
pub struct OutgoingRequest<'a> {
    /// The method.
    pub method: Method,
    /// Full URL. Over QUIC only its path and query are used; the authority is
    /// the QUIC endpoint's.
    pub url: &'a str,
    /// Extra headers. `Content-Type: application/octet-stream` is added
    /// whenever there is a body.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body, streamed from disk, or `None` for no body.
    pub body: Option<&'a FileRange>,
}

impl fmt::Debug for OutgoingRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Header values can hold the bearer, and the URL the report address.
        f.debug_struct("OutgoingRequest")
            .field("method", &self.method)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.map(FileRange::len))
            .finish_non_exhaustive()
    }
}

/// What a [`send`] produced.
#[derive(Debug, Clone)]
#[must_use]
pub struct SendOutcome {
    /// Status, timings and failure tag of the attempt that counts.
    pub result: PutResult,
    /// Which transport carried it.
    pub transport_used: TransportUsed,
}

/// Send `request` over `transport`. See the module documentation for the
/// dispatch.
pub fn send(transport: Transport, request: &OutgoingRequest<'_>) -> SendOutcome {
    let direct = || crate::upload::send_direct_tls(request);
    #[cfg(feature = "quic")]
    {
        let quic = || crate::quic::send_quic(request);
        let leg = if crate::quic::quic_is_degraded() {
            QuicLeg::Degraded
        } else {
            QuicLeg::Ready(&quic)
        };
        dispatch(transport, leg, &direct)
    }
    #[cfg(not(feature = "quic"))]
    {
        dispatch(transport, QuicLeg::NotCompiled, &direct)
    }
}

/// True when a failure tag names a problem on this device (the body file, the
/// URL) that another transport cannot fix, so no fallback is attempted.
#[must_use]
pub fn is_local_failure(tag: Option<&str>) -> bool {
    tag.is_some_and(|tag| tag == "bad_url" || RangeFailure::is_tag(tag))
}

/// The state of the QUIC transport for one dispatch.
enum QuicLeg<'a> {
    /// The build carries no QUIC transport.
    #[cfg_attr(feature = "quic", allow(dead_code))]
    NotCompiled,
    /// QUIC is latched as unable to establish.
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    Degraded,
    /// QUIC can be tried with this sender.
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    Ready(&'a dyn Fn() -> PutResult),
}

/// The dispatch rules, separated from the network so they can be tested with
/// canned results.
fn dispatch(
    transport: Transport,
    quic: QuicLeg<'_>,
    direct: &dyn Fn() -> PutResult,
) -> SendOutcome {
    let (result, transport_used) = match (transport, quic) {
        (Transport::DirectTls, _) | (Transport::ObfQuic, QuicLeg::NotCompiled) => {
            (direct(), TransportUsed::DirectTls)
        }
        (Transport::ObfQuic, QuicLeg::Degraded) => (direct(), TransportUsed::DirectTlsDegraded),
        (Transport::ObfQuic, QuicLeg::Ready(quic)) => {
            let over_quic = quic();
            if over_quic.http_status == 0 && !is_local_failure(over_quic.error_detail.as_deref()) {
                let mut over_tls = direct();
                if over_tls.http_status == 0 {
                    let quic_tag = over_quic.error_detail.as_deref().unwrap_or("quic");
                    let tls_tag = over_tls.error_detail.as_deref().unwrap_or("network");
                    over_tls.error_detail = Some(format!("quic_fallback:{quic_tag}->{tls_tag}"));
                }
                (over_tls, TransportUsed::DirectTlsFallback)
            } else {
                (over_quic, TransportUsed::ObfQuic)
            }
        }
    };
    SendOutcome {
        result,
        transport_used,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn status(code: u16) -> PutResult {
        PutResult {
            http_status: code,
            upload_ms: 1,
            transfer_ms: 1,
            error_detail: None,
        }
    }

    fn failed(tag: &str) -> PutResult {
        PutResult {
            http_status: 0,
            upload_ms: 1,
            transfer_ms: 0,
            error_detail: Some(tag.to_owned()),
        }
    }

    #[test]
    fn direct_tls_never_touches_quic() {
        let quic_calls = Cell::new(0);
        let quic = || {
            quic_calls.set(quic_calls.get() + 1);
            status(200)
        };
        let out = dispatch(Transport::DirectTls, QuicLeg::Ready(&quic), &|| status(204));
        assert_eq!(out.result.http_status, 204);
        assert_eq!(out.transport_used, TransportUsed::DirectTls);
        assert_eq!(quic_calls.get(), 0);

        let out = dispatch(Transport::ObfQuic, QuicLeg::NotCompiled, &|| status(201));
        assert_eq!(out.transport_used, TransportUsed::DirectTls);
        assert_eq!(out.result.http_status, 201);
    }

    #[test]
    fn a_degraded_latch_skips_quic() {
        let out = dispatch(Transport::ObfQuic, QuicLeg::Degraded, &|| status(204));
        assert_eq!(out.transport_used, TransportUsed::DirectTlsDegraded);
        assert_eq!(out.transport_used.as_str(), "directtls_degraded");
    }

    #[test]
    fn any_http_status_over_quic_is_final() {
        for code in [200u16, 204, 401, 409, 425, 429, 500, 507] {
            let direct_calls = Cell::new(0);
            let direct = || {
                direct_calls.set(direct_calls.get() + 1);
                status(204)
            };
            let quic = || status(code);
            let out = dispatch(Transport::ObfQuic, QuicLeg::Ready(&quic), &direct);
            assert_eq!(out.result.http_status, code);
            assert_eq!(out.transport_used, TransportUsed::ObfQuic);
            assert_eq!(direct_calls.get(), 0, "status {code} must not fall back");
        }
    }

    #[test]
    fn a_transport_failure_over_quic_falls_back_to_tls() {
        let quic = || failed("connect");
        let out = dispatch(Transport::ObfQuic, QuicLeg::Ready(&quic), &|| status(204));
        assert_eq!(out.result.http_status, 204);
        assert_eq!(out.transport_used, TransportUsed::DirectTlsFallback);
        assert!(out.result.error_detail.is_none());

        let out = dispatch(Transport::ObfQuic, QuicLeg::Ready(&quic), &|| {
            failed("timeout")
        });
        assert_eq!(out.result.http_status, 0);
        assert_eq!(
            out.result.error_detail.as_deref(),
            Some("quic_fallback:connect->timeout")
        );
        assert_eq!(out.transport_used.as_str(), "directtls_fallback");
    }

    #[test]
    fn local_failures_never_fall_back() {
        for tag in [
            "file_missing",
            "file_open",
            "body_short",
            "body_read",
            "body_mismatch",
            "bad_url",
        ] {
            let direct_calls = Cell::new(0);
            let direct = || {
                direct_calls.set(direct_calls.get() + 1);
                status(204)
            };
            let quic = || failed(tag);
            let out = dispatch(Transport::ObfQuic, QuicLeg::Ready(&quic), &direct);
            assert_eq!(out.result.error_detail.as_deref(), Some(tag));
            assert_eq!(out.transport_used, TransportUsed::ObfQuic);
            assert_eq!(direct_calls.get(), 0, "{tag} must not fall back");
        }
        assert!(!is_local_failure(None));
        assert!(!is_local_failure(Some("network")));
    }

    #[test]
    fn transport_tags_are_the_metrics_tags() {
        assert_eq!(TransportUsed::ObfQuic.as_str(), "obfquic");
        assert_eq!(TransportUsed::DirectTls.as_str(), "directtls");
    }
}
