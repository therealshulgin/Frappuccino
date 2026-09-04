//! `AsyncUdpSocket` shim applying Salamander obfuscation under quinn — Phase 3b
//! brick 1 (transport plan `docs/TRANSPORT_PLAN.md` Phase 3, ROADMAP §10.9).
//!
//! Wraps quinn's default UDP socket: every outgoing datagram is obfuscated and
//! every incoming one de-obfuscated with the shared PSK (see [`crate::salamander`]),
//! so QUIC / h3 / ratchet / BBR above the datagram layer are untouched. GSO and
//! GRO are disabled (each packet carries a unique random salt, so datagrams
//! cannot be batched into one syscall) — an accepted, negligible cost at the
//! app's mobile-upload packet rate, and the only structural throughput effect.
//!
//! Injected via `quinn::Endpoint::new_with_abstract_socket` in
//! [`crate::quic`]'s `build_connection` when the target carries an obfs PSK.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::salamander::{self, SALT_LEN};

/// A Salamander-obfuscating wrapper around quinn's default UDP socket. The PSK
/// is held zeroized; it is an app-embedded obfs secret (not a per-user key).
pub struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    psk: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the PSK.
        f.debug_struct("SalamanderSocket").finish_non_exhaustive()
    }
}

impl SalamanderSocket {
    /// Wrap `inner` (quinn's default socket) with Salamander keyed by `psk`.
    #[must_use]
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, psk: Vec<u8>) -> Self {
        Self {
            inner,
            psk: Zeroizing::new(psk),
        }
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Write-readiness is purely the inner socket's concern.
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // GSO is disabled (`max_transmit_segments` == 1), so `contents` is
        // exactly one datagram. Insurance against a future quinn ignoring that:
        debug_assert!(
            transmit.segment_size.is_none(),
            "GSO must be disabled for the obfs socket (one salt per datagram)"
        );
        // Prepend a fresh random salt + XOR, then send.
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut buf = Vec::with_capacity(SALT_LEN + transmit.contents.len());
        salamander::obfuscate_into(&mut buf, transmit.contents, &self.psk, salt);
        let obf = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&obf)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Pending and Ready(Err) pass straight through (`ready!` returns Pending,
        // `?` returns the error); only Ready(Ok(n)) reaches the de-obfs loop.
        let n = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
        // GRO is disabled (`max_receive_segments` == 1), so each of the `n`
        // entries is exactly one datagram in `buf[..m.len]`. De-obfuscate each.
        for (buf, m) in bufs.iter_mut().zip(meta.iter_mut()).take(n) {
            // `None` (un-keyed / too-short garbage, e.g. an active probe with no
            // PSK) maps to a 0-length datagram, which quinn discards; `Some` is
            // the recovered QUIC packet length. `stride == len` is load-bearing:
            // quinn strides the recv buffer by `stride`, so for one datagram it
            // must equal `len` (a 0 stride with len>0 would loop forever).
            let plain =
                salamander::deobfuscate_in_place(&mut buf[..], m.len, &self.psk).unwrap_or(0);
            m.len = plain;
            m.stride = plain;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Disable UDP GSO: each datagram needs its own random salt, so they cannot
    /// be coalesced into a single segmented send.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// Disable UDP GRO: each datagram is de-obfuscated independently.
    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
