//! Classifies a dial outcome for the traversal counters and `net probe` (`v0.5.4` NEW-3/NEW-4,
//! `docs/METRICS.md`).
//!
//! Per address error, the error chain is walked (`source()`), so the classification does not
//! depend on how many layers (`Boxed`, the upgrade, `Either`) wrap it: an `io::Error` kind of
//! `ConnectionRefused` is `refused`, `TimedOut` is `timeout`, `HostUnreachable` /
//! `NetworkUnreachable` are `unreachable`; a Noise error or a protocol negotiation error on the
//! upgrade is `noise_failed`; `LabDialDenied` is `denied`; `MultiaddrNotSupported` is
//! `transport_unsupported`; anything else is `other`.

use crate::network::traversal_gate::LabDialDenied;
use crate::traversal_metrics::{PathKind, TransportKind, TraversalReason};
use libp2p::core::transport::TransportError;
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::DialError;
use libp2p::Multiaddr;
use std::error::Error as StdError;
use std::io;

/// An upgrade (security or multiplexer negotiation) failed after the TCP connection opened: the
/// remote was reached. NEW-3 counts it as `noise_failed`.
#[derive(Debug)]
pub struct UpgradeFailed(pub String);

impl std::fmt::Display for UpgradeFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connection upgrade failed: {}", self.0)
    }
}

impl StdError for UpgradeFailed {}

/// The TCP stack's error (`Either<Either<tcp io::Error, security>, multiplexer>` in libp2p-core
/// 0.42) as one `io::Error`: the TCP error itself, or an [`UpgradeFailed`]. `Either`'s
/// `source()` skips the error it wraps, so without this the TCP kind is unreachable.
pub fn flatten_tcp_stack_error<A, B>(
    e: either::Either<either::Either<io::Error, A>, B>,
) -> io::Error
where
    A: StdError,
    B: StdError,
{
    match e {
        either::Either::Left(either::Either::Left(tcp)) => tcp,
        either::Either::Left(either::Either::Right(sec)) => {
            io::Error::other(UpgradeFailed(sec.to_string()))
        }
        either::Either::Right(mux) => io::Error::other(UpgradeFailed(mux.to_string())),
    }
}

/// The TCP-or-QUIC transport's error (`Either<tcp io::Error, quic::Error>`) as one `io::Error`
/// whose inner error is downcastable.
pub fn flatten_or_error<B>(e: either::Either<io::Error, B>) -> io::Error
where
    B: StdError + Send + Sync + 'static,
{
    match e {
        either::Either::Left(tcp) => tcp,
        either::Either::Right(other) => io::Error::other(other),
    }
}

/// `relayed` iff the address has `/p2p-circuit`; `quic` iff it has `/quic-v1` (else `tcp`).
pub fn classify_addr(addr: &Multiaddr) -> (PathKind, TransportKind) {
    let mut path = PathKind::Direct;
    let mut transport = TransportKind::Tcp;
    for p in addr.iter() {
        match p {
            Protocol::P2pCircuit => path = PathKind::Relayed,
            Protocol::QuicV1 => transport = TransportKind::Quic,
            _ => {}
        }
    }
    (path, transport)
}

fn reason_of_io_kind(kind: io::ErrorKind) -> Option<TraversalReason> {
    match kind {
        io::ErrorKind::ConnectionRefused => Some(TraversalReason::Refused),
        io::ErrorKind::TimedOut => Some(TraversalReason::Timeout),
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            Some(TraversalReason::Unreachable)
        }
        _ => None,
    }
}

/// One error, classified by its whole `source()` chain.
pub fn classify_error_chain(err: &(dyn StdError + 'static)) -> TraversalReason {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
    let mut io_reason = None;
    while let Some(e) = cur {
        if e.downcast_ref::<LabDialDenied>().is_some() {
            return TraversalReason::Denied;
        }
        if e.downcast_ref::<UpgradeFailed>().is_some()
            || e.downcast_ref::<libp2p::noise::Error>().is_some()
            || e.downcast_ref::<libp2p::core::upgrade::NegotiationError>()
                .is_some()
        {
            return TraversalReason::NoiseFailed;
        }
        if let Some(q) = e.downcast_ref::<libp2p::quic::Error>() {
            return match q {
                libp2p::quic::Error::HandshakeTimedOut => TraversalReason::Timeout,
                _ => TraversalReason::Other,
            };
        }
        if let Some(ioe) = e.downcast_ref::<io::Error>() {
            if io_reason.is_none() {
                io_reason = reason_of_io_kind(ioe.kind());
            }
            // An io::Error wraps its inner error in `get_ref`, not always in `source()`.
            if let Some(inner) = ioe.get_ref() {
                let inner: &(dyn StdError + 'static) = inner;
                let r = classify_error_chain(inner);
                if r != TraversalReason::Other {
                    return r;
                }
            }
        }
        cur = e.source();
    }
    io_reason.unwrap_or(TraversalReason::Other)
}

/// One `(address, error)` of a `DialError::Transport`.
pub fn classify_transport_error(err: &TransportError<io::Error>) -> TraversalReason {
    match err {
        TransportError::MultiaddrNotSupported(_) => TraversalReason::TransportUnsupported,
        TransportError::Other(e) => classify_error_chain(e),
    }
}

/// The multi-address precedence: an error showing the remote was reached wins over one showing
/// it was not, and a lab refusal ranks below any real network result.
pub const fn precedence(r: TraversalReason) -> u8 {
    match r {
        TraversalReason::NoiseFailed => 7,
        TraversalReason::Refused => 6,
        TraversalReason::Unreachable => 5,
        TraversalReason::Timeout => 4,
        TraversalReason::TransportUnsupported => 3,
        TraversalReason::Denied => 2,
        _ => 1,
    }
}

/// Picks one `(reason, path, transport)` from classified address errors: the highest
/// precedence; on a tie `tcp` before `quic`, then the lowest index. Independent of the order the
/// concurrent errors arrived in only through that fixed rule.
pub fn pick_transport_error(
    classified: &[(PathKind, TransportKind, TraversalReason)],
) -> Option<(PathKind, TransportKind, TraversalReason)> {
    let tie = |t: TransportKind| match t {
        TransportKind::Tcp => 0u8,
        TransportKind::Quic => 1,
        TransportKind::None => 2,
    };
    let mut best: Option<(usize, (PathKind, TransportKind, TraversalReason))> = None;
    for (i, c) in classified.iter().enumerate() {
        let better = match best {
            None => true,
            Some((_, b)) => {
                let (pc, pb) = (precedence(c.2), precedence(b.2));
                pc > pb || (pc == pb && tie(c.1) < tie(b.1))
            }
        };
        if better {
            best = Some((i, *c));
        }
    }
    best.map(|(_, c)| c)
}

fn endpoint_addr(ep: &ConnectedPoint) -> &Multiaddr {
    match ep {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}

/// A whole dial's outcome, or `None` for `DialPeerConditionFalse` (not an attempt).
pub fn classify_dial_error(err: &DialError) -> Option<(PathKind, TransportKind, TraversalReason)> {
    let none = |r| Some((PathKind::Direct, TransportKind::None, r));
    match err {
        DialError::DialPeerConditionFalse(_) => None,
        DialError::Transport(errors) => {
            let classified: Vec<_> = errors
                .iter()
                .map(|(addr, e)| {
                    let (p, t) = classify_addr(addr);
                    (p, t, classify_transport_error(e))
                })
                .collect();
            pick_transport_error(&classified)
                .or_else(|| none(TraversalReason::TransportUnsupported))
        }
        DialError::WrongPeerId { endpoint, .. } => {
            let (p, t) = classify_addr(endpoint_addr(endpoint));
            Some((p, t, TraversalReason::PeerIdMismatch))
        }
        DialError::LocalPeerId { endpoint } => {
            let (p, t) = classify_addr(endpoint_addr(endpoint));
            Some((p, t, TraversalReason::Other))
        }
        DialError::NoAddresses => none(TraversalReason::TransportUnsupported),
        DialError::Aborted => none(TraversalReason::Aborted),
        DialError::Denied { cause } => match cause.downcast_ref::<LabDialDenied>() {
            Some(d) if d.code == crate::network::traversal_gate::LAB_PEER_MISMATCH => {
                none(TraversalReason::PeerIdMismatch)
            }
            _ => none(TraversalReason::Denied),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TraversalReason::*;

    #[test]
    fn precedence_orders_every_pair() {
        let order = [
            NoiseFailed,
            Refused,
            Unreachable,
            Timeout,
            TransportUnsupported,
            Denied,
            Other,
        ];
        for (i, hi) in order.iter().enumerate() {
            for lo in &order[i + 1..] {
                for (a, b) in [(*hi, *lo), (*lo, *hi)] {
                    let picked = pick_transport_error(&[
                        (PathKind::Direct, TransportKind::Tcp, a),
                        (PathKind::Direct, TransportKind::Tcp, b),
                    ])
                    .unwrap();
                    assert_eq!(picked.2, *hi, "{a:?} vs {b:?}");
                }
            }
        }
    }

    #[test]
    fn ties_prefer_tcp_then_the_lowest_index() {
        let quic_first = [
            (PathKind::Direct, TransportKind::Quic, Refused),
            (PathKind::Direct, TransportKind::Tcp, Refused),
        ];
        assert_eq!(
            pick_transport_error(&quic_first).unwrap().1,
            TransportKind::Tcp
        );
        let two_tcp = [
            (PathKind::Direct, TransportKind::Tcp, Timeout),
            (PathKind::Relayed, TransportKind::Tcp, Timeout),
        ];
        assert_eq!(pick_transport_error(&two_tcp).unwrap().0, PathKind::Direct);
        assert_eq!(pick_transport_error(&[]), None);
    }

    #[test]
    fn io_kinds_and_wrapped_errors_classify() {
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_error_chain(&refused), Refused);
        let wrapped = io::Error::other(io::Error::from(io::ErrorKind::TimedOut));
        assert_eq!(classify_error_chain(&wrapped), Timeout);
        let denied = io::Error::new(
            io::ErrorKind::PermissionDenied,
            LabDialDenied {
                code: "reject.lab_dial_shape",
            },
        );
        assert_eq!(classify_error_chain(&io::Error::other(denied)), Denied);
        assert_eq!(
            classify_transport_error(&TransportError::MultiaddrNotSupported(
                "/ip4/1.2.3.4/tcp/1".parse().unwrap()
            )),
            TransportUnsupported
        );
        assert_eq!(classify_error_chain(&io::Error::other("x")), Other);
    }

    /// Real dials through the crate's own transport stack (TCP and TCP+QUIC): a closed port is
    /// `refused`, and a listener that accepts and closes is `noise_failed` (the upgrade failed
    /// after the remote was reached).
    #[test]
    fn real_dial_errors_classify() {
        use libp2p::futures::StreamExt;
        fn dial_reason(quic: bool, addr: Multiaddr) -> TraversalReason {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut sw = crate::network::build_mesh_client_swarm(
                    libp2p::identity::Keypair::generate_ed25519(),
                    quic,
                )
                .unwrap();
                sw.dial(addr).unwrap();
                loop {
                    if let libp2p::swarm::SwarmEvent::OutgoingConnectionError { error, .. } =
                        sw.select_next_some().await
                    {
                        return classify_dial_error(&error).unwrap().2;
                    }
                }
            })
        }
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        for quic in [false, true] {
            let a: Multiaddr = format!("/ip4/127.0.0.1/tcp/{closed}").parse().unwrap();
            assert_eq!(dial_reason(quic, a), Refused, "quic={quic}");
        }
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                drop(s);
            }
        });
        let a: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
        assert_eq!(dial_reason(false, a), NoiseFailed);
    }

    #[test]
    fn addresses_give_path_and_transport() {
        let q: Multiaddr = "/ip4/1.2.3.4/udp/1/quic-v1".parse().unwrap();
        assert_eq!(classify_addr(&q), (PathKind::Direct, TransportKind::Quic));
        let r: Multiaddr = "/ip4/1.2.3.4/tcp/1/p2p-circuit".parse().unwrap();
        assert_eq!(classify_addr(&r), (PathKind::Relayed, TransportKind::Tcp));
    }
}
