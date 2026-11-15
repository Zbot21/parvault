//! The lab dial gate on both swarms (`v0.5.4` NEW-5, `docs/LAB_MODE.md`).
//!
//! - [`LabDialTransport`] wraps the whole TCP + QUIC transport. Every address the swarm dials
//!   passes `Transport::dial`, including addresses a behaviour added, so a refusal there means
//!   no socket is opened for an address outside the set.
//! - [`TraversalGate`] is the first field of `MeshNetworkBehaviour`, so the derive calls it
//!   before any other field: it refuses a pending dial to a peer or address outside the set with
//!   a labelled `ConnectionDenied`, and checks the Noise-authenticated PeerId of every
//!   established outbound connection against the entry it was dialled at.
//!
//! Both call the one pure decision, `lab_dial::lab_dial_decision`. Inbound connections are not
//! restricted. Each refusal logs `warn!` once with its code and no address.

use crate::lab_dial::{
    dial_addr_from_parts, lab_dial_decision, AddrPart, DialAddr, DialEntry, DialSet, LabIp, PeerKey,
};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{
    DialOpts as TransportDialOpts, ListenerId, TransportError, TransportEvent,
};
use libp2p::core::{Endpoint, Transport};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// The components of `maddr`, as the shape check sees them.
pub fn multiaddr_parts(maddr: &Multiaddr) -> Vec<AddrPart> {
    maddr
        .iter()
        .map(|p| match p {
            Protocol::Ip4(v4) => AddrPart::Ip(LabIp::from_std(std::net::IpAddr::V4(v4))),
            Protocol::Ip6(v6) => AddrPart::Ip(LabIp::from_std(std::net::IpAddr::V6(v6))),
            Protocol::Tcp(port) => AddrPart::Tcp(port),
            Protocol::Udp(port) => AddrPart::Udp(port),
            Protocol::QuicV1 => AddrPart::QuicV1,
            Protocol::P2p(peer) => match peer_key(&peer) {
                Some(k) => AddrPart::P2p(k),
                None => AddrPart::Other,
            },
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                AddrPart::Dns
            }
            _ => AddrPart::Other,
        })
        .collect()
}

/// A PeerId's bytes as a [`PeerKey`]; `None` if longer than `PEER_KEY_MAX` (never for libp2p
/// 0.54 PeerIds).
pub fn peer_key(peer: &PeerId) -> Option<PeerKey> {
    PeerKey::from_bytes(&peer.to_bytes())
}

/// The shape check on a `Multiaddr`.
pub fn dial_addr_from_multiaddr(maddr: &Multiaddr) -> Result<DialAddr, &'static str> {
    dial_addr_from_parts(&multiaddr_parts(maddr))
}

/// A dial-set entry from its configured string; `None` unless it is an IP-literal TCP or QUIC
/// multiaddr with a `/p2p/` PeerId (`config::lab_addr_decision` refuses those at startup).
pub fn dial_entry_from_str(raw: &str) -> Option<DialEntry> {
    let maddr: Multiaddr = raw.trim().parse().ok()?;
    let a = dial_addr_from_multiaddr(&maddr).ok()?;
    Some(DialEntry {
        ip: a.ip,
        port: a.port,
        transport: a.transport,
        peer: a.peer?,
    })
}

/// The gate's decision for one address (and the peer it is dialled for, if known).
pub fn gate_addr_decision(
    addr: &Multiaddr,
    peer: Option<&PeerId>,
    set: &DialSet,
) -> Result<(), &'static str> {
    if !set.is_fixed() {
        return Ok(());
    }
    let parsed = dial_addr_from_multiaddr(addr)?;
    let key = match peer {
        Some(p) => Some(peer_key(p).ok_or("reject.lab_dial_shape")?),
        None => None,
    };
    lab_dial_decision(Some(&parsed), key.as_ref(), set)
}

/// The error a refused dial carries (in `TransportError::Other` and in `ConnectionDenied`);
/// NEW-3 classifies it as `denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabDialDenied {
    pub code: &'static str,
}

impl std::fmt::Display for LabDialDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lab dial gate: {}", self.code)
    }
}

impl std::error::Error for LabDialDenied {}

fn log_denied(code: &'static str, at: &'static str) {
    tracing::warn!(code, at, "lab dial gate refused a dial");
}

/// The transport choke point: every dialled address passes [`gate_addr_decision`] first.
pub struct LabDialTransport<T> {
    inner: T,
    set: Arc<DialSet>,
}

impl<T> LabDialTransport<T> {
    pub fn new(inner: T, set: Arc<DialSet>) -> Self {
        Self { inner, set }
    }
}

impl<T> Transport for LabDialTransport<T>
where
    T: Transport<Error = std::io::Error> + Unpin,
{
    type Output = T::Output;
    type Error = std::io::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: TransportDialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        // A known peer's address arrives with `/p2p/<id>` appended; an unknown-peer dial's
        // address as given. Either way the PeerId in it must be the entry's.
        if let Err(code) = gate_addr_decision(&addr, None, &self.set) {
            log_denied(code, "transport");
            return Err(TransportError::Other(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                LabDialDenied { code },
            )));
        }
        self.inner.dial(addr, opts)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// The boxed transport both swarms use.
pub type MeshTransport = libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)>;

/// The swarm side of the gate (the first field of `MeshNetworkBehaviour`).
pub struct TraversalGate {
    set: Arc<DialSet>,
}

impl TraversalGate {
    pub fn new(set: Arc<DialSet>) -> Self {
        Self { set }
    }

    pub fn dial_set(&self) -> &DialSet {
        &self.set
    }
}

impl NetworkBehaviour for TraversalGate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = <dummy::Behaviour as NetworkBehaviour>::ToSwarm;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Deterministic mode never restricts inbound connections.
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if self.set.is_fixed() {
            if let Some(peer) = maybe_peer {
                let key = peer_key(&peer);
                let verdict = match key {
                    Some(k) => lab_dial_decision(None, Some(&k), &self.set),
                    None => Err("reject.lab_dial_shape"),
                };
                if let Err(code) = verdict {
                    log_denied(code, "pending-peer");
                    return Err(ConnectionDenied::new(LabDialDenied { code }));
                }
            }
            for a in addresses {
                if let Err(code) = gate_addr_decision(a, maybe_peer.as_ref(), &self.set) {
                    log_denied(code, "pending-addr");
                    return Err(ConnectionDenied::new(LabDialDenied { code }));
                }
            }
        }
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _: Endpoint,
        _: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.set.is_fixed() {
            let verdict = dial_addr_from_multiaddr(addr).and_then(|parsed| {
                let key = peer_key(&peer).ok_or("reject.lab_dial_shape")?;
                lab_dial_decision(Some(&parsed), Some(&key), &self.set)
            });
            if let Err(code) = verdict {
                log_denied(code, "established");
                return Err(ConnectionDenied::new(LabDialDenied { code }));
            }
        }
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    #[test]
    fn ed25519_peer_ids_fit_the_key_bound() {
        let p = pid();
        assert_eq!(p.to_bytes().len(), 38);
        assert!(peer_key(&p).is_some());
    }

    #[test]
    fn gate_refuses_learned_dns_circuit_and_ws_addresses() {
        let b = pid();
        let entry = format!("/ip4/10.9.0.2/tcp/4001/p2p/{b}");
        let set = DialSet::Fixed(vec![dial_entry_from_str(&entry).unwrap()]);
        let ok: Multiaddr = entry.parse().unwrap();
        assert_eq!(gate_addr_decision(&ok, None, &set), Ok(()));
        let bare: Multiaddr = "/ip4/10.9.0.2/tcp/4001".parse().unwrap();
        assert_eq!(gate_addr_decision(&bare, Some(&b), &set), Ok(()));
        assert_eq!(
            gate_addr_decision(&bare, Some(&pid()), &set),
            Err("reject.lab_dial_peer_mismatch")
        );
        for bad in [
            "/ip4/10.9.0.3/tcp/4001".to_string(),
            "/ip6/::1/tcp/4001".to_string(),
        ] {
            let m: Multiaddr = bad.parse().unwrap();
            assert_eq!(
                gate_addr_decision(&m, None, &set),
                Err("reject.lab_dial_outside_set"),
                "{bad}"
            );
        }
        for bad in [
            format!("/dns4/b.example/tcp/4001/p2p/{b}"),
            format!("/ip4/10.9.0.2/tcp/4001/p2p/{b}/p2p-circuit"),
            "/ip4/10.9.0.2/tcp/4001/ws".to_string(),
            "/ip4/10.9.0.2/udp/4001/quic".to_string(),
        ] {
            let m: Multiaddr = bad.parse().unwrap();
            assert_eq!(
                gate_addr_decision(&m, None, &set),
                Err("reject.lab_dial_shape"),
                "{bad}"
            );
        }
        assert_eq!(gate_addr_decision(&bare, None, &DialSet::Open), Ok(()));
    }

    #[test]
    fn dial_entries_need_ip_literal_and_peer_id() {
        let b = pid();
        assert!(dial_entry_from_str(&format!("/ip6/fe80::1/udp/4001/quic-v1/p2p/{b}")).is_some());
        assert!(dial_entry_from_str("/ip4/10.0.0.1/tcp/4001").is_none());
        assert!(dial_entry_from_str(&format!("/dns4/x/tcp/4001/p2p/{b}")).is_none());
    }
}
