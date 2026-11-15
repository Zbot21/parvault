//! The lab dial gate (`v0.5.4` NEW-5, `docs/LAB_MODE.md`): in deterministic mode both swarms may
//! dial only the fixed dial set (`bootstrap_peers` ∪ `lite_seed_addr` ∪ `lab.relays`).
//!
//! Pure and free of libp2p types, so Kani reaches it in the default build. The libp2p side
//! (`network::traversal_gate`) turns a `Multiaddr` into [`AddrPart`]s and a `PeerId` into a
//! [`PeerKey`], then asks [`lab_dial_decision`].

/// Longest `PeerId` byte form accepted. A libp2p `PeerId` is a multihash: an Ed25519 key is the
/// 38-byte identity form (`0x00 0x24` + 36 bytes of protobuf key), keys whose protobuf form is
/// over 42 bytes are hashed (`0x12 0x20` + 32 bytes = 34), and the largest multihash libp2p 0.54
/// parses has a 64-byte digest (66 bytes with its two varint bytes). 72 covers every form.
/// Under Kani the bound is 4 so the byte compare stays small (the harness ranges over every
/// length up to it); the comparison code is the same.
#[cfg(not(kani))]
pub const PEER_KEY_MAX: usize = 72;
#[cfg(kani)]
pub const PEER_KEY_MAX: usize = 4;

/// A `PeerId`'s bytes in a fixed buffer, compared on its first `len` bytes only.
#[derive(Clone, Copy, Debug)]
pub struct PeerKey {
    len: u8,
    bytes: [u8; PEER_KEY_MAX],
}

impl PeerKey {
    /// `None` if `raw` is empty or longer than [`PEER_KEY_MAX`].
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.is_empty() || raw.len() > PEER_KEY_MAX {
            return None;
        }
        let mut bytes = [0u8; PEER_KEY_MAX];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self {
            len: raw.len() as u8,
            bytes,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..(self.len as usize).min(PEER_KEY_MAX)]
    }
}

impl PartialEq for PeerKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for PeerKey {}

/// An IP literal: IPv4 uses the first 4 octets, the rest are ignored.
#[derive(Clone, Copy, Debug)]
pub struct LabIp {
    pub v6: bool,
    pub octets: [u8; 16],
}

impl LabIp {
    pub fn from_std(ip: std::net::IpAddr) -> Self {
        let mut octets = [0u8; 16];
        match ip {
            std::net::IpAddr::V4(v4) => {
                octets[..4].copy_from_slice(&v4.octets());
                Self { v6: false, octets }
            }
            std::net::IpAddr::V6(v6) => Self {
                v6: true,
                octets: v6.octets(),
            },
        }
    }

    fn significant(&self) -> &[u8] {
        if self.v6 {
            &self.octets
        } else {
            &self.octets[..4]
        }
    }
}

impl PartialEq for LabIp {
    fn eq(&self, other: &Self) -> bool {
        self.v6 == other.v6 && self.significant() == other.significant()
    }
}
impl Eq for LabIp {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialTransport {
    Tcp,
    Quic,
}

/// One dial-set entry: an IP-literal TCP or QUIC address and its `/p2p/` PeerId.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialEntry {
    pub ip: LabIp,
    pub port: u16,
    pub transport: DialTransport,
    pub peer: PeerKey,
}

/// A dialled address in an accepted shape, with its `/p2p/` PeerId if it carries one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialAddr {
    pub ip: LabIp,
    pub port: u16,
    pub transport: DialTransport,
    pub peer: Option<PeerKey>,
}

/// `Open`: not deterministic, every dial allowed. `Fixed`: only these entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialSet {
    Open,
    Fixed(Vec<DialEntry>),
}

impl DialSet {
    pub fn is_fixed(&self) -> bool {
        matches!(self, Self::Fixed(_))
    }
}

/// One multiaddr component, as the shape check sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrPart {
    Ip(LabIp),
    Tcp(u16),
    Udp(u16),
    QuicV1,
    P2p(PeerKey),
    /// `/dns`, `/dns4`, `/dns6`, `/dnsaddr`: a name that would be resolved.
    Dns,
    /// Anything else (`/ws`, `/p2p-circuit`, `/quic` draft-29, ...).
    Other,
}

/// The shape check: `/ip4|ip6/<ip>/tcp/<port>` or `/ip4|ip6/<ip>/udp/<port>/quic-v1`, optionally
/// followed by `/p2p/<id>`, and nothing else; port 0 is refused.
pub fn dial_addr_from_parts(parts: &[AddrPart]) -> Result<DialAddr, &'static str> {
    let (ip, port, transport, rest) = match parts {
        [AddrPart::Ip(ip), AddrPart::Tcp(port), rest @ ..] => {
            (*ip, *port, DialTransport::Tcp, rest)
        }
        [AddrPart::Ip(ip), AddrPart::Udp(port), AddrPart::QuicV1, rest @ ..] => {
            (*ip, *port, DialTransport::Quic, rest)
        }
        _ => return Err("reject.lab_dial_shape"),
    };
    if port == 0 {
        return Err("reject.lab_dial_shape");
    }
    let peer = match rest {
        [] => None,
        [AddrPart::P2p(peer)] => Some(*peer),
        _ => return Err("reject.lab_dial_shape"),
    };
    Ok(DialAddr {
        ip,
        port,
        transport,
        peer,
    })
}

/// The dial gate. `Open` allows everything. Under `Fixed`, an address is allowed iff some entry
/// has the same `(ip, port, transport)` and every PeerId given (`peer`, and the address's own
/// `/p2p/`) equals that entry's. A peer-only check (`addr = None`) needs `peer` to be some
/// entry's PeerId. Refusals: `reject.lab_dial_outside_set` (no entry), and
/// `reject.lab_dial_peer_mismatch` (the address is in the set under another PeerId).
pub fn lab_dial_decision(
    addr: Option<&DialAddr>,
    peer: Option<&PeerKey>,
    set: &DialSet,
) -> Result<(), &'static str> {
    let entries = match set {
        DialSet::Open => return Ok(()),
        DialSet::Fixed(entries) => entries,
    };
    let Some(addr) = addr else {
        return match peer {
            Some(p) if entries.iter().any(|e| e.peer == *p) => Ok(()),
            _ => Err("reject.lab_dial_outside_set"),
        };
    };
    let mut same_endpoint = false;
    for e in entries {
        if e.ip == addr.ip && e.port == addr.port && e.transport == addr.transport {
            same_endpoint = true;
            let addr_peer_ok = addr.peer.is_none_or(|p| p == e.peer);
            let peer_ok = peer.is_none_or(|p| *p == e.peer);
            if addr_peer_ok && peer_ok {
                return Ok(());
            }
        }
    }
    if same_endpoint {
        Err("reject.lab_dial_peer_mismatch")
    } else {
        Err("reject.lab_dial_outside_set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> LabIp {
        LabIp::from_std(s.parse::<IpAddr>().unwrap())
    }
    fn pk(b: u8) -> PeerKey {
        PeerKey::from_bytes(&[0, 36, b, b, b]).unwrap()
    }
    fn entry(a: &str, port: u16, t: DialTransport, p: u8) -> DialEntry {
        DialEntry {
            ip: ip(a),
            port,
            transport: t,
            peer: pk(p),
        }
    }

    #[test]
    fn shape_check_accepts_only_tcp_and_quic_v1() {
        let tcp = [AddrPart::Ip(ip("10.0.0.1")), AddrPart::Tcp(4001)];
        assert!(dial_addr_from_parts(&tcp).is_ok());
        let quic = [
            AddrPart::Ip(ip("::1")),
            AddrPart::Udp(4001),
            AddrPart::QuicV1,
            AddrPart::P2p(pk(1)),
        ];
        let a = dial_addr_from_parts(&quic).unwrap();
        assert_eq!(a.transport, DialTransport::Quic);
        assert!(a.ip.v6);
        for bad in [
            vec![AddrPart::Dns, AddrPart::Tcp(4001)],
            vec![AddrPart::Ip(ip("10.0.0.1")), AddrPart::Tcp(0)],
            vec![AddrPart::Ip(ip("10.0.0.1")), AddrPart::Udp(4001)],
            vec![
                AddrPart::Ip(ip("10.0.0.1")),
                AddrPart::Tcp(4001),
                AddrPart::Other,
            ],
            vec![
                AddrPart::Ip(ip("10.0.0.1")),
                AddrPart::Tcp(4001),
                AddrPart::P2p(pk(1)),
                AddrPart::Other,
            ],
            vec![
                AddrPart::Ip(ip("10.0.0.1")),
                AddrPart::Tcp(4001),
                AddrPart::P2p(pk(1)),
                AddrPart::P2p(pk(1)),
            ],
            vec![AddrPart::Tcp(4001)],
            vec![],
        ] {
            assert_eq!(
                dial_addr_from_parts(&bad),
                Err("reject.lab_dial_shape"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn fixed_set_allows_only_its_entries() {
        let set = DialSet::Fixed(vec![entry("10.9.0.2", 4001, DialTransport::Tcp, 7)]);
        let ok = DialAddr {
            ip: ip("10.9.0.2"),
            port: 4001,
            transport: DialTransport::Tcp,
            peer: Some(pk(7)),
        };
        assert_eq!(lab_dial_decision(Some(&ok), None, &set), Ok(()));
        assert_eq!(lab_dial_decision(Some(&ok), Some(&pk(7)), &set), Ok(()));
        let bare = DialAddr { peer: None, ..ok };
        assert_eq!(lab_dial_decision(Some(&bare), None, &set), Ok(()));
        assert_eq!(
            lab_dial_decision(Some(&bare), Some(&pk(8)), &set),
            Err("reject.lab_dial_peer_mismatch")
        );
        let other_peer = DialAddr {
            peer: Some(pk(8)),
            ..ok
        };
        assert_eq!(
            lab_dial_decision(Some(&other_peer), None, &set),
            Err("reject.lab_dial_peer_mismatch")
        );
        for (a, port, t) in [
            ("10.9.0.3", 4001, DialTransport::Tcp),
            ("10.9.0.2", 4002, DialTransport::Tcp),
            ("10.9.0.2", 4001, DialTransport::Quic),
            ("::ffff:10.9.0.2", 4001, DialTransport::Tcp),
        ] {
            let addr = DialAddr {
                ip: ip(a),
                port,
                transport: t,
                peer: None,
            };
            assert_eq!(
                lab_dial_decision(Some(&addr), None, &set),
                Err("reject.lab_dial_outside_set")
            );
        }
        assert_eq!(lab_dial_decision(None, Some(&pk(7)), &set), Ok(()));
        assert_eq!(
            lab_dial_decision(None, Some(&pk(8)), &set),
            Err("reject.lab_dial_outside_set")
        );
        assert_eq!(
            lab_dial_decision(None, None, &set),
            Err("reject.lab_dial_outside_set")
        );
        assert_eq!(
            lab_dial_decision(None, None, &DialSet::Fixed(vec![])),
            Err("reject.lab_dial_outside_set")
        );
        assert_eq!(lab_dial_decision(None, None, &DialSet::Open), Ok(()));
    }

    #[test]
    fn ipv6_entries_compare_all_octets_and_v4_ignores_padding() {
        let mut a = ip("10.0.0.1");
        a.octets[10] = 9;
        assert_eq!(a, ip("10.0.0.1"));
        assert_ne!(ip("fe80::1"), ip("fe80::2"));
        assert_ne!(ip("::"), ip("0.0.0.0"));
    }

    #[test]
    fn peer_key_bounds() {
        assert!(PeerKey::from_bytes(&[]).is_none());
        assert!(PeerKey::from_bytes(&[1u8; PEER_KEY_MAX + 1]).is_none());
        // The Ed25519 identity multihash is 38 bytes and fits.
        assert!(PeerKey::from_bytes(&[1u8; 38]).is_some());
        assert_ne!(
            PeerKey::from_bytes(&[1, 2]).unwrap(),
            PeerKey::from_bytes(&[1, 2, 0]).unwrap()
        );
    }
}
