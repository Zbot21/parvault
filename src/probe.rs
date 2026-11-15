//! `parvault net probe --force-direct` (`v0.5.4` NEW-4, `docs/LAB_MODE.md`): one deterministic
//! connection attempt against a named peer, with a machine-readable result
//! (`parvault.net-probe/1`). The decision and the result types are here, in the library's default
//! build, so Kani reaches `probe_target_decision`; the dial is `cli/net.rs`.

use serde::Serialize;

/// The probe mode. `--force-direct` is required in `v0.5.4`; `v0.5.9` adds relayed and auto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum ProbeMode {
    ForceDirect,
    /// No mode flag given.
    Unspecified,
}

/// What the target decision needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ProbeTargetFacts {
    /// The (resolved) address ends in `/p2p/<id>`.
    pub has_p2p: bool,
    /// The address has `/p2p-circuit`.
    pub has_circuit: bool,
    /// The address is `/ip4` or `/ip6` (no name to resolve).
    pub is_ip_literal: bool,
    /// The target was given as a bare PeerId (resolved from `known_peers.json`).
    pub bare_peer_id: bool,
    /// Deterministic lab mode.
    pub deterministic: bool,
    /// How many addresses the target resolved to (always 1 for a multiaddr).
    pub addr_count: u8,
    pub mode: ProbeMode,
}

/// The probe target rule: a mode is given; in lab mode a bare PeerId and a non-IP-literal address
/// are refused (the probe then reads no state file and resolves no name); the target resolves to
/// exactly one address; the address names its PeerId (Noise authenticates that peer); a relay
/// address is refused under `--force-direct`.
pub fn probe_target_decision(f: &ProbeTargetFacts) -> Result<(), &'static str> {
    if f.mode != ProbeMode::ForceDirect {
        return Err("reject.probe_mode_required");
    }
    if f.deterministic && f.bare_peer_id {
        return Err("reject.probe_bare_peer_id_lab");
    }
    if f.addr_count == 0 {
        return Err("reject.probe_peer_unknown");
    }
    if f.addr_count > 1 {
        return Err("reject.probe_ambiguous_peer");
    }
    if !f.has_p2p {
        return Err("reject.probe_peer_id_required");
    }
    if f.mode == ProbeMode::ForceDirect && f.has_circuit {
        return Err("reject.probe_relay_addr_forced_direct");
    }
    if f.deterministic && !f.is_ip_literal {
        return Err("reject.probe_addr_not_ip_literal_lab");
    }
    Ok(())
}

pub const PROBE_SCHEMA: &str = "parvault.net-probe/1";

/// Microsecond timings; `None` when the step did not run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProbeTimings {
    pub established: Option<u64>,
    pub ping_rtt: Option<u64>,
    pub first_response: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeLocal {
    /// Always `unknown` until AutoNAT (`v0.5.9`).
    pub nat_status: &'static str,
}

/// `parvault.net-probe/1`. Field order is fixed; no remote-supplied string appears.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeResult {
    pub schema: &'static str,
    pub version: &'static str,
    pub mode: &'static str,
    pub peer_id: Option<String>,
    pub addr: Option<String>,
    pub transport: Option<&'static str>,
    /// `connected`, `failed` (the attempt ran and did not connect) or `error` (no attempt).
    pub result: &'static str,
    pub path: Option<&'static str>,
    /// A traversal reason for `connected` / `failed`; a reason code for `error`.
    pub reason: String,
    pub timings_us: ProbeTimings,
    pub local: ProbeLocal,
    /// Always null in `v0.5.4`.
    pub relay: Option<String>,
    pub started_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_error: Option<String>,
}

impl ProbeResult {
    pub fn new(started_unix_ms: u64) -> Self {
        Self {
            schema: PROBE_SCHEMA,
            version: env!("CARGO_PKG_VERSION"),
            mode: "force-direct",
            peer_id: None,
            addr: None,
            transport: None,
            result: "error",
            path: None,
            reason: String::new(),
            timings_us: ProbeTimings::default(),
            local: ProbeLocal {
                nat_status: "unknown",
            },
            relay: None,
            started_unix_ms,
            rpc_error: None,
        }
    }
}

/// 0 connected (RPC ok or skipped), 1 failed, 4 connected but the RPC failed, 3 error.
pub fn probe_exit_code(r: &ProbeResult) -> i32 {
    match r.result {
        "connected" if r.rpc_error.is_some() => 4,
        "connected" => 0,
        "failed" => 1,
        _ => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_facts() -> ProbeTargetFacts {
        ProbeTargetFacts {
            has_p2p: true,
            has_circuit: false,
            is_ip_literal: true,
            bare_peer_id: false,
            deterministic: false,
            addr_count: 1,
            mode: ProbeMode::ForceDirect,
        }
    }

    #[test]
    fn target_refusals_have_their_codes() {
        assert_eq!(probe_target_decision(&ok_facts()), Ok(()));
        let cases = [
            (
                ProbeTargetFacts {
                    mode: ProbeMode::Unspecified,
                    ..ok_facts()
                },
                "reject.probe_mode_required",
            ),
            (
                ProbeTargetFacts {
                    has_p2p: false,
                    ..ok_facts()
                },
                "reject.probe_peer_id_required",
            ),
            (
                ProbeTargetFacts {
                    has_circuit: true,
                    ..ok_facts()
                },
                "reject.probe_relay_addr_forced_direct",
            ),
            (
                ProbeTargetFacts {
                    addr_count: 2,
                    ..ok_facts()
                },
                "reject.probe_ambiguous_peer",
            ),
            (
                ProbeTargetFacts {
                    addr_count: 0,
                    bare_peer_id: true,
                    ..ok_facts()
                },
                "reject.probe_peer_unknown",
            ),
            (
                ProbeTargetFacts {
                    bare_peer_id: true,
                    deterministic: true,
                    ..ok_facts()
                },
                "reject.probe_bare_peer_id_lab",
            ),
            (
                ProbeTargetFacts {
                    is_ip_literal: false,
                    deterministic: true,
                    ..ok_facts()
                },
                "reject.probe_addr_not_ip_literal_lab",
            ),
        ];
        for (f, code) in cases {
            assert_eq!(probe_target_decision(&f), Err(code), "{f:?}");
        }
        // Outside lab mode a bare PeerId and a DNS address are fine.
        assert_eq!(
            probe_target_decision(&ProbeTargetFacts {
                bare_peer_id: true,
                is_ip_literal: false,
                ..ok_facts()
            }),
            Ok(())
        );
    }

    #[test]
    fn exit_codes() {
        let mut r = ProbeResult::new(0);
        assert_eq!(probe_exit_code(&r), 3);
        r.result = "failed";
        assert_eq!(probe_exit_code(&r), 1);
        r.result = "connected";
        assert_eq!(probe_exit_code(&r), 0);
        r.rpc_error = Some("timeout".into());
        assert_eq!(probe_exit_code(&r), 4);
    }
}
