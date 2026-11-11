# ADR-22: Signed Zero-IP Home LAN UDP Discovery, DHCP Self-Healing & 4-Word BIP-39 SAS Pairing

- **Status:** Accepted
- **Subsystem:** `network::discovery`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Typing 60-character `/ip4/.../tcp/.../p2p/<PeerId>` multiaddrs blocks non-technical household adoption, and residential DHCP lease renewals silently break static IP configs when devices reconnect to Wi-Fi—yet trusting unauthenticated LAN broadcasts would allow rogue Wi-Fi guests to spoof peer identities.

## Decision

1. **Ed25519-Signed UDP 4009 Beacons (`LanBeaconPacket`):** Daemons broadcast signed beacons on UDP `4009` (multicast `239.255.80.86` + broadcast `255.255.255.255`, configured via `os_sys::bind_reusable_udp_v4`) under domain `"parvault-lan-beacon-v1:"` with a strict `±15 s` replay window (`MAX_LAN_BEACON_AGE_SECS = 15`). Receivers verify that `libp2p_peer_id` cryptographically matches `ed25519_pubkey`.
2. **4-Word BIP-39 SAS Pairing (`parvault pair` / `parvault join`):** Derives a human-readable 4-word Short Authentication String (e.g., `shield-copper-alpine-matrix`) from `(libp2p_peer_id, owner_pq_fingerprint, pairing_nonce)` committed via SHA-256 in the beacon.
3. **DHCP-Resilient Peer Store (`KnownPeersStore`):** Indexes `known_peers.json` by pinned `libp2p_peer_id`, dynamically updating socket IPs upon DHCP rotation and powering zero-flag peer resolution (`resolve_zero_config_peers`).

## Consequences & Verification

- **Consequences:** Zero IP addresses or port numbers required for home LAN pairing, with cryptographic anti-spoofing and automatic DHCP self-healing.
- **Verification:** `tests/zero_config_lan_and_router_soc_tests.rs` and Stage 11 of `scripts/docker_acceptance_gate.sh`.
