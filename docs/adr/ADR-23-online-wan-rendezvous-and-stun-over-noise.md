# ADR-23: Blinded Online WAN Rendezvous Mailbox, STUN-over-Noise Reflection & Dynamic-IP Presence

- **Status:** Accepted
- **Subsystem:** `network::wan_rendezvous` / `network::behaviour`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Remote family devices and co-op nodes across cities lack static public IPs or third-party DynDNS accounts, and relying on external plaintext STUN servers or unencrypted rendezvous brokers would leak social-graph peering metadata.

## Decision

1. **Blinded 4-Word WAN Rendezvous (`WanRendezvousRegistry`):** From a shared 4-word WAN code `W`, peers derive an opaque lookup slot key and AEAD wrapping key so seed rendezvous servers index `SignedWanRendezvousEntry` records by an opaque key. Correction (v0.5.0): the derivation is unsalted and `W` is guessable (44 bits; the CLI derives it from the node's `PeerId` and PQ fingerprint), so a server can recover `W` offline and read or forge the card ([F-54](../security/TRUST_FINDINGS.md); CPace in v0.6.0):

```text
slot_key = HKDF-SHA256(ikm = W, info = "parvault-wan-rendezvous-slot-v1")
wrap_key = HKDF-SHA256(ikm = W, info = "parvault-wan-rendezvous-wrap-v1")
ddns_key = HKDF-SHA256(ikm = pq_fingerprint, info = "parvault-wan-ddns-v1")   # not secret (F-54)
```

2. **STUN-over-Noise Address Reflection & Bounded Anti-Spam Quotas:** Seed anchors reflect the authenticated Noise XX peer socket address (`observed_external_addr` in `RegisterWanRendezvousAck`) with zero external STUN dependencies, while capping the registry at `16,384` slots, `8` entries/slot, `4 KiB`/entry, and `3,600 s` TTL. Registration needs no ring admission (pairing uses it before admission), so new entries are also capped per signer (`8` slots) and per sender subnet (`32` live entries), refused with `reject.rendezvous_quota`; only admitted signers are written to the admission-IP map (F-22).

## Consequences & Verification

- **Consequences:** Enables zero-IP cross-city pairing and automatic ISP dynamic-IP recovery; rendezvous anchors are not zero-knowledge: they can learn the pairing code offline and read or forge peer cards (F-54).
- **Verification:** `network::wan_rendezvous::tests` (`src/network/wan_rendezvous.rs`) and `tests/zero_config_lan_and_router_soc_tests.rs`.
