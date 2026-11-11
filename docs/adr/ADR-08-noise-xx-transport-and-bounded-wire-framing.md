# ADR-08: Primary `TCP + Noise XX + Yamux` Transport & Pre-Auth Bounded `bincode` Framing

- **Status:** Accepted
- **Subsystem:** `network::transport` / `network::behaviour`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

P2P daemons require mutually authenticated, forward-secret point-to-point channels minimal enough for stripped `musl` router binaries, alongside binary RPC framing immune to Slowloris socket stalling and pre-authentication `Vec` length-prefix heap OOM bombs.

## Decision

1. **Primary `TCP + Noise XX + Yamux` Stack (`build_mesh_swarm`):** Standardizes on `libp2p` TCP authenticated with `Noise_XX_25519_ChaChaPoly_SHA256` and multiplexed via `Yamux` (with optional secondary QUIC listener `enable_quic` and persistent `MeshClient` connection pooling + `/p2p/<PeerId>` TOFU pinning).
2. **Transport vs. End-to-End HNDL Boundary:** Point-to-point `Noise XX` authenticates live transport peers and hides wire framing, while long-term Harvest-Now, Decrypt-Later (HNDL) confidentiality never relies on transport encryption—all user stripes, manifests, and onion relay hops are pre-encrypted client-side ([ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md), [ADR-13](ADR-13-symmetric-pq-grover-baseline-and-cascaded-aead.md)).
3. **Versioned Pre-Auth Bounded Wire Codec (`BincodeWireCodec`):** Negotiates `/parvault/wire/1.0.0`, caps frames at `MAX_WIRE_FRAME_BYTES = 32 MiB`, reserves at most `64 KiB` initially before bytes arrive on the socket, and deserializes with `bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(buf.len() as u64)`.

## Consequences & Verification

- **Consequences:** Crafted 16-byte frames claiming `u64::MAX` vector lengths fail closed immediately with zero multi-gigabyte heap allocation, and static `musl` binaries stay compact (`3.62–7.52 MiB` on `x86_64`, `2.88–5.89 MiB` on `aarch64`).
- **Verification:** `tests/red_team_hardening_tests.rs` and Kani frame-bound harnesses (`proof_admin_rpc_wire_frame_header_no_panic_or_unbounded_alloc`, `proof_gateway_ipc_frame_header_bounds`).
