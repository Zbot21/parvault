//! Formal Bounded Model Checking Harnesses (`cargo kani`) for `parvault`.
//!
//! Every `#[kani::proof]` harness in this module exercises **real production functions** across:
//! 1. `crate::storage::eviction`: `M-of-N` Federated Council Quorum verification
//!    (`SignedBadActorEvictionOrder`), canonical signing payload collision-freeness, and
//!    4-vector `PrivacyPreservingEvictionEngine` keyed-HMAC dual-stack IP normalization &
//!    cross-domain preimage isolation.
//! 2. `crate::admin_rpc`: Length-prefixed TCP wire frame validation (`MAX_ADMIN_RPC_FRAME_BYTES`,
//!    `MAX_ADMIN_RPC_INITIAL_ALLOC_BYTES`), `[0u8; 32]` zero-key rejection, challenge-nonce
//!    anti-replay binding, and overflow-free `MAX_ADMIN_RPC_CLOCK_SKEW_MS` window enforcement.
//! 3. `crate::config` & `crate::sharding::reed_solomon`: Overflow-free streaming stripe
//!    decomposition across the entire `0..=u64::MAX` (`MAX_FILE_BYTES`) file size domain and
//!    Reed-Solomon shard/memory bounds under `HardwareProfile::RouterSoc` (`< 32 MiB` ceiling)
//!    and `HardwareProfile::Desktop`.

use crate::admin_rpc::{
    validate_admin_rpc_frame_header, validate_admin_rpc_slice_replay_and_auth_meta,
    MAX_ADMIN_RPC_CLOCK_SKEW_MS, MAX_ADMIN_RPC_FRAME_BYTES, MAX_ADMIN_RPC_INITIAL_ALLOC_BYTES,
};
use crate::capabilities::{
    AccessRequestContext, CapabilityError, CapabilityMacaroon, Caveat, MacaroonSliceView,
};
use crate::config::{
    compute_stripe_layout_for_size, ErasureTier, HardwareProfile, AES_GCM_TAG_OVERHEAD_BYTES,
    DEFAULT_STRIPE_SIZE_BYTES, MAX_FILE_BYTES, MIN_STRIPE_SIZE_BYTES,
    ROUTER_SOC_MAX_STRIPE_MEMORY_BYTES, ROUTER_SOC_STRIPE_SIZE_BYTES,
};
use crate::gateway::engine::PinnedRingBudget;
use crate::gateway::ipc::{
    validate_ipc_frame_header, MAX_IPC_FRAME_BYTES, MAX_IPC_INITIAL_ALLOC_BYTES,
};
use crate::sharding::reed_solomon::{
    compute_reed_solomon_shard_len, compute_stripe_memory_footprint_bytes,
};
use crate::storage::eviction::{
    EvictionOrderSliceView, EvictionTarget, PrivacyPreservingEvictionEngine,
    SignedBadActorEvictionOrder, TrackerOperatorCosignature,
};
use crate::sync::{sanitize_sync_relative_path, sanitize_sync_relative_path_into};
#[cfg(feature = "vfs")]
use crate::vfs::{
    compute_vfs_block_window, parse_fuse_in_header, parse_fuse_read_in, FuseInHeader, FuseReadIn,
    FUSE_IN_HEADER_BYTES, FUSE_READ_IN_BYTES,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn symbolic_eviction_target_fixed() -> EvictionTarget {
    let variant: u8 = kani::any();
    kani::assume(variant < 5);
    match variant {
        0 => {
            let octets: [u8; 4] = kani::any();
            EvictionTarget::IpAddress(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        1 => {
            let octets: [u8; 16] = kani::any();
            EvictionTarget::IpAddress(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        2 => EvictionTarget::PeerOrIssuerPubkey(kani::any()),
        3 => EvictionTarget::StripeMerkleRoot(kani::any()),
        _ => EvictionTarget::BlindedLocator(kani::any()),
    }
}

fn symbolic_ascii_bytes_4() -> [u8; 4] {
    let raw: [u8; 4] = kani::any();
    kani::assume(raw[0].is_ascii_graphic());
    kani::assume(raw[1].is_ascii_graphic());
    kani::assume(raw[2].is_ascii_graphic());
    kani::assume(raw[3].is_ascii_graphic());
    raw
}

fn symbolic_cosig() -> TrackerOperatorCosignature {
    TrackerOperatorCosignature {
        cosigner_pubkey: kani::any(),
        sig_r: kani::any(),
        sig_s: kani::any(),
    }
}

/// Constant-loop-bound byte-slice equality helper for Kani BMC so symbolic slice lengths never
/// trigger unbounded `<builtin-library-memcmp>` loop unwinding in CBMC.
fn slice_eq_bounded<const MAX: usize>(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    assert!(a.len() <= MAX);
    let mut i = 0;
    while i < MAX {
        if i < a.len() && a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn eviction_target_eq_fixed(a: &EvictionTarget, b: &EvictionTarget) -> bool {
    match (a, b) {
        (EvictionTarget::IpAddress(IpAddr::V4(x)), EvictionTarget::IpAddress(IpAddr::V4(y))) => {
            x.octets() == y.octets()
        }
        (EvictionTarget::IpAddress(IpAddr::V6(x)), EvictionTarget::IpAddress(IpAddr::V6(y))) => {
            x.octets() == y.octets()
        }
        (EvictionTarget::PeerOrIssuerPubkey(x), EvictionTarget::PeerOrIssuerPubkey(y)) => x == y,
        (EvictionTarget::StripeMerkleRoot(x), EvictionTarget::StripeMerkleRoot(y)) => x == y,
        (EvictionTarget::BlindedLocator(x), EvictionTarget::BlindedLocator(y)) => x == y,
        _ => false,
    }
}

// ============================================================================
// (2a) Eviction M-of-N Quorum Soundness & Keyed-HMAC Isolation (`eviction.rs`)
// ============================================================================

/// Proves against real `SignedBadActorEvictionOrder::tally_and_verify_quorum_raw` (which backs
/// `valid_council_signer_count_with` and `verify_against_quorum_with`) that an adversary
/// controlling:
/// - ANY subset of `< min_quorum` (`<= M - 1`) compromised council public keys, PLUS
/// - EVERY external non-council public key in the universe, PLUS
/// - Arbitrary duplicate co-signatures from the same compromised council key(s), PLUS
/// - All-zero `[0u8; 32]` public key injection attempts
/// can **NEVER** reach `min_quorum` or authorize eviction.
#[kani::proof]
fn proof_eviction_quorum_sub_threshold_and_duplicate_signer_rejected() {
    let council: [[u8; 32]; 4] = kani::any();
    kani::assume(council[0] != [0u8; 32]);
    kani::assume(council[1] != [0u8; 32]);
    kani::assume(council[2] != [0u8; 32]);
    kani::assume(council[3] != [0u8; 32]);
    kani::assume(council[0] != council[1]);
    kani::assume(council[0] != council[2]);
    kani::assume(council[0] != council[3]);
    kani::assume(council[1] != council[2]);
    kani::assume(council[1] != council[3]);
    kani::assume(council[2] != council[3]);

    let min_quorum: usize = kani::any();
    kani::assume((2..=4).contains(&min_quorum));

    // Adversary controls any subset of strictly fewer than `min_quorum` council keys,
    // plus every non-council public key outside `council`.
    let active_mask: u8 = kani::any::<u8>() & 0b1111;
    kani::assume((active_mask.count_ones() as usize) < min_quorum);

    // 3 symbolic cosignatures + 1 symbolic issuer = 4 stack signature slots (covering 0..=3 active
    // cosigs since any slot may hold `[0u8; 32]`, an outsider key, or a duplicate council key).
    let order_id: [u8; 32] = kani::any();
    let target = symbolic_eviction_target_fixed();
    let issued_at_ms: u64 = kani::any();
    let expires_at_ms: u64 = kani::any();
    let issuer_pubkey: [u8; 32] = kani::any();
    let sig_r: [u8; 32] = kani::any();
    let sig_s: [u8; 32] = kani::any();
    let cosigs = [symbolic_cosig(), symbolic_cosig(), symbolic_cosig()];

    // Maximally permissive Byzantine UF-CMA verifier: EVERY non-council key and EVERY
    // compromised council key is allowed to forge valid signatures on arbitrary messages,
    // while uncompromised honest council members never signed the order.
    let byzantine_verify = |pk: &[u8; 32], _msg: &[u8], _sig: &[u8; 64]| -> bool {
        if *pk == [0u8; 32] {
            return false;
        }
        if council[0] == *pk {
            return (active_mask & 0b0001) != 0;
        }
        if council[1] == *pk {
            return (active_mask & 0b0010) != 0;
        }
        if council[2] == *pk {
            return (active_mask & 0b0100) != 0;
        }
        if council[3] == *pk {
            return (active_mask & 0b1000) != 0;
        }
        true
    };

    let now_ms: u64 = kani::any();
    let (tally, quorum_ok) = SignedBadActorEvictionOrder::tally_and_verify_quorum_raw(
        EvictionOrderSliceView {
            order_id: &order_id,
            target: &target,
            reason_bytes: b"k",
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey: &issuer_pubkey,
            sig_r: &sig_r,
            sig_s: &sig_s,
            cosignatures: &cosigs,
        },
        &council,
        min_quorum,
        now_ms,
        byzantine_verify,
    );
    assert!(tally < min_quorum);
    assert!(!quorum_ok);
}

/// Proves:
/// 1. `SignedBadActorEvictionOrder::default_tracker_quorum_threshold(n)` enforces strict majority
///    (`2 * M > N` and `1 <= M <= N`) for all symbolic `N >= 1`.
/// 2. `>= M` (`2-of-3`) distinct authorized council signers succeed iff the order has not expired.
/// 3. Mutating the signed message (`mut_order_id != order_id`) strictly invalidates quorum.
#[kani::proof]
fn proof_eviction_quorum_authorized_distinct_signers_and_expiry() {
    let any_n: usize = kani::any();
    kani::assume((1..=10_000).contains(&any_n));
    let m_thresh = SignedBadActorEvictionOrder::default_tracker_quorum_threshold(any_n);
    assert!(m_thresh >= 1 && m_thresh <= any_n);
    assert!(2 * m_thresh > any_n);

    let council: [[u8; 32]; 3] = kani::any();
    kani::assume(council[0] != [0u8; 32]);
    kani::assume(council[1] != [0u8; 32]);
    kani::assume(council[2] != [0u8; 32]);
    kani::assume(council[0] != council[1]);
    kani::assume(council[0] != council[2]);
    kani::assume(council[1] != council[2]);

    let min_quorum = SignedBadActorEvictionOrder::default_tracker_quorum_threshold(3);
    assert_eq!(min_quorum, 2);

    let order_id: [u8; 32] = kani::any();
    let v4_octets: [u8; 4] = kani::any();
    let target = EvictionTarget::IpAddress(IpAddr::V4(Ipv4Addr::from(v4_octets)));
    let reason_a = symbolic_ascii_bytes_4();
    let issued_at_ms: u64 = kani::any();
    let expires_at_ms: u64 = kani::any();
    let issuer_pubkey = council[0];
    let sig_r = [0xA1u8; 32];
    let sig_s = [0xA2u8; 32];
    let cosigs = [TrackerOperatorCosignature {
        cosigner_pubkey: council[1],
        sig_r: [0xB1; 32],
        sig_s: [0xB2; 32],
    }];

    let (signed_buf, signed_len) = SignedBadActorEvictionOrder::encode_signing_payload_stack(
        &order_id,
        &target,
        &reason_a,
        issued_at_ms,
        expires_at_ms,
        &issuer_pubkey,
    )
    .expect("fits in 256-byte stack preimage");

    let ufcma_verify = |pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]| -> bool {
        if !slice_eq_bounded::<132>(msg, &signed_buf[..signed_len]) {
            return false;
        }
        if *pk == council[0] {
            sig[..32] == [0xA1; 32] && sig[32..] == [0xA2; 32]
        } else if *pk == council[1] {
            sig[..32] == [0xB1; 32] && sig[32..] == [0xB2; 32]
        } else {
            false
        }
    };

    let now_ms: u64 = kani::any();
    let is_expired = expires_at_ms != 0 && now_ms > expires_at_ms;
    let (tally, quorum_ok) = SignedBadActorEvictionOrder::tally_and_verify_quorum_raw(
        EvictionOrderSliceView {
            order_id: &order_id,
            target: &target,
            reason_bytes: &reason_a,
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey: &issuer_pubkey,
            sig_r: &sig_r,
            sig_s: &sig_s,
            cosignatures: &cosigs,
        },
        &council,
        min_quorum,
        now_ms,
        ufcma_verify,
    );
    assert_eq!(tally, 2);
    assert_eq!(quorum_ok, !is_expired);

    let mut_order_id: [u8; 32] = kani::any();
    kani::assume(mut_order_id != order_id);
    let (_mut_tally, mut_quorum_ok) = SignedBadActorEvictionOrder::tally_and_verify_quorum_raw(
        EvictionOrderSliceView {
            order_id: &mut_order_id,
            target: &target,
            reason_bytes: &reason_a,
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey: &issuer_pubkey,
            sig_r: &sig_r,
            sig_s: &sig_s,
            cosignatures: &cosigs,
        },
        &council,
        min_quorum,
        0,
        ufcma_verify,
    );
    assert!(!mut_quorum_ok);
}

fn symbolic_eviction_target_32b() -> EvictionTarget {
    let variant: u8 = kani::any();
    kani::assume(variant < 3);
    let digest: [u8; 32] = kani::any();
    match variant {
        0 => EvictionTarget::PeerOrIssuerPubkey(digest),
        1 => EvictionTarget::StripeMerkleRoot(digest),
        _ => EvictionTarget::BlindedLocator(digest),
    }
}

/// Proves `SignedBadActorEvictionOrder::encode_signing_payload_stack` (backing
/// `canonical_sign_bytes` and `tally_and_verify_quorum_raw`) is strictly collision-free across
/// ALL symbolic mutations to `order_id`, `target` (IPv4, IPv6, Pubkey, MerkleRoot, BlindedLocator),
/// `reason` (content & length), `issued_at_ms`, `expires_at_ms`, and `issuer_pubkey`.
#[kani::proof]
fn proof_eviction_signing_payload_collision_free_across_all_fields() {
    let order_id: [u8; 32] = kani::any();
    let reason_a = symbolic_ascii_bytes_4();
    let issued_at_ms: u64 = kani::any();
    let expires_at_ms: u64 = kani::any();
    let issuer_pubkey: [u8; 32] = kani::any();

    let mut_order_id: [u8; 32] = kani::any();
    let mut_reason = symbolic_ascii_bytes_4();
    let mut_issued: u64 = kani::any();
    let mut_expires: u64 = kani::any();
    let mut_issuer: [u8; 32] = kani::any();

    // 1. Disjoint preimage lengths across V4 (131B), V6 (143B), and 32-byte digest targets (158B),
    //    plus variable `reason` length (`3B` vs `4B`), prevent all cross-length-class collisions:
    let t_v4 = EvictionTarget::IpAddress(IpAddr::V4(Ipv4Addr::from(kani::any::<[u8; 4]>())));
    let t_v6 = EvictionTarget::IpAddress(IpAddr::V6(Ipv6Addr::from(kani::any::<[u8; 16]>())));
    let t_32 = symbolic_eviction_target_32b();

    let (_, len_v4) = SignedBadActorEvictionOrder::encode_signing_payload_stack(
        &order_id,
        &t_v4,
        &reason_a,
        issued_at_ms,
        expires_at_ms,
        &issuer_pubkey,
    )
    .expect("fits in 256B");
    let (_, len_v6) = SignedBadActorEvictionOrder::encode_signing_payload_stack(
        &mut_order_id,
        &t_v6,
        &mut_reason,
        mut_issued,
        mut_expires,
        &mut_issuer,
    )
    .expect("fits in 256B");
    let (buf_32_a, len_32_a) = SignedBadActorEvictionOrder::encode_signing_payload_stack(
        &order_id,
        &t_32,
        &reason_a,
        issued_at_ms,
        expires_at_ms,
        &issuer_pubkey,
    )
    .expect("fits in 256B");
    assert!(len_v4 != len_v6 && len_v4 != len_32_a && len_v6 != len_32_a);

    let (_, short_len) = SignedBadActorEvictionOrder::encode_signing_payload_stack(
        &order_id,
        &t_32,
        b"abc",
        issued_at_ms,
        expires_at_ms,
        &issuer_pubkey,
    )
    .expect("fits in 256B");
    assert_ne!(short_len, len_32_a);

    // 2. Within every equal-length target class (V4, V6, and 32-byte {Pubkey, MerkleRoot, BlindedLocator}),
    //    preimage bytes are equal iff ALL header/target/reason/timestamp/issuer fields are identical:
    let mut_t32 = symbolic_eviction_target_32b();
    let (buf_32_b, len_32_b) = SignedBadActorEvictionOrder::encode_signing_payload_stack(
        &mut_order_id,
        &mut_t32,
        &mut_reason,
        mut_issued,
        mut_expires,
        &mut_issuer,
    )
    .expect("fits in 256B");
    assert_eq!(len_32_a, 158);
    assert_eq!(len_32_b, 158);
    assert_eq!(
        slice_eq_bounded::<158>(&buf_32_a[..158], &buf_32_b[..158]),
        mut_order_id == order_id
            && eviction_target_eq_fixed(&mut_t32, &t_32)
            && mut_reason == reason_a
            && mut_issued == issued_at_ms
            && mut_expires == expires_at_ms
            && mut_issuer == issuer_pubkey
    );
}

/// Proves on real `PrivacyPreservingEvictionEngine`:
/// 1. Dual-stack IPv4-mapped IPv6 (`::ffff:a.b.c.d`) normalizes to `IpAddr::V4(a.b.c.d)` and
///    produces identical domain-separated HMAC preimages across ALL `2^{32}` IPv4 addresses.
/// 2. `encode_ip_hmac_preimage` is strictly bijective modulo `normalize_ip` across ALL
///    `IpAddr::V4` (`2^{32}`) and `IpAddr::V6` (`2^{128}`).
/// 3. `encode_subnet_hmac_preimage_stack` and `encode_peer_id_hmac_preimage_stack` are bijective
///    on their inputs AND strictly disjoint across all 3 domain-separated HMAC vectors (`IP`,
///    `Subnet`, `PeerId`) — arbitrary cross-vector inputs can NEVER collide on HMAC preimages.
#[kani::proof]
fn proof_eviction_hmac_dual_stack_normalization_and_domain_isolation() {
    let v4_octets: [u8; 4] = kani::any();
    let v4 = IpAddr::V4(Ipv4Addr::from(v4_octets));
    let mapped_v6 = IpAddr::V6(Ipv4Addr::from(v4_octets).to_ipv6_mapped());

    assert_eq!(PrivacyPreservingEvictionEngine::normalize_ip(mapped_v6), v4);
    let (pre_v4, len_v4) = PrivacyPreservingEvictionEngine::encode_ip_hmac_preimage(v4);
    let (pre_mapped, len_mapped) =
        PrivacyPreservingEvictionEngine::encode_ip_hmac_preimage(mapped_v6);
    assert!(slice_eq_bounded::<48>(
        &pre_v4[..len_v4],
        &pre_mapped[..len_mapped]
    ));

    // Bijectivity of IP HMAC preimage modulo dual-stack normalization across ALL IPv4 and IPv6.
    let ip_a = if kani::any() {
        IpAddr::V4(Ipv4Addr::from(kani::any::<[u8; 4]>()))
    } else {
        IpAddr::V6(Ipv6Addr::from(kani::any::<[u8; 16]>()))
    };
    let ip_b = if kani::any() {
        IpAddr::V4(Ipv4Addr::from(kani::any::<[u8; 4]>()))
    } else {
        IpAddr::V6(Ipv6Addr::from(kani::any::<[u8; 16]>()))
    };
    let (pre_a, len_a) = PrivacyPreservingEvictionEngine::encode_ip_hmac_preimage(ip_a);
    let (pre_b, len_b) = PrivacyPreservingEvictionEngine::encode_ip_hmac_preimage(ip_b);
    assert_eq!(
        slice_eq_bounded::<48>(&pre_a[..len_a], &pre_b[..len_b]),
        PrivacyPreservingEvictionEngine::normalize_ip(ip_a)
            == PrivacyPreservingEvictionEngine::normalize_ip(ip_b)
    );

    // Bijectivity & strict cross-vector domain isolation across IP, Subnet, and PeerId preimages
    // for arbitrary symbolic payloads.
    let payload_x: [u8; 8] = kani::any();
    let payload_y: [u8; 8] = kani::any();
    let len_x: usize = kani::any();
    let len_y: usize = kani::any();
    kani::assume(len_x <= 8 && len_y <= 8);

    let (sub_x, sub_len_x) =
        PrivacyPreservingEvictionEngine::encode_subnet_hmac_preimage_stack(&payload_x[..len_x])
            .expect("<= 64 bytes");
    let (sub_y, sub_len_y) =
        PrivacyPreservingEvictionEngine::encode_subnet_hmac_preimage_stack(&payload_y[..len_y])
            .expect("<= 64 bytes");
    assert_eq!(
        slice_eq_bounded::<96>(&sub_x[..sub_len_x], &sub_y[..sub_len_y]),
        slice_eq_bounded::<8>(&payload_x[..len_x], &payload_y[..len_y])
    );

    let (pid_x, pid_len_x) =
        PrivacyPreservingEvictionEngine::encode_peer_id_hmac_preimage_stack(&payload_x[..len_x])
            .expect("<= 64 bytes");
    let (pid_y, pid_len_y) =
        PrivacyPreservingEvictionEngine::encode_peer_id_hmac_preimage_stack(&payload_y[..len_y])
            .expect("<= 64 bytes");
    assert_eq!(
        slice_eq_bounded::<96>(&pid_x[..pid_len_x], &pid_y[..pid_len_y]),
        slice_eq_bounded::<8>(&payload_x[..len_x], &payload_y[..len_y])
    );

    // Cross-domain preimage collision is mathematically impossible for ANY ip_a, payload_x, payload_y:
    assert!(!slice_eq_bounded::<96>(
        &pre_a[..len_a],
        &sub_x[..sub_len_x]
    ));
    assert!(!slice_eq_bounded::<96>(
        &pre_a[..len_a],
        &pid_x[..pid_len_x]
    ));
    assert!(!slice_eq_bounded::<96>(
        &sub_x[..sub_len_x],
        &pid_y[..pid_len_y]
    ));
}

// ============================================================================
// (2b) `admin_rpc` Wire Framing & Replay Window Safety (`src/admin_rpc.rs`)
// ============================================================================

/// Proves `validate_admin_rpc_frame_header` never panics, integer-overflows, or allows unbounded
/// pre-allocation for arbitrary symbolic `[u8; 4]` big-endian headers and arbitrary `max_len`.
#[kani::proof]
fn proof_admin_rpc_wire_frame_header_no_panic_or_unbounded_alloc() {
    let len_buf: [u8; 4] = kani::any();
    let max_len: usize = kani::any();

    let declared_u32 = u32::from_be_bytes(len_buf);
    let hard_ceiling = MAX_ADMIN_RPC_FRAME_BYTES.saturating_add(64);
    let effective_max = max_len.min(hard_ceiling);

    match validate_admin_rpc_frame_header(len_buf, max_len) {
        Ok((frame_len, initial_cap)) => {
            assert_eq!(frame_len as u64, declared_u32 as u64);
            assert!(frame_len <= max_len);
            assert!(frame_len <= hard_ceiling);
            assert!(initial_cap <= frame_len);
            assert!(initial_cap <= MAX_ADMIN_RPC_INITIAL_ALLOC_BYTES);
        }
        Err(_) => {
            assert!((declared_u32 as u64) > (effective_max as u64));
        }
    }
}

/// Proves `validate_admin_rpc_slice_replay_and_auth_meta` (`src/admin_rpc.rs`):
/// 1. Always rejects `[0u8; 32]` zero public keys (even if explicitly present in the allowlist).
/// 2. Always rejects unauthorized operator public keys.
/// 3. Always rejects mismatched / replayed 32-byte `challenge_nonce` values.
/// 4. Strictly rejects stale (`now_ms - req_ts_ms > MAX_ADMIN_RPC_CLOCK_SKEW_MS`) and future-skewed
///    (`req_ts_ms - now_ms > MAX_ADMIN_RPC_CLOCK_SKEW_MS`) timestamps across the full `0..=u64::MAX`
///    clock domain without arithmetic overflow or underflow.
#[kani::proof]
fn proof_admin_rpc_replay_window_challenge_and_zero_key_rejection() {
    let pk_a: [u8; 32] = kani::any();
    let pk_b: [u8; 32] = kani::any();
    let caller_pk: [u8; 32] = kani::any();
    let expected_nonce: [u8; 32] = kani::any();
    let provided_nonce: [u8; 32] = kani::any();
    let now_ms: u64 = kani::any();
    let req_ts_ms: u64 = kani::any();

    // Include `[0u8; 32]` and duplicate `pk_a` directly in the slice to prove zero-key rejection.
    let allowlist_slice: [[u8; 32]; 4] = [[0u8; 32], pk_a, pk_b, pk_a];
    assert!(validate_admin_rpc_slice_replay_and_auth_meta(
        &allowlist_slice,
        &[0u8; 32],
        &expected_nonce,
        &expected_nonce,
        now_ms,
        now_ms,
    )
    .is_err());

    let res = validate_admin_rpc_slice_replay_and_auth_meta(
        &allowlist_slice,
        &caller_pk,
        &expected_nonce,
        &provided_nonce,
        now_ms,
        req_ts_ms,
    );

    let authorized = caller_pk != [0u8; 32] && (caller_pk == pk_a || caller_pk == pk_b);
    let nonce_fresh = provided_nonce == expected_nonce;
    let delta_ms = if now_ms >= req_ts_ms {
        (now_ms as u128) - (req_ts_ms as u128)
    } else {
        (req_ts_ms as u128) - (now_ms as u128)
    };
    let within_skew_window = delta_ms <= (MAX_ADMIN_RPC_CLOCK_SKEW_MS as u128);

    assert_eq!(res.is_ok(), authorized && nonce_fresh && within_skew_window);
}

// ============================================================================
// (2c) Streaming Stripe & Reed-Solomon Boundary Safety (`config.rs`/`reed_solomon.rs`)
// ============================================================================

/// Proves for ALL symbolic `file_size: u64` (`0..=MAX_FILE_BYTES`, i.e., `0..=u64::MAX`),
/// arbitrary `raw_stripe_size: usize`, and all three production `HardwareProfile`s (`RouterSoc`
/// `1 MiB`, `HomelabNas` `4 MiB`, `Desktop` `16 MiB`) that streaming stripe decomposition never
/// overflows, never divides by zero, emits `stripe_count >= 1`, and conserves exact plaintext
/// byte length in `u128`.
#[kani::proof]
fn proof_streaming_stripe_layout_all_u64_file_sizes_and_profiles() {
    let file_size: u64 = kani::any();
    assert!(file_size <= MAX_FILE_BYTES);

    let profiles = [
        (HardwareProfile::RouterSoc, ROUTER_SOC_STRIPE_SIZE_BYTES),
        (
            HardwareProfile::HomelabNas,
            crate::config::HOMELAB_NAS_STRIPE_SIZE_BYTES,
        ),
        (HardwareProfile::Desktop, DEFAULT_STRIPE_SIZE_BYTES),
    ];

    for (profile, expected_stripe_cap) in profiles {
        let layout = profile.compute_streaming_stripe_layout(file_size);
        assert_eq!(layout.stripe_size_bytes, expected_stripe_cap);
        assert!(layout.stripe_count >= 1);
        assert_eq!(
            layout.max_stripe_ciphertext_bytes,
            layout.max_stripe_plaintext_bytes + AES_GCM_TAG_OVERHEAD_BYTES
        );

        if file_size == 0 {
            assert_eq!(layout.stripe_count, 1);
            assert_eq!(layout.last_stripe_plaintext_bytes, 0);
            assert_eq!(layout.max_stripe_plaintext_bytes, 0);
            assert_eq!(
                layout.max_stripe_ciphertext_bytes,
                AES_GCM_TAG_OVERHEAD_BYTES
            );
        } else {
            assert!(layout.last_stripe_plaintext_bytes >= 1);
            assert!(layout.last_stripe_plaintext_bytes <= expected_stripe_cap);
            assert!(layout.max_stripe_plaintext_bytes <= expected_stripe_cap);
            let total_reconstructed_bytes = ((layout.stripe_count as u128 - 1)
                * (layout.stripe_size_bytes as u128))
                + (layout.last_stripe_plaintext_bytes as u128);
            assert_eq!(total_reconstructed_bytes, file_size as u128);
        }
    }

    // Also verify arbitrary caller-supplied `raw_stripe_size` clamping across `0..=usize::MAX`.
    let raw_stripe: usize = kani::any();
    let clamped = compute_stripe_layout_for_size(file_size, raw_stripe);
    assert!(clamped.stripe_size_bytes >= MIN_STRIPE_SIZE_BYTES);
    assert!(clamped.stripe_size_bytes <= DEFAULT_STRIPE_SIZE_BYTES);
}

/// Proves across ALL symbolic `file_size` (`0..=MAX_FILE_BYTES`), all 4 `ErasureTier`s
/// (`Consumer` 10-of-20, `Mixed` 16-of-24, `Homelab` 16-of-20, `Relay` 20-of-24), and both
/// `HardwareProfile::RouterSoc` (`1 MiB`) and `HardwareProfile::Desktop` (`16 MiB`) that:
/// 1. `compute_reed_solomon_shard_len` rejects `k_data == 0` without division-by-zero and sizes
///    shards tightly (`k_data * shard_len >= ciphertext_len` and `shard_len >= 1`).
/// 2. `HardwareProfile::RouterSoc` peak concurrent stripe RAM (`plaintext + ciphertext + N * shard`)
///    strictly stays well below `ROUTER_SOC_MAX_STRIPE_MEMORY_BYTES` (`< 32 MiB`, in fact `< 5 MiB`).
#[kani::proof]
fn proof_router_soc_and_desktop_reed_solomon_memory_ceiling() {
    let any_ct: usize = kani::any();
    assert!(compute_reed_solomon_shard_len(any_ct, 0).is_err());

    let tier_idx: u8 = kani::any();
    kani::assume(tier_idx < 4);
    let tier = match tier_idx {
        0 => ErasureTier::Consumer,
        1 => ErasureTier::Mixed,
        2 => ErasureTier::Homelab,
        _ => ErasureTier::Relay,
    };
    let (k_data, m_parity, n_total) = tier.params();
    assert_eq!(k_data + m_parity, n_total);
    assert!(k_data >= 10 && m_parity >= 4);

    let file_size: u64 = kani::any();

    // 1. RouterSoC (`1 MiB` stripes): prove `< 32 MiB` strict ceiling for ALL file sizes & tiers.
    let soc_layout = HardwareProfile::RouterSoc.compute_streaming_stripe_layout(file_size);
    let (soc_shard_len, soc_peak_ram) =
        compute_stripe_memory_footprint_bytes(soc_layout.max_stripe_plaintext_bytes, tier)
            .expect("RouterSoC stripe footprint must never overflow");
    assert!(soc_shard_len >= 1);
    assert!(k_data * soc_shard_len >= soc_layout.max_stripe_ciphertext_bytes);
    assert!((k_data * (soc_shard_len - 1)) < soc_layout.max_stripe_ciphertext_bytes);
    assert!(soc_peak_ram < ROUTER_SOC_MAX_STRIPE_MEMORY_BYTES);
    assert!(soc_peak_ram <= 5 * 1024 * 1024);

    // 2. Desktop (`16 MiB` stripes): prove overflow-freeness and exact shard bounds for ALL sizes.
    let desktop_layout = HardwareProfile::Desktop.compute_streaming_stripe_layout(file_size);
    let (desk_shard_len, desk_peak_ram) =
        compute_stripe_memory_footprint_bytes(desktop_layout.max_stripe_plaintext_bytes, tier)
            .expect("Desktop stripe footprint must never overflow");
    assert!(desk_shard_len >= 1);
    assert!(k_data * desk_shard_len >= desktop_layout.max_stripe_ciphertext_bytes);
    assert!((k_data * (desk_shard_len - 1)) < desktop_layout.max_stripe_ciphertext_bytes);
    assert!(desk_peak_ram <= 65 * 1024 * 1024);
}

// ============================================================================
// (2d) CapabilityMacaroon Attenuation & Zero-Copy IPC / VFS Window Proofs
// ============================================================================

fn symbolic_caveat() -> Caveat {
    let kind: u8 = kani::any();
    kani::assume(kind < 5);
    match kind {
        0 => Caveat::AllowedManifest(kani::any()),
        1 => Caveat::ByteRange {
            offset: kani::any(),
            length: kani::any(),
        },
        2 => Caveat::ExpiresAtUnixMs(kani::any()),
        3 => Caveat::ReadOnly,
        _ => Caveat::AllowedPeerUid(kani::any()),
    }
}

/// Proves on real `CapabilityMacaroon` (`mint_slice_tag_with`, `verify_caveat_slice_in_ram_with`,
/// `Caveat::encode_stack`, `Caveat::allows`, `ct_eq_32`):
/// 1. `[0u8; 32]` zero root keys are strictly rejected in both `mint_slice_tag_with` and
///    `verify_caveat_slice_in_ram_with`.
/// 2. `Caveat::encode_stack` is collision-free (injective) across all 4 caveat variants & `u64` bounds.
/// 3. Symbolic caveat attenuation (`[]` -> `[c_a]` -> `[c_a, c_b]`) is strictly monotonic across
///    ALL `0..=u64::MAX` offsets/lengths/epochs (`child_ok ==> parent_ok`), and any non-zero bit
///    flip to `tag` is rejected in constant time (`ct_eq_32`).
#[kani::proof]
fn proof_macaroon_caveat_attenuation_monotonic_and_zero_key_rejected() {
    let nonce_id: [u8; 32] = kani::any();
    let issuer_fp: [u8; 32] = kani::any();

    // 1. Prove Caveat::encode_stack injectivity across ALL variants & symbolic u64 values.
    let c_a = symbolic_caveat();
    let c_b = symbolic_caveat();
    let (enc_a, len_a) = c_a.encode_stack();
    let (enc_b, len_b) = c_b.encode_stack();
    assert_eq!(
        slice_eq_bounded::<33>(&enc_a[..len_a], &enc_b[..len_b]),
        c_a == c_b
    );

    // 2. Full symbolic state-machine & caveat-algebra monotonicity via `mint_slice_tag_with` and
    //    `verify_caveat_slice_in_ram_with` (zero heap Vec iterators, zero 64-round Sha256 CNF blowup).
    let root_key: [u8; 32] = kani::any();
    kani::assume(root_key != [0u8; 32]);

    let ideal_root_prf = |rk: &[u8; 32], nid: &[u8; 32], ifp: &[u8; 32]| -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = rk[i] ^ nid[i].rotate_left(1) ^ ifp[i].rotate_left(3);
            i += 1;
        }
        out
    };
    let ideal_chain_prf = |prev: &[u8; 32], cav: &Caveat| -> [u8; 32] {
        let (enc, clen) = cav.encode_stack();
        let mut out = *prev;
        out[0] ^= clen as u8;
        let mut i = 0;
        while i < 32 {
            out[i] = out[i].wrapping_add(enc[i + 1]).rotate_left(1);
            i += 1;
        }
        out
    };

    let empty_caveats: [Caveat; 0] = [];
    let parent_caveats = [c_a.clone()];
    let child_caveats = [c_a.clone(), c_b.clone()];

    // Zero root key unconditionally rejected at mint time:
    assert_eq!(
        CapabilityMacaroon::mint_slice_tag_with(
            &[0u8; 32],
            &nonce_id,
            &issuer_fp,
            &empty_caveats,
            ideal_root_prf,
            ideal_chain_prf,
        ),
        Err(CapabilityError::InvalidRootKey)
    );

    let root_tag = CapabilityMacaroon::mint_slice_tag_with(
        &root_key,
        &nonce_id,
        &issuer_fp,
        &empty_caveats,
        ideal_root_prf,
        ideal_chain_prf,
    )
    .expect("non-zero root key mints root tag");
    let parent_tag = CapabilityMacaroon::mint_slice_tag_with(
        &root_key,
        &nonce_id,
        &issuer_fp,
        &parent_caveats,
        ideal_root_prf,
        ideal_chain_prf,
    )
    .expect("parent tag");
    let child_tag = ideal_chain_prf(&parent_tag, &c_b);

    let ctx = AccessRequestContext {
        manifest_root: kani::any(),
        offset: kani::any(),
        length: kani::any(),
        now_unix_ms: kani::any(),
        is_write: kani::any(),
        peer_uid: if kani::any() { Some(kani::any()) } else { None },
    };

    // Zero root key unconditionally rejected at verify time:
    assert_eq!(
        CapabilityMacaroon::verify_caveat_slice_in_ram_with(
            &[0u8; 32],
            MacaroonSliceView {
                nonce_id: &nonce_id,
                issuer_fingerprint: &issuer_fp,
                caveats: &child_caveats,
                tag: &child_tag,
            },
            &ctx,
            ideal_root_prf,
            ideal_chain_prf,
        ),
        Err(CapabilityError::InvalidRootKey)
    );

    assert!(CapabilityMacaroon::verify_caveat_slice_in_ram_with(
        &root_key,
        MacaroonSliceView {
            nonce_id: &nonce_id,
            issuer_fingerprint: &issuer_fp,
            caveats: &empty_caveats,
            tag: &root_tag,
        },
        &ctx,
        ideal_root_prf,
        ideal_chain_prf,
    )
    .is_ok());

    let parent_ok = CapabilityMacaroon::verify_caveat_slice_in_ram_with(
        &root_key,
        MacaroonSliceView {
            nonce_id: &nonce_id,
            issuer_fingerprint: &issuer_fp,
            caveats: &parent_caveats,
            tag: &parent_tag,
        },
        &ctx,
        ideal_root_prf,
        ideal_chain_prf,
    )
    .is_ok();
    assert_eq!(parent_ok, c_a.allows(&ctx));

    let child_ok = CapabilityMacaroon::verify_caveat_slice_in_ram_with(
        &root_key,
        MacaroonSliceView {
            nonce_id: &nonce_id,
            issuer_fingerprint: &issuer_fp,
            caveats: &child_caveats,
            tag: &child_tag,
        },
        &ctx,
        ideal_root_prf,
        ideal_chain_prf,
    )
    .is_ok();
    if child_ok {
        assert!(parent_ok);
        assert!(c_a.allows(&ctx) && c_b.allows(&ctx));
    }
    assert_eq!(child_ok, parent_ok && c_b.allows(&ctx));

    // Symbolic bit-flip unforgeability on tag:
    let flip_idx: usize = kani::any();
    kani::assume(flip_idx < 32);
    let flip_mask: u8 = kani::any();
    kani::assume(flip_mask != 0);
    let mut forged_tag = child_tag;
    forged_tag[flip_idx] ^= flip_mask;
    assert_eq!(
        CapabilityMacaroon::verify_caveat_slice_in_ram_with(
            &root_key,
            MacaroonSliceView {
                nonce_id: &nonce_id,
                issuer_fingerprint: &issuer_fp,
                caveats: &child_caveats,
                tag: &forged_tag,
            },
            &ctx,
            ideal_root_prf,
            ideal_chain_prf,
        ),
        Err(CapabilityError::InvalidMacaroonTag)
    );
}

/// Proves `validate_ipc_frame_header` (`src/gateway/ipc.rs`) never panics, integer-overflows, or
/// permits unbounded pre-allocation across arbitrary `[u8; 4]` IPC frame headers and `max_len`.
#[kani::proof]
fn proof_gateway_ipc_frame_header_bounds() {
    let hdr: [u8; 4] = kani::any();
    let max_len: usize = kani::any();
    let raw_u32 = u32::from_be_bytes(hdr);
    let ceiling = max_len.min(MAX_IPC_FRAME_BYTES);
    match validate_ipc_frame_header(hdr, max_len) {
        Ok((frame_len, init_cap)) => {
            assert!(frame_len >= 1);
            assert_eq!(frame_len as u64, raw_u32 as u64);
            assert!(frame_len <= ceiling);
            assert!(init_cap <= frame_len);
            assert!(init_cap <= MAX_IPC_INITIAL_ALLOC_BYTES);
        }
        Err(_) => {
            assert!(raw_u32 == 0 || (raw_u32 as u64) > (ceiling as u64));
        }
    }
}

/// Proves `compute_vfs_block_window` (`src/vfs.rs`) never panics, divides by zero, or overflows
/// across `block_size == 0` and all power-of-two VFS block sizes (`1 B ..= 1 GiB`, including
/// `DEFAULT_VFS_BLOCK_BYTES = 1 MiB`) over the full `0..=u64::MAX` domain of `(file_size, offset, length)`.
#[cfg(feature = "vfs")]
#[kani::proof]
fn proof_vfs_block_window_power_of_two_and_zero_bounds() {
    let file_size: u64 = kani::any();
    let offset: u64 = kani::any();
    let length: u64 = kani::any();

    // 1. Zero block_size always returns `None` without division by zero.
    assert_eq!(compute_vfs_block_window(file_size, offset, length, 0), None);

    // 2. All power-of-two block sizes `1 << shift` (`1 B` up to `1 GiB`, covering `4 KiB`, `64 KiB`,
    //    `1 MiB` RouterSoC/VFS default, `4 MiB` HomelabNas, and `16 MiB` Desktop).
    let shift: u32 = kani::any();
    kani::assume(shift <= 30);
    let block_size: usize = 1usize << shift;

    match compute_vfs_block_window(file_size, offset, length, block_size) {
        None => {
            assert!(length == 0 || offset >= file_size);
        }
        Some((end, first_blk, last_blk)) => {
            assert!(length > 0 && offset < file_size);
            assert!(end > offset && end <= file_size);
            assert!(first_blk <= last_blk);
            assert_eq!(first_blk, offset >> shift);
            assert_eq!(last_blk, (end - 1) >> shift);
            assert!((first_blk as u128) << shift <= (offset as u128));
            assert!(((last_blk as u128) + 1) << shift >= (end as u128));
        }
    }
}

/// Proves `PinnedRingBudget<SLOTS>` (`src/gateway/engine.rs`) strictly preserves:
/// 1. `ring.used_bytes() <= ring.max_bytes()` and `ring.len() <= SLOTS` after every admission.
/// 2. Zero-slot (`SLOTS == 0`) or oversized (`size_bytes > max_bytes`) admissions return `false`
///    without mutating `used_bytes` or `len` or firing spurious evictions.
/// 3. Exact byte conservation in `u128`: `used_bytes + total_evicted_bytes == total_admitted_bytes`
///    across an arbitrary symbolic multi-step admission & FIFO eviction sequence.
#[kani::proof]
#[kani::unwind(5)]
fn proof_pinned_ring_capacity_invariant() {
    let max_bytes: u64 = kani::any();

    // Zero-slot ring unconditionally rejects without mutation.
    let mut zero_ring = PinnedRingBudget::<0>::new(max_bytes);
    let mut zero_evicted = false;
    assert!(!zero_ring.admit([0xAA; 32], 0, |_, _| zero_evicted = true));
    assert!(!zero_evicted && zero_ring.is_empty() && zero_ring.used_bytes() == 0);

    let mut ring = PinnedRingBudget::<3>::new(max_bytes);
    let mut admitted_sum: u128 = 0;
    let mut evicted_sum: u128 = 0;

    let mut step = 0usize;
    while step < 4 {
        let root: [u8; 32] = [step as u8; 32];
        let sz: u64 = kani::any();
        let prev_used = ring.used_bytes();
        let prev_len = ring.len();

        let mut step_evicted: u128 = 0;
        let accepted = ring.admit(root, sz, |_ev_root, ev_sz| {
            step_evicted += ev_sz as u128;
        });

        if sz > max_bytes {
            assert!(!accepted);
            assert_eq!(step_evicted, 0);
            assert_eq!(ring.used_bytes(), prev_used);
            assert_eq!(ring.len(), prev_len);
        } else {
            assert!(accepted);
            admitted_sum += sz as u128;
            evicted_sum += step_evicted;
            assert!(ring.len() >= 1 && ring.len() <= 3);
            assert!(ring.used_bytes() >= sz && ring.used_bytes() <= ring.max_bytes());
        }

        assert_eq!(ring.max_bytes(), max_bytes);
        assert!(ring.used_bytes() <= max_bytes);
        assert!(ring.len() <= 3);
        assert_eq!((ring.used_bytes() as u128) + evicted_sum, admitted_sum);
        step += 1;
    }
}

/// Proves the `0`-`unsafe` Linux FUSE ABI `7.31` byte-slice parsers `parse_fuse_in_header` and
/// `parse_fuse_read_in` (`src/vfs.rs`) never panic, out-of-bounds index, or misparse across
/// arbitrary symbolic byte buffers of any length `0..=96`, and satisfy exact bijective round-trip
/// fidelity with `FuseInHeader::to_ne_bytes` and `FuseReadIn::to_ne_bytes`.
#[cfg(feature = "vfs")]
#[kani::proof]
fn proof_fuse_header_parser_no_panic() {
    let buf: [u8; 96] = kani::any();
    let slice_len: usize = kani::any();
    kani::assume(slice_len <= buf.len());
    let slice = &buf[..slice_len];

    match parse_fuse_in_header(slice) {
        None => {
            if slice_len >= FUSE_IN_HEADER_BYTES {
                let declared =
                    u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
                assert!(declared < FUSE_IN_HEADER_BYTES || declared > slice_len);
            }
        }
        Some(hdr) => {
            assert!(slice_len >= FUSE_IN_HEADER_BYTES);
            assert!((hdr.len as usize) >= FUSE_IN_HEADER_BYTES);
            assert!((hdr.len as usize) <= slice_len);
            let encoded = hdr.to_ne_bytes();
            assert!(slice_eq_bounded::<FUSE_IN_HEADER_BYTES>(
                &encoded,
                &slice[..FUSE_IN_HEADER_BYTES]
            ));
        }
    }

    match parse_fuse_read_in(slice) {
        None => {
            assert!(slice_len < FUSE_READ_IN_BYTES);
        }
        Some(rd) => {
            assert!(slice_len >= FUSE_READ_IN_BYTES);
            let encoded = rd.to_ne_bytes();
            assert!(slice_eq_bounded::<FUSE_READ_IN_BYTES>(
                &encoded,
                &slice[..FUSE_READ_IN_BYTES]
            ));
        }
    }

    // Also prove exact round-trip reconstruction for any valid symbolic FuseInHeader & FuseReadIn:
    let sym_hdr = FuseInHeader {
        len: FUSE_IN_HEADER_BYTES as u32,
        opcode: kani::any(),
        unique: kani::any(),
        nodeid: kani::any(),
        uid: kani::any(),
        gid: kani::any(),
        pid: kani::any(),
        padding: kani::any(),
    };
    assert_eq!(parse_fuse_in_header(&sym_hdr.to_ne_bytes()), Some(sym_hdr));

    let sym_rd = FuseReadIn {
        fh: kani::any(),
        offset: kani::any(),
        size: kani::any(),
        read_flags: kani::any(),
        lock_owner: kani::any(),
        flags: kani::any(),
        padding: kani::any(),
    };
    assert_eq!(parse_fuse_read_in(&sym_rd.to_ne_bytes()), Some(sym_rd));
}

/// Proves `sanitize_sync_relative_path_into` / `sanitize_sync_relative_path` (`src/sync.rs`,
/// `ADR-33`) never panics across arbitrary symbolic `[u8; 10]` inputs of any length `0..=10`
/// (`0` heap `Vec` allocations) and strictly rejects empty outputs, NUL bytes, leading/trailing
/// `/` or `\`, Windows drive colons (`:`), duplicate `//`, and `.` or `..` path-traversal
/// segments, while preserving exact normalization idempotence on every accepted path.
#[kani::proof]
#[kani::unwind(12)]
fn proof_sanitize_sync_relative_path_no_traversal() {
    let raw_bytes: [u8; 10] = kani::any();
    let slice_len: usize = kani::any();
    kani::assume(slice_len <= raw_bytes.len());

    let mut out_buf = [0u8; 10];
    let result =
        sanitize_sync_relative_path_into(&raw_bytes[..slice_len], &mut out_buf[..slice_len]);

    if slice_len == 0 || raw_bytes[0] == b'/' || raw_bytes[0] == b'\\' {
        assert!(result.is_none());
    }

    if let Some(norm_len) = result {
        assert!(norm_len >= 1 && norm_len <= slice_len);
        let nb = &out_buf[..norm_len];
        assert!(nb[0] != b'/' && nb[0] != b'\\');
        assert!(nb[norm_len - 1] != b'/' && nb[norm_len - 1] != b'\\');

        let mut p = 0usize;
        let mut seg_len = 0usize;
        let mut seg_dots = 0usize;
        while p < 10 {
            if p < norm_len {
                let c = nb[p];
                assert!(c != 0 && c != b'\\' && c != b':');
                if c == b'/' {
                    assert!(seg_len > 0);
                    assert!(!(seg_len == 1 && seg_dots == 1));
                    assert!(!(seg_len == 2 && seg_dots == 2));
                    seg_len = 0;
                    seg_dots = 0;
                } else {
                    if c == b'.' {
                        seg_dots += 1;
                    }
                    seg_len += 1;
                }
            }
            p += 1;
        }
        assert!(seg_len > 0);
        assert!(!(seg_len == 1 && seg_dots == 1));
        assert!(!(seg_len == 2 && seg_dots == 2));

        // Prove normalization idempotence (`f(f(x)) == f(x)`):
        let mut idemp_buf = [0u8; 10];
        let idemp_len = sanitize_sync_relative_path_into(nb, &mut idemp_buf[..norm_len])
            .expect("normalized relative path must remain valid");
        assert_eq!(idemp_len, norm_len);
        assert!(slice_eq_bounded::<10>(&idemp_buf[..idemp_len], nb));
    }

    // Concrete wrapper boundary checks on `sanitize_sync_relative_path`:
    assert!(sanitize_sync_relative_path("").is_none());
    assert!(sanitize_sync_relative_path("/etc/passwd").is_none());
    assert!(sanitize_sync_relative_path("../escape").is_none());
    assert!(sanitize_sync_relative_path("C:\\win").is_none());
}

/// F-38 (L-40): a syndication repair grant is accepted only when absent or owned by exactly the
/// authenticated sender's 32-byte key; any other owner, or an unknown sender, is refused.
#[kani::proof]
#[kani::unwind(34)]
fn proof_syndication_grant_owned_by_sender() {
    let owner: [u8; 32] = kani::any();
    let sender: [u8; 32] = kani::any();
    let has_grant: bool = kani::any();
    let sender_known: bool = kani::any();
    let grant = has_grant.then_some(owner);
    let sender_opt = sender_known.then_some(sender);
    let decision = crate::network::wire_handler::syndication_grant_decision(grant, sender_opt);
    kani::cover!(decision.is_err(), "grant not owned by sender");
    let expected_ok = !has_grant || (sender_known && owner == sender);
    // Only the outcome is checked: comparing the &str reason code makes CBMC unwind memcmp
    // without a bound; the code itself is checked by the claim's wire test.
    assert_eq!(decision.is_ok(), expected_ok);
}
