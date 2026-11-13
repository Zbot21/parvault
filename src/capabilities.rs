//! Zero-Knowledge Macaroon Capability Tokens & Post-Quantum Gateway Identity Statements
//! (`parvault::capabilities`).
//!
//! Provides two core primitives shared between `parvault` storage vaults, `parvault-fuse`, and
//! `parvault-auth-broker` (`parvault-suite`):
//! 1. [`CapabilityMacaroon`]: Chained `HMAC-SHA256` bearer capabilities supporting public,
//!    monotonically attenuating [`Caveat`] chains (`AllowedManifest`, `ByteRange`,
//!    `ExpiresAtUnixMs`, `ReadOnly`) verified purely in RAM in `< 1 ms` (`~2 µs`, zero heap
//!    allocations and zero disk I/O) without exposing master keys.
//! 2. [`GatewayIdentityStatement`]: Composite Post-Quantum (`Ed25519 + NIST FIPS 204 ML-DSA-65`)
//!    master gateway identity statement binding local Noise static keys (`Noise_IKpsk2_25519_...`)
//!    and transport PeerIds to the household/CPE root of trust.
//!
//! Formal model: `specs/ParVaultGatewayPluginBus.tla` (guards `macaroon-uid-caveat`).

use crate::crypto::{CryptoError, HybridPqPublicKey, HybridPqSignature, HybridPqSigningKeypair};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Maximum chained caveats permitted on a single [`CapabilityMacaroon`] to guarantee `< 1 ms`
/// constant-bounded RAM verification on low-power ARM64 CPE routers.
pub const MAX_MACAROON_CAVEATS: usize = 32;

/// Maximum byte length of `GatewayIdentityStatement::gateway_id`.
pub const MAX_GATEWAY_ID_BYTES: usize = 128;

/// Domain separator for deriving the root Macaroon tag from `K_macaroon_root`.
pub const MACAROON_ROOT_DOMAIN: &[u8] = b"parvault-macaroon-root-v1:";

/// Domain separator for chaining each subsequent [`Caveat`] tag.
pub const MACAROON_CAVEAT_DOMAIN: &[u8] = b"parvault-macaroon-caveat-v1:";

/// Domain separator for composite `Ed25519 + ML-DSA-65` [`GatewayIdentityStatement`] signatures.
pub const GATEWAY_STATEMENT_DOMAIN: &[u8] = b"parvault-gateway-identity-statement-v1:";

/// Longest lifetime of a [`GatewayIdentityStatement`] (`expires - issued`): 30 days (F-17).
pub const MAX_GATEWAY_STATEMENT_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Largest clock skew allowed for a statement's issue time (5 minutes, as eviction orders).
pub const GATEWAY_STATEMENT_FUTURE_SKEW_MS: u64 = 5 * 60 * 1000;

/// F-17: a gateway statement counts only if its authority is the one the verifier pinned and its
/// expiry is bounded (`issued < expires <= issued + 30 days`) and not yet passed.
pub fn gateway_statement_decision(
    authority_pinned: bool,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<(), &'static str> {
    if !authority_pinned {
        return Err("reject.gateway_authority_unpinned");
    }
    if expires_at_unix_ms <= issued_at_unix_ms
        || expires_at_unix_ms - issued_at_unix_ms > MAX_GATEWAY_STATEMENT_LIFETIME_MS
    {
        return Err("reject.gateway_statement_unbounded");
    }
    // QA 2c D4: issued at most 5 minutes in the future (the eviction-order clock skew).
    if issued_at_unix_ms > now_unix_ms.saturating_add(GATEWAY_STATEMENT_FUTURE_SKEW_MS) {
        return Err("reject.gateway_statement_future");
    }
    if now_unix_ms > expires_at_unix_ms {
        return Err("reject.gateway_statement_expired");
    }
    Ok(())
}

/// Compact shareable ASCII prefix for `CapabilityMacaroon` tokens (`ADR-28` / `ADR-32`).
pub const COMPACT_MACAROON_PREFIX: &str = "PARVAULT-MAC-V1:";

/// Binary wire format version byte inside `PARVAULT-MAC-V1:<hex>` compact tokens.
pub const COMPACT_MACAROON_VERSION: u8 = 0x01;

/// Minimum binary payload size of a compact `CapabilityMacaroon` (`0` caveats: `1 + 32 + 32 + 1 + 32`).
pub const MIN_COMPACT_MACAROON_BYTES: usize = 98;

/// Hard upper bound on binary payload bytes for a compact `CapabilityMacaroon`
/// (`32` caveats × `33` max bytes + `98` fixed header/tag bytes = `1,154` bytes).
pub const MAX_COMPACT_MACAROON_BYTES: usize =
    MIN_COMPACT_MACAROON_BYTES + (MAX_MACAROON_CAVEATS * 33);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("all-zero root Macaroon key is forbidden")]
    InvalidRootKey,
    #[error("Macaroon caveat chain length ({0}) exceeds MAX_MACAROON_CAVEATS")]
    TooManyCaveats(usize),
    #[error("Macaroon HMAC-SHA256 authentication tag verification failed")]
    InvalidMacaroonTag,
    #[error("request rejected by Macaroon caveat policy")]
    CaveatRejected,
    #[error("malformed compact Macaroon token encoding")]
    MalformedCompactToken,
}

/// First-party zero-knowledge attenuation caveat chained onto a [`CapabilityMacaroon`].
#[derive(Debug, Clone, Copy, Eq, Serialize, Deserialize)]
pub enum Caveat {
    /// Restricts access exclusively to the specified 32-byte manifest Merkle root.
    AllowedManifest([u8; 32]),
    /// Restricts access exclusively to sub-ranges contained within `[offset .. offset + length]`.
    ByteRange { offset: u64, length: u64 },
    /// Restricts token validity to `now_unix_ms <= expires_at_unix_ms`.
    ExpiresAtUnixMs(u64),
    /// Prohibits write/mutation operations (`ctx.is_write` must be `false`).
    ReadOnly,
    /// Restricts token presentation to a specific Linux `SO_PEERCRED` peer effective UID.
    AllowedPeerUid(u32),
}

impl PartialEq for Caveat {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AllowedManifest(a), Self::AllowedManifest(b)) => ct_eq_32(a, b),
            (
                Self::ByteRange {
                    offset: o1,
                    length: l1,
                },
                Self::ByteRange {
                    offset: o2,
                    length: l2,
                },
            ) => o1 == o2 && l1 == l2,
            (Self::ExpiresAtUnixMs(a), Self::ExpiresAtUnixMs(b)) => a == b,
            (Self::ReadOnly, Self::ReadOnly) => true,
            (Self::AllowedPeerUid(a), Self::AllowedPeerUid(b)) => a == b,
            _ => false,
        }
    }
}

/// Zero-allocation request descriptor evaluated in RAM against a [`CapabilityMacaroon`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRequestContext {
    pub manifest_root: [u8; 32],
    pub offset: u64,
    pub length: u64,
    pub is_write: bool,
    pub now_unix_ms: u64,
    pub peer_uid: Option<u32>,
}

impl Caveat {
    /// Encodes this caveat into a fixed stack buffer `([u8; 33], used_len)` with injective
    /// variant-tag framing so zero heap allocation occurs during HMAC chaining or verification.
    pub const fn encode_stack(&self) -> ([u8; 33], usize) {
        let mut buf = [0u8; 33];
        match self {
            Self::AllowedManifest(r) => {
                let [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, r31] =
                    *r;
                (
                    [
                        0x01, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15,
                        r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30,
                        r31,
                    ],
                    33,
                )
            }
            Self::ByteRange { offset, length } => {
                let [o0, o1, o2, o3, o4, o5, o6, o7] = offset.to_be_bytes();
                let [l0, l1, l2, l3, l4, l5, l6, l7] = length.to_be_bytes();
                buf[0] = 0x02;
                buf[1] = o0;
                buf[2] = o1;
                buf[3] = o2;
                buf[4] = o3;
                buf[5] = o4;
                buf[6] = o5;
                buf[7] = o6;
                buf[8] = o7;
                buf[9] = l0;
                buf[10] = l1;
                buf[11] = l2;
                buf[12] = l3;
                buf[13] = l4;
                buf[14] = l5;
                buf[15] = l6;
                buf[16] = l7;
                (buf, 17)
            }
            Self::ExpiresAtUnixMs(exp) => {
                let [e0, e1, e2, e3, e4, e5, e6, e7] = exp.to_be_bytes();
                buf[0] = 0x03;
                buf[1] = e0;
                buf[2] = e1;
                buf[3] = e2;
                buf[4] = e3;
                buf[5] = e4;
                buf[6] = e5;
                buf[7] = e6;
                buf[8] = e7;
                (buf, 9)
            }
            Self::ReadOnly => {
                buf[0] = 0x04;
                (buf, 1)
            }
            Self::AllowedPeerUid(uid) => {
                let [u0, u1, u2, u3] = uid.to_be_bytes();
                buf[0] = 0x05;
                buf[1] = u0;
                buf[2] = u1;
                buf[3] = u2;
                buf[4] = u3;
                (buf, 5)
            }
        }
    }

    /// Decodes a single canonical [`Caveat`] from the front of `bytes`, returning `(caveat, consumed_bytes)`.
    pub const fn decode_one(bytes: &[u8]) -> Result<(Self, usize), CapabilityError> {
        let Some(&tag) = bytes.first() else {
            return Err(CapabilityError::MalformedCompactToken);
        };
        match tag {
            0x01 => {
                if bytes.len() < 33 {
                    return Err(CapabilityError::MalformedCompactToken);
                }
                let root = [
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                    bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
                    bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22],
                    bytes[23], bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29],
                    bytes[30], bytes[31], bytes[32],
                ];
                Ok((Self::AllowedManifest(root), 33))
            }
            0x02 => {
                if bytes.len() < 17 {
                    return Err(CapabilityError::MalformedCompactToken);
                }
                let offset = u64::from_be_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                let length = u64::from_be_bytes([
                    bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
                    bytes[16],
                ]);
                Ok((Self::ByteRange { offset, length }, 17))
            }
            0x03 => {
                if bytes.len() < 9 {
                    return Err(CapabilityError::MalformedCompactToken);
                }
                let exp = u64::from_be_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                Ok((Self::ExpiresAtUnixMs(exp), 9))
            }
            0x04 => Ok((Self::ReadOnly, 1)),
            0x05 => {
                if bytes.len() < 5 {
                    return Err(CapabilityError::MalformedCompactToken);
                }
                let uid = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                Ok((Self::AllowedPeerUid(uid), 5))
            }
            _ => Err(CapabilityError::MalformedCompactToken),
        }
    }

    /// Evaluates whether `ctx` satisfies this caveat using overflow-free `u128` range bounds.
    pub const fn allows(&self, ctx: &AccessRequestContext) -> bool {
        match self {
            Self::AllowedManifest(allowed) => ct_eq_32(allowed, &ctx.manifest_root),
            Self::ByteRange { offset, length } => {
                let req_start = ctx.offset as u128;
                let req_end = req_start + (ctx.length as u128);
                let cap_start = *offset as u128;
                let cap_end = cap_start + (*length as u128);
                req_start >= cap_start && req_end <= cap_end
            }
            Self::ExpiresAtUnixMs(expires_at_ms) => ctx.now_unix_ms <= *expires_at_ms,
            Self::ReadOnly => !ctx.is_write,
            Self::AllowedPeerUid(expected) => match ctx.peer_uid {
                Some(actual) => actual == *expected,
                None => false,
            },
        }
    }
}

fn compute_root_macaroon_tag(
    root_key: &[u8; 32],
    nonce_id: &[u8; 32],
    issuer_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(root_key)
        .expect("HMAC-SHA256 accepts 32-byte root key");
    mac.update(MACAROON_ROOT_DOMAIN);
    mac.update(nonce_id);
    mac.update(issuer_fingerprint);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn chain_caveat_tag(prev_tag: &[u8; 32], caveat: &Caveat) -> [u8; 32] {
    let (encoded, len) = caveat.encode_stack();
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(prev_tag)
        .expect("HMAC-SHA256 accepts 32-byte chaining tag");
    mac.update(MACAROON_CAVEAT_DOMAIN);
    mac.update(&encoded[..len]);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl std::fmt::Debug for CapabilityMacaroon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityMacaroon")
            .field("nonce_id_prefix", &hex::encode(&self.nonce_id[..4]))
            .field("caveats", &self.caveats)
            .field("tag", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MacaroonSliceView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacaroonSliceView")
            .field("nonce_id_prefix", &hex::encode(&self.nonce_id[..4]))
            .field("caveats", &self.caveats)
            .field("tag", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// F-43 (L-44 item 4): whether `child` is `parent` itself or an offline attenuation of it,
/// checked without the root key. Same `nonce_id` and `issuer_fingerprint`; `child`'s caveats begin
/// with exactly `parent`'s; at most `MAX_MACAROON_CAVEATS` in total; `child`'s tag equals the chain
/// recomputed from `parent`'s tag over the extra caveats (zero extras: equal tags), compared in
/// constant time. Caveats are not evaluated here.
///
/// For `parvault-fuse webdav`, a block-cache hit never reaches the gateway, so this check (with
/// the WebDAV edge's caveat evaluation) is the only check on that read (L-44 item 4).
pub fn is_attenuation_of(parent: &CapabilityMacaroon, child: &CapabilityMacaroon) -> bool {
    if !ct_eq_32(&parent.nonce_id, &child.nonce_id)
        || !ct_eq_32(&parent.issuer_fingerprint, &child.issuer_fingerprint)
        || child.caveats.len() > MAX_MACAROON_CAVEATS
        || child.caveats.len() < parent.caveats.len()
        || child.caveats[..parent.caveats.len()] != parent.caveats[..]
    {
        return false;
    }
    let mut tag = parent.tag;
    for caveat in &child.caveats[parent.caveats.len()..] {
        tag = chain_caveat_tag(&tag, caveat);
    }
    ct_eq_32(&tag, &child.tag)
}

/// Constant-time 32-byte tag equality check (zero early-exit timing side channels).
#[inline]
pub const fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u64;
    let mut chunk = 0usize;
    while chunk < 4 {
        let base = chunk * 8;
        let wa = u64::from_le_bytes([
            a[base],
            a[base + 1],
            a[base + 2],
            a[base + 3],
            a[base + 4],
            a[base + 5],
            a[base + 6],
            a[base + 7],
        ]);
        let wb = u64::from_le_bytes([
            b[base],
            b[base + 1],
            b[base + 2],
            b[base + 3],
            b[base + 4],
            b[base + 5],
            b[base + 6],
            b[base + 7],
        ]);
        diff |= wa ^ wb;
        chunk += 1;
    }
    diff == 0
}

/// Borrowed zero-allocation view over a [`CapabilityMacaroon`] used by in-RAM slice verifiers
/// and Kani formal proof harnesses.
/// `Debug` is manual and redacts the tag, as for [`CapabilityMacaroon`].
#[derive(Clone, Copy)]
pub struct MacaroonSliceView<'a> {
    pub nonce_id: &'a [u8; 32],
    pub issuer_fingerprint: &'a [u8; 32],
    pub caveats: &'a [Caveat],
    pub tag: &'a [u8; 32],
}

/// Stack-decoded representation of a compact [`CapabilityMacaroon`] binary payload
/// `(nonce_id, issuer_fingerprint, caveats_array, caveat_count, tag)` with zero heap allocations.
pub type DecodedCompactMacaroon<const MAX_C: usize> =
    ([u8; 32], [u8; 32], [Caveat; MAX_C], usize, [u8; 32]);

/// HMAC-SHA256 chained capability token enabling zero-knowledge, `< 1 ms` RAM-only authorization
/// of constrained manifest and byte-range reads without sharing `MasterKey` or `root_key`.
/// `Debug` is manual and redacts the tag (the bearer secret) so a stray `{:?}` cannot leak a
/// usable token (F-43, L-44 item 8).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMacaroon {
    pub nonce_id: [u8; 32],
    pub issuer_fingerprint: [u8; 32],
    pub caveats: Vec<Caveat>,
    pub tag: [u8; 32],
}

impl CapabilityMacaroon {
    /// Zero-allocation slice-based Macaroon tag derivation (`mint_with` and
    /// `verify_caveat_slice_in_ram_with` share this exact implementation).
    pub fn mint_slice_tag_with<R, C>(
        root_key: &[u8; 32],
        nonce_id: &[u8; 32],
        issuer_fingerprint: &[u8; 32],
        caveats: &[Caveat],
        root_prf: R,
        chain_prf: C,
    ) -> Result<[u8; 32], CapabilityError>
    where
        R: Fn(&[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32],
        C: Fn(&[u8; 32], &Caveat) -> [u8; 32],
    {
        if ct_eq_32(root_key, &[0u8; 32]) {
            return Err(CapabilityError::InvalidRootKey);
        }
        if caveats.len() > MAX_MACAROON_CAVEATS {
            return Err(CapabilityError::TooManyCaveats(caveats.len()));
        }
        let mut tag = root_prf(root_key, nonce_id, issuer_fingerprint);
        let mut idx = 0;
        while idx < caveats.len() {
            tag = chain_prf(&tag, &caveats[idx]);
            idx += 1;
        }
        Ok(tag)
    }

    /// Mints a `CapabilityMacaroon` parameterized by `root_prf` and `chain_prf` (`mint` instantiates
    /// both with `HMAC-SHA256`).
    pub fn mint_with<R, C>(
        root_key: &[u8; 32],
        nonce_id: [u8; 32],
        issuer_fingerprint: [u8; 32],
        initial_caveats: Vec<Caveat>,
        root_prf: R,
        chain_prf: C,
    ) -> Result<Self, CapabilityError>
    where
        R: Fn(&[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32],
        C: Fn(&[u8; 32], &Caveat) -> [u8; 32],
    {
        let tag = Self::mint_slice_tag_with(
            root_key,
            &nonce_id,
            &issuer_fingerprint,
            initial_caveats.as_slice(),
            root_prf,
            chain_prf,
        )?;
        Ok(Self {
            nonce_id,
            issuer_fingerprint,
            caveats: initial_caveats,
            tag,
        })
    }

    /// Mints a new root or pre-attenuated `CapabilityMacaroon` from `root_key`.
    pub fn mint(
        root_key: &[u8; 32],
        nonce_id: [u8; 32],
        issuer_fingerprint: [u8; 32],
        initial_caveats: Vec<Caveat>,
    ) -> Result<Self, CapabilityError> {
        Self::mint_with(
            root_key,
            nonce_id,
            issuer_fingerprint,
            initial_caveats,
            compute_root_macaroon_tag,
            chain_caveat_tag,
        )
    }

    /// Whether this token's HMAC chain is valid under `root_key`, in constant time. Caveats are
    /// not evaluated: callers check them against the request separately (F-43 WebDAV edge).
    pub fn tag_valid(&self, root_key: &[u8; 32]) -> bool {
        Self::mint_slice_tag_with(
            root_key,
            &self.nonce_id,
            &self.issuer_fingerprint,
            &self.caveats,
            compute_root_macaroon_tag,
            chain_caveat_tag,
        )
        .is_ok_and(|expected| ct_eq_32(&expected, &self.tag))
    }

    /// Publicly attenuates this Macaroon parameterized by `chain_prf` (`attenuate` instantiates
    /// `chain_prf` with `HMAC-SHA256`).
    pub fn attenuate_with<C>(&self, caveat: Caveat, chain_prf: C) -> Result<Self, CapabilityError>
    where
        C: Fn(&[u8; 32], &Caveat) -> [u8; 32],
    {
        let next_len = self.caveats.len() + 1;
        if next_len > MAX_MACAROON_CAVEATS {
            return Err(CapabilityError::TooManyCaveats(next_len));
        }
        let next_tag = chain_prf(&self.tag, &caveat);
        let mut caveats = Vec::with_capacity(next_len);
        caveats.extend_from_slice(&self.caveats);
        caveats.push(caveat);
        Ok(Self {
            nonce_id: self.nonce_id,
            issuer_fingerprint: self.issuer_fingerprint,
            caveats,
            tag: next_tag,
        })
    }

    /// Publicly attenuates this Macaroon with an additional [`Caveat`] **without** requiring
    /// knowledge of `root_key`. Because `HMAC-SHA256` is one-way, holders can only narrow
    /// permissions and can never strip or relax any prior caveat.
    pub fn attenuate(&self, caveat: Caveat) -> Result<Self, CapabilityError> {
        self.attenuate_with(caveat, chain_caveat_tag)
    }

    /// Evaluates all attached caveats purely in RAM (`O(caveats.len())`, zero allocations).
    pub fn evaluate_caveats(&self, ctx: &AccessRequestContext) -> bool {
        let mut idx = 0;
        let slice = self.caveats.as_slice();
        while idx < slice.len() {
            if !slice[idx].allows(ctx) {
                return false;
            }
            idx += 1;
        }
        true
    }

    /// Zero-allocation slice-based Macaroon verifier parameterized by `root_prf` and `chain_prf`
    /// (`verify_in_ram` instantiates this with `HMAC-SHA256`).
    pub fn verify_caveat_slice_in_ram_with<R, C>(
        root_key: &[u8; 32],
        view: MacaroonSliceView<'_>,
        ctx: &AccessRequestContext,
        root_prf: R,
        chain_prf: C,
    ) -> Result<(), CapabilityError>
    where
        R: Fn(&[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32],
        C: Fn(&[u8; 32], &Caveat) -> [u8; 32],
    {
        let expected_tag = Self::mint_slice_tag_with(
            root_key,
            view.nonce_id,
            view.issuer_fingerprint,
            view.caveats,
            root_prf,
            chain_prf,
        )?;
        if !ct_eq_32(&expected_tag, view.tag) {
            return Err(CapabilityError::InvalidMacaroonTag);
        }
        let mut cidx = 0;
        while cidx < view.caveats.len() {
            if !view.caveats[cidx].allows(ctx) {
                return Err(CapabilityError::CaveatRejected);
            }
            cidx += 1;
        }
        Ok(())
    }

    /// Verifies this Macaroon in RAM parameterized by `root_prf` and `chain_prf`.
    pub fn verify_in_ram_with_mac<R, C>(
        &self,
        root_key: &[u8; 32],
        ctx: &AccessRequestContext,
        root_prf: R,
        chain_prf: C,
    ) -> Result<(), CapabilityError>
    where
        R: Fn(&[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32],
        C: Fn(&[u8; 32], &Caveat) -> [u8; 32],
    {
        Self::verify_caveat_slice_in_ram_with(
            root_key,
            MacaroonSliceView {
                nonce_id: &self.nonce_id,
                issuer_fingerprint: &self.issuer_fingerprint,
                caveats: self.caveats.as_slice(),
                tag: &self.tag,
            },
            ctx,
            root_prf,
            chain_prf,
        )
    }

    /// Verifies both cryptographic `HMAC-SHA256` chain authenticity (in constant time) and all
    /// attached [`Caveat`] constraints strictly in RAM (`< 1 ms`, zero heap allocations, zero
    /// filesystem/disk I/O).
    pub fn verify_in_ram(
        &self,
        root_key: &[u8; 32],
        ctx: &AccessRequestContext,
    ) -> Result<(), CapabilityError> {
        self.verify_in_ram_with_mac(root_key, ctx, compute_root_macaroon_tag, chain_caveat_tag)
    }

    /// Zero-heap-allocation binary encoder writing the canonical compact layout
    /// `[version = 0x01][nonce_id: 32B][issuer_fingerprint: 32B][caveat_count: u8][caveats...][tag: 32B]`
    /// into caller-supplied slice `out`, returning total written byte length.
    pub fn encode_compact_slice_into(
        view: MacaroonSliceView<'_>,
        out: &mut [u8],
    ) -> Result<usize, CapabilityError> {
        let count = view.caveats.len();
        if count > MAX_MACAROON_CAVEATS {
            return Err(CapabilityError::TooManyCaveats(count));
        }
        if out.len() < MIN_COMPACT_MACAROON_BYTES {
            return Err(CapabilityError::MalformedCompactToken);
        }
        out[0] = COMPACT_MACAROON_VERSION;
        out[1..33].copy_from_slice(view.nonce_id);
        out[33..65].copy_from_slice(view.issuer_fingerprint);
        out[65] = count as u8;

        let mut cursor = 66usize;
        let mut idx = 0usize;
        while idx < count {
            let (enc, used) = view.caveats[idx].encode_stack();
            if cursor + used + 32 > out.len() {
                return Err(CapabilityError::MalformedCompactToken);
            }
            out[cursor..cursor + used].copy_from_slice(&enc[..used]);
            cursor += used;
            idx += 1;
        }
        if cursor + 32 > out.len() {
            return Err(CapabilityError::MalformedCompactToken);
        }
        out[cursor..cursor + 32].copy_from_slice(view.tag);
        Ok(cursor + 32)
    }

    /// Zero-heap-allocation binary decoder parsing a canonical compact `CapabilityMacaroon` payload
    /// into fixed stack arrays (`MAX_C <= MAX_MACAROON_CAVEATS`), enforcing strict length bounds,
    /// version check, caveat cap, and zero trailing bytes.
    pub fn decode_compact_into<const MAX_C: usize>(
        raw: &[u8],
    ) -> Result<DecodedCompactMacaroon<MAX_C>, CapabilityError> {
        if raw.len() < MIN_COMPACT_MACAROON_BYTES || raw.len() > MAX_COMPACT_MACAROON_BYTES {
            return Err(CapabilityError::MalformedCompactToken);
        }
        if raw[0] != COMPACT_MACAROON_VERSION {
            return Err(CapabilityError::MalformedCompactToken);
        }
        let count = raw[65] as usize;
        if count > MAX_MACAROON_CAVEATS {
            return Err(CapabilityError::TooManyCaveats(count));
        }
        if count > MAX_C {
            return Err(CapabilityError::TooManyCaveats(count));
        }
        let caveats_end = raw.len() - 32;
        if count > caveats_end - 66 {
            return Err(CapabilityError::MalformedCompactToken);
        }
        let mut nonce_id = [0u8; 32];
        nonce_id.copy_from_slice(&raw[1..33]);
        let mut issuer_fingerprint = [0u8; 32];
        issuer_fingerprint.copy_from_slice(&raw[33..65]);

        let mut caveats = [Caveat::ReadOnly; MAX_C];
        let mut cursor = 66usize;
        let mut idx = 0usize;
        while idx < count {
            if cursor >= caveats_end {
                return Err(CapabilityError::MalformedCompactToken);
            }
            let (cav, used) = Caveat::decode_one(&raw[cursor..caveats_end])?;
            caveats[idx] = cav;
            cursor += used;
            idx += 1;
        }
        if cursor != caveats_end {
            return Err(CapabilityError::MalformedCompactToken);
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&raw[caveats_end..raw.len()]);
        Ok((nonce_id, issuer_fingerprint, caveats, count, tag))
    }

    /// Serializes this `CapabilityMacaroon` into its canonical deterministic binary layout:
    /// `[version = 0x01][nonce_id: 32B][issuer_fingerprint: 32B][caveat_count: u8][caveats...][tag: 32B]`.
    pub fn to_compact_bytes(&self) -> Vec<u8> {
        let mut stack_buf = [0u8; MAX_COMPACT_MACAROON_BYTES];
        let encode_n = self.caveats.len().min(MAX_MACAROON_CAVEATS);
        let used = Self::encode_compact_slice_into(
            MacaroonSliceView {
                nonce_id: &self.nonce_id,
                issuer_fingerprint: &self.issuer_fingerprint,
                caveats: &self.caveats[..encode_n],
                tag: &self.tag,
            },
            &mut stack_buf,
        )
        .expect("MAX_COMPACT_MACAROON_BYTES fits MAX_MACAROON_CAVEATS");
        if self.caveats.len() > MAX_MACAROON_CAVEATS {
            stack_buf[65] = self.caveats.len().min(u8::MAX as usize) as u8;
        }
        stack_buf[..used].to_vec()
    }

    /// Parses a `CapabilityMacaroon` from its canonical compact binary layout, enforcing strict
    /// length bounds (`MIN_COMPACT_MACAROON_BYTES ..= MAX_COMPACT_MACAROON_BYTES`), `MAX_MACAROON_CAVEATS`,
    /// and zero trailing bytes.
    pub fn from_compact_bytes(raw: &[u8]) -> Result<Self, CapabilityError> {
        let (nonce_id, issuer_fingerprint, caveats_arr, count, tag) =
            Self::decode_compact_into::<MAX_MACAROON_CAVEATS>(raw)?;
        Ok(Self {
            nonce_id,
            issuer_fingerprint,
            caveats: caveats_arr[..count].to_vec(),
            tag,
        })
    }

    /// Encodes this `CapabilityMacaroon` into a shareable `PARVAULT-MAC-V1:<hex>` ASCII token.
    pub fn to_compact_token(&self) -> String {
        let raw = self.to_compact_bytes();
        let mut out = String::with_capacity(COMPACT_MACAROON_PREFIX.len() + raw.len() * 2);
        out.push_str(COMPACT_MACAROON_PREFIX);
        out.push_str(&hex::encode(raw));
        out
    }

    /// Decodes a `PARVAULT-MAC-V1:<hex>` compact token with pre-allocation length bounds (`0` `unsafe`).
    pub fn from_compact_token(token: &str) -> Result<Self, CapabilityError> {
        let trimmed = token.trim();
        let hex_body = trimmed
            .strip_prefix(COMPACT_MACAROON_PREFIX)
            .ok_or(CapabilityError::MalformedCompactToken)?;
        let min_hex = MIN_COMPACT_MACAROON_BYTES * 2;
        let max_hex = MAX_COMPACT_MACAROON_BYTES * 2;
        if hex_body.len() < min_hex || hex_body.len() > max_hex || !hex_body.len().is_multiple_of(2)
        {
            return Err(CapabilityError::MalformedCompactToken);
        }
        let raw = hex::decode(hex_body).map_err(|_| CapabilityError::MalformedCompactToken)?;
        Self::from_compact_bytes(&raw)
    }
}

/// Post-Quantum Master Gateway Identity Statement (`Ed25519 + NIST FIPS 204 ML-DSA-65`) binding a
/// CPE router/gateway's `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` static public key and `Ed25519`
/// mesh transport key to its post-quantum root authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayIdentityStatement {
    pub gateway_id: String,
    pub ed25519_transport_pubkey: [u8; 32],
    pub noise_static_x25519_pubkey: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub authority_pq_pubkey: HybridPqPublicKey,
    pub signature: HybridPqSignature,
}

impl GatewayIdentityStatement {
    /// Signs a new composite post-quantum `GatewayIdentityStatement` with `authority`.
    pub fn issue(
        authority: &HybridPqSigningKeypair,
        gateway_id: impl Into<String>,
        ed25519_transport_pubkey: [u8; 32],
        noise_static_x25519_pubkey: [u8; 32],
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, CryptoError> {
        let gateway_id = gateway_id.into();
        if gateway_id.is_empty() || gateway_id.len() > MAX_GATEWAY_ID_BYTES {
            return Err(CryptoError::InvalidKeyMaterial(
                "gateway_id must be 1..=128 bytes".into(),
            ));
        }
        if ed25519_transport_pubkey == [0u8; 32] || noise_static_x25519_pubkey == [0u8; 32] {
            return Err(CryptoError::InvalidKeyMaterial(
                "all-zero transport or Noise static public key forbidden".into(),
            ));
        }
        let authority_pq_pubkey = authority.public_key();
        let payload = Self::canonical_sign_bytes(
            &gateway_id,
            &ed25519_transport_pubkey,
            &noise_static_x25519_pubkey,
            issued_at_unix_ms,
            expires_at_unix_ms,
            &authority_pq_pubkey,
        );
        let signature = authority.sign(&payload)?;
        Ok(Self {
            gateway_id,
            ed25519_transport_pubkey,
            noise_static_x25519_pubkey,
            issued_at_unix_ms,
            expires_at_unix_ms,
            authority_pq_pubkey,
            signature,
        })
    }

    /// Verifies the statement against the authority the caller pinned (F-17): the decision
    /// ([`gateway_statement_decision`]: pinned authority, bounded and unexpired lifetime), the
    /// structural bounds, and both legs of the composite `Ed25519 + ML-DSA-65` signature. There is
    /// no unpinned verify: a statement signed by any other authority is refused.
    pub fn verify_pinned(
        &self,
        expected_authority: &HybridPqPublicKey,
        now_unix_ms: u64,
    ) -> Result<(), &'static str> {
        gateway_statement_decision(
            self.authority_pq_pubkey == *expected_authority,
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
            now_unix_ms,
        )?;
        if self.verify_signature() {
            Ok(())
        } else {
            Err("reject.gateway_statement_invalid")
        }
    }

    fn verify_signature(&self) -> bool {
        if self.gateway_id.is_empty()
            || self.gateway_id.len() > MAX_GATEWAY_ID_BYTES
            || self.ed25519_transport_pubkey == [0u8; 32]
            || self.noise_static_x25519_pubkey == [0u8; 32]
        {
            return false;
        }
        let payload = Self::canonical_sign_bytes(
            &self.gateway_id,
            &self.ed25519_transport_pubkey,
            &self.noise_static_x25519_pubkey,
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
            &self.authority_pq_pubkey,
        );
        HybridPqSigningKeypair::verify(&self.authority_pq_pubkey, &payload, &self.signature)
    }

    fn canonical_sign_bytes(
        gateway_id: &str,
        ed25519_transport_pubkey: &[u8; 32],
        noise_static_x25519_pubkey: &[u8; 32],
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        authority_pq_pubkey: &HybridPqPublicKey,
    ) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(160 + gateway_id.len() + authority_pq_pubkey.ml_dsa_65_pk.len());
        out.extend_from_slice(GATEWAY_STATEMENT_DOMAIN);
        out.extend_from_slice(&(gateway_id.len() as u32).to_be_bytes());
        out.extend_from_slice(gateway_id.as_bytes());
        out.extend_from_slice(ed25519_transport_pubkey);
        out.extend_from_slice(noise_static_x25519_pubkey);
        out.extend_from_slice(&issued_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&authority_pq_pubkey.ed25519_pub);
        out.extend_from_slice(&(authority_pq_pubkey.ml_dsa_65_pk.len() as u32).to_be_bytes());
        out.extend_from_slice(&authority_pq_pubkey.ml_dsa_65_pk);
        out
    }
}

/// The token a plugin presents, from `--macaroon` (inline; visible to every local user in
/// `/proc/<pid>/cmdline`) or `--macaroon-file` (QA item 3: a file only its owner can read).
/// Both at once is refused; neither is `Ok(None)`.
pub fn token_from_args(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<CapabilityMacaroon>, String> {
    let text = match (inline.map(str::trim).filter(|s| !s.is_empty()), file) {
        (Some(_), Some(_)) => return Err("give --macaroon or --macaroon-file, not both".into()),
        (Some(t), None) => t.to_string(),
        (None, Some(path)) => read_owner_only_token_file(path)?,
        (None, None) => return Ok(None),
    };
    CapabilityMacaroon::from_compact_token(&text)
        .map(Some)
        .map_err(|e| format!("invalid token: {e}"))
}

/// Largest `--macaroon-file` read (a compact token is a few KiB at most).
pub const MAX_TOKEN_FILE_BYTES: u64 = 16 * 1024;

/// Reads a token file (QA item 3). It is opened without following a symlink and without
/// blocking (so a FIFO cannot hang the caller), then checked on the open descriptor, so there
/// is no check-then-open race: a regular file, owned by this effective UID, that group and
/// others cannot read, at most [`MAX_TOKEN_FILE_BYTES`].
fn read_owner_only_token_file(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let shown = path.display();
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| {
                format!("cannot open --macaroon-file {shown}: {e} (a symlink is refused)")
            })?;
        let meta = file
            .metadata()
            .map_err(|e| format!("cannot stat --macaroon-file {shown}: {e}"))?;
        if !meta.file_type().is_file() {
            return Err(format!("--macaroon-file {shown} is not a regular file"));
        }
        let euid = crate::os_sys::geteuid();
        if meta.uid() != euid {
            return Err(format!(
                "--macaroon-file {shown} is owned by uid {}, not by this user (uid {euid})",
                meta.uid()
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "--macaroon-file {shown} is readable by group or others (mode {:o}); chmod 600 it",
                meta.mode() & 0o777
            ));
        }
        if meta.len() > MAX_TOKEN_FILE_BYTES {
            return Err(format!(
                "--macaroon-file {shown} is larger than {MAX_TOKEN_FILE_BYTES} bytes"
            ));
        }
        file
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open --macaroon-file {shown}: {e}"))?;
    let mut text = String::new();
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read --macaroon-file {shown}: {e}"))?;
    if text.len() as u64 > MAX_TOKEN_FILE_BYTES {
        return Err(format!(
            "--macaroon-file {shown} is larger than {MAX_TOKEN_FILE_BYTES} bytes"
        ));
    }
    Ok(text.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // QA item 3 re-check: the token file is opened without following links, checked on the
    // open descriptor, and read with a bound.
    #[cfg(unix)]
    fn private_file(dir: &std::path::Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    #[cfg(unix)]
    fn a_token() -> String {
        CapabilityMacaroon::mint(&[7; 32], [1; 32], [2; 32], vec![Caveat::ReadOnly])
            .unwrap()
            .to_compact_token()
    }

    #[cfg(unix)]
    #[test]
    fn token_file_private_regular_file_read() {
        let d = tempfile::tempdir().unwrap();
        let f = private_file(d.path(), "t", format!("{}\n", a_token()).as_bytes());
        assert!(token_from_args(None, Some(&f)).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn token_file_symlink_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = private_file(d.path(), "t", a_token().as_bytes());
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        let err = token_from_args(None, Some(&link)).unwrap_err();
        assert!(err.contains("cannot open"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn token_file_fifo_refused_without_blocking() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let err = token_from_args(None, Some(&fifo)).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn token_file_oversized_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = private_file(
            d.path(),
            "big",
            &vec![b'a'; MAX_TOKEN_FILE_BYTES as usize + 1],
        );
        let err = token_from_args(None, Some(&f)).unwrap_err();
        assert!(err.contains("larger than"), "{err}");
    }
    use std::time::Instant;

    /// F-17 accept: a statement from the pinned authority with a bounded lifetime verifies.
    #[test]
    fn f17_pinned_authority_statement_accepted() {
        let authority = HybridPqSigningKeypair::generate().unwrap();
        let stmt =
            GatewayIdentityStatement::issue(&authority, "gw-1", [0x11; 32], [0x22; 32], 1, 60_000)
                .unwrap();
        assert_eq!(stmt.verify_pinned(&authority.public_key(), 30_000), Ok(()));
    }

    /// F-17 reject: a validly signed statement from another authority is refused, and so is a
    /// pinned one that never expires or outlives 30 days.
    #[test]
    fn f17_unpinned_authority_statement_refused() {
        let pinned = HybridPqSigningKeypair::generate().unwrap();
        let rogue = HybridPqSigningKeypair::generate().unwrap();
        let stmt =
            GatewayIdentityStatement::issue(&rogue, "gw-1", [0x11; 32], [0x22; 32], 1, 60_000)
                .unwrap();
        assert_eq!(
            stmt.verify_pinned(&pinned.public_key(), 30_000),
            Err("reject.gateway_authority_unpinned")
        );
        let future = GatewayIdentityStatement::issue(
            &pinned, "gw-1", [0x11; 32], [0x22; 32], 10_000_000, 10_060_000,
        )
        .unwrap();
        assert_eq!(
            future.verify_pinned(
                &pinned.public_key(),
                10_000_000 - GATEWAY_STATEMENT_FUTURE_SKEW_MS - 1
            ),
            Err("reject.gateway_statement_future")
        );
        for expires in [0, 1 + MAX_GATEWAY_STATEMENT_LIFETIME_MS + 1] {
            let stmt = GatewayIdentityStatement::issue(
                &pinned, "gw-1", [0x11; 32], [0x22; 32], 1, expires,
            )
            .unwrap();
            assert_eq!(
                stmt.verify_pinned(&pinned.public_key(), 2),
                Err("reject.gateway_statement_unbounded")
            );
        }
    }

    #[test]
    fn test_macaroon_sub_millisecond_ram_verification_and_attenuation() {
        let root_key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let manifest_a = [0xAAu8; 32];
        let manifest_b = [0xBBu8; 32];

        let root_token = CapabilityMacaroon::mint(
            &root_key,
            [0x11; 32],
            [0x22; 32],
            vec![Caveat::AllowedManifest(manifest_a), Caveat::ReadOnly],
        )
        .expect("mint root macaroon");

        let delegated = root_token
            .attenuate(Caveat::ByteRange {
                offset: 1024,
                length: 4096,
            })
            .unwrap()
            .attenuate(Caveat::ExpiresAtUnixMs(50_000))
            .unwrap()
            .attenuate(Caveat::AllowedPeerUid(1000))
            .unwrap();

        let valid_ctx = AccessRequestContext {
            manifest_root: manifest_a,
            offset: 2048,
            length: 1024,
            is_write: false,
            now_unix_ms: 40_000,
            peer_uid: Some(1000),
        };

        let t0 = Instant::now();
        delegated
            .verify_in_ram(&root_key, &valid_ctx)
            .expect("valid delegated macaroon should pass");
        let elapsed = t0.elapsed();
        assert!(
            elapsed.as_micros() < 1_000,
            "RAM verification took {} us (>= 1 ms)",
            elapsed.as_micros()
        );

        // Unauthorized root key rejected in < 1ms.
        let t_unauth = Instant::now();
        assert_eq!(
            delegated.verify_in_ram(&wrong_key, &valid_ctx),
            Err(CapabilityError::InvalidMacaroonTag)
        );
        assert!(t_unauth.elapsed().as_micros() < 1_000);

        // Stripping last caveat without root_key fails HMAC chain verification.
        let mut stripped = delegated.clone();
        stripped.caveats.pop();
        assert_eq!(
            stripped.verify_in_ram(&root_key, &valid_ctx),
            Err(CapabilityError::InvalidMacaroonTag)
        );

        // Wrong manifest, out-of-bounds byte range, write op, or expired timestamp rejected.
        assert_eq!(
            delegated.verify_in_ram(
                &root_key,
                &AccessRequestContext {
                    manifest_root: manifest_b,
                    ..valid_ctx
                }
            ),
            Err(CapabilityError::CaveatRejected)
        );
        assert_eq!(
            delegated.verify_in_ram(
                &root_key,
                &AccessRequestContext {
                    offset: 4096,
                    length: 2048,
                    ..valid_ctx
                }
            ),
            Err(CapabilityError::CaveatRejected)
        );
        assert_eq!(
            delegated.verify_in_ram(
                &root_key,
                &AccessRequestContext {
                    is_write: true,
                    ..valid_ctx
                }
            ),
            Err(CapabilityError::CaveatRejected)
        );
        assert_eq!(
            delegated.verify_in_ram(
                &root_key,
                &AccessRequestContext {
                    now_unix_ms: 50_001,
                    ..valid_ctx
                }
            ),
            Err(CapabilityError::CaveatRejected)
        );
    }

    #[test]
    fn test_pq_gateway_identity_statement_ml_dsa_65_roundtrip_and_tamper_rejection() {
        let authority = HybridPqSigningKeypair::generate().expect("ML-DSA-65 keygen");
        let stmt = GatewayIdentityStatement::issue(
            &authority,
            "cpe-prplos-gw-01",
            [0x33; 32],
            [0x77; 32],
            1_000,
            60_000,
        )
        .expect("issue statement");

        let pinned = authority.public_key();
        assert_eq!(stmt.verify_pinned(&pinned, 25_000), Ok(()));
        assert_eq!(
            stmt.verify_pinned(&pinned, 60_001),
            Err("reject.gateway_statement_expired")
        );

        let mut tampered = stmt.clone();
        tampered.noise_static_x25519_pubkey[0] ^= 0xFF;
        assert_eq!(
            tampered.verify_pinned(&pinned, 25_000),
            Err("reject.gateway_statement_invalid")
        );
    }

    #[test]
    fn test_macaroon_with_helpers_exact_production_equivalence() {
        let root_key = [0x5Au8; 32];
        let nonce_id = [0x12u8; 32];
        let issuer_fp = [0x34u8; 32];
        let caveats = vec![
            Caveat::AllowedManifest([0xAB; 32]),
            Caveat::ByteRange {
                offset: 512,
                length: 8192,
            },
            Caveat::ExpiresAtUnixMs(99_000),
            Caveat::ReadOnly,
        ];

        let prod = CapabilityMacaroon::mint(&root_key, nonce_id, issuer_fp, caveats.clone())
            .expect("prod mint");
        let via_with = CapabilityMacaroon::mint_with(
            &root_key,
            nonce_id,
            issuer_fp,
            caveats.clone(),
            compute_root_macaroon_tag,
            chain_caveat_tag,
        )
        .expect("mint_with");
        assert_eq!(prod, via_with);

        let slice_tag = CapabilityMacaroon::mint_slice_tag_with(
            &root_key,
            &nonce_id,
            &issuer_fp,
            &caveats,
            compute_root_macaroon_tag,
            chain_caveat_tag,
        )
        .expect("mint_slice_tag_with");
        assert_eq!(slice_tag, prod.tag);

        let ok_ctx = AccessRequestContext {
            manifest_root: [0xAB; 32],
            offset: 1024,
            length: 2048,
            now_unix_ms: 50_000,
            is_write: false,
            peer_uid: Some(1000),
        };
        let bad_ctx = AccessRequestContext {
            is_write: true,
            ..ok_ctx
        };
        for ctx in [ok_ctx, bad_ctx] {
            assert_eq!(
                prod.verify_in_ram(&root_key, &ctx),
                prod.verify_in_ram_with_mac(
                    &root_key,
                    &ctx,
                    compute_root_macaroon_tag,
                    chain_caveat_tag,
                )
            );
            assert_eq!(
                prod.verify_in_ram(&root_key, &ctx),
                CapabilityMacaroon::verify_caveat_slice_in_ram_with(
                    &root_key,
                    MacaroonSliceView {
                        nonce_id: &prod.nonce_id,
                        issuer_fingerprint: &prod.issuer_fingerprint,
                        caveats: &prod.caveats,
                        tag: &prod.tag,
                    },
                    &ctx,
                    compute_root_macaroon_tag,
                    chain_caveat_tag,
                )
            );
        }
    }

    #[test]
    fn test_compact_macaroon_token_roundtrip_and_peer_uid_caveat() {
        let root_key = [0x77u8; 32];
        let manifest = [0xCDu8; 32];
        let base = CapabilityMacaroon::mint(
            &root_key,
            [0x01; 32],
            [0x02; 32],
            vec![
                Caveat::AllowedManifest(manifest),
                Caveat::AllowedPeerUid(1001),
            ],
        )
        .expect("mint");
        let child = base
            .attenuate(Caveat::ByteRange {
                offset: 4096,
                length: 8192,
            })
            .unwrap()
            .attenuate(Caveat::ExpiresAtUnixMs(120_000))
            .unwrap()
            .attenuate(Caveat::ReadOnly)
            .unwrap();

        let token = child.to_compact_token();
        assert!(token.starts_with(COMPACT_MACAROON_PREFIX));
        let parsed = CapabilityMacaroon::from_compact_token(&token).expect("from_compact_token");
        assert_eq!(parsed, child);

        let ctx_ok = AccessRequestContext {
            manifest_root: manifest,
            offset: 4096,
            length: 1024,
            is_write: false,
            now_unix_ms: 100_000,
            peer_uid: Some(1001),
        };
        parsed
            .verify_in_ram(&root_key, &ctx_ok)
            .expect("peer_uid=1001 authorized");

        // Mismatched peer_uid or missing peer_uid rejected:
        assert_eq!(
            parsed.verify_in_ram(
                &root_key,
                &AccessRequestContext {
                    peer_uid: Some(1002),
                    ..ctx_ok
                }
            ),
            Err(CapabilityError::CaveatRejected)
        );
        assert_eq!(
            parsed.verify_in_ram(
                &root_key,
                &AccessRequestContext {
                    peer_uid: None,
                    ..ctx_ok
                }
            ),
            Err(CapabilityError::CaveatRejected)
        );

        // Malformed prefix, truncated hex, trailing byte, and > MAX_MACAROON_CAVEATS rejected:
        assert_eq!(
            CapabilityMacaroon::from_compact_token("BAD-PREFIX:00"),
            Err(CapabilityError::MalformedCompactToken)
        );
        assert_eq!(
            CapabilityMacaroon::from_compact_token("PARVAULT-MAC-V1:0102"),
            Err(CapabilityError::MalformedCompactToken)
        );
        let mut raw = child.to_compact_bytes();
        raw.push(0xFF);
        assert_eq!(
            CapabilityMacaroon::from_compact_bytes(&raw),
            Err(CapabilityError::MalformedCompactToken)
        );
        let mut too_many = base.to_compact_bytes();
        too_many[65] = (MAX_MACAROON_CAVEATS as u8) + 1;
        assert_eq!(
            CapabilityMacaroon::from_compact_bytes(&too_many),
            Err(CapabilityError::TooManyCaveats(MAX_MACAROON_CAVEATS + 1))
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn symbolic_caveat_all_5() -> Caveat {
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

    /// Proves with **zero heap (`Vec`) allocations**:
    /// 1. `Caveat::AllowedPeerUid(expected)` strictly rejects every symbolic `actual_uid != Some(expected)`
    ///    (both `None` and `Some(other)` across `0..=u32::MAX`) and accepts iff `actual_uid == Some(expected)`
    ///    inside `CapabilityMacaroon::verify_caveat_slice_in_ram_with`.
    /// 2. `Caveat::encode_stack` <-> `Caveat::decode_one` is bijective across all 5 symbolic `Caveat`
    ///    variants on stack `[u8; 34]` slices and rejects unknown discriminant tags and truncated slices.
    /// 3. The production wire codec `CapabilityMacaroon::encode_compact_slice_into` <->
    ///    `CapabilityMacaroon::decode_compact_into::<2>` round-trips losslessly across arbitrary symbolic
    ///    `nonce_id`, `issuer_fingerprint`, `tag`, and `0..=2` symbolic caveats spanning all 5 variants,
    ///    while rejecting invalid version tags, truncated buffers, and `caveat_count > MAX_MACAROON_CAVEATS`.
    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_macaroon_peer_uid_and_compact_roundtrip() {
        let root_key: [u8; 32] = kani::any();
        kani::assume(!ct_eq_32(&root_key, &[0u8; 32]));
        let nonce_id: [u8; 32] = kani::any();
        let issuer_fp: [u8; 32] = kani::any();

        // (1) Exhaustive symbolic proof of `Caveat::AllowedPeerUid(expected)` across `None` & `0..=u32::MAX`:
        let expected_uid: u32 = kani::any();
        let actual_uid: Option<u32> = if kani::any() { Some(kani::any()) } else { None };
        let peer_cav = [Caveat::AllowedPeerUid(expected_uid)];

        let ideal_root_prf = |rk: &[u8; 32], nid: &[u8; 32], ifp: &[u8; 32]| -> [u8; 32] {
            let mut out = *rk;
            out[0] ^= nid[0];
            out[1] ^= ifp[1];
            out
        };
        let ideal_chain_prf = |prev: &[u8; 32], cav: &Caveat| -> [u8; 32] {
            let (enc, clen) = cav.encode_stack();
            let mut out = *prev;
            out[0] ^= clen as u8;
            out[1] = out[1].wrapping_add(enc[0]);
            out[2] ^= enc[1];
            out[3] ^= enc[2];
            out[4] ^= enc[3];
            out[5] ^= enc[4];
            out
        };

        let tag = CapabilityMacaroon::mint_slice_tag_with(
            &root_key,
            &nonce_id,
            &issuer_fp,
            &peer_cav,
            ideal_root_prf,
            ideal_chain_prf,
        )
        .expect("mint tag");

        let ctx = AccessRequestContext {
            manifest_root: kani::any(),
            offset: kani::any(),
            length: kani::any(),
            is_write: kani::any(),
            now_unix_ms: kani::any(),
            peer_uid: actual_uid,
        };
        let verify_res = CapabilityMacaroon::verify_caveat_slice_in_ram_with(
            &root_key,
            MacaroonSliceView {
                nonce_id: &nonce_id,
                issuer_fingerprint: &issuer_fp,
                caveats: &peer_cav,
                tag: &tag,
            },
            &ctx,
            ideal_root_prf,
            ideal_chain_prf,
        );
        if actual_uid == Some(expected_uid) {
            assert_eq!(verify_res, Ok(()));
        } else {
            assert_eq!(verify_res, Err(CapabilityError::CaveatRejected));
        }

        // (2) Single-caveat `encode_stack` <-> `decode_one` bijection + malformed prefix/truncation rejection:
        let single_cav = symbolic_caveat_all_5();
        let (enc_one, used_one) = single_cav.encode_stack();
        let mut padded_one = [0u8; 34];
        padded_one[..33].copy_from_slice(&enc_one);
        padded_one[33] = kani::any();
        let (dec_one, consumed_one) =
            Caveat::decode_one(&padded_one[..used_one + 1]).expect("decode_one valid caveat");
        assert_eq!(dec_one, single_cav);
        assert_eq!(consumed_one, used_one);
        if used_one > 1 {
            assert_eq!(
                Caveat::decode_one(&enc_one[..used_one - 1]),
                Err(CapabilityError::MalformedCompactToken)
            );
        }
        let bad_tag: u8 = kani::any();
        kani::assume(bad_tag == 0 || bad_tag > 0x05);
        let bad_slice = [bad_tag, 0, 0, 0, 0];
        assert_eq!(
            Caveat::decode_one(&bad_slice),
            Err(CapabilityError::MalformedCompactToken)
        );

        // (3) Zero-heap production wire codec round-trip:
        //     (a) `0` caveats (empty caveat chain), and
        //     (b) `2` chained symbolic caveats (`AllowedPeerUid` + `ExpiresAtUnixMs`, proving multi-caveat
        //         cursor advancement, zero trailing bytes, version check, and caveat-cap enforcement).
        let empty_slice: [Caveat; 0] = [];
        let mut wire_zero = [0u8; MIN_COMPACT_MACAROON_BYTES];
        let used_zero = CapabilityMacaroon::encode_compact_slice_into(
            MacaroonSliceView {
                nonce_id: &nonce_id,
                issuer_fingerprint: &issuer_fp,
                caveats: &empty_slice,
                tag: &tag,
            },
            &mut wire_zero,
        )
        .expect("encode 0 caveats");
        assert_eq!(used_zero, MIN_COMPACT_MACAROON_BYTES);
        let (d0_nid, d0_ifp, _d0_cavs, d0_cnt, d0_tag) =
            CapabilityMacaroon::decode_compact_into::<2>(&wire_zero[..used_zero])
                .expect("decode 0 caveats");
        assert!(ct_eq_32(&d0_nid, &nonce_id));
        assert!(ct_eq_32(&d0_ifp, &issuer_fp));
        assert!(ct_eq_32(&d0_tag, &tag));
        assert_eq!(d0_cnt, 0);

        let two_slice = [
            Caveat::AllowedPeerUid(expected_uid),
            Caveat::ExpiresAtUnixMs(kani::any()),
        ];
        let mut wire_two = [0u8; MIN_COMPACT_MACAROON_BYTES + 5 + 9];
        let used_two = CapabilityMacaroon::encode_compact_slice_into(
            MacaroonSliceView {
                nonce_id: &nonce_id,
                issuer_fingerprint: &issuer_fp,
                caveats: &two_slice,
                tag: &tag,
            },
            &mut wire_two,
        )
        .expect("encode 2 symbolic caveats");
        assert_eq!(used_two, wire_two.len());

        let (dec_nid, dec_ifp, dec_cavs, dec_cnt, dec_tag) =
            CapabilityMacaroon::decode_compact_into::<2>(&wire_two[..used_two])
                .expect("decode_compact_into round-trip succeeds");
        assert!(ct_eq_32(&dec_nid, &nonce_id));
        assert!(ct_eq_32(&dec_ifp, &issuer_fp));
        assert!(ct_eq_32(&dec_tag, &tag));
        assert_eq!(dec_cnt, 2);
        assert_eq!(dec_cavs[0], two_slice[0]);
        assert_eq!(dec_cavs[1], two_slice[1]);

        // Reject truncated slice, invalid version byte, and `caveat_count > MAX_MACAROON_CAVEATS`:
        assert!(CapabilityMacaroon::decode_compact_into::<2>(&wire_two[..used_two - 1]).is_err());

        wire_two[0] = 0x00;
        assert_eq!(
            CapabilityMacaroon::decode_compact_into::<2>(&wire_two[..used_two]).err(),
            Some(CapabilityError::MalformedCompactToken)
        );
        wire_two[0] = COMPACT_MACAROON_VERSION;

        let over: u8 = kani::any();
        kani::assume((over as usize) > MAX_MACAROON_CAVEATS);
        wire_two[65] = over;
        assert_eq!(
            CapabilityMacaroon::decode_compact_into::<2>(&wire_two[..used_two]).err(),
            Some(CapabilityError::TooManyCaveats(over as usize))
        );
    }
}

#[cfg(test)]
mod f43_attenuation_tests {
    use super::*;

    const K: [u8; 32] = [0x43; 32];

    fn parent() -> CapabilityMacaroon {
        CapabilityMacaroon::mint(&K, [1; 32], [2; 32], vec![Caveat::ReadOnly]).unwrap()
    }

    #[test]
    fn pinned_token_and_its_attenuation_accepted() {
        let p = parent();
        assert!(is_attenuation_of(&p, &p));
        let child = p.attenuate(Caveat::ExpiresAtUnixMs(u64::MAX)).unwrap();
        assert!(is_attenuation_of(&p, &child));
        let grandchild = child
            .attenuate(Caveat::ByteRange {
                offset: 0,
                length: 9,
            })
            .unwrap();
        assert!(is_attenuation_of(&p, &grandchild));
        assert!(p.tag_valid(&K) && grandchild.tag_valid(&K));
        assert!(!p.tag_valid(&[0x44; 32]));
    }

    /// L-44 item 8: `{:?}` of a token never prints its tag (or its full nonce).
    #[test]
    fn debug_redacts_the_tag() {
        let p = parent();
        let text = format!("{p:?} {:?}", p.attenuate(Caveat::ReadOnly).unwrap());
        assert!(!text.contains(&hex::encode(p.tag)), "{text}");
        assert!(!text.contains(&hex::encode(p.nonce_id)), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn sibling_and_prefix_violations_refused() {
        let p = parent();
        // A sibling under the same root key (other nonce) is not an attenuation.
        let sibling =
            CapabilityMacaroon::mint(&K, [9; 32], [2; 32], vec![Caveat::ReadOnly]).unwrap();
        assert!(!is_attenuation_of(&p, &sibling));
        // Same nonce and issuer but missing the parent's caveat (minted from the root).
        let p2 = CapabilityMacaroon::mint(
            &K,
            [1; 32],
            [2; 32],
            vec![Caveat::ReadOnly, Caveat::ExpiresAtUnixMs(5)],
        )
        .unwrap();
        let missing = CapabilityMacaroon::mint(
            &K,
            [1; 32],
            [2; 32],
            vec![
                Caveat::ReadOnly,
                Caveat::ByteRange {
                    offset: 0,
                    length: 1,
                },
            ],
        )
        .unwrap();
        assert!(!is_attenuation_of(&p2, &missing));
        // A forged tag on a correct caveat list.
        let mut forged = p.attenuate(Caveat::ExpiresAtUnixMs(7)).unwrap();
        forged.tag[0] ^= 1;
        assert!(!is_attenuation_of(&p, &forged));
        // A child shorter than the parent.
        assert!(!is_attenuation_of(&p2, &p));
    }
}
