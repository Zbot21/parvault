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
}

/// First-party zero-knowledge attenuation caveat chained onto a [`CapabilityMacaroon`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Caveat {
    /// Restricts access exclusively to the specified 32-byte manifest Merkle root.
    AllowedManifest([u8; 32]),
    /// Restricts access exclusively to sub-ranges contained within `[offset .. offset + length]`.
    ByteRange { offset: u64, length: u64 },
    /// Restricts token validity to `now_unix_ms <= expires_at_unix_ms`.
    ExpiresAtUnixMs(u64),
    /// Prohibits write/mutation operations (`ctx.is_write` must be `false`).
    ReadOnly,
}

/// Zero-allocation request descriptor evaluated in RAM against a [`CapabilityMacaroon`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRequestContext {
    pub manifest_root: [u8; 32],
    pub offset: u64,
    pub length: u64,
    pub is_write: bool,
    pub now_unix_ms: u64,
}

impl Caveat {
    /// Encodes this caveat into a fixed stack buffer `([u8; 33], used_len)` with injective
    /// variant-tag framing so zero heap allocation occurs during HMAC chaining or verification.
    pub const fn encode_stack(&self) -> ([u8; 33], usize) {
        let mut buf = [0u8; 33];
        match self {
            Self::AllowedManifest(root) => {
                buf[0] = 0x01;
                let mut i = 0;
                while i < 32 {
                    buf[1 + i] = root[i];
                    i += 1;
                }
                (buf, 33)
            }
            Self::ByteRange { offset, length } => {
                buf[0] = 0x02;
                let off_be = offset.to_be_bytes();
                let len_be = length.to_be_bytes();
                let mut i = 0;
                while i < 8 {
                    buf[1 + i] = off_be[i];
                    buf[9 + i] = len_be[i];
                    i += 1;
                }
                (buf, 17)
            }
            Self::ExpiresAtUnixMs(exp) => {
                buf[0] = 0x03;
                let exp_be = exp.to_be_bytes();
                let mut i = 0;
                while i < 8 {
                    buf[1 + i] = exp_be[i];
                    i += 1;
                }
                (buf, 9)
            }
            Self::ReadOnly => {
                buf[0] = 0x04;
                (buf, 1)
            }
        }
    }

    /// Evaluates whether `ctx` satisfies this caveat using overflow-free `u128` range bounds.
    pub const fn allows(&self, ctx: &AccessRequestContext) -> bool {
        match self {
            Self::AllowedManifest(allowed) => {
                let mut diff = 0u8;
                let mut i = 0;
                while i < 32 {
                    diff |= allowed[i] ^ ctx.manifest_root[i];
                    i += 1;
                }
                diff == 0
            }
            Self::ByteRange { offset, length } => {
                let req_start = ctx.offset as u128;
                let req_end = req_start + (ctx.length as u128);
                let cap_start = *offset as u128;
                let cap_end = cap_start + (*length as u128);
                req_start >= cap_start && req_end <= cap_end
            }
            Self::ExpiresAtUnixMs(expires_at_ms) => ctx.now_unix_ms <= *expires_at_ms,
            Self::ReadOnly => !ctx.is_write,
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

/// Constant-time 32-byte tag equality check (zero early-exit timing side channels).
#[inline]
pub const fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < 32 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// HMAC-SHA256 chained capability token enabling zero-knowledge, `< 1 ms` RAM-only authorization
/// of constrained manifest and byte-range reads without sharing `MasterKey` or `root_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[allow(clippy::too_many_arguments)]
    pub fn verify_caveat_slice_in_ram_with<R, C>(
        root_key: &[u8; 32],
        nonce_id: &[u8; 32],
        issuer_fingerprint: &[u8; 32],
        caveats: &[Caveat],
        tag: &[u8; 32],
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
            nonce_id,
            issuer_fingerprint,
            caveats,
            root_prf,
            chain_prf,
        )?;
        if !ct_eq_32(&expected_tag, tag) {
            return Err(CapabilityError::InvalidMacaroonTag);
        }
        let mut cidx = 0;
        while cidx < caveats.len() {
            if !caveats[cidx].allows(ctx) {
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
            &self.nonce_id,
            &self.issuer_fingerprint,
            self.caveats.as_slice(),
            &self.tag,
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

    /// Verifies structural bounds, expiration (`expires_at_unix_ms == 0 || now_unix_ms <= expires_at_unix_ms`),
    /// AND both legs of the composite `Ed25519 + NIST FIPS 204 ML-DSA-65` signature.
    pub fn verify(&self, now_unix_ms: u64) -> bool {
        if self.gateway_id.is_empty()
            || self.gateway_id.len() > MAX_GATEWAY_ID_BYTES
            || self.ed25519_transport_pubkey == [0u8; 32]
            || self.noise_static_x25519_pubkey == [0u8; 32]
        {
            return false;
        }
        if self.expires_at_unix_ms != 0 && now_unix_ms > self.expires_at_unix_ms {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

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
            .unwrap();

        let valid_ctx = AccessRequestContext {
            manifest_root: manifest_a,
            offset: 2048,
            length: 1024,
            is_write: false,
            now_unix_ms: 40_000,
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

        assert!(stmt.verify(25_000));
        assert!(!stmt.verify(60_001)); // Expired

        let mut tampered = stmt.clone();
        tampered.noise_static_x25519_pubkey[0] ^= 0xFF;
        assert!(!tampered.verify(25_000));
    }
}
