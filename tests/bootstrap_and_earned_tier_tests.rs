use parvault::bootstrap::{
    BootstrapError, EarnedStanding, ElasticBootstrapEngine, ElasticPeerCandidate, PeerRole,
    PersonalDeviceCert,
};
use parvault::crypto::pqc::{HybridPqSigningKeypair, PqVaultMasterKey};
use parvault::storage::quota::{PeerCreditAccount, TrustLevel};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};
use stateright::{Checker, Model, Property};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

/// ============================================================================
/// TEST 1: Mechanism 1 — Day-1 Personal Device Ring & Post-Quantum Cert Verification
/// ============================================================================
#[test]
fn test_mechanism1_day1_personal_device_ring_and_pq_cert_verification() {
    let owner_keypair = HybridPqSigningKeypair::generate().expect("PQ signing keypair");
    let owner_pub = owner_keypair.public_key();

    let attacker_keypair = HybridPqSigningKeypair::generate().expect("attacker PQ keypair");
    let attacker_pub = attacker_keypair.public_key();

    let cert_laptop = PersonalDeviceCert::issue(
        &owner_keypair,
        "peer-laptop-01",
        "device-laptop",
        1_750_000_000,
    )
    .expect("issue laptop cert");
    let cert_desktop = PersonalDeviceCert::issue(
        &owner_keypair,
        "peer-desktop-02",
        "device-desktop",
        1_750_000_001,
    )
    .expect("issue desktop cert");
    let cert_rpi = PersonalDeviceCert::issue(
        &owner_keypair,
        "peer-rpi-nas-03",
        "device-rpi-nas",
        1_750_000_002,
    )
    .expect("issue rpi nas cert");

    // Genuine certificates verify against owner's hybrid Ed25519 + ML-DSA-65 root key
    assert!(cert_laptop.verify(&owner_pub).is_ok());
    assert!(cert_desktop.verify(&owner_pub).is_ok());
    assert!(cert_rpi.verify(&owner_pub).is_ok());

    // Verification against a different owner root key must fail
    assert!(matches!(
        cert_laptop.verify(&attacker_pub),
        Err(BootstrapError::InvalidPersonalDeviceCert)
    ));

    // Bit-flipped ML-DSA-65 lattice signature must fail verification
    let mut forged_cert = cert_laptop.clone();
    forged_cert.owner_signature.ml_dsa_65_sig[42] ^= 0xFF;
    assert!(matches!(
        forged_cert.verify(&owner_pub),
        Err(BootstrapError::InvalidPersonalDeviceCert)
    ));

    // Bit-flipped Ed25519 classical signature must also fail verification
    let mut forged_ed_cert = cert_desktop.clone();
    forged_ed_cert.owner_signature.ed25519_sig[10] ^= 0x55;
    assert!(matches!(
        forged_ed_cert.verify(&owner_pub),
        Err(BootstrapError::InvalidPersonalDeviceCert)
    ));

    // Day-1 evaluation with 0 external peers:
    // - 1 personal device -> SoloPersonalVault (2-of-3 local stripe, 0.0 network quota tax)
    // - 3 personal devices -> PersonalDeviceRing (2-of-3 across Laptop + Desktop + RPi, 0.0 tax)
    let acct = PeerCreditAccount::default();
    let solo = EarnedStanding::evaluate(&acct, 1, 0, 0).expect("solo standing");
    assert_eq!(solo, EarnedStanding::SoloPersonalVault);
    assert_eq!(solo.erasure_params(), (2, 1, 3));
    assert_eq!(solo.reciprocity_expansion_tax(), 0.0);

    let ring = EarnedStanding::evaluate(&acct, 3, 0, 0).expect("personal ring standing");
    assert_eq!(ring, EarnedStanding::PersonalDeviceRing);
    assert_eq!(ring.erasure_params(), (2, 1, 3));
    assert_eq!(ring.reciprocity_expansion_tax(), 0.0);
}

/// ============================================================================
/// TEST 2: Earned Tier Progression & Automatic Downtime Demotion
/// ============================================================================
#[test]
fn test_earned_tier_progression_and_downtime_demotion() {
    let mut acct = PeerCreditAccount::default();
    let organic_peers = 100;

    // 1. Newly joined node (0 PoR passes) in a 100-node mesh CANNOT claim Homelab (16-of-20).
    //    It is strictly assigned ProbationaryConsumerPool (10-of-20, 2.00x expansion tax).
    assert_eq!(acct.trust_level(), TrustLevel::UntrustedProbationary);
    let initial_standing =
        EarnedStanding::evaluate(&acct, 1, organic_peers, 0).expect("initial standing");
    assert_eq!(initial_standing, EarnedStanding::ProbationaryConsumerPool);
    assert_eq!(initial_standing.erasure_params(), (10, 10, 20));
    assert!((initial_standing.reciprocity_expansion_tax() - 2.00).abs() < 1e-9);

    // 2. Simulate 50 consecutive PoR passes (100% SLA >= 98.0%) -> VerifiedNeighbor & EarnedVerifiedMixedPool (16-of-24, 1.50x)
    acct.por_passes = 50;
    assert_eq!(acct.trust_level(), TrustLevel::VerifiedNeighbor);
    let verified_standing =
        EarnedStanding::evaluate(&acct, 1, organic_peers, 0).expect("verified standing");
    assert_eq!(verified_standing, EarnedStanding::EarnedVerifiedMixedPool);
    assert_eq!(verified_standing.erasure_params(), (16, 8, 24));
    assert!((verified_standing.reciprocity_expansion_tax() - 1.50).abs() < 1e-9);

    // 3. Simulate 150 more consecutive PoR passes (total = 200, 100% SLA >= 99.8%) -> HighUptimeAnchor & EarnedHomelabAnchorPool (16-of-20, 1.25x)
    acct.por_passes = 200;
    assert_eq!(acct.trust_level(), TrustLevel::HighUptimeAnchor);
    let homelab_standing =
        EarnedStanding::evaluate(&acct, 1, organic_peers, 0).expect("homelab standing");
    assert_eq!(homelab_standing, EarnedStanding::EarnedHomelabAnchorPool);
    assert_eq!(homelab_standing.erasure_params(), (16, 4, 20));
    assert!((homelab_standing.reciprocity_expansion_tax() - 1.25).abs() < 1e-9);

    // 4. Simulate 2 PoR failures (200 / 202 = 99.01% < 99.8%) -> automatically demotes back to EarnedVerifiedMixedPool (16-of-24)
    acct.por_failures = 2;
    assert_eq!(acct.trust_level(), TrustLevel::VerifiedNeighbor);
    let demoted_once =
        EarnedStanding::evaluate(&acct, 1, organic_peers, 0).expect("demoted to verified");
    assert_eq!(demoted_once, EarnedStanding::EarnedVerifiedMixedPool);

    // 5. Simulate 5 more PoR failures (200 / 207 = 96.62% < 98.0%) -> automatically demotes back to ProbationaryConsumerPool (10-of-20)
    acct.por_failures = 7;
    assert_eq!(acct.trust_level(), TrustLevel::UntrustedProbationary);
    let demoted_twice =
        EarnedStanding::evaluate(&acct, 1, organic_peers, 0).expect("demoted to probationary");
    assert_eq!(demoted_twice, EarnedStanding::ProbationaryConsumerPool);

    // 6. Simulate Byzantine slashing (is_slashed = true) -> NodeSlashedQuarantined error
    acct.is_slashed = true;
    assert_eq!(acct.trust_level(), TrustLevel::SlashedQuarantined);
    assert!(matches!(
        EarnedStanding::evaluate(&acct, 1, organic_peers, 0),
        Err(BootstrapError::NodeSlashedQuarantined)
    ));
}

/// ============================================================================
/// TEST 3: Mechanism 2 — Foundation Seed Anchor Fallback & Organic Drain to 10,000 Peers
/// ============================================================================
#[test]
fn test_mechanism2_foundation_seed_anchor_fallback_and_organic_drain_to_10k_scale() {
    let standing = EarnedStanding::ProbationaryConsumerPool; // 10-of-20 (20 shards)
    let mut candidates = Vec::new();

    // 4 organic peers on distinct /24 subnets
    for i in 0..4 {
        candidates.push(ElasticPeerCandidate {
            peer_id: format!("organic-peer-{i:04}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("10.0.{i}.0/24"),
            trust_level: TrustLevel::VerifiedNeighbor,
            rtt_ms: 15 + i as u64,
            committed_standby_bytes: 100 * 1024 * 1024 * 1024,
        });
    }
    // 20 Foundation Seed Anchors
    for s in 0..20 {
        candidates.push(ElasticPeerCandidate {
            peer_id: format!("foundation-seed-{s:02}"),
            role: PeerRole::FoundationSeedAnchor,
            subnet_prefix: format!("198.51.{}.0/24", 100 + (s % 4)),
            trust_level: TrustLevel::HighUptimeAnchor,
            rtt_ms: 40 + s as u64,
            committed_standby_bytes: 0,
        });
    }

    // Initial placement: 4 organic peers selected first, 16 shards fall back to FoundationSeedAnchor
    let mut placements = ElasticBootstrapEngine::select_elastic_targets(standing, &candidates);
    assert_eq!(placements.len(), 20);
    let initial_organic = placements
        .iter()
        .filter(|p| p.role == PeerRole::OrganicCommunityPeer)
        .count();
    let initial_seed = placements
        .iter()
        .filter(|p| p.role == PeerRole::FoundationSeedAnchor)
        .count();
    assert_eq!(initial_organic, 4);
    assert_eq!(initial_seed, 16);

    // Grow organic pool from 4 to 12 peers (+8 new organic peers)
    for i in 4..12 {
        candidates.push(ElasticPeerCandidate {
            peer_id: format!("organic-peer-{i:04}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("10.0.{i}.0/24"),
            trust_level: TrustLevel::VerifiedNeighbor,
            rtt_ms: 20 + i as u64,
            committed_standby_bytes: 100 * 1024 * 1024 * 1024,
        });
    }
    let drain_wave_1 =
        ElasticBootstrapEngine::plan_seed_anchor_drain(standing, &placements, &candidates);
    assert_eq!(drain_wave_1.len(), 8);

    // Apply wave 1 migrations
    for mig in &drain_wave_1 {
        let slot = &mut placements[mig.shard_index];
        assert_eq!(slot.peer_id, mig.from_seed_anchor_id);
        slot.peer_id = mig.to_organic_peer_id.clone();
        slot.role = PeerRole::OrganicCommunityPeer;
        slot.subnet_prefix = mig.to_subnet_prefix.clone();
    }
    let remaining_seed_after_wave_1 = placements
        .iter()
        .filter(|p| p.role == PeerRole::FoundationSeedAnchor)
        .count();
    assert_eq!(remaining_seed_after_wave_1, 8);

    // Grow organic pool from 12 to 25 peers across distinct /24 subnets
    for i in 12..25 {
        candidates.push(ElasticPeerCandidate {
            peer_id: format!("organic-peer-{i:04}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("10.0.{i}.0/24"),
            trust_level: TrustLevel::VerifiedNeighbor,
            rtt_ms: 20 + i as u64,
            committed_standby_bytes: 100 * 1024 * 1024 * 1024,
        });
    }
    let drain_wave_2 =
        ElasticBootstrapEngine::plan_seed_anchor_drain(standing, &placements, &candidates);
    assert_eq!(drain_wave_2.len(), 8);

    for mig in &drain_wave_2 {
        let slot = &mut placements[mig.shard_index];
        slot.peer_id = mig.to_organic_peer_id.clone();
        slot.role = PeerRole::OrganicCommunityPeer;
        slot.subnet_prefix = mig.to_subnet_prefix.clone();
    }
    let remaining_seed_after_wave_2 = placements
        .iter()
        .filter(|p| p.role == PeerRole::FoundationSeedAnchor)
        .count();
    assert_eq!(
        remaining_seed_after_wave_2, 0,
        "Foundation Seed Anchors must drain to 0% once organic peers >= N"
    );

    // Scale to 10,000 organic peers across 2,500 /24 subnets at EarnedHomelabAnchorPool (16-of-20)
    let mut scale_10k_candidates = Vec::with_capacity(10_020);
    for i in 0..10_000 {
        let subnet_id = i / 4; // 2,500 distinct /24 subnets (4 peers per subnet)
        scale_10k_candidates.push(ElasticPeerCandidate {
            peer_id: format!("mesh10k-peer-{i:05}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("172.{}.{}.0/24", (subnet_id / 256) % 256, subnet_id % 256),
            trust_level: if i % 3 == 0 {
                TrustLevel::HighUptimeAnchor
            } else {
                TrustLevel::VerifiedNeighbor
            },
            rtt_ms: 5 + (i % 50) as u64,
            committed_standby_bytes: 500 * 1024 * 1024 * 1024,
        });
    }

    let start = Instant::now();
    let targets_10k = ElasticBootstrapEngine::select_elastic_targets(
        EarnedStanding::EarnedHomelabAnchorPool,
        &scale_10k_candidates,
    );
    let elapsed = start.elapsed();

    assert_eq!(targets_10k.len(), 20);
    assert!(
        elapsed.as_millis() < 50,
        "10,000-node placement selection took {} ms (expected < 50 ms)",
        elapsed.as_millis()
    );

    let mut per_subnet: HashMap<String, usize> = HashMap::new();
    for t in &targets_10k {
        assert_eq!(t.role, PeerRole::OrganicCommunityPeer);
        *per_subnet.entry(t.subnet_prefix.clone()).or_insert(0) += 1;
    }
    let cap = EarnedStanding::EarnedHomelabAnchorPool.max_shards_per_subnet_fault_domain();
    assert_eq!(cap, 4);
    for count in per_subnet.values() {
        assert!(*count <= cap);
    }
}

/// ============================================================================
/// TEST 4: Mechanism 3 — Zero-Knowledge Elastic Ciphertext Re-Sharding (2-of-3 -> 16-of-20)
/// ============================================================================
#[test]
fn test_mechanism3_zero_knowledge_elastic_ciphertext_resharding_2of3_to_16of20() {
    // 1. Encrypt a 64 KiB payload using 512-bit PqVaultMasterKey (Cascaded AEAD)
    let pq_master_key = PqVaultMasterKey::generate();
    let file_salt = [0x42u8; 32];
    let stripe_index = 7u64;
    let plaintext: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i * 31 + 17) & 0xFF) as u8)
        .collect();

    let ciphertext = pq_master_key
        .encrypt_stripe_pq(&file_salt, stripe_index, &plaintext)
        .expect("512-bit PQ stripe encryption");
    let expected_ct_hash: [u8; 32] = Sha256::digest(&ciphertext).into();

    // 2. Day-1: Encode ciphertext as SoloPersonalVault (2-of-3)
    let (shards_2of3, _root_2of3) = ElasticBootstrapEngine::encode_ciphertext_elastic(
        EarnedStanding::SoloPersonalVault,
        &ciphertext,
    )
    .expect("encode 2-of-3");
    assert_eq!(shards_2of3.len(), 3);

    // Drop 1 shard (2 surviving out of 3) and re-shard into BuddyMicroCluster (3-of-5) WITHOUT pq_master_key
    let mut surviving_2of3: Vec<Option<Vec<u8>>> = shards_2of3.into_iter().map(Some).collect();
    surviving_2of3[1] = None;

    let (shards_3of5, _root_3of5) = ElasticBootstrapEngine::reshard_ciphertext_stripe_elastic(
        EarnedStanding::SoloPersonalVault,
        EarnedStanding::BuddyMicroCluster,
        surviving_2of3,
        ciphertext.len(),
        &expected_ct_hash,
    )
    .expect("zero-knowledge reshard 2-of-3 -> 3-of-5");
    assert_eq!(shards_3of5.len(), 5);

    // 3. Drop 2 shards from 3-of-5 (3 surviving) and re-shard into ProbationaryConsumerPool (10-of-20)
    let mut surviving_3of5: Vec<Option<Vec<u8>>> = shards_3of5.into_iter().map(Some).collect();
    surviving_3of5[0] = None;
    surviving_3of5[4] = None;

    let (shards_10of20, _root_10of20) = ElasticBootstrapEngine::reshard_ciphertext_stripe_elastic(
        EarnedStanding::BuddyMicroCluster,
        EarnedStanding::ProbationaryConsumerPool,
        surviving_3of5,
        ciphertext.len(),
        &expected_ct_hash,
    )
    .expect("zero-knowledge reshard 3-of-5 -> 10-of-20");
    assert_eq!(shards_10of20.len(), 20);

    // 4. Drop 10 shards from 10-of-20 (10 surviving) and re-shard into EarnedHomelabAnchorPool (16-of-20)
    let mut surviving_10of20: Vec<Option<Vec<u8>>> = shards_10of20.into_iter().map(Some).collect();
    for i in (0..20).step_by(2) {
        surviving_10of20[i] = None; // Drop 10 shards, leaving 10
    }

    let (shards_16of20, _root_16of20) = ElasticBootstrapEngine::reshard_ciphertext_stripe_elastic(
        EarnedStanding::ProbationaryConsumerPool,
        EarnedStanding::EarnedHomelabAnchorPool,
        surviving_10of20,
        ciphertext.len(),
        &expected_ct_hash,
    )
    .expect("zero-knowledge reshard 10-of-20 -> 16-of-20");
    assert_eq!(shards_16of20.len(), 20);

    // 5. Drop 4 shards from 16-of-20 (16 surviving), reconstruct outer ciphertext, and decrypt with PqVaultMasterKey
    let mut surviving_16of20: Vec<Option<Vec<u8>>> = shards_16of20.into_iter().map(Some).collect();
    surviving_16of20[2] = None;
    surviving_16of20[7] = None;
    surviving_16of20[13] = None;
    surviving_16of20[19] = None;

    let rs_16of20 = ReedSolomon::new(16, 4).expect("RS 16-of-20");
    rs_16of20
        .reconstruct(&mut surviving_16of20)
        .expect("reconstruct 16-of-20");

    let mut final_ciphertext = Vec::with_capacity(ciphertext.len());
    for shard_opt in surviving_16of20.into_iter().take(16) {
        final_ciphertext.extend_from_slice(&shard_opt.unwrap());
    }
    final_ciphertext.truncate(ciphertext.len());
    assert_eq!(final_ciphertext, ciphertext);

    let recovered_plaintext = pq_master_key
        .decrypt_stripe_pq(&file_salt, stripe_index, &final_ciphertext)
        .expect("decrypt 512-bit PQ stripe after 3 elastic re-shardings");
    assert_eq!(recovered_plaintext, plaintext);
}

/// ============================================================================
/// TEST 5: Mechanism 4 — Pioneer Standby Mining, /24 Subnet Sybil Conservation & Stateright Model
/// ============================================================================
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ElasticGrowthState {
    personal_devices: usize,
    organic_peers: usize,
    seed_anchors: usize,
    por_passes: u64,
    por_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ElasticGrowthAction {
    AddPersonalDevice,
    JoinOrganicCohort(usize),
    PassPorAuditBatch(u64),
    FailPorAuditBatch(u64),
}

struct ElasticGrowthModel;

impl Model for ElasticGrowthModel {
    type State = ElasticGrowthState;
    type Action = ElasticGrowthAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![ElasticGrowthState {
            personal_devices: 1,
            organic_peers: 0,
            seed_anchors: 20,
            por_passes: 0,
            por_failures: 0,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.personal_devices < 3 {
            actions.push(ElasticGrowthAction::AddPersonalDevice);
        }
        if state.organic_peers == 0 {
            actions.push(ElasticGrowthAction::JoinOrganicCohort(4));
        } else if state.organic_peers == 4 {
            actions.push(ElasticGrowthAction::JoinOrganicCohort(25));
        }
        if state.por_passes < 200 {
            actions.push(ElasticGrowthAction::PassPorAuditBatch(50));
        }
        if state.por_passes >= 200 && state.por_failures == 0 {
            actions.push(ElasticGrowthAction::FailPorAuditBatch(5));
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next = last.clone();
        match action {
            ElasticGrowthAction::AddPersonalDevice => {
                next.personal_devices += 1;
            }
            ElasticGrowthAction::JoinOrganicCohort(new_total) => {
                next.organic_peers = new_total;
            }
            ElasticGrowthAction::PassPorAuditBatch(n) => {
                next.por_passes += n;
            }
            ElasticGrowthAction::FailPorAuditBatch(n) => {
                next.por_failures += n;
            }
        }
        Some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("HomelabNeverGrantedWithoutHighUptime", |_model, state| {
                let acct = PeerCreditAccount {
                    por_passes: state.por_passes,
                    por_failures: state.por_failures,
                    ..Default::default()
                };
                let standing = EarnedStanding::evaluate(
                    &acct,
                    state.personal_devices,
                    state.organic_peers,
                    if state.organic_peers == 0 {
                        0
                    } else {
                        state.seed_anchors
                    },
                )
                .unwrap();
                if standing == EarnedStanding::EarnedHomelabAnchorPool {
                    acct.trust_level() == TrustLevel::HighUptimeAnchor
                } else {
                    true
                }
            }),
            Property::<Self>::always("SeedAnchorsDrainWhenOrganicSufficient", |_model, state| {
                if state.organic_peers >= 25 {
                    let mut cands = Vec::new();
                    for i in 0..state.organic_peers {
                        cands.push(ElasticPeerCandidate {
                            peer_id: format!("org-{i}"),
                            role: PeerRole::OrganicCommunityPeer,
                            subnet_prefix: format!("10.1.{i}.0/24"),
                            trust_level: TrustLevel::HighUptimeAnchor,
                            rtt_ms: 10,
                            committed_standby_bytes: 1024,
                        });
                    }
                    for s in 0..state.seed_anchors {
                        cands.push(ElasticPeerCandidate {
                            peer_id: format!("seed-{s}"),
                            role: PeerRole::FoundationSeedAnchor,
                            subnet_prefix: format!("198.51.{s}.0/24"),
                            trust_level: TrustLevel::HighUptimeAnchor,
                            rtt_ms: 50,
                            committed_standby_bytes: 0,
                        });
                    }
                    let targets = ElasticBootstrapEngine::select_elastic_targets(
                        EarnedStanding::EarnedHomelabAnchorPool,
                        &cands,
                    );
                    targets
                        .iter()
                        .all(|t| t.role == PeerRole::OrganicCommunityPeer)
                } else {
                    true
                }
            }),
            Property::<Self>::always("DataAlwaysRecoverable", |_model, state| {
                let acct = PeerCreditAccount {
                    por_passes: state.por_passes,
                    por_failures: state.por_failures,
                    ..Default::default()
                };
                let standing = EarnedStanding::evaluate(
                    &acct,
                    state.personal_devices,
                    state.organic_peers,
                    if state.organic_peers == 0 {
                        0
                    } else {
                        state.seed_anchors
                    },
                )
                .unwrap();
                let (k, m, n) = standing.erasure_params();
                k >= 2 && m >= 1 && k + m == n
            }),
            Property::<Self>::sometimes("ReachesEarnedHomelab16of20", |_model, state| {
                let acct = PeerCreditAccount {
                    por_passes: state.por_passes,
                    por_failures: state.por_failures,
                    ..Default::default()
                };
                let standing = EarnedStanding::evaluate(
                    &acct,
                    state.personal_devices,
                    state.organic_peers,
                    state.seed_anchors,
                )
                .unwrap();
                standing == EarnedStanding::EarnedHomelabAnchorPool && state.organic_peers >= 25
            }),
        ]
    }
}

#[test]
fn test_mechanism4_pioneer_standby_mining_subnet_sybil_conservation_and_stateright_model() {
    let mut accounts: BTreeMap<String, PeerCreditAccount> = BTreeMap::new();
    let mut candidates = Vec::new();
    let mut passed = HashMap::new();

    let hundred_gib: u64 = 100 * 1024 * 1024 * 1024;

    // Subnet A: 1 honest pioneer node on 192.168.10.0/24 committing 100 GiB
    candidates.push(ElasticPeerCandidate {
        peer_id: "honest-pioneer-node".to_string(),
        role: PeerRole::OrganicCommunityPeer,
        subnet_prefix: "192.168.10.0/24".to_string(),
        trust_level: TrustLevel::UntrustedProbationary,
        rtt_ms: 12,
        committed_standby_bytes: hundred_gib,
    });
    passed.insert("honest-pioneer-node".to_string(), true);

    // Subnet B: 20 Sybil Docker containers on 192.168.20.0/24 each claiming 100 GiB on the same home router
    for sybil_idx in 0..20 {
        let id = format!("sybil-container-{sybil_idx:02}");
        candidates.push(ElasticPeerCandidate {
            peer_id: id.clone(),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: "192.168.20.0/24".to_string(),
            trust_level: TrustLevel::UntrustedProbationary,
            rtt_ms: 12,
            committed_standby_bytes: hundred_gib,
        });
        passed.insert(id, true);
    }

    // Accrue 1 bootstrap epoch at 0% initial network utilization (pioneer_standby_rate = 10%)
    let minted = ElasticBootstrapEngine::accrue_standby_uptime_epoch(
        &mut accounts,
        &candidates,
        &passed,
        0.0,
    );

    let honest_credit = minted["honest-pioneer-node"];
    let sybil_total_credit: u64 = (0..20)
        .map(|i| minted[&format!("sybil-container-{i:02}")])
        .sum();

    // Exact /24 Subnet Conservation: 20 Sybil nodes claiming 100 GiB each on the same /24
    // earn the EXACT same aggregate credit (10 GiB) as 1 honest node committing 100 GiB!
    let expected_ten_gib = (hundred_gib as f64 * 0.10) as u64;
    assert_eq!(honest_credit, expected_ten_gib);
    assert_eq!(
        sybil_total_credit, honest_credit,
        "20 Sybil containers on the same /24 subnet must earn the exact same aggregate credit as 1 honest node"
    );

    // Also run the Stateright model checker over the elastic Day-1-to-10,000-user state space
    let checker = ElasticGrowthModel.checker().spawn_bfs().join();
    checker.assert_properties();
}

/// ============================================================================
/// TEST 6: Mechanism 5 — Departing Node Blinded Lease Expiry & Tombstone Eviction
/// ============================================================================
#[test]
fn test_mechanism5_departing_node_blinded_lease_expiry_and_tombstone_eviction() {
    use parvault::bootstrap::{BlindedShardLeaseManager, BlindedShardTombstone};

    // Storage node has 300 KiB capacity and 2-epoch grace window
    let shard_size = 100 * 1024;
    let mut lease_mgr = BlindedShardLeaseManager::new(3 * shard_size, 2);

    let shard_a = [0xAAu8; 32]; // Owned by Departing Peer X (never renewed)
    let shard_b = [0xBBu8; 32]; // Owned by Active Peer Y (renewed every epoch)
    let shard_c = [0xCCu8; 32]; // Owned by Graceful Peer Z (deleted via Tombstone)

    let cap_secret_x = [0x11u8; 32];
    let cap_secret_y = [0x22u8; 32];
    let cap_secret_z = [0x33u8; 32];

    let verifier_a = BlindedShardTombstone::derive_delete_verifier(&cap_secret_x, &shard_a);
    let verifier_b = BlindedShardTombstone::derive_delete_verifier(&cap_secret_y, &shard_b);
    let verifier_c = BlindedShardTombstone::derive_delete_verifier(&cap_secret_z, &shard_c);

    // Epoch 1: All 3 blinded shards are stored with a 5-epoch lease (expires at epoch 6, grace until epoch 8)
    assert!(lease_mgr
        .store_with_lease(shard_a, shard_size, 1, 5, verifier_a)
        .is_empty());
    assert!(lease_mgr
        .store_with_lease(shard_b, shard_size, 1, 5, verifier_b)
        .is_empty());
    assert!(lease_mgr
        .store_with_lease(shard_c, shard_size, 1, 5, verifier_c)
        .is_empty());
    assert_eq!(lease_mgr.active_shard_count(), 3);
    assert_eq!(lease_mgr.used_bytes(), 3 * shard_size);

    // 1. Graceful Departure / Deletion: Peer Z deletes shard_c. Authorisation (a signature by
    //    the capability key, F-41) is `BlockStore::delete_blinded_shard_signed`; the lease
    //    manager only removes the lease.
    assert!(
        lease_mgr.remove_lease(&shard_c),
        "removing shard_c's lease must purge it immediately"
    );
    assert!(
        !lease_mgr.remove_lease(&shard_c),
        "a second removal finds nothing"
    );
    assert_eq!(lease_mgr.active_shard_count(), 2);
    assert_eq!(lease_mgr.used_bytes(), 2 * shard_size);

    // Fill the freed slot with shard_d ([0xDD; 32]) at epoch 4 (expires at epoch 9)
    let shard_d = [0xDDu8; 32];
    let verifier_d = BlindedShardTombstone::derive_delete_verifier(&cap_secret_y, &shard_d);
    assert!(lease_mgr
        .store_with_lease(shard_d, shard_size, 4, 5, verifier_d)
        .is_empty());
    assert_eq!(lease_mgr.active_shard_count(), 3);

    // 2. Active Peer Y renews shard_b at epoch 5 (extending lease to epoch 15),
    //    while Peer X permanently leaves the network and NEVER renews shard_a!
    assert!(lease_mgr.renew_lease(&shard_b, 5, 10));

    // 3. Lazy Retention at Epoch 9 (shard_a expired at 6 + 2 grace = 8, so it is eligible for eviction,
    //    but no new shard has demanded space yet, so shard_a lazily remains on disk!):
    assert_eq!(lease_mgr.active_shard_count(), 3);

    // 4. Disk Pressure at Epoch 9: New shard_e ([0xEE; 32]) arrives needing 100 KiB.
    //    Storage node automatically evicts ONLY Peer X's expired shard_a without ever knowing Peer X's identity!
    let shard_e = [0xEEu8; 32];
    let verifier_e = BlindedShardTombstone::derive_delete_verifier(&cap_secret_y, &shard_e);
    let evicted = lease_mgr.store_with_lease(shard_e, shard_size, 9, 5, verifier_e);
    assert_eq!(
        evicted,
        vec![shard_a],
        "Departed Peer X's un-renewed blinded shard_a must be automatically evicted under disk pressure"
    );
    assert_eq!(lease_mgr.active_shard_count(), 3);
    assert_eq!(lease_mgr.used_bytes(), 3 * shard_size);
}

/// ============================================================================
/// TEST 7: Mechanism 6 — End-to-End BlockStore Physical Disk Deletion Over Time
/// ============================================================================
#[test]
fn test_mechanism6_blockstore_physical_file_deletion_over_time_on_lease_expiry_and_tombstone() {
    use parvault::bootstrap::BlindedShardTombstone;
    use parvault::crypto::keys::{MasterKey, NodeIdentity};
    use parvault::storage::anonymity::{
        AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, VoucherNullifierLedger,
    };
    use parvault::storage::{BlockStore, QuotaManager, StorageError};

    let tmp_dir = tempfile::tempdir().expect("tempdir for BlockStore eviction over time");
    let shard_len = 4096usize;
    // Storage node configured with 2-shard capacity (8 KiB) and a 2-epoch grace window
    let quota = QuotaManager::new((2 * shard_len) as u64, (2 * shard_len) as u64);
    let store = BlockStore::new(tmp_dir.path(), quota).expect("init BlockStore");
    store.set_blinded_lease_policy((2 * shard_len) as u64, 2);

    let issuer_identity = NodeIdentity::from_seed([0x55u8; 32]);
    let mut nullifier_ledger = VoucherNullifierLedger::new(issuer_identity.public_key_bytes());

    let master_x = MasterKey::from_bytes([0xA1u8; 32]); // Departing Node X
    let master_y = MasterKey::from_bytes([0xB2u8; 32]); // Active Node Y
    let stripe_root = [0x99u8; 32];

    // 1. Epoch 1: Node X stores shard_x (lease = 5 epochs -> expires at epoch 6, grace until epoch 8)
    let bytes_x = vec![0x41u8; shard_len];
    let bid_x = BlindedShardId::derive(&master_x, &stripe_root, 0, &bytes_x);
    let (cap_id_x, cap_x) = BlindedShardCapability::derive_keypair(&master_x, &bid_x.locator);
    let read_sig_x = BlindedShardCapability::sign_read_token(&cap_id_x, &bid_x.locator, 1_000);
    let verifier_x = BlindedShardTombstone::derive_delete_verifier(&[0xA1u8; 32], &bid_x.locator);
    let voucher_x = AnonymousQuotaVoucher::mint(&issuer_identity, shard_len as u64);

    let path_x = store
        .put_blinded_shard_with_lease(
            &bid_x,
            &bytes_x,
            cap_x,
            &voucher_x,
            &mut nullifier_ledger,
            parvault::storage::BlindedLeaseSpec::new(1, 5, verifier_x),
        )
        .expect("store shard_x at epoch 1");
    assert!(
        path_x.exists(),
        "shard_x .bshard file must exist on disk at epoch 1"
    );
    assert!(store.has_blinded_shard_on_disk(&bid_x));

    // 2. Epoch 1: Node Y stores shard_y (lease = 5 epochs -> expires at epoch 6)
    let bytes_y = vec![0x42u8; shard_len];
    let bid_y = BlindedShardId::derive(&master_y, &stripe_root, 1, &bytes_y);
    let (cap_id_y, cap_y) = BlindedShardCapability::derive_keypair(&master_y, &bid_y.locator);
    let read_sig_y = BlindedShardCapability::sign_read_token(&cap_id_y, &bid_y.locator, 1_000);
    let verifier_y = BlindedShardTombstone::derive_delete_verifier(&[0xB2u8; 32], &bid_y.locator);
    let voucher_y = AnonymousQuotaVoucher::mint(&issuer_identity, shard_len as u64);

    let path_y = store
        .put_blinded_shard_with_lease(
            &bid_y,
            &bytes_y,
            cap_y,
            &voucher_y,
            &mut nullifier_ledger,
            parvault::storage::BlindedLeaseSpec::new(1, 5, verifier_y),
        )
        .expect("store shard_y at epoch 1");
    assert!(
        path_y.exists(),
        "shard_y .bshard file must exist on disk at epoch 1"
    );

    // 3. Epoch 4 (Before Lease Expiry) & Epoch 7 (Inside Grace Window):
    //    Node Y renews shard_y at Epoch 4 (+10 epochs -> expires at epoch 14), while Node X leaves the network!
    assert!(store.renew_blinded_shard_lease(&bid_y, 4, 10));
    let swept_epoch4 = store
        .sweep_expired_blinded_shards(4)
        .expect("sweep epoch 4");
    assert!(swept_epoch4.is_empty());
    let swept_epoch7 = store
        .sweep_expired_blinded_shards(7)
        .expect("sweep epoch 7 (inside grace)");
    assert!(
        swept_epoch7.is_empty(),
        "Shard X must NOT be deleted at epoch 7 while still inside its 2-epoch grace window (6 + 2 = 8)"
    );
    assert!(path_x.exists(), "shard_x file still on disk at epoch 7");

    // 4. Epoch 8 (Lease 6 + Grace 2 Reached): Time-based sweep physically deletes Node X's .bshard file!
    let swept_epoch8 = store
        .sweep_expired_blinded_shards(8)
        .expect("sweep epoch 8");
    assert_eq!(swept_epoch8, vec![bid_x]);
    assert!(
        !path_x.exists(),
        "Departed Node X's .bshard file MUST be physically deleted from disk at epoch 8"
    );
    assert!(!store.has_blinded_shard_on_disk(&bid_x));
    let read_deleted_x =
        store.get_blinded_shard_authorized(&bid_x, &cap_x, 1_000, &read_sig_x, 1_000);
    assert!(
        matches!(read_deleted_x, Err(StorageError::ShardNotFound(_))),
        "Reading departed Node X's evicted shard must return Err(StorageError::ShardNotFound)"
    );

    // Meanwhile, Active Node Y's renewed shard_y is still intact on disk and readable!
    assert!(path_y.exists());
    let read_y = store
        .get_blinded_shard_authorized(&bid_y, &cap_y, 1_000, &read_sig_y, 1_000)
        .expect("Active Node Y shard remains readable");
    assert_eq!(read_y, bytes_y);

    // 5. Graceful deletion on disk (F-41): Node Y signs a delete with shard_y's capability key
    //    for this host.
    let host = [0x5Au8; 32];
    let del_sig = BlindedShardCapability::sign_delete(&cap_id_y, &host, &bid_y, 1_000);
    let deleted_y = store
        .delete_blinded_shard_signed(&bid_y, 1_000, &del_sig, &host, 1_000)
        .expect("signed delete shard_y");
    assert!(deleted_y);
    assert!(
        !path_y.exists(),
        "Tombstoned .bshard file must be physically unlinked from the filesystem immediately"
    );
    assert!(matches!(
        store.get_blinded_shard_authorized(&bid_y, &cap_y, 1_000, &read_sig_y, 1_000),
        Err(StorageError::ShardNotFound(_))
    ));
}

/// ============================================================================
/// TEST 8: Mechanism 7 — 2,000-Node Correlated ISP Outage Waves
///         (2,000 Total -> -1,000 Down -> -500 More Down -> +500 Return)
/// ============================================================================
#[test]
fn test_mechanism7_2000_node_isp_mass_outage_waves_1000_down_500_down_500_up() {
    use parvault::bootstrap::CorrelatedOutageController;

    let total_nodes = 2_000usize;
    let num_stripes = 100usize;
    let standing = EarnedStanding::ProbationaryConsumerPool; // 10-of-20 (K=10, M=10, N=20)

    // Place 100 stripes (20 shards each = 2,000 shards) spread evenly across 20 ISPs (100 nodes/ISP)
    // so each stripe has 1 shard in each of the 20 ISP fault domains.
    let mut stripe_assignments: Vec<Vec<usize>> = Vec::with_capacity(num_stripes);
    for s in 0..num_stripes {
        let mut peers = Vec::with_capacity(20);
        for isp in 0..20 {
            let node_idx = isp * 100 + (s % 100);
            peers.push(node_idx);
        }
        stripe_assignments.push(peers);
    }

    // Wave 0: Baseline — all 2,000 nodes online across all 20 ISPs
    let mask_wave0 = vec![true; total_nodes];
    let report0 = CorrelatedOutageController::evaluate_outage_wave(
        "Wave 0: Baseline (2,000/2,000 Online)",
        standing,
        total_nodes,
        &mask_wave0,
        &mask_wave0,
        &stripe_assignments,
    );
    assert_eq!(report0.online_nodes, 2_000);
    assert!(!report0.circuit_breaker_active);
    assert_eq!(report0.stripes_immediately_readable, 100);
    assert_eq!(report0.stripes_hibernating_zero_data_loss, 0);

    // Wave 1: 1,000 nodes go down simultaneously (10 of 20 ISPs suffer total blackout -> 1,000 online)
    let mut mask_wave1 = vec![true; total_nodes];
    for slot in mask_wave1.iter_mut().take(1_000) {
        *slot = false;
    }
    let report1 = CorrelatedOutageController::evaluate_outage_wave(
        "Wave 1: -1,000 ISP Nodes Down (1,000/2,000 Online)",
        standing,
        total_nodes,
        &mask_wave0,
        &mask_wave1,
        &stripe_assignments,
    );
    assert_eq!(report1.online_nodes, 1_000);
    assert_eq!(report1.offline_nodes, 1_000);
    assert!(
        report1.circuit_breaker_active && report1.por_sla_penalties_frozen,
        "50% mass ISP outage must trip the circuit breaker and freeze PoR SLA demotions"
    );
    // With 10-of-20 (K=10) and ASN-diversified placement, 10 shards per stripe are STILL online!
    assert_eq!(
        report1.stripes_immediately_readable, 100,
        "All 100 stripes remain immediately readable (10/20 shards online) even with 1,000 nodes down!"
    );

    // Wave 2: Another 500 nodes go down (1,500/2,000 offline = 75% blackout, only 500 online)
    let mut mask_wave2 = mask_wave1.clone();
    for slot in mask_wave2.iter_mut().take(1_500).skip(1_000) {
        *slot = false;
    }
    let report2 = CorrelatedOutageController::evaluate_outage_wave(
        "Wave 2: -500 More Nodes Down (500/2,000 Online, 75% Outage)",
        standing,
        total_nodes,
        &mask_wave1,
        &mask_wave2,
        &stripe_assignments,
    );
    assert_eq!(report2.online_nodes, 500);
    assert_eq!(report2.offline_nodes, 1_500);
    assert!(report2.circuit_breaker_active);
    // With 75% of the network dark (only 5/20 shards reachable < K=10), stripes cleanly hibernate
    // with ZERO data loss (shards remain on the 1,500 offline nodes' disks within their 30-day lease).
    assert_eq!(report2.stripes_immediately_readable, 0);
    assert_eq!(report2.stripes_hibernating_zero_data_loss, 100);
    assert_eq!(report2.permanent_data_loss_stripes, 0);

    // Wave 3: 500 of the first 1,000 offline nodes come back online (1,000/2,000 online again!)
    let mut mask_wave3 = mask_wave2.clone();
    for slot in mask_wave3.iter_mut().take(500) {
        *slot = true;
    }
    let report3 = CorrelatedOutageController::evaluate_outage_wave(
        "Wave 3: +500 Nodes Return from Wave 1 (1,000/2,000 Online)",
        standing,
        total_nodes,
        &mask_wave2,
        &mask_wave3,
        &stripe_assignments,
    );
    assert_eq!(report3.online_nodes, 1_000);
    assert_eq!(
        report3.zero_bandwidth_rejoined_shards, 500,
        "All 500 returning shards snap back into the mesh from local disk with 0 bytes re-uploaded!"
    );
    assert_eq!(
        report3.stripes_immediately_readable, 100,
        "All 100 stripes immediately resume 100% online readability as soon as the 500 nodes return!"
    );
    assert_eq!(report3.stripes_hibernating_zero_data_loss, 0);
    assert_eq!(report3.permanent_data_loss_stripes, 0);

    // --- Part B: What happens to 16-of-20 (EarnedHomelabAnchorPool) under 50% Outage? ---
    // 1. Naive 16-of-20 with 50% (10/20) shards offline has only 10 shards (< K=16), so it pauses.
    // 2. With Elastic Surge Parity (`synthesize_surge_parity_shards`: 16-of-20 -> 16-of-28) +
    //    Failure Co-Variance Anti-Correlation (`select_decorrelated_targets`), the stripe survives
    //    BOTH a 100% single-power-grid/ISP wipeout AND 12 simultaneous dead shards!
    let pq_key = PqVaultMasterKey::generate();
    let salt = [0x33u8; 32];
    let pt = vec![0x7Au8; 32 * 1024];
    let ct = pq_key.encrypt_stripe_pq(&salt, 0, &pt).expect("encrypt pq");
    let ct_sha: [u8; 32] = Sha256::digest(&ct).into();

    let (shards_16of20, _root) = ElasticBootstrapEngine::encode_ciphertext_elastic(
        EarnedStanding::EarnedHomelabAnchorPool,
        &ct,
    )
    .expect("encode 16-of-20");

    // Simulate rolling outage beginning: 3 nodes drop (17/20 surviving >= 16), triggering +8 Surge Parity shards (16-of-28)
    let mut surviving_17: Vec<Option<Vec<u8>>> = shards_16of20.into_iter().map(Some).collect();
    surviving_17[0] = None;
    surviving_17[1] = None;
    surviving_17[2] = None;

    let extended_16of28 = CorrelatedOutageController::synthesize_surge_parity_shards(
        EarnedStanding::EarnedHomelabAnchorPool,
        surviving_17,
        ct.len(),
        &ct_sha,
        8, // +8 emergency surge parity shards -> 16-of-28 (tolerates 12 dead shards!)
    )
    .expect("synthesize 16-of-28 surge parity over ciphertext");
    assert_eq!(extended_16of28.len(), 28);

    // Now kill 12 out of 28 shards (including 10 of the original 20 shards = 50% base loss!):
    // 16 shards survive out of 28 -> full 16-of-20 Homelab recovery succeeds during the outage!
    let mut after_12_killed: Vec<Option<Vec<u8>>> = extended_16of28.into_iter().map(Some).collect();
    for slot in after_12_killed.iter_mut().take(12) {
        *slot = None;
    }
    let rs_16of28 = ReedSolomon::new(16, 12).expect("RS 16-of-28");
    rs_16of28
        .reconstruct(&mut after_12_killed)
        .expect("reconstruct 16-of-28 after losing 12 shards");

    let mut recovered_ct = Vec::with_capacity(ct.len());
    for s_opt in after_12_killed.into_iter().take(16) {
        recovered_ct.extend_from_slice(&s_opt.unwrap());
    }
    recovered_ct.truncate(ct.len());
    let recovered_pt = pq_key
        .decrypt_stripe_pq(&salt, 0, &recovered_ct)
        .expect("decrypt after 16-of-28 surge recovery");
    assert_eq!(recovered_pt, pt);

    // Verify Empirical Failure Co-Variance Anti-Correlation Filter:
    // Suppose 10 nodes secretly share the same power grid / upstream reseller (identical downtime bitmask 0b1111_0000),
    // while 18 other nodes have independent downtime bitmasks.
    let mut candidates_with_masks = Vec::new();
    for i in 0..10 {
        candidates_with_masks.push((
            ElasticPeerCandidate {
                peer_id: format!("hidden-correlated-grid-node-{i}"),
                role: PeerRole::OrganicCommunityPeer,
                subnet_prefix: format!("10.{i}.0.0/24"), // Different /24s, but secretly correlated!
                trust_level: TrustLevel::HighUptimeAnchor,
                rtt_ms: 5,
                committed_standby_bytes: 100_000_000,
            },
            0b1111_0000_1111_0000u64, // Identical historical outage windows!
        ));
    }
    for i in 0..18 {
        candidates_with_masks.push((
            ElasticPeerCandidate {
                peer_id: format!("independent-node-{i}"),
                role: PeerRole::OrganicCommunityPeer,
                subnet_prefix: format!("172.16.{i}.0/24"),
                trust_level: TrustLevel::HighUptimeAnchor,
                rtt_ms: 10,
                committed_standby_bytes: 100_000_000,
            },
            1u64 << i, // Completely uncorrelated single-epoch blips
        ));
    }

    // Limit any correlated failure cluster (Jaccard > 0.30) to at most 2 shards of a 16-of-20 stripe:
    let decorrelated = CorrelatedOutageController::select_decorrelated_targets(
        EarnedStanding::EarnedHomelabAnchorPool,
        &candidates_with_masks,
        0.30,
        2,
    );
    assert_eq!(decorrelated.len(), 20);
    let hidden_grid_count = decorrelated
        .iter()
        .filter(|a| a.peer_id.starts_with("hidden-correlated-grid-node-"))
        .count();
    assert_eq!(
        hidden_grid_count, 2,
        "Anti-correlation filter must cap the 10 secretly correlated power-grid nodes to at most 2 shards (< M=4), leaving 18/20 shards online when that grid fails!"
    );
}
