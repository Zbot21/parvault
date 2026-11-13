------------------- MODULE ParVaultBootstrapAndEarnedTier -------------------
\* @traceability
\*   adr      ADR-15
\*   const    MaxOrganicPeers    -> model-only: model bound
\*   const    SeedAnchorPoolSize -> model-only: model bound
\*   const    MaxPorStreak       -> model-only: abstracts the 50 / 200 PoR-pass thresholds of PeerCreditAccount::trust_level
\* @end
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxOrganicPeers,        \* Full organic neighborhood cohort size (20)
    SeedAnchorPoolSize,     \* Foundation Seed Anchor fallback pool size (20)
    MaxPorStreak            \* PoR uptime streak ceiling modeled (3)

ASSUME
    /\ MaxOrganicPeers = 20
    /\ SeedAnchorPoolSize = 20
    /\ MaxPorStreak = 3

TierNames == {
    "PersonalRing_2of3",
    "Probationary_10of20",
    "VerifiedMixed_16of24",
    "Homelab_16of20"
}

VARIABLES
    personalDevices,                \* Day-1 personal devices in PersonalDeviceCert ring (1..2)
    organicPeers,                   \* Reachable OrganicCommunityPeer count (0 -> 4 -> 10 -> 20)
    seedAnchors,                    \* Reachable FoundationSeedAnchor fallback nodes (20)
    porStreak,                      \* Audited PoR uptime streak (0..3)
    isSlashed,                      \* Whether the honest node has been slashed (an external event)
    byzantinePeerSlashed,           \* Whether a faulting probationary peer was slashed (BOOLEAN)
    unauthorizedEscalationRejected, \* TRUE once a premature --tier homelab request is rejected
    earnedTier,                     \* Current EarnedStanding tier name
    activeK,                        \* Current Reed-Solomon data shard threshold K
    activeN,                        \* Current Reed-Solomon total stripe shards N
    recoverableShards,              \* Currently available/recoverable shards for the stripe
    seedAnchorShardsHeld,           \* Shards currently held by FoundationSeedAnchor nodes (0..20)
    seedAnchorsDrained             \* TRUE once plan_seed_anchor_drain migrates all seed shards

vars == <<personalDevices, organicPeers, seedAnchors, porStreak, isSlashed,
          byzantinePeerSlashed, unauthorizedEscalationRejected, earnedTier,
          activeK, activeN, recoverableShards, seedAnchorShardsHeld,
          seedAnchorsDrained>>

\* Helper: maps (porStreak, isSlashed) to EarnedStanding tier once in the 20-peer mesh
EarnedTierFromStreak(streak, slashed) ==
    IF slashed THEN "Probationary_10of20"   \* @guard tier-respects-slash sym=src/bootstrap.rs::evaluate (EarnedStanding::evaluate; F-07 caveat: not yet on the wire path)
    ELSE IF streak >= 2 THEN "Homelab_16of20"
    ELSE IF streak = 1 THEN "VerifiedMixed_16of24"
    ELSE "Probationary_10of20"

TierK(tier) ==
    CASE tier = "PersonalRing_2of3"    -> 2
      [] tier = "Probationary_10of20"  -> 10
      [] tier = "VerifiedMixed_16of24" -> 16
      [] tier = "Homelab_16of20"       -> 16
      [] OTHER                         -> 10

TierN(tier) ==
    CASE tier = "PersonalRing_2of3"    -> 3
      [] tier = "Probationary_10of20"  -> 20
      [] tier = "VerifiedMixed_16of24" -> 24
      [] tier = "Homelab_16of20"       -> 20
      [] OTHER                         -> 20

Init ==
    /\ personalDevices                = 1
    /\ organicPeers                   = 0
    /\ seedAnchors                    = SeedAnchorPoolSize
    /\ porStreak                      = 0
    /\ isSlashed                      = FALSE
    /\ byzantinePeerSlashed           = FALSE
    /\ unauthorizedEscalationRejected = FALSE
    /\ earnedTier                     = "PersonalRing_2of3"
    /\ activeK                        = 2
    /\ activeN                        = 3
    /\ recoverableShards              = 3
    /\ seedAnchorShardsHeld           = 0
    /\ seedAnchorsDrained             = FALSE

\* Action 1: PairSecondPersonalDevice (Mechanism 1 — Day-1 Personal Device Ring)
\* User pairs a second personal device (e.g. Laptop + Home NAS) via composite
\* post-quantum PersonalDeviceCert (Ed25519 + ML-DSA-65) with zero external peers.
PairSecondPersonalDevice ==
    /\ personalDevices = 1
    /\ organicPeers = 0
    /\ personalDevices' = 2
    /\ earnedTier' = "PersonalRing_2of3"
    /\ activeK' = 2
    /\ activeN' = 3
    /\ recoverableShards' = 3
    /\ UNCHANGED <<organicPeers, seedAnchors, porStreak, isSlashed,
                   byzantinePeerSlashed, unauthorizedEscalationRejected,
                   seedAnchorShardsHeld, seedAnchorsDrained>>

\* Action 2: BootstrapOnFoundationSeedAnchors (Mechanism 2 — Seed Anchor Fallback)
\* When the node enters the wider mesh with 0 organic peers, it starts in the mandatory
\* ProbationaryConsumerPool (10-of-20) backed by 20 zero-knowledge FoundationSeedAnchors.
BootstrapOnFoundationSeedAnchors ==
    /\ personalDevices = 2
    /\ organicPeers = 0
    /\ earnedTier = "PersonalRing_2of3"
    /\ earnedTier' = "Probationary_10of20"
    /\ activeK' = 10
    /\ activeN' = 20
    /\ recoverableShards' = 20
    /\ seedAnchorShardsHeld' = 20
    /\ UNCHANGED <<personalDevices, organicPeers, seedAnchors, porStreak,
                   isSlashed, byzantinePeerSlashed, unauthorizedEscalationRejected,
                   seedAnchorsDrained>>

\* Action 3: AttemptUnauthorizedHomelabEscalation
\* A probationary or mid-tier node (porStreak < 2) attempts to self-select "Homelab_16of20"
\* to get a cheap 1.25x reciprocity expansion tax without earning HighUptimeAnchor status.
\* EarnedStanding::evaluate strictly rejects the escalation.
AttemptUnauthorizedHomelabEscalation ==
    /\ porStreak < 2
    /\ ~unauthorizedEscalationRejected
    /\ unauthorizedEscalationRejected' = TRUE
    \* earnedTier remains strictly bounded by porStreak (never "Homelab_16of20")
    /\ UNCHANGED <<personalDevices, organicPeers, seedAnchors, porStreak,
                   isSlashed, byzantinePeerSlashed, earnedTier, activeK, activeN,
                   recoverableShards, seedAnchorShardsHeld, seedAnchorsDrained>>

\* Action 4: OrganicPeersJoinAndDrainSeedAnchors (Mechanism 2 — Auto-Drain)
\* As organic community peers join (0 -> 4 -> 10 -> 20), shards are progressively
\* migrated off FoundationSeedAnchor nodes onto OrganicCommunityPeer nodes until
\* seedAnchorShardsHeld reaches 0 at organicPeers = 20.
OrganicPeersJoinAndDrainSeedAnchors ==
    /\ earnedTier /= "PersonalRing_2of3"
    /\ organicPeers < MaxOrganicPeers
    /\ LET nextOrganic == CASE organicPeers = 0  -> 4
                            [] organicPeers = 4  -> 10
                            [] organicPeers = 10 -> 20
                            [] OTHER             -> 20
           nextSeedHeld == MaxOrganicPeers - nextOrganic
       IN /\ organicPeers' = nextOrganic
          /\ seedAnchorShardsHeld' = nextSeedHeld
          /\ seedAnchorsDrained' = (nextOrganic = MaxOrganicPeers /\ nextSeedHeld = 0)
    /\ UNCHANGED <<personalDevices, seedAnchors, porStreak, isSlashed,
                   byzantinePeerSlashed, unauthorizedEscalationRejected,
                   earnedTier, activeK, activeN, recoverableShards>>

\* Action 5: AccruePorUptimeAndZeroKnowledgeReshard (Mechanism 3 & 4)
\* Honest node passes sustained PoR uptime epochs (porStreak: 0 -> 1 -> 2 -> 3)
\* and executes zero-knowledge ciphertext re-sharding (reshard_ciphertext_stripe_elastic):
\*   porStreak = 0 -> "Probationary_10of20"  (10-of-20, 2.00x tax)
\*   porStreak = 1 -> "VerifiedMixed_16of24" (16-of-24, 1.50x tax)
\*   porStreak >= 2 -> "Homelab_16of20"      (16-of-20, 1.25x tax)
AccruePorUptimeAndZeroKnowledgeReshard ==
    /\ earnedTier /= "PersonalRing_2of3"
    /\ ~isSlashed
    /\ porStreak < MaxPorStreak
    /\ LET nextStreak == porStreak + 1
           nextTier   == EarnedTierFromStreak(nextStreak, isSlashed)
           nextK      == TierK(nextTier)
           nextN      == TierN(nextTier)
       IN /\ porStreak'         = nextStreak
          /\ earnedTier'        = nextTier
          /\ activeK'           = nextK
          /\ activeN'           = nextN
          /\ recoverableShards' = nextN
    /\ UNCHANGED <<personalDevices, organicPeers, seedAnchors, isSlashed,
                   byzantinePeerSlashed, unauthorizedEscalationRejected,
                   seedAnchorShardsHeld, seedAnchorsDrained>>

\* The honest node is slashed (an external event; what slashes it is not modelled). Its tier is
\* re-evaluated through the same EarnedTierFromStreak, so it leaves the earned tiers.
\* The former SybilSubnetStandbySpawn action and Safety_SubnetSybilQuotaConservation are removed:
\* no Rust function enforces the aggregate per-subnet standby credit (it was `x \div x`, P-04);
\* `canonical_sybil_subnet_key` only buckets addresses. Not model-checked (L-47 item 7).
HonestNodeSlashed ==
    /\ ~isSlashed
    /\ earnedTier /= "PersonalRing_2of3"
    /\ LET nextTier == EarnedTierFromStreak(porStreak, TRUE)
       IN /\ isSlashed'         = TRUE
          /\ earnedTier'        = nextTier
          /\ activeK'           = TierK(nextTier)
          /\ activeN'           = TierN(nextTier)
          /\ recoverableShards' = TierN(nextTier)
    /\ UNCHANGED <<personalDevices, organicPeers, seedAnchors, porStreak,
                   byzantinePeerSlashed, unauthorizedEscalationRejected,
                   seedAnchorShardsHeld, seedAnchorsDrained>>

\* Action 7: SlashByzantinePeer
\* A faulting external peer that fails PoR / withholds egress is slashed and barred
\* from ever entering the EarnedHomelabAnchorPool.
SlashByzantinePeer ==
    /\ ~byzantinePeerSlashed
    /\ byzantinePeerSlashed' = TRUE
    /\ UNCHANGED <<personalDevices, organicPeers, seedAnchors, porStreak,
                   isSlashed, unauthorizedEscalationRejected, earnedTier,
                   activeK, activeN, recoverableShards, seedAnchorShardsHeld,
                   seedAnchorsDrained>>

\* Terminal stuttering step once organic self-sufficiency and earned Homelab tier are reached.
Idle ==
    /\ organicPeers = MaxOrganicPeers
    /\ seedAnchorsDrained = TRUE
    /\ seedAnchorShardsHeld = 0
    /\ (isSlashed \/ (porStreak = MaxPorStreak /\ earnedTier = "Homelab_16of20"))
    /\ byzantinePeerSlashed = TRUE
    /\ UNCHANGED vars

Next ==
    \/ PairSecondPersonalDevice
    \/ BootstrapOnFoundationSeedAnchors
    \/ AttemptUnauthorizedHomelabEscalation
    \/ OrganicPeersJoinAndDrainSeedAnchors
    \/ AccruePorUptimeAndZeroKnowledgeReshard
    \/ HonestNodeSlashed
    \/ SlashByzantinePeer
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Next)

\* ============================================================================
\* SAFETY INVARIANTS
\* ============================================================================

\* 1. Tier Strictly Earned By Uptime:
\* A node can never select or occupy the 16-of-20 Homelab tier without earning
\* high-uptime status (porStreak >= 2) and remaining unslashed (~isSlashed).
Safety_TierStrictlyEarnedByUptime ==
    /\ (earnedTier = "Homelab_16of20" => (porStreak >= 2 /\ ~isSlashed))
    /\ (earnedTier = "VerifiedMixed_16of24" => (porStreak >= 1 /\ ~isSlashed))
    /\ (porStreak = 0 => earnedTier \in {"PersonalRing_2of3", "Probationary_10of20"})

\* 2. Seed Anchors Drain At Organic Threshold:
\* Foundation Seed Anchors hold 0 shards once 20+ organic community peers take over.
Safety_SeedAnchorsDrainAtOrganicThreshold ==
    /\ ((organicPeers >= 20 /\ seedAnchorsDrained) => seedAnchorShardsHeld = 0)
    /\ (seedAnchorShardsHeld <= SeedAnchorPoolSize)

\* 4. Day-1-to-Scale Data Availability:
\* In every reachable state from 0 organic peers (Personal Ring / Seed Anchor fallback)
\* to 20+ organic peers across all elastic re-sharding transitions, recoverableShards >= activeK.
Safety_Day1ToScaleDataAvailability ==
    /\ recoverableShards >= activeK
    /\ activeK >= 2
    /\ activeN > activeK

\* ============================================================================
\* TEMPORAL LIVENESS PROPERTY
\* ============================================================================

\* Eventual Organic Self-Sufficiency and Earned Homelab Tier:
\* Every fair execution eventually drains all Foundation Seed Anchors to 0 shards
\* and promotes the sustained high-uptime node to the 16-of-20 Homelab tier.
Liveness_EventualOrganicSelfSufficiencyAndEarnedTier ==
    \* Scoped by L-47: a node that is slashed never earns Homelab.
    <> (seedAnchorShardsHeld = 0 /\ (earnedTier = "Homelab_16of20" \/ isSlashed))

=============================================================================
