--------------------- MODULE ParVaultConfidentialityAndTrust ---------------------
\* @traceability
\*   adr      ADR-01 ADR-10
\*   const    K         -> model-only: erasure tier tuple (ErasureTier::erasure_params), not a Rust const
\*   const    N         -> model-only: erasure tier tuple (ErasureTier::erasure_params), not a Rust const
\*   const    MaxPasses -> model-only: model bound on uptime passes
\* @end
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    K,              \* Reconstruction threshold (16 shards)
    N,              \* Total Reed-Solomon stripe shards (20 shards)
    MaxPasses       \* Consecutive PoR passes required for High-Uptime Anchor (2)

ASSUME
    /\ K = 16
    /\ N = 20
    /\ K < N
    /\ MaxPasses = 2

\* Five honest subnets (1..5) capable of holding up to 4 shards each as Anchors (5 * 4 = 20),
\* plus one potentially Byzantine subnet (6) subject to immediate slashing.
HonestSubnets == 1..5
FaultySubnet  == 6
Subnets       == 1..6

TrustLevels == {"Untrusted", "Verified", "Anchor", "Slashed"}

\* Tiered subnet shard concentration caps (ADR-10):
\* - "Untrusted" (Probationary): max 1 shard per /24 subnet
\* - "Verified"  (Neighbor):     max 2 shards per /24 subnet
\* - "Anchor"    (High-Uptime):  max 4 shards per /24 subnet (< K = 16)
\* - "Slashed"   (Quarantined):  0 shards allowed
TrustCap(level) ==
    CASE level = "Untrusted" -> 1
      [] level = "Verified"  -> 2
      [] level = "Anchor"    -> 4
      [] level = "Slashed"   -> 0
      [] OTHER               -> 0

VARIABLES
    subnetTrust,        \* Function [Subnets -> TrustLevels]
    subnetShards,       \* Function [Subnets -> 0..4]
    consecutivePasses,  \* Accumulated PoR audit epochs (0..MaxPasses)
    totalPlacedShards,  \* Total shards allocated across honest subnets (0..N)
    adversaryShards,    \* Ciphertext shards observed/colluded by adversary (0..N)
    adversarySlashed    \* Whether the faulting subnet has been slashed and quarantined

vars == <<subnetTrust, subnetShards, consecutivePasses, totalPlacedShards,
          adversaryShards, adversarySlashed>>

Init ==
    /\ subnetTrust       = [s \in Subnets |-> "Untrusted"]
    /\ subnetShards      = [s \in Subnets |-> 0]
    /\ consecutivePasses = 0
    /\ totalPlacedShards = 0
    /\ adversaryShards   = 0
    /\ adversarySlashed  = FALSE

\* Action 1: RecordUptimePass
\* Promotes non-slashed subnets along the dynamic trust ladder:
\* "Untrusted" (cap 1) -> "Verified" (cap 2) -> "Anchor" (cap 4).
\* Slashed subnets can never be promoted.
RecordUptimePass ==
    /\ consecutivePasses < MaxPasses
    /\ LET nextPass == consecutivePasses + 1
           nextTier == IF nextPass = 1 THEN "Verified" ELSE "Anchor"
       IN /\ consecutivePasses' = nextPass
          /\ subnetTrust' = [s \in Subnets |->
                IF subnetTrust[s] = "Slashed"   \* @guard slashed-sticky sym=src/storage/quota.rs::trust_level (N-09: nothing sets is_slashed in production v0.5.0)
                THEN "Slashed"
                ELSE nextTier]
    /\ UNCHANGED <<subnetShards, totalPlacedShards, adversaryShards,
                   adversarySlashed>>

\* Action 2: AllocateShardToSubnet(s)
\* Allocates a shard to the next canonical honest subnet `s` that has remaining capacity
\* under its current dynamic trust tier cap (1, 2, or 4) and strictly below K.
AllocateShardToSubnet(s) ==
    /\ s \in HonestSubnets
    /\ totalPlacedShards < N
    \* @assume placement-trust-cap: TrustLevel::max_shards_per_subnet caps placement only in
    \* PlacementEngine::select_trust_weighted_peers, which has no production caller in v0.5.0.
    \* (TrustCap("Slashed") = 0 also excludes slashed subnets; the separate check was dead, QA Q6.)
    /\ subnetShards[s] < TrustCap(subnetTrust[s])
    /\ (subnetShards[s] + 1) < K
    /\ \A prev \in HonestSubnets :
        (prev < s) => (subnetShards[prev] = TrustCap(subnetTrust[prev]))
    /\ subnetShards' = [subnetShards EXCEPT ![s] = subnetShards[s] + 1]
    /\ totalPlacedShards' = totalPlacedShards + 1
    /\ UNCHANGED <<subnetTrust, consecutivePasses, adversaryShards,
                   adversarySlashed>>

\* Action 3: AdversaryCollude
\* Models an adversary compromising:
\*   (a) an entire High-Uptime Anchor subnet (4 shards < K),
\*   (b) a multi-subnet coalition of 15 shards (15 < K = 16), or
\*   (c) all 20 encrypted shards in transit on the wire without K_user (hasMasterKey = FALSE).
\* Because AES-256-GCM encryption precedes Reed-Solomon encoding and K_user never leaves
\* the client device, plaintextExposed remains FALSE in all cases.
AdversaryCollude ==
    /\ adversaryShards < N
    /\ LET nextAdv == CASE adversaryShards = 0  -> 4
                        [] adversaryShards = 4  -> 15
                        [] adversaryShards = 15 -> N
                        [] OTHER                -> N
       IN adversaryShards' = nextAdv
    /\ UNCHANGED <<subnetTrust, subnetShards, consecutivePasses,
                   totalPlacedShards, adversarySlashed>>

\* Action 4: ByzantineFaultAndSlash
\* Immediately demotes a faulting/withholding subnet to "Slashed", revoking its trust
\* and preventing any shard placement (cap = 0).
ByzantineFaultAndSlash ==
    /\ ~adversarySlashed
    /\ subnetTrust' = [subnetTrust EXCEPT ![FaultySubnet] = "Slashed"]
    /\ subnetShards' = [subnetShards EXCEPT ![FaultySubnet] = 0]
    /\ adversarySlashed' = TRUE
    /\ UNCHANGED <<consecutivePasses, totalPlacedShards, adversaryShards>>

\* Terminal stuttering step once all 20 shards are placed and the faulty subnet is slashed.
Idle ==
    /\ totalPlacedShards = N
    /\ adversarySlashed = TRUE
    /\ adversaryShards = N
    /\ UNCHANGED vars

Next ==
    \/ RecordUptimePass
    \/ \E s \in HonestSubnets : AllocateShardToSubnet(s)
    \/ AdversaryCollude
    \/ ByzantineFaultAndSlash
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Next)

\* ============================================================================
\* SAFETY INVARIANTS
\* ============================================================================

\* Zero-knowledge confidentiality: the adversary may collude every shard, and still never
\* decrypts, because K_user never leaves the client: @structural ciphertext-only-egress. AES-256-GCM
\* @structural ciphertext-only-egress: holds by construction; traced to compile-time types: no MeshWireRequest variant (src/network/behaviour.rs) carries a MasterKey, and encrypt_stripe precedes Reed-Solomon encoding (ADR-01)
\* encryption precedes Reed-Solomon encoding (`encrypt_stripe`, ADR-01) and no wire message carries
\* a key. Not model-checked (L-47 item 2); hasMasterKey and plaintextExposed were constant FALSE.

\* 2. Subnet Trust Caps Enforced:
\* Every subnet strictly respects its tier ceiling (1 for Untrusted, 2 for Verified,
\* 4 for Anchor, 0 for Slashed) and no single subnet ever holds >= K shards.
Safety_SubnetTrustCapsEnforced ==
    \A s \in Subnets :
        /\ subnetShards[s] <= TrustCap(subnetTrust[s])
        /\ subnetShards[s] < K
        /\ (subnetTrust[s] = "Untrusted" => subnetShards[s] <= 1)
        /\ (subnetTrust[s] = "Verified"  => subnetShards[s] <= 2)
        /\ (subnetTrust[s] = "Anchor"    => subnetShards[s] <= 4)
        /\ (subnetTrust[s] = "Slashed"   => subnetShards[s] = 0)

\* 3. Slashed Never Trusted:
\* Once a subnet is slashed, it never promotes back to "Anchor" (or any trusted tier)
\* and holds 0 shards.
Safety_SlashedNeverTrusted ==
    /\ (adversarySlashed => (subnetTrust[FaultySubnet] = "Slashed" /\ subnetShards[FaultySubnet] = 0))
    /\ \A s \in Subnets :
        (subnetTrust[s] = "Slashed") => (subnetTrust[s] /= "Anchor" /\ subnetShards[s] = 0)

\* ============================================================================
\* TEMPORAL LIVENESS PROPERTY
\* ============================================================================

\* Eventual Backup and Trust Convergence:
\* Every fair execution eventually places all 20 stripe shards across promoted
\* cohorts or slashes the Byzantine offender.
Liveness_EventualBackupAndTrustConvergence ==
    <> (totalPlacedShards = 20 \/ adversarySlashed = TRUE)

=============================================================================
