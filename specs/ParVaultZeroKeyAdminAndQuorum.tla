------------------- MODULE ParVaultZeroKeyAdminAndQuorum -------------------
EXTENDS Naturals, FiniteSets, Sequences

\* Formal TLA+ Specification of ParVault's Zero-Private-Key-On-VPS `admin_rpc`
\* Architecture and Federated `M-of-N` Council Eviction Governance (`ADR-19`).
\*
\* Models:
\*  1. A front-line `parvault-seed` VPS provisioned with `--admin-rpc-pubkey`
\*     allowlisting (zero council Ed25519 private keys stored on the VPS disk).
\*  2. Full root/disk compromise of the VPS (`AdversarySeizeVpsDisk`), exposing
\*     all secrets on the VPS disk (`vps_transport_seed`, `vps_eviction_hmac_seed`)
\*     to an active adversary.
\*  3. Collusion between `M - 1` Byzantine rogue council operators (`ByzantineCouncil`)
\*     and unvetted external attackers (`StrangerSigners`), attempting:
\*       - `< M` unilateral eviction orders,
\*       - duplicate co-signatures from the same rogue councilor across multiple
\*         signature slots (`primary` + `cosig1` + `cosig2`) to fake `>= M` count,
\*       - target payload mutation (`"AbuseTarget"` -> `"InnocentTarget"`) on an
\*         order already signed by an honest councilor,
\*       - `admin_rpc` `challenge_nonce` replay and `order_id` replay, and
\*       - cross-mode injection of Public Commons council orders into a private
\*         `HomelabRedundancyVault` (`PrivateRing`) node.
\*  4. Honest `M-of-N` out-of-band co-signing (`parvault-control`) evicting
\*     cryptographically proven abuse while preserving innocent shards.

CONSTANTS
    HonestCouncil,      \* Set of honest council operator IDs (e.g. {"c1", "c2"})
    ByzantineCouncil,   \* Set of compromised/rogue council operator IDs (size M - 1, e.g. {"c_rogue"})
    StrangerSigners,    \* Set of unvetted non-council attacker IDs (e.g. {"stranger"})
    QuorumM,            \* Strict council quorum threshold M (e.g. 2 for 2-of-3)
    MaxNonces           \* Bounded pool of fresh single-use admin_rpc challenge nonces (e.g. 3)

Council == HonestCouncil \cup ByzantineCouncil
AllSigners == Council \cup StrangerSigners
Targets == {"AbuseTarget", "InnocentTarget"}
Slots == {"primary", "cosig1", "cosig2"}
OrderIds == {"ord_abuse", "ord_forged_dup", "ord_tampered"}
HomelabOwner == "homelab_owner"

ASSUME
    /\ QuorumM >= 2
    /\ HonestCouncil \cap ByzantineCouncil = {}
    /\ StrangerSigners \cap Council = {}
    /\ HomelabOwner \notin AllSigners
    /\ Cardinality(ByzantineCouncil) <= QuorumM - 1   \* @assume byzantine-below-quorum (which of them are corrupt is chosen in Init)
    /\ Cardinality(HonestCouncil) >= QuorumM
    /\ MaxNonces >= 2

VARIABLES
    vpsDiskSecrets,         \* Secrets persisted on the front-line VPS filesystem
    vpsCompromised,         \* TRUE once an attacker dumps the entire VPS disk
    attackerKeys,           \* Private signing/HMAC keys possessed by the adversary
    activeChallenge,        \* Current single-use 32B challenge_nonce on open admin_rpc conn (0 = none)
    nextNonce,              \* Next fresh CSPRNG nonce index (1..MaxNonces+1)
    consumedNonces,         \* Set of already-used admin_rpc challenge nonces
    acceptedRpcNonces,      \* Sequence of nonces accepted by admin_rpc (proves zero nonce replay)
    rejectedReplays,        \* Counter of rejected nonce/order_id replay attempts (bounded for finiteness)
    advRpcSubmissions,      \* Bounded count of adversary admin_rpc connection submissions
    confirmedAbuseTargets,  \* Targets proven via AES-256-GCM cryptographic burden-of-proof
    honestOrderSigs,        \* Signature entries <<slot, signer, signedTarget>> on "ord_abuse"
    forgedOrderBuilt,       \* TRUE once adversary crafts duplicate-signer forged order for "InnocentTarget"
    tamperedOrderBuilt,     \* TRUE once adversary mutates target of an honest-signed order to "InnocentTarget"
    seenOrderIds,           \* Anti-replay FIFO set of applied eviction order_ids
    appliedOrderLog,        \* Sequence of applied eviction order_ids (proves zero order_id replay)
    publicSwarmEvicted,     \* Targets zero-shredded (0x00) on Public Commons nodes
    privateRingEvicted      \* Targets zero-shredded on PrivateRing / HomelabVault nodes

vars == <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
          consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
          confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt, tamperedOrderBuilt,
          seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted>>

\* Helper: Private key token for a signer identity.
PrivKey(s) == <<"priv", s>>

\* Helper: Signers whose private signing keys are currently held by the adversary.
AttackerControlledSigners ==
    { s \in AllSigners : PrivKey(s) \in attackerKeys }

\* Construct concrete SignedBadActorEvictionOrder records from protocol state:
HonestAbuseOrder ==
    [ id     |-> "ord_abuse",
      target |-> "AbuseTarget",
      sigs   |-> honestOrderSigs ]

\* Adversary stuffs all 3 signature slots (primary + cosig1 + cosig2) using every
\* council/stranger private key in `attackerKeys` (including duplicate signatures
\* from the same rogue councilor across multiple slots!).
ForgedDuplicateSignerOrder ==
    [ id     |-> "ord_forged_dup",
      target |-> "InnocentTarget",
      sigs   |-> { <<slot, s, "InnocentTarget">> :
                    slot \in Slots, s \in AttackerControlledSigners } ]

\* Adversary takes existing `honestOrderSigs` (bound to "AbuseTarget"), mutates the
\* order's target field to "InnocentTarget", and appends signatures from every
\* attacker-controlled signer over "InnocentTarget".
TamperedTargetOrder ==
    [ id     |-> "ord_tampered",
      target |-> "InnocentTarget",
      sigs   |-> honestOrderSigs \cup
                 { <<"cosig2", s, "InnocentTarget">> : s \in AttackerControlledSigners } ]

\* Real production quorum tally (`SignedBadActorEvictionOrder::valid_council_signer_count`):
\* Counts DISTINCT signers in `authoritySet` that produced a valid signature cryptographically
\* bound to `ord.target`. Duplicate slots from the same signer collapse into a single set element,
\* and signatures over a different target prior to mutation do NOT match `ord.target`.
ValidDistinctSigners(ord, authoritySet) ==
    { s \in authoritySet : \E slot \in Slots : <<slot, s, ord.target>> \in ord.sigs }

OrderMeetsCouncilQuorum(ord) ==
    Cardinality(ValidDistinctSigners(ord, Council)) >= QuorumM   \* @guard quorum-count sym=src/storage/council.rs::council_manifest_decision

\* The admin RPC compares the request's nonce with the connection's single active challenge
\* (`validate_admin_rpc_slice_replay_and_auth_meta`, src/admin_rpc.rs).
ChallengeMatches(nonce) == activeChallenge > 0 /\ nonce = activeChallenge   \* @guard nonce-fresh sym=src/admin_rpc.rs::validate_admin_rpc_slice_replay_and_auth_meta
OrderIdFresh(id) == id \notin seenOrderIds   \* @guard order-id-fresh sym=src/storage/eviction.rs::order_admission_decision

OrderMeetsPrivateRingAuth(ord) ==
    Cardinality(ValidDistinctSigners(ord, {HomelabOwner})) >= 1

Init ==
    \* Zero-Private-Key-On-VPS: VPS disk holds transport & per-node HMAC keys ONLY;
    \* ZERO Council private keys (`PrivKey(c)`) exist on the VPS filesystem.
    \* @structural no-admin-key-persist: no code path writes a council key to the seed's disk
    \* @structural no-admin-key-persist: holds by construction; traced to test trust_enforcement::admin_key_never_persisted_on_seed
    \* (`tracker_admin.seed` is never auto-generated); vpsDiskSecrets is fixed data.
    /\ vpsDiskSecrets = {<<"vps_secret", "transport_seed">>, <<"vps_secret", "eviction_hmac_seed">>}
    /\ vpsCompromised = FALSE
    \* Any subset of the (at most QuorumM - 1) Byzantine councilors is corrupt (P-03).
    /\ attackerKeys \in { { PrivKey(s) : s \in (B \cup StrangerSigners) } : B \in SUBSET ByzantineCouncil }
    /\ activeChallenge = 0
    /\ nextNonce = 1
    /\ consumedNonces = {}
    /\ acceptedRpcNonces = <<>>
    /\ rejectedReplays = 0
    /\ advRpcSubmissions = 0
    /\ confirmedAbuseTargets = {}
    /\ honestOrderSigs = {}
    /\ forgedOrderBuilt = FALSE
    /\ tamperedOrderBuilt = FALSE
    /\ seenOrderIds = {}
    /\ appliedOrderLog = <<>>
    /\ publicSwarmEvicted = {}
    /\ privateRingEvicted = {}

\* 1. Cryptographic Burden-of-Proof Abuse Report (`VerifiableAbuseReport`):
\*    Authenticates "AbuseTarget" via AES-256-GCM + Merkle proof and queues for review
\*    WITHOUT auto-deleting any shards (`publicSwarmEvicted` is UNCHANGED).
SubmitVerifiedAbuseReport ==
    /\ "AbuseTarget" \notin confirmedAbuseTargets
    /\ confirmedAbuseTargets' = confirmedAbuseTargets \cup {"AbuseTarget"}
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   honestOrderSigs, forgedOrderBuilt, tamperedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted>>

\* 2. Adversary compromises the front-line VPS disk (`root` read of `/var/lib/parvault-seed`):
\*    Copies all of `vpsDiskSecrets` into `attackerKeys`.
AdversarySeizeVpsDisk ==
    /\ ~vpsCompromised
    /\ vpsCompromised' = TRUE
    /\ attackerKeys' = attackerKeys \cup vpsDiskSecrets
    /\ UNCHANGED <<vpsDiskSecrets, activeChallenge, nextNonce, consumedNonces,
                   acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, seenOrderIds, appliedOrderLog,
                   publicSwarmEvicted, privateRingEvicted>>

\* 3. Honest council operators (`parvault-control` on out-of-band laptops) issue & co-sign
\*    eviction order for a cryptographically verified abuse target.
HonestIssuePrimarySig ==
    /\ "AbuseTarget" \in confirmedAbuseTargets
    /\ honestOrderSigs = {}
    /\ \E c \in HonestCouncil :
        honestOrderSigs' = { <<"primary", c, "AbuseTarget">> }
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, forgedOrderBuilt, tamperedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted>>

HonestAddCosignature ==
    /\ "AbuseTarget" \in confirmedAbuseTargets
    /\ honestOrderSigs # {}
    /\ Cardinality(ValidDistinctSigners(HonestAbuseOrder, HonestCouncil)) < QuorumM
    /\ \E c \in HonestCouncil :
        /\ c \notin ValidDistinctSigners(HonestAbuseOrder, HonestCouncil)
        /\ honestOrderSigs' = honestOrderSigs \cup { <<"cosig1", c, "AbuseTarget">> }
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, forgedOrderBuilt, tamperedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted>>

\* 4. Adversary crafts duplicate-signer / sub-quorum order targeting "InnocentTarget"
\*    using compromised VPS secrets + M - 1 Byzantine councilors + stranger keys.
AdversaryBuildDuplicateSignerOrder ==
    /\ ~forgedOrderBuilt
    /\ forgedOrderBuilt' = TRUE
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, tamperedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted>>

\* 5. Adversary intercepts an honest-signed order and mutates `target` to "InnocentTarget"
\*    while appending M - 1 rogue council co-signatures.
AdversaryBuildTamperedTargetOrder ==
    /\ honestOrderSigs # {}
    /\ ~tamperedOrderBuilt
    /\ tamperedOrderBuilt' = TRUE
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted>>

\* 6. Seed `admin_rpc` issues a fresh single-use 32-byte `challenge_nonce` (`SeedAdminHello`).
SeedIssueFreshAdminChallenge ==
    /\ activeChallenge = 0
    /\ nextNonce <= MaxNonces
    /\ activeChallenge' = nextNonce
    /\ nextNonce' = nextNonce + 1
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, consumedNonces,
                   acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, seenOrderIds, appliedOrderLog,
                   publicSwarmEvicted, privateRingEvicted>>

\* 7. Honest operator submits co-signed `HonestAbuseOrder` over `admin_rpc` using fresh `activeChallenge`.
HonestSubmitQuorumOrderViaAdminRpc ==
    /\ ChallengeMatches(activeChallenge)
    /\ activeChallenge \notin consumedNonces
    /\ OrderMeetsCouncilQuorum(HonestAbuseOrder)
    /\ OrderIdFresh(HonestAbuseOrder.id)
    /\ consumedNonces' = consumedNonces \cup {activeChallenge}
    /\ acceptedRpcNonces' = Append(acceptedRpcNonces, activeChallenge)
    /\ activeChallenge' = 0
    /\ seenOrderIds' = seenOrderIds \cup {HonestAbuseOrder.id}
    /\ appliedOrderLog' = Append(appliedOrderLog, HonestAbuseOrder.id)
    /\ publicSwarmEvicted' = publicSwarmEvicted \cup {HonestAbuseOrder.target}
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, nextNonce,
                   rejectedReplays, advRpcSubmissions, confirmedAbuseTargets,
                   honestOrderSigs, forgedOrderBuilt, tamperedOrderBuilt,
                   privateRingEvicted>>

\* 8. Adversary submits forged or payload-mutated order over `admin_rpc` (using a fresh challenge,
\*    signed by a Byzantine councilor on the allowlist): `admin_rpc` consumes the single-use
\*    challenge_nonce, runs `apply_signed_eviction_order_with_quorum`, and REJECTS execution
\*    whenever `OrderMeetsCouncilQuorum(ord)` is FALSE!
AdversarySubmitForgedOrderViaAdminRpc ==
    /\ activeChallenge > 0
    /\ activeChallenge \notin consumedNonces
    /\ advRpcSubmissions < 1
    /\ (forgedOrderBuilt \/ tamperedOrderBuilt)
    /\ \E ord \in ( (IF forgedOrderBuilt THEN {ForgedDuplicateSignerOrder} ELSE {})
                    \cup (IF tamperedOrderBuilt THEN {TamperedTargetOrder} ELSE {}) ) :
        /\ consumedNonces' = consumedNonces \cup {activeChallenge}
        /\ acceptedRpcNonces' = Append(acceptedRpcNonces, activeChallenge)
        /\ activeChallenge' = 0
        /\ advRpcSubmissions' = advRpcSubmissions + 1
        /\ IF OrderMeetsCouncilQuorum(ord) /\ OrderIdFresh(ord.id)
           THEN /\ seenOrderIds' = seenOrderIds \cup {ord.id}
                /\ appliedOrderLog' = Append(appliedOrderLog, ord.id)
                /\ publicSwarmEvicted' = publicSwarmEvicted \cup {ord.target}
           ELSE /\ UNCHANGED <<seenOrderIds, appliedOrderLog, publicSwarmEvicted>>
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, nextNonce,
                   rejectedReplays, confirmedAbuseTargets, honestOrderSigs,
                   forgedOrderBuilt, tamperedOrderBuilt, privateRingEvicted>>

\* 9. Adversary replays a captured quorum order over `admin_rpc` with any nonce it has seen
\*    (a consumed one, or the connection's current challenge). Accepted only through both
\*    guards: the nonce must be the active challenge and the order id must be fresh.
AdversaryAttemptReplay ==
    /\ rejectedReplays < 2
    /\ activeChallenge > 0
    /\ OrderMeetsCouncilQuorum(HonestAbuseOrder)
    /\ \E nonce \in consumedNonces \cup {activeChallenge} :
        IF ChallengeMatches(nonce) /\ OrderIdFresh(HonestAbuseOrder.id)
        THEN /\ consumedNonces' = consumedNonces \cup {nonce}
             /\ acceptedRpcNonces' = Append(acceptedRpcNonces, nonce)
             /\ activeChallenge' = 0
             /\ seenOrderIds' = seenOrderIds \cup {HonestAbuseOrder.id}
             /\ appliedOrderLog' = Append(appliedOrderLog, HonestAbuseOrder.id)
             /\ publicSwarmEvicted' = publicSwarmEvicted \cup {HonestAbuseOrder.target}
             /\ UNCHANGED rejectedReplays
        ELSE /\ rejectedReplays' = rejectedReplays + 1
             /\ UNCHANGED <<consumedNonces, acceptedRpcNonces, activeChallenge, seenOrderIds,
                            appliedOrderLog, publicSwarmEvicted>>
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, nextNonce, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, privateRingEvicted>>

\* 10. Cross-mode broadcast check (`ADR-19` Strict Mode Isolation):
\*     Even a valid `M-of-N` Public Tracker Council order sent to a `HomelabRedundancyVault`
\*     (`PrivateRing`) node is evaluated ONLY against `{HomelabOwner}`, never `Council`.
BroadcastCouncilOrderToPrivateRing ==
    /\ honestOrderSigs # {}
    /\ OrderMeetsCouncilQuorum(HonestAbuseOrder)
    /\ rejectedReplays < 2
    /\ IF OrderMeetsPrivateRingAuth(HonestAbuseOrder)
       THEN privateRingEvicted' = privateRingEvicted \cup {HonestAbuseOrder.target}
       ELSE UNCHANGED privateRingEvicted
    /\ rejectedReplays' = rejectedReplays + 1
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, seenOrderIds, appliedOrderLog,
                   publicSwarmEvicted>>

Idle ==
    /\ "AbuseTarget" \in publicSwarmEvicted
    /\ UNCHANGED vars

Next ==
    \/ SubmitVerifiedAbuseReport
    \/ AdversarySeizeVpsDisk
    \/ HonestIssuePrimarySig
    \/ HonestAddCosignature
    \/ AdversaryBuildDuplicateSignerOrder
    \/ AdversaryBuildTamperedTargetOrder
    \/ SeedIssueFreshAdminChallenge
    \/ HonestSubmitQuorumOrderViaAdminRpc
    \/ AdversarySubmitForgedOrderViaAdminRpc
    \/ AdversaryAttemptReplay
    \/ BroadcastCouncilOrderToPrivateRing
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(SubmitVerifiedAbuseReport)
    /\ WF_vars(HonestIssuePrimarySig)
    /\ WF_vars(HonestAddCosignature)
    /\ WF_vars(SeedIssueFreshAdminChallenge)
    /\ WF_vars(HonestSubmitQuorumOrderViaAdminRpc)

-----------------------------------------------------------------------------
\* FORMAL INVARIANTS & TEMPORAL PROPERTIES

TypeOK ==
    /\ vpsCompromised \in BOOLEAN
    /\ activeChallenge \in 0..MaxNonces
    /\ nextNonce \in 1..(MaxNonces + 1)
    /\ consumedNonces \subseteq (1..MaxNonces)
    /\ rejectedReplays \in 0..2
    /\ advRpcSubmissions \in 0..1
    /\ confirmedAbuseTargets \subseteq Targets
    /\ forgedOrderBuilt \in BOOLEAN
    /\ tamperedOrderBuilt \in BOOLEAN
    /\ seenOrderIds \subseteq OrderIds
    /\ publicSwarmEvicted \subseteq Targets
    /\ privateRingEvicted \subseteq Targets

\* INVARIANT 1 (Zero-Private-Key-On-VPS):
\* No council private key ever resides on the VPS disk, and even after full VPS disk
\* compromise (`vpsCompromised = TRUE`), the adversary never obtains any honest council key.
Safety_ZeroAdminPrivKeyOnVpsDisk ==
    /\ \A c \in Council : PrivKey(c) \notin vpsDiskSecrets
    /\ \A c \in HonestCouncil : PrivKey(c) \notin attackerKeys

\* INVARIANT 2 (M-of-N Quorum Soundness, Duplicate-Signer Rejection & Payload Binding):
\* Neither VPS disk compromise, nor M - 1 Byzantine councilors, nor duplicate signatures
\* across multiple slots, nor target mutation on an honest signature can ever evict an
\* innocent target or satisfy council quorum without >= M distinct honest+council signers.
Safety_NoUnauthorizedOrSubQuorumEviction ==
    /\ "InnocentTarget" \notin publicSwarmEvicted
    /\ publicSwarmEvicted \subseteq confirmedAbuseTargets
    /\ ~OrderMeetsCouncilQuorum(ForgedDuplicateSignerOrder)
    /\ ~OrderMeetsCouncilQuorum(TamperedTargetOrder)

\* INVARIANT 3 (Strict Nonce & Order-ID Anti-Replay):
\* Every accepted `admin_rpc` request uses a strictly unique `challenge_nonce`, and
\* every applied eviction `order_id` executes at most once.
Safety_NoNonceOrOrderReplay ==
    /\ \A i, j \in 1..Len(acceptedRpcNonces) :
        i # j => acceptedRpcNonces[i] # acceptedRpcNonces[j]
    /\ \A i, j \in 1..Len(appliedOrderLog) :
        i # j => appliedOrderLog[i] # appliedOrderLog[j]
    /\ activeChallenge # 0 => activeChallenge \notin consumedNonces

\* INVARIANT 4 (Strict PrivateRing / Homelab Mode Isolation):
\* Public Tracker Council orders can never zero-shred shards on a PrivateRing / Homelab node.
Safety_PrivateRingImmuneToPublicCouncil ==
    privateRingEvicted = {}

\* LIVENESS PROPERTY:
\* Despite VPS disk compromise and M - 1 Byzantine councilors, confirmed abuse is eventually
\* evicted by the M honest councilors over `admin_rpc`.
Liveness_HonestQuorumEvictsConfirmedAbuse ==
    <>("AbuseTarget" \in publicSwarmEvicted)

=============================================================================
