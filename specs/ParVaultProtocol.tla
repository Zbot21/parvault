--------------------------- MODULE ParVaultProtocol ---------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS
    K,                  \* Minimum data shards required for reconstruction (e.g., 16)
    N,                  \* Total Reed-Solomon shards per stripe (e.g., 20)
    RepairWatermark,    \* Proactive repair trigger threshold (e.g., 18)
    MaxEpochChurn,      \* Maximum node failures within a single repair window (<= N - K)
    MaxLeafFailures,    \* Maximum invalid handshakes / failed PoR audits before leaf slashing (3)
    MaxSubtreeSlashes   \* Maximum slashed children before parent inviter branch is pruned (M = 5, `DEFAULT_SUBTREE_SLASH_LIMIT` in `src/network/wot.rs`)

ASSUME
    /\ K > 0
    /\ N > K
    /\ RepairWatermark >= K
    /\ RepairWatermark <= N
    /\ MaxEpochChurn <= (N - K)
    /\ MaxLeafFailures > 0
    /\ MaxSubtreeSlashes > 0

\* Keys (L-47): the adversary signs only with its own keys (`AdvKeys`); guards compare what it
\* presents with honest state. That the adversary holds no honest key is an assumption.
Owner == "owner"
Genesis == "genesis"
Self == "self"
Leaf == "leaf"
Witnesses == {"w1", "w2"}
AdvKeys == {"adv1", "adv2"}
\* `MIN_WITNESS_SIGNATURES_FOR_REPAIR` in `src/por/verifier.rs`.
MinWitnessSignatures == 2
ASSUME AdvKeys \cap ({Owner, Genesis, Self} \cup Witnesses) = {}   \* @assume adversary-holds-no-honest-key

\* The guards: each compares a presented credential with honest state, and is used by both the
\* adversary's attempts (it fails) and the honest access (it passes).
OwnerReadOk(signer) == signer = Owner   \* @guard read-auth-owner sym=src/por/verifier.rs::grant_owner_decision
RepairReadOk(receipts) == Cardinality(receipts \cap Witnesses) >= MinWitnessSignatures   \* @guard read-auth-repair sym=src/por/verifier.rs::repair_read_decision
ChainAdmitted(root) == root = Genesis   \* @guard wot-admission sym=src/network/wot.rs::chain_admission_decision
MayApplySlash(tgt) == tgt \notin {Genesis, Self}   \* @guard slash-target sym=src/network/wot.rs::slash_target_decision

VARIABLES
    activeShards,           \* Number of currently healthy shards in the cohort (K..N)
    epochDrops,             \* Node failures accumulated in the current repair window
    adversaryShards,        \* Number of ciphertext shards held by an unauthenticated adversary
    uninvitedRoutingEntries,\* Count of uninvited Sybil nodes admitted into Kademlia routing table
    offenderFailures,       \* Failed PoR / handshake count for current dishonest leaf node (0..MaxLeafFailures)
    offenderQuarantined,    \* Whether the current dishonest leaf node is isolated
    parentBranchSlashes,    \* Cumulative slashed leaf children under a suspicious parent inviter (0..MaxSubtreeSlashes)
    parentBranchPruned,     \* Whether the parent inviter's entire delegated subtree is pruned
    slashedTargets,         \* Keys slashed by applied evidence (the guard keeps genesis and self out)
    honestServed            \* The owner's read, a witness repair and a ring member's handshake passed

vars == <<activeShards, epochDrops, adversaryShards,
          uninvitedRoutingEntries, offenderFailures, offenderQuarantined,
          parentBranchSlashes, parentBranchPruned, slashedTargets, honestServed>>

Init ==
    /\ activeShards = N
    /\ epochDrops = 0
    /\ adversaryShards = 0
    /\ uninvitedRoutingEntries = 0
    /\ offenderFailures = 0
    /\ offenderQuarantined = FALSE
    /\ parentBranchSlashes = 0
    /\ parentBranchPruned = FALSE
    /\ slashedTargets = {}
    /\ honestServed = FALSE

\* A storage node drops offline during the current repair window.
NodeChurn ==
    /\ epochDrops < MaxEpochChurn
    /\ activeShards > K
    /\ activeShards' = activeShards - 1
    /\ epochDrops' = epochDrops + 1
    /\ UNCHANGED <<adversaryShards, uninvitedRoutingEntries,
                   offenderFailures, offenderQuarantined,
                   parentBranchSlashes, parentBranchPruned, slashedTargets, honestServed>>

\* Delegated witnesses present RepairGrant + >= 2 failure receipts and reconstruct missing ciphertext shards.
ProactiveWitnessRepair ==
    /\ activeShards <= RepairWatermark
    /\ activeShards >= K
    /\ activeShards' = N
    /\ epochDrops' = 0
    /\ UNCHANGED <<adversaryShards, uninvitedRoutingEntries,
                   offenderFailures, offenderQuarantined,
                   parentBranchSlashes, parentBranchPruned, slashedTargets, honestServed>>

\* NodeChurn's bound `epochDrops < MaxEpochChurn` is the threat model's churn bound, not a Rust
\* check: @assume bounded-epoch-churn (DurabilitySafetyInvariant rests on it).

\* Adversary passively compromises storage nodes up to the Byzantine collusion bound (< K - 1)
\* and tries to read more: an owner read signed by one of its keys, or a witness repair read with
\* receipts signed by its keys; and an uninvited handshake with a chain rooted at one of its keys.
\* Key derivation needs the owner's phrase: @structural kdf-needs-phrase test=crypto::keys (the
\* @structural kdf-needs-phrase: holds by construction; traced to test red_team_hardening_tests::test_rt1_zero_local_state_house_fire_recovery_from_seed_phrase_alone and the compile-time signature MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace)
\* adversary never derives K_user; not modelled as a variable).
AdversaryCollusionAndAttackAttempt ==
    /\ ~parentBranchPruned
    /\ adversaryShards < K - 1
    /\ \E signer \in AdvKeys, receipts \in SUBSET AdvKeys, root \in AdvKeys :
        LET compromised == adversaryShards + 1
        IN /\ adversaryShards' = IF OwnerReadOk(signer) \/ RepairReadOk(receipts)
                                 THEN compromised + 1 ELSE compromised
           /\ uninvitedRoutingEntries' = IF ChainAdmitted(root)
                                         THEN uninvitedRoutingEntries + 1
                                         ELSE uninvitedRoutingEntries
    /\ UNCHANGED <<activeShards, epochDrops, offenderFailures, offenderQuarantined,
                   parentBranchSlashes, parentBranchPruned, slashedTargets, honestServed>>

\* A dishonest leaf fails a PoR audit (evidenced failure only; an unverified handshake is refused
\* by `wot-admission` and never counts, L-47 item 5). At MaxLeafFailures (`MAX_LEAF_FAILURES`) the
\* leaf is quarantined and its parent inviter takes a slash.
RecordDishonestFailure ==
    /\ ~parentBranchPruned
    /\ ~offenderQuarantined
    /\ offenderFailures < MaxLeafFailures
    /\ LET nextLeafFails     == offenderFailures + 1
           leafSlashed       == (nextLeafFails >= MaxLeafFailures)
           nextParentSlashes == IF leafSlashed THEN parentBranchSlashes + 1 ELSE parentBranchSlashes
           branchPruned      == (nextParentSlashes >= MaxSubtreeSlashes)
       IN /\ offenderFailures' = IF leafSlashed /\ ~branchPruned THEN 0 ELSE nextLeafFails
          /\ offenderQuarantined' = (leafSlashed /\ branchPruned)
          /\ parentBranchSlashes' = nextParentSlashes
          /\ parentBranchPruned' = branchPruned
          /\ slashedTargets' = IF leafSlashed THEN slashedTargets \cup {Leaf} ELSE slashedTargets
    /\ UNCHANGED <<activeShards, epochDrops, adversaryShards, uninvitedRoutingEntries, honestServed>>

\* Evidence naming the genesis or this node itself is never applied (the slash guard).
AttemptSlashProtected ==
    /\ \E tgt \in {Genesis, Self, Leaf} :
        slashedTargets' = IF MayApplySlash(tgt) THEN slashedTargets \cup {tgt} ELSE slashedTargets
    /\ UNCHANGED <<activeShards, epochDrops, adversaryShards, uninvitedRoutingEntries,
                   offenderFailures, offenderQuarantined, parentBranchSlashes, parentBranchPruned, honestServed>>

\* Honest access through the same guards: the owner reads with its own key, witnesses repair with
\* the registered witnesses' receipts, and a ring member's chain is rooted at the genesis.
HonestAccess ==
    /\ ~honestServed
    /\ OwnerReadOk(Owner) /\ RepairReadOk(Witnesses) /\ ChainAdmitted(Genesis)
    /\ honestServed' = TRUE
    /\ UNCHANGED <<activeShards, epochDrops, adversaryShards, uninvitedRoutingEntries,
                   offenderFailures, offenderQuarantined, parentBranchSlashes, parentBranchPruned,
                   slashedTargets>>

\* Terminal stuttering step once parent branch is pruned and cohort is healthy.
Idle ==
    /\ activeShards = N
    /\ parentBranchPruned
    /\ UNCHANGED vars

Next ==
    \/ NodeChurn
    \/ ProactiveWitnessRepair
    \/ AdversaryCollusionAndAttackAttempt
    \/ RecordDishonestFailure
    \/ AttemptSlashProtected
    \/ HonestAccess
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(ProactiveWitnessRepair)
    /\ WF_vars(RecordDishonestFailure)

\* SAFETY INVARIANT 1: Data Secrecy (adversary never accumulates >= K shards and never obtains K_user)
DataSecrecyInvariant ==
    adversaryShards < K

\* SAFETY INVARIANT 2: Web-of-Trust Sybil Resistance (uninvited sub-graphs never enter routing tables)
SybilResistanceInvariant ==
    uninvitedRoutingEntries = 0

\* SAFETY INVARIANT 3: Data Durability (active shards never drop below K under bounded epoch churn)
DurabilitySafetyInvariant ==
    activeShards >= K

\* SAFETY INVARIANT 4: Malicious node & branch isolation within bounded failures
SlashingBoundInvariant ==
    /\ (offenderFailures >= MaxLeafFailures => offenderQuarantined)
    /\ (parentBranchSlashes >= MaxSubtreeSlashes => parentBranchPruned)

\* SAFETY INVARIANT 5: the genesis and this node itself are never slashed (F-01 guard)
ProtectedKeysNeverSlashedInvariant ==
    slashedTargets \cap {Genesis, Self} = {}

\* LIVENESS INVARIANT 1: Eventually Retrievable Data (degraded cohorts self-heal back to N shards)
EventuallyRepaired ==
    []((activeShards <= RepairWatermark) => <>(activeShards = N))

\* LIVENESS INVARIANT 2: Subtree Slashing Convergence (dishonest branch is pruned in finite steps <= M)
EventuallyBranchPruned ==
    <>(parentBranchPruned)

=============================================================================
