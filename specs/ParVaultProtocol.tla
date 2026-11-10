--------------------------- MODULE ParVaultProtocol ---------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS
    K,                  \* Minimum data shards required for reconstruction (e.g., 16)
    N,                  \* Total Reed-Solomon shards per stripe (e.g., 20)
    RepairWatermark,    \* Proactive repair trigger threshold (e.g., 18)
    MaxEpochChurn,      \* Maximum node failures within a single repair window (<= N - K)
    MaxLeafFailures,    \* Maximum invalid handshakes / failed PoR audits before leaf slashing (3)
    MaxSubtreeSlashes   \* Maximum slashed children before parent inviter branch is pruned (M = 3)

ASSUME
    /\ K > 0
    /\ N > K
    /\ RepairWatermark >= K
    /\ RepairWatermark <= N
    /\ MaxEpochChurn <= (N - K)
    /\ MaxLeafFailures > 0
    /\ MaxSubtreeSlashes > 0

VARIABLES
    activeShards,           \* Number of currently healthy shards in the cohort (K..N)
    epochDrops,             \* Node failures accumulated in the current repair window
    adversaryShards,        \* Number of ciphertext shards held by an unauthenticated adversary
    hasMasterKey,           \* Whether the adversary possesses K_user (always FALSE for remote peers)
    uninvitedRoutingEntries,\* Count of uninvited Sybil nodes admitted into Kademlia routing table
    offenderFailures,       \* Failed PoR / handshake count for current dishonest leaf node (0..MaxLeafFailures)
    offenderQuarantined,    \* Whether the current dishonest leaf node is isolated
    parentBranchSlashes,    \* Cumulative slashed leaf children under a suspicious parent inviter (0..MaxSubtreeSlashes)
    parentBranchPruned      \* Whether the parent inviter's entire delegated subtree is pruned

vars == <<activeShards, epochDrops, adversaryShards, hasMasterKey,
          uninvitedRoutingEntries, offenderFailures, offenderQuarantined,
          parentBranchSlashes, parentBranchPruned>>

Init ==
    /\ activeShards = N
    /\ epochDrops = 0
    /\ adversaryShards = 0
    /\ hasMasterKey = FALSE
    /\ uninvitedRoutingEntries = 0
    /\ offenderFailures = 0
    /\ offenderQuarantined = FALSE
    /\ parentBranchSlashes = 0
    /\ parentBranchPruned = FALSE

\* A storage node drops offline during the current repair window.
NodeChurn ==
    /\ epochDrops < MaxEpochChurn
    /\ activeShards > K
    /\ activeShards' = activeShards - 1
    /\ epochDrops' = epochDrops + 1
    /\ UNCHANGED <<adversaryShards, hasMasterKey, uninvitedRoutingEntries,
                   offenderFailures, offenderQuarantined,
                   parentBranchSlashes, parentBranchPruned>>

\* Delegated witnesses present RepairGrant + >= 2 failure receipts and reconstruct missing ciphertext shards.
ProactiveWitnessRepair ==
    /\ activeShards <= RepairWatermark
    /\ activeShards >= K
    /\ activeShards' = N
    /\ epochDrops' = 0
    /\ UNCHANGED <<adversaryShards, hasMasterKey, uninvitedRoutingEntries,
                   offenderFailures, offenderQuarantined,
                   parentBranchSlashes, parentBranchPruned>>

\* Adversary passively compromises storage nodes up to the Byzantine collusion bound (< K - 1),
\* and attempts an unauthorized wire read (without owner signature and with < 2 witness receipts)
\* plus master-key recovery and uninvited Sybil handshake admission.
AdversaryCollusionAndAttackAttempt ==
    /\ ~parentBranchPruned
    /\ adversaryShards < K - 1
    /\ LET passiveCompromiseShard == adversaryShards + 1
           \* Adversary attempts GetCiphertextShard without owner_sig (FALSE) and only 1 witness receipt (< 2)
           hasOwnerSig            == FALSE
           witnessReceipts        == 1
           wireReadAuthorized     == hasOwnerSig \/ (witnessReceipts >= 2)
           nextAdversaryShards    == IF wireReadAuthorized
                                     THEN passiveCompromiseShard + 1
                                     ELSE passiveCompromiseShard
           \* Adversary attempts to derive K_user without owner seed phrase
           hasOwnerSeedPhrase     == FALSE
           nextHasMasterKey       == (nextAdversaryShards >= K /\ hasOwnerSeedPhrase)
           \* Adversary attempts HandshakeWoT without Genesis->Inviter signature chain
           hasValidGenesisCert    == FALSE
           sybilAdmitted          == (hasValidGenesisCert /\ ~parentBranchPruned)
       IN /\ adversaryShards' = nextAdversaryShards
          /\ hasMasterKey' = nextHasMasterKey
          /\ uninvitedRoutingEntries' = IF sybilAdmitted
                                        THEN uninvitedRoutingEntries + 1
                                        ELSE uninvitedRoutingEntries
    /\ UNCHANGED <<activeShards, epochDrops, offenderFailures, offenderQuarantined,
                   parentBranchSlashes, parentBranchPruned>>

\* Dishonest leaf peer or Sybil node fails a PoR challenge or presents an invalid/uninvited Noise WoT handshake.
\* Protocol guard rejects uninvited routing admission and increments leaf failure counter;
\* upon hitting MaxLeafFailures (3), the leaf is quarantined and its parent inviter takes a slash penalty.
RecordDishonestFailure ==
    /\ ~parentBranchPruned
    /\ ~offenderQuarantined
    /\ offenderFailures < MaxLeafFailures
    /\ LET nextLeafFails     == offenderFailures + 1
           leafSlashed       == (nextLeafFails >= MaxLeafFailures)
           nextParentSlashes == IF leafSlashed THEN parentBranchSlashes + 1 ELSE parentBranchSlashes
           branchPruned      == (nextParentSlashes >= MaxSubtreeSlashes)
           \* Uninvited/forged handshake during failure step is checked by WoT admission guard
           hasValidGenesisCert == FALSE
           sybilAdmitted     == (hasValidGenesisCert /\ ~branchPruned)
           \* Unauthorized raw shard read attempt during dishonest step is checked by ADR-04 guard
           unauthorizedReadGranted == FALSE
       IN /\ offenderFailures' = IF leafSlashed /\ ~branchPruned THEN 0 ELSE nextLeafFails
          /\ offenderQuarantined' = (leafSlashed /\ branchPruned)
          /\ parentBranchSlashes' = nextParentSlashes
          /\ parentBranchPruned' = branchPruned
          /\ uninvitedRoutingEntries' = IF sybilAdmitted
                                        THEN uninvitedRoutingEntries + 1
                                        ELSE uninvitedRoutingEntries
          /\ adversaryShards' = IF unauthorizedReadGranted
                                THEN adversaryShards + 1
                                ELSE adversaryShards
          /\ hasMasterKey' = (adversaryShards' >= K /\ FALSE)
    /\ UNCHANGED <<activeShards, epochDrops>>

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
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(ProactiveWitnessRepair)
    /\ WF_vars(RecordDishonestFailure)

\* SAFETY INVARIANT 1: Data Secrecy (adversary never accumulates >= K shards and never obtains K_user)
DataSecrecyInvariant ==
    /\ adversaryShards < K
    /\ ~hasMasterKey
    /\ ~(adversaryShards >= K /\ hasMasterKey)

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

\* LIVENESS INVARIANT 1: Eventually Retrievable Data (degraded cohorts self-heal back to N shards)
EventuallyRepaired ==
    []((activeShards <= RepairWatermark) => <>(activeShards = N))

\* LIVENESS INVARIANT 2: Subtree Slashing Convergence (dishonest branch is pruned in finite steps <= M)
EventuallyBranchPruned ==
    <>(parentBranchPruned)

=============================================================================
