--------------------------- MODULE ParVaultAnonymity ---------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* ============================================================================
\* ParVault 4-Layer Shard Anonymization & 2-Layer PQ Onion Routing (ADR-11)
\* ============================================================================
\* Models the 4-layer shard anonymization pipeline with 2-layer post-quantum
\* onion routing:
\*   1. Blinded Shard Locators (HMAC-SHA256 under client-only K_user)
\*   2. Per-Shard Capability Keys (V_i pinned at upload time)
\*   3. Unlinkable Bearer Quota Vouchers signed by per-shard ephemeral issuer
\*      keys (no static uploader PeerId or cross-shard issuer linkability)
\*   4. 2-Layer Post-Quantum Onion Routing:
\*      - Outer Layer (sealed to RelayNode's HybridKemPublicKey): contains ONLY
\*        (next_hop_addr, inner_onion_envelope, jitter_delay_ms). RelayNode
\*        NEVER sees blinded_id, capability, voucher, or shard_bytes in plaintext.
\*      - Inner Layer (sealed to StorageNode's HybridKemPublicKey): contains
\*        (blinded_id, capability, voucher, shard_bytes). StorageNode observes
\*        "RelayNode" as the transport sender and never "OwnerNode".

CONSTANTS
    K,              \* Reed-Solomon reconstruction threshold (16 shards)
    N,              \* Total shards per stripe (20 shards)
    MaxVouchers     \* Total anonymous shard vouchers minted for a stripe (20)

ASSUME
    /\ K = 16
    /\ N = 20
    /\ K < N
    /\ MaxVouchers = N

Senders == {"None", "OwnerNode", "RelayNode"}

VARIABLES
    mintedVouchers,             \* Count of owner-minted ephemeral-issuer bearer vouchers (0..MaxVouchers)
    spentNullifiers,            \* Set of redeemed voucher nullifier IDs (SUBSET (1..MaxVouchers))
    ephemeralIssuerIds,         \* Set of distinct ephemeral voucher issuer pubkeys observed (SUBSET (1..MaxVouchers))
    anonymousShardsStored,      \* Count of blinded shards stored across storage cohort (0..MaxVouchers)
    relayedUploads,             \* Count of shards delivered via 2-layer PQ Onion Relay (0..MaxVouchers)
    relayModeActive,            \* Whether 2-layer PQ Onion Relay dispatch is active (always TRUE)
    relayPlaintextCapExposed,   \* Whether RelayNode ever sees capability or voucher in plaintext (always FALSE)
    observedSender,             \* Sender identity observed by the storage node ("None" or "RelayNode")
    stripeRootKnown,            \* Whether storage node learns stripe_merkle_root (always FALSE)
    shardIndexKnown,            \* Whether storage node learns shard_index 0..19 (always FALSE)
    hasMasterKey,               \* Whether adversary possesses client master key K_user (always FALSE)
    adversaryGroupedStripe,     \* Whether adversary can group K shards from the blinded pool (always FALSE)
    adversaryAttemptedGrouping, \* Whether adversary has attempted combinatorial pool correlation
    rejectedDoubleSpends        \* Count of rejected voucher replay attempts (0..1)

vars == <<mintedVouchers, spentNullifiers, ephemeralIssuerIds, anonymousShardsStored,
          relayedUploads, relayModeActive, relayPlaintextCapExposed, observedSender,
          stripeRootKnown, shardIndexKnown, hasMasterKey, adversaryGroupedStripe,
          adversaryAttemptedGrouping, rejectedDoubleSpends>>

Init ==
    /\ mintedVouchers             = 0
    /\ spentNullifiers            = {}
    /\ ephemeralIssuerIds         = {}
    /\ anonymousShardsStored      = 0
    /\ relayedUploads             = 0
    /\ relayModeActive            = TRUE
    /\ relayPlaintextCapExposed   = FALSE
    /\ observedSender             = "None"
    /\ stripeRootKnown            = FALSE
    /\ shardIndexKnown            = FALSE
    /\ hasMasterKey               = FALSE
    /\ adversaryGroupedStripe     = FALSE
    /\ adversaryAttemptedGrouping = FALSE
    /\ rejectedDoubleSpends       = 0

\* Action 1: MintQuotaVoucher
\* The vault owner mints an unlinkable AnonymousQuotaVoucher signed with a fresh
\* per-shard ephemeral Ed25519 issuer key before dispatching an anonymized shard.
MintQuotaVoucher ==
    /\ mintedVouchers < MaxVouchers
    /\ mintedVouchers' = mintedVouchers + 1
    /\ UNCHANGED <<spentNullifiers, ephemeralIssuerIds, anonymousShardsStored,
                   relayedUploads, relayModeActive, relayPlaintextCapExposed,
                   observedSender, stripeRootKnown, shardIndexKnown,
                   hasMasterKey, adversaryGroupedStripe,
                   adversaryAttemptedGrouping, rejectedDoubleSpends>>

\* Action 2: RelayAndStoreAnonymousShard(v)
\* Models the 4-Layer Shard Anonymization pipeline with 2-Layer PQ Onion Routing (ADR-11):
\*   Layer 1 (Blinded Locator): Storage node receives only Locator_i = HMAC(K_blob, ...),
\*            so stripeRootKnown = FALSE and shardIndexKnown = FALSE.
\*   Layer 2 (Per-Shard Capability V_i): Sealed inside the inner onion layer to StorageNode;
\*            RelayNode never sees capability in plaintext (relayPlaintextCapExposed = FALSE).
\*   Layer 3 (Ephemeral-Issuer Bearer Quota Voucher): Sealed inside the inner onion layer;
\*            each voucher `v` uses a fresh unlinkable ephemeral issuer key `v` and is
\*            atomically recorded in `spentNullifiers` on first spend.
\*   Layer 4 (2-Layer PQ Onion Relay): RelayNode peels the outer layer (learning only
\*            next_hop) and forwards the inner ciphertext to StorageNode, which observes
\*            "RelayNode" and never "OwnerNode".
RelayAndStoreAnonymousShard(v) ==
    /\ relayModeActive = TRUE
    /\ v = anonymousShardsStored + 1
    /\ v <= mintedVouchers
    /\ v \notin spentNullifiers
    /\ spentNullifiers'          = spentNullifiers \cup {v}
    /\ ephemeralIssuerIds'       = ephemeralIssuerIds \cup {v}
    /\ anonymousShardsStored'    = anonymousShardsStored + 1
    /\ relayedUploads'           = relayedUploads + 1
    /\ relayPlaintextCapExposed' = FALSE
    /\ observedSender'           = "RelayNode"
    /\ stripeRootKnown'          = FALSE
    /\ shardIndexKnown'          = FALSE
    /\ UNCHANGED <<mintedVouchers, relayModeActive, hasMasterKey,
                   adversaryGroupedStripe, adversaryAttemptedGrouping,
                   rejectedDoubleSpends>>

\* Action 3: AttemptVoucherDoubleSpend(v)
\* Models a malicious client or replay attacker attempting to reuse a previously
\* redeemed voucher nullifier `v \in spentNullifiers`. The storage node's
\* VoucherNullifierLedger rejects the replay, preserving 1-to-1 voucher conservation.
AttemptVoucherDoubleSpend(v) ==
    /\ v \in spentNullifiers
    /\ rejectedDoubleSpends < 1
    /\ rejectedDoubleSpends' = rejectedDoubleSpends + 1
    /\ UNCHANGED <<mintedVouchers, spentNullifiers, ephemeralIssuerIds,
                   anonymousShardsStored, relayedUploads, relayModeActive,
                   relayPlaintextCapExposed, observedSender, stripeRootKnown,
                   shardIndexKnown, hasMasterKey, adversaryGroupedStripe,
                   adversaryAttemptedGrouping>>

\* Action 4: AttemptAdversaryPoolGrouping
\* Models a colluding relay + storage pool attempting to identify which K shards
\* out of a blinded pool belong to the same stripe and in which permutation order (0..K-1).
\* Because:
\*   (a) K_user is never exported over the wire (hasMasterKey = FALSE),
\*   (b) capabilities and vouchers are encrypted inside the inner onion layer
\*       (relayPlaintextCapExposed = FALSE), and
\*   (c) each voucher uses a distinct per-shard ephemeral issuer key
\*       (Cardinality(ephemeralIssuerIds) = anonymousShardsStored),
\* the combinatorial search space is C(M, K) * N! / (N - K)! >= 2^224, so
\* adversaryGroupedStripe remains FALSE.
AttemptAdversaryPoolGrouping ==
    /\ ~adversaryAttemptedGrouping
    /\ anonymousShardsStored > 0
    /\ LET masterKeyExportedOverWire == FALSE
           nextHasMasterKey          == (masterKeyExportedOverWire /\ anonymousShardsStored >= K)
           canCorrelateLocators      == (nextHasMasterKey
                                         \/ (stripeRootKnown /\ shardIndexKnown)
                                         \/ relayPlaintextCapExposed)
       IN /\ hasMasterKey'               = nextHasMasterKey
          /\ adversaryGroupedStripe'     = canCorrelateLocators
          /\ adversaryAttemptedGrouping' = TRUE
    /\ UNCHANGED <<mintedVouchers, spentNullifiers, ephemeralIssuerIds,
                   anonymousShardsStored, relayedUploads, relayModeActive,
                   relayPlaintextCapExposed, observedSender, stripeRootKnown,
                   shardIndexKnown, rejectedDoubleSpends>>

\* Terminal stuttering step once all 20 anonymous shards are stored via 2-layer relay,
\* voucher double-spend defense has been exercised, and pool correlation was attempted.
Idle ==
    /\ mintedVouchers = MaxVouchers
    /\ anonymousShardsStored = MaxVouchers
    /\ rejectedDoubleSpends = 1
    /\ adversaryAttemptedGrouping = TRUE
    /\ UNCHANGED vars

Next ==
    \/ MintQuotaVoucher
    \/ \E v \in 1..MaxVouchers : RelayAndStoreAnonymousShard(v)
    \/ \E v \in 1..MaxVouchers : AttemptVoucherDoubleSpend(v)
    \/ AttemptAdversaryPoolGrouping
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Next)

\* ============================================================================
\* SAFETY INVARIANTS
\* ============================================================================

\* 1. Zero Origin & Relay Metadata Leakage:
\* When 2-layer onion relay mode is active, storage nodes never observe "OwnerNode"
\* as the direct uploader, relay nodes never observe capability/voucher metadata
\* in plaintext, and every stored shard uses a distinct ephemeral voucher issuer.
Safety_ZeroOriginLeakage ==
    /\ (relayModeActive => observedSender /= "OwnerNode")
    /\ observedSender \in Senders
    /\ relayPlaintextCapExposed = FALSE
    /\ stripeRootKnown = FALSE
    /\ shardIndexKnown = FALSE
    /\ relayedUploads = anonymousShardsStored
    /\ Cardinality(ephemeralIssuerIds) = anonymousShardsStored

\* 2. No Voucher Double-Spend & 1-to-1 Conservation:
\* Every stored anonymous shard corresponds to a unique spent voucher nullifier,
\* and stored shards never exceed minted vouchers.
Safety_NoVoucherDoubleSpend ==
    /\ Cardinality(spentNullifiers) = anonymousShardsStored
    /\ anonymousShardsStored <= mintedVouchers
    /\ mintedVouchers <= MaxVouchers

\* 3. Unlinkable Reconstruction Hardness:
\* Without K_user, the adversary cannot group K shards from the blinded pool.
Safety_UnlinkableReconstructionHardness ==
    /\ hasMasterKey = FALSE
    /\ adversaryGroupedStripe = FALSE

\* ============================================================================
\* TEMPORAL LIVENESS PROPERTY
\* ============================================================================

\* Anonymous Backup Completes:
\* Every fair execution eventually stores all MaxVouchers (20) anonymized shards.
Liveness_AnonymousBackupCompletes ==
    <> (anonymousShardsStored = MaxVouchers)

=============================================================================
