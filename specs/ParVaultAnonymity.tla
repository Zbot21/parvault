--------------------------- MODULE ParVaultAnonymity ---------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* ============================================================================
\* ParVault Shard Anonymization & PQ Onion Routing (ADR-11), scoped by L-38 / L-39 / L-47
\* ============================================================================
\* What the code delivers in v0.5.0, and what this model checks:
\*   - Both onion paths are in use. The 2-layer path seals capability and voucher inside the
\*     inner layer; the single-layer `RelayPqOnionEnvelope` carries `capability` and `voucher`
\*     as outer fields (`src/network/behaviour.rs`), so that relay sees them (not modelled as a
\*     claim). The entry relay sees the originator's connection (L-38).
\*   - The storage target observes the relay, never the owner, on either path; the voucher
\*     issuer is visible to the target but is a fresh key per shard (L-39). Checked:
\*     Safety_ZeroOriginLeakage.
\*   - Voucher nullifiers are spent once (guard `nullifier-fresh`). Checked:
\*     Safety_NoVoucherDoubleSpend.
\*   - Blinded locators and K_user never on the wire make pool grouping infeasible:
\*     @structural blinded-locators (a `PutBlindedShard` carries no stripe root or shard index)
\*     and @structural no-key-on-wire. Not model-checked; the former grouping action and
\*     Safety_UnlinkableReconstructionHardness held by constant FALSE flags (P-02).

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

\* The guard: a voucher nullifier is accepted only once (`VoucherNullifierLedger`).
NullifierFresh(v, spent) == v \notin spent   \* @guard nullifier-fresh sym=src/storage/anonymity.rs::redeem_voucher

VARIABLES
    mintedVouchers,             \* Count of owner-minted ephemeral-issuer bearer vouchers (0..MaxVouchers)
    spentNullifiers,            \* Set of redeemed voucher nullifier IDs (SUBSET (1..MaxVouchers))
    ephemeralIssuerIds,         \* Set of distinct ephemeral voucher issuer pubkeys observed (SUBSET (1..MaxVouchers))
    anonymousShardsStored,      \* Count of blinded shards stored across storage cohort (0..MaxVouchers)
    relayedUploads,             \* Count of shards delivered through an onion relay (0..MaxVouchers)
    observedSender,             \* Sender identity observed by the storage node ("None" or "RelayNode")
    rejectedDoubleSpends        \* Count of rejected voucher replay attempts (0..1)

vars == <<mintedVouchers, spentNullifiers, ephemeralIssuerIds, anonymousShardsStored,
          relayedUploads, observedSender, rejectedDoubleSpends>>

Init ==
    /\ mintedVouchers        = 0
    /\ spentNullifiers       = {}
    /\ ephemeralIssuerIds    = {}
    /\ anonymousShardsStored = 0
    /\ relayedUploads        = 0
    /\ observedSender        = "None"
    /\ rejectedDoubleSpends  = 0

\* The vault owner mints an unlinkable voucher under a fresh per-shard ephemeral issuer key.
MintQuotaVoucher ==
    /\ mintedVouchers < MaxVouchers
    /\ mintedVouchers' = mintedVouchers + 1
    /\ UNCHANGED <<spentNullifiers, ephemeralIssuerIds, anonymousShardsStored,
                   relayedUploads, observedSender, rejectedDoubleSpends>>

\* A shard is relayed (2-layer or single-layer path; the target sees the relay on both) and
\* stored once its voucher's nullifier is fresh.
RelayAndStoreAnonymousShard(v, path) ==
    /\ path \in {"two-layer", "single-layer"}
    /\ v = anonymousShardsStored + 1
    /\ v <= mintedVouchers
    /\ NullifierFresh(v, spentNullifiers)
    /\ spentNullifiers'       = spentNullifiers \cup {v}
    /\ ephemeralIssuerIds'    = ephemeralIssuerIds \cup {v}
    /\ anonymousShardsStored' = anonymousShardsStored + 1
    /\ relayedUploads'        = relayedUploads + 1
    /\ observedSender'        = "RelayNode"
    /\ UNCHANGED <<mintedVouchers, rejectedDoubleSpends>>

\* A replay of a spent voucher: the nullifier guard refuses it; were it accepted, a shard would be
\* stored with no new nullifier.
AttemptVoucherDoubleSpend(v) ==
    /\ v \in spentNullifiers
    /\ rejectedDoubleSpends < 1
    /\ IF NullifierFresh(v, spentNullifiers)
       THEN /\ anonymousShardsStored' = anonymousShardsStored + 1
            /\ relayedUploads' = relayedUploads + 1
            /\ UNCHANGED rejectedDoubleSpends
       ELSE /\ rejectedDoubleSpends' = rejectedDoubleSpends + 1
            /\ UNCHANGED <<anonymousShardsStored, relayedUploads>>
    /\ UNCHANGED <<mintedVouchers, spentNullifiers, ephemeralIssuerIds, observedSender>>

\* Terminal stuttering step once all shards are stored and a replay was refused.
Idle ==
    /\ mintedVouchers = MaxVouchers
    /\ anonymousShardsStored = MaxVouchers
    /\ rejectedDoubleSpends = 1
    /\ UNCHANGED vars

Next ==
    \/ MintQuotaVoucher
    \/ \E v \in 1..MaxVouchers, path \in {"two-layer", "single-layer"} : RelayAndStoreAnonymousShard(v, path)
    \/ \E v \in 1..MaxVouchers : AttemptVoucherDoubleSpend(v)
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Next)

\* 1. Zero origin leakage at the target (scoped, L-38 / L-39): on either onion path the storage
\* target observes the relay, never the owner, and every stored shard has its own issuer key.
Safety_ZeroOriginLeakage ==
    /\ observedSender /= "OwnerNode"
    /\ observedSender \in Senders
    /\ relayedUploads = anonymousShardsStored
    /\ Cardinality(ephemeralIssuerIds) = anonymousShardsStored

\* 2. No voucher double-spend: every stored shard has its own spent nullifier.
Safety_NoVoucherDoubleSpend ==
    /\ Cardinality(spentNullifiers) = anonymousShardsStored
    /\ anonymousShardsStored <= mintedVouchers
    /\ mintedVouchers <= MaxVouchers

\* Every fair execution eventually stores all MaxVouchers anonymized shards.
Liveness_AnonymousBackupCompletes ==
    <> (anonymousShardsStored = MaxVouchers)

=============================================================================
