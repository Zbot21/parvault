------------------- MODULE ParVaultZeroKeyAdminAndQuorum -------------------
\* @traceability
\*   adr      ADR-16 ADR-25 ADR-26
\*   const    HonestCouncil    -> model-only: model identities
\*   const    ByzantineCouncil -> model-only: model identities (@assume byzantine-below-quorum)
\*   const    StrangerSigners  -> model-only: model identities
\*   const    QuorumM          -> model-only: the quorum comes from the installed council manifest
\*   const    MaxNonces        -> model-only: model bound
\*   const    MaxCouncilEpoch  -> model-only: model bound on council rotations
\*   const    RootOnDisk       -> model-only: the seed's tracker_admin.seed holds the scope root key A (TLC runs both values)
\* @end
EXTENDS Naturals, FiniteSets, Sequences

\* Formal TLA+ Specification of ParVault's Zero-Private-Key-On-VPS `admin_rpc`
\* Architecture and Federated `M-of-N` Council Eviction Governance (`ADR-26`).
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
    MaxNonces,          \* Bounded pool of fresh single-use admin_rpc challenge nonces (e.g. 3)
    MaxCouncilEpoch,    \* Bound on installed council epochs (e.g. 3)
    RootOnDisk          \* TRUE: the scope root A's key is in tracker_admin.seed on the seed's disk (F-53)

Council == HonestCouncil \cup ByzantineCouncil
AllSigners == Council \cup StrangerSigners
Targets == {"AbuseTarget", "InnocentTarget", "OwnerTarget"}
Slots == {"primary", "cosig1", "cosig2"}
OrderIds == {"ord_abuse", "ord_forged_dup", "ord_tampered", "ord_owner"}
HomelabOwner == "homelab_owner"

ASSUME
    /\ QuorumM >= 2
    /\ HonestCouncil \cap ByzantineCouncil = {}
    /\ StrangerSigners \cap Council = {}
    /\ HomelabOwner \notin AllSigners
    /\ Cardinality(ByzantineCouncil) <= QuorumM - 1   \* @assume byzantine-below-quorum: threat model; fewer than QuorumM council members are Byzantine (which of them is chosen in Init)
    /\ Cardinality(HonestCouncil) >= QuorumM
    /\ MaxNonces >= 2
    /\ MaxCouncilEpoch >= 3
    /\ RootOnDisk \in BOOLEAN

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
    privateRingEvicted,     \* Targets zero-shredded on PrivateRing / HomelabVault nodes
    ownerOrderSigned,       \* TRUE once the HomelabOwner signs an eviction order for its own ring
    councilLog,             \* The seed's installed council manifests in install order (item 6, plan-6 change 6)
    advCouncilTries,        \* Bounded count of adversary InstallCouncilManifest submissions
    cfgRoot,                \* The seed's configured scope root (the flag wins over tracker_admin.seed, F-53)
    clientLog,              \* A public client's installed council manifests (it pinned A and holds A's epoch 1)
    clientPin               \* The client's pinned tracker admin key (moves only at a re-root it installs)

vars == <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
          consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
          confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt, tamperedOrderBuilt,
          seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted, ownerOrderSigned,
          councilLog, advCouncilTries, cfgRoot, clientLog, clientPin>>
councilVars == <<councilLog, advCouncilTries, cfgRoot, clientLog, clientPin>>

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
    Cardinality(ValidDistinctSigners(ord, Council)) >= QuorumM   \* @guard quorum-count sym=src/storage/eviction.rs::tally_and_verify_quorum_raw

\* The admin RPC compares the request's nonce with the connection's single active challenge
\* (`validate_admin_rpc_slice_replay_and_auth_meta`, src/admin_rpc.rs).
ChallengeMatches(nonce) == activeChallenge > 0 /\ nonce = activeChallenge   \* @guard nonce-fresh sym=src/admin_rpc.rs::validate_admin_rpc_slice_replay_and_auth_meta
OrderIdFresh(id) == id \notin seenOrderIds   \* @guard order-id-fresh sym=src/storage/eviction.rs::replay_slot_check

\* A PrivateRing node resolves its order authority from the manifest whose scope root is its
\* genesis (owner) key (council_scope_root / council_from_manifest), never the public council.
OrderMeetsPrivateRingAuth(ord) ==
    Cardinality(ValidDistinctSigners(ord, {HomelabOwner})) >= 1   \* @guard ring-scope sym=src/storage/council.rs::council_from_manifest

\* The owner's own eviction order for its ring (the honest accept path of ring-scope).
OwnerRingOrder ==
    [id |-> "ord_owner", target |-> "OwnerTarget",
     sigs |-> {<<"primary", HomelabOwner, "OwnerTarget">>}]

\* --- Council manifests: install, rotation and re-root (item 6; F-53, L-98) ---------------------
\* A public seed installs `CouncilManifest`s through `InstallCouncilManifest` (admin RPC,
\* `install_council_manifest`). Epoch 1 is signed by the scope root; epoch n + 1 by a quorum of
\* epoch n's members (a rotation, same root); or, in public mode only, epoch n + 1 moves the root
\* (a re-root, signed under its own domain binding the old root, by a quorum of epoch n and by the
\* new root). A seed accepts a re-root only onto its configured root, a client only away from its
\* pinned root. A seed installs nothing while its configured root's key is on its disk and no
\* manifest is installed under that root. Re-installing the installed manifest is a no-op.
ScopeRoot == "scope_root"     \* A: the root a v0.5.0 seed advertised (its tracker_admin.seed key)
NewRoot == "new_root"         \* B: the off-disk key given by --admin-rpc-pubkey
RogueRoot == "rogue_root"     \* a root whose key the adversary holds
Roots == {ScopeRoot, NewRoot, RogueRoot}
ScopeRootKey == "scope_root_key"
NewRootKey == "new_root_key"
RogueRootKey == "rogue_root_key"
RootKeys == {ScopeRootKey, NewRootKey, RogueRootKey}
RootKeyOf(r) == CASE r = ScopeRoot -> ScopeRootKey [] r = NewRoot -> NewRootKey [] OTHER -> RogueRootKey
\* @assume new-root-key-off-disk: B's key (the --admin-rpc-pubkey holder) is never on the seed's
\* disk nor in the adversary's hands. A's key is on the disk when RootOnDisk and is then stolen by
\* AdversarySeizeVpsDisk. (F-53: a flag equal to the on-disk key is the RootOnDisk case of A.)
RootOnSeedDisk(r) == PrivKey(RootKeyOf(r)) \in vpsDiskSecrets
Last(log) == log[Len(log)]
CurrentCouncil == IF councilLog = <<>> THEN {} ELSE Last(councilLog).members
\* @assume honest-rotation-majority: an honest rotation keeps Byzantine members below the quorum.
\* The model uses one constant QuorumM; the code uses each manifest's own quorum field (a strict
\* majority of its members, checked by council_manifest_decision).
HonestMemberChoices ==
    { m \in SUBSET Council : Cardinality(m) >= QuorumM /\ Cardinality(m \cap ByzantineCouncil) < QuorumM }

\* The v0.5.0 state of a seed and its clients: epoch 1 under the on-disk root A, already installed.
LegacyEpoch1 == [scope |-> ScopeRoot, epoch |-> 1, members |-> HonestCouncil, kind |-> "rotate",
                 from |-> ScopeRoot, signers |-> {ScopeRootKey}, shapeOk |-> TRUE, legacy |-> TRUE]

\* `council_manifest_decision` over `facts` (shared by seed and client): `kind` and `from` are the
\* signing domain (a re-root's signatures bind the old root and never verify as a rotation).
QuorumOf(m, log) == Cardinality(m.signers \cap Last(log).members) >= QuorumM
ChainStepOk(m, log) ==
    /\ m.shapeOk
    /\ m.epoch = Len(log) + 1
    /\ IF log = <<>> THEN m.kind = "rotate" /\ RootKeyOf(m.scope) \in m.signers
       ELSE IF m.scope = Last(log).scope
            THEN m.kind = "rotate" /\ QuorumOf(m, log)   \* @guard council-manifest sym=src/storage/council.rs::council_manifest_decision
            ELSE /\ m.kind = "reroot"
                 /\ m.from = Last(log).scope
                 /\ QuorumOf(m, log)   \* @guard council-reroot-quorum sym=src/storage/council.rs::council_manifest_decision
                 /\ RootKeyOf(m.scope) \in m.signers   \* @guard council-reroot-new-root sym=src/storage/council.rs::council_manifest_decision

\* `seed_council_install_decision`: no install while the configured root's key is on the disk and
\* nothing is installed under that root (the epoch under the configured root, not any file).
SeedRootGateOk ==
    ~(RootOnSeedDisk(cfgRoot) /\ (councilLog = <<>> \/ Last(councilLog).scope # cfgRoot))   \* @guard council-root-not-on-disk sym=src/storage/council.rs::seed_council_install_decision

\* Seed shape (`CouncilInstallRole::PublicSeed`): every accepted manifest is under the configured root.
CouncilManifestAccepted(m) ==
    /\ SeedRootGateOk
    /\ m.scope = cfgRoot
    /\ ChainStepOk(m, councilLog)

\* Client shape (`CouncilInstallRole::PublicClient`): a rotation under the pinned root, or a re-root
\* away from it.
ClientAccepts(m) ==
    /\ clientLog # <<>>
    /\ IF m.scope = Last(clientLog).scope THEN m.scope = clientPin ELSE Last(clientLog).scope = clientPin
    /\ ChainStepOk(m, clientLog)

\* `install_council_manifest` on the seed.
InstallCouncilManifest(m) ==
    /\ IF councilLog # <<>> /\ m = Last(councilLog)
       THEN UNCHANGED councilLog
       ELSE IF CouncilManifestAccepted(m)
            THEN councilLog' = Append(councilLog, m)
            ELSE UNCHANGED councilLog
    /\ UNCHANGED <<clientLog, clientPin>>

\* `install_council_manifest` on the client: a re-root also moves its pin (all three stores).
ClientInstall(m) ==
    /\ IF clientLog # <<>> /\ m = Last(clientLog)
       THEN UNCHANGED <<clientLog, clientPin>>
       ELSE IF ClientAccepts(m)
            THEN /\ clientLog' = Append(clientLog, m)
                 /\ clientPin' = m.scope
            ELSE UNCHANGED <<clientLog, clientPin>>
    /\ UNCHANGED councilLog

HonestManifest(mem) ==
    IF councilLog = <<>>
    THEN [scope |-> cfgRoot, epoch |-> 1, members |-> mem, kind |-> "rotate", from |-> cfgRoot,
          signers |-> {RootKeyOf(cfgRoot)}, shapeOk |-> TRUE, legacy |-> FALSE]
    ELSE IF Last(councilLog).scope = cfgRoot
    THEN [scope |-> cfgRoot, epoch |-> Len(councilLog) + 1, members |-> mem, kind |-> "rotate",
          from |-> cfgRoot, signers |-> CurrentCouncil \cap HonestCouncil, shapeOk |-> TRUE,
          legacy |-> FALSE]
    ELSE [scope |-> cfgRoot, epoch |-> Len(councilLog) + 1, members |-> mem, kind |-> "reroot",
          from |-> Last(councilLog).scope,
          signers |-> (CurrentCouncil \cap HonestCouncil) \cup {RootKeyOf(cfgRoot)},
          shapeOk |-> TRUE, legacy |-> FALSE]

HonestInstallCouncil ==
    /\ Len(councilLog) < MaxCouncilEpoch
    /\ \E mem \in HonestMemberChoices : InstallCouncilManifest(HonestManifest(mem))
    /\ UNCHANGED <<advCouncilTries, cfgRoot>>

\* The client follows the seed's chain (the catch-up fetch, or `parvault council install`).
ClientFollowSeed ==
    /\ Len(clientLog) < Len(councilLog)
    /\ ClientInstall(councilLog[Len(clientLog) + 1])
    /\ UNCHANGED <<advCouncilTries, cfgRoot>>

\* The adversary submits, to the seed or the client, any manifest it can sign: any root, either
\* domain (a re-root bound to any old root), any epoch, any members, a bad shape, signed by every
\* key it controls (Byzantine and stranger keys, the rogue root, stolen disk secrets such as A's
\* key when RootOnDisk); or replays one already installed. A rotation never reads `from`, so it is
\* fixed to the manifest's own root (no loss of adversary power).
AttackerSignerIds == { s \in AllSigners \cup RootKeys : PrivKey(s) \in attackerKeys }
\* @assume reroot-ceremony-files-public: a re-root is signed by passing one manifest file between
\* holders (`CouncilManifest::sign_reroot`, once per key, any order), so a file signed by the old
\* council's honest quorum but not (yet, or ever) by the new root exists and the adversary may read
\* it: the new root's holder may not have signed or may have declined. Only the new-root guard
\* keeps such a file from installing. The intended new root is B.
PartialReroots(log) ==
    IF log = <<>> \/ Len(log) >= MaxCouncilEpoch THEN {}
    ELSE { [scope |-> NewRoot, epoch |-> Len(log) + 1, members |-> mem, kind |-> "reroot",
            from |-> Last(log).scope,
            signers |-> ((Last(log).members \cap HonestCouncil) \cup AttackerSignerIds) \ {NewRootKey},
            shapeOk |-> TRUE, legacy |-> FALSE] : mem \in HonestMemberChoices }
AdversaryManifests ==
    { m \in { [scope |-> sc, epoch |-> e, members |-> mem, kind |-> k, from |-> fr,
                signers |-> AttackerSignerIds, shapeOk |-> ok, legacy |-> FALSE] :
                 sc \in Roots, e \in 1..MaxCouncilEpoch, mem \in (SUBSET AllSigners) \ {{}},
                 k \in {"rotate", "reroot"}, fr \in Roots, ok \in BOOLEAN } :
        m.kind = "reroot" \/ m.from = m.scope }
    \cup { councilLog[i] : i \in 1..Len(councilLog) }
    \cup PartialReroots(councilLog) \cup PartialReroots(clientLog)

AdversaryInstallCouncil ==
    /\ advCouncilTries < 2
    /\ advCouncilTries' = advCouncilTries + 1
    /\ \E m \in AdversaryManifests : InstallCouncilManifest(m) \/ ClientInstall(m)
    /\ UNCHANGED cfgRoot

CouncilStep ==
    /\ (HonestInstallCouncil \/ ClientFollowSeed \/ AdversaryInstallCouncil)
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, seenOrderIds, appliedOrderLog,
                   publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>

Init ==
    \* Zero-Private-Key-On-VPS: VPS disk holds transport & per-node HMAC keys ONLY;
    \* ZERO Council private keys (`PrivKey(c)`) exist on the VPS filesystem.
    \* @structural no-admin-key-persist: a seed given `--admin-rpc-pubkey` writes no admin key to its disk;
    \* holds by construction; traced to test trust_enforcement::admin_key_never_persisted_on_seed
    \* That test covers the explicit-key case only. A persistent seed started WITHOUT
    \* `--admin-rpc-pubkey` (or with an existing file) holds the scope root A's key in
    \* `tracker_admin.seed` on its disk: RootOnDisk (F-53). No council member key is ever on it.
    /\ vpsDiskSecrets = {<<"vps_secret", "transport_seed">>, <<"vps_secret", "eviction_hmac_seed">>}
                        \cup (IF RootOnDisk THEN {PrivKey(ScopeRootKey)} ELSE {})
    /\ vpsCompromised = FALSE
    \* Any subset of the (at most QuorumM - 1) Byzantine councilors is corrupt (P-03).
    /\ attackerKeys \in { { PrivKey(s) : s \in (B \cup StrangerSigners \cup {RogueRootKey}) } : B \in SUBSET ByzantineCouncil }
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
    /\ ownerOrderSigned = FALSE
    \* Fresh seed (no council) or the v0.5.0 legacy state (A's epoch 1 installed); the configured
    \* root is A (no flag) or B (restarted with --admin-rpc-pubkey B). The client pinned A and
    \* holds A's epoch 1 (its own epoch 1 is a manual install, outside this model).
    /\ councilLog \in {<<>>, <<LegacyEpoch1>>}
    /\ cfgRoot \in {ScopeRoot, NewRoot}
    /\ advCouncilTries = 0
    /\ clientLog = <<LegacyEpoch1>>
    /\ clientPin = ScopeRoot

\* 1. Cryptographic Burden-of-Proof Abuse Report (`VerifiableAbuseReport`):
\*    Authenticates "AbuseTarget" via AES-256-GCM + Merkle proof and queues for review
\*    WITHOUT auto-deleting any shards (`publicSwarmEvicted` is UNCHANGED).
SubmitVerifiedAbuseReport ==
    /\ "AbuseTarget" \notin confirmedAbuseTargets
    /\ confirmedAbuseTargets' = confirmedAbuseTargets \cup {"AbuseTarget"}
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   honestOrderSigs, forgedOrderBuilt, tamperedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
                   publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

\* 4. Adversary crafts duplicate-signer / sub-quorum order targeting "InnocentTarget"
\*    using compromised VPS secrets + M - 1 Byzantine councilors + stranger keys.
AdversaryBuildDuplicateSignerOrder ==
    /\ ~forgedOrderBuilt
    /\ forgedOrderBuilt' = TRUE
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, tamperedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

\* 5. Adversary intercepts an honest-signed order and mutates `target` to "InnocentTarget"
\*    while appending M - 1 rogue council co-signatures.
AdversaryBuildTamperedTargetOrder ==
    /\ honestOrderSigs # {}
    /\ ~tamperedOrderBuilt
    /\ tamperedOrderBuilt' = TRUE
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   seenOrderIds, appliedOrderLog, publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
                   publicSwarmEvicted, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
                   privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
           ELSE /\ UNCHANGED <<seenOrderIds, appliedOrderLog, publicSwarmEvicted, ownerOrderSigned>>
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, nextNonce,
                   rejectedReplays, confirmedAbuseTargets, honestOrderSigs,
                   forgedOrderBuilt, tamperedOrderBuilt, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
                            appliedOrderLog, publicSwarmEvicted, ownerOrderSigned>>
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, nextNonce, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, privateRingEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

\* 10. Cross-mode council broadcast check (`ADR-26` Strict Mode Isolation):
\*     A quorum-signed Public Tracker Council order and the owner's own order both reach a
\*     `HomelabRedundancyVault` (`PrivateRing`) node, which evaluates each ONLY against
\*     `{HomelabOwner}`. A rejected order changes nothing (no counter is bumped).
HomelabOwnerSignsRingOrder ==
    /\ ~ownerOrderSigned
    /\ ownerOrderSigned' = TRUE
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, seenOrderIds, appliedOrderLog,
                   publicSwarmEvicted, privateRingEvicted>>
    /\ UNCHANGED councilVars

RingCandidateOrders ==
    (IF OrderMeetsCouncilQuorum(HonestAbuseOrder) THEN {HonestAbuseOrder} ELSE {})
    \cup (IF ownerOrderSigned THEN {OwnerRingOrder} ELSE {})

ApplyOrderOnPrivateRing(ord) ==
    /\ OrderMeetsPrivateRingAuth(ord)
    /\ ord.target \notin privateRingEvicted
    /\ privateRingEvicted' = privateRingEvicted \cup {ord.target}
    /\ UNCHANGED <<vpsDiskSecrets, vpsCompromised, attackerKeys, activeChallenge, nextNonce,
                   consumedNonces, acceptedRpcNonces, rejectedReplays, advRpcSubmissions,
                   confirmedAbuseTargets, honestOrderSigs, forgedOrderBuilt,
                   tamperedOrderBuilt, seenOrderIds, appliedOrderLog,
                   publicSwarmEvicted, ownerOrderSigned>>
    /\ UNCHANGED councilVars

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
    \/ HomelabOwnerSignsRingOrder
    \/ \E ord \in RingCandidateOrders : ApplyOrderOnPrivateRing(ord)
    \/ CouncilStep
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
    /\ Len(councilLog) \in 0..MaxCouncilEpoch
    /\ Len(clientLog) \in 1..MaxCouncilEpoch
    /\ advCouncilTries \in 0..2
    /\ cfgRoot \in {ScopeRoot, NewRoot}
    /\ clientPin \in Roots

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
\* Only the HomelabOwner's own orders can zero-shred shards on a PrivateRing / Homelab node; a Public Tracker Council order never can.
Safety_PrivateRingImmuneToPublicCouncil ==
    privateRingEvicted \subseteq (IF ownerOrderSigned THEN {OwnerRingOrder.target} ELSE {})

\* INVARIANT 5 (Council chain, item 6; re-root, L-98), for the seed's and the client's logs:
\* epochs 1..n in order, each of a valid shape; epoch 1 signed by its root; a later epoch under the
\* same root is a rotation signed by at least one honest member of the council before it; a root
\* change is a re-root bound to the previous root, signed by such a member and by the new root,
\* onto a root the adversary does not hold. No stolen key set installs, rotates or re-roots.
ChainAuthorised(log) ==
    \A i \in 1..Len(log) :
        /\ log[i].epoch = i
        /\ log[i].shapeOk
        /\ log[i].scope # RogueRoot
        /\ (i = 1 => RootKeyOf(log[i].scope) \in log[i].signers)
        /\ (i > 1 => log[i].signers \cap log[i - 1].members \cap HonestCouncil # {})
        /\ (i > 1 /\ log[i].scope # log[i - 1].scope =>
               /\ log[i].kind = "reroot"
               /\ log[i].from = log[i - 1].scope
               /\ RootKeyOf(log[i].scope) \in log[i].signers)
Safety_CouncilChainAuthorised ==
    /\ ChainAuthorised(councilLog)
    /\ ChainAuthorised(clientLog)
    /\ clientPin = Last(clientLog).scope

\* INVARIANT 6 (F-53): a council installed by this model is never rooted on a key on the seed's
\* disk: neither an epoch 1 nor a re-root onto it. (The legacy epoch 1 predates the fix.)
Safety_Epoch1RootedOffDisk ==
    \A i \in 1..Len(councilLog) :
        (~councilLog[i].legacy /\ (i = 1 \/ councilLog[i].scope # councilLog[i - 1].scope))
            => PrivKey(RootKeyOf(councilLog[i].scope)) \notin vpsDiskSecrets

\* INVARIANT 7 (L-98): after a re-root, no manifest under the old root ever installs.
Safety_NoOldRootAfterReRoot ==
    \A log \in {councilLog, clientLog} :
        \A j, k \in 1..Len(log) :
            (j < k /\ log[j].kind = "reroot") => log[k].scope # log[j].from

\* LIVENESS PROPERTY:
\* Despite VPS disk compromise and M - 1 Byzantine councilors, confirmed abuse is eventually
\* evicted by the M honest councilors over `admin_rpc`.
Liveness_HonestQuorumEvictsConfirmedAbuse ==
    <>("AbuseTarget" \in publicSwarmEvicted)

=============================================================================
