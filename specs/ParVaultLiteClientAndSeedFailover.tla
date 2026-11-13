------------------- MODULE ParVaultLiteClientAndSeedFailover -------------------
EXTENDS Naturals

CONSTANTS
    K,                      \* Minimum Reed-Solomon shards required to reconstruct (e.g. 16)
    N,                      \* Total Reed-Solomon shards syndicated per stripe (e.g. 20)
    TotalVaultFiles,        \* Total files in the user's vault snapshot (e.g. 4)
    SelectiveTargetCount    \* Number of files selectively requested by the Lite Client (e.g. 1)

ASSUME
    /\ K > 0
    /\ N > K
    /\ TotalVaultFiles >= SelectiveTargetCount
    /\ SelectiveTargetCount > 0

VARIABLES
    liteUploadedFiles,          \* Encrypted 1.0x files deposited by LiteClient to SeedServer (0..TotalVaultFiles)
    syndicatedFiles,            \* Files RS-encoded (N shards) and syndicated by SeedServer to Mesh (0..TotalVaultFiles)
    seedAlive,                  \* TRUE while NAS / parvault-seed is online; FALSE if NAS dies
    meshHealthyShards,          \* Surviving shards in the Neighborhood Cloud mesh (K..N)
    selectiveRestoredCount,     \* Count of selectively restored files on the laptop (0..SelectiveTargetCount)
    stripesDownloaded,          \* Total file stripes downloaded during selective restore
    restoreRoute,               \* "NONE", "SEED_FAST_PATH", or "MESH_DIRECT_FAILOVER"
    selectiveRestoreComplete    \* TRUE once the requested selective subset is verified on the laptop

vars == <<liteUploadedFiles, syndicatedFiles, seedAlive, meshHealthyShards,
          selectiveRestoredCount,
          stripesDownloaded, restoreRoute, selectiveRestoreComplete>>

Init ==
    /\ liteUploadedFiles = 0
    /\ syndicatedFiles = 0
    /\ seedAlive = TRUE
    /\ meshHealthyShards = N
    /\ selectiveRestoredCount = 0
    /\ stripesDownloaded = 0
    /\ restoreRoute = "NONE"
    /\ selectiveRestoreComplete = FALSE

\* Step 1: LiteClient encrypts a file locally and deposits 1.0x ciphertext to SeedServer.
\* The client encrypts before upload (structural; see below).
LiteClientDepositEncryptedFile ==
    /\ seedAlive = TRUE
    /\ liteUploadedFiles < TotalVaultFiles
    /\ liteUploadedFiles' = liteUploadedFiles + 1
    /\ UNCHANGED <<syndicatedFiles, seedAlive, meshHealthyShards,
                   selectiveRestoredCount,
                   stripesDownloaded, restoreRoute, selectiveRestoreComplete>>

\* Step 2: SeedServer encodes ciphertext into N Reed-Solomon shards and syndicates to the mesh.
\* The seed holds and forwards ciphertext only (structural; see below).
SeedServerSyndicateToMesh ==
    /\ seedAlive = TRUE
    /\ syndicatedFiles < liteUploadedFiles
    /\ syndicatedFiles' = syndicatedFiles + 1
    /\ UNCHANGED <<liteUploadedFiles, seedAlive, meshHealthyShards,
                   selectiveRestoredCount,
                   stripesDownloaded, restoreRoute, selectiveRestoreComplete>>

\* Environmental Fault A: The NAS / SeedServer suffers a hardware failure or power outage AFTER syndication.
SeedServerCatastrophicFailure ==
    /\ syndicatedFiles = TotalVaultFiles
    /\ seedAlive = TRUE
    /\ seedAlive' = FALSE
    /\ UNCHANGED <<liteUploadedFiles, syndicatedFiles, meshHealthyShards,
                   selectiveRestoredCount,
                   stripesDownloaded, restoreRoute, selectiveRestoreComplete>>

\* Environmental Fault B: Up to (N - K) external mesh nodes drop offline concurrently.
MeshPeerChurn ==
    /\ meshHealthyShards > K   \* @assume mesh-churn-stops-at-k: churn never takes the mesh below K healthy shards (threat model; NasDeathSurvivableInvariant rests on it)
    /\ meshHealthyShards' = meshHealthyShards - 1
    /\ UNCHANGED <<liteUploadedFiles, syndicatedFiles, seedAlive,
                   selectiveRestoredCount,
                   stripesDownloaded, restoreRoute, selectiveRestoreComplete>>

\* Step 3A ("Cloud-Away-From-Home" Fast Path): SeedServer is alive; LiteClient fetches only SelectiveTargetCount.
SelectiveRestoreViaSeedFastPath ==
    /\ syndicatedFiles = TotalVaultFiles
    /\ ~selectiveRestoreComplete
    /\ seedAlive = TRUE
    /\ selectiveRestoredCount' = SelectiveTargetCount
    /\ stripesDownloaded' = SelectiveTargetCount
    /\ restoreRoute' = "SEED_FAST_PATH"
    /\ selectiveRestoreComplete' = TRUE
    /\ UNCHANGED <<liteUploadedFiles, syndicatedFiles, seedAlive, meshHealthyShards>>

\* Step 3B (NAS-Death Direct Mesh Failover): SeedServer is DEAD (seedAlive = FALSE),
\* but LiteClient speaks the identical protocol and reconstructs K-of-N shards directly from the mesh!
SelectiveRestoreDirectMeshFailover ==
    /\ syndicatedFiles = TotalVaultFiles
    /\ ~selectiveRestoreComplete
    /\ seedAlive = FALSE
    /\ meshHealthyShards >= K
    /\ selectiveRestoredCount' = SelectiveTargetCount
    /\ stripesDownloaded' = SelectiveTargetCount
    /\ restoreRoute' = "MESH_DIRECT_FAILOVER"
    /\ selectiveRestoreComplete' = TRUE
    /\ UNCHANGED <<liteUploadedFiles, syndicatedFiles, seedAlive, meshHealthyShards>>

Idle ==
    /\ selectiveRestoreComplete
    /\ UNCHANGED vars

Next ==
    \/ LiteClientDepositEncryptedFile
    \/ SeedServerSyndicateToMesh
    \/ SeedServerCatastrophicFailure
    \/ MeshPeerChurn
    \/ SelectiveRestoreViaSeedFastPath
    \/ SelectiveRestoreDirectMeshFailover
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(LiteClientDepositEncryptedFile)
    /\ WF_vars(SeedServerSyndicateToMesh)
    /\ WF_vars(SelectiveRestoreViaSeedFastPath)
    /\ WF_vars(SelectiveRestoreDirectMeshFailover)

TypeOK ==
    /\ liteUploadedFiles \in 0..TotalVaultFiles
    /\ syndicatedFiles \in 0..TotalVaultFiles
    /\ seedAlive \in BOOLEAN
    /\ meshHealthyShards \in K..N
    /\ selectiveRestoredCount \in 0..SelectiveTargetCount
    /\ stripesDownloaded \in 0..SelectiveTargetCount
    /\ restoreRoute \in {"NONE", "SEED_FAST_PATH", "MESH_DIRECT_FAILOVER"}
    /\ selectiveRestoreComplete \in BOOLEAN

\* Neither the seed nor mesh peers ever receive K_user: @structural client-strips-key and
\* @structural client-strips-key: holds by construction; traced to the compile-time type LiteStripeSyndicationBundle (src/bootstrap.rs), which has no key field
\* @structural seed-forwards-ciphertext. It holds by type, not by a modelled guard: the lite client sends a
\* @structural seed-forwards-ciphertext: holds by construction; traced to compile-time code: ingest_lite_stripe and run_lite_fan_out (src/bootstrap.rs) handle only bundle.ciphertext_bytes and shards read back from the block store
\* `LiteStripeSyndicationBundle` (`src/bootstrap.rs`), which has no key field, carrying the
\* stripe already encrypted by `encrypt_stripe` (`src/cli/folder.rs`), and the seed forwards
\* shards of that ciphertext. Not model-checked (L-47 item 2).

\* SAFETY INVARIANT 2: Even if the NAS dies (seedAlive = FALSE), any syndicated vault remains
\* 100% recoverable by the LiteClient directly from the mesh as long as >= K shards survive.
NasDeathSurvivableInvariant ==
    (syndicatedFiles = TotalVaultFiles) => (seedAlive \/ meshHealthyShards >= K)

\* SAFETY INVARIANT 3: Selective partial restore never downloads unrequested files in the vault.
SelectiveBandwidthSavingInvariant ==
    /\ stripesDownloaded <= SelectiveTargetCount
    /\ stripesDownloaded < TotalVaultFiles

\* LIVENESS PROPERTY: Selective restore eventually completes regardless of whether the NAS dies after syndication.
EventuallySelectiveRestoreComplete ==
    <>(selectiveRestoreComplete)

=============================================================================
