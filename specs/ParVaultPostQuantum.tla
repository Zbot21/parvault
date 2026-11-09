------------------------- MODULE ParVaultPostQuantum -------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    ClassicalMasterKeyBits,     \* 512-bit PqVaultMasterKey (K_outer || K_inner)
    ClassicalAesBits,           \* 256-bit AES-256-GCM & SHA-256 primitive width
    MinPostQuantumBitFloor      \* 128-bit NIST Post-Quantum security floor

ASSUME
    /\ ClassicalMasterKeyBits = 512
    /\ ClassicalAesBits = 256
    /\ MinPostQuantumBitFloor = 128

VARIABLES
    x25519Broken,               \* TRUE once CRQC executes Shor's algorithm on ECDLP
    ed25519Broken,              \* TRUE once CRQC executes Shor's algorithm on Ed25519
    mlKem768Broken,             \* FALSE (NIST FIPS 203 ML-KEM-768 Module-LWE remains hard)
    mlDsa65Broken,              \* FALSE (NIST FIPS 204 ML-DSA-65 Module-LWE/SIS remains hard)
    groverApplied,              \* TRUE once CRQC applies Grover's quadratic search speedup
    effectiveMasterKeyBits,     \* 512 classical -> 256 post-quantum bits under Grover
    effectiveSymmetricBits,     \* 256 classical -> 128 post-quantum bits under Grover
    hybridKemEstablished,       \* TRUE once X25519 + ML-KEM-768 session key is derived
    hybridKemCompromised,       \* TRUE only if BOTH X25519 and ML-KEM-768 are broken
    hybridSigVerified,          \* TRUE once Ed25519 + ML-DSA-65 composite signature verified
    quantumForgeryAccepted,     \* TRUE only if BOTH Ed25519 and ML-DSA-65 are forged
    pqBackupSealed,             \* TRUE once 512-bit cascaded AEAD stripe & PQ envelope sealed
    hndlAttackAttempted,        \* TRUE once adversary executes Harvest-Now-Decrypt-Later attack
    hndlPlaintextExposed        \* TRUE if HNDL adversary recovers any vault plaintext

vars == <<x25519Broken, ed25519Broken, mlKem768Broken, mlDsa65Broken,
          groverApplied, effectiveMasterKeyBits, effectiveSymmetricBits,
          hybridKemEstablished, hybridKemCompromised, hybridSigVerified,
          quantumForgeryAccepted, pqBackupSealed, hndlAttackAttempted,
          hndlPlaintextExposed>>

Init ==
    /\ x25519Broken           = FALSE
    /\ ed25519Broken          = FALSE
    /\ mlKem768Broken         = FALSE
    /\ mlDsa65Broken          = FALSE
    /\ groverApplied          = FALSE
    /\ effectiveMasterKeyBits = ClassicalMasterKeyBits
    /\ effectiveSymmetricBits = ClassicalAesBits
    /\ hybridKemEstablished   = FALSE
    /\ hybridKemCompromised   = FALSE
    /\ hybridSigVerified      = FALSE
    /\ quantumForgeryAccepted = FALSE
    /\ pqBackupSealed         = FALSE
    /\ hndlAttackAttempted    = FALSE
    /\ hndlPlaintextExposed   = FALSE

\* Action 1: QuantumShorBreaksClassicalAsymmetric
\* Models arrival of a Cryptographically Relevant Quantum Computer (CRQC) running
\* Shor's polynomial-time discrete-log algorithm against elliptic curves (X25519 & Ed25519).
\* Lattice-based Module-LWE / Module-SIS primitives (ML-KEM-768 & ML-DSA-65) remain unbroken.
QuantumShorBreaksClassicalAsymmetric ==
    /\ (~x25519Broken \/ ~ed25519Broken)
    /\ x25519Broken'           = TRUE
    /\ ed25519Broken'          = TRUE
    /\ hybridKemCompromised'   = (TRUE /\ mlKem768Broken)
    /\ quantumForgeryAccepted' = (TRUE /\ mlDsa65Broken)
    /\ UNCHANGED <<mlKem768Broken, mlDsa65Broken, groverApplied,
                   effectiveMasterKeyBits, effectiveSymmetricBits,
                   hybridKemEstablished, hybridSigVerified, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed>>

\* Action 2: QuantumGroverQuadraticSpeedup
\* Models Grover's O(2^(n/2)) quantum search algorithm halving effective symmetric
\* and hash bit-security: 512-bit PqVaultMasterKey -> 256 bits; 256-bit AES/SHA -> 128 bits.
QuantumGroverQuadraticSpeedup ==
    /\ ~groverApplied
    /\ groverApplied'          = TRUE
    /\ effectiveMasterKeyBits' = ClassicalMasterKeyBits \div 2
    /\ effectiveSymmetricBits' = ClassicalAesBits \div 2
    /\ UNCHANGED <<x25519Broken, ed25519Broken, mlKem768Broken, mlDsa65Broken,
                   hybridKemEstablished, hybridKemCompromised, hybridSigVerified,
                   quantumForgeryAccepted, pqBackupSealed, hndlAttackAttempted,
                   hndlPlaintextExposed>>

\* Action 3: EstablishHybridKemSession
\* Derives a 256-bit session key via HKDF-SHA512(ss_x25519 || ss_mlkem768, context).
\* By the PRF property of HKDF-SHA512, the derived key remains pseudorandom and secret
\* as long as at least one component KEM remains secure: ~(x25519Broken /\ mlKem768Broken).
EstablishHybridKemSession ==
    /\ ~hybridKemEstablished
    /\ hybridKemEstablished' = TRUE
    /\ hybridKemCompromised' = (x25519Broken /\ mlKem768Broken)
    /\ UNCHANGED <<x25519Broken, ed25519Broken, mlKem768Broken, mlDsa65Broken,
                   groverApplied, effectiveMasterKeyBits, effectiveSymmetricBits,
                   hybridSigVerified, quantumForgeryAccepted, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed>>

\* Action 4: VerifyHybridPqSignature
\* Verifies a HybridPqSignature on a Web-of-Trust certificate, RepairGrant, BearerQuotaVoucher,
\* or SignedDhtManifestEnvelope. Verification requires BOTH Ed25519 AND ML-DSA-65 (FIPS 204)
\* signatures to be valid, so an adversary can forge only if (ed25519Broken /\ mlDsa65Broken).
VerifyHybridPqSignature ==
    /\ ~hybridSigVerified
    /\ hybridSigVerified'      = TRUE
    /\ quantumForgeryAccepted' = (ed25519Broken /\ mlDsa65Broken)
    /\ UNCHANGED <<x25519Broken, ed25519Broken, mlKem768Broken, mlDsa65Broken,
                   groverApplied, effectiveMasterKeyBits, effectiveSymmetricBits,
                   hybridKemEstablished, hybridKemCompromised, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed>>

\* Action 5: SealPostQuantumVaultBackup
\* Encrypts the stripe with 512-bit PqVaultMasterKey cascaded AEAD, wraps the upload in
\* a HybridKemCiphertext (X25519 + ML-KEM-768) onion envelope, and signs the manifest
\* with a HybridPqSignature (Ed25519 + ML-DSA-65).
SealPostQuantumVaultBackup ==
    /\ hybridKemEstablished
    /\ hybridSigVerified
    /\ ~pqBackupSealed
    /\ pqBackupSealed' = TRUE
    /\ UNCHANGED <<x25519Broken, ed25519Broken, mlKem768Broken, mlDsa65Broken,
                   groverApplied, effectiveMasterKeyBits, effectiveSymmetricBits,
                   hybridKemEstablished, hybridKemCompromised, hybridSigVerified,
                   quantumForgeryAccepted, hndlAttackAttempted,
                   hndlPlaintextExposed>>

\* Action 6: AttemptHarvestNowDecryptLater
\* Adversary records all encrypted shards, hybrid onion envelopes, and DHT manifests today,
\* then attacks them on a future CRQC with both Shor's and Grover's algorithms active.
AttemptHarvestNowDecryptLater ==
    /\ pqBackupSealed
    /\ x25519Broken
    /\ ed25519Broken
    /\ groverApplied
    /\ ~hndlAttackAttempted
    /\ LET kemCompromised == (x25519Broken /\ mlKem768Broken)
           aeadCompromised == (effectiveMasterKeyBits < 256 \/ effectiveSymmetricBits < MinPostQuantumBitFloor)
       IN /\ hybridKemCompromised' = kemCompromised
          /\ hndlPlaintextExposed' = (kemCompromised \/ aeadCompromised)
          /\ hndlAttackAttempted'  = TRUE
    /\ UNCHANGED <<x25519Broken, ed25519Broken, mlKem768Broken, mlDsa65Broken,
                   groverApplied, effectiveMasterKeyBits, effectiveSymmetricBits,
                   hybridKemEstablished, hybridSigVerified,
                   quantumForgeryAccepted, pqBackupSealed>>

\* Terminal stuttering step once all PQ protocol steps and CRQC attacks have executed.
Idle ==
    /\ x25519Broken
    /\ ed25519Broken
    /\ groverApplied
    /\ hybridKemEstablished
    /\ hybridSigVerified
    /\ pqBackupSealed
    /\ hndlAttackAttempted
    /\ UNCHANGED vars

Next ==
    \/ QuantumShorBreaksClassicalAsymmetric
    \/ QuantumGroverQuadraticSpeedup
    \/ EstablishHybridKemSession
    \/ VerifyHybridPqSignature
    \/ SealPostQuantumVaultBackup
    \/ AttemptHarvestNowDecryptLater
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Next)

\* ============================================================================
\* SAFETY INVARIANTS
\* ============================================================================

\* 1. Harvest-Now, Decrypt-Later (HNDL) Confidentiality Preserved:
\* Even when a CRQC breaks X25519 and Ed25519 via Shor's algorithm, as long as
\* ML-KEM-768 (FIPS 203) remains unbroken, neither the hybrid KEM session nor
\* the 512-bit cascaded vault plaintext is ever exposed.
Safety_HNDLConfidentialityPreserved ==
    /\ (mlKem768Broken = FALSE => hybridKemCompromised = FALSE)
    /\ hndlPlaintextExposed = FALSE

\* 2. Quantum Signature Unforgeability:
\* Even when Ed25519 is broken by Shor's algorithm, composite HybridPqSignature
\* verification rejects any forgery as long as ML-DSA-65 (FIPS 204) is unbroken.
Safety_QuantumSignatureUnforgeability ==
    /\ (mlDsa65Broken = FALSE => quantumForgeryAccepted = FALSE)
    /\ quantumForgeryAccepted = FALSE

\* 3. Grover Bit-Security Floor:
\* Under Grover's quadratic speedup, PqVaultMasterKey maintains >= 256-bit
\* post-quantum security (512 -> 256) and symmetric primitives maintain >= 128-bit
\* post-quantum security (256 -> 128).
Safety_GroverBitSecurityFloor ==
    /\ effectiveMasterKeyBits >= 256
    /\ (groverApplied => effectiveMasterKeyBits = 256)
    /\ effectiveSymmetricBits >= MinPostQuantumBitFloor
    /\ (groverApplied => effectiveSymmetricBits = 128)

\* ============================================================================
\* TEMPORAL LIVENESS PROPERTY
\* ============================================================================

\* Post-Quantum Session and Backup Eventually Established:
\* Every fair execution establishes the hybrid PQ session, verifies composite
\* signatures, and seals the post-quantum vault backup.
Liveness_PostQuantumSessionAndBackupEstablished ==
    <> (pqBackupSealed = TRUE)

=============================================================================
