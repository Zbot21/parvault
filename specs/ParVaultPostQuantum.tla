------------------------- MODULE ParVaultPostQuantum -------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

\* ============================================================================
\* ParVault Post-Quantum Hybrid Protocol & Adversary State Machine (ADR-12)
\* ============================================================================
\* Models concrete protocol actors (Client, RelayPeer, StoragePeer, Adversary),
\* hybrid keypairs (x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys), wire
\* transcripts (kemTranscripts, signedEnvelopes, onionLayers), and a
\* non-deterministic adversary that can break ANY single primitive in each
\* hybrid pair (e.g., Shor's algorithm breaking X25519 + Ed25519, OR a
\* lattice cryptanalytic break of ML-KEM-768 or ML-DSA-65, OR a single-cipher
\* break of either AES-256-GCM or ChaCha20-Poly1305) and attempt active
\* multi-target public-key substitution and signature forgery.

CONSTANTS
    ClassicalMasterKeyBits,     \* 512-bit PqVaultMasterKey (K_outer || K_inner)
    ClassicalAesBits,           \* 256-bit AES-256-GCM & ChaCha20-Poly1305 key width
    MinPostQuantumBitFloor      \* 128-bit NIST Category 5 Post-Quantum security floor

ASSUME
    /\ ClassicalMasterKeyBits = 512
    /\ ClassicalAesBits = 256
    /\ MinPostQuantumBitFloor = 128

Actors == {"Client", "RelayPeer", "StoragePeer", "Adversary"}
HonestPeers == {"Client", "RelayPeer", "StoragePeer"}

KemPrimitives == {"X25519", "ML_KEM_768"}
SigPrimitives == {"Ed25519", "ML_DSA_65"}
CipherPrimitives == {"AES_256_GCM", "ChaCha20_Poly1305"}
AllPrimitives == KemPrimitives \cup SigPrimitives \cup CipherPrimitives

VARIABLES
    x25519Keys,                 \* Function mapping Actor -> public key token
    mlKemKeys,                  \* Function mapping Actor -> ML-KEM-768 encapsulation key token
    ed25519Keys,                \* Function mapping Actor -> Ed25519 verifying key token
    mlDsaKeys,                  \* Function mapping Actor -> ML-DSA-65 verifying key token
    adversaryBroken,            \* Subset of AllPrimitives broken by the adversary
    groverApplied,              \* TRUE once CRQC applies Grover's O(2^(n/2)) search speedup
    effectiveSymmetricBits,     \* 256 classical -> 128 post-quantum bits under Grover
    hkdfSha512BoundPk,          \* TRUE when X-Wing HKDF-SHA512 binds both recipient PKs
    kemTranscripts,             \* Set of encapsulated X-Wing KEM wire transcripts
    signedEnvelopes,            \* Set of composite Ed25519 + ML-DSA-65 signed wire envelopes
    onionLayers,                \* Set of 2-layer PQ onion envelopes (Outer -> Relay, Inner -> Storage)
    kemAttackAttempted,         \* TRUE once adversary attempts PK substitution / decapsulation
    hybridKemCompromised,       \* TRUE if adversary recovers derived session key or substitutes PK
     unboundKemWouldCompromise, \* Contrast witness: TRUE when an unbound combiner would fail under PK substitution
    sigAttackAttempted,         \* TRUE once adversary attempts composite signature forgery
    quantumForgeryAccepted,     \* TRUE if verifier accepts an adversary-forged envelope
    pqBackupSealed,             \* TRUE once 2-layer PQ onion + cascaded AEAD stripe is sealed
    hndlAttackAttempted,        \* TRUE once adversary executes HNDL attack on captured transcripts
    hndlPlaintextExposed,       \* TRUE if HNDL adversary recovers vault plaintext
    honestVerify                \* "pending", then the StoragePeer verifier's verdict on the honest envelope

vars == <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys, adversaryBroken,
          groverApplied, effectiveSymmetricBits, hkdfSha512BoundPk,
          kemTranscripts, signedEnvelopes, onionLayers,
          kemAttackAttempted, hybridKemCompromised, unboundKemWouldCompromise,
          sigAttackAttempted, quantumForgeryAccepted, pqBackupSealed,
          hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

Init ==
    /\ x25519Keys                = [a \in Actors |-> a \o "_X25519_PK"]
    /\ mlKemKeys                 = [a \in Actors |-> a \o "_MLKEM768_EK"]
    /\ ed25519Keys               = [a \in Actors |-> a \o "_ED25519_VK"]
    /\ mlDsaKeys                 = [a \in Actors |-> a \o "_MLDSA65_PK"]
    /\ adversaryBroken           = {}
    /\ groverApplied             = FALSE
    /\ effectiveSymmetricBits    = ClassicalAesBits
    /\ hkdfSha512BoundPk         = TRUE
    /\ kemTranscripts            = {}
    /\ signedEnvelopes           = {}
    /\ honestVerify              = "pending"
    /\ onionLayers               = {}
    /\ kemAttackAttempted        = FALSE
    /\ hybridKemCompromised      = FALSE
    /\ unboundKemWouldCompromise = FALSE
    /\ sigAttackAttempted        = FALSE
    /\ quantumForgeryAccepted    = FALSE
    /\ pqBackupSealed            = FALSE
    /\ hndlAttackAttempted       = FALSE
    /\ hndlPlaintextExposed      = FALSE

\* ----------------------------------------------------------------------------
\* Action 1: AdversaryChooseCapability(prim)
\* Adversary non-deterministically breaks up to 1 KEM leg ("X25519" or "ML_KEM_768"),
\* up to 1 Signature leg ("Ed25519" or "ML_DSA_65"), and up to 1 Symmetric AEAD
\* leg ("AES_256_GCM" or "ChaCha20_Poly1305"), and activates Grover search.
\* This explores BOTH quantum Shor attacks (breaking X25519 & Ed25519) AND
\* hypothetical lattice cryptanalysis (breaking ML-KEM-768 or ML-DSA-65).
\* ----------------------------------------------------------------------------
AdversaryChooseCapability(prim) ==
    /\ prim \in AllPrimitives
    /\ prim \notin adversaryBroken
    /\ LET nextBroken == adversaryBroken \cup {prim}
       IN /\ Cardinality(nextBroken \cap KemPrimitives) <= 1
          /\ Cardinality(nextBroken \cap SigPrimitives) <= 1
          /\ Cardinality(nextBroken \cap CipherPrimitives) <= 1
          /\ adversaryBroken' = nextBroken
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   groverApplied, effectiveSymmetricBits, hkdfSha512BoundPk,
                   kemTranscripts, signedEnvelopes, onionLayers,
                   kemAttackAttempted, hybridKemCompromised, unboundKemWouldCompromise,
                   sigAttackAttempted, quantumForgeryAccepted, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

ActivateGroverSearch ==
    /\ ~groverApplied
    /\ groverApplied'          = TRUE
    /\ effectiveSymmetricBits' = ClassicalAesBits \div 2
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, hkdfSha512BoundPk, kemTranscripts,
                   signedEnvelopes, onionLayers, kemAttackAttempted,
                   hybridKemCompromised, unboundKemWouldCompromise,
                   sigAttackAttempted, quantumForgeryAccepted, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

\* ----------------------------------------------------------------------------
\* Action 2: ClientEncapsulateXWingHybridKem
\* Client encapsulates to StoragePeer and RelayPeer using the X-Wing style
\* HKDF-SHA512 combiner that explicitly binds:
\*   (ephem_pk, recipient_x25519_pk, SHA256(mlkem_ct), SHA256(recipient_mlkem_ek))
\* into the HKDF salt and info context.
\* ----------------------------------------------------------------------------
ClientEncapsulateXWingHybridKem ==
    /\ kemTranscripts = {}
    /\ LET storageTx == [
               sender             |-> "Client",
               recipient          |-> "StoragePeer",
               ephem_pk           |-> "Client_Ephem_X25519_1",
               recipient_x25519   |-> x25519Keys["StoragePeer"],
               mlkem_ct_hash      |-> "SHA256_MLKEM_CT_Storage",
               recipient_mlkem_ek |-> mlKemKeys["StoragePeer"],
               bound_pk_in_hkdf   |-> hkdfSha512BoundPk
           ]
           relayTx == [
               sender             |-> "Client",
               recipient          |-> "RelayPeer",
               ephem_pk           |-> "Client_Ephem_X25519_2",
               recipient_x25519   |-> x25519Keys["RelayPeer"],
               mlkem_ct_hash      |-> "SHA256_MLKEM_CT_Relay",
               recipient_mlkem_ek |-> mlKemKeys["RelayPeer"],
               bound_pk_in_hkdf   |-> hkdfSha512BoundPk
           ]
       IN kemTranscripts' = {storageTx, relayTx}
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, groverApplied, effectiveSymmetricBits,
                   hkdfSha512BoundPk, signedEnvelopes, onionLayers,
                   kemAttackAttempted, hybridKemCompromised, unboundKemWouldCompromise,
                   sigAttackAttempted, quantumForgeryAccepted, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

\* ----------------------------------------------------------------------------
\* Action 3: AdversaryAttemptKemKeySubstitutionOrDecaps
\* Adversary intercepts kemTranscripts and attempts BOTH:
\*   (a) Direct decapsulation of both component shared secrets (ss_x25519, ss_mlkem),
\*   (b) Multi-target public-key substitution (replacing recipient_x25519 with
\*       x25519Keys["Adversary"] when ML_KEM_768 is broken, or vice versa).
\* Because X-Wing HKDF-SHA512 binds both recipient_x25519 and recipient_mlkem_ek,
\* any public-key substitution alters the HKDF transcript so the recipient derives
\* a disjoint key; thus session compromise occurs IFF {"X25519", "ML_KEM_768"} \subseteq adversaryBroken.
\* ----------------------------------------------------------------------------
AdversaryAttemptKemKeySubstitutionOrDecaps ==
    /\ kemTranscripts /= {}
    /\ ~kemAttackAttempted
    /\ LET bothKemLegsBroken == (KemPrimitives \subseteq adversaryBroken)
           oneKemLegBroken   == (Cardinality(adversaryBroken \cap KemPrimitives) = 1)
           pkSubAttackOnUnbound == oneKemLegBroken
           pkSubAttackOnBound   == (\E tx \in kemTranscripts :
                                       ~tx.bound_pk_in_hkdf /\ oneKemLegBroken)
       IN /\ kemAttackAttempted'        = TRUE
          /\ unboundKemWouldCompromise' = pkSubAttackOnUnbound
          /\ hybridKemCompromised'      = (bothKemLegsBroken \/ pkSubAttackOnBound)
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, groverApplied, effectiveSymmetricBits,
                   hkdfSha512BoundPk, kemTranscripts, signedEnvelopes,
                   onionLayers, sigAttackAttempted, quantumForgeryAccepted,
                   pqBackupSealed, hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

\* ----------------------------------------------------------------------------
\* Action 4: ClientSignCompositeEnvelope
\* Client signs a manifest / PersonalDeviceCert envelope with both Ed25519 and
\* NIST FIPS 204 ML-DSA-65 (bound to ML_DSA_65_CONTEXT).
\* ----------------------------------------------------------------------------
\* ADR-12 verifier: a hybrid signature holds only if BOTH halves verify.
HybridVerifies(edValid, mlValid) == edValid /\ mlValid   \* @guard hybrid-sig-both sym=src/crypto/pqc.rs::hybrid_signature_decision

ClientSignCompositeEnvelope ==
    /\ signedEnvelopes = {}
    /\ LET env == [
               signer          |-> "Client",
               ed25519_vk      |-> ed25519Keys["Client"],
               ml_dsa_pk       |-> mlDsaKeys["Client"],
               context         |-> "parvault-pq-hybrid-dsa65-v1",
               ed25519_valid   |-> TRUE,
               ml_dsa_65_valid |-> TRUE
           ]
       IN signedEnvelopes' = {env}
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, groverApplied, effectiveSymmetricBits,
                   hkdfSha512BoundPk, kemTranscripts, onionLayers,
                   kemAttackAttempted, hybridKemCompromised, unboundKemWouldCompromise,
                   sigAttackAttempted, quantumForgeryAccepted, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

\* ----------------------------------------------------------------------------
\* Action 5: AdversaryAttemptSignatureForgery
\* Adversary attempts to forge a composite signature on behalf of Client using
\* its broken signature primitives. Verification requires BOTH ed25519_valid
\* AND ml_dsa_65_valid under ML_DSA_65_CONTEXT, so forgery succeeds IFF
\* {"Ed25519", "ML_DSA_65"} \subseteq adversaryBroken.
\* ----------------------------------------------------------------------------
AdversaryAttemptSignatureForgery ==
    /\ signedEnvelopes /= {}
    /\ ~sigAttackAttempted
    /\ LET forgedEd25519Valid == ("Ed25519" \in adversaryBroken)
           forgedMlDsa65Valid == ("ML_DSA_65" \in adversaryBroken)
           verifierAccepts    == HybridVerifies(forgedEd25519Valid, forgedMlDsa65Valid)
       IN /\ sigAttackAttempted'     = TRUE
          /\ quantumForgeryAccepted' = verifierAccepts
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, groverApplied, effectiveSymmetricBits,
                   hkdfSha512BoundPk, kemTranscripts, signedEnvelopes,
                   onionLayers, kemAttackAttempted, hybridKemCompromised,
                   unboundKemWouldCompromise, pqBackupSealed,
                   hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

\* Action 5b: StoragePeerVerifyHonestEnvelope
\* The receiving peer runs the same hybrid verifier on the Client's envelope
\* (both halves produced with the Client's own keys), so the accept branch of
\* HybridVerifies is exercised, not only its reject branch.
StoragePeerVerifyHonestEnvelope ==
    /\ honestVerify = "pending"
    /\ \E env \in signedEnvelopes :
        honestVerify' = IF HybridVerifies(env.ed25519_valid, env.ml_dsa_65_valid)
                        THEN "accepted" ELSE "rejected"
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys, adversaryBroken,
                   groverApplied, effectiveSymmetricBits, hkdfSha512BoundPk,
                   kemTranscripts, signedEnvelopes, onionLayers, kemAttackAttempted,
                   hybridKemCompromised, unboundKemWouldCompromise, sigAttackAttempted,
                   quantumForgeryAccepted, pqBackupSealed, hndlAttackAttempted,
                   hndlPlaintextExposed>>

\* ----------------------------------------------------------------------------
\* Action 6: ClientSealTwoLayerPqOnion
\* Client encrypts the stripe with the dual-cipher PqVaultMasterKey cascade
\* (AES-256-GCM inner + ChaCha20-Poly1305 outer) and seals a 2-layer PQ onion:
\*   - Inner layer sealed to StoragePeer: (blinded_id, capability, voucher, shard)
\*   - Outer layer sealed to RelayPeer:   (next_hop = "StoragePeer", inner_ct)
\* ----------------------------------------------------------------------------
ClientSealTwoLayerPqOnion ==
    /\ kemTranscripts /= {}
    /\ signedEnvelopes /= {}
    /\ ~pqBackupSealed
    /\ LET innerLayer == [
               layer              |-> "InnerStorageLayer",
               sealed_to          |-> "StoragePeer",
               exposes_origin_ip  |-> FALSE,
               exposes_capability |-> FALSE,
               exposes_voucher    |-> FALSE
           ]
           outerLayer == [
               layer              |-> "OuterRelayLayer",
               sealed_to          |-> "RelayPeer",
               next_hop           |-> "StoragePeer",
               exposes_capability |-> FALSE,
               exposes_voucher    |-> FALSE
           ]
       IN /\ onionLayers'    = {innerLayer, outerLayer}
          /\ pqBackupSealed' = TRUE
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, groverApplied, effectiveSymmetricBits,
                   hkdfSha512BoundPk, kemTranscripts, signedEnvelopes,
                   kemAttackAttempted, hybridKemCompromised, unboundKemWouldCompromise,
                   sigAttackAttempted, quantumForgeryAccepted,
                   hndlAttackAttempted, hndlPlaintextExposed, honestVerify>>

\* ----------------------------------------------------------------------------
\* Action 7: AttemptHarvestNowDecryptLater
\* Adversary records all onion layers, KEM transcripts, and dual-cipher stripes,
\* and attacks them with Grover's algorithm + all adversaryBroken primitives.
\* Vault plaintext is exposed only if BOTH KEM legs are broken OR BOTH symmetric
\* ciphers in the AES-256-GCM + ChaCha20-Poly1305 cascade are broken/exhausted.
\* ----------------------------------------------------------------------------
AttemptHarvestNowDecryptLater ==
    /\ pqBackupSealed
    /\ kemAttackAttempted
    /\ sigAttackAttempted
    /\ groverApplied
    /\ ~hndlAttackAttempted
    /\ LET bothCiphersBroken == (CipherPrimitives \subseteq adversaryBroken)
           groverExhausted   == (effectiveSymmetricBits < MinPostQuantumBitFloor)
           cascadeBroken     == (bothCiphersBroken \/ groverExhausted)
       IN /\ hndlPlaintextExposed' = (hybridKemCompromised \/ cascadeBroken)
          /\ hndlAttackAttempted'  = TRUE
    /\ UNCHANGED <<x25519Keys, mlKemKeys, ed25519Keys, mlDsaKeys,
                   adversaryBroken, groverApplied, effectiveSymmetricBits,
                   hkdfSha512BoundPk, kemTranscripts, signedEnvelopes,
                   onionLayers, kemAttackAttempted, hybridKemCompromised,
                   unboundKemWouldCompromise, sigAttackAttempted,
                   quantumForgeryAccepted, pqBackupSealed, honestVerify>>

Idle ==
    /\ pqBackupSealed
    /\ kemAttackAttempted
    /\ sigAttackAttempted
    /\ groverApplied
    /\ hndlAttackAttempted
    /\ UNCHANGED vars

Next ==
    \/ \E p \in AllPrimitives : AdversaryChooseCapability(p)
    \/ ActivateGroverSearch
    \/ ClientEncapsulateXWingHybridKem
    \/ AdversaryAttemptKemKeySubstitutionOrDecaps
    \/ ClientSignCompositeEnvelope
    \/ AdversaryAttemptSignatureForgery
    \/ StoragePeerVerifyHonestEnvelope
    \/ ClientSealTwoLayerPqOnion
    \/ AttemptHarvestNowDecryptLater
    \/ Idle

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(ClientEncapsulateXWingHybridKem)
    /\ WF_vars(ClientSignCompositeEnvelope)
    /\ WF_vars(ClientSealTwoLayerPqOnion)
    /\ WF_vars(ActivateGroverSearch)
    /\ WF_vars(AdversaryAttemptKemKeySubstitutionOrDecaps)
    /\ WF_vars(AdversaryAttemptSignatureForgery)
    /\ WF_vars(AttemptHarvestNowDecryptLater)

\* ============================================================================
\* SAFETY INVARIANTS
\* ============================================================================

\* 1. Harvest-Now, Decrypt-Later (HNDL) Confidentiality & X-Wing Binding:
\* As long as at least one KEM leg in {X25519, ML_KEM_768} and at least one
\* AEAD cipher in {AES_256_GCM, ChaCha20_Poly1305} remain unbroken, neither
\* active public-key substitution nor HNDL decapsulation exposes the session
\* key or vault plaintext. Also verifies that every onion layer hides the
\* shard capability and bearer quota voucher from intermediate relays.
Safety_HNDLConfidentialityPreserved ==
    /\ ~(KemPrimitives \subseteq adversaryBroken) => (hybridKemCompromised = FALSE)
    /\ ~(CipherPrimitives \subseteq adversaryBroken) => (hndlPlaintextExposed = FALSE)
    /\ \A layer \in onionLayers :
        /\ layer.exposes_capability = FALSE
        /\ layer.exposes_voucher = FALSE

\* 2. Quantum Signature Unforgeability:
\* As long as at least one signature scheme in {Ed25519, ML_DSA_65} remains
\* unbroken, composite verification rejects any adversary forgery attempt.
Safety_QuantumSignatureUnforgeability ==
    /\ ~(SigPrimitives \subseteq adversaryBroken) => (quantumForgeryAccepted = FALSE)
    /\ quantumForgeryAccepted = FALSE

\* 3. Grover Bit-Security Floor & Dual-Cipher Diversity:
\* Under Grover's quadratic speedup, 256-bit symmetric keys retain >= 128-bit
\* post-quantum security (NIST Category 5 floor), and at most one cipher in the
\* AES-256-GCM + ChaCha20-Poly1305 cascade can be broken under single-primitive failure.
Safety_GroverBitSecurityFloor ==
    /\ effectiveSymmetricBits >= MinPostQuantumBitFloor
    /\ (groverApplied => effectiveSymmetricBits = 128)
    /\ Cardinality(adversaryBroken \cap CipherPrimitives) <= 1

\* ============================================================================
\* TEMPORAL LIVENESS PROPERTY
\* ============================================================================

Liveness_PostQuantumSessionAndBackupEstablished ==
    <> (pqBackupSealed = TRUE /\ hndlAttackAttempted = TRUE)

=============================================================================
