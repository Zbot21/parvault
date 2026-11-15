--------------------------- MODULE ParVaultPorAudit ---------------------------
\* @traceability
\*   adr      ADR-03
\* @end
EXTENDS Naturals, FiniteSets

\* ============================================================================
\* ParVault chunk-Merkle audit loop (ADR-03 as amended by B-59, L-27, L-29)
\* ============================================================================
\* The owner daemon ("self") challenges one chunk of a shard on a host and records what the
\* answer proves in its own ledger. Three hosts: "self" (a manifest may name the auditor's own
\* node), "honest" (keeps every chunk; its link may still time out) and "cheat" (may drop
\* chunks, may forge answers, and as a co-host of the stripe holds the stripe's session key, so
\* it may send chunk audits of its own to "honest" to rebuild what it dropped).
\*
\* Checked:
\*   - NoCreditWithoutProof (ground truth): a credited pass for chunk i of host h implies h
\*     stored i when it answered. Guards `chunk-proof` and `chunk-storer`.
\*   - SelfNeverCredited: the auditor's own node earns nothing. Guard `audit-credit`.
\*   - HonestNeverFails: a host that keeps its data is never recorded as failing, even when it
\*     times out. Guard `verdict-classes` (only an invalid proof is a failure, L-27).
\*   - EventuallyRecorded (PROPERTY): a dropped chunk is eventually seen as a failed proof or an
\*     unanswered audit. Counters saturate; there is no audit bound and no state constraint.
\* Not modelled: SHA-256 (a proof is valid iff it names the challenged index and carries the
\* stored content), the session-key HMAC and the rate limits (E-POR, F-06-RATE claims).
\* Nothing in this model quarantines: `record_failure` has no caller (the assumption
\* leaf-quarantine-not-run is declared in ParVaultProtocol).

Owner == "self"
Hosts == {"self", "honest", "cheat"}
Chunks == 1..2
NoChallenge == 0
Verdicts == {"None", "Pass", "Invalid", "Timeout"}

\* A proof verifies only for the challenged index with the stored content.
ProofOk(i, j, valid) == j = i /\ valid   \* @guard chunk-proof sym=src/por/chunk_merkle.rs::chunk_proof_decision
\* A verdict is credited only to a prover other than the auditor.
MayCredit(v, p) == v # p   \* @guard audit-credit sym=src/por/audit.rs::audit_credit_decision
\* Only an invalid proof is a ledger failure; a timeout never is.
IsFail(verdict) == verdict = "Invalid"   \* @guard verdict-classes sym=src/por/audit.rs::chunk_audit_decision
\* A host answers a chunk audit only to the peer the shard is accounted to (the owner).
StorerOk(sender) == sender = Owner   \* @guard chunk-storer sym=src/por/verifier.rs::por_storer_decision

VARIABLES
    cheatStored,   \* chunks "cheat" still holds of its shard
    cheatFetched,  \* chunks "cheat" rebuilt from chunk audits it sent to "honest"
    pending,       \* host -> challenged chunk, or NoChallenge
    passes,        \* host -> credited passes (saturating at 1)
    fails,         \* host -> recorded failures (saturating at 1)
    cheatVerdict,  \* the last verdict recorded for "cheat"
    badCredit      \* a pass was credited for a chunk the host did not store (ground truth)

vars == <<cheatStored, cheatFetched, pending, passes, fails, cheatVerdict, badCredit>>

Stored(h) == IF h = "cheat" THEN cheatStored ELSE Chunks
Have(h) == IF h = "cheat" THEN cheatStored \cup cheatFetched ELSE Chunks
Sat(n) == IF n >= 1 THEN 1 ELSE n + 1

TypeOK ==
    /\ cheatStored \subseteq Chunks
    /\ cheatFetched \subseteq Chunks
    /\ pending \in [Hosts -> Chunks \cup {NoChallenge}]
    /\ passes \in [Hosts -> 0..1]
    /\ fails \in [Hosts -> 0..1]
    /\ cheatVerdict \in Verdicts
    /\ badCredit \in BOOLEAN

Init ==
    /\ cheatStored = Chunks
    /\ cheatFetched = {}
    /\ pending = [h \in Hosts |-> NoChallenge]
    /\ passes = [h \in Hosts |-> 0]
    /\ fails = [h \in Hosts |-> 0]
    /\ cheatVerdict = "None"
    /\ badCredit = FALSE

\* The owner challenges chunk i of host h (indices from the OS RNG: any chunk).
Challenge(h, i) ==
    /\ pending[h] = NoChallenge
    /\ pending' = [pending EXCEPT ![h] = i]
    /\ UNCHANGED <<cheatStored, cheatFetched, passes, fails, cheatVerdict, badCredit>>

\* Records verdict v for host h, challenged on chunk i.
Record(h, i, v) ==
    /\ pending' = [pending EXCEPT ![h] = NoChallenge]
    /\ passes' = IF v = "Pass" /\ MayCredit(Owner, h)
                    THEN [passes EXCEPT ![h] = Sat(@)] ELSE passes
    /\ fails' = IF IsFail(v) /\ MayCredit(Owner, h)
                   THEN [fails EXCEPT ![h] = Sat(@)] ELSE fails
    /\ badCredit' = (badCredit \/ (v = "Pass" /\ MayCredit(Owner, h) /\ i \notin Stored(h)))
    /\ cheatVerdict' = IF h = "cheat" THEN v ELSE cheatVerdict

\* Host h answers with chunk j; `valid` (correct content) only for a chunk it has. "honest"
\* and "self" answer the challenged chunk truthfully; "cheat" may answer anything.
Answer(h, j, valid) ==
    /\ pending[h] # NoChallenge
    /\ valid => j \in Have(h)
    /\ h # "cheat" => (j = pending[h] /\ valid)
    /\ Record(h, pending[h], IF ProofOk(pending[h], j, valid) THEN "Pass" ELSE "Invalid")
    /\ UNCHANGED <<cheatStored, cheatFetched>>

\* No answer within the bound (any host, the honest one included).
Timeout(h) ==
    /\ pending[h] # NoChallenge
    /\ Record(h, pending[h], "Timeout")
    /\ UNCHANGED <<cheatStored, cheatFetched>>

Respond(h) == Timeout(h) \/ \E j \in Chunks, valid \in BOOLEAN : Answer(h, j, valid)

\* "cheat" drops a chunk of its shard.
Drop(i) ==
    /\ i \in cheatStored
    /\ cheatStored' = cheatStored \ {i}
    /\ UNCHANGED <<cheatFetched, pending, passes, fails, cheatVerdict, badCredit>>

\* "cheat", a co-host holding the stripe key, sends its own chunk audit to "honest" to rebuild
\* chunk i (Reed-Solomon, position-wise). "honest" answers only the accounted owner.
CoHostFetch(i) ==
    /\ StorerOk("cheat")
    /\ cheatFetched' = cheatFetched \cup {i}
    /\ UNCHANGED <<cheatStored, pending, passes, fails, cheatVerdict, badCredit>>

Next ==
    \/ \E h \in Hosts, i \in Chunks : Challenge(h, i)
    \/ \E h \in Hosts : Respond(h)
    \/ \E i \in Chunks : Drop(i)
    \/ \E i \in Chunks : CoHostFetch(i)

Fairness ==
    /\ \A i \in Chunks : SF_vars(Challenge("cheat", i))
    /\ WF_vars(Respond("cheat"))

Spec == Init /\ [][Next]_vars /\ Fairness

NoCreditWithoutProof == ~badCredit
SelfNeverCredited == passes[Owner] = 0 /\ fails[Owner] = 0
HonestNeverFails == fails["honest"] = 0

EventuallyRecorded ==
    \A i \in Chunks :
        (i \notin cheatStored) ~> (cheatVerdict \in {"Invalid", "Timeout"})
=============================================================================
