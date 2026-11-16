------------------------------ MODULE ParVaultVersionGC ------------------------------
\* @traceability
\*   const    Hosts -> model-only: two storage hosts; every stripe needs a shard on each (k = n)
\*   const    Stripes -> model-only: stripe roots, re-referenced across versions (deduplication modelled, C9)
\*   const    SeedStripes -> model-only: stripes the lite seed fanned out (accounted to the seed, not the owner)
\*   const    MaxVer -> model-only: versions written in one run of the model
\*   const    MaxEpoch -> model-only: free orders the owner signs in one run
\*   const    MaxClock -> model-only: clock ticks
\*   const    Window -> model-only: MAX_CAPABILITY_CLOCK_SKEW_MS (30 s) in ticks
\*   const    MaxCrash -> model-only: owner crashes in one run
\* @end
EXTENDS Naturals, FiniteSets

\* ============================================================================
\* ParVault version GC (B-154 2.2-2.4; arch154 C2, C3, C6, C9, C10-C16, C21, C29)
\* ============================================================================
\* The owner writes versions (each references a set of stripes; a later version may reference
\* a stripe again, as deduplication would), keeps any subset of versions containing the newest
\* (C29: the policy is not modelled), marks, journals the garbage, drops version files, and
\* sends one-shard `FreeShards` orders that the network may delay, duplicate, reorder or lose;
\* an adversary replays every order it has seen. The owner may crash at any step. Hosts accept
\* an order only fresh (within Window of its timestamp) and with an epoch above the last they
\* accepted, and credit the shard's accounted owner.
\*
\* Checked:
\*   - RetainedRecoverable: every stripe of every retained version (and of the pass being
\*     written) is held on every host. Guards mark-includes-pass, free-fresh, free-epoch,
\*     c9-fence.
\*   - PublishedRecoverable: every stripe of the last acknowledged catalog is held (C6). Guard
\*     catalog-pin.
\*   - NoLeakedGarbage: a held shard no retained version references is journalled, or in the
\*     in-flight log (C3). Guard journal-before-drop.
\*   - QuotaMatchesHeld: each host charges exactly the shards it holds, each to its accounted
\*     owner (C16). Guard credit-accounted.
\* Not modelled: signatures and host binding (an order names one host; F-36 and B154-FREE claims
\* check them), the retention policy (C29), offline hosts beyond lost messages, abandonment after
\* 30 days, PoR penalties (an audit of a freed shard is Unanswered, never Invalid: B-59 claims).

CONSTANTS Hosts, Stripes, SeedStripes, MaxVer, MaxEpoch, MaxClock, Window, MaxCrash

Versions == 1..MaxVer
NoTs == MaxClock + Window + 1
Acct(s) == IF s \in SeedStripes THEN "seed" ELSE "owner"
Order(h, s, e, t) == [h |-> h, s |-> s, e |-> e, ts |-> t]

VARIABLES
    clock,      \* wall clock (owner and hosts agree within the model)
    ver,        \* the newest version written
    refs,       \* version -> stripes it references
    retained,   \* version files on the owner's disk
    published,  \* the last catalog version a host acknowledged (0: none)
    phase,      \* where the owner's pass and GC are
    pending,    \* stripes of the pass being written (placed, no version yet)
    inflight,   \* the in-flight log: stripes placed by a pass not yet journalled (C3)
    gcKeep,     \* versions this GC run keeps
    gcGarbage,  \* stripes this GC run found garbage
    journal,    \* <<stripe, host>> frees not yet acknowledged
    held,       \* host -> stripes it holds a shard of
    charged,    \* host -> <<stripe, account>> it charges
    orders,     \* every order ever sent (the network and the replaying adversary)
    unacked,    \* orders the owner sent and no host acknowledged
    oepoch,     \* the owner's last signed epoch (persisted before sending, C10)
    hepoch,     \* host -> the last epoch it accepted
    crashes

vars == <<clock, ver, refs, retained, published, phase, pending, inflight, gcKeep, gcGarbage,
          journal, held, charged, orders, unacked, oepoch, hepoch, crashes>>

\* ---- Guards: owner side (track B2) ----
\* The marks: every kept version and the pass being written.
Marks(keep) == UNION {refs[v] : v \in keep} \cup pending   \* @guard mark-includes-pass sym=src/sync/gc_journal.rs::mark
\* A GC run keeps the newest version and the last acknowledged catalog.
KeepOk(keep) == ver \in keep /\ (published > 0 => published \in keep)   \* @guard catalog-pin sym=src/sync/gc_journal.rs::gc_free_decision
\* Version files are dropped only after the garbage is journalled.
DropPhases == {"journaled"}   \* @guard journal-before-drop
\* C9 (gate for v0.5.7 dedup): no stripe is referenced again while a sent order for it can
\* still be accepted (no acknowledgement and inside the window).
FenceOk(s) == \A o \in unacked : o.s = s => clock > o.ts + Window   \* @guard c9-fence

\* ---- Guards: host side (track B1, `free_order_decision`) ----
Fresh(o) == clock <= o.ts + Window   \* @guard free-fresh
EpochOk(o) == o.e > hepoch[o.h]   \* @guard free-epoch
CreditAcct(s) == Acct(s)   \* @guard credit-accounted

Referenced == UNION {refs[v] : v \in retained} \cup pending

Init ==
    /\ clock = 0
    /\ ver = 0
    /\ refs = [v \in Versions |-> {}]
    /\ retained = {}
    /\ published = 0
    /\ phase = "idle"
    /\ pending = {}
    /\ inflight = {}
    /\ gcKeep = {}
    /\ gcGarbage = {}
    /\ journal = {}
    /\ held = [h \in Hosts |-> {}]
    /\ charged = [h \in Hosts |-> {}]
    /\ orders = {}
    /\ unacked = {}
    /\ oepoch = 0
    /\ hepoch = [h \in Hosts |-> 0]
    /\ crashes = 0

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<ver, refs, retained, published, phase, pending, inflight, gcKeep, gcGarbage,
                   journal, held, charged, orders, unacked, oepoch, hepoch, crashes>>

\* A pass places its stripes: logged in flight first (C3), then put on every host that lacks
\* them. A stripe already held is referenced again (deduplication).
Place(S) ==
    /\ phase = "idle"
    /\ ver < MaxVer
    /\ S # {}
    /\ \A s \in S : FenceOk(s)
    /\ inflight' = inflight \cup S
    /\ pending' = S
    /\ held' = [h \in Hosts |-> held[h] \cup S]
    /\ charged' = [h \in Hosts |-> charged[h] \cup {<<s, Acct(s)>> : s \in S \ held[h]}]
    /\ phase' = "placed"
    /\ UNCHANGED <<clock, ver, refs, retained, published, gcKeep, gcGarbage, journal, orders,
                   unacked, oepoch, hepoch, crashes>>

\* Step 1: the version file.
Write ==
    /\ phase = "placed"
    /\ ver' = ver + 1
    /\ refs' = [refs EXCEPT ![ver + 1] = pending]
    /\ retained' = retained \cup {ver + 1}
    /\ pending' = {}
    /\ phase' = "written"
    /\ UNCHANGED <<clock, published, inflight, gcKeep, gcGarbage, journal, held, charged,
                   orders, unacked, oepoch, hepoch, crashes>>

\* The catalog of the newest version is acknowledged by a host.
Publish ==
    /\ phase \in {"written", "idle"}
    /\ ver > 0
    /\ published' = ver
    /\ UNCHANGED <<clock, ver, refs, retained, phase, pending, inflight, gcKeep, gcGarbage,
                   journal, held, charged, orders, unacked, oepoch, hepoch, crashes>>

\* Step 2: retention picks any subset keeping the newest (C29); marks; garbage.
Mark(keep) ==
    /\ phase = "written"
    /\ keep \subseteq retained
    /\ KeepOk(keep)
    /\ gcKeep' = keep
    /\ gcGarbage' = (UNION {refs[v] : v \in retained \ keep} \cup inflight) \ Marks(keep)
    /\ phase' = "marked"
    /\ UNCHANGED <<clock, ver, refs, retained, published, pending, inflight, journal, held,
                   charged, orders, unacked, oepoch, hepoch, crashes>>

\* Step 3: the garbage into the journal; the in-flight log cleared.
Journal ==
    /\ phase \in {"marked", "dropped"}
    /\ journal' = journal \cup (gcGarbage \X Hosts)
    /\ inflight' = {}
    /\ phase' = IF phase = "dropped" THEN "idle" ELSE "journaled"
    /\ UNCHANGED <<clock, ver, refs, retained, published, pending, gcKeep, gcGarbage, held,
                   charged, orders, unacked, oepoch, hepoch, crashes>>

\* Step 4: the dropped version files.
Drop ==
    /\ phase \in DropPhases
    /\ retained' = gcKeep
    /\ phase' = IF phase = "marked" THEN "dropped" ELSE "idle"
    /\ UNCHANGED <<clock, ver, refs, published, pending, inflight, gcKeep, gcGarbage, journal,
                   held, charged, orders, unacked, oepoch, hepoch, crashes>>

\* Steps 5 and 6: an entry is re-checked against the marks (a marked stripe leaves the journal,
\* never freed), else signed with a fresh epoch and sent (C10, C11: max(last + 1, clock)).
Free(s, h) ==
    /\ <<s, h>> \in journal
    /\ IF s \in Marks(retained)
       THEN /\ journal' = journal \ {<<s, h>>}
            /\ UNCHANGED <<orders, unacked, oepoch>>
       ELSE LET e == IF oepoch + 1 > clock THEN oepoch + 1 ELSE clock
            IN /\ e <= MaxEpoch
               /\ oepoch' = e
               /\ orders' = orders \cup {Order(h, s, e, clock)}
               /\ unacked' = unacked \cup {Order(h, s, e, clock)}
               /\ UNCHANGED journal
    /\ UNCHANGED <<clock, ver, refs, retained, published, phase, pending, inflight, gcKeep,
                   gcGarbage, held, charged, hepoch, crashes>>

\* A host takes any order ever sent (delayed, duplicated, reordered, replayed). Accepted, it
\* frees the shard if held and credits the accounted owner; the owner sees the acknowledgement.
Deliver(o) ==
    /\ o \in orders
    /\ Fresh(o)
    /\ EpochOk(o)
    /\ hepoch' = [hepoch EXCEPT ![o.h] = o.e]
    /\ held' = [held EXCEPT ![o.h] = @ \ {o.s}]
    /\ charged' = IF o.s \in held[o.h]
                  THEN [charged EXCEPT ![o.h] = @ \ {<<o.s, CreditAcct(o.s)>>}]
                  ELSE charged
    /\ journal' = journal \ {<<o.s, o.h>>}
    /\ unacked' = {u \in unacked : u.h # o.h \/ u.e > o.e}
    /\ UNCHANGED <<clock, ver, refs, retained, published, phase, pending, inflight, gcKeep,
                   gcGarbage, orders, oepoch, crashes>>

\* The owner dies: the pass and GC in memory are lost; files, journal and epoch persist.
Crash ==
    /\ crashes < MaxCrash
    /\ crashes' = crashes + 1
    /\ phase' = "idle"
    /\ pending' = {}
    /\ gcKeep' = {}
    /\ gcGarbage' = {}
    /\ UNCHANGED <<clock, ver, refs, retained, published, inflight, journal, held, charged,
                   orders, unacked, oepoch, hepoch>>

Next ==
    \/ Tick
    \/ \E S \in SUBSET Stripes : Place(S)
    \/ Write
    \/ Publish
    \/ \E keep \in SUBSET Versions : Mark(keep)
    \/ Journal
    \/ Drop
    \/ \E s \in Stripes, h \in Hosts : Free(s, h)
    \/ \E o \in orders : Deliver(o)
    \/ Crash

Spec == Init /\ [][Next]_vars

\* ---- Invariants ----
RetainedRecoverable ==
    \A s \in Referenced : \A h \in Hosts : s \in held[h]

PublishedRecoverable ==
    published > 0 => \A s \in refs[published] : \A h \in Hosts : s \in held[h]

NoLeakedGarbage ==
    \A h \in Hosts : \A s \in held[h] :
        s \in Referenced \/ <<s, h>> \in journal \/ s \in inflight

QuotaMatchesHeld ==
    \A h \in Hosts :
        /\ {c[1] : c \in charged[h]} = held[h]
        /\ \A c \in charged[h] : c[2] = Acct(c[1])
=============================================================================
