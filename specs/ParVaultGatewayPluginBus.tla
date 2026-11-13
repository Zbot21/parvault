------------------------ MODULE ParVaultGatewayPluginBus ------------------------
\* @traceability
\*   adr      ADR-27 ADR-28 ADR-32
\*   var      allowlistSet      -> src/gateway/engine.rs::set_strict_allowed_peer_uids
\*   var      rootKeySet        -> src/gateway/engine.rs::set_macaroon_root_key
\*   var      requireSealed     -> src/gateway/engine.rs::set_require_sealed_ingest_memfd
\*   var      snapshotPublished -> model-only: a status snapshot provider is installed
\*   var      conns             -> model-only: UIDs holding an admitted connection
\*   var      lastRead          -> model-only: history variable for NoReadWithoutCapability
\*   var      lastStatus        -> model-only: history variable for StatusOnlyWithIssuedToken
\*   var      lastUnauth        -> model-only: history variable for OnlyAllowedUidsServed
\*   var      stored            -> model-only: stored payloads and whether they changed
\*   action   Connect           -> src/gateway/server.rs::GatewayIpcServer
\*   action   FetchRange        -> src/gateway/ipc.rs::IpcCommand::FetchRange
\*   action   FetchPayload      -> src/gateway/ipc.rs::IpcCommand::FetchPayload
\*   action   QueryStatus       -> src/gateway/ipc.rs::IpcCommand::QueryStatus
\*   action   RegisterManifest  -> src/gateway/ipc.rs::IpcCommand::RegisterManifest
\*   action   QueryHealthStatus -> src/gateway/ipc.rs::IpcCommand::QueryHealthStatus
\*   action   StorePayload      -> src/gateway/ipc.rs::IpcCommand::StorePayload
\*   action   MutateAfterStore  -> model-only: adversary writes to a memfd it already sent
\*   const    DaemonUid         -> model-only: model identity
\*   const    PluginUid         -> model-only: model identity
\*   const    OtherUid          -> model-only: model identity
\*   const    ModeAdmitted      -> model-only: UIDs the socket's file mode admits (a set)
\* @end
\* The gateway plugin bus (ADR-27, ADR-32) at item 3's end state: the SO_PEERCRED UID
\* allowlist per connection, the macaroon check on every read frame (FetchRange and
\* FetchPayload, ADR-28), the immutable ingest memfd, and QueryStatus. Plan-4 ruling (L-49).
EXTENDS Naturals, FiniteSets

CONSTANTS
    DaemonUid,      \* the gateway daemon's own UID (in-process clients run as it)
    PluginUid,      \* a plugin's UID
    OtherUid,       \* another local user
    ModeAdmitted    \* UIDs the socket's file mode lets connect

Uids == {DaemonUid, PluginUid, OtherUid}
\* The allowlist, when configured (`--allow-peer-uid` / `--strict-plugins`).
Allowlist == {DaemonUid, PluginUid}

ASSUME
    /\ Cardinality(Uids) = 3
    /\ ModeAdmitted \subseteq Uids

\* @structural socket-mode: holds by construction; the socket is chmod 0600 right after bind
\* (src/gateway/server.rs::bind_clean_std_listener), traced to test
\* gateway_bus_and_plugin_security::gateway_socket_is_mode_0600. F-49 covers the window before
\* the chmod and the ignored result; the cfg lets every UID through to stay conservative.

\* A macaroon: who signed it, which UID its AllowedPeerUid caveat binds (or none), and its
\* scope: "in" (manifest and range caveats cover the request), "out" (they exclude it) or
\* "any" (a ReadOnly token with no manifest or range caveat).
Keys == {"root", "adv"}
Caveats == Uids \cup {"none"}
Scopes == {"in", "out", "any"}
Tokens == [key : Keys, uid : Caveats, scope : Scopes]
NoToken == [key |-> "absent", uid |-> "none", scope |-> "in"]

\* Ground truth: tokens the owner issued, by holder. A plugin holds a UID-bound read token,
\* a bearer read token and a UID-bound unscoped ReadOnly token (for status); nobody else
\* holds one.
\* @assume bearer-tokens-not-leaked: a token with no UID caveat stays with its holder.
IssuedTo(u) == IF u = PluginUid
               THEN {[key |-> "root", uid |-> PluginUid, scope |-> "in"],
                     [key |-> "root", uid |-> "none", scope |-> "in"],
                     [key |-> "root", uid |-> PluginUid, scope |-> "any"]}
               ELSE {}
\* What a requester can present: its own tokens, nothing, any token signed with a key it
\* holds (never the root key), or one of the plugin's UID-bound tokens (leaked).
Presentable(u) == IssuedTo(u) \cup {NoToken}
                  \cup {t \in Tokens : t.key = "adv"}
                  \cup {[key |-> "root", uid |-> PluginUid, scope |-> s] : s \in Scopes}

VARIABLES
    allowlistSet,       \* configuration, chosen in Init
    rootKeySet,
    requireSealed,
    snapshotPublished,
    conns,              \* UIDs with an admitted connection
    lastRead,           \* the last served read frame: <<uid, token>>, or <<>>
    lastStatus,         \* the last served QueryStatus: <<uid, token>>, or <<>>
    lastUnauth,         \* the last served token-less command: <<uid>>, or <<>>
    stored              \* stored payloads: [sealed, mutated]

vars == <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns, lastRead,
          lastStatus, lastUnauth, stored>>

\* --- Guards (each mirrors one Rust decision) -------------------------------------------
UidAdmitted(u) == ~allowlistSet \/ u \in Allowlist   \* @guard uid-allowlist sym=src/gateway/engine.rs::gateway_peer_uid_decision
UidCaveatOk(t, u) == t.uid \in {"none", u}   \* @guard macaroon-uid-caveat sym=src/capabilities.rs::evaluate_caveats
\* gateway_macaroon_decision: with a root key a frame needs a token with a valid tag; any
\* token it carries must allow this frame (scope and peer UID).
ReadAuthorized(t, u) ==   \* @guard macaroon-frame sym=src/gateway/engine.rs::gateway_macaroon_decision
    /\ rootKeySet => (t /= NoToken /\ t.key = "root")
    /\ t /= NoToken => (UidCaveatOk(t, u) /\ t.scope \in {"in", "any"})
IngestSealedOk(sealed) == ~requireSealed \/ sealed   \* @guard memfd-seal sym=src/gateway/engine.rs::gateway_memfd_seal_decision
\* status_auth_decision: a verifier (root key) and a snapshot, then a valid, ReadOnly,
\* unscoped token whose AllowedPeerUid (if any) is the caller's.
StatusAuthorized(t, u) ==   \* @guard status-auth sym=src/http_edge.rs::status_auth_decision
    /\ rootKeySet /\ snapshotPublished
    /\ t /= NoToken /\ t.key = "root" /\ t.scope = "any" /\ UidCaveatOk(t, u)

Init ==
    /\ allowlistSet \in BOOLEAN
    /\ rootKeySet \in BOOLEAN
    /\ requireSealed \in BOOLEAN
    /\ snapshotPublished \in BOOLEAN
    /\ conns = {}
    /\ lastRead = <<>>
    /\ lastStatus = <<>>
    /\ lastUnauth = <<>>
    /\ stored = {}

\* A client connects over the socket (the file mode decides who can), or in process with the
\* daemon's UID (the in-process path runs the same decision with geteuid()).
Connect(u) ==
    /\ u \notin conns
    /\ u \in ModeAdmitted \/ u = DaemonUid
    /\ IF UidAdmitted(u) THEN conns' = conns \cup {u} ELSE UNCHANGED conns
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, lastRead,
                   lastStatus, lastUnauth, stored>>

FetchRange(u, t) ==
    /\ u \in conns
    /\ ReadAuthorized(t, u)
    /\ lastRead' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastStatus, lastUnauth, stored>>

\* Item 3 gives FetchPayload the same per-frame check (before it, FetchPayload had none).
FetchPayload(u, t) ==
    /\ u \in conns
    /\ ReadAuthorized(t, u)   \* @guard fetch-payload-macaroon sym=src/gateway/engine.rs::fetch_by_shard_ids_to_owned_fd_with_peer_uid
    /\ lastRead' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastStatus, lastUnauth, stored>>

QueryStatus(u, t) ==
    /\ u \in conns
    /\ StatusAuthorized(t, u)
    /\ lastStatus' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastUnauth, stored>>

\* RegisterManifest and QueryHealthStatus carry no token (F-47).
\* @assume local-uid-trust: commands without a token rely on the UID allowlist and socket mode.
RegisterManifest(u) ==
    /\ u \in conns
    /\ lastUnauth' = <<u>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, stored>>

QueryHealthStatus(u) ==
    /\ u \in conns
    /\ lastUnauth' = <<u>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, stored>>

StorePayload(u, sealed) ==
    /\ u \in conns
    /\ Cardinality(stored) < 2
    /\ IngestSealedOk(sealed)
    /\ stored' = stored \cup {[sealed |-> sealed, mutated |-> FALSE]}
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, lastUnauth>>

\* The sender writes to a memfd it already sent; F_SEAL_WRITE | SHRINK | GROW forbid it.
MutateAfterStore(p) ==
    /\ p \in stored
    /\ ~p.sealed /\ ~p.mutated
    /\ stored' = (stored \ {p}) \cup {[sealed |-> FALSE, mutated |-> TRUE]}
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, lastUnauth>>

Next ==
    \/ \E u \in Uids : Connect(u)
    \/ \E u \in Uids : \E t \in Presentable(u) : FetchRange(u, t)
    \/ \E u \in Uids : \E t \in Presentable(u) : FetchPayload(u, t)
    \/ \E u \in Uids : \E t \in Presentable(u) : QueryStatus(u, t)
    \/ \E u \in Uids : RegisterManifest(u)
    \/ \E u \in Uids : QueryHealthStatus(u)
    \/ \E u \in Uids, s \in BOOLEAN : StorePayload(u, s)
    \/ \E p \in stored : MutateAfterStore(p)

Spec == Init /\ [][Next]_vars

\* --- Invariants: over what was served, against the ground truth IssuedTo -------------
TypeOK ==
    /\ conns \subseteq Uids
    /\ lastRead = <<>> \/ lastRead[1] \in Uids
    /\ lastStatus = <<>> \/ lastStatus[1] \in Uids

\* With an allowlist, only allowlisted UIDs are ever served anything.
OnlyAllowedUidsServed ==
    allowlistSet =>
        \A rec \in {lastRead, lastStatus, lastUnauth} : rec = <<>> \/ rec[1] \in Allowlist

\* With a root key, a read is served only on a token its owner issued to that requester.
\* Without one, tokenless reads are served (F-47): TLC reaches that state.
NoReadWithoutCapability ==
    (rootKeySet /\ lastRead /= <<>>) => lastRead[2] \in IssuedTo(lastRead[1])

\* QueryStatus is refused without a root key and needs an issued token (not scoped).
StatusOnlyWithIssuedToken ==
    lastStatus /= <<>> => (rootKeySet /\ lastStatus[2] \in IssuedTo(lastStatus[1]))

\* Under --require-sealed-memfd no stored payload changes after it was stored.
StoredPayloadImmutable ==
    requireSealed => \A p \in stored : ~p.mutated
=============================================================================
