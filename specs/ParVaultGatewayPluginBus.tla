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
\*   var      lastWrite         -> model-only: history variable for WriteOnlyWithWriteToken
\*   var      lastHealth        -> model-only: history variable for HealthOnlyWithIssuedToken
\*   var      stored            -> model-only: stored payloads and whether they changed
\*   action   Connect           -> src/gateway/server.rs::GatewayIpcServer
\*   action   FetchRange        -> src/gateway/ipc.rs::IpcCommand::FetchRange
\*   action   FetchPayload      -> src/gateway/ipc.rs::IpcCommand::FetchPayload
\*   action   QueryStatus       -> src/gateway/ipc.rs::IpcCommand::QueryStatus
\*   action   QueryStatus       -> src/gateway/ipc.rs::IpcCommand::QueryLiveStatus
\*   action   RegisterManifest  -> src/gateway/ipc.rs::IpcCommand::RegisterManifest
\*   action   QueryHealthStatus -> src/gateway/ipc.rs::IpcCommand::QueryHealthStatus
\*   action   QueryHealthStatusAuthed -> src/gateway/ipc.rs::IpcCommand::QueryHealthStatusAuthed
\*   action   StorePayload      -> src/gateway/ipc.rs::IpcCommand::StorePayload
\*   action   MutateAfterStore  -> model-only: adversary writes to a memfd it already sent
\*   action   Disconnect        -> model-only: a client closes its connection (B-16: with no root key nothing else is enabled)
\*   const    DaemonUid         -> model-only: model identity
\*   const    PluginUid         -> model-only: model identity
\*   const    OtherUid          -> model-only: model identity
\*   const    ModeAdmitted      -> model-only: UIDs the socket's file mode admits (a set)
\* @end
\* The gateway plugin bus (ADR-27, ADR-32): the SO_PEERCRED UID allowlist per connection, the
\* macaroon check on every command (ADR-28; since B-16 store, register and health too, and no
\* root key means no service), the immutable ingest memfd, and QueryStatus. Plan-4 ruling (L-49).
\* rootKeySet stays a choice in Init: every shipped gateway has a key, but a library-built engine may not, and the model shows it then serves nothing.
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

\* A macaroon: who signed it, which UID its AllowedPeerUid caveat binds (or none), its
\* scope: "in" (manifest and range caveats cover the request), "out" (they exclude it) or
\* "any" (no manifest or range caveat), and whether it may write (no ReadOnly caveat; B-16).
Keys == {"root", "adv"}
Caveats == Uids \cup {"none"}
Scopes == {"in", "out", "any"}
Tokens == [key : Keys, uid : Caveats, scope : Scopes, write : BOOLEAN]
NoToken == [key |-> "absent", uid |-> "none", scope |-> "in", write |-> FALSE]

\* Ground truth: tokens the owner issued, by holder. A plugin holds a UID-bound read token,
\* a bearer read token, a UID-bound unscoped ReadOnly token (for status and health) and a
\* UID-bound unscoped write token (for store and register). Another local user holds a
\* UID-bound ReadOnly token of its own (issued, say, for the status page), so the UID allowlist
\* is what keeps it off the socket when one is set. The daemon holds none.
\* @assume bearer-tokens-not-leaked: a token with no UID caveat stays with its holder.
IssuedTo(u) == CASE u = PluginUid ->
                    {[key |-> "root", uid |-> PluginUid, scope |-> "in", write |-> FALSE],
                     [key |-> "root", uid |-> "none", scope |-> "in", write |-> FALSE],
                     [key |-> "root", uid |-> PluginUid, scope |-> "any", write |-> FALSE],
                     [key |-> "root", uid |-> PluginUid, scope |-> "any", write |-> TRUE]}
                 [] u = OtherUid ->
                    {[key |-> "root", uid |-> OtherUid, scope |-> "any", write |-> FALSE]}
                 [] OTHER -> {}
\* What a requester can present: its own tokens, nothing, any token signed with a key it
\* holds (never the root key), or one of the plugin's UID-bound tokens (leaked). Attenuation
\* only adds caveats, so a leaked read token never becomes a write token.
Presentable(u) == IssuedTo(u) \cup {NoToken}
                  \cup {t \in Tokens : t.key = "adv"}
                  \cup {[key |-> "root", uid |-> PluginUid, scope |-> s, write |-> FALSE] : s \in Scopes}
                  \cup {[key |-> "root", uid |-> PluginUid, scope |-> "any", write |-> TRUE]}

VARIABLES
    allowlistSet,       \* configuration, chosen in Init
    rootKeySet,
    requireSealed,
    snapshotPublished,
    conns,              \* UIDs with an admitted connection
    lastRead,           \* the last served read frame: <<uid, token>>, or <<>>
    lastStatus,         \* the last served QueryStatus: <<uid, token>>, or <<>>
    lastWrite,          \* the last served StorePayload or RegisterManifest: <<uid, token>>, or <<>>
    lastHealth,         \* the last served health query: <<uid, token>>, or <<>>
    stored              \* stored payloads: [sealed, mutated]

vars == <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns, lastRead,
          lastStatus, lastWrite, lastHealth, stored>>

\* --- Guards (each mirrors one Rust decision) -------------------------------------------
UidAdmitted(u) == ~allowlistSet \/ u \in Allowlist   \* @guard uid-allowlist sym=src/gateway/engine.rs::gateway_peer_uid_decision
\* The sym is broader than this check: the UID comparison is the AllowedPeerUid arm of `allows` in capabilities.rs.
UidCaveatOk(t, u) == t.uid \in {"none", u}   \* @guard macaroon-uid-caveat sym=src/capabilities.rs::evaluate_caveats
\* gateway_macaroon_decision (B-16): no root key, no service; then a token with a valid tag
\* whose caveats allow this frame (peer UID here, scope for reads).
GatedAuthorized(t, u) ==
    /\ rootKeySet   \* @guard macaroon-nokey sym=src/gateway/engine.rs::gateway_macaroon_decision
    /\ t /= NoToken /\ t.key = "root"   \* @guard macaroon-frame sym=src/gateway/engine.rs::gateway_macaroon_decision
    /\ UidCaveatOk(t, u)
ReadAuthorized(t, u) ==
    /\ GatedAuthorized(t, u)
    \* The manifest and byte-range caveats (AllowedManifest, ByteRange arms of `allows`): a token
    \* scoped to another file is not a capability for this one.
    /\ t /= NoToken => t.scope \in {"in", "any"}   \* @guard macaroon-scope sym=src/capabilities.rs::evaluate_caveats
\* A write (store, register) needs a token without ReadOnly; a store, which has no manifest root
\* yet, also one with no manifest or range caveat (scope "any").
WriteAuthorized(t, u) ==
    /\ GatedAuthorized(t, u)
    /\ t.write /\ t.scope = "any"   \* @guard macaroon-write sym=src/gateway/engine.rs::gateway_macaroon_decision
IngestSealedOk(sealed) == ~requireSealed \/ sealed   \* @guard memfd-seal sym=src/gateway/engine.rs::gateway_memfd_seal_decision
\* status_auth_decision: a verifier (root key) and a snapshot, then a valid, ReadOnly,
\* unscoped token whose AllowedPeerUid (if any) is the caller's.
StatusAuthorized(t, u) ==
    /\ rootKeySet /\ snapshotPublished   \* @guard status-verifier sym=src/http_edge.rs::status_auth_decision
    /\ t /= NoToken /\ t.key = "root" /\ t.scope = "any" /\ UidCaveatOk(t, u)   \* @guard status-auth sym=src/http_edge.rs::status_auth_decision

Init ==
    /\ allowlistSet \in BOOLEAN
    /\ rootKeySet \in BOOLEAN
    /\ requireSealed \in BOOLEAN
    /\ snapshotPublished \in BOOLEAN
    /\ conns = {}
    /\ lastRead = <<>>
    /\ lastStatus = <<>>
    /\ lastWrite = <<>>
    /\ lastHealth = <<>>
    /\ stored = {}

\* A client connects over the socket (the file mode decides who can), or in process with the
\* daemon's UID (the in-process path runs the same decision with geteuid()).
Connect(u) ==
    /\ u \notin conns
    /\ u \in ModeAdmitted \/ u = DaemonUid
    /\ IF UidAdmitted(u) THEN conns' = conns \cup {u} ELSE UNCHANGED conns
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, lastRead,
                   lastStatus, lastWrite, lastHealth, stored>>

FetchRange(u, t) ==
    /\ u \in conns
    /\ ReadAuthorized(t, u)
    /\ lastRead' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastStatus, lastWrite, lastHealth, stored>>

\* Item 3 gives FetchPayload the same per-frame check (before it, FetchPayload had none).
FetchPayload(u, t) ==
    /\ u \in conns
    /\ ReadAuthorized(t, u)   \* @guard fetch-payload-macaroon sym=src/gateway/engine.rs::fetch_by_shard_ids_to_owned_fd_with_peer_uid
    /\ lastRead' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastStatus, lastWrite, lastHealth, stored>>

QueryStatus(u, t) ==
    /\ u \in conns
    /\ StatusAuthorized(t, u)
    /\ lastStatus' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastWrite, lastHealth, stored>>

\* B-16: store, register and health carry a token too. The tokenless QueryHealthStatus
\* (index 4) is always refused: it is QueryHealthStatusAuthed presenting no token.
RegisterManifest(u, t) ==
    /\ u \in conns
    /\ WriteAuthorized(t, u)   \* @guard register-macaroon sym=src/gateway/engine.rs::gateway_macaroon_decision
    /\ lastWrite' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, lastHealth, stored>>

QueryHealthStatusAuthed(u, t) ==
    /\ u \in conns
    /\ ReadAuthorized(t, u)   \* @guard health-macaroon sym=src/gateway/engine.rs::gateway_macaroon_decision
    /\ lastHealth' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, lastWrite, stored>>

QueryHealthStatus(u) == QueryHealthStatusAuthed(u, NoToken)

StorePayload(u, t, sealed) ==
    /\ u \in conns
    /\ Cardinality(stored) < 2
    /\ WriteAuthorized(t, u)   \* @guard store-macaroon sym=src/gateway/engine.rs::gateway_macaroon_decision
    /\ IngestSealedOk(sealed)
    /\ stored' = stored \cup {[sealed |-> sealed, mutated |-> FALSE]}
    /\ lastWrite' = <<u, t>>
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, lastHealth>>

\* A client closes its connection; it may connect again.
Disconnect(u) ==
    /\ u \in conns
    /\ conns' = conns \ {u}
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, lastRead,
                   lastStatus, lastWrite, lastHealth, stored>>

\* The sender writes to a memfd it already sent; F_SEAL_WRITE | SHRINK | GROW forbid it.
MutateAfterStore(p) ==
    /\ p \in stored
    /\ ~p.sealed /\ ~p.mutated
    /\ stored' = (stored \ {p}) \cup {[sealed |-> FALSE, mutated |-> TRUE]}
    /\ UNCHANGED <<allowlistSet, rootKeySet, requireSealed, snapshotPublished, conns,
                   lastRead, lastStatus, lastWrite, lastHealth>>

Next ==
    \/ \E u \in Uids : Connect(u)
    \/ \E u \in Uids : \E t \in Presentable(u) : FetchRange(u, t)
    \/ \E u \in Uids : \E t \in Presentable(u) : FetchPayload(u, t)
    \/ \E u \in Uids : \E t \in Presentable(u) : QueryStatus(u, t)
    \/ \E u \in Uids : \E t \in Presentable(u) : RegisterManifest(u, t)
    \/ \E u \in Uids : QueryHealthStatus(u)
    \/ \E u \in Uids : \E t \in Presentable(u) : QueryHealthStatusAuthed(u, t)
    \/ \E u \in Uids, s \in BOOLEAN : \E t \in Presentable(u) : StorePayload(u, t, s)
    \/ \E p \in stored : MutateAfterStore(p)
    \/ \E u \in Uids : Disconnect(u)

Spec == Init /\ [][Next]_vars

\* --- Invariants: over what was served, against the ground truth IssuedTo -------------
TypeOK ==
    /\ conns \subseteq Uids
    /\ lastRead = <<>> \/ lastRead[1] \in Uids
    /\ lastStatus = <<>> \/ lastStatus[1] \in Uids

\* With an allowlist, only allowlisted UIDs are ever served anything.
OnlyAllowedUidsServed ==
    allowlistSet =>
        \A rec \in {lastRead, lastStatus, lastWrite, lastHealth} : rec = <<>> \/ rec[1] \in Allowlist

\* A read is served only on a token its owner issued to that requester (B-16: there is no
\* tokenless read, with or without a root key).
NoReadWithoutCapability ==
    /\ lastRead /= <<>> => lastRead[2] \in IssuedTo(lastRead[1])
    \* ... and never on a token scoped to another file, with or without a root key.
    /\ (lastRead /= <<>> /\ lastRead[2] /= NoToken) => lastRead[2].scope \in {"in", "any"}

\* QueryStatus is refused without a root key and needs an issued token (not scoped).
StatusOnlyWithIssuedToken ==
    lastStatus /= <<>> => (rootKeySet /\ snapshotPublished /\ lastStatus[2] \in IssuedTo(lastStatus[1]))

\* B-16: a store or register is served only on a write token issued to that requester.
WriteOnlyWithWriteToken ==
    lastWrite /= <<>> => (lastWrite[2] \in IssuedTo(lastWrite[1]) /\ lastWrite[2].write)

\* B-16: health is served only on a token issued to that requester.
HealthOnlyWithIssuedToken ==
    lastHealth /= <<>> => lastHealth[2] \in IssuedTo(lastHealth[1])

\* B-16 (L-86): a gateway without a root key serves nothing.
NoServiceWithoutRootKey ==
    ~rootKeySet => (lastRead = <<>> /\ lastWrite = <<>> /\ lastHealth = <<>> /\ lastStatus = <<>>)

\* Under --require-sealed-memfd no stored payload changes after it was stored.
StoredPayloadImmutable ==
    requireSealed => \A p \in stored : ~p.mutated
=============================================================================
