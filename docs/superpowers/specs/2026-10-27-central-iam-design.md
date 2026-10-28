# Design: a generic central IAM on an event-sourced grant log

**Status:** decisions taken; builder check complete; CAS join, OpenFGA
change-feed and projection spikes complete; all §14 owner decisions
resolved; ready for the implementation plan. Written 2026-10-27 from a
brainstorm with the owner.

This supersedes the authorization half of
`docs/superpowers/specs/2026-10-26-central-iam-design.md` and the identity
half of `docs/superpowers/specs/2026-10-23-iam-design.md`. Those documents
remain the record of how the earlier decisions were reached.
`docs/research/20261025_iam.md` remains the owner's input and the source of
the target architecture; the divergences from it are listed in §2.

---

## 1. Intent

A **central** identity-and-authorization service for every product in the
set — `cas`, `cogos` and `ledger` today — and a **generic library** that
the service is built from. It starts at household scale and must not
foreclose many paying organisations later.

Identities are users and agents. Resources are URNs. Authorization is
relationship-based: a subject holds a relation on a node, and that relation
inherits down a tree. The questions the system must answer are:

- May this subject do this on this object?
- Who can see this object, and who granted that?
- Who could see it on 3 January?
- May this agent act, on whose behalf, with what supervision, and did a
  human approve?
- Can the engine be rebuilt from the record?

The last two are why the log, not the engine, is the authority.

### 1.1 Scope and migration

This replaces the existing `iam` module outright. There are no live
consumers, no data to migrate, and no compatibility obligation: the current
API, tables, migrations and examples are rewritten around this design. The old charter's ban on a third-party authorization engine,
and its no-deny/no-classification rules, are superseded where they conflict;
the no-deny rule survives for the reasons in §2. The charter's ban on key
material is also superseded by the `Sealer` port: IAM handles DEKs in
memory, but OpenBao holds the KEK and IAM never stores it. The old design
documents remain the record of how the earlier decisions were reached.

The `es-lite` dependency moves the module and its consumers from Go 1.25.6
to Go 1.26.5. That is a deliberate, one-commit decision across the set, not
a side effect to be discovered in CI.

## 2. What changed from the research and the earlier designs

The research architecture wins on the engine and topology: OpenFGA, a
tenant-partitioned Postgres, NATS for delivery and cache invalidation, and
an in-process cache on the decision path. It loses on five points, each
argued below.

| Research or earlier decision | This design | Why |
|---|---|---|
| Per-tenant OpenFGA `store_id` | **One global OpenFGA store**, tenant in the URN prefix | The owner wants one IAM, and a global store keeps the model and the operator surface singular. Isolation moves to a validated prefix plus the Postgres backstop. |
| OpenFGA is the authority | **es-lite log is the record; OpenFGA is a derived read model** | Point-in-time reconstruction and \"who granted this\" cannot be answered from current tuples or a finite `ReadChanges` retention. |
| Conditions, `check_clearance`, `blocked_inheritance` | **No ABAC conditions and no deny** | A condition cannot be precomputed and fragments the cache; a per-relation deny is a silent bypass when one relation or type is forgotten. The one absolute stays cryptographic. |
| `classification` column | **`tags`**, searchable metadata only | The column does not gate reads. Naming it `classification` invites the mandatory tier back in. |
| Identity registry inside IAM | **Zitadel owns identity; IAM is authorization-only** | The owner's decision: the IdP supplies verified identity; IAM supplies relationships. |
| Zitadel roles and groups as authorization | **IAM owns its groups; Zitadel roles are informational** | One authority for \"who can see this\". |
| Resource catalog and `kg_quads` inside the IAM core | **Consumer-side** | IAM stores the authorization graph only. Content, search text, embeddings and payload pointers are the apps' concern. |
| A fixed research model | **A default Google-Documents-like schema plus a small DSL** | Most consumers should never write a model; the DSL is the escape hatch. |
| CDC watermark as the consistency token | **The per-tenant es-lite log position** | The log is already ordered and resumable; the watermark becomes the projection cursor. |
| Multiple databases or FDW for the read join | **One tenant-partitioned Postgres and no FDW** | The CAS SQL join is a same-database join (§9.4a); a consumer in another database uses `ListObjects`. |

## 3. The shape

```
                         Zitadel (identity)
                                │ user / agent lifecycle
                                ▼
 consumer ── RegisterNode, Grant, Check, ListObjects, AuthorizeAction
    │                           │
    │                           ▼
    │                   ┌───────────────┐
    │                   │  IAM library  │  generic policy + schema
    │                   └───────┬───────┘
    │                           │
    │                 ┌─────────┴──────────┐
    │                 ▼                    ▼
    │          es-lite log          identity/agent
    │          THE RECORD           projections (Postgres, RLS)
    │                 │
    │                 ▼ projector (holds keys)
    │          ┌──────┴────────┬──────────────┐
    │          ▼               ▼              ▼
    │      OpenFGA        live-subject     read models
    │   (derived engine)   projection      (RLS)
    │
    ▼
 tool gateway / agent runtime (HITL/HOTL, approvals, tool execution)
```

The IAM library owns the generic mechanics: URNs, subjects, relations,
the tree, grants, groups, supervision, maturity, schema compilation,
authorization decisions, and the action policy. The consumer owns its
domain vocabulary, content, catalog, tools and approval workflow.

## 4. Nodes, URNs and kinds

### 4.1 One node, not two entities

At the IAM level a **container is not a separate entity**. It is the role
a node plays when another node names it as parent. A **resource** is a node
with content. One record carries both roles:

| Attribute | Why IAM needs it |
|---|---|
| `urn` | Stable identity, tenant-prefixed; the thing grants and tuples name |
| `tenant` | Isolation boundary; derived from the URN and validated, never trusted separately |
| `parent_urn` | The inheritance edge — exactly one, same tenant, or none for a root |
| `kind` | Whether the node may contain children, which relations apply, which schema rules it follows |
| `state` | Live or deleted, so a tombstoned node stops matching grants |
| `created_at`, `created_by` | Audit; also carried by the es-lite envelope |

The load-bearing attribute is `parent_urn`. It creates inheritance, and the
one-parent rule is the security invariant. Placement is immutable in v1;
re-parenting is deferred because neither consumer moves a subtree and a
move needs a cycle check across the whole ancestry (`es-lite` streams make
that a service-level read). A node is deleted by tombstone, not by removing
its history. Deletion is refused while live children exist; a recursive
delete is an explicit owner command, not an implication. A deleted URN is
retired and cannot be re-registered, for the same reason a group id is not
reused: the old ACL stream would otherwise resurrect grants written to the
previous object.

Content metadata — display name, MIME type, size, storage URI, search text,
embedding, tags — is not IAM's. It belongs to the consumer's catalog, fed
by the consumer's own events and joined to IAM's node URNs.

### 4.2 URNs and stream identities

The logical URN is `<tenant>/<kind>/<id>`, built by one helper and validated
at every boundary. Subjects use the same shape with a subject-kind segment:
`<tenant>/user/<id>`, `<tenant>/agent/<id>` or `<tenant>/group/<id>`. The
kind segment is load-bearing: a user, an agent and a group may share a raw
id, and a user and a group must not share a liveness row. The principal
stream id is `<subject-kind>_<id>` (`user_u0001`, `agent_a0001`,
`group_g0001`), so those streams cannot collide either. The tenant must
equal the service credential's tenant; a mismatch fails loudly.

`kind` and `id` are lower-case slugs (`[a-z0-9][a-z0-9_-]{0,127}`), matching
es-lite's stream-id rule. A consumer with an opaque external id maps it to a
slug at registration; IAM rejects anything else rather than silently
encoding it. The stream id for a node is `<kind>_<id>` and for its ACL is
`acl_<kind>_<id>`, so two kinds may share an id without colliding. The
es-lite workspace is the tenant, so tenant never enters the stream id.

### 4.3 Kinds are consumer data

The default OpenFGA model has one generic `node` type. A consumer registers
kinds separately:

```
folder    may contain [folder, document, album]   relations [owner, editor, commenter, viewer]
album     may contain [photo]                     relations [owner, editor, commenter, viewer]
photo     may contain []                          relations [owner, editor, commenter, viewer]
document  may contain []                          relations [owner, editor, commenter, viewer]
space     may contain [folder, message]           relations [owner, editor, commenter, viewer]
```

A new kind is a row in IAM, not a new OpenFGA type. IAM refuses a node
whose parent's kind may not contain it, a grant naming a relation the kind
does not allow, and a parent in another tenant. `can_delete` is the one
global relation: it is not in a kind's relation list, and it is grantable
on every node under the owner/senior-agent rule in §6.2. This is what keeps the
model stable while `cas`, `cogos` and the household use different words for
their things.

One kind is IAM's, not consumer data: the tenant root. Each tenant has
exactly one root node of kind `root`, created by `CreateTenant`, with no
parent and no tombstone; any registered kind may be its child. Consumers
cannot register a second root or a root kind. Every other node descends
from it, which is what makes the root owner's inherited authority cover the
tenant.

The kind vocabulary is deployment-wide, not per tenant, because the store
and model are global. A tenant that needs a relation vocabulary the default
does not have uses the DSL in §5.3 and gets a namespaced type.

### 4.4 The household, concretely

```
laenen/folder/home
├── laenen/folder/photos
│   └── laenen/album/2026
│       └── laenen/photo/IMG_4821
├── laenen/folder/tax
│   └── laenen/document/tax-2026
├── laenen/space/family-chat
│   └── laenen/message/msg-123
└── laenen/space/budget
    └── laenen/transaction/txn-456
```

The tenant root is omitted above; `home`, `family-chat` and `budget` are its
top-level children, and `photos` and `tax` are under `home`. `photos` is a
container because other nodes name it as parent. `IMG_4821`
is a resource because it has content — and it is still grantable, which is
how one photo is shared without its album. `photo` declares `may contain
[]`, so a photo under a photo is refused at registration.

## 5. The authorization model

### 5.1 The default schema

The default is Google-Documents-shaped: one tree, four roles, inheritance,
groups, and agents that can hold access but never sharing.

```
type user

type group
  relations
    define member:      [user]                     # flat; humans only
    define admin:       [user]                     # may add/remove members
    define can_manage:  admin

type node
  relations
    define parent:    [node]                      # IAM enforces exactly one
    define owner:     [user, group#member] or owner from parent
    define editor:    [user, agent, group#member] or owner or editor from parent
    define commenter: [user, agent, group#member] or editor or commenter from parent
    define viewer:    [user, agent, group#member] or commenter or viewer from parent
    define can_share:   owner
    define can_delete:  [user, agent, group#member] or owner  # direct grants do not inherit
    define can_edit:    editor
    define can_comment: commenter
    define can_view:    viewer

type agent
  relations
    define supervisor:  [user, agent, group#member]  # set; multiple allowed
    define can_act_for: [user]
    define can_manage:  supervisor
```

The ladder is `owner > editor > commenter > viewer`. Owner inherits, so a
folder owner can manage its contents. Only owner implies `can_share`;
receiving access never confers the ability to pass it on. Agents are
editor/commenter/viewer subjects but never owner, and they are not group
members, so an agent cannot obtain `can_share` through a group either.

`can_delete` is a separate relation, not part of the read ladder. A direct
grant of `can_delete` does not inherit; it reaches only the object it is
written on. `owner` still implies it, and owner inherits, so an owner can
delete its subtree. Only senior and autonomous agents may receive a direct
`can_delete` grant, and it never implies `can_share`.

`can_act_for` is explicit and human-only. The supervisor relation does not
imply delegation: an agent supervisor must not be able to hand a
subordinate a human's authority.

Out of v1: link sharing, transfer of ownership, expiring access, commenter
threads, and nested groups. Each is an extra subject or relation later, not
a change to the tree.

### 5.2 Why one generic node type

One `node` type keeps the model stable. Kind rules are IAM data, so adding
`photo` or `graph` does not rewrite the model every consumer shares. It
also avoids the earlier design's per-consumer-type problem: a change to
`cas_document` would have rewritten the model used by `cogos` and `ledger`
too. A consumer that needs semantics the default cannot express adds a
namespaced type through the DSL and accepts that its changes are model
changes.

Relation names are global in a single store. The default's `viewer` means
one thing everywhere; a consumer that means something else by `viewer`
gets its own type rather than redefining the shared one.

### 5.3 The DSL and the kind registry

The default schema is written in a deliberately small DSL. It supports:

- type declarations and relation declarations;
- direct subject types (`[user, agent, group#member]`);
- union and inheritance (`or`, `from parent`);
- exactly one parent relation;
- no conditions, no exclusion, no deny, no arbitrary relation algebra.

The compiler emits an OpenFGA model, validates it, and records a model
version. The default is a built-in DSL declaration, so there is one
compiler and one test path; consumers normally never see the DSL. A
consumer that needs `manager` or another non-inheriting relation
writes a small extension, and the compiler computes the model delta before
it is applied.

Model and kind changes are authorization events. A kind change is staged
until `ModelPublished`; writers validate against the published model, and a
kind that is not in it is unusable. Every authorization event records the
model version it was validated against, and the projector applies that
model version before the event. The decision cache key includes the model
version as well as the tenant position, so a model change cannot be hidden
behind a cached allow.

A check evaluates under the model active at the time; a point-in-time
rebuild replays the model events up to the target instant before replaying
grants. The model stream is deployment-wide, while grant streams are
per-tenant; the projector therefore keeps a global model cursor and
per-tenant cursors, and orders a tenant event after the model version it
names.

The deployment-wide stream needs a home that is not a tenant. It lives in
one reserved platform workspace, `_platform`, created by deployment
bootstrap and the sole exception to "the workspace is the tenant".
Per-tenant workspaces hold the node, ACL, group, agent and principal
streams; `_platform` holds `model:<version>` and its key. The projector
tails `_platform` once for the global model cursor and each tenant
workspace for its own cursor, and applies a tenant event only after the
model cursor has passed the version named in that event.

## 6. Aggregates and events

The aggregates mirror the questions the log must answer, not the OpenFGA
tuples. Each stream is a consistency boundary; cross-stream checks happen
in the service before `Handle`, because es-lite Deciders are pure.

### 6.1 `node:<kind>_<id>`

State: URN, kind, parent URN, live/deleted.

- `NodeRegistered{urn, kind, parent_urn, created_by}`
- `NodeDeleted{reason}`

Invariants: no duplicate URN; parent exists, is live, is in the tenant, and
its kind may contain this kind. Placement is immutable; a move is a later
command with an ancestry check. Deletion is a tombstone, so grants stay in
history but the projector removes the node's tuples.

### 6.2 `acl:<kind>_<id>`

State: grants by grant id, with a uniqueness index over `(subject, relation)`.

- `GrantIssued{grant_id, subject_urn, subject_kind, relation, granted_by, reason}`
- `GrantRevoked{grant_id, revoked_by, reason}`

Invariants: `(subject, relation)` unique; revoke only a live grant; the
relation is declared for the node's kind, or is the global `can_delete`;
the subject is live and allowed for the relation; an `owner` grant to an
agent is refused. A direct
`can_delete` grant is non-inheriting, may be issued only by an owner, and an
agent recipient must be senior or autonomous; an apprentice or associate
agent is refused. A typo in a relation is refused at the write, not stored
as a grant that never fires. The service checks that the actor may share
(`can_share`) before appending, and the actor's own authority is checked
under the same staleness guard as a read.

### 6.3 `group:<id>`

State: group live/deleted, members.

- `GroupCreated{name, admin_urn, created_by}`
- `GroupAdminChanged{admin_urn, changed_by}`
- `MemberAdded{principal_urn, added_by}`
- `MemberRemoved{principal_urn, removed_by}`
- `GroupDeleted{reason}`

Invariants: groups are flat and human-only; a principal is added once;
removing a non-member is a no-op or a refused command, chosen explicitly.
One admin manages membership; the creator is the initial admin. Group ids
are never reused after deletion, or a recreated group would resurrect
grants written to the old one.

### 6.4 `agent:<id>`

State: subject URN, supervisor set, maturity, delegation set, live/suspended.

- `AgentRegistered{subject_urn, supervisor_urns, maturity}`
- `SupervisorAdded{supervisor_urn}`
- `SupervisorRemoved{supervisor_urn}`
- `MaturityChanged{maturity}`
- `DelegationGranted{user_urn, granted_by}`
- `DelegationRevoked{user_urn, revoked_by}`
- `AgentSuspended{reason}`
- `AgentResumed{reason}`
- `AgentDeleted{reason}`

The agent's identity is a Zitadel machine user; IAM owns the supervision,
maturity and delegation facts. Invariants: at least one supervisor; no
duplicate supervisor; at registration or add time each supervisor is a live
user, a live agent, or a live group with at least one live member; an agent
supervisor has strictly higher maturity; a group supervisor is human-only
(groups are flat and human-only); every chain ends at a human or a group,
and a chain is live only if its end is live; no cycles, because
agent-to-agent edges strictly increase maturity and groups contain no
agents. A later deactivation does not remove the supervisor edge; it makes
that path non-live.

Effective agent liveness is
`principal_live AND NOT suspended AND any live supervisor path`, where a
live supervisor path is a live user, a live group with a live member, or a
live agent supervisor. The agent's Zitadel machine user must also be live:
a `PrincipalDeactivated` for that user makes the agent non-live even when
its supervisor path is live. `AgentSuspended` sets an explicit `suspended`
flag that is a hard false and persists until `AgentResumed`; a resume with
no live path is refused. Losing the last live path makes the agent
**orphaned** (`live=false`) but leaves its supervisor set intact. Removing
the last supervisor is refused as a structural invariant; deactivation,
group-member loss or an upstream agent's explicit suspension is what can
leave no live path. The agent and any dependents whose **only** live path
ran through it become orphaned, not explicitly suspended.

`Suspended` means only the explicit `AgentSuspended` flag. An orphaned
agent is not explicitly suspended: a new live supervisor path restores it
without a command. Only `AgentResumed` clears the explicit flag, and only
when the principal is live and a live path exists.

`AgentRegistered` requires the agent's machine-user principal to be linked
in the tenant. If that principal is already non-live (for example a global
deactivation arrived first), the agent is registered non-live and
`AgentResumed` is refused until the principal is live.

The projector recomputes this derivation for the affected agent and its DAG
descendants whenever a supervisor edge, principal liveness, group member,
group liveness or explicit suspension changes. It processes the affected
set in topological order so an upstream suspension is visible before its
dependents. The derivation is idempotent; `live` is an output, while
`suspended` mirrors the explicit event state and is not a second
derivation.

If the identity adapter deletes an agent's machine user, the agent is
non-live and can never be resumed; a human supervisor or tenant admin must
append `AgentDeleted` (or link a new agent identity). A change that would
invert maturity or create a cycle is refused.

### 6.5 `principal:<subject-kind>_<id>`

State: linked, global live, tenant live, deleted. Effective live is
`global_live AND tenant_live`; for an agent machine user, the agent's
effective live is the derivation in §6.4.

- `PrincipalLinked{issuer, external_id, urn, kind}`
- `PrincipalDeactivated{source, reason}` — source is `global` or `tenant`
- `PrincipalReactivated{source, reason}` — source is `global` or `tenant`
- `PrincipalDeleted{reason}` — identity adapter only

The principal stream covers users and agent machine users. Groups are
IAM-owned and their liveness is `group:<id>`, not a principal stream.

The identity adapter maintains a deployment-wide external-identity index
keyed by `(issuer, subject)` that maps to every linked tenant and principal
URN, plus the current global live state. A global deactivation,
reactivation or deletion fans out `PrincipalDeactivated{source=global}`,
`PrincipalReactivated{source=global}` or `PrincipalDeleted` to every linked
tenant. A link created after a global deactivation writes
`PrincipalLinked` followed by the current global state, so the new
principal does not start live. The index is rebuildable from the per-tenant
principal streams; it is not a second record.

The identity adapter issues global deactivation/reactivation; a tenant admin
issues tenant-scoped deactivation/reactivation for a principal in their
tenant. A tenant reactivation cannot override a global deactivation. Only
the identity adapter issues `Deleted`.

`Deactivated` and `AgentSuspended` are reversible: the live filter denies,
but the subject's tuples are left in place, so reactivation restores the
same access without re-granting. Effective live is `global_live AND
tenant_live`, so a tenant admin can offboard a user without deleting the
Zitadel identity, and Zitadel's global deactivation cannot be overridden.
`Deleted` is terminal: the projector deletes the subject's direct grants,
group memberships, group-admin tuples, delegations and supervisor edges
where the subject is the supervisor; for an agent it also deletes the
agent's own supervisor and delegation tuples as an object; it retires the
URN. Agents whose only
live path ran through a deleted user become non-live; a deleted agent's
dependents become non-live and its own record remains until `AgentDeleted`.
That distinction is what keeps a temporary suspension from destroying a
household member's grants, while still closing the direct-grant leak on
real offboarding.

Identity is Zitadel's; this stream is IAM's projection of the lifecycle it
needs for decisions. It stores no credentials, attributes or PII beyond the
mapping. Zitadel remains the source of identity; IAM mirrors only liveness
and the stable URN.

### 6.6 The model stream

`model:<version>` carries `KindRegistered`, `KindUpdated` and
`ModelPublished`. It is deployment-wide, written rarely, and lives in the
reserved `_platform` workspace rather than a tenant workspace (§5.3). The
compiler produces the model; publishing it is a reviewed, logged event so a
point-in-time rebuild knows which model was active.

## 7. Supervision, maturity, delegation and agents

### 7.1 The supervision chain

Each agent has one or more supervisors, each a user, an agent, or a group.
The graph is a DAG: maturity strictly increases along agent-to-agent edges,
and a human or a group is a root. A group's live members are human roots.
That makes cycles impossible without a separate graph walk and gives the
levels meaning.

A user may supervise any agent. An agent may supervise only a strictly
lower maturity. A group may supervise any agent, because its members are
human. A supervisor addition or removal that would invert maturity or
create a cycle is refused. Removing the last supervisor is refused; losing
the last **live** path through deactivation, group-member loss or an
upstream agent's suspension makes the agent non-live and leaves the set
intact. An agent is live while **at least one** supervisor path reaches a
live human or a live group member, its own principal is live, and it is not
explicitly suspended. If no path is live, the agent and any dependents
whose only live path ran through it become non-live (orphaned) until a
supervisor is reassigned; checks deny the non-live agent. An explicit `AgentSuspended` is
a hard false and overrides the path rule until `AgentResumed`; a resume
with no live path is refused. The live projection recomputes this for the
affected agent and its DAG descendants in topological order.

A group supervisor expands to its live members for approval: the group is
not itself a human, and a group with no live members is a dead path.

### 7.2 Maturity

Four levels, ordered:

| Level | Autonomy | May supervise | Default grant ceiling |
|---|---|---|---|
| `apprentice` | acts only on explicit grants; shortest run TTL | nobody | viewer/commenter |
| `associate` | acts within granted containers | apprentices | editor |
| `senior` | autonomous within its scope; manages a small tree | associates and apprentices | editor |
| `autonomous` | manages agent trees; broadest scope | seniors and below | editor; never owner |

`interim` is a status, not a maturity: it means temporarily acting and can
apply at any level. If it is needed, it is a separate flag on the agent.

`can_delete` is a separate non-inheriting relation, not part of the default
grant ceiling. Only senior and autonomous agents may receive it. A demotion
that would leave a `can_delete` grant on an associate or apprentice is
refused until the grant is revoked.

Maturity gates supervision, agent creation and promotion, the grant-time
ceiling, and the run token's TTL and tool scope. It **never gates a read**.
Once a grant exists, the decision is the grant's; an attribute that denies
reads is the mandatory tier returning by the back door.

The run-token issuer reads maturity through `GetAgent`, which returns the
agent's supervisor set, maturity, delegation set, liveness and revision. It
does not infer maturity from `AuthorizeAction`; a cached copy is keyed by
revision so a demotion or suspension is observable before the next run.

A demotion that would leave an agent above its own ceiling or above its
supervisees is refused until the grants and supervisees are adjusted.

### 7.3 Agents work on behalf of users

- The agent is a stable Zitadel machine user. It inherits nothing from the
  human who launched it.
- A run is a short-lived token with `agent`, `on_behalf_of`, `run_id`, TTL
  and tool scope. The TTL is a session attribute; it creates and destroys
  no relationships.
- `can_act_for(agent, user)` is an explicit IAM delegation. A human
  supervisor may grant it for themselves; granting it for another user is
  a human decision, never an agent's.
- A delegated run's access is the **intersection** of the agent's own grants
  and the on-behalf-of user's grants. The agent must have its own grant and
  the user must have access. This keeps \"an agent inherits nothing\" true
  while allowing real delegation.
- A destructive run is subject to the same intersection: the agent needs
  `can_delete` and the on-behalf-of user needs `can_delete` or `owner`. The
  human approval in §8 is additional. An agent cannot use its own
  `can_delete` to delete something the user could not.
- `can_share` is always denied when the actor is an agent, even if the
  on-behalf-of user is an owner.

Audit records the agent, the on-behalf-of user, and the human or supervisor
set responsible for the run. An approval records the actual approving human,
which may be one of several supervisors or a member of a supervising group.

## 8. HITL, HOTL, tools and approvals

### 8.1 The boundary

**IAM makes the decision; the app runs the workflow.** HITL/HOTL is not an
OpenFGA relation and not a tuple. It is a run policy that depends on
IAM-owned maturity and supervision plus an app-owned tool class.

IAM exposes:

```go
decision := iam.AuthorizeAction(ctx, iam.ActionRequest{
    Agent:      agentURN,
    OnBehalfOf: userURN,
    Object:     nodeURN,
    Relation:   iam.Editor,
    Action:     iam.ActionWrite,
})
// decision.Verdict: Allow | Deny | RequireApproval
// decision.Approvers: set of nearest live humans across all supervisor paths,
//                     deduplicated; a group expands to its live members
```

It performs the relationship check, applies `(maturity, action class)`, and
returns the human approvers. For `ActionDestructive`, IAM requires
`can_delete` on the object for both the agent and the on-behalf-of user, in
addition to the tool's `required_relation`; the `Relation` field cannot
substitute for the destructive gate. The gateway derives `Action` from the
registered tool, not from the agent. The agent is live if at least one
supervisor path reaches a live human; the approver set is the union across
all live paths. Any one of them may approve by default; the app's approval
policy may require all. It is stateless and cacheable.

The app or a separate approvals service owns the tool registry, approval
requests, notifications, the signed approval token, tool execution,
monitoring, interrupt/revoke, and the action audit. IAM never stores tool
payloads, approval requests or action outcomes.

### 8.2 Action classes and the default policy

| Action class | Autonomous | Senior | Associate | Apprentice |
|---|---|---|---|---|
| read | HOTL | HOTL | HOTL | HOTL |
| comment | HOTL | HOTL | HOTL | HOTL |
| write | HOTL | HITL | HITL | HITL |
| external (send, spend) | HOTL | HITL | HITL | HITL |
| destructive | HITL with `can_delete` | HITL with `can_delete` | human-only | human-only |
| share | human-only | human-only | human-only | human-only |

HOTL means the agent acts and a human supervisor in the approver set
monitors, with revoke and interrupt available. HITL means the action waits
for a human approval. The approver set is the one returned by
`AuthorizeAction`; the default workflow accepts any one live human. A tenant
may later require all, but that is an app-side approval policy, not a second
IAM verdict. Sharing actions require `owner`, which agents never hold.
Destructive actions require `owner` or `can_delete`. A human with either
deletes directly; that is a `Check` on `can_delete`, not an
`AuthorizeAction`. An agent needs `can_delete` and HITL, and the
on-behalf-of user must also have `can_delete` or `owner`; otherwise the
verdict is Deny, not `RequireApproval`. `DeleteSubtree` remains
owner-only. In v1 the table is a library constant: there is no tenant
override, no policy aggregate and no extra cache invalidation. A tenant-specific policy is a
later aggregate and command, and the share row remains non-overridable
when it arrives.

### 8.3 Tools

Each tool is registered app-side with the metadata the gateway needs:

```
tool:              photos.edit
action_class:      write
required_relation: editor
target:            node/photo
payload_hash:      [photo_id, patch]

tool:              email.send
action_class:      external
required_relation: none
target:            mailbox
payload_hash:      [to, subject, body]
```

The tool gateway is the PEP. For each call it resolves the target URN and
relation, calls `AuthorizeAction`, and then either executes (HOTL), waits
for approval (HITL), or returns a structured denial. An approval token is
single-use, short-lived, and bound to the exact tool call and payload hash,
so it cannot be replayed for a different recipient, amount or document.
Approval never bypasses authorization: if IAM denies, a human supervisor
must grant access or perform the action.

If a supervisor path goes through an agent, that path escalates to its
supervisors; an agent cannot satisfy HITL. The approver set is the union of
the nearest live humans across all live paths. If no human responds before
the deadline, the action is denied. The gateway revalidates liveness and
the destructive `can_delete` check for both the agent and the on-behalf-of
user immediately before execution, so a decision cannot outlive a
deprovision or a revoked grant.

## 9. The record, projection, consistency and rebuild

### 9.1 es-lite is the record

The append-only es-lite log is the authority. It is workspace-scoped, and
the workspace is the tenant, with the single `_platform` exception for the
model stream (§5.3). es-lite v0.6 stores opaque **payloads** and never
decrypts, and deliberately ships no crypto of its own. The es-lite envelope
metadata (stream id, position, actor, timestamps) is plaintext; the payload
is sealed. IAM seals every event payload before append through a `Sealer`
port. The adapter uses envelope encryption: a per-tenant-version DEK
encrypts the payload, and OpenBao Transit holds the KEK that wraps the DEK.
The sealed payload carries its `key_id`; the wrapped DEK is stored in
`tenant_keys(tenant_id, key_id, wrapped_dek, created_at, retired_at)`, not
in the log. OpenBao is present in the household and the enterprise; a local
key file is dev/test only. IAM never stores the KEK; the service and
projector cache the DEK in memory. `CreateTenant` provisions the tenant's
first key, and deployment bootstrap provisions a separate `_platform` key;
losing the `_platform` key breaks rebuild and must be escrowed. Deleting a
tenant's keys crypto-shreds its payloads **but not the es-lite metadata**,
which remains the audit skeleton. Tenant deletion is a deployment-admin
procedure: delete the tenant keys, publish the key-revocation event, then
purge the workspace and read models; it is not a tenant command. The
consequences are stated rather than discovered:

- The grant log is **not SQL-queryable**. An audit question is answered by
  the IAM service replaying, not by `psql`; the plaintext metadata is not a
  substitute for the payload.
- es-lite is on Go 1.26.5. Adopting it pulls this module and its consumers
  forward from 1.25.6. The owner accepted this for consistency with the
  other apps.
- Every workspace maps to a tenant except `_platform`. The projector reads
  each tenant's workspace with a keyholder; it never trusts a
  client-supplied tenant.
- A missing or deleted tenant key fails closed. The projector cannot read
  that tenant's log, and queries do not fall back to plaintext; the
  ciphertext remains, but crypto-shredding is irreversible.
- Rotation is supported: `RotateTenantKey` creates a new `key_id`; old
  events keep their key and stay readable, and the old wrapped DEK is
  retained for the life of the log. `ForgetTenantKey` deletes all keys and
  publishes a key-revocation event on NATS; every service and projector
  evicts the tenant DEK before acknowledging. An instance that misses the
  event fails closed on the next OpenBao unwrap; a cached DEK must not
  outlive the key.

The envelope carries actor, command, correlation, causation, occurred-at and
recorded-at. The grant event carries `granted_by` and `reason`, so "who
granted this" is in the record by construction.

### 9.2 The projector

The projector tails the log per tenant, applies events in order to OpenFGA
and to the Postgres read models, and stores its last-applied position. It
is at-least-once; every handler is idempotent. OpenFGA writes and deletes
are set operations, so replaying a batch is safe. A malformed or failed
projection is visible lag, not silent inconsistency.

Tuple mapping:

- `NodeRegistered` → `node:<urn>#parent@node:<parent_urn>` when a parent exists.
- `GrantIssued` → `node:<urn>#<relation>@<subject>`; a group subject is
  `group:<urn>#member`. `GrantRevoked` deletes that tuple.
- `GroupCreated` → `group:<urn>#admin@user:<admin_urn>`;
  `GroupAdminChanged` deletes the old admin tuple and writes the new one.
- `MemberAdded` → `group:<urn>#member@user:<urn>`; `MemberRemoved` deletes it.
- `AgentRegistered` → one `agent:<urn>#supervisor@<supervisor>` tuple per
  supervisor; a group supervisor is `group:<urn>#member`.
  `SupervisorAdded` writes the tuple; `SupervisorRemoved` deletes it.
- `DelegationGranted` → `agent:<urn>#can_act_for@user:<urn>`;
  `DelegationRevoked` deletes it.
- `PrincipalDeactivated` → mark the principal not live; if it is an agent
  machine user, set the agent's `principal_live=false` so it is non-live.
  Its tuples stay in place so reactivation restores the same access.
  `AgentSuspended` sets the agent's explicit suspended flag; its tuples
  stay.
- `PrincipalDeleted`/`AgentDeleted` → delete the subject's direct grants,
  group memberships, group-admin tuples, delegations, and supervisor edges
  where it is the supervisor; for an agent, also delete its own supervisor
  and delegation tuples as an object; mark agents whose only live path ran
  through it non-live; retire the URN. An agent's own record remains until
  `AgentDeleted`.
- `NodeDeleted`/`GroupDeleted` → delete that object's tuples and its
  memberships; mark it not live. A group's deletion also removes its admin
  and member tuples; a node's deletion does not cascade to children (the
  aggregate refuses while live children exist). The event log keeps the
  history.

The read models keep the history even when the engine tuple is gone:
`GrantRevoked` sets `iam_grants.live=false`, `MemberRemoved` sets
`iam_group_members.live=false`, and `DelegationRevoked` sets
`iam_agent_delegations.live=false`; the OpenFGA tuples are deleted.

The live-subject projection is the second line: `Check`, `ListObjects` and
`AuthorizeAction` consult it, so a deactivated or suspended subject denies
immediately, and a deleted subject denies even before its tuple deletion has
applied. It stores `global_live`, `tenant_live` and the effective
`global_live AND tenant_live`; a tenant admin's deactivation and Zitadel's
global deactivation use the same filter. For deletion, both the tuple removal and the filter are required:
the filter covers the projection window, and the deletion keeps the engine
honest for anything that reads OpenFGA directly. Either alone leaves a hole
the old direct-grant finding exposed.

The projector recomputes the live-subject rows for a change's affected
subjects. A user or group change affects agents supervised by that subject
(through `iam_agent_supervisors`) and their DAG descendants; it updates
`iam_agents.principal_live` and `suspended`, recomputes `live` in
topological order, then upserts `iam_live_subjects`. It is the same
derivation as §6.4/§7.1, not a second rule. For an agent,
`iam_live_subjects.live` is the effective agent liveness; the principal's
global/tenant state is stored in `iam_agents.principal_live`. The projector
also upserts `iam_live_subjects` for every user, group and agent on
creation, deactivation, reactivation and deletion; a group's row follows
`iam_groups.live`.

Building the read models from OpenFGA's `ReadChanges` was tested directly.
The feed reproduced the tuple-derived state exactly: 11,052 changes over 111
pages in 4.91 s, with zero node, grant or membership diffs. It cannot be the
sole source. `ReadChanges` carries no deactivation (tuples stay in place), no
node tombstone (deleting a parent tuple is not a `NodeDeleted`), no model
version, no `grant_id`/`granted_by`, and no root bootstrap. The spike measured
the liveness gap: 14 direct grants stayed visible until the simulated
`PrincipalDeactivated` event, then went to zero. The log remains the
projection source; `ReadChanges` is a catch-up and verification tool, not the
record.

### 9.3 Consistency

The per-tenant log position is the consistency token. `Grant` returns it; a
caller that needs read-your-writes passes it to `Check` or `WaitForRevision`
and waits until the projector's applied position reaches it. A check
without a token accepts bounded staleness. The revision is on every answer,
so a later consumer can build on it without a breaking change.

The bound is a security parameter, not a tuning knob. In v1 it is five
seconds, shared by reads and writes and configurable per deployment; the
projector should normally be far below it. When the lag exceeds it,
`Check`, `ListObjects`, `AuthorizeAction` and the write-path `can_share`
check fail closed with `ErrStale` rather than serving or acting on an
unbounded stale allow. A caller that cannot tolerate the bound passes a
revision and waits. The owner confirmed the shared five-second bound on
2026-10-27.

The direct SQL join in §9.4a is outside the IAM API, so it must enforce the
same bound itself. The projector maintains
`iam_projection_state(tenant_id, applied_position, applied_at)` and
`iam_model_cursor(global_position, applied_at)`. It heartbeats `applied_at`
per tenant even when idle, so an idle tenant is not perpetually stale; the
heartbeat is not a new event. A consumer that needs read-your-writes calls
`WaitForRevision` before the join. A consumer that accepts bounded staleness
includes `iam.fresh()` in the query; a read-your-writes consumer includes
`iam.fresh($revision)`. It returns false, and the query returns no rows,
when the tenant's applied position is behind the requested revision or the
lag exceeds the bound. The SQL path never serves an unbounded stale allow.
`iam.fresh` is a SQL function in the IAM schema; it reads
`iam_projection_state` for the tenant set in `app.tenant`. A missing state
row is false, not fresh. Because `iam.fresh` false returns no rows, the app
must treat that as `ErrStale`, not as an empty result; `ProjectionStatus`
distinguishes stale from empty.

The base tables are not granted to consumers. The consumer role selects
secured views defined by the projector (for example
`iam.visible_grants`) that call `iam.fresh` and apply the live-subject and
live-node filters. The views read `app.tenant`, `app.subject` and, when
needed, `app.revision` from session GUCs. The consumer's DB role is
tenant-scoped; a role that can set another tenant is a deployment error.
The view owner is the projector role; the consumer has SELECT only. A
compromised backend can still query as another subject in its own tenant,
which is the same trust assumption as the API; it cannot cross tenants.

### 9.4 Rebuild and point-in-time

Two operations share one replay path:

- **Full rebuild** replays the log from position 0 into a new OpenFGA store
  and a shadow Postgres schema, then cuts readers over. The URNs are public
  identity and do not change, so the rebuild never rewrites a URN prefix.
  The old store and schema remain readable until the new one catches the
  tail. A per-tenant rebuild uses a shadow store and schema for that tenant
  and routes the tenant to them until cutover.
- **Point-in-time** replays the model events and authorization events up to
  time T into a shadow store and schema, then answers `Check`/`ListObjects`
  there. It is O(events) and is an audit operation, not a request-path one.

`Rebuild` rebuilds the Postgres read models in the same pass. They are
disposable and tenant-partitioned, so the shadow schema is swapped by a
view/partition switch; `ProjectionStatus` reports both positions.

Retention is indefinite in v1. The log is authorization-sized, not
content-sized, so this is affordable and keeps point-in-time and rebuild
unbounded. Archival and compaction are later features. If a finite floor is
introduced, a snapshot becomes the new base, and point-in-time before the
floor returns `ErrRetention`; the design does not build that in v1. The
`_platform` model stream is retained indefinitely because it is tiny and
needed for rebuild.

The Postgres read models live in the same tenant-partitioned Postgres as the
consumer's tables. The design already requires one Postgres and no FDW (§2),
so the CAS join in §9.4a is a same-database join. The consumer connects with
a tenant-scoped read credential and selects from secured `iam_*` views; it
does not write them. The RLS policy reads `app.tenant`, bound by that
credential, not from the caller's predicate. The consumer table is also
RLS-protected by tenant; both sides of the join run under the same tenant.
A consumer in another database cannot use the join path and must use
`ListObjects`.

The OpenFGA store is global; its isolation is the validated tenant prefix
plus the RLS-protected read models, not row security inside the engine. The
central PDP does not remove the RLS backstop: a PEP can forget a clause, and
the database cannot be asked nicely.

### 9.4a The consumer row-level join (CAS)

A consumer that must filter a large table in one SQL statement does not call
`ListObjects` and pass a list of URNs. It joins its own table to the
projector's read models. The spike measured both shapes on 10,000,000 CAS
documents; the report is
`docs/superpowers/spikes/2026-10-27-cas-sql-join.md`.

The projector maintains:

- `iam_nodes(tenant_id, urn, kind, parent_urn, live)`;
- `iam_node_closure(tenant_id, descendant_urn, ancestor_urn, depth)`, one
  row per node per ancestor, built on `NodeRegistered` because containment
  is a tree;
- `iam_grants(tenant_id, grant_id, object_urn, subject_urn, subject_kind,
  relation, relation_rank, granted_by, granted_at, live)`, direct grants
  only; `grant_id` and `granted_by` are there so provenance does not have to
  come from the engine, which does not carry them;
- `iam_group_members(tenant_id, group_urn, member_urn, live)`, flat groups;
  `MemberRemoved` sets `live=false`, it does not delete the row;
- `iam_groups(tenant_id, group_urn, admin_urn, live)`, for the group-admin
  check and group liveness;
- `iam_agents(tenant_id, agent_urn, maturity, principal_live, suspended,
  live)`, for `GetAgent`; `live` is the derived root liveness, while
  `principal_live` is the machine user's global/tenant state and
  `suspended` is the explicit `AgentSuspended` flag. `GetAgent`'s `Revision`
  is the tenant's applied position, not a per-agent counter;
- `iam_agent_supervisors(tenant_id, agent_urn, supervisor_urn,
  supervisor_kind)`, the supervisor set; a group supervisor expands through
  `iam_group_members` and `iam_groups` for approval;
- `iam_agent_delegations(tenant_id, agent_urn, user_urn, live)`, the
  delegation set returned by `GetAgent`;
- `iam_live_subjects(tenant_id, subject_urn, subject_kind, live)`, the
  single deprovisioning filter for every subject, including agents; an
  agent's row is derived from `principal_live`, `suspended` and the
  supervision chain;
- `iam_projection_state(tenant_id, applied_position, applied_at)`, the
  watermark used by `iam.fresh` in §9.3;
- `iam_model_cursor(global_position, applied_at)`, the model-stream
  watermark used by `ProjectionStatus`; the model stream is
  deployment-wide, so it has no tenant row.

Every query over these tables carries a live-subject check and a live-node
check, and runs under tenant RLS. The live check uses `iam_live_subjects`
for users, groups and agents; an agent's row already contains the
root-chain result. The direct-grant leak is reproduced if either check is
omitted. The same-database requirement is §9.4; a consumer in another
database cannot use this path.

The join is specified for the default `node` schema and its four base
relations (`viewer`, `commenter`, `editor`, `owner`). It uses the base
relation, not a computed relation such as `can_view`. A DSL extension that
adds a relation must declare its rank or provide its own view; without that,
the extension uses `Check`/`ListObjects` and the generic join is not
available. This keeps the rank ladder from becoming a second model language.
`can_delete` is a destructive relation, not part of the read ladder; the SQL
join does not use it. The rank ladder is pinned: `viewer=1`, `commenter=2`,
`editor=3`, `owner=4`; `can_delete` and every relation outside the ladder
are `0`, so they never match a view or edit check. Destructive actions go
through `AuthorizeAction` and the HITL workflow.

The direct join is for a single live user or agent subject. A delegated
run's intersection of the agent's grants and the on-behalf-of user's grants
is evaluated by `AuthorizeAction`/`Check`, not by the consumer join; the
consumer must not use the join to widen an agent's access. `iam_agents.live`
carries the derived supervision-chain liveness, so an orphaned agent is
filtered like any other non-live subject.

There are two query shapes, and the choice is by selectivity:

- **Broad access: document-driven.** Walk the consumer's ordered page index,
  and for each row test a direct or ancestor grant. CAS denormalizes
  `fileset_urn` and `root_urn` onto `cas_documents`, so the test is a small
  `IN` over the row's ancestors, not a closure join. At 1% access this was
  **27.7 ms p50**, against **41.7 ms** for the generic closure path.
- **Narrow access: grant-driven.** Resolve the subject's accessible ancestor
  URNs first, expand them to documents through `iam_node_closure`, then sort
  the small candidate set. At 0.1% access this was **94 ms p50**, against
  **272 ms** for the denormalized document-driven path; at 0.01% it was
  **7.2 ms**, against roughly **4 s**. For ten direct document grants it was
  **0.77 ms**; the document-driven path did not finish inside 60 s.

The crossover sits between 0.1% and 1% of the table. `AccessibleCount` is a
hint, not a filter: it counts IAM nodes of the requested kind, not the
consumer's filtered or deleted rows, and it can cost more than the page it
selects (**866 ms** for 100,000 versus **28 ms** for the broad page). Cache
it per `(tenant, subject, relation, kind, revision)` or precompute it; do
not call it per page. A cached `ListObjects` result is an alternative
source. The `ListObjects` URN baseline itself was not competitive at scale:
materializing 10,000 URNs cost **202 ms** and 100,000 cost **1.5 s**, before
the join.

This settles the **row-level** join. A sensitive column is handled by
representation: model the field as its own node with its own URN and grant,
placed **outside the document's subtree** (for example under a tenant-level
`fields` container with no broad grants). A field that is a descendant of
the document inherits the document's viewer/editor and does not close F4.
The document row references the field URN; the field row is visible only
with the field's own grant. The field's lifecycle is separate, so deleting
the document does not delete the field; the consumer deletes its field
nodes explicitly or uses `DeleteSubtree` on the fields container. F4 closes
by respecification for consumers that adopt this. If a consumer cannot, F4
reopens and the permitted-attribute set is the fallback; it is not the v1
path.

### 9.5 Cache and NATS

The research's in-process cache is an optimization, not a correctness
dependency. A decision may be cached per `(tenant, subject, on_behalf_of,
relation, node)` with the applied position in the key. The projector
publishes invalidation events after applying; a missed invalidation only
serves a stale allow within the bounded staleness policy, never a wrong
allow after the projection is observable. NATS carries delivery and
invalidation; the es-lite log remains the outbox and the record.

## 10. Security invariants

1. **Deprovisioning is closed on every arm.** A deactivated or suspended
   user or agent stops matching direct grants, group grants, delegations and
   supervision tuples because the decision path filters through the live
   projection. Effective live is `global_live AND tenant_live`; an agent adds
   `principal_live AND NOT suspended` and any live supervisor path. A tenant
   admin's deactivation is as immediate as Zitadel's, and a tenant
   reactivation cannot override a global one. A deleted subject also has its
   direct grants, group memberships, group-admin tuples, delegations and
   supervisor edges removed by the projector, and agents whose only live
   path ran through it become non-live. Both arms are covered; either
   mechanism alone is not.
2. **Containment is a tree.** IAM refuses a second parent and a parent in
   another tenant. The OpenFGA model cannot enforce this by itself, so the
   node aggregate and the registration service do.
3. **Tenant isolation is structural at the edges.** Every URN is
   tenant-prefixed and validated against the service credential's tenant.
   The Postgres read models and the consumer table use RLS under a
   tenant-scoped DB role. A mismatch fails loudly; an unknown object or
   subject denies rather than erroring, so there is no existence oracle.
4. **No deny and no read-time attributes.** There is no exclusion, no
   negative grant, no classification gate and no condition. `tags` are
   search metadata; maturity and sensitivity may gate a grant, never a
   read.
5. **Agents never share.** `owner` excludes agents in the model, IAM refuses
   an owner grant to an agent, and `can_share` is denied to an agent actor
   even when the on-behalf-of user is an owner. A direct `can_delete` grant
   is limited to senior/autonomous agents, and never implies `can_share`.
6. **Approval is not authorization.** A signed approval token is a session
   caveat for an already-authorized action; it cannot create access.
7. **Every live agent has at least one live human root.** The supervision
   graph is acyclic, strictly ordered by maturity on agent-to-agent edges,
   and a live agent has at least one path rooted in a live user or live
   group member. An agent without one is non-live (orphaned); a later
   deactivation does not remove its supervisor edges.
8. **The record is the log.** Nothing writes OpenFGA directly. Every
   authorization change is an event, and the projector is the only writer
   to the engine.
9. **Event payloads are ciphertext; metadata is not.** IAM seals the
   payload before append; the es-lite envelope metadata is plaintext, and
   that is the audit skeleton. Each sealed payload carries a `key_id`; the
   wrapped DEK is in `tenant_keys`; OpenBao holds the KEK. Rotation keeps old
   keys readable. Deleting the tenant keys erases payloads, not metadata,
   and a missing key fails closed. The log is not a plaintext audit table.
10. **Destructive delegation is explicit and supervised.** An agent may
    delete only with a direct, non-inheriting `can_delete` grant, the
    on-behalf-of user's `can_delete` or ownership, and a human approval
    (HITL). `DeleteSubtree` remains owner-only, and `can_delete` never
    implies `can_share`.
11. **Agent liveness is derived, not asserted.** The projector recomputes an
    agent and its DAG descendants on any supervisor, principal, group or
    suspension change. `suspended` is explicit and separate from `live`; a
    resume with no live path is refused, and a resume cannot override a
    deleted principal.

## 11. The public surface

The library is consumer-agnostic and depends on ports, not on es-lite,
OpenFGA or Zitadel. The central service wires the adapters.

Ports: `EventLog`, `Engine`, `IdentityEvents`, `Sealer`, `Clock`,
`IDGenerator`, optional `Cache`. The `Sealer` port covers `Seal`, `Open`,
`ProvisionTenantKey`, `RotateTenantKey` and `ForgetTenantKey`; `Seal`
returns the ciphertext with its `key_id`, and `Open` takes the `key_id`.
The OpenBao adapter is the deployment implementation, and the local key
file is dev/test only. Key rotation and forgetting are deployment-admin
operations through the `Sealer`, not tenant commands.

Commands and queries:

- `RegisterNode`, `DeleteNode`, `DeleteSubtree`
- `Grant`, `Revoke`
- `CreateGroup`, `AddGroupMember`, `RemoveGroupMember`, `SetGroupAdmin`,
  `DeleteGroup`
- `RegisterAgent`, `AddAgentSupervisor`, `RemoveAgentSupervisor`,
  `SetAgentMaturity`, `SuspendAgent`, `ResumeAgent`, `DeleteAgent`,
  `GrantDelegation`, `RevokeDelegation`
- `LinkPrincipal`, `DeletePrincipal` (identity adapter only);
  `DeactivatePrincipal`, `ReactivatePrincipal` (identity adapter or tenant
  admin)
- `CreateTenant` (deployment-admin bootstrap)
- `RegisterKind`, `PublishModel`
- `GetAgent`, `Check`, `AccessibleCount`, `ListObjects`, `ListSubjects`,
  `AuthorizeAction`, `WaitForRevision`, `AuditWhoCouldSee`
- `Rebuild`, `ProjectionStatus`

### 11.1 Control-plane authority

The trust boundary is service-to-service for **every** call, writes and
reads. The caller is a consumer backend presenting a tenant-scoped service
credential and a delegated actor token from Zitadel or `captoken`. The
tenant comes from the service credential, never from the request. The actor
comes from the token; the service maps the external identity to that
tenant's principal and denies if the actor is not linked there. The service
credential is bound to one tenant: mTLS/SPIFFE identity in deployment, a
signed bearer token with the tenant claim in the household. Direct user
calls are not part of v1; a UI or CLI goes through a consumer backend. One
Zitadel user may have a principal per tenant; the service credential
selects the tenant, and the actor token's tenant claim is not trusted.
Deployment-admin commands use a separate operator credential, not a tenant
service credential. Creating a tenant also creates its es-lite workspace,
its first wrapped DEK in `tenant_keys`, and its OpenBao key; the projector
is registered then. Deployment bootstrap creates the separate `_platform`
key and workspace.

The commands above need an actor rule, or the first grant has no one to
issue it and `AddGroupMember` becomes an unchecked path to everything the
group holds.

The authority model:

- **Deployment admin:** `CreateTenant`, `RegisterKind`, `PublishModel`,
  `Rebuild`, and owner recovery. This is an operator credential, not a
  tenant user.
- **Tenant bootstrap:** `CreateTenant` creates exactly one root node
  (`<tenant>/root/<slug>`, kind `root`) and one owner grant to the first
  user. That user is the tenant's first owner and tenant admin, and can
  create groups and top-level nodes below the root. Consumers cannot
  register a second root.
- **Node owner / destructive delegate:** `RegisterNode` under a node they
  can share, `Grant`, `Revoke`, `DeleteNode`, `DeleteSubtree`. `RegisterNode`,
  `Grant` and `Revoke` require `can_share`; `DeleteNode` requires `can_share`
  or `can_delete`; `DeleteSubtree` requires owner. An agent with
  `can_delete` must pass the app's HITL workflow before the backend issues
  `DeleteNode`. The creator of a node receives an owner grant automatically,
  so a fresh node is never ownerless.
- **Group admin:** `CreateGroup`, `AddGroupMember`, `RemoveGroupMember`,
  `DeleteGroup`, `GroupAdminChanged`. Any live user in the tenant may
  create a group and becomes its admin. A group-admin change is made by the
  current admin or a tenant admin; only a human may be a group admin.
- **Agent supervisor:** `RegisterAgent`, `AddAgentSupervisor`,
  `RemoveAgentSupervisor`, `SetAgentMaturity`, `SuspendAgent`, `ResumeAgent`,
  `DeleteAgent`, `GrantDelegation`, `RevokeDelegation`, bounded by maturity.
  A live user may register an agent with themselves as a supervisor;
  additional supervisors are added by a human supervisor or a tenant admin.
  A live agent may register only a strictly lower-maturity agent under
  itself, and only if its own maturity permits agent creation (§7.2); no
  agent may create an agent at or above its own maturity. Only a human
  supervisor or a tenant admin may add or remove a supervisor; an agent
  cannot edit its own or a subordinate's supervisor set. Only a human may
  grant `can_act_for`; an agent supervisor may manage a subordinate agent
  but not hand it a human's authority.
- **Identity adapter:** `LinkPrincipal`, global
  `DeactivatePrincipal`/`ReactivatePrincipal`, and `DeletePrincipal` are
  issued by the identity adapter from Zitadel lifecycle events. Only the
  identity adapter may link or delete a principal, and a tenant reactivation
  cannot override a global deactivation. It maintains the deployment-wide
  external-identity index and fans a global change out to every linked
  tenant; a link created after a global deactivation starts non-live.
- **Tenant admin:** there is no separate tenant-admin type. The tenant
  admin is an owner of the single root node; because owner inherits, that
  is authority across the tenant. The first owner is the initial tenant
  admin. The tenant admin may deactivate or reactivate a principal in the
  tenant; it cannot link or delete one. A lost owner is recovered by the
  deployment-admin recovery command, which installs a new root owner and is
  audited; there is no implicit superuser.

Registration and bootstrap span more than one stream (a node plus its
automatic owner grant, a group plus its admin tuple, a tenant plus its root
and owner). Those commands are idempotent and retried; a node or tenant is
not reported as ready until the accompanying grant is projected.

`Check`, `AccessibleCount`, `ListObjects` and `ListSubjects` are reads;
they arrive through a consumer backend with the tenant service credential
and a live actor token. `ListSubjects` reveals who else has access, so it
requires `can_share` on the object or the tenant's auditor credential;
`Check`, `ListObjects` and `AccessibleCount` do not. `AuditWhoCouldSee`
requires a tenant-admin actor or the tenant's auditor service credential. An auditor is a tenant-scoped
service credential with an `auditor` scope; it is not an IAM relation and
cannot write. The trust boundary is resolved in §14.1. An unknown object,
subject or relation is a deny, not an error.

### 11.2 Reverse and historical queries

`AccessibleCount(subject, relation, kind)` returns the number of nodes the
subject can reach, using the grant-driven count from §9.4a. It is a cached
hint that chooses between the document-driven and grant-driven join shapes,
not a per-page filter; see §9.4a for the cost and the caching key.

`ListSubjects(object, relation)` answers "who can see this now" from
OpenFGA's reverse index. The effective subject set comes from the engine;
the provenance comes from `iam_grants` and `iam_node_closure`, because the
engine carries neither `grant_id` nor `granted_by`. It returns effective
user and agent URNs, never groups. Each result carries provenance: the
grant id, the subject as written (user, agent, or
`group:<urn>#member`), the object that grant is on, `granted_by`, and
`granted_at`. Inherited access names the grant that
actually confers it; when several grants confer the same access, all
contributing grants are returned. `AuditWhoCouldSee(object, relation, at)`
replays the log into a shadow store at `at` and returns the same shape
reconstructed there; it is O(events) and is an audit operation, not a
request-path call. `at` is compared against `recorded_at` (the reproducible
commit clock), not `occurred_at`, unless the caller explicitly asks for
domain time. Both are restricted to tenant admins and auditors; the audit
endpoint is where the zero-knowledge consequence is visible, because
`psql` cannot answer it.

Results carry a `Revision`. Domain errors are typed sentinels: a malformed
schema, an undeclared relation, a duplicate grant, a second parent, a cycle
in supervision, a maturity inversion, a non-live subject, a tenant
mismatch, and a point-in-time before the retained floor (`ErrRetention`).
An unknown node, subject or relation is a deny, not an error, except where
the caller is writing an authorization fact: a grant naming an undeclared
relation is refused loudly.

The facade carries no `Open` until the deployment config is settled; the
service constructor wires the adapters.

## 12. Deployment

- **Household:** one IAM binary, one Postgres for es-lite and the read
  models, OpenFGA embedded in-process (`pkg/server` has no gRPC requirement
  at this scale), OpenBao Transit for the tenant KEKs, NATS optional. The
  apps call the IAM library or the local service.
- **Enterprise:** the same code with an OpenFGA cluster, a shared es-lite
  Postgres, OpenBao Transit (clustered), and NATS. Type names are namespaced
  per consumer; the model is a reviewed artifact; the compiler computes the
  delta before applying it.
- **Service identity:** one tenant-scoped service credential per consumer
  per tenant. mTLS/SPIFFE in deployment; a signed bearer token with the
  tenant claim in the household. The tenant is never a request field; the
  deployment-admin operator credential is separate. A CAS consumer also
  gets a tenant-scoped Postgres read role for the join; the API credential
  and the DB role are separate.
- Connect-Go for the service surface, matching the other modules, with the
  research's per-stage latency budget as the target.

## 13. What is deliberately absent

- Conditions, clearance comparisons, `blocked_inheritance` and deny.
- Per-tenant OpenFGA stores and per-tenant models.
- Resource catalog, search, embeddings, payload storage and global ranked
  search — consumer concerns.
- Tool execution, approval state, notifications and action payloads — app
  concerns.
- Link sharing, ownership transfer, expiring access, commenter threads and
  nested groups.
- Re-parenting a subtree, and per-run agent principals.
- Zitadel roles as authorization input.
- Credentials, identity attributes and PII.
- Archival and compaction of the grant log; retention is indefinite in v1.
- Engine-level column hiding. A sensitive field is its own node outside the
  document's subtree, and the row-level join authorizes it (§9.4a); F4 is
  closed by respecification, not by a column predicate.

## 14. Owner decisions (2026-10-27)

1. **Trust boundary — resolved 2026-10-27.** Every call is service-to-service
   from a consumer backend. The tenant comes from a tenant-scoped service
   credential (mTLS/SPIFFE in deployment, signed bearer token in the
   household); the actor comes from the Zitadel or `captoken` actor token;
   the request's tenant is not trusted. No direct user calls in v1. One
   Zitadel user may have a principal per tenant; the service credential
   selects the tenant. The auditor is a tenant-scoped read credential, not a
   Zitadel role. Deployment-admin commands use a separate operator
   credential.
2. **Bootstrap and control-plane authority — resolved 2026-10-27.** A
   deployment admin creates the tenant, its single root, and the first
   owner; the first owner is the tenant admin. Node creators become owners;
   group creators become admins; only human supervisors or tenant admins
   change supervisor sets; the identity adapter alone links or deletes
   principals; a tenant admin may deactivate or reactivate a principal in
   the tenant. The identity adapter fans a global change out to every
   linked tenant and remembers the global state for later links. Recovery
   is deployment-admin-only and audited.
3. **Reversible deactivation — resolved 2026-10-27.** `Deactivated` and
   `Suspended` keep tuples and reactivation restores access; effective live
   is `global_live AND tenant_live`, and for an agent
   `principal_live AND NOT suspended AND a live supervisor path`. `Deleted`
   is terminal and removes the tuples; only the identity adapter issues it.
4. **Stale-allow bound — resolved 2026-10-27.** Five seconds, shared by
   reads and writes, fail closed with `ErrStale`; `WaitForRevision` bypasses
   by waiting. The direct SQL path uses `iam.fresh()` for bounded staleness
   and `iam.fresh($revision)` for read-your-writes; the projector heartbeats
   `applied_at` when idle. The threshold is configurable per deployment; no
   per-tenant override in v1.
5. **Multiple supervisors — resolved 2026-10-27.** An agent may have
   two humans, a group, or an agent→agent→user chain. The graph is a DAG;
   agent-to-agent edges strictly increase maturity; a group's live members
   are human roots. Any live path keeps the agent live; any one live human
   in the approver set may approve by default. Removing the last supervisor
   is refused; losing the last live path makes the agent non-live (orphaned).
   Dependents become non-live only if their only live path ran through it.
   The strict alternative (all paths, all approvers) is not used.
6. **Maturity names — resolved 2026-10-27.** `apprentice → associate →
   senior → autonomous`; `interim` is a status, not a level. The top level
   is renamed from `principal` to avoid the collision with a user/agent
   principal.
7. **Destructive tools — resolved 2026-10-27.** Added `can_delete`, a
   non-inheriting relation. Only an owner may grant it; only senior and
   autonomous agents may receive it. A human owner or a human with
   `can_delete` deletes directly; an agent needs `can_delete`, the
   on-behalf-of user needs `can_delete` or ownership, and HITL is
   additional. `DeleteSubtree` remains owner-only, and `can_delete` never
   implies sharing. A demotion that would leave a `can_delete` grant on an
   associate or apprentice is refused.
8. **Column-level filtered reads (F4) — resolved 2026-10-27 by
   respecification.** The sensitive field is its own node with its own URN
   and grant, placed outside the document's subtree so it does not inherit
   the document's access; the row join authorizes it. If a consumer cannot
   model the field that way, F4 reopens and the permitted-attribute set is
   the fallback.
9. **Retention — resolved 2026-10-27.** Indefinite in v1; the log is
   authorization-sized. Each sealed payload carries a `key_id`; rotation
   keeps old keys, so indefinite retention remains readable.
   Crypto-shredding erases payloads, not the plaintext es-lite metadata.
   Archival/compaction is later; a finite floor would add a snapshot and
   `ErrRetention`. `_platform` is retained indefinitely.
10. **Key custody — resolved 2026-10-27.** IAM owns the `Sealer` port; a
    per-tenant-version DEK encrypts events, OpenBao Transit holds the KEK in
    the household and the enterprise, and a local key file is dev/test only.
    The sealed payload carries its `key_id`; the wrapped DEK lives in
    `tenant_keys`, not the log. IAM never stores the KEK; the service and
    projector cache the DEK. `CreateTenant` provisions the first key;
    `RotateTenantKey` adds a version; `ForgetTenantKey` deletes them and
    fans out an eviction. Deleting the keys crypto-shreds the payloads, not
    the metadata. The `_platform` key is separate and escrowed.

## 15. Testing

- **Schema:** compile the default DSL to a golden OpenFGA model; assert the
  kind rules, the owner-excludes-agent rule, and the one-parent refusal.
- **Aggregates:** node tree, duplicate grants, revoke-only-live, group
  membership, agent DAG and maturity inversion, delegation.
- **Supervision:** two human supervisors, a group supervisor, and an
  agent→agent→user chain; any live path keeps the agent live; losing the
  last live path makes the agent non-live (orphaned), not explicitly
  suspended; a dependent with another live path stays live; removing the
  last supervisor is refused; explicit suspend is a hard false and a resume
  without a live path is refused; principal deactivation or deletion makes
  the agent non-live; the approver set is the union of nearest live humans;
  an agent cannot edit its own or a subordinate's supervisor set.
- **Principal lifecycle:** tenant-admin deactivation denies direct and
  group grants; reactivation restores them; Zitadel global deactivation
  cannot be overridden by tenant reactivation; a link created after a
  global deactivation starts non-live; deletion is identity-adapter-only
  and removes group-admin and supervisor edges; a deleted agent's
  dependents become non-live.
- **Destructive delegation:** owner grants `can_delete` to a senior agent
  and to the on-behalf-of user; the agent's destructive action returns
  `RequireApproval`; after HITL it deletes; an agent whose user lacks
  `can_delete` is denied, not asked to approve; apprentice/associate
  recipients are refused; `DeleteSubtree` is denied for `can_delete`;
  revocation before execution denies; sharing is unaffected.
- **Projection:** idempotent replay, tuple deletion on deletion, live
  filter on deactivation, rebuild from 0, point-in-time shadow store,
  model-version replay. The log is the source; OpenFGA `ReadChanges` is a
  catch-up/verification path only, because it cannot carry deactivation,
  tombstones, model versions or grant provenance.
- **Integration:** es-lite + Postgres + OpenFGA; tenant prefix mismatch;
  RLS on the read models and the consumer table; a tenant-scoped DB role;
  `AuthorizeAction` policy table; approval token binding and replay refusal.
- **CAS join:** point check; broad document-driven page; narrow
  grant-driven page; live-subject, group-membership and tombstone filters;
  subject kind; relation ranks 1–4 and `can_delete` 0; `AccessibleCount`
  choosing the shape. Measured in the 2026-10-27 spike.
- **Sensitive fields:** model the field as a separate node outside the
  document's subtree; the document is visible without it; the field is
  visible only with its own grant, not through the document's viewer/editor;
  the consumer join excludes unauthorized field rows; field deletion is
  explicit; provenance is preserved.
- **Key custody:** seal/open round-trip with `key_id`; the wrapped DEK is in
  `tenant_keys`; rotation leaves old events readable; es-lite stores
  payload ciphertext and plaintext metadata; per-tenant key isolation;
  deleting the tenant keys makes payloads unreadable but leaves metadata; a
  missing key fails closed; `ForgetTenantKey` fans out an eviction; the
  `_platform` key is separate; the local key file is rejected in deployment.
- **Retention/erasure:** point-in-time at any retained position; deleting
  the tenant key makes payloads unreadable while metadata remains; a finite
  floor (if introduced) returns `ErrRetention`; `_platform` is retained.
- **Staleness:** lag above five seconds fails `Check`, `ListObjects`,
  `AccessibleCount`, `AuthorizeAction` and write-path `can_share` with
  `ErrStale`; `WaitForRevision` waits; `iam.fresh()` handles bounded
  staleness and `iam.fresh($revision)` read-your-writes; an idle tenant's
  heartbeat stays fresh; a missing state row is false; the app distinguishes
  stale from empty via `ProjectionStatus`; consumers use secured views under
  a tenant-scoped role, not the base tables.
- **Audit:** reconstruct "who could see X on T, and who granted it" from
  the log alone.
- **Latency:** decision p50/p95/p99 against the research budget; projection
  lag visible and bounded.

## 16. Builder-check calls (2026-10-27)

A fresh builder reviewed the design before handover. These are the calls
made in response, recorded so the owner can check them while reading. The
owner questions remain §14.

| Call | Resolution |
|---|---|
| Where sealing happens | es-lite is keyless and payload-opaque; IAM seals before append through the `Sealer` port. OpenBao Transit holds the per-tenant KEK in household and enterprise; a local key file is dev/test only; IAM never stores the KEK. |
| Tenant root | Exactly one root per tenant, kind `root`, created by `CreateTenant`; every other node descends from it. |
| Model stream placement | The deployment-wide `model:<version>` stream lives in one reserved `_platform` workspace; every other workspace maps to a tenant. |
| Run-token inputs | `GetAgent` returns supervisor, maturity, delegation, liveness and revision; `AuthorizeAction` stays stateless. |
| Audit provenance | `ListSubjects` and `AuditWhoCouldSee` return effective users and agents, with every contributing grant and its grantor. |
| Missing command authority | Group creation, agent registration, group-admin changes and principal lifecycle authority are filled in §11.1; tenant admins may deactivate/reactivate, the identity adapter links/deletes. |
| Auditor representation | A tenant-scoped service credential with an `auditor` scope; not an IAM relation or a Zitadel role. Resolved with the trust boundary. |
| Trust boundary | Service-to-service for every call; tenant from a per-tenant service credential; actor from Zitadel/`captoken`; no direct user calls in v1. |
| Supervisors | Multiple: two humans, a group, or an agent→agent→user chain. Any live path keeps the agent live; any one live human may approve; only a human supervisor or tenant admin changes the set. Removing the last supervisor is refused; losing the last live path makes the agent non-live, and dependents become non-live only if their only path ran through it. |
| Maturity names | `apprentice → associate → senior → autonomous`; `interim` is a status, not a level. |
| Destructive tools | Added `can_delete`, non-inheriting, owner-granted, senior/autonomous agents only; the agent and the on-behalf-of user both need `can_delete`; HITL is additional; `DeleteSubtree` owner-only; no sharing. |
| CAS row-level join | Denormalized ancestors for broad access; grant-driven for narrow access; live-subject and live-node filters mandatory; RLS. Measured in §9.4a and the 2026-10-27 spike. |
| F4 columns | A sensitive field is its own node outside the document's subtree, with its own grant; the row join authorizes it. F4 closes by respecification; the permitted-attribute set is only a fallback. |
| OpenFGA `ReadChanges` | Not the read-model source. The feed cannot carry deactivation, tombstones, model versions, grant provenance or root bootstrap; the log-driven projector remains. Measured in §9.2 and the 2026-10-27 spike. |
| Stale bound | Five seconds, shared by reads and writes; fail closed; `WaitForRevision` bypasses by waiting; direct SQL uses `iam.fresh()` for bounded staleness and `iam.fresh($revision)` for read-your-writes; idle heartbeat; secured views; `ProjectionStatus` distinguishes stale from empty. |
| Retention | Indefinite in v1; the log is authorization-sized. Crypto-shredding erases payloads, not metadata; archival/compaction is later; `_platform` is retained indefinitely. |

### 16.1 Final consistency pass (2026-10-27)

A second pass after the owner decisions found contradictions introduced by
combining them. These are the resolutions; the sections above are updated,
and this table is the record.

| Issue | Resolution |
|---|---|
| Last supervisor vs last live path | Removing the last supervisor is refused as a structural invariant; losing the last live path through deactivation, group loss or an upstream suspension makes the agent non-live (orphaned). Dependents become non-live only if their only path ran through it. §6.4, §7.1. |
| Agent liveness propagation | Effective live is `principal_live AND NOT suspended AND any live path`; the projector recomputes the affected agent and its DAG descendants in topological order on supervisor, principal, group or suspension changes. `suspended` is a separate explicit flag; resume with no live path is refused. §6.4, §9.2, §10.11. |
| Subject kind collision | Subjects use `<tenant>/<subject-kind>/<id>`; the principal stream is `<subject-kind>_<id>`; `iam_live_subjects` carries `subject_kind`. §4.2, §6.5, §9.4a. |
| Global principal lifecycle | The identity adapter keeps a deployment-wide external-identity index, fans global deactivation/deletion out to every linked tenant, and writes current global state on a later link. §6.5, §11.1. |
| Deletion cleanup | Deletion removes direct grants, group memberships, group-admin tuples, delegations and supervisor edges; dependent agents become non-live; the agent record remains until `AgentDeleted`. §6.5, §9.2. |
| Destructive action class | `can_delete` is required for the agent and the on-behalf-of user; the tool's `required_relation` is additional; the gateway derives `Action` from the tool. §7.3, §8.1–8.2. |
| F4 field placement | A field is its own node outside the document subtree; a descendant would inherit. The row join authorizes the field row; lifecycle is separate. §9.4a, §13, §15. |
| Stale bound and SQL enforcement | Bounded uses `iam.fresh()`; read-your-writes uses `iam.fresh($revision)`; idle heartbeat; consumers select secured views under a tenant-scoped role; base tables are not granted; consumer table RLS. §9.3, §9.4. |
| Key versions and erasure | The sealed payload carries `key_id`; wrapped DEK in `tenant_keys`; `RotateTenantKey`; `ForgetTenantKey` fans out and evicts; `_platform` key separate; metadata remains. §9.1, §11. |
| Read-model schema | `iam_group_members.live`; `iam_agents.principal_live/suspended`; `iam_agent_delegations`; `iam_live_subjects.subject_kind`; `iam_model_cursor`; ranks pinned 1–4, `can_delete` 0. §9.4a. |
| Same-database premise | Added to §2; a consumer in another database uses `ListObjects`. §2, §9.4. |
