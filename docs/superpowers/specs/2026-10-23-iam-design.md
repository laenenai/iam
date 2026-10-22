# Design: `iam` — Identity and Authorization

Date: 2026-10-23
Status: Draft for review
Companion documents:
- `cas/docs/superpowers/specs/2026-10-22-content-addressable-store-design.md` (**CAS §n**)
- `kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md` (**KGS §n**)

## 1. Intent and why

Three systems need the same answer to the same question, and the question is
not "who is this?" but **"may this principal see this, and can that answer be
computed inside a SQL statement over ten million rows?"**

- **CAS** needs it for documents, filesets and slots, with legal-grade
  conflict screens that no firm-wide grant may defeat (CAS §9.3).
- **kgs** needs it for entities, facts and observations, where a wrong answer
  is not an error page but a disclosure, and where the authorization predicate
  must compile into the same statement as a vector search (KGS §9.4, A3).
- **acre** needs it from its first commit; it has no code yet.

Built three times it becomes three divergent authorization engines, and
divergence in authorization is a security defect rather than an
inconsistency. Built once in a catch-all `platform` module it becomes the
dependency nobody can reason about (owner's objection, 2026-10-23). So:
**one module, one job, a stated boundary** — see `CHARTER.md`.

The "why" that should settle the hundred unmentioned decisions: **this module
is the thing that says no.** Every other module can be wrong and produce a
bug. This one being wrong produces a disclosure, in systems holding privileged
legal matters and private household records. When in doubt, choose the option
whose correctness can be *tested* over the one that is merely argued, and the
option that denies.

## 2. Goals

1. **An authorization decision that compiles into a SQL predicate**, joinable
   in the consumer's own query, with no network call and no post-filtering
   (§9).
2. **Three enforcement tiers that compose** rather than compete: discretionary
   relationships, mandatory classifications, and cryptographic custody (§7).
3. **Absolute negatives that cannot be defeated** by any grant, any owner, any
   future schema change, or forgetting to write an exclusion (§7.2).
4. **Google-Drive-shaped sharing**: containers, inheritance, groups, roles,
   link sharing — expressed once, inherited down, navigable up (§8.2).
5. **Teams and roles without multiplication**: a role is an object, not a
   cross product (§8.2).
6. **Registerable resource kinds**, so CAS, kgs and acre each declare their own
   containment path into one evaluator (§8.4).
7. **Identity that is joinable**: principals and group membership as rows, from
   Zitadel over OIDC with JIT provisioning (§8.1).
8. **Bounded, fail-closed staleness** for grants; immediate propagation for
   denials and revocations (§9.3).
9. **A projection that is audited, not trusted** (§9.4).
10. **Two deployment shapes from one codebase**: embedded in a Go binary, and
    a service — identical semantics (§11).
11. **No required external service** (§4/A1).

## 3. Non-goals

- **Not an identity provider.** No passwords, MFA, user lifecycle, consent
  screens or session management. Zitadel does that; this module mirrors and
  authorizes.
- **Not a token library.** Minting, attenuation, caveats and revocation chains
  are `captoken`. This module answers "may this principal?"; `captoken`
  answers "is this credential valid and what does it permit?"
- **Not a key manager.** `keyring` wraps DEKs; `escrow` holds shares. This
  module records that a classification is *crypto-enforced*; it never touches
  key material.
- **Not a policy-as-code engine.** No Rego, no Cedar, no general-purpose
  expression language in v1. A deliberately restricted relationship schema plus
  classifications (§8.5 explains the restriction as a feature).
- **Not a reasoner or an inference engine.**
- **Not an admin UI.** Headless: a Go library and an API.
- **No cross-tenant anything.** The registry is global; every rule is
  tenant-scoped; no decision reads another tenant's rules.

## 4. Anti-goals

### A1 — Requires infrastructure to run

Inherited verbatim from CAS A1 and KGS A1, and the owner's objection that
"the problem with ReBAC is the complexity it brings from an infra/tenant
perspective." If adding authorization to a single Go binary requires anything
beyond a Postgres connection string and one constructor call, it has failed.

- **No required separate authorization service, container or sidecar.** The
  engine runs in-process.
- **One Postgres instance**, with this module's tables in their own schema.
- No cgo. Migrations embedded. Workers in-process as goroutines.
- A deployment with no IdP configured still works for service principals.

### A2 — The decision is too slow to be used where it matters

Budgets at: 2,000 principals, 200 overlapping groups, 10,000 grants, 500
classifications, a containment hierarchy of depth 6, and a consumer table of
**10,000,000 rows** (KGS A2's fact count).

- A single decision against a warm projection: **p95 < 5 ms**.
- The projection join added as a predicate to a consumer's existing query over
  10,000,000 rows: **adds < 20 ms at p95**, and the plan must show an index
  join, never a sequential scan or a materialization of the rule set.
- Grant propagation to every projection: **p95 < 2 s**.
- Denial, revocation and deprovisioning propagation: **p95 < 500 ms** — and
  correctness must not depend on that number (§9.3's epoch check is
  synchronous, so a slow propagation denies rather than permits).
- Closure maintenance on a group-membership change must be proportional to the
  group's membership, **not to the number of resources reachable from it.**
  Sharing a container of 100,000 objects with a 50-member team must write
  **O(50)** projection rows, not O(5,000,000). This is the budget that forces
  §9.2's two-closure design and it is the one most likely to be violated by a
  well-meaning implementation.
- No decision may degrade with the number of tenants or consumers in the
  deployment.

**Reference fixture** (Claude's call): a seeded generator producing the above,
plus the three consumer schemas (CAS's `tenant > fileset > document > slot`,
kgs's `tenant > graph > entity-set | episode > fact`, and a synthetic
workspace/team shape), with grants and classifications placed at every level,
overlapping and disjoint group membership, and the KGS §1 household scenario
and a legal conflict screen encoded as named cases.

### A3 — A mandatory control that can be defeated

The anti-goal this module exists for, stated as a testable invariant:

> No sequence of discretionary operations — grants, shares, role assignments,
> ownership transfers, schema changes, or link creation — performed by any
> principal, can cause a classification gate to pass for a principal that does
> not satisfy it.

Enforced by a **mandatory-control adversarial suite**: for each classification
in the fixture, enumerate every discretionary operation available to every
principal (including owners and project admins), apply them in combination up
to a bounded depth, and assert the gate never opens. Fails the build on any
breach.

Two corollaries, each its own test:

- **A classification cannot be removed by the act of deriving.** A derived
  object carries the union of its inputs' classifications (§8.3). A pipeline
  that reads classified inputs and writes an unclassified output is the failure
  Foundry tolerates at its read boundary (KGS §8.7) and this module must not.
- **An absolute may never be expressed as a relationship.** A "blocked" or
  "denied" relation in a consumer's schema is a design error, because
  exclusion in a relationship model is *local to the permission where it is
  written* (§5a) — one forgotten exclusion is a silent bypass. CI lints
  registered schemas and **rejects any exclusion operator**, naming the
  classification mechanism in the error.

### A4 — A projection that silently diverges

A denormalized copy of security decisions is a dangerous object. If divergence
between the authority and any projection can exist without anything failing,
this module has failed regardless of its performance. §9.4's differential
authorization audit is the control, and zero divergence is the threshold — it
is an alert and a test failure, never a metric on a dashboard.

## 5. Decided constraints and technology

Decided by Pascal:

- **Language: Go.** Library first; the service is a thin adapter.
- **Postgres**, same instance as the consumer, own schema.
- **Do not build a ReBAC engine.** "I don't want to build SpiceDB myself."
- **Flatten the engine into the database as a projection** for fast filtered
  reads (owner's proposal, 2026-10-23).
- **Zitadel over OIDC with JIT provisioning** (CAS §9.1a).
- **The hard requirement is the negatives**: "whatever rule ever happens my
  will document should always stay private except if I die and the lawyer gives
  the access key" — the requirement that established the third tier (§7.3).
- **Roles, teams, workspace membership and Drive-style sharing** are required,
  without exponential complexity.
- **Fine-grained single-purpose modules**, never a `platform` catch-all.

Decided by Claude in this document (flagged, open to reversal):

- **Two decision tiers plus one orthogonal enforcement tier** (§7), rather than
  one unified policy lattice.
- **Absolute negatives are classifications, not relationships** (§7.2, §8.3),
  because exclusion is local and unflattenable.
- **The registered schema is deliberately restricted** to union, group
  usersets and tuple-to-userset inheritance — the subset that flattens (§8.5).
- **Bare and effective relations**, adopting Lakekeeper's v4.12 fix (§8.2).
- **Bottom-up navigational visibility** as an explicit relation rather than an
  implicit derivation (§8.2).
- **Two small closures, never the subject × resource cross product** (§9.2).
- **Asymmetric staleness with a synchronous deny epoch** (§9.3).
- **Engine selection deferred to the §10 spike**, with the module's own API
  stable across either choice.

### 5a. Prior art, and what is taken from each

Surveyed 2026-10-23. Recorded because the design's shape is almost entirely
borrowed, deliberately.

| System | Taken | Rejected / absent |
|---|---|---|
| **Zanzibar** | Relation tuples as the data model; userset rewrites; tuple-to-userset for hierarchy at **one tuple per hop**; the Leopard index as proof that *set expansion* is the part worth materializing. Google Drive is its flagship application, which is the owner's stated sharing requirement. | Its exclusion operator (see below). Its scale assumptions and its service-shaped deployment. |
| **SpiceDB / AuthZed** | The authority-plus-projection pattern, productized as **Materialize** — consumes the Watch change stream, computes permission deltas, maintains a local denormalized view so "ACL-aware filtering becomes a simple JOIN". Independent confirmation of §9. Its escalation ladder: Check → BulkCheck → projection → Materialize. | Materialize is commercial, not open-source SpiceDB. And `pkg/embedded` is **`CheckPermission` only** — no writes, no lookup, no watch (§10), which rules it out as an embedded authority. |
| **OpenFGA** | Apache-2.0, written in Go, so it embeds natively in a Go process. `ReadChanges` as a pollable changelog, which is a better projection source than a long-lived stream because it is resumable. The configuration language's `[user, team#member]` usersets and `X from Y` inheritance. | Its `but not` operator, for the reason below. |
| **Lakekeeper** | The most instructive comparable — a production Iceberg catalog doing ReBAC over a hierarchy. **Roles as first-class objects** parented to a container with `assignee`/`ownership` relations, which is the teams-and-roles answer with no cross product. **Bi-directional inheritance**: top-down grants, plus bottom-up *navigational* visibility so a principal granted access to one deep object gets limited list rights on its ancestors and **only on the direct path**. And the **v4.12 bare/effective split** (§8.2), with numbers. | **It has no deny at all** — "permissions are additive", with `Managed Access` restricting who may grant rather than denying access. The one mature open-source implementation declined to attempt the owner's hardest requirement, which is the strongest available evidence that absolutes do not belong in the relationship layer. |
| **Palantir Foundry** | The mandatory/discretionary split itself. Mandatory controls (markings, CBAC) **propagate through derivation** and cannot be granted away; discretionary row/column policies apply at the read layer. Marking allowlists governing what a language model may see. | Its read boundary: discretionary controls stop propagating once data is read, and "the rows that the user did receive are ordinary data… carry no metadata, classification, or tag that subsequent code can use to re-apply the policy." kgs cannot accept that (KGS §8.7), so §8.3 propagates through derivation unconditionally. |

**On exclusion operators, since three of these systems have one.** In OpenFGA
(`but not`) and SpiceDB (`-`), exclusion is **local to the single relation
definition in which it is written**. To make "this principal may never see
this" absolute, the exclusion must appear in every permission on every resource
type, and be remembered for every type added later — N permissions × M
exclusion dimensions, growing with the schema, where one omission is a silent
bypass rather than an error. Exclusion is also the one operator that cannot be
flattened into a precomputed closure, so using it forfeits §9's projection and
with it the A2 budget. Both reasons point the same way: **absolutes are
classifications** (§7.2).

## 6. Architecture

```
   consuming app (CAS / kgs / acre)
        |                      |
        |  iam.Decide(...)     |  predicate SQL fragment
        |  (single decision)   |  (filtered reads, traversal)
        v                      v
   +--------------------------------------------------+
   |                      core                        |
   |  decision procedure, schema registry, class-     |
   |  ification evaluation, predicate compiler,       |
   |  projection maintenance, differential audit      |
   +--------------------------------------------------+
     |            |             |            |
   engine      identity     projection    audit
   port         port           port        port
     |            |             |            |
  ReBAC        Zitadel      Postgres      audit
  engine       OIDC/JIT     (per pool)    module
  (in-process) + registry
     |
  Postgres (own schema, same instance)
```

- **Ports**: `Engine`, `IdentityProvider`, `ProjectionStore`, `AuditSink`,
  `Clock`, `Tenancy` (from the `tenancy` module), `EventSink`.
- **Two consumer-facing surfaces, and the second is the point.** `Decide` for a
  single decision; **`Predicate`** returns a composable SQL fragment plus its
  bound parameters, to be embedded in the consumer's own statement. A consumer
  that can only call `Decide` will post-filter, which is KGS leak channel #6.
- **Core performs no I/O** and the decision procedure is unit-testable with
  in-memory adapters, because that component is what A3 is about.
- **`iamd`** is the service shape; the embedded path is `iam.Open(ctx, Config)`
  returning the same interface. Conformance tests run against both.

## 7. The three enforcement tiers

The spine of the design. They are not three ways of writing rules; they are
three different things that enforce, with different survival properties.

| Tier | Mechanism | Survives | Costs |
|---|---|---|---|
| **1. Discretionary** | Relation tuples, usersets, inheritance | nothing in particular — it is the everyday, shareable, revocable layer | nothing |
| **2. Mandatory** | Classifications on resources, clearances on principals | any grant, any owner, any project admin, any future discretionary rule, and any forgotten exclusion | some query surface; must propagate through every derivation |
| **3. Cryptographic** | A key the system does not hold (`keyring` + `escrow`) | the administrator, the operator, a subpoena, a stolen backup, and every future policy change | **everything** — no extraction, indexing, embedding or summarisation; unrecoverable if the key is lost |

### 7.1 The decision procedure

```
Decide(principal, action, resource, at) =
      mandatory_gate(principal, resource)        // tier 2, live, never projected
  AND discretionary_allows(principal, action, resource)   // tier 1, projected
```

Both must pass. Neither can override the other. **Deny-wins is therefore
structural** — it is a property of the conjunction, not a rule anyone has to
remember to write. CAS §9.3's "any applicable denial wins, at any level,
regardless of specificity" is this conjunction, with denials promoted from
rules to classifications.

Evaluation order is mandatory-first, because it is cheap, and because a
principal who fails the gate must not have the discretionary layer consulted
at all — the attempt is auditable without being informative.

### 7.2 Why absolutes are tier 2 and not tier 1

Three independent reasons, each sufficient:

1. **Locality.** Exclusion in a relationship model applies only to the
   permission it is written in (§5a). Absolutes written there are absolute only
   where someone remembered them.
2. **Unflattenability.** Union, usersets and inheritance precompute into a
   closure; arbitrary exclusion does not. Tier 1 is restricted precisely so
   that §9's projection is possible, and that restriction is what buys the A2
   budget.
3. **Evidence.** Lakekeeper, the one production open-source ReBAC-over-a-
   hierarchy implementation, has no deny mechanism at all (§5a). The absence is
   not an oversight; it is what the model is bad at.

### 7.3 Why tier 3 exists at all

From the owner's requirement: *"whatever rule ever happens my will document
should always stay private except if I die and the lawyer gives the access
key."*

Tiers 1 and 2 are enforced by policy, which means they are enforced by whoever
administers policy. No access-control system can promise that no future rule
will grant access, because rules are mutable and administrators exist. The only
mechanism that survives "whatever rule ever happens" is one where the system
**cannot decrypt**.

So tier 3 is **not part of the decision**. `Decide` may well return allow for a
crypto-enforced resource; the caller still cannot read it without a key the
deployment does not hold. This module's entire responsibility for tier 3 is one
field: a classification carries an **enforcement class** of `policy` or
`crypto`. `keyring` holds the wrapping; `escrow` holds the shares, the
custodians, the ceremony and the dead-man's switch. Recording the class here is
what lets a consumer tell a user *why* something is unreadable, and lets the
API refuse processing operations on crypto-enforced content with a typed error
rather than failing obscurely later.

## 8. Data model

### 8.1 Identity

- **Principals** — users, services, and agent runs — are rows carrying a stable
  internal id. Grants, classifications, audit chains and metering attribution
  reference that id, never an external subject string, so re-issuing an
  external identity never rewrites history (CAS §9.1).
- **Groups** and membership are rows, **joinable inside the predicate**. This
  is the whole reason identity lives here rather than being read from token
  claims: §9's predicate must join membership in SQL, and claims cannot be
  joined.
- **External subjects** map to internal principals by `(issuer, subject)`,
  recorded at first sight. Per-tenant OIDC issuers with JWKS discovery and
  cached key sets; the accepted issuer set is tenant policy, and a token from an
  unregistered issuer is rejected before any lookup.
- **Provisioning is a port.** JIT from token claims is the default and the only
  v1 implementation; SCIM push and directory pull are later adapters.
  Claim-derived groups are **upserted into the registry on sight**, never passed
  through, which is what keeps them joinable. A claim set that shrinks removes
  memberships.
- **Staleness bound.** Each principal carries `synced_at`; the deployment
  declares a bound; a token whose principal is staler than the bound forces a
  re-sync before the request proceeds.
- **Agent-run principals** are ephemeral rows created by delegation from a user
  or service principal, with their own id so audit and metering attribute per
  run, garbage-collected on a policy TTL. An agent run is a first-class
  principal, not a flag on its parent — KGS §9.5 depends on this.
- **Deprovisioning denies immediately**, regardless of token validity, via the
  deny epoch (§9.3).

### 8.2 Tier 1: the discretionary layer

**Relation tuples**, `object#relation@subject`, where a subject is a principal
or a userset (`team:eng#member`). Stored as rows in this module's schema.

**Four composition forms, and only four** (§8.5):

1. **Direct** — `document:x#viewer@user:anne`.
2. **Userset** — `document:x#viewer@team:eng#member`, giving every member of
   the team the relation. Groups and teams need no special mechanism.
3. **Tuple-to-userset inheritance** — `viewer from parent`, so a grant on a
   container reaches every descendant at **one tuple per hop** rather than one
   per object. Sharing a folder shares its contents; this is the Drive
   behaviour.
4. **Union** of the above.

**Roles are objects, not a cross product.** A role is an object parented to a
container, with `assignee` and `ownership` relations (Lakekeeper's model).
Permissions are defined over relations, so adding a resource type never
multiplies roles, and adding a role never touches resource definitions. A role
may hold container-level or deployment-level privileges, which is how admin
delegation happens without a special case in code.

**Bare and effective relations.** Adopted from Lakekeeper's v4.12 model change,
which is worth recording with its numbers because it is the empirical form of
this design's central worry. In their previous model each descendant
re-resolved authorization upward to its parent; a single warehouse check over
**68 namespaces and 353 tables** cost **59,378 dispatches and 291,124 datastore
queries**, exceeding the engine's timeout. The fix: store two relations per
grant — a **bare** relation holding only what was granted directly on that
object, and an **`_effective`** twin adding what is inherited from parents.
Decisions read `_effective`; nothing re-queries parents. Result: **450
dispatches and 3,724 queries, ~76× fewer**, with no tuples rewritten because
grants were already stored under the bare relations.

Two things follow for this module. The split is adopted because it makes the
authority's own evaluation tractable *and* because `_effective` is precisely
what a closure materializes. And the ceiling it reveals is instructive: 353
objects was enough to break the unfixed model, and the fixed model is tuned for
thousands. A2 budgets **ten million**. So the bare/effective split is necessary
and nowhere near sufficient — §9's projection is structural, not an
optimization.

**Bottom-up navigational visibility.** A principal granted a relation on a deep
object gets limited *list* rights on that object's ancestors, **and only on the
direct path** — Lakekeeper's bi-directional inheritance, made an explicit
`visible_below`-style relation that reads bare relations and recurses downward
rather than being derived at read time.

This matters more here than in a catalog, because it is how a consumer answers
"find the thing you may see" without revealing its siblings. KGS §7.3 derives
entity existence from authorized assertions, which is correct but implicit;
this makes it a relation that can be tested directly, and it is folded back
into KGS §7.3 as a result.

**Link sharing** is a tuple whose subject is a capability token's bearer
identity, minted and constrained by `captoken`. This module stores the
relationship; it does not interpret caveats.

### 8.3 Tier 2: the mandatory layer

**Classifications** are labels on resources; **clearances** are the
classifications a principal satisfies. Both are rows. The gate is set
containment: every classification on the resource must be satisfied by the
principal.

Properties, each non-negotiable and each a test in §13:

- **Mandatory.** A classification cannot be granted away, delegated,
  transferred with ownership, or satisfied by any tier-1 relation. There is no
  API that grants a clearance as a side effect of sharing.
- **Propagates through derivation, with no read boundary.** A derived object
  carries the **union** of its inputs' classifications. This is where the design
  departs from Foundry (§5a), and it departs because kgs's consolidator reads
  filtered facts and writes derived beliefs back into the same store; without
  unconditional propagation a belief derived from privileged evidence lands
  unclassified. Consumers declare derivations; the module computes the union.
- **Checked live, never projected.** Classifications are small and change
  rarely, so the gate is evaluated against authoritative rows rather than a
  materialized copy. This is deliberate: it means an absolute is **never
  stale**, which is the property that makes a conflict screen trustworthy, and
  it is why §9.3's bounded staleness applies only to grants.
- **Carries an enforcement class** of `policy` or `crypto` (§7.3).
- **Scoped**: a classification may be declared over a whole resource, or over a
  named attribute or field of it, which is how property-level and cell-level
  security compose without a second mechanism (CAS §9.3, KGS §9.2).
- **Creating and assigning classifications is itself permissioned and
  audited**, and is not a power that ownership confers.

**Who may hold a clearance — and why tier-1 groups may never.** Clearance may
be held by a principal or by a **clearance group**, and a clearance group is a
*mandatory* object: its membership is changed only through the classify
permission or an authoritative directory sync, it is audited, and **it can
never be referenced in a tier-1 tuple**. An ordinary team or workspace group
may not hold a clearance.

This distinction is not fussiness, it is A3. If a clearance could attach to a
tier-1 group, then anyone able to add a member to that group could open a
mandatory gate through a discretionary operation, and the invariant is breached
by construction rather than by a bug. It is also how real mandatory access
control has always worked: clearances and compartments are administered by a
security function, not by data owners — Palantir's marking membership is
administered separately from dataset ownership for the same reason.

And it is what makes administration tractable. "Everyone except Bob" is a
clearance group that does not contain Bob, maintained through the mandatory
channel, rather than 1,999 individual grants. A directory-synced clearance
group (`all-timekeepers`) keeps a firm workable, because employment is an
authoritative fact rather than a discretionary share.

**A newly provisioned principal holds no clearances.** JIT provisioning grants
identity, never clearance. This is fail-closed and it means a new joiner sees
nothing classified until a mandatory act includes them — directly or through a
synced clearance group.

**Classifications inherit through containment as well as derivation.**
Derivation propagation (above) is what kgs needs; CAS needs the other
direction — "mark this fileset `privileged`" must cover the documents inside
it, and a document is *contained* by a fileset, not derived from it. So the
gate resolves a resource's classification set over its ancestry closure (§9.2)
as well as its derivation inputs. Consequence, stated because it costs
something: the gate is a closure join rather than a single-table anti-join, and
it is subject to the §9.3 staleness rule like everything else.

### 8.4 Resource kinds, registered

Each consumer registers a **schema**: its object types, its relations, its
containment edges, and the actions that map onto relations. CAS registers
`tenant > fileset > document > slot`; kgs registers
`tenant > graph > [compartment] > entity-set | episode > fact`; acre registers
its own. No consumer's types appear in this module's code.

Schemas are **versioned and migrated explicitly**. A schema change that could
widen access requires a review step and is audited; the module computes and
reports the access delta between two schema versions before applying one, which
is the only honest way to approve such a change.

### 8.5 The restriction, as a feature

Tier 1 permits union, usersets and tuple-to-userset inheritance. It does **not**
permit arbitrary nested intersection, exclusion, or conditional expressions over
attributes.

This is the central trade of the design and it is deliberate on three counts:
the permitted subset is exactly what flattens into §9's closures; the excluded
operators are the ones whose absence pushes absolutes into tier 2 where they
belong; and a restricted language is one a consumer can be *lint-checked*
against, which is how A3's "no exclusion operator" guard is possible at all.

Where a real requirement cannot be expressed in the subset, the answer is a
classification, not a richer language. If a requirement arrives that is neither
— that is a design conversation, not a configuration change.

## 9. The projection

### 9.1 Why a projection at all

Because the consumers do not ask "may this principal see resource X?" — they
ask "return the fifty of ten million facts this principal may see, ranked by
vector similarity, as of last March." Three ways exist to answer that, and only
one meets A2:

- **Check per candidate row.** Fatal at any scale, and in kgs it is
  post-filtering, which is a disclosure channel (KGS §8.5 #6) rather than
  merely slow.
- **Enumerate accessible resources and pass them back as a list.**
  Post-filtering with extra hops. `ListObjects`/`LookupResources` cannot
  enumerate a ten-million-row space, and AuthZed's own guidance says as much.
- **Materialize a joinable predicate into the consumer's database.** Zanzibar
  built Leopard for this; AuthZed productized it as Materialize, which consumes
  the engine's change stream and "maintains a local denormalized view of user
  permissions, allowing you to use simple database JOINs for filtering."

This module takes the third route, with the engine as the authority and the
projection as a derived read model. **Writes go to the authority; reads go to
the projection.** Never the reverse.

### 9.2 Two closures, never the cross product

The failure mode of a naive materialization is the subject × resource cross
product: share a container of 100,000 objects with a 50-member team and write
5,000,000 rows, then do it again on every membership change. A2 forbids this
explicitly.

Instead, materialize the two things that are *expensive to compute* and *cheap
to store*, and leave the rest as a join:

1. **Membership closure** — `principal → every userset it belongs to,
   transitively`. This is the only unbounded set expansion in the permitted
   subset, and it is exactly what Leopard indexes. It changes only when group
   membership changes, and the write is proportional to the group's members.
2. **Ancestry closure** — `resource → every ancestor on its containment path`.
   Bounded by hierarchy depth, changes only when the hierarchy changes, and
   most consumers already maintain it (CAS's fileset nesting, kgs's entity-set
   nesting).

The predicate then compiles to an index join over small tables:

```
   consumer rows
     ⋈ ancestry closure        (resource → ancestors)
     ⋈ grant tuples            (bare+effective relation on any ancestor)
     ⋈ membership closure      (subject ∈ principal's usersets)
   ANTI-⋈ unsatisfied classifications   (tier 2, live)
```

Sharing that 100,000-object container stays **one tuple plus an ancestry
join**. The 50-member team costs 50 membership rows. This is the design's
load-bearing performance claim and A2's closure budget is written to catch its
violation.

### 9.3 Staleness is asymmetric, and reversing it is the whole risk

A stale grant is a disclosure. A stale denial is an outage. They are not
symmetric and must not share a path.

- **Grants may lag**, within a declared staleness bound. **Past the bound the
  projection fails closed** — it denies rather than serving old decisions. A
  projection that cannot confirm its freshness is stale and therefore denies;
  `ErrReadinessBlocked` is the honest answer.
- **Classifications are never projected** (§8.3), so every absolute is
  evaluated live against authoritative rows. This is why the asymmetry is
  tolerable at all: the thing that must never be wrong is never cached.
- **Revocations, denials and deprovisioning ride a deny epoch.** Every
  projection row carries an epoch; every decision checks the current epoch
  synchronously; bumping it invalidates affected rows at once. So revocation
  does not wait for a refresh, and a slow propagation path denies rather than
  permits. The epoch check is the one synchronous dependency in the read path
  and is a single indexed lookup.
- Propagation is fed by the engine's **changelog**, polled and resumable
  (§10), with the cursor stored so a restarted worker resumes rather than
  rebuilds.

**One rule, stated once, replacing two asymmetries that were drifting apart:**

> **The restrictive change propagates on the fast path. The permissive change
> may lag, and lagging fails closed.**

Applied to tier 1 that reads: a grant may lag; a revocation may not. Applied to
tier 2 it reads the other way round, and an earlier draft got this wrong by
claiming classifications are "never projected": *adding* a classification is
restrictive and must propagate fast, because a missed addition is a disclosure;
*removing* one is permissive and may lag, because a missed removal is only an
outage. Both tiers are projected — §9.5's pools can be separate databases and a
SQL predicate cannot join another database — and both obey the one rule above.
What makes an absolute trustworthy is therefore not that it is unprojected but
that its *restrictive* direction is synchronous and its projection fails closed.

**A verified hazard in the changelog, which the fast path must not trust.**
OpenFGA stamps each changelog entry's ULID from the application clock at write
time, `ReadChanges` orders by `ulid asc` and resumes with `ulid > cursor`, and
the only protection is a horizon guard `inserted_at < NOW() - horizon_offset`
whose **default is zero**, with the operator knob denominated in whole minutes.
At offset zero, a transaction that stamps a ULID at T but commits after the
poller has passed T is **skipped permanently**. A dropped insert is a missed
grant — benign. A dropped delete is a **missed revocation — a silent
disclosure, in precisely the path this section claims is safe.**

So: the horizon offset must exceed the longest write transaction plus
application-to-database clock skew, and that offset is a **hard floor on
propagation latency** — which falsifies A2's "grant propagation p95 < 2 s" and
"revocation p95 < 500 ms" as written if the changelog is the only channel.
Therefore it is not: **revocations, denials, deprovisioning and classification
assignments are written to this module's own tables in the same statement as
the authority call, and the deny epoch is bumped from there**, with the
changelog used only to converge the permissive direction. The changelog is a
convergence mechanism, never the carrier of a restrictive change. §13 gains a
test that injects a late-committing write and asserts no revocation is lost.

### 9.4 The projection is audited, not trusted

A denormalized copy of security decisions is a dangerous object, so the design
treats it as suspect by construction. A background **differential
authorization audit** continuously samples `(principal, action, resource)`
triples, recomputes each decision *directly from the authority*, and diffs
against what the projection would answer.

**Zero divergence is the threshold.** A divergence is an alert and a test
failure, not a gauge on a dashboard. This is what makes "we denormalized
authorization for performance" a defensible sentence rather than a confession,
and it is the same discipline as KGS A3's differential projection test aimed
one layer down.

The audit also runs in CI against the §4 fixture, exhaustively rather than
sampled, so divergence is caught before deployment.

### 9.5 Placement

One authority per deployment; **one projection per pool** (`tenancy`'s pool —
CAS §14.1). The authority is a control-plane component and no data-plane query
touches it; projections are data-plane and live in the same database and schema
reach as the rows they filter. This is the same control-plane/data-plane
asymmetry `tenancy` documents for connection handling, and it preserves CAS's
rule that cross-pool queries do not exist.

## 10. Engine selection — resolved by spike, 2026-10-23

The spike asked two questions: can the engine run in-process without a
separate service (A1), and does it expose a change stream to project from
(§9.3). Run against `spicedb@v1.57.0` and `openfga@v1.22.0`.

**SpiceDB `pkg/embedded`: ruled out.** Its entire exported surface is
`NewPermissions`, `Check` and `Close`. The package documentation is explicit —
*"You need the full SpiceDB v1 API surface (schema writes, relationship writes,
bulk operations, watch, lookup, reflection, etc.). This package only does
`CheckPermission`."* So it can be neither the authority (no writes, no schema)
nor the projection source (no watch). Using SpiceDB means running a real
server, which costs A1. Noted separately: `spicedb@v1.57.0` requires Go ≥
1.26.9 and silently upgraded the spike's toolchain from 1.25.6, which would
drag CAS's toolchain forward as a side effect of an authorization choice.

**OpenFGA `pkg/server`: selected.** `Server` is an ordinary Go struct whose
methods are the full API — `Check`, `BatchCheck`, `Write`,
`WriteAuthorizationModel`, `Read`, `Expand`, `ListObjects`,
`StreamedListObjects`, `ListUsers`, store CRUD — all callable in-process with
no gRPC server, no sidecar and no network hop. Specifically:

- **`ReadChanges`** is the projection source, and being a *pollable, cursored
  changelog* rather than a long-lived stream it is resumable by construction —
  a restarted projection worker continues from its stored cursor.
- **`postgres.NewWithDB(primaryDB, secondaryDB *pgxpool.Pool, cfg)`** accepts
  an **existing pgx pool**. This is the A1 answer in one function signature:
  the engine shares the pool `tenancy` already manages, so there is no second
  DSN, no second connection pool, and schema placement is controlled by the
  pool's `search_path`. The owner's objection — "the complexity it brings from
  an infra/tenant perspective" — is answered here rather than argued away.
- **`ListUsers`** gives the membership expansion §9.2's first closure needs.
- Apache-2.0, pure Go, no cgo, and it did not force a toolchain change.
- **Lakekeeper is the production reference** for exactly this hierarchy pattern
  (§5a), including the bare/effective fix this design adopts.
- Bonus, and relevant to the standing preference for industry standards:
  v1.22 ships **AuthZEN** endpoints (`Evaluation`, `Evaluations`,
  `ResourceSearch`, `SubjectSearch`, `ActionSearch`), so this module's external
  API can speak a standard rather than a bespoke shape.

**Resolved, and the answer is no.** An earlier draft flagged
`sqlcommon.NewTxConnector(tx *sql.Tx)` as a possible route to enlisting a rule
write in a caller's transaction. Verified against the source: it is a
`database/sql` connector, while the Postgres datastore reaches the database
through its own private pgx connector, and `Datastore.Write` opens its own
transaction with no exported way to supply one. **A grant and a consumer's
write cannot commit atomically, in any deployment shape.**

Two consequences, both load-bearing. KGS §6.2 promised that the single-binary
shape would maintain the projection in the same transaction as the rule change;
that promise is withdrawn there and must not be reintroduced. And there is
always a window between a classification being assigned and a derived row
existing, which §8.3 must close by ordering rather than by atomicity: a
consumer declares the derivation and receives its classification set **before**
writing the derived row, and a row whose classification set cannot be resolved
is not written.

**The engine stays behind the `Engine` port.** Nothing OpenFGA-specific reaches
this module's public API, so a reversal is an adapter plus tests.

## 11. Deployment shapes

- **Embedded** (default, and what A1 is about): `iam.Open(ctx, Config)` with a
  Postgres DSN or an existing pool. OpenFGA runs in-process on the same pool;
  the projection worker is a goroutine. Nothing else to deploy.
- **Service**: `iamd` serves the module's API (gRPC with a REST/JSON gateway,
  mirroring CAS and kgs) and runs the projection workers. Projections still
  live in each pool's database, so the service is control-plane only.

Identical semantics, conformance-tested against both. A household deployment
runs CAS + kgs + iam + OpenFGA in one binary against one Postgres.

## 12. Consumers

Each registers a schema (§8.4) and gets two things: `Decide` for single
decisions and `Predicate` for filtered reads.

- **CAS** — `tenant > fileset > document > slot`. Its grants become tuples
  unchanged; its **denials become classifications** (CAS §9.3's deny-wins is
  §7.1's conjunction); its permission enum becomes relations. Conflict screens
  are classifications with `policy` enforcement; vault-mode content is
  `crypto`.
- **kgs** — `tenant > graph > [compartment] > entity-set | episode > fact`. Its
  markings are classifications. Its per-fact escape-hatch rules are tuples on
  fact objects. Its §9.4 predicate is this module's `Predicate`. Its sealed
  episodes are `crypto`-class classifications backed by `escrow`.
  **`visible_below` (§8.2) is folded back into KGS §7.3**, replacing implicit
  derived existence with an explicit, testable relation.
- **acre** — no code yet, so it adopts from birth and is the one consumer that
  costs nothing to onboard. Its event-sourced core is orthogonal: authorization
  decisions are not events, though every decision is an audit record.

## 13. Testing and verification

- **A3's mandatory-control adversarial suite** — the most important suite in
  the repository. For every classification, enumerate every discretionary
  operation available to every principal including owners and admins, apply
  them in combination to a bounded depth, assert the gate never opens.
- **Schema lint**: registered schemas are rejected if they use an exclusion
  operator, with an error naming the classification mechanism (A3).
- **Derivation propagation**: a derived object always carries the union of its
  inputs' classifications; a pipeline cannot launder a classification by
  deriving (A3 corollary, and KGS §8.7's departure from Foundry).
- **The differential authorization audit**, exhaustive in CI over the fixture
  and sampled continuously in production, with zero tolerance (A4).
- **Closure growth tests**: assert O(members) and not O(reachable resources) on
  a membership change, at the A2 fixture's scale. This is the test that catches
  a regression into the cross product.
- **Staleness tests**: past the bound the projection denies; a bumped deny
  epoch takes effect within the budget; a projection that cannot confirm
  freshness denies.
- **Predicate plan tests**: `EXPLAIN` the compiled predicate against the
  10,000,000-row fixture and assert an index join — no sequential scan, no
  materialization of the rule set. A performance budget is not enough here,
  because a plan regression under a different statistics distribution is how
  this fails in production.
- **Conformance across embedded and service**, identical expectations.
- **Decision-procedure unit tests with in-memory adapters**, no database.

## 14. Phasing

Ordered by what cannot be retrofitted.

**Phase 1 — the decision and the predicate.** Schema registry, identity
registry with joinable membership, tier-1 tuples through the OpenFGA adapter,
tier-2 classifications evaluated live, the decision procedure, and the
`Predicate` compiler against a hand-built closure. The A3 adversarial suite and
the §4 fixture. Verify the `NewTxConnector` question. **Deliverable: the KGS §1
household scenario and a legal conflict screen both decided correctly, with
`EXPLAIN` showing an index join.**

**Phase 2 — the projection.** Closure maintenance from `ReadChanges`, the
cursor, the deny epoch, the staleness contract, the differential audit, and the
A2 benchmark suite. Phase 1's hand-built closure is replaced; its tests are
not.

**Phase 3 — identity completion.** Zitadel adapter, OIDC discovery and JWKS
caching, JIT provisioning, claim-derived group upsert, staleness bound,
agent-run delegation, deprovisioning through the deny epoch.

**Phase 4 — consumer onboarding.** CAS's schema and the migration of its grants
to tuples and denials to classifications; kgs's schema; acre's schema. Each
lands with that consumer's conformance run.

**Phase 5 — surface and operations.** `iamd`, the AuthZEN-shaped external API,
schema-version access-delta reporting, the review step for widening changes,
audit integration, metering.

`escrow` integration is not a phase here: this module only records the
enforcement class, and `escrow` ships on its own timeline.

## 15. Open decisions left to the builder

- **Closure storage shape**: one table per closure, a single wide table, or
  materialized views. Decided by the A2 predicate-plan tests.
- **Whether the deny epoch is global, per tenant, or per principal.** Global is
  simplest and invalidates most aggressively; per principal is the finest and
  the most bookkeeping. The A2 revocation budget decides.
- Projection update strategy: incremental deltas from `ReadChanges` versus
  periodic full recompute per affected subtree, and the crossover point.
- Differential audit sampling rate and selection strategy in production.
- Whether `Predicate` returns a SQL fragment, a CTE, or a joinable view, and
  how it is parameterized safely across the three consumers' query builders.
- Caching of decisions in-process, and its invalidation against the deny epoch.
- Concrete relation naming conventions, and whether `_effective` relations are
  generated from a declaration or written out in each registered schema.
- Go module layout and whether the AuthZEN surface is a subpackage.

## 16. Outstanding questions for the owner

1. **Does a classification ever need to be scoped to a principal rather than a
   clearance?** §8.3 models absolutes as labels: "this carries `personal:pascal`
   and she holds no such clearance." That covers both stated cases — the
   household invoice and the legal conflict screen — and it propagates through
   derivation, which a named `(principal, resource)` block would not. If a real
   requirement needs a named pair, the mandatory layer gains a second rule
   shape and the A3 suite doubles. The design assumes **no**.
2. **Who may create and assign classifications?** They cannot be granted away
   (§8.3), which means the power to classify is strictly more dangerous than
   the power to grant. Candidates: a deployment-level security admin only; a
   per-tenant security admin; or the resource owner at creation time with
   changes restricted afterwards. The household case wants the third; the legal
   case wants the second. This decides whether the permission is one role or
   three.
3. **Is a schema change that widens access allowed to take effect without a
   human approving the computed delta?** §8.4 reports the access delta between
   schema versions. Making approval mandatory is safer and makes automated
   deployment of a consumer's schema change impossible without a human in the
   loop. Making it advisory keeps CI green and relies on review discipline.

4. **What must exist by CAS's ~2026-11-05 alpha?** §14 has five phases and no
   dates. CAS has a dated commitment, KGS §6.1 puts its plan rewrite on that
   critical path, and KGS §21 puts this module's *full* projection protocol —
   deny epoch, fail-closed staleness, differential audit — in its phase 0. That
   is roughly two weeks for work phased across five stages. So: may CAS ship
   its alpha on phase 1's hand-built closure, with no projection worker, no
   deny epoch and no differential audit — accepting that the A2 and A4 controls
   do not yet exist — or is the alpha gated on phase 2? And is kgs's phase-0
   dependency the full protocol, or only its semantics and schema? Nothing can
   be sequenced without this.

5. **How much divergence tolerance is acceptable in production?** A4 makes zero
   divergence a build failure. But the projection is *designed* to lag within a
   bound, so during that window authority and projection legitimately differ.
   Distinguishing lag from divergence needs a point-in-time read of the
   authority at the projection's cursor — and OpenFGA has no read-at-revision:
   it offers a `ConsistencyPreference` and nothing resembling a ZedToken, and
   `ReadChanges`' continuation token is a changelog ULID, not a consistency
   token `Check` accepts. So the audit can be exhaustive and zero-tolerance in
   CI against a quiesced fixture, but in production it must either quiesce
   writes (unacceptable) or tolerate a window. Since A4 is what makes the whole
   projection defensible, which weakening is acceptable is the owner's call,
   not the builder's.

## 17. Builder-check findings register (2026-10-23)

Open items from the builder check, recorded rather than resolved, so none is
lost and each has an owner. Items the check raised that *were* resolved are in
§8.3, §9.3, §10 and §16 above.

| # | Finding | Status |
|---|---|---|
| F1 | **Filtered ANN versus the predicate.** A2 wants an index join; KGS A2 and leak channel #8 want the predicate *inside* the ANN search with recall ≥ 0.90 at 0.1% selectivity. pgvector's workable shape is to pre-restrict the candidate set, which needs the accessible set expressible as an indexable key on consumer rows — which looks like the per-principal materialization A2 forbids. The household graph at 0.1% selectivity is exactly where a correct-looking system returns nothing. | **Blocking. Moves to phase 1** as a proof, not phase 3. `Predicate`'s contract may have to be "a fragment *plus* a key the consumer indexes and partitions by", with a maintenance path owned here. Recall ownership must be assigned to one document. |
| F2 | **Classification assignment cardinality.** A2 budgets "500 classifications"; if that means *assignments*, it is wrong by orders of magnitude — KGS propagates an episode's markings to every derived fact, observation and vector, which is tens of millions of rows. "Small and changes rarely" is then false and the gate is not a small-table join. | **Blocking for the fixture.** A2 must distinguish label *definitions* from *assignments* and the fixture must carry the real shape before any benchmark means anything. |
| F3 | **Containment is a DAG, not a tree.** §9.2's ancestry closure and §8.2's "only on the direct path" both assume one path, but a kgs fact has an episode *and* zero or more nestable, sometimes predicate-defined entity-sets. Many-to-many at fact cardinality, maintained on every write, and "the direct path" is undefined. | **Blocking for §9.2.** Either kgs's entity-sets stop being an authorization container, or the closure and `visible_below` are redefined for multiple paths. |
| F4 | **Attribute-scoped classifications cannot be enforced by a row predicate.** A `WHERE` fragment hides rows, not columns. kgs is fine (facts are rows); CAS is not (document fields are columns). | **Open.** Either `Predicate` returns a permitted-attribute set the *consumer* applies — expanding the A3 trust boundary into consumer code — or this module becomes a query rewriter across three query builders. Two different modules; pick one before phase 1 fixes the API. |
| F5 | **OpenFGA store topology.** One store per tenant (a changelog poller and model write per tenant, pressure on "no decision degrades with tenant count") or one global store with tenant-prefixed ids (one shared model in which all three consumers' types coexist, so any consumer's schema bump rewrites the model all three share). §8.4's per-consumer versioning and access-delta report may not be computable in the second shape. | **Open, decide in phase 1.** |
| F6 | **Which `tenancy` connection the engine gets.** `tenancy`'s data-plane handles carry RLS session context and its control-plane path must not accept caller-supplied predicates; OpenFGA sets no tenant context, runs its own migrations (against the goose decision), and its queries inherit whatever RLS the pool's role carries. If it needs its own role, pool and `search_path`, the one-function-signature A1 argument that selected it is weaker than §10 states. | **Open.** Changes phase-1 wiring and `tenancy`'s public surface. |
| F7 | **Two of kgs §9.3's rule dimensions fall outside §8.5's permitted subset** — ontology scope ("may read `Person` but not `salary`": attribute-conditioned and exclusionary) and predicate-defined entity-sets (authorization as a function of data). §8.5's answer is "use a classification", but a classification is mandatory and non-delegable, so a discretionary "don't show her salary facts" becomes an absolute no owner can lift. | **Open.** Either kgs loses those dimensions or tier 1 gains a form. Do not add a form casually; §8.5's restriction is what buys the projection. |
| F8 | **What is the audit unit on the `Predicate` path?** A filtered read over 10M rows makes no per-row decision and produces no denials — absent rows are not refusals. KGS §8.6 requires denied access to be audited. | **Open.** Likely the compiled predicate plus parameters plus epoch, but §7.1's "auditable without being informative" needs a concrete answer for the surface carrying the traffic. |

Verified by the check and already folded in above: `postgres.NewWithDB` is real
(§10's A1 argument holds); `NewTxConnector` does **not** permit a caller's
transaction (§10, and KGS §6.2 corrected); `DefaultChangelogHorizonOffset = 0`
creates the dropped-revocation hazard (§9.3).
