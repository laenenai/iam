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

- **CAS** needs it for documents, filesets and slots, including legal conflict
  screens (CAS §9.3). CAS asked for a screen "that no firm-wide grant may
  defeat"; what it gets is default-deny — a matter outside the firm-wide
  container that nothing names the screened principal on — plus `escrow` for
  anything that must survive a future administrator. §7.2 explains why that
  is the honest answer rather than a reduced one.
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
   (§9). Since the whole decision is now one term (§7.1), the whole decision
   is one predicate.
2. **Two enforcement tiers that do different jobs** rather than compose:
   discretionary relationships with default-deny, and cryptographic custody
   (§7). There were three. The middle one was a deny mechanism and it is
   gone — see anti-goal A3.
3. **Exactly two honest strengths of "no", and no third that pretends.**
   "She may not see this" is a grant nobody wrote, liftable by anyone who may
   share. "Nobody may ever see this, whatever rule ever happens" is a key the
   deployment does not hold. There is nothing in between, by design (§7.2).
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
  module records that a marking is *crypto-enforced*; it never touches key
  material.
- **Not a policy-as-code engine.** No Rego, no Cedar, no general-purpose
  expression language in v1. A deliberately restricted relationship schema and
  nothing else (§8.5 explains the restriction as a feature). Note that the
  restriction is now load-bearing in a way it was not: §8.5's escape hatch used
  to be "express it as a classification", and there is no classification.
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

Budgets at: 2,000 principals, 200 overlapping groups, 10,000 grants, a
containment hierarchy of depth 6, and a consumer table of **10,000,000 rows**
(KGS A2's fact count).

There used to be a sixth number, "500 classifications", and it is gone with
the tier it budgeted. What happened to it is worth keeping, because it is one
of the two reasons A3 inverted.

- A single decision against a warm projection: **p95 < 5 ms**.
- The projection join added as a predicate to a consumer's existing query over
  10,000,000 rows: **adds < 20 ms at p95**, and the plan must show an index
  join, never a sequential scan or a materialization of the rule set.

  > **Measured 2026-10-23 (F1 spike, F2), and the measurement removed half the
  > budget rather than restating it.** The discretionary closure join meets
  > this comfortably — 0.006 ms per candidate row, index-served. The tier-2
  > classification anti-join did not: at 200,394 assignment rows it turned a
  > 0.46 ms keyset page into **296 ms**, and the gate's cost was a function of
  > *assignment* cardinality, which KGS propagates to every derived fact,
  > observation and vector. An earlier draft split this into two budgets, one
  > per tier. The tier is gone, so there is one budget again and it is the one
  > that was already met. This is the performance half of A3's inversion; the
  > correctness half is in §7.2.
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
workspace/team shape), with grants placed at every level, overlapping and
disjoint group membership, and the KGS §1 household scenario and a legal
conflict screen encoded as named cases. Note that the household scenario now
needs a grant per episode rather than one per graph (see §7.2's cost), so the
fixture's tuple count is a function of its episode count.

### A3 — A deny mechanism

**Inverted on 2026-10-23.** This anti-goal used to read "a mandatory control
that can be defeated", and it was the anti-goal the module existed for. It now
reads the other way round:

> **There is no deny mechanism, at all.** No classification, no clearance, no
> deny tuple, no exclusion operator, and no plan for one. A principal is
> refused by the absence of a grant and by nothing else. An absolute that must
> survive a future administrator is a key the deployment does not hold, which
> is `escrow`, not a policy row.

Enforced by the schema lint, which **rejects any exclusion operator** on a
registered relation and names `escrow` in the error, and by the decision
procedure having one term (§7.1) with no second place for a refusal to come
from. The `examples/` corpus's expectation language has no `Reason` value for a
deny that is not "no grant reaches this principal".

#### Why: a classification is a deny

A deny administered by policy is only as absolute as whoever administers the
policy. The previous design admitted this and tried to contain it —
classification membership moved only through a security function's channel,
audited, with the witness unforgeable in Go — and the corpus then demonstrated
against the real registry that *any* principal could construct that witness,
because "who may classify" was an unanswered design question (the old F9). So
the absolute was administered by whoever could call the registry.

That is the correctness half. The performance half is A2's measurement above.

#### The diagnosis, which is the general lesson

The design anchored on "this principal may never see this" — a rare case — and
made it the template for the common one. Every ordinary privacy preference
arrived as an absolute no owner could lift: the household's invoice got the
same mechanism as a legal ethical wall, and "actually, show her this one" had
no operation behind it. That was the corpus's U2, and it was foreseeable from
the paragraph that recommended the workaround.

Three different things had been collapsed into one rejection of exclusion, and
only two of them deserved it:

- **(a) Attribute-conditioned rules** genuinely cannot precompute into a
  closure. Refusing them is correct and costs §8.5's expressiveness. Open as
  F7 and F4.
- **(b) Relation-scoped exclusion**, OpenFGA's `but not` and SpiceDB's `-`, is
  genuinely local to the permission it is written in. Refusing it is correct
  and the locality argument is sound *for it specifically*.
- **(c) A deny tuple on `(principal, resource)` inheriting through
  containment** was never separately examined. It is not (a) — it precomputes
  — and it is not (b) — it is not relation-scoped. It was refused by
  association.

The resolution was not to add (c) but to remove the need for any of them.

#### The guardrail: a caveat is not a deny, and the distinction is one rule

Caveats are **not being added now.** This records the shape one would have to
take, because the rule is short and getting it wrong brings back everything
just deleted.

A caveat must be writable **only by the grantor** and **only onto the grant it
attaches to**. Then it narrows something you hold, it has no effect without a
grant to attach to, it can never make an ungranted thing denied, and it cannot
punch a hole in someone else's grant. If anyone but the grantor can caveat
your grant, that is a deny in disguise.

Two further constraints, if caveats are ever wanted:

- **A closed enum of kinds, each compiling to one SQL conjunct** over columns
  the closure already carries. Never an expression language: CEL and OpenFGA
  conditions cannot compile to SQL, so adopting either forfeits the in-query
  predicate this module exists to produce.
- **Stateful kinds — use counts, byte budgets — can exist only on `Decide`,
  never on `Predicate`.** A filtered read over ten million rows has no single
  operation to count.

`iam` already has one caveat, unnamed: `live_group_members`' condition that a
membership is only live while its principal is neither deprovisioned nor
expired nor stale. It satisfies the rule above by accident — it narrows,
it attaches to a membership, and nobody but the registry writes it.

#### The corollary that survives

**A marking cannot be removed by the act of deriving.** A derived object
carries the union of its inputs' markings (§8.3). A pipeline that reads sealed
inputs and writes an unsealed output is the failure Foundry tolerates at its
read boundary (KGS §8.7) and this module must not. Note what this is *not* any
more: it is not an access control, because a marking refuses no principal
anything. It is a flow label gating egress, which is the same conclusion kgs
reached independently.

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

Decided by Pascal on 2026-10-23, after the first draft of this document:

- **There is no deny mechanism** (A3, §7.2). The mandatory tier is removed in
  full. Two tiers remain: discretionary grants with default-deny, and
  cryptographic custody.
- **OpenFGA is dropped; `iam` owns its tuples and closures in Postgres** (§10).
  `Predicate` must return a SQL fragment the consumer joins inside its own
  query, so the authority the predicate reads has to be tables we own.

Decided by Claude in this document (flagged, open to reversal):

- **One decision tier plus one orthogonal enforcement tier** (§7), rather than
  one unified policy lattice.
- **The registered schema is deliberately restricted** to union, group
  usersets and tuple-to-userset inheritance — the subset that flattens (§8.5).
- **Bare and effective relations**, adopting Lakekeeper's v4.12 fix (§8.2).
- **Bottom-up navigational visibility** as an explicit relation rather than an
  implicit derivation (§8.2).
- **Two small closures, never the subject × resource cross product** (§9.2).
- **Asymmetric staleness with a synchronous deny epoch** (§9.3).
- **No `Engine` port** (§10). A port with one implementation is speculative;
  the seam belongs at `Decide` and `Predicate`, which is the boundary
  consumers actually see.

### 5a. Prior art, and what is taken from each

Surveyed 2026-10-23. Recorded because the design's shape is almost entirely
borrowed, deliberately.

| System | Taken | Rejected / absent |
|---|---|---|
| **Zanzibar** | Relation tuples as the data model; userset rewrites; tuple-to-userset for hierarchy at **one tuple per hop**; the Leopard index as proof that *set expansion* is the part worth materializing. Google Drive is its flagship application, which is the owner's stated sharing requirement. | Its exclusion operator (see below). Its scale assumptions and its service-shaped deployment. |
| **SpiceDB / AuthZed** | The authority-plus-projection pattern, productized as **Materialize** — consumes the Watch change stream, computes permission deltas, maintains a local denormalized view so "ACL-aware filtering becomes a simple JOIN". Independent confirmation of §9. Its escalation ladder: Check → BulkCheck → projection → Materialize. | Materialize is commercial, not open-source SpiceDB. And `pkg/embedded` is **`CheckPermission` only** — no writes, no lookup, no watch (§10), which rules it out as an embedded authority. |
| **OpenFGA** | The configuration language's `[user, team#member]` usersets and `X from Y` inheritance, which is what §8.2's permitted subset is. `ReadChanges`' *shape* as a projection source — a pollable, cursored changelog rather than a long-lived stream, so a restarted worker resumes rather than rebuilds — which §9.3's own write-log copies. | **The engine itself, as of 2026-10-23 (§10).** It answers `Check`/`ListObjects` over its own store and cannot produce a SQL fragment, so it would be a second source of truth polled in order to populate the one that answers. Also its `but not` operator, for the reason below. |
| **Lakekeeper** | The most instructive comparable — a production Iceberg catalog doing ReBAC over a hierarchy. **Roles as first-class objects** parented to a container with `assignee`/`ownership` relations, which is the teams-and-roles answer with no cross product. **Bi-directional inheritance**: top-down grants, plus bottom-up *navigational* visibility so a principal granted access to one deep object gets limited list rights on its ancestors and **only on the direct path**. And the **v4.12 bare/effective split** (§8.2), with numbers. | **It has no deny at all** — "permissions are additive", with `Managed Access` restricting who may grant rather than denying access. This design now agrees with that, and arrived there by a different route. An earlier draft of this cell called the absence "the strongest available evidence that absolutes do not belong in the relationship layer", and that is **weak support and should not be leaned on**: Lakekeeper governs data-catalog hierarchies for org-internal analytics, a domain with no per-resource owner asserting privacy against a peer and therefore no demand for the thing it lacks. The agreement is a coincidence of conclusions, not shared evidence. |
| **Palantir Foundry** | **Marking propagation through derivation**, and marking allowlists governing what a language model may see. §8.3 keeps both, as flow labels rather than as access rules. | **The mandatory/discretionary split itself**, which this design adopted and then removed (A3): a mandatory control administered by a security function is only as absolute as that administration, and routing ordinary privacy through it makes every preference an absolute. Also its read boundary: controls stop propagating once data is read, and "the rows that the user did receive are ordinary data… carry no metadata, classification, or tag that subsequent code can use to re-apply the policy." kgs cannot accept that (KGS §8.7), so §8.3's markings propagate through derivation unconditionally. |

**On exclusion operators, since three of these systems have one.** In OpenFGA
(`but not`) and SpiceDB (`-`), exclusion is **local to the single relation
definition in which it is written**. To make a restriction absolute, the
exclusion must appear in every permission on every resource type, and be
remembered for every type added later — N permissions × M exclusion
dimensions, growing with the schema, where one omission is a silent bypass
rather than an error. Exclusion is also the one operator that cannot be
flattened into a precomputed closure, so using it forfeits §9's projection and
with it the A2 budget.

Both reasons still hold and the conclusion they point to has changed. They
used to point at "absolutes are classifications". They now point at **no
absolute is a policy object at all** (§7.2) — because the locality argument is
an objection to relation-scoped exclusion specifically, and it was being made
to carry an argument about where absolutes should live instead. Where they live
is `escrow`.

## 6. Architecture

```
   consuming app (CAS / kgs / acre)
        |                      |
        |  iam.Decide(...)     |  predicate SQL fragment
        |  (single decision)   |  (filtered reads, traversal)
        v                      v
   +--------------------------------------------------+
   |                      core                        |
   |  decision procedure, schema registry, tuple      |
   |  store, closure maintainer, predicate compiler,   |
   |  write log + cursor, differential audit          |
   +--------------------------------------------------+
        |             |             |
    identity      projection      audit
     port            port          port
        |             |             |
     Zitadel       Postgres       audit
     OIDC/JIT      (per pool)     module
     + registry
        |
  Postgres (own schema, same instance)
```

- **Ports**: `IdentityProvider`, `ProjectionStore`, `AuditSink`, `Clock`,
  `Tenancy` (from the `tenancy` module), `EventSink`.

  There was an `Engine` port. It is gone with OpenFGA (§10): a port with one
  implementation is speculative, and the seam consumers actually see is
  `Decide` and `Predicate`. What sat behind that port is now ordinary code in
  the core — a tuple store, a closure maintainer and a write log — because
  with exclusion, conditions and the mandatory gate all removed, what remains
  is union, usersets and containment inheritance. That is a closure
  maintainer, not a policy engine.
- **Two consumer-facing surfaces, and the second is the point.** `Decide` for a
  single decision; **`Predicate`** returns a composable SQL fragment plus its
  bound parameters, to be embedded in the consumer's own statement. A consumer
  that can only call `Decide` will post-filter, which is KGS leak channel #6.
- **Core performs no I/O** and the decision procedure is unit-testable with
  in-memory adapters, because that component is what A3 is about.
- **`iamd`** is the service shape; the embedded path is `iam.Open(ctx, Config)`
  returning the same interface. Conformance tests run against both.

## 7. The two enforcement tiers

The spine of the design. They are not two ways of writing rules; they are two
different things, one of which decides and one of which does not.

| Tier | Mechanism | Survives | Costs |
|---|---|---|---|
| **1. Discretionary** | Relation tuples, usersets, inheritance, default-deny | nothing in particular — it is the everyday, shareable, revocable layer, and the only thing that decides | nothing |
| **2. Cryptographic** | A key the deployment does not hold (`keyring` + `escrow`) | the administrator, the operator, a subpoena, a stolen backup, and every future policy change | **everything** — no extraction, indexing, embedding or summarisation; unrecoverable if the key is lost |

There were three. The middle tier was classifications on resources and
clearances on principals, and it is removed: see A3 for the two reasons and
§7.2 for what replaces it.

### 7.1 The decision procedure

```
Decide(principal, action, resource, at) =
      discretionary_allows(principal, action, resource)   // and nothing else
```

Default-deny. One term, projected, and **this is what makes the whole decision
a single SQL predicate** — there is no live, unprojectable second term that a
compiled fragment would have to be conjoined with outside the query.

It used to read `mandatory_gate(principal, resource) AND
discretionary_allows(...)`, evaluated mandatory-first because the gate was
cheap and because a principal who failed it should not have the discretionary
layer consulted at all. "Cheap" was falsified by measurement (A2), and the gate
was a deny administered by policy (A3).

CAS §9.3's "any applicable denial wins, at any level, regardless of
specificity" has no counterpart here, and CAS must be told so rather than left
to discover it: there are no denials, so there is nothing for a precedence rule
to order. §12 says what CAS does instead.

### 7.2 Why there is no deny, and what replaces it

A3 gives the reasons. This section is the consequence a consumer has to design
against: there are exactly **two honest strengths of "no"**, and nothing in
between.

**"She may not see this" is a grant nobody wrote.** Default-deny is the only
thing that refuses. It is liftable by anybody who may share, which for a
private letter or a household invoice is the correct property — the owner
asked for a default, not a prohibition, and the previous design handed them a
prohibition. The `examples/` corpus's D6 and H1 are this.

**"Nobody may ever see this, whatever rule ever happens" is a key the
deployment does not hold.** That is §7.3, and it is the only mechanism in the
design that withholds something from a principal a grant did reach.

Three consequences worth stating plainly, because two of them are costs.

- **The legal ethical wall has no policy mechanism.** It is a matter outside
  the firm-wide container that nothing names the screened principal on, plus
  `escrow` for anything that must survive a future administrator. The corpus's
  D8 is that, and it says in its own prose that it survives nobody: any
  principal who may share the matter can share it tomorrow. This is a
  reduction in what the design claims and not in what it delivered, because
  the old mechanism's absoluteness depended on an unanswered question about
  who could administer it.
- **Privacy inside a shared container becomes grant granularity.** The
  household used to share a graph with one tuple and keep one episode private
  with a label. With no label, the grant moves down to the episode — which is
  also KGS §9.3's own default for a new episode. §9.2's closure budget is
  untouched (a per-episode grant still reaches every fact inside it at one
  tuple per hop) but the tuple count a tenant carries is now a function of how
  much it ingests rather than of how many principals it has.
- **One kgs leak channel is worse, not merely unchanged.** Sending content to
  a hosted model used to be guarded twice: the marking allowlist decided what
  the provider could receive, and the mandatory gate decided what the pipeline
  principal could read in the first place. One of those is gone, so an
  over-granted pipeline principal is stopped by the allowlist or not at all.
  kgs recorded the same finding on its own side; the corpus's A3 carries it as
  a claim.

### 7.3 Why the cryptographic tier exists at all

From the owner's requirement: *"whatever rule ever happens my will document
should always stay private except if I die and the lawyer gives the access
key."*

The discretionary tier is enforced by policy, which means it is enforced by
whoever administers policy. No access-control system can promise that no future
rule will grant access, because rules are mutable and administrators exist. The
only mechanism that survives "whatever rule ever happens" is one where the
system **cannot decrypt**.

So this tier is **not part of the decision**. `Decide` may well return allow
for a sealed resource; the caller still cannot read it without a key the
deployment does not hold. This module's entire responsibility here is one
field: a marking carries an **enforcement class** of `crypto` or `none`
(§8.3). `keyring` holds the wrapping; `escrow` holds the shares, the
custodians, the ceremony and the dead-man's switch. Recording the class here is
what lets a consumer tell a user *why* something is unreadable, and lets the
API refuse processing operations on sealed content with a typed error rather
than failing obscurely later.

The enforcement class used to have the values `policy` and `crypto`. `policy`
is now `none` — the class of a marking that enforces nothing by itself — and
the renaming is A3 in one enum value. A label that refused a principal access
was a deny administered by policy.

This tier mattered before and matters more now: with the mandatory tier gone,
it is the only thing left in the design that withholds anything from a
principal a grant reached. That is not a weakening. A classification never
survived "whatever rule ever happens" either; it only read as though it did.

## 8. Data model

### 8.1 Identity

- **Principals** — users, services, and agent runs — are rows carrying a stable
  internal id. Grants, audit chains and metering attribution reference that id,
  never an external subject string, so re-issuing an external identity never
  rewrites history (CAS §9.1).
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

### 8.2 The discretionary layer, which is the only one that decides

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

> **"Only on the direct path" is implementable as of 2026-10-24, because every
> specified consumer's containment is a tree** — one parent per container, one
> container per resource. The sentence has a referent rather than being the
> open problem it was, and F3 is closed. **It is also a sentence with a
> precondition, and the precondition belongs next to it:** the phrase is
> well-defined exactly while `scenario.DirectPath` can find one path. A
> consumer registering a schema in which a resource has two containment paths
> does not get a degraded version of this relation; it gets a phrase that names
> nothing again, and F3 reopens.
>
> What changed is not an answer to the question. The question was removed. kgs
> was respecified on 2026-10-24 — `kgs/docs/epistemic_quad_store_spec.md`,
> §2.1 and §4.2 — onto a four-tier graph tree, UNIVERSE → WORLD → SCOPE →
> TOPIC, with `named_graphs.parent_graph_id` holding one parent and
> `tenant_quads.graph_id` one graph per quad. The nestable, sometimes
> predicate-defined entity-sets that made containment many-to-many are absent
> from it entirely. F3's own first branch — "kgs's entity-sets stop being an
> authorization container" — is what happened, and it happened in the consumer
> rather than here.
>
> **The three repairs are recorded as superseded rather than deleted**, because
> the spike that was measuring them got far enough to show that two of the
> three were worse than the finding admitted, and a future DAG consumer should
> not have to rediscover it. A union of paths was going to reopen leak channel
> #1: measured at **2,356 containers made list-visible to a principal granted
> ten episodes — 1,000 facts of 10,000,000 — that it held no grant on and none
> below**, 2,354 of them entity-sets. An intersection was called "usually
> empty"; measured, it was exactly `{tenant, graph}` — size 2, min 2, max 2 —
> for *every* resource with more than one path, so it names nothing below the
> graph rather than being merely sparse. Designating a primary container per
> write still pushes the decision onto every consumer write, and as a
> containment key it silently pruned **87%** of one probe's authorized rows.
> The surviving candidate, which nobody had written down, is to anchor the
> relation on the **grant** rather than on the object: a container is navigable
> iff it lies on a path from one of the principal's own grants down to
> something it may read, which is well-defined for any number of paths and
> leaks nothing by construction. That is where to start if F3 reopens.
> `docs/superpowers/spikes/2026-10-24-f3-dag-containment.md` carries the numbers
> and says plainly that they are partial.
>
> One thing did not change. With no deny mechanism, "the screened principal
> navigates to nothing" is part of how a conflict screen is asserted (the
> corpus's D8), so this phrase is load-bearing for a security property and not
> only for navigation — which is why the precondition above is a precondition
> and not a footnote.

This matters more here than in a catalog, because it is how a consumer answers
"find the thing you may see" without revealing its siblings. KGS §7.3 derives
entity existence from authorized assertions, which is correct but implicit;
this makes it a relation that can be tested directly, and it is folded back
into KGS §7.3 as a result.

**Link sharing** is a tuple whose subject is a capability token's bearer
identity, minted and constrained by `captoken`. This module stores the
relationship; it does not interpret caveats.

### 8.3 Markings: content labels that decide nothing

**Removed on 2026-10-23: this section used to be the mandatory layer.** It
described classifications on resources, clearances on principals, clearance
groups administered through a security function's channel, and a gate that was
set containment over a resource's resolved label set. A3 gives the two reasons
it is gone and §7.2 gives what replaces it. One of its sentences is worth
quoting as it is deleted, because it was already false by measurement rather
than by argument: *"Classifications are small and change rarely, so the gate is
evaluated against authoritative rows rather than a materialized copy."* F2
measured 200,394 assignment rows in a fixture an order of magnitude smaller
than KGS A2's, because KGS propagates an episode's markings to every derived
fact, observation and vector.

What remains is much smaller, and it is not an access control.

**A marking is a label on a resource's content.** It carries an **enforcement
class** of `crypto` or `none`, and `Decide` never reads one. Two things still
need content labels now that nothing denies:

- **`crypto`** — the content is encrypted under a key the deployment does not
  hold (§7.3). The class is recorded here so a consumer can tell a user *why*
  something is unreadable and so the API can refuse a processing operation with
  a typed error rather than failing obscurely later.
- **`none`** — the marking enforces nothing by itself. It is metadata a
  consumer's own egress gate reads: KGS §9.5's model-provider allowlist is the
  one such gate across the three consumers. `none` is where the old `policy`
  class went, and the renaming is A3 in one enum value.

**Markings are flow labels, not access rules.** They propagate and they gate
egress; they refuse no principal anything. kgs reached the same conclusion
independently and relocated "what may a hosted model be shown?" out of
authorization entirely, down to egress eligibility at its `LLMProvider` and
`EmbeddingProvider` ports. This design agrees: a marking is content metadata
`iam` stores, and the gate that reads it belongs to the consumer.

**Propagation, which survives for a different reason than it had.** A derived
object carries the **union** of its inputs' markings, and a marking on a
container reaches what the container holds (resolved over the ancestry closure
of §9.2). For a `crypto` marking that is physics rather than policy — content
derived from sealed content is sealed, and a cipher does not care which
pipeline stage read it. For an egress marking it is KGS leak channel #15: a
consolidator that saw privileged evidence must not emit an observation a
non-allowlisted provider may then read. Consumers declare derivations; the
module computes the union.

What propagation is *not* any more: a mandatory control. The old §8.3 said a
classification "cannot be granted away, delegated, transferred with ownership,
or satisfied by any tier-1 relation", and that sentence was about an access
decision. A marking has nothing to be granted away.

**There is no attribute scope.** The old section permitted a classification
"declared over a whole resource, or over a named attribute or field of it,
which is how property-level and cell-level security compose without a second
mechanism". Attribute-granular restriction was the half of that sentence F4 was
already a caveat on, and with the label gone there is no mechanism for it at
all — neither a rule language to express it (F7) nor a fragment that could
enforce it over a column (F4). Those two findings are now a single fork with a
single option on it. `examples/UNEXPRESSIBLE.md`'s U1 and U4 are the two faces
of it.

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

> **This report is now ours to build.** It was going to fall out of an OpenFGA
> authorization-model diff. With the engine dropped (§10) there is no model to
> diff, so the delta between two registered schema versions is computed here,
> over our own tables. That is a real cost of §10 and it is recorded rather
> than discovered later.
>
> **And it is not built, as of 2026-10-25.** `RegisterSchema` validates a
> declaration and remembers it *in the process*: the schema is not persisted,
> not versioned, and no delta between two versions is computed. What that
> costs, precisely: two binaries with different registered schemas disagree
> about which container *kinds* may be created, and agree about every
> decision — because the tree a decision reads is enforced by the single
> parent column in the database rather than by the declaration. So the gap is
> in change *management*, not in enforcement. A schema registration that could
> widen access is still the thing §16.3 asks the owner about, and it still has
> no mechanism.

### 8.5 The restriction, as a feature

The discretionary layer permits union, usersets and tuple-to-userset
inheritance. It does **not** permit arbitrary nested intersection, exclusion,
or conditional expressions over attributes.

**The restriction stays. Its justification is narrower than it was, and the
narrowing matters because the old version was load-bearing in the wrong
place.** Two reasons survive and one is withdrawn:

1. **The permitted subset is exactly what flattens into §9's closures.** Union,
   usersets and inheritance precompute; intersection over large sets and
   conditional expressions over attributes do not. This is the reason that buys
   the A2 budget and it is sufficient on its own.
2. **A restricted language can be lint-checked**, which is how A3's "no
   exclusion operator" guard is possible at all.
3. ~~The excluded operators are the ones whose absence pushes absolutes into
   tier 2 where they belong.~~ **Withdrawn.** There is no tier 2 to push them
   into. This reason was doing most of the rhetorical work and it was circular:
   exclusion was refused because absolutes belonged elsewhere, and absolutes
   belonged elsewhere partly because exclusion was refused.

**On the locality argument, which is sound and should not be made to carry
more than it holds.** Exclusion in a relationship model applies only to the
relation definition it is written in, so a restriction meant to be absolute is
absolute only where somebody remembered it. That is a correct objection to
**relation-scoped exclusion specifically** — OpenFGA's `but not`, SpiceDB's
`-`. It is not an argument about exclusion in general, and in particular it
says nothing about a deny tuple on `(principal, resource)` inheriting through
containment, which is neither relation-scoped nor unflattenable. A3's diagnosis
names that conflation; the design's answer is that no form of deny is added,
which is a decision rather than an inference from locality.

**And discount the Lakekeeper evidence here.** §5a used to call Lakekeeper's
complete absence of deny "the strongest available evidence that this is what
the model is bad at". It is weak support for the conclusion this design needs:
Lakekeeper governs data-catalog hierarchies for org-internal analytics, a
domain with no per-resource owner asserting privacy against a peer, so it has
no demand for the mechanism it lacks. Its agreement with this design is a
coincidence of conclusions and not shared evidence.

**Where a requirement cannot be expressed in the subset, there is no longer a
second mechanism to redirect it to.** This paragraph used to read "the answer
is a classification, not a richer language", with a following paragraph warning
that answering a *discretionary* requirement that way was a one-way promotion
of a preference into an absolute. Both are gone: the warning because the thing
it warned about cannot happen, and the redirect because there is nowhere to
redirect to.

So the honest statement is shorter and harder. A requirement outside the subset
is a design conversation, not a configuration change, and it has no workaround
in the meantime. F7 is where those requirements are registered, F4 is the same
fork from the other side, and `examples/UNEXPRESSIBLE.md` is the list.

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
   most consumers already maintain it (CAS's fileset nesting, kgs's graph
   nesting).

> **"Its containment path", singular, is correct for every specified consumer
> as of 2026-10-24 — and the word doing the work is "specified".** CAS
> registers `tenant > fileset > document > slot`; kgs, respecified that day
> (`kgs/docs/epistemic_quad_store_spec.md` §2.1, §4.2), registers a four-tier
> graph tree with `named_graphs.parent_graph_id` holding exactly one parent and
> `tenant_quads.graph_id` exactly one graph per quad. One parent per container
> and one container per resource is what makes this closure "bounded by
> hierarchy depth" true rather than aspirational, and F3 is closed on that
> basis.
>
> **Two consequences to keep in view, because the sentence is now load-bearing
> in a way it was not when it was a draft assumption.**
>
> First, it is a **registered-schema invariant and not a property of this
> module**. ~~Nothing in §8.4's schema registration currently rejects a
> containment declaration that gives a resource two parents~~ — **closed
> 2026-10-25**: `domain.Schema.Validate` refuses such a declaration outright
> with its own sentinel, `ErrMultipleContainmentParents`, naming the schema,
> the kind, both parents and the two row counts below, and nothing from a
> refused schema is registered. The check is reimplemented in
> `internal/domain` rather than reusing the corpus's `Paths`/`DirectPath`,
> because `examples` imports the facade and the import cannot go the other
> way; the corpus's version is the fixture-level twin and a test holds the two
> together. The instance-level half is enforced by `iam.containers.parent_id`
> being one nullable column that no statement in the module updates — so the
> tree is a column rather than a convention, and a cycle needs an UPDATE that
> does not exist.
>
> Second, if that invariant is ever relaxed, this closure is the wrong shape
> and F3 reopens with F1's condition (iii) attached. The partial spike
> (`docs/superpowers/spikes/2026-10-24-f3-dag-containment.md`) measured the
> naive repair at kgs A2's scale before it was abandoned: keyed on the
> **resource**, a DAG closure over 10,000,000 facts was **106,495,540 rows and
> 10.9 GB**; keyed on the **container**, the same containment was **433,063
> rows and 37 MB**. A factor of 246, and the direction it points is that a
> multi-path closure must be keyed on the container with the resource's own
> edges left as a join — not that §9.2 as written needs widening.

The predicate then compiles to an index join over small tables:

```
   consumer rows
     ⋈ ancestry closure        (resource → ancestors)
     ⋈ grant tuples            (bare+effective relation on any ancestor)
     ⋈ membership closure      (subject ∈ principal's usersets)
```

There was a fourth line, `ANTI-⋈ unsatisfied classifications (tier 2, live)`.
It is gone with the tier, and its removal is the whole of why the decision is
now one predicate: it was the term that could not be projected, and F2
measured it turning a 0.46 ms keyset page into 296 ms.

Sharing that 100,000-object container stays **one tuple plus an ancestry
join**. The 50-member team costs 50 membership rows. This is the design's
load-bearing performance claim and A2's closure budget is written to catch its
violation.

### 9.3 Staleness is asymmetric, and reversing it is the whole risk

> **Amended 2026-10-25: in the shape that is built, there is no staleness to
> be asymmetric about — and the mechanism that will need this section again
> is in place rather than deferred.**
>
> The embedded deployment has no projection. The closures are the authority
> and they live in the consumer's own Postgres, so a grant and a revocation
> both take effect in the consumer's next statement and neither has a path to
> lag on. This section's hazard is a property of a *separated* authority, and
> §11's seam note says when that returns.
>
> What is built now, and built now precisely because adding it later is a
> breaking change at every call site: an append-only change log whose
> **revision** is gapless, assigned in commit order under a per-tenant
> advisory lock, and carried on every `Decision` and every residual. Not from
> a sequence — a sequence allocates its number before the transaction commits,
> so a reader can observe revision 5 while 4 is still in flight and a cursor
> stored at 5 skips 4 forever. That is this section's hazard in its purest
> form, and §17 already records it as `DefaultChangelogHorizonOffset = 0`. A
> revocation is logged as its own kind rather than as an absence, for this
> section's reason: a projection that misses a grant is an outage and one that
> misses a revocation is a disclosure.
>
> No semantics are built on the revision yet. There is no "decide at revision
> R", no declared bound, no fail-closed threshold. It is a value that exists,
> is monotonic, and is documented as the token a separated deployment will
> require.

A stale grant is a disclosure. A stale denial is an outage. They are not
symmetric and must not share a path.

- **Grants may lag**, within a declared staleness bound. **Past the bound the
  projection fails closed** — it denies rather than serving old decisions. A
  projection that cannot confirm its freshness is stale and therefore denies;
  `ErrReadinessBlocked` is the honest answer.
- **Revocations and deprovisioning ride a deny epoch.** Every
  projection row carries an epoch; every decision checks the current epoch
  synchronously; bumping it invalidates affected rows at once. So revocation
  does not wait for a refresh, and a slow propagation path denies rather than
  permits. The epoch check is the one synchronous dependency in the read path
  and is a single indexed lookup.
- Propagation is fed by **this module's own write log**, polled and resumable,
  with the cursor stored so a restarted worker resumes rather than rebuilds.
  That shape is copied from OpenFGA's `ReadChanges`, which was the projection
  source until the engine was dropped (§10): a pollable, cursored changelog
  rather than a long-lived stream is resumable by construction. We now write
  the log, which is a cost §10 records.

**One rule, stated once:**

> **The restrictive change propagates on the fast path. The permissive change
> may lag, and lagging fails closed.**

A grant may lag; a revocation may not. That is the whole of it now. An earlier
draft needed a second paragraph here because the rule read one way for tier 1
and the other way for tier 2 — *adding* a classification was restrictive and
*removing* one was permissive — and the draft before that got it wrong by
claiming classifications were "never projected" at all. With one tier there is
one direction and no second reading.

**A hazard the fast path must not trust, which is now ours rather than
inherited.** The verified form of this was OpenFGA-specific: it stamped each
changelog entry's ULID from the application clock at write time,
`ReadChanges` ordered by `ulid asc` and resumed with `ulid > cursor`, and the
only protection was a horizon guard `inserted_at < NOW() - horizon_offset`
whose **default was zero**, with the operator knob denominated in whole
minutes. At offset zero a transaction that stamps a ULID at T but commits after
the poller has passed T is **skipped permanently**. A dropped insert is a
missed grant — benign. A dropped delete is a **missed revocation — a silent
disclosure.**

Dropping the engine does not remove the hazard, it moves it: any
timestamp-ordered, cursor-resumed log written by concurrent transactions has
it. So the rule stands and is now a rule about our own log. Either order the
log by a sequence assigned at commit rather than at statement time, or carry a
horizon offset exceeding the longest write transaction plus clock skew — and
in the second case that offset is a **hard floor on propagation latency**,
which would falsify A2's "grant propagation p95 < 2 s" if the log were the only
channel.

It is not the only channel: **revocations and deprovisioning are written to
this module's own projection tables in the same statement as the authority
write, and the deny epoch is bumped from there**, with the log used only to
converge the permissive direction. The log is a convergence mechanism, never
the carrier of a restrictive change. §13 keeps the test that injects a
late-committing write and asserts no revocation is lost; owning the log makes
that test easier to write rather than harder, which is one of the few places
§10's decision is a simplification.

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

## 10. Engine selection — resolved, 2026-10-23: there is no engine

**Decided by Pascal: OpenFGA is dropped. `iam` owns its tuples and closures in
Postgres.** The spike that selected it is kept below, because its findings
about SpiceDB and about atomicity still hold and are still load-bearing.

### 10.1 Why no third-party engine, and why the reason is structural

`Predicate` must return a SQL fragment the consumer joins **inside its own
query** — settled by the F1 spike, which measured what happens when it does
not. OpenFGA answers `Check`, `BatchCheck` and `ListObjects` over its own
store and has no surface that produces a fragment. So the authority the
predicate reads has to be tables we own.

That makes the engine's role the problem rather than its quality. It would not
be the authority: it would be a **second source of truth we poll in order to
populate the one that answers**, and owning the divergence between them forever
is precisely §9.3's asymmetric-staleness problem and §16.5's unanswered
divergence-tolerance question, acquired as a permanent architectural feature
rather than as a bounded projection lag.

And there is not much left to run. With exclusion, conditional expressions and
the mandatory gate all gone (A3, §8.5), the permitted subset is union, usersets
and containment inheritance. **That is a closure maintainer, not a policy
engine.**

Two findings close by deletion as a result, and the second is the more serious:

- **F5 (store topology)** asked whether to run one OpenFGA store per tenant or
  one global store with tenant-prefixed ids. There is no store.
- **F6 (which `tenancy` connection the engine gets)** asked what happens when
  a component that *sets no tenant context*, *runs its own migrations against
  this project's goose decision*, and *inherits whatever RLS the pool's role
  carries* sits next to `tenancy`'s RLS model. The honest answer was that it is
  unacceptable, and the one-function-signature A1 argument that selected
  OpenFGA (`postgres.NewWithDB`, below) was weaker than §10 claimed because it
  answered connection *plumbing* and not connection *semantics*.

### 10.2 No `Engine` port either

The port is removed from §6. A port with one implementation is speculative, and
the seam consumers actually see is `Decide` and `Predicate` — which is where
the API stability §5 wanted was always going to come from. Nothing
OpenFGA-specific ever reached the public API, so this costs no compatibility.

### 10.3 What it costs, recorded rather than hidden

Four things, and none of them is zero:

- **`ReadChanges` was a genuinely good projection source.** A pollable,
  cursored changelog is resumable by construction, and we now write our own
  write log plus cursor. §9.3 keeps the shape and inherits the
  commit-ordering hazard as our own problem.
- **`ListUsers` and `ListObjects` are gone**, so "who can see this?" is a
  query we write. §9.1 already rejected `ListObjects` as a *read* path
  (it cannot enumerate a ten-million-row space), but it was still the obvious
  implementation of the membership expansion §9.2's first closure needs and of
  an admin "who has access" screen.
- **§8.4's access-delta-between-schema-versions report** was going to fall out
  of an authorization-model diff. It is ours to build.
- **AuthZEN endpoints** came free with v1.22 and would have let the external
  API speak a standard rather than a bespoke shape. If that is still wanted it
  is now work, not a dependency upgrade.

One thing it does **not** cost: **F3 was never solved by OpenFGA either.** DAG
containment is a property of kgs's data model, not of an engine, so it stays
open regardless and §14's "resolve the API-shaping findings by measurement"
is unaffected.

### 10.4 The spike, kept because two of its findings still bind

The spike asked two questions: can the engine run in-process without a separate
service (A1), and does it expose a change stream to project from (§9.3). Run
against `spicedb@v1.57.0` and `openfga@v1.22.0`.

**SpiceDB `pkg/embedded`: ruled out.** Its entire exported surface is
`NewPermissions`, `Check` and `Close`. The package documentation is explicit —
*"You need the full SpiceDB v1 API surface (schema writes, relationship writes,
bulk operations, watch, lookup, reflection, etc.). This package only does
`CheckPermission`."* So it could be neither the authority (no writes, no
schema) nor the projection source (no watch). Using SpiceDB means running a
real server, which costs A1. Noted separately: `spicedb@v1.57.0` requires Go ≥
1.26.9 and silently upgraded the spike's toolchain from 1.25.6, which would
drag CAS's toolchain forward as a side effect of an authorization choice.

**OpenFGA `pkg/server` was selected and is now rejected.** `Server` is an
ordinary Go struct whose methods are the full API, callable in-process with no
gRPC server, no sidecar and no network hop, and
`postgres.NewWithDB(primaryDB, secondaryDB *pgxpool.Pool, cfg)` accepts an
existing pgx pool — which was read as the A1 answer in one function signature.
F6 is the correction: sharing a pool is not the same as sharing a tenancy
model, and an engine that sets no tenant context and runs its own migrations
does not become acceptable by using someone else's connection.

**Still resolved, and still the answer: a grant and a consumer's write cannot
commit atomically, in any deployment shape.** An earlier draft flagged
`sqlcommon.NewTxConnector(tx *sql.Tx)` as a possible route to enlisting a rule
write in a caller's transaction. Verified against the source: it is a
`database/sql` connector, while the Postgres datastore reached the database
through its own private pgx connector, and `Datastore.Write` opened its own
transaction with no exported way to supply one.

> **Owning the tables changes this, and the change is not claimed yet.** With
> the tuple store in our own schema on the consumer's own pool, a grant write
> *could* enlist in a caller's transaction. That is the one genuine upside of
> §10 beyond the structural argument, and it is deliberately not promised here:
> KGS §6.2 had its atomicity promise withdrawn on the strength of the paragraph
> above, and reinstating it needs a design decision about whether `iam` accepts
> a caller-supplied transaction at all — which is a boundary question, not a
> capability question. Until that is decided, the consequence below stands.

Two consequences, both still load-bearing. KGS §6.2 promised that the
single-binary shape would maintain the projection in the same transaction as
the rule change; **that promise stays withdrawn and must not be reintroduced
without the decision above.** And there is always a window between a marking
being assigned and a derived row existing, which §8.3 closes by ordering
rather than by atomicity: a consumer declares the derivation and receives its
marking set **before** writing the derived row, and a row whose marking set
cannot be resolved is not written.

## 11. Deployment shapes

- **Embedded** (default, and what A1 is about): `iam.Open(ctx, Config)` with a
  Postgres DSN or an existing pool. The tuple store and both closures are
  tables in this module's own schema on that pool; the closure-maintenance
  worker is a goroutine. Nothing else to deploy, and — since §10 — nothing
  else *running* either: the embedded shape no longer starts an authorization
  engine in-process.
- **Service**: `iamd` serves the module's API (gRPC with a REST/JSON gateway,
  mirroring CAS and kgs) and runs the closure workers. Projections still live
  in each pool's database, so the service is control-plane only.

  > **The seam, marked 2026-10-25 and deliberately not crossed.** The embedded
  > shape is the one that is built, and everything cheap about it comes from
  > one property: the closures are in the same Postgres the consumer queries,
  > so the consumer *joins the authority* and nothing propagates. A revocation
  > takes effect in the consumer's next statement; a deprovisioning takes
  > effect in the statement that records it.
  >
  > The service shape breaks exactly that. The closures would live in the
  > consumer's pool while the authority lives in the service, which makes them
  > a **projection** again — and then §9.3's asymmetric staleness, §9.4's
  > differential audit and §16.5's divergence tolerance all come back, none of
  > them answered. Two things are already in place so that this is a build
  > rather than a redesign: the **change log** with its gapless per-tenant
  > cursor, which is what a projection resumes from, and the **revision** on
  > every answer, which is the only thing that can distinguish "lagging within
  > a declared bound" from "diverged". Neither has semantics built on it yet,
  > and building them is what the service shape costs.
  >
  > The same seam is what makes another storage backend possible at all: a
  > consumer on a store that is not this Postgres is the service shape by
  > another name, and it projects from the same log.

Identical semantics, conformance-tested against both. A household deployment
runs CAS + kgs + iam in one binary against one Postgres.

## 12. Consumers

Each registers a schema (§8.4) and gets two things: `Decide` for single
decisions and `Predicate` for filtered reads.

- **CAS** — `tenant > fileset > document > slot`. Its grants become tuples
  unchanged and its permission enum becomes relations.

  **Its denials have nowhere to go, and CAS must be told rather than left to
  find out.** An earlier draft said "its denials become classifications (CAS
  §9.3's deny-wins is §7.1's conjunction)", and there are no classifications
  and no conjunction. A CAS denial has to become one of three things, chosen
  per denial: a grant that is not written, which means the resource moves out
  of the container the broad grant covers; a `crypto` marking backed by
  `escrow`, for vault-mode content and for any screen that must survive a
  future administrator; or a requirement CAS drops. Conflict screens are the
  first option plus, where the firm needs more, the second — see §7.2 and the
  corpus's D8. CAS §9.3's precedence rule ("any applicable denial wins, at any
  level, regardless of specificity") has nothing left to order and should be
  deleted there rather than reinterpreted here.
- **kgs** — `tenant > graph > [compartment] > entity-set | episode > fact`. Its
  markings stay markings (§8.3), as flow labels propagated through derivation
  and gating egress at its provider ports — the conclusion kgs reached
  independently. Its per-fact escape-hatch rules are tuples on fact objects.
  Its §9.4 predicate is this module's `Predicate`. Its sealed episodes are
  `crypto`-class markings backed by `escrow`.
  **`visible_below` (§8.2) is folded back into KGS §7.3**, replacing implicit
  derived existence with an explicit, testable relation.

  Two things kgs has to absorb. Privacy inside a shared graph is now grant
  granularity, so an episode nobody else may read is an episode with its own
  grant — which is KGS §9.3's own default, so this is a confirmation rather
  than a new requirement. And one leak channel is **worse**: LLM context had
  two independent guards and now has one, because the union of markings no
  longer also gates reads (§7.2).
- **acre** — no code yet, so it adopts from birth and is the one consumer that
  costs nothing to onboard. Its event-sourced core is orthogonal: authorization
  decisions are not events, though every decision is an audit record.

## 13. Testing and verification

- **The mandatory-control adversarial suite is gone**, and it is worth saying
  so where it used to be listed as "the most important suite in the
  repository". It enumerated every discretionary operation available to every
  principal, applied them in combination to a bounded depth, and asserted that
  a classification gate never opened. There is no gate. What was load-bearing
  about it — that a principal holds only what has been granted — is now true by
  construction rather than by adversarial search, because there is no second
  mechanism for a grant to interact with.
- **Schema lint**: registered schemas are rejected if they use an exclusion
  operator or a conditional expression over attributes. The exclusion error
  names `escrow` and the no-deny anti-goal; the attribute error names findings
  F7 and F4 and does **not** invent an alternative, because there is none
  (A3, §8.5).
- **Marking propagation**: a derived object always carries the union of its
  inputs' markings; a pipeline cannot launder a marking by deriving (§8.3,
  and KGS §8.7's departure from Foundry). Note what this tests now: an egress
  property and, for a `crypto` marking, a property of the ciphertext. It is no
  longer an access-control test.
- **The egress gate fails closed**: a provider allowlisted for fewer markings
  than the content carries receives nothing, with a typed error rather than a
  degraded prompt. This test matters more than it did, because §7.2's third
  consequence is that it is now the only guard on that path.
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

**Superseded later on 2026-10-23: the modules go first, then CAS.** The owner's
decision — *"we will implement everything else first then go back to CAS,
better to have CAS working with production grade implementations"* — reverses
the seam below. The order is now: `tenancy`, `seal`, `captoken`, `escrow` to
production grade; then this module; then CAS, rebuilt on top of them.

What that changes, stated plainly because one of them is a cost:

- **CAS's ~2026-11-05 alpha date is released.** CAS §19.1 recorded "both
  systems at once, alpha in two weeks", and that commitment no longer holds.
  This is the trade being made: a later alpha, built on components that have
  been through their own conformance suites and integration tests, against an
  earlier one built on code written to a deadline and swapped afterwards.
- **The seam is no longer needed.** Its whole purpose was to let CAS ship
  before this module existed. If CAS waits, it simply uses the real thing, and
  the window in which a second authorization implementation existed never
  opens. That is strictly better — the seam was a mitigation for a constraint
  that has been removed rather than managed.
- **The extraction direction inverts, helpfully.** The modules are extractions
  *from* CAS, so CAS does not need to be rewritten against them: it adopts the
  modules and deletes its own copies, which is a smaller and more reviewable
  change than building adapters against an unfinished port. The duplication
  guards land at that moment.
- **This module is no longer on anyone's critical path**, which is the right
  place for it to be given §17 still holds **two open findings** (F4, F8),
  neither of which can change the shape of what is already decided. The count
  was eight; A3 and §10 closed four by deletion and resolved one, and F3 closed
  on 2026-10-24 when the consumer that caused it was respecified onto a
  containment tree — which took F1's condition (iii) with it. **So the thing
  that was blocking the public API is gone**, and the honest consequence is
  that the argument for this module staying off the critical path is now the
  sequencing one (§16 question 4) rather than the API-instability one.

The superseded decision is kept below, because the reasoning in it is still
the reasoning that applies if a date ever returns.

---

**~~Decided 2026-10-23: ship a seam, then accelerate.~~** CAS's ~2026-11-05 alpha
does **not** wait for this module. CAS builds its own authorization
(its plan 02 tasks 5/7/8, in `cas/internal/`) **shaped as this module's port
and verified by this module's conformance suite**, and swaps to the real
implementation after the alpha, at which point the CI duplication guard lands.
The `captoken` and `tenancy` extractions also happen after the alpha — moving
5,500 lines of working, tested code out from under a dated commitment is the
highest-risk item available and it buys nothing before the date.

This is a staged migration, not divergence: one consumer, written to a
published contract, replaced before a second consumer exists. The invariant
that must hold is **never two production authorization engines at the same
time**, and it holds.

Two things must be written down rather than assumed: CAS's alpha
authorization is **not performance-qualified** (no §9 projection) and **not
divergence-audited** (no §9.4 differential audit), so nobody later mistakes
alpha behaviour for designed behaviour.

**And the owner has asked to accelerate this module regardless.** The
compression comes from three things, not from starting more phases at once:

1. ~~**Resolve the API-shaping findings by measurement, immediately.**~~
   **Done, and only half of it was done the way this item expected.** F1
   (filtered ANN) was resolved by measurement on 2026-10-23 and answered the
   first question: `Predicate` returns a fragment *plus* an indexable key.
   F3 (tree versus DAG containment) was *not* resolved by measurement — the
   probe was abandoned on 2026-10-24 when kgs was respecified onto a
   containment tree and the many-to-many case stopped existing. So the second
   question is answered too: the ancestry closure is depth-bounded. **The
   lesson is worth keeping, because this item asserted the opposite of what
   happened:** it said these were "empirical questions against a real pgvector
   fixture, not design discussions", and one of the two turned out to be a
   question about a consumer's data model that a consumer's redesign settled
   for free. A finding whose subject lives in another document can be closed
   by that document changing, and checking whether it has is cheaper than
   measuring. Neither finding shapes the API any more, so nothing downstream
   is provisional on this account.
2. **Write the port and the conformance suite centrally and first.** It is the
   seam CAS needs anyway, it forces the API decisions into the open, and it is
   the yardstick every parallel workstream is judged against. **It is not
   delegated.** The A3 adversarial suite used to carry the same rule, and it
   no longer exists (§13): with one mechanism there is no combination of
   operations for an adversarial search to explore.
3. **Parallelise only what does not depend on the API.** The identity registry
   (formerly phase 3) is wholly independent of F1/F4 and moves to the front.
   The `Engine` adapter and the F5/F6 topology and connection spikes were the
   other items here and all three are deleted (§10). The classification store
   for the tree case is deleted too (A3). So this item is now just the identity
   registry, which is done.

What acceleration cannot buy: **F7 is a design conversation with kgs, not a
task**, and it is now a shorter conversation with fewer outcomes. Two of kgs
§9.3's rule dimensions fall outside §8.5's permitted subset. The resolution
used to be "either kgs loses those dimensions, or the discretionary layer gains
a form, or express it as a classification". The third option is deleted and the
second is refused permanently (A3, §8.5), so the answer is that kgs loses the
ontology-scope dimension — unless F4's consumer-applied attribute set is built,
which is the same fork. It should still be settled before the projection is
built on an assumption about it.

Phases below are otherwise unchanged in content, with identity moved forward
and the F1 spike prepended.

Ordered by what cannot be retrofitted.

**Phase 1 — the decision and the predicate.** Schema registry, identity
registry with joinable membership, the relation-tuple store in this module's
own schema, the decision procedure, and the `Predicate` compiler against a
hand-built closure. The schema lint and the §4 fixture. **Deliverable: the KGS
§1 household scenario and a legal conflict screen both decided correctly, with
`EXPLAIN` showing an index join** — noting that "correctly" for the conflict
screen now means §7.2's answer, which is an ungranted matter plus `escrow`,
and that the corpus's D8 is the acceptance test.

**Phase 2 — the projection.** Closure maintenance from this module's own write
log, the cursor, the deny epoch, the staleness contract, the differential
audit, and the A2 benchmark suite. Phase 1's hand-built closure is replaced;
its tests are not. The write log and its commit-ordering guarantee (§9.3) are
work this phase acquired from §10 and did not previously have.

**Phase 3 — identity completion.** Zitadel adapter, OIDC discovery and JWKS
caching, JIT provisioning, claim-derived group upsert, staleness bound,
agent-run delegation, deprovisioning through the deny epoch.

**Phase 4 — consumer onboarding.** CAS's schema and the migration of its
grants to tuples — plus the per-denial decision §12 now requires of it, which
is a design conversation with CAS rather than a mechanical migration; kgs's
schema; acre's schema. Each lands with that consumer's conformance run.

**Phase 5 — surface and operations.** `iamd`, an AuthZEN-shaped external API
if that is still wanted (it came free with OpenFGA and is now work — §10.3),
schema-version access-delta reporting (also now ours to build), the review step
for widening changes, audit integration, metering.

`escrow` integration is not a phase here: this module only records the
enforcement class, and `escrow` ships on its own timeline. Note that `escrow`
is now the design's *only* answer to "an absolute that must survive a future
administrator", so a consumer with that requirement is blocked on `escrow`'s
timeline rather than on this module's. CAS's conflict screens are the first
case.

## 15. Open decisions left to the builder

**Amended 2026-10-25**, when the authorization layer was built. Six of the
items below are now decided and say so with their reason; the rest are
untouched. Two decisions were taken that this section did not anticipate at
all, and they are recorded at the end rather than folded in, because a
section of "open decisions" should not quietly grow answers to questions it
never asked.

- ~~**Closure storage shape**: one table per closure, a single wide table, or
  materialized views. Decided by the A2 predicate-plan tests.~~
  **DECIDED 2026-10-25: one table per closure, and the containment one is
  keyed on the container.** `iam.container_closure(tenant_id, container_id,
  ancestor_id, depth)`, primary key `(container_id, ancestor_id)`, with the
  reflexive depth-0 row included. The membership closure needed no new table:
  `iam.live_group_members` over `iam.group_members` already is it.
  - The keying is the decision, not the table count. F3's spike priced both
    ends on one 10,000,000-row fixture: keyed on the **resource**,
    106,495,540 rows and 10.9 GB; keyed on the **container**, 433,063 rows
    and 37 MB. The closure holds no resource at all, so a consumer's row
    carries one scalar column naming its container and the resource's own
    edge stays in the consumer's table.
  - The reflexive row is what makes a decision one join rather than a union
    of "a grant here" and "a grant above". It costs one row per container and
    it means the residual a consumer ANDs into its own policy is one EXISTS
    instead of two clauses that have to stay in step inside somebody else's
    policy text.
  - Not materialized views: a materialized copy of a *denial* needs a refresh
    path, and §9.3 makes a stale denial a disclosure.
- ~~**Enforcing §9.2's single-path invariant at schema registration.**~~
  **DECIDED 2026-10-25: registration refuses a multi-parent declaration
  outright**, which was this section's own recommendation.
  `domain.Schema.Validate` returns `ErrMultipleContainmentParents` — its own
  sentinel, not folded into `ErrInvalidSchema`, because the caller that hits
  it has to redesign a data model or reopen F3 rather than fix a field — and
  the message names the schema, the kind and both parents, with the 10.9 GB
  against 37 MB numbers in it. The refusal is total: nothing from a refused
  schema is registered, so a container of one of its kinds still fails, since
  a partially registered schema is worse than a refused one.

  Two things were done differently from the recommendation, both narrowings.
  The check is reimplemented in `internal/domain` rather than reusing
  `examples/scenario`'s `Paths`/`DirectPath`, because `examples` imports the
  facade and the import cannot go the other way; the corpus's version remains
  the fixture-level twin and the two are held together by a test rather than
  by shared code. And the invariant is enforced twice over: at declaration by
  that refusal, and at instance level by `iam.containers.parent_id` being one
  nullable column with no statement in the module that updates it — so a
  cycle needs an UPDATE that does not exist, and the tree is a column rather
  than a convention.
- ~~**Whether the deny epoch is global, per tenant, or per principal.**~~
  **MOOT, and replaced by something else: there is no deny epoch, and the
  revision is per tenant.** The epoch existed to invalidate cached decisions
  on a revocation; with the closures being the authority and living in the
  same Postgres the consumer queries, a revocation takes effect in the
  consumer's next statement and there is nothing to invalidate. What took its
  place is the change log's **revision** (§9.3's amendment, 2026-10-25), and
  that one is per tenant — not by preference but because it cannot be
  otherwise: under a tenant session context `max(revision)` is that tenant's
  maximum, so a deployment-wide counter read through the row-level-security
  policy on the log would hand two tenants the same next value. Per tenant is
  also the unit a projection resumes.
- Projection update strategy: incremental deltas from the write log versus
  periodic full recompute per affected subtree, and the crossover point.
- ~~Whether the write log is ordered by a commit-time sequence or by a
  statement-time stamp plus a horizon offset (§9.3). The first avoids a floor
  on propagation latency and is more work.~~
  **DECIDED 2026-10-25: commit-time order, and the work is one statement.**
  Every closure-affecting write takes a per-tenant advisory lock for the
  remainder of its transaction and assigns `max(revision) + 1` under it, so
  revision order is commit order with no gaps and no horizon offset to tune.
  Not a sequence: a sequence allocates before commit, so a reader can observe
  revision 5 while 4 is still in flight and a cursor stored at 5 skips 4
  forever — the hazard §17 records as `DefaultChangelogHorizonOffset = 0`.
  The cost, stated: closure-affecting writes within one tenant serialize
  against each other, and two tenants colliding in the lock's 32-bit hash
  serialize with each other; reads take no lock at all.
- Differential audit sampling rate and selection strategy in production.
- ~~Whether `Predicate` returns a SQL fragment, a CTE, or a joinable view, and
  how it is parameterized safely across the three consumers' query builders.~~
  **SUPERSEDED 2026-10-25: all three answers share one defect, and it is not a
  SQL defect.** Each of them puts **SQL text across the port**, so every
  consumer holds a dependency on the string and a second storage backend —
  and other backends are coming — becomes a breaking change for all of them
  rather than a new renderer here. So the authority returns a *residual*: a
  typed expression over the consumer's own column, with a per-backend
  renderer. This is where OPA's partial evaluation and Oso's data filtering
  both landed, and for this reason.

  The Postgres renderer is the only one built. **CQL is the known hard case
  and it is not a translation problem**: Cassandra filters only on a partition
  key and a prefix of the clustering columns, so "this row's container is one
  the principal may read" is renderable there only if the containment key *is*
  part of the table's key — a data-modelling constraint on the consumer. Every
  render path therefore returns an error, so a backend can refuse honestly
  rather than emit something that filters less than it claims.

  The question this leaves open is narrower and is still open: what the
  residual has to grow for F4's attribute set, if that is the branch taken.
- Caching of decisions in-process. Its invalidation no longer has a deny
  epoch to check against and would check the revision instead — which is
  exactly what the revision is for, and still unbuilt.
- ~~Concrete relation naming conventions, and whether `_effective` relations
  are generated from a declaration or written out in each registered schema.~~
  **MOOT 2026-10-25: there are no relations.** §8.2's bare/effective split was
  adopted because `_effective` is precisely what a closure materializes — and
  with the containment closure materialized directly and keyed on the
  container, there is nothing left for a second relation per grant to hold. A
  permission on a container, inherited down, is the whole language. Lakekeeper's
  numbers stand as the reason the split mattered in a model that had relations.

**Two decisions this section did not ask for.**

- **The revision exists on every answer before anything reads it.** A
  `Decision` and a residual each carry the authorization state they were
  computed against. Nothing builds consistency semantics on it yet: no
  "decide at revision R", no bound, no arithmetic. It is there because it
  cannot be added later without changing the shape of every answer, and the
  deployment that needs it — `iam` separated, with the consumer projecting
  locally — is the one where it is the only thing distinguishing §9.3's
  bounded lag from §16.5's divergence. It is this design's zookie.
- **Tenant isolation is `tenancy`'s `EnableRLS`, asserted from `MigrateUp`
  rather than written into a migration.** A hand-written *permissive* tenant
  predicate was a measured cross-tenant disclosure in this project on
  2026-10-23 — OR-ed away by any later permissive policy — and `EnableRLS`
  creates it `AS RESTRICTIVE` with a permissive companion to AND against. It
  is asserted on every `Up` because it is idempotent by design and therefore
  repairs a drifted predicate, which a one-shot `CREATE POLICY` cannot. The
  cost: "the schema is what the migrations say" is no longer the whole truth
  about this database, and `migrate.RLSTables` is the rest of it. The identity
  tables stay uncovered, named with the reason in
  `migrate.RLSTablesExemptFromPolicy`, because covering them requires the
  registry adapter to establish a tenant session context on every statement —
  a stated gap, not a decision.
- Go module layout and whether the AuthZEN surface is a subpackage.

## 16. Outstanding questions for the owner

1. ~~**Does a classification ever need to be scoped to a principal rather than
   a clearance?**~~ **Moot — there are no classifications** (A3). Recorded
   rather than deleted because the question's framing is the no-deny decision in
   miniature. It asked whether the mandatory layer needed a *second* rule shape
   — a named `(principal, resource)` block — beside the label, and observed
   that adding one would double the adversarial suite "since every absolute
   would then have two ways to be satisfied instead of one". A3's diagnosis is
   that the right move was neither shape: the named pair is case (c) in A3,
   the one that was never separately examined, and the resolution was to remove
   the need for any of them. **No answer is required.**
2. ~~**Who may create and assign classifications?**~~ **Moot — nothing creates
   or assigns one.** This is stated explicitly rather than dropped, because it
   was the **blocking input to F9** and the owner should see it closed rather
   than wonder whether it is still waiting. The `examples/` corpus had
   demonstrated, against the real registry, that while this was unanswered any
   principal could construct a mandatory act naming themselves and walk into a
   conflict screen's clearance group. There are no mandatory acts, no clearance
   groups and no classify permission, so F9 is closed by deletion and this
   question needs no answer. **It is also one of the two reasons the tier went**
   (A3): an absolute whose administration was undecided was not an absolute.
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

5. **How much divergence tolerance is acceptable in production?** **Still
   open, and substantially smaller than it was.** A4 makes zero divergence a
   build failure, while the projection is *designed* to lag within a bound, so
   during that window authority and projection legitimately differ.

   What shrank it is §10. The hard part of this question was that
   distinguishing lag from divergence needs a point-in-time read of the
   authority at the projection's cursor, and OpenFGA had no read-at-revision:
   it offered a `ConsistencyPreference` and nothing resembling a ZedToken, and
   `ReadChanges`' continuation token was a changelog ULID rather than a
   consistency token `Check` would accept. With one source of truth in our own
   Postgres, the authority *is* readable at a point in time — the tuple tables
   are ordinary rows in the same database as the closures, so a repeatable-read
   snapshot answers "what did the authority say at the cursor" directly, and
   there is no second system whose notion of "now" has to be reconciled with
   ours.

   What is left is the ordinary question of how a sampled audit treats a
   legitimately-lagging row, which is a tuning decision rather than an
   architectural one. It is still the owner's call because A4 is what makes the
   whole projection defensible, but it no longer requires accepting a
   permanent, unmeasurable window.

## 17. Builder-check findings register (2026-10-23)

Open items from the builder check, recorded rather than resolved, so none is
lost and each has an owner. Items the check raised that *were* resolved are in
§8.3, §9.3, §10 and §16 above.

**The register was rewritten on 2026-10-23**, after the no-deny decision (A3)
and the engine decision (§10), **amended on 2026-10-24** when F3 closed, and
**amended again on 2026-10-25** when the authorization layer was built.

**What 2026-10-25 changed in this register, and what it did not.** F3's
precondition is now *enforced* rather than recorded: schema registration
refuses a multi-parent declaration with its own sentinel (§8.4, §9.2, §15).
F2's remaining half — the containment-key half — is half-addressed: a
realistic containment *tree* fixture exists and the **point** decision's plan
is asserted to be an index join (closure primary key, then
`grants_container_permission_idx`), measured at about 0.17 ms of server time
against the spike's 1.0–1.5 ms. What is still unmeasured is the filtered-read
side of A2, "adds < 20 ms at p95 over 10,000,000 rows", which needs a
ten-million-row fixture and is a spike rather than a unit test; the first
version of that assertion was written against a small fixture, failed, and was
*correct to fail* — the planner built the authorized container set once and
hashed it, which is the better plan because that set is bounded by container
count. The assertion was wrong, not the plan. **F4 and F8 are untouched and
remain the two open findings**, and F4's branch is still unchosen, which is why
`Predicate`'s filtered-read contract is unbuilt.
The arithmetic, because the README quotes a count and the count must be true:

| Disposition | Findings |
|---|---|
| **Closed by deletion** | F5, F6, F9 |
| **Resolved** | F1 (by measurement, two conditions carried), F2 (half deleted, half carried), F3 (by respecification, with a precondition), F7 |
| **Open** | F4, F8 |

**Two open, and neither can move the public API any more.** That is the one
structural change on 2026-10-24: F3 closed, and F1's condition (iii) closed
with it, so the `Predicate` signature is no longer waiting on anything. F4 can
still *grow* the surface — it is a fork about whether `Predicate` returns a
permitted-attribute set — but it cannot change the shape of what is already
decided.

**F3 is resolved conditionally and the condition is not a formality.** It
closed because the consumer whose data model caused it was respecified onto a
containment tree, not because a way to project a DAG was found. A future
consumer with multi-path containment reopens F3 and reopens F1's condition
(iii) with it. §8.2 and §9.2 carry the precondition next to the sentences that
depend on it, which is the only place a reader will actually meet it.

| # | Finding | Status |
|---|---|---|
| F1 | ~~**Filtered ANN versus the predicate.**~~ **RESOLVED by measurement, 2026-10-23** — see `docs/superpowers/spikes/2026-10-23-f1-filtered-ann.md`. Postgres 18.6 / pgvector 0.8.7, 2,000,000 `halfvec(768)` rows, 30 queries per cell. **`Predicate` returns a fragment *plus* a key.** Pushing the predicate inside the ANN index scan (option a) failed at **every** selectivity, not merely the low ones — no variant reached recall@20 0.95 anywhere, defaults scored **0.000** on adversarial queries at 0.1%, and tuning it to a full index walk cost **18 seconds**. Pre-restricting the candidate set by a key (option b) reached 0.955–0.962 at 1% and 0.1% with a per-partition HNSW, and 1.000 in 5 ms with an exact scan over the pruned set. **And A2's closure budget survives intact:** the key is one scalar column per row holding the id of the row's ancestor at a declared containment depth, derived from the containment path only and naming no principal, group or grant — so adding a member to a 50-member team with access to 200,000 objects writes **2 rows and zero fact rows**, identical to the closures alone, where a per-principal key would write 200,000. The worry that (b) required the forbidden materialization was unfounded; §9.2 stands as written. | **Still closed. Two conditions carried forward; the third is satisfied as of 2026-10-24.** (i) **The fragment stays mandatory.** Key-only is not a slow path, it is a disclosure: with a grant finer than the key, a key-only top-20 returned **9 unauthorized rows out of 20**. The key pre-filters; it never authorizes. (ii) **The consumer must choose exact-versus-ANN explicitly** — the planner gets it wrong at 1% selectivity, scoring 0.100 where an exact scan over the same pruned set scores 1.000 in 131 ms. (iii) ~~**A scalar key presumes a containment tree, so this answer depends on F3's, which is open.** Settle F3 before freezing the signature.~~ **SATISFIED, 2026-10-24.** What satisfied it is **F3's resolution, which is the consumer's respecification onto a containment tree** (`kgs/docs/epistemic_quad_store_spec.md` §2.1, §4.2: one parent per graph, one graph per quad) — not a measurement of a multi-path key, which was never completed. The presumption the condition named is now true of every specified consumer, so the key stays **scalar** exactly as F1 measured it and **the signature can be frozen.** The condition is satisfied rather than deleted, because it is the precondition in another form: a consumer with multi-path containment reopens F3 and reopens this condition with it, and the abandoned spike's partial numbers say which way to go if that happens — a scalar key on one dimension of a two-dimensional containment over-approximated by **57–77×** and its key-only page returned **43–50 unauthorized rows of 50**, while an array of the resource's direct containers with a GIN index was exact. Unaffected by A3 and by §10: the spike measured our own Postgres tables either way. |
| F2 | **Half resolved by deletion, half carried into the containment key.** The spike measured the discretionary closure join at **0.006 ms per candidate row, index-served**: the closures were never the problem. The problem was the tier-2 classification anti-join, walking 200,394 `fact_classification` rows and turning a 0.46 ms keyset page into **296 ms** — and the gate's cost was a function of *assignment* cardinality, which KGS propagates to every derived fact, observation and vector. That half is **closed by deletion** (A3): there is no gate, no anti-join, and A2 is back to one budget, which was already met. §8.3's "classifications are small and change rarely" was false by this measurement and the sentence is deleted with its section. | **The containment-key half stays open and is the only half left.** The key is what made the measured query fast (3 ms) for reasons unrelated to ANN, so the §4 fixture must still carry a realistic containment shape and the predicate-plan tests must still assert an index join over it. What is no longer required is distinguishing label *definitions* from *assignments* in the fixture, because there are neither. **Narrowed 2026-10-24 by F3's resolution:** "a realistic containment shape" now means a realistic **tree**, which is a much cheaper fixture to build than the one F3 was going to need — the abandoned F3 probe spent 13 m 23 s and ~20 GB on a multi-path one, of which 7 m 12 s was the resource-keyed DAG closure alone. |
| F3 | ~~**Containment is a DAG, not a tree.**~~ §9.2's ancestry closure and §8.2's "only on the direct path" both assume one path, but a kgs fact had an episode *and* zero or more nestable, sometimes predicate-defined entity-sets. Many-to-many at fact cardinality, maintained on every write, and "the direct path" undefined. **RESOLVED 2026-10-24 by respecification of the consumer, not by measurement.** kgs's implementation target is now `kgs/docs/epistemic_quad_store_spec.md`, whose containment is a strict four-tier tree — UNIVERSE → WORLD → SCOPE → TOPIC (§2.1) — with `named_graphs.parent_graph_id` holding **one** parent, `tenant_quads.graph_id` **one** graph per quad, and `tenant_entities.home_graph_id` **one** graph per entity (§4.2). Its own ancestry walk is `WITH RECURSIVE … UNION ALL` over `parent_graph_id` (§4.3), which is correct only for a single parent. There is no entity-set table, no many-to-many membership and nothing predicate-defined; the words do not appear in the document. So F3 closed by **its own first branch** — "kgs's entity-sets stop being an authorization container" — chosen in the consumer's design rather than argued here, and that also disposes of the branch this register had marked as the owner's. | **Resolved, with one precondition carried forward, and the precondition is the whole of what is left.** **The resolution is scoped to the specified consumers**: CAS's `tenant > fileset > document > slot` and kgs's four-tier graph tree are both trees, so §9.2's "its containment path" has a referent and §8.2's "only on the direct path" is implementable. It is **not** a result about authorization containment in general, and must not be read as one — a future consumer whose resources belong to several containers reopens this finding and F1's condition (iii) with it. `acre` is a planned consumer nobody has specified and is therefore evidence in neither direction. **What this costs:** the single-path assumption is now a registered-schema invariant that §8.4 does not currently enforce — a consumer could declare a two-parent containment and get a closure whose size is a function of resource cardinality, silently. The corpus has the check already (`scenario.Paths`, `scenario.DirectPath`); §15 carries wiring it into schema registration. **The spike that was measuring the alternative is abandoned**, and its partial numbers are kept because two of F3's three stated repairs turned out worse than the finding admitted: a union of paths made **2,356 containers list-visible to a principal holding no grant on any of them**, and the intersection was exactly `{tenant, graph}` for every multi-path resource rather than merely "usually empty". See `docs/superpowers/spikes/2026-10-24-f3-dag-containment.md`. |
| F4 | **An attribute-granular restriction cannot be enforced by a row predicate.** A `WHERE` fragment hides rows, not columns. kgs is fine (facts are rows); CAS is not (document fields are columns). | **Open, and it lost a branch.** Either `Predicate` returns a permitted-attribute set the *consumer* applies — moving part of the trust boundary into consumer code, and making §9.4's audit responsible for consumer compliance — or this module becomes a query rewriter across three query builders. Two different modules; pick one before phase 1 fixes the API. **What changed:** the finding used to be about an attribute-scoped *classification*, and a third resolution existed implicitly — declare the label and accept that the gate answers correctly while `Predicate` cannot. There is no label, so F4 and F7 are now one fork with one option on it. CAS's own cheapest answer is unaffected and more attractive: make the sensitive field its own addressable resource, so the columnar case becomes a row case and an ordinary grant reaches it. |
| F5 | ~~**OpenFGA store topology.**~~ One store per tenant versus one global store with tenant-prefixed ids, with §8.4's per-consumer schema versioning possibly uncomputable in the second shape. | **CLOSED BY DELETION, 2026-10-23 (§10).** There is no store. |
| F6 | ~~**Which `tenancy` connection the engine gets.**~~ `tenancy`'s data-plane handles carry RLS session context and its control-plane path must not accept caller-supplied predicates; OpenFGA set no tenant context, ran its own migrations against this project's goose decision, and its queries inherited whatever RLS the pool's role carried. | **CLOSED BY DELETION, 2026-10-23 (§10), and it is the finding that most deserved it.** The honest resolution was never a wiring choice: a component that sets no tenant context and runs its own migrations is unacceptable next to `tenancy`'s RLS model, and the one-function-signature A1 argument that selected OpenFGA answered connection *plumbing* rather than connection *semantics*. §10 records this as one of the two reasons the engine is dropped. |
| F7 | **Two of kgs §9.3's rule dimensions fall outside §8.5's permitted subset** — ontology scope ("may read `Person` but not `salary`": attribute-conditioned and exclusionary) and predicate-defined entity-sets (authorization as a function of data). The old answer was "use a classification", which converted a discretionary restriction into an absolute no owner could lift. | **RESOLVED, 2026-10-23, and the resolution is a refusal plus a definitive answer.** The discretionary-restriction form is **refused permanently**: A3 rules out exclusion and §8.5 rules out attribute conditions, and neither refusal is open to a case-by-case exception. And since classifications no longer exist, **"kgs loses the ontology-scope dimension" is the definitive answer rather than one of two** — the branch that made this a choice was the classification workaround. The one remaining way the requirement could be met is F4's consumer-applied attribute set, which is why the two findings are one fork. The predicate-defined-entity-set dimension stays unresolved but it lands in F3, not here: see `examples/UNEXPRESSIBLE.md`'s U5. Nothing here is a design conversation any more; what is left is a decision in kgs. **Updated 2026-10-24:** that decision was taken, in the direction that removes the dimension. kgs's respecified containment (`kgs/docs/epistemic_quad_store_spec.md`) has no entity-set, explicit or predicate-defined, so the second dimension is gone along with F3 and U5's subject is gone with it. **Both halves of F7 are therefore closed, and neither by this module getting more expressive** — one by a permanent refusal here, one by the requirement being withdrawn there. |
| F8 | **What is the audit unit on the `Predicate` path?** A filtered read over 10M rows makes no per-row decision and produces no denials — absent rows are not refusals. KGS §8.6 requires denied access to be audited. | **Open.** Likely the compiled predicate plus parameters plus epoch, but §7.1's "auditable without being informative" needs a concrete answer for the surface carrying the traffic. **Two notes.** The removal of the mandatory tier makes this slightly *simpler* in one respect — there is no "gate failed before any grant was consulted" event to audit separately — and leaves the hard part untouched, since the hard part was always that a filtered read has no per-row decision. And **caveats would make it worse**: a caveated grant means an absent row might be absent because a caveat narrowed it, which is a refusal with a reason the predicate path has no place to record. That is one more argument for A3's guardrail. |
| F9 | ~~**Nothing checks whether the actor on a mandatory act may classify.**~~ The registry enforced the witness (a `MandatoryAct` carrying channel, actor, reason and instant, unforgeable in Go) and not the right, because §16.2 was unanswered — so an ordinary principal could construct an act naming themselves, join a conflict screen's clearance group, and the gate opened. The `examples/` corpus did exactly that against the real registry, and the registry accepted it. | **CLOSED BY DELETION, 2026-10-23 (A3).** There are no mandatory acts. **And it is one of the two reasons the tier was removed**, so this entry should be read as having been answered rather than discarded: an absolute administered through an unguarded channel was only as absolute as that channel, which is the correctness half of A3's argument. §16.2, which was this finding's blocking input, is moot and says so explicitly. The corpus scenario that demonstrated it (U6) is recorded in `examples/UNEXPRESSIBLE.md` under "Resolved by removal" rather than deleted. |

Two entries are kept below the table because their original wording is the
record of what was believed before the measurements, and both measurements
changed a decision.

| # | Original wording | |
|---|---|---|
| F1-orig | **Filtered ANN versus the predicate.** A2 wants an index join; KGS A2 and leak channel #8 want the predicate *inside* the ANN search with recall ≥ 0.90 at 0.1% selectivity. pgvector's workable shape is to pre-restrict the candidate set, which needs the accessible set expressible as an indexable key on consumer rows — which looks like the per-principal materialization A2 forbids. The household graph at 0.1% selectivity is exactly where a correct-looking system returns nothing. | **Blocking. Moves to phase 1** as a proof, not phase 3. `Predicate`'s contract may have to be "a fragment *plus* a key the consumer indexes and partitions by", with a maintenance path owned here. Recall ownership must be assigned to one document. |
| F2-orig | **Classification assignment cardinality.** A2 budgets "500 classifications"; if that means *assignments*, it is wrong by orders of magnitude — KGS propagates an episode's markings to every derived fact, observation and vector, which is tens of millions of rows. "Small and changes rarely" is then false and the gate is not a small-table join. | **Blocking for the fixture.** A2 must distinguish label *definitions* from *assignments* and the fixture must carry the real shape before any benchmark means anything. |

Verified by the check and already folded in above: `postgres.NewWithDB` is real
(§10.4's A1 argument held as far as plumbing went, and F6 is why that was not
enough); `NewTxConnector` does **not** permit a caller's transaction (§10.4,
and KGS §6.2 corrected); `DefaultChangelogHorizonOffset = 0` creates the
dropped-revocation hazard (§9.3, which now applies to our own write log).
