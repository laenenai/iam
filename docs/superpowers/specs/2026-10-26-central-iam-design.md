# Design: a central IAM on an event-sourced grant log

**Status:** decisions taken, specification not yet complete. Written 2026-10-26
from a brainstorm with the owner the same day. Every numbered decision below is
the owner's unless marked *(Claude's call)*.

This supersedes the authorization half of
`docs/superpowers/specs/2026-10-23-iam-design.md`. That document remains the
record of how the earlier decisions were reached, and its findings register is
still live — see §9. The identity half of it stands unchanged.

---

## 1. Intent

A **central** identity-and-authorization service in the sense Google Cloud IAM,
AWS IAM and Entra are central: one place that answers who someone is and what
they may do, for every product in the set — `cas`, `cogos` and `ledger` today.

It starts at household scale, with a handful of tenants, and must not foreclose
many paying organisations later. **Build for the household; do not design the
household out of the enterprise shape.**

Identities are **users and agents**. Resources are documents, chats, spaces and
entities.

## 2. The decisions

### D1 — ReBAC only. No ABAC in the engine.

Authorization is relationship-based, evaluated by OpenFGA. There is no
attribute-condition language in the model.

The owner has no decision that relationships cannot express. And the structural
reason to keep it that way: **a condition cannot be precomputed.** Its inputs do
not exist until the request arrives, so every condition inside the model is a
question the inverse index (D7) cannot answer — requirement 2 working against
requirement 4.

Request-context checks — network, validity window, single use, delegation depth
— live in `captoken`, where thirteen caveat kinds are already built and
adversarially tested, and where a third party can verify them without calling
us. This is the split Entra uses: **attributes gate the session, relationships
gate the object.** AWS is the counter-example, and AWS IAM policy evaluation is
also the one engineers find hardest to audit.

If data sensitivity ever needs to gate anything, it is a **scalar column on the
row** compared against a clearance the request carries — a property of stored
data, which survives projection, rather than a condition, which does not.

### D2 — No deny mechanism. No classification tier. Absolutes are cryptographic.

Confirmed from the requirement side rather than from principle. The only
"never" in the system is a will: something that must stay unreadable **even if
access is granted by accident**.

A deny row does not deliver that. It is administered by the same people who
make the accidental grant, so it defends against one accident by introducing a
second artefact that can be removed, reordered, or never written on a resource
type added later. In OpenFGA it is worse: exclusion is local to the relation it
is written in, so "never" means writing it on every relation of every type and
remembering it for every type added afterwards, where **one omission is a
silent bypass rather than an error**.

What delivers it is that the system cannot decrypt: `escrow` (threshold custody,
verified reconstruction) over `seal`'s SEAL2 record, whose AAD binds ciphertext
to its address so it cannot even be relocated onto another row and read. No
grant, no bug, no administrator and no subpoena opens it — only M-of-N
custodians.

**Its cost is total and must be stated to users rather than discovered by
them:** a crypto-sealed document cannot be OCR'd, extracted, indexed, embedded
or summarised. The owner confirmed there is nothing requiring "never" that must
remain readable, which is what makes this sufficient.

Accidental over-granting generally is addressed by **separation of duties on the
grant** and **periodic access recertification** — the standard controls, which
attack the accident directly.

### D3 — Owner-centric sharing. Sharing is not implied by access.

The person who holds a document grants access to it; no administrator is in the
path. At household scale this is forced — there is no administrator. At
enterprise scale the model does not change, it is *bounded* (D4).

In ReBAC terms the ability to grant is **just another relation** (`owner`
implies `can_share`), so this is the model doing its job rather than a special
case.

Two defaults, both of which Google Drive gets wrong:

- **Receiving access does not confer the ability to pass it on.** Re-sharing is
  a distinct permission, granted deliberately. Drive's transitive re-sharing is
  the largest single source of "how does this person have access?" in real
  deployments, and the narrowing-only discipline is the same one `captoken`
  already enforces for tokens.
- **An agent can hold access but never hold sharing.** An agent run is its own
  principal that inherits nothing, with a TTL and a deprovisioning cascade —
  already built. An agent that can widen its own reach is the last thing wanted
  in a system that also runs an autonomous scout.

### D4 — Guardrails are grant-time, never read-time, and not yet built.

No limits on sharing today. Later, possibly keyed on sensitivity.

**The distinction decides whether that is cheap or catastrophic.** A sensitivity
label that constrains *who may grant*, or requires a second approver, is an
administrative control evaluated at write time: it never touches the read path
and never touches the projection. A sensitivity label that *denies reads* is the
mandatory tier removed in D2 — it breaks the inverse index and turns preferences
into absolutes no owner can lift. **Sensitivity may gate the grant; never the
read.**

### D5 — Identity broker, not identity provider. OIDC, Zitadel first.

Never store a credential. Federate: OIDC to Zitadel now, other providers later.
The existing registry is already this shape — verified claims in, a stable
internal principal out, an issuer policy per tenant, JIT provisioning on first
sight.

Two consequences:

- **Zitadel's own roles are not an authorization system.** It owns
  authentication, identity attributes and group *membership*. All authorization
  is OpenFGA. A `roles` claim in a token is informational at most and is never
  an input to a decision — otherwise there are two authorities and no single
  query can answer "who can see this".
- **External identity becomes its own table.** The registry today keys
  `(issuer, subject)` one-to-one onto a principal. The owner expects one person
  to arrive through more than one provider later — an IdP migration, or a
  household member with a personal and a corporate identity. Without a
  many-to-one link their grants silently split in two and half their access
  disappears. So: `external_identity(principal_id, issuer, subject, linked_at,
  linked_by)` from the start. Linking a **new** identity to an existing
  principal is additive and safe; **merging two principals that both already
  hold grants** is a separate, audited, admin-only operation, because it means
  deciding whose access the merged identity keeps.

### D6 — The append-only grant log is the record. OpenFGA is a derived read model.

The owner requires point-in-time reconstruction: *"who could see this document
on 3 January, and who granted them that."*

OpenFGA cannot answer that. It stores current tuples; `ReadChanges` is a
changelog with finite, configurable retention, so reconstructing an arbitrary
past date means replaying it and depends on retention never having been pruned.
"Who granted this, and why" is not in a tuple at all.

So the authority inverts. A grant API writes **one immutable event** — tenant,
container, subject, permission, granted by whom, reason, instant — and a
projector applies it to OpenFGA and to the projections of D7. This answers four
things with one mechanism:

| | |
|---|---|
| Point-in-time | replay to any date, bounded by our retention, not the engine's |
| "Who granted them that" | in the record by construction |
| The consistency token | it *is* the log position; the zookie is a sequence number |
| Divergence | detectable by comparing log position to applied position, repairable by replay |

`audit`'s hash-chain discipline applies to the log, so the history is
tamper-evident rather than append-only by convention.

The honest cost: a grant is not instantly visible to the engine, so
grant-then-check needs read-your-writes — wait until the applied position
reaches the token. A failed projection is **visible lag rather than silent
inconsistency**, which is the better failure.

**Implementation: `github.com/laenenai/es-lite`** (v0.6.0). Its own README
states this design's motivation: *"only an immutable log answers 'what did
aggregate X look like on 3 March, and why?' from the database alone."*

Three things it forces, to be confirmed against its ten ADRs before committing
*(unverified at the time of writing — only its README and file listing were
read)*:

1. **Zero-knowledge: the store holds ciphertext and no keys.** The grant log is
   therefore **not SQL-queryable** — it cannot be indexed by tenant, container
   or subject, and an audit question is answered by a keyholder process
   replaying, not by a query. This is coherent here (the projector holds keys
   and writes *plaintext* read models, which are RLS-protected) but it changes
   *who* can answer an audit question: the service, not someone with `psql`.
   Auditors often expect the latter.
2. **It is on go 1.26.5; the rest of the set is on 1.25.6.** Adopting it pulls
   this module's toolchain forward and transitively its consumers'. A one-commit
   decision across a set we own, but `seal`'s charter counted "did not force a
   toolchain change" as a selection criterion, so it is named rather than left
   to arrive sideways.
3. **It is workspace-scoped**, which must be confirmed to map onto tenant. If it
   does, it aligns with a finding already in the code: the consistency revision
   has to be **per tenant** rather than global, because `max(revision)`
   evaluated under a tenant policy *is* per tenant.

### D7 — One global OpenFGA store. Projections are container-keyed.

**One global store**, not one per tenant. Tenant isolation is therefore a naming
convention rather than a structural boundary, which is safe here for two
reasons specific to this design:

- Because grants are event-sourced, the tenant is a typed column on the event
  and the **projector** derives the FGA object id — so the prefix is constructed
  in exactly one place, tested once, rather than at every call site.
- The projections are tenant-partitioned with RLS, so a container returned from
  another tenant is dropped by the SQL join. The engine says "these
  containers"; Postgres says "and only in your tenant". The research design has
  a global store with **no RLS** and therefore no second line; this one has one.

What is given up: per-tenant model divergence, and the fact that any consumer's
type change rewrites the model all three share. Mitigation *(Claude's call)*:
namespace types per consumer — `cas_document`, `cogos_graph`, `ledger_entry` —
keep the model as a reviewed artifact in the repo, and compute the access delta
between model versions before applying one.

**Two query-side projections:**

- **The inverse index** — `(tenant_id, principal_id, container_id)`, maintained
  from the log. A plain indexed join rather than an array parameter, because
  `= ANY($huge)` degrades and `ListObjects` to produce it is the call OpenFGA
  warns about. This means a group membership change **does** touch rows, which
  the research claims to avoid — but it touches `principals × containers`, not
  `principals × resources`, and that is the whole asymmetry: measured at
  **433,063 rows / 37 MB against 106,495,540 rows / 10.9 GB** for the same
  containment. Per-principal over containers is affordable; over resources it is
  not, and the design forbids it.
- **The resource catalog** — one table every store writes into, carrying
  `tenant_id`, the container key, `store_type`, the resource id, searchable
  text, the embedding, timestamps and a pointer to the payload. Payloads stay in
  `cas`, `cogos` and `ledger`; only the searchable projection is shared.

### D8 — One tenant-partitioned Postgres. No FDW federation.

Forced by a product requirement: **global search spans `cas`, `cogos` and
`ledger` in a single ranked result list.** Fan out to three stores and correct
`ORDER BY … LIMIT` is lost — a true global top-50 needs 50 from each, deep
pagination degrades per store, and vector scores are not comparable unless all
three share one embedding model. Application-side merge is fine for a federated
list and not fine for ranked, paginated search.

With the catalog in the same database as the stores, a write lands in it in the
**same transaction**, so there is no staleness window.

**This answers cogos's O3 and retires its Universe-database-plus-`postgres_fdw`
proposal.** The reconciliation had already found two defects in that topology: a
`pgx.Tx` cannot span two databases, and cogos's FDW mapping is
`FOR CURRENT_USER` where `tenancy` does `SET LOCAL ROLE`, so the read fails.

## 3. The shape

```
            OIDC (Zitadel, others later)
                      │  verified claims
                      ▼
            ┌───────────────────┐
            │ identity registry │  principals, groups, external identities,
            │   (unchanged)     │  agent runs, deprovisioning
            └─────────┬─────────┘
                      │
  grant API ──────────┼──────────────────────────────┐
      │               │                              │
      ▼               ▼                              ▼
┌───────────────┐   the record                 ┌───────────────┐
│  es-lite log  │ ◄── append-only, encrypted   │ RLS backstop  │
│  THE RECORD   │                              │  (tenancy)    │
└───────┬───────┘                              └───────────────┘
        │ projector (holds keys)                       ▲
        ├──────────────► OpenFGA  (ReBAC read model)   │
        ├──────────────► inverse index ────────────────┤
        └──────────────► resource catalog ─────────────┘
                              │
                     one tenant-partitioned Postgres
```

## 4. The decision surfaces

- **`Decide`** — the point check. Already built and merged (#7): one term, allow
  iff a grant on the container or any ancestor names the principal or a live
  group of theirs. Measured server time ≈ **0.17 ms**, inside the spike's
  1.0–1.5 ms.
- **The residual** — a typed expression, never SQL text, rendered per backend.
  Built and merged (#7). An array of container ids is the simplest form and
  ports directly: `= ANY($1)` in Postgres, `$in` in Mongo, a partition-key
  restriction in Cassandra — which is the one that changes data modelling rather
  than translation, because CQL cannot express an arbitrary predicate.
- **The RLS backstop** — a restrictive policy ANDed with `tenancy`'s restrictive
  tenant predicate. Kept **even with a central PDP**, because the PEP can forget
  a clause and the database cannot be asked nicely. Two pieces of evidence from
  this week: the permissive-policy disclosure reproduced on CAS's own fixture (a
  tenant with one row saw two, the second another tenant's), and
  `CheckEnforcement` existing at all — because a superuser connection makes
  every policy inert while looking correct from Go.
- **Global search** — the hardest case, and already measured. Pushing the
  predicate inside the ANN index scan failed at **every** selectivity: no
  variant reached recall@20 0.95 anywhere, defaults scored **0.000** on
  adversarial queries at 0.1%, and tuning it into a full index walk cost **18
  seconds**. What works: pre-restrict by the container key, run the ANN inside
  that (0.955–0.962 at 1% and 0.1% with a per-partition HNSW; 1.000 in 5 ms with
  an exact scan over the pruned set). Two conditions carry forward — the exact
  predicate stays **mandatory** on top, because a key-only top-20 returned
  **9 unauthorized rows of 20**, so the key pre-filters and never authorizes;
  and the consumer chooses exact-versus-ANN **explicitly**, because the planner
  gets it wrong at 1% selectivity, scoring 0.100 where an exact scan over the
  same set scores 1.000.

## 5. What survives, and what is deleted

**Survives unchanged:** the identity registry in full — principals, external
subject resolution, claim-sourced group reconciliation, agent-run delegation
with TTL, and the deny-epoch deprovisioning cascade. OpenFGA has no concept of a
user; it replaces none of this.

**Survives from #7:** the typed residual and its Postgres policy renderer, the
per-tenant revision, `live_principals` and `live_group_members`, the
one-containment-parent refusal, and `Decide`'s shape.

**Deleted:** the hand-rolled containment closure and its maintenance, now
OpenFGA's job. The change log built in #7, now `es-lite`'s.

**Added:** the grant API and its event, the projector, the inverse index, the
resource catalog, the external-identity table, the FGA model as a reviewed
artifact.

## 6. Four things that must not be lost in the rewrite

Each was found by a test or a measurement, and OpenFGA solves none of them.

1. **The direct-grant deprovisioning leak, which OpenFGA cannot see.** #7 found
   that a deprovisioned principal stops matching *group* grants while still
   matching grants written to them *by name* — which passes every group-based
   test and leaks on exactly the grants a human chose to write. OpenFGA has no
   notion of a deprovisioned user, so this is reintroduced by default and must
   be closed at the registry/FGA boundary: filter the engine's answer through
   `live_principals`, or remove tuples on deprovision and accept the window.
2. **Containment must stay a tree.** An FGA model can express several parents,
   and the spike measured what that costs: union-of-paths `visible_below`
   exposed **2,356 containers** to a principal granted 1,000 facts of 10M and
   holding no grant on any; intersection-of-paths collapsed to `{tenant, graph}`
   every time; the canonical-container shortcut silently pruned **87% of a
   probe's authorized rows**. The model must constrain containment to one
   parent, and something must enforce it.
3. **The RLS backstop**, per §4.
4. **The consistency token**, now the log position per D6.

## 7. Deployment

- **Household** — one binary. OpenFGA's `pkg/server` is an ordinary Go struct
  whose methods are the full API, callable in-process with no gRPC server, no
  sidecar and no network hop, so "central" does not force a hop at this scale.
- **Enterprise** — the service plus an OpenFGA cluster, same code.

*(Claude's call)* Connect-Go for the service surface, matching the other
modules; the research's per-stage P99 budget as the target.

## 8. Open questions for the owner

1. **`es-lite`'s three forced consequences** (D6) — confirm the zero-knowledge
   consequence for auditors, accept the toolchain bump, and confirm
   workspace-maps-to-tenant.
2. **Separation of duties and recertification** (D2) — needed for the enterprise
   shape, not for the household. Phase them, or build the hooks now?
3. **The embedding model** — a single ranked list across three stores requires
   one shared embedding space. Which model, and who owns re-embedding when it
   changes?
4. **Retention of the grant log.** Point-in-time reconstruction is bounded by
   it. How long?

## 9. Findings still open

From `2026-10-23-iam-design.md` §17: **F4** (attribute-scoped rules) is now
*probably moot* — D1 removes conditions from the engine and cogos no longer
forces the question; CAS may, and it should be re-read against D1 before being
closed. **F8** (the audit unit on a filtered read) is **answered in part** by
D6: the grant log records every authorization *change*, but what to record for a
filtered read that makes no per-row decision and produces no denials is still
open. F1, F2, F3, F5, F6, F7 and F9 are resolved or closed; F5 and F6 were
closed by dropping OpenFGA and are **reopened by D7** in a different form — F5's
store-topology question is answered (one global store), F6's RLS and migration
conflict needs re-examining now that OpenFGA shares one Postgres.
