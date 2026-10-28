# Charter

## Mission

`iam` is the central identity-and-authorization library for the products in
the set. It answers four questions and nothing else:

- May this subject do this on this object?
- Who can see this object now, and who granted that?
- Who could see it at time T?
- Can every derived answer be rebuilt from the record?

It is consumer-agnostic. Content, catalogs, search, embeddings, tools,
approval workflows and action payloads belong to the products.

## The record is the log

An append-only event log is the authority. Commands validate against the
published kind model and the actor's authority, then append typed events. A
projector is the only writer to the relation engine and the read models.
Replaying the log reproduces them.

The record carries actor, command, correlation, causation, occurred-at,
recorded-at, and the model version the event was validated against.
Authorization facts carry `granted_by` and `reason`, so provenance is in the
record by construction.

## What IAM owns

- Tenants, their single root, and tenant-prefixed URNs.
- Kinds, containment and the published model.
- Nodes, grants, groups and principal liveness.
- Checks, reverse queries and projections.
- The `Sealer` port and its key lifecycle. IAM handles DEKs in memory; OpenBao
  holds the KEK, and IAM never stores it.

## What IAM does not own

- Identity. Zitadel supplies verified users and machine users; IAM mirrors
  only liveness and the stable URN.
- Resource metadata, content, search text and embeddings.
- Tool execution, approval state, notifications and action payloads.
- Credentials, attributes or PII.

IAM makes the decision; the application runs the workflow.

## Invariants

1. **The log is the record.** Nothing writes the engine outside the projector.
2. **Containment is a tree.** One parent, same tenant; deleted URNs are
   retired and never reused.
3. **Tenant isolation is structural.** Every URN is tenant-prefixed and
   validated. The Postgres read models use tenant RLS under a tenant-scoped
   role.
4. **No deny, no read-time attributes.** There is no exclusion, negative
   grant, classification gate or condition. A subject either has a grant or
   does not.
5. **Deprovisioning is closed on every arm.** Effective liveness gates direct
   grants, group grants and inherited grants alike. Deactivation is reversible;
   deletion is terminal and removes the subject's edges.
6. **Agents never share.** `owner` excludes agents, and `can_share` is denied
   to an agent actor. `can_delete` is direct, non-inheriting and owner-granted.
7. **Event payloads are ciphertext; metadata is not.** A per-tenant-version
   DEK encrypts payloads; OpenBao holds the KEK; a missing key fails closed.
8. **Staleness fails closed.** Reads and writes share a bounded staleness
   window; a caller that needs read-your-writes passes the revision.
9. **No panic and no `fmt.Print*` in library code.** Errors are typed
   sentinels; logging belongs to the caller.

## Public surface

`api.txt` is generated from the source and checked by `TestAPIGolden`.
Growing it is a reviewed diff, shrinking it is a breaking change. The facade
re-exports domain and core types as aliases and forwards constructors; it
carries no logic.

`iamtest.RunSuite` is the adoption contract. An adapter demonstrates
adoption by passing the suite unchanged, not by asserting that it does.

## Ports and shared modules

The library depends on ports, not products:

- `EventLog` -> es-lite in deployment; the memory log is the reference.
- `Engine` -> OpenFGA in deployment; the memory engine is the reference.
- `Sealer` -> `seal` for payload encryption and `keyring` for DEK wrapping,
  with OpenBao Transit as the production key manager.
- Postgres read models -> `pgmigrate` for owned migrations and `tenancy` for
  tenant-scoped connections and RLS.
- `audit` carries the service's hash-chained audit trail; `meter` records
  usage where a product adopts it. Neither replaces the IAM log.

Shared modules improve independently and are consumed at their tagged
versions. The core must not grow a dependency on a product to avoid one
import.

## Roadmap

- **Plan 1, current:** the in-memory core, facade and conformance suite.
- **Plan 2:** agents, supervision, maturity, delegation, HITL and
  `AuthorizeAction`.
- **Plan 3:** es-lite, sealing, Postgres read models, OpenFGA, consistency and
  rebuild.
- **Plan 4:** the CAS row-level SQL join.
- **Plan 5:** the Connect-Go service, tenant service credentials and
  deployment.

## Deliberately absent

Conditions and deny; per-tenant engines and models; resource catalogs;
tool execution and approval state; link sharing, ownership transfer,
expiring access and nested groups; re-parenting; per-run agent principals;
Zitadel roles as authorization input; credentials and PII; log compaction.
