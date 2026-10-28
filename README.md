# iam

[![ci](https://github.com/laenenai/iam/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/iam/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/iam.svg)](https://pkg.go.dev/github.com/laenenai/iam)

Central identity and authorization for every product in the set: users,
agents, groups, resources, and the relationships between them. The authority
is an append-only event log; the relation engine and every query surface are
derived from it.

> **Status: pre-1.0, plan 1 of 5.** The in-memory core is implemented and
> tested: tenants and their single root, kinds, nodes, grants, groups, user
> principals, the event log record, a projector, a reference relation engine,
> checks, reverse queries, the public facade, and the conformance suite.
> Durable adapters, agents, supervision, HITL, Postgres, OpenFGA, sealing and
> the service are later plans. The in-memory core is the reference contract
> the adapters must satisfy, not a deployment target.

## Install

```
go get github.com/laenenai/iam
```

Requires Go 1.26.5. No cgo.

## Quick start

```go
svc, err := iam.NewMemory(ctx, iam.Config{})
if err != nil {
	return err
}

deploymentAdmin := iam.Actor{ID: "operator", Role: iam.RoleDeploymentAdmin}
owner, _ := iam.NewUserSubject("laenen", "u1")
tenant, err := svc.CreateTenant(ctx, deploymentAdmin, iam.CreateTenantRequest{
	Tenant:     "laenen",
	RootID:     "root",
	FirstOwner: owner,
})
if err != nil {
	return err
}

identityAdapter := iam.Actor{ID: "identity", Role: iam.RoleIdentityAdapter}
if _, err := svc.LinkPrincipal(ctx, identityAdapter, iam.LinkPrincipalRequest{
	Tenant:     "laenen",
	Issuer:     "zitadel",
	ExternalID: "user-1",
	Subject:    owner,
}); err != nil {
	return err
}

ownerActor := iam.Actor{ID: "user-1", Tenant: "laenen", Role: iam.RoleUser, Subject: owner}
folder, err := svc.RegisterNode(ctx, ownerActor, iam.RegisterNodeRequest{
	Tenant: "laenen",
	URN:    "laenen/folder/home",
	Parent: tenant.Root,
})
if err != nil {
	return err
}

decision, err := svc.Check(ctx, ownerActor, iam.CheckRequest{
	Tenant:   "laenen",
	Subject:  owner,
	Object:   folder.Node.URN,
	Relation: iam.Owner,
})
if err != nil {
	return err
}
if !decision.Allowed {
	return fmt.Errorf("owner check denied: %s", decision.Reason)
}
```

A node's creator becomes its owner. Owner inherits down the tree and implies
`can_share`; `can_delete` is a separate, non-inheriting grant. Agents never
hold `owner` or `can_share`.

## The model

- One node type, tenant-prefixed URNs (`<tenant>/<kind>/<id>`), one parent.
- One root per tenant, created only by `CreateTenant`.
- Kinds are deployment data: they declare containment and the four base
  relations (`owner > editor > commenter > viewer`).
- `can_delete` is the only global relation. It does not inherit, and only an
  owner may grant it.
- Groups are flat and human-only; a group grant is a `group#member` userset.
- Deactivation is reversible and keeps tuples; deletion is terminal and
  removes them. Every read filters through subject and node liveness.
- There is no deny, no classification, and no read-time attribute.

## Reuse and boundaries

The core depends on ports, not products:

| Port / seam | Plan-3 adapter | Shared module |
|---|---|---|
| `EventLog` | es-lite workspace log | `github.com/laenenai/es-lite` |
| `Engine` | OpenFGA | `openfga` |
| `Sealer` | per-tenant DEK, OpenBao KEK | `github.com/laenenai/seal` + `github.com/laenenai/keyring` |
| Postgres read models | tenant-partitioned RLS | `github.com/laenenai/pgmigrate` + `github.com/laenenai/tenancy` |
| Service audit trail | hash-chained audit log | `github.com/laenenai/audit` |
| Metering | usage ledger, where adopted | `github.com/laenenai/meter` |

The record stays the IAM log. Audit and metering observe it; they do not
replace it. None of these adapters is a dependency of the in-memory core.

## Layout

```
iam.go                 public facade: aliases and constructors only
iamtest/               adoption conformance suite
internal/domain/       URNs, subjects, relations, events, aggregates
internal/eventlog/     append-only log port and memory adapter
internal/engine/       relation engine port and reference engine
internal/projector/    log -> read model + engine
internal/core/         commands, checks, reverse queries, wiring
scripts/api-diff.sh    apidiff against the last root tag
```

## Docs and roadmap

- Design: `docs/superpowers/specs/2026-10-27-central-iam-design.md`
- Plan 1: `docs/superpowers/plans/2026-10-27-central-iam-core.md`
- Charter: `CHARTER.md`

Plan 2 adds agents, supervision, maturity, delegation, HITL and
`AuthorizeAction`. Plan 3 adds es-lite, the `Sealer`/OpenBao, Postgres read
models, the OpenFGA projector, consistency and rebuild. Plan 4 adds the CAS
SQL join. Plan 5 adds the Connect-Go service, tenant service credentials and
deployment.
