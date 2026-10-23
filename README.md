# iam

[![ci](https://github.com/laenenai/iam/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/iam/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/iam.svg)](https://pkg.go.dev/github.com/laenenai/iam)

Who exists, what groups they are in, and what they are allowed to do —
answerable **inside a SQL query**.

Authorization for systems where the answer has to filter ten million rows in
the same statement as a vector search, not one row at a time.

> **Status: pre-1.0, and incomplete in a way worth reading before you adopt
> it.** The identity registry is implemented and tested against real Postgres.
> **The decision API (`Decide`, `Predicate`) is not built yet**, and eight open
> findings — two of which can still change the public API — are tracked in the
> design document's §17. The `examples/` corpus marks which use cases work
> today, which are pending, and which the design currently cannot express at
> all.

## Install

```
go get github.com/laenenai/iam
```

Requires Go 1.25.6, and Postgres 17+ for the Postgres registry. No cgo.

## Example

```go
reg, err := iam.NewPostgresRegistry(pool, iam.RegistryConfig{StalenessBound: time.Hour})
if err != nil {
	return err
}

// Identity arrives from the IdP and is upserted on sight, never passed
// through as claims: group membership has to be joinable in SQL.
p, err := reg.UpsertFromClaims(ctx, iam.Claims{
	TenantID: tenantID,
	Subject:  iam.ExternalSubject{Issuer: "https://issuer.example", Subject: "subject-7"},
	Kind:     iam.PrincipalKindUser,
	Groups:   []string{"engineering"},
})
if err != nil {
	return err
}

// Group membership is read as of an instant, because a principal staler
// than the deployment's bound must be re-synced before it is trusted.
groups, err := reg.GroupsOf(ctx, p.ID, time.Now())
```

## Three enforcement tiers, deliberately not one

| Tier | Mechanism | Survives |
|---|---|---|
| **Discretionary** | relation tuples, usersets, inheritance | the everyday shareable, revocable layer |
| **Mandatory** | classifications on resources, clearances on principals | any grant, any owner, any admin, any future discretionary rule |
| **Cryptographic** | a key the system does not hold | the administrator, the operator, a subpoena, every future policy change |

The decision is `mandatory_gate AND discretionary_allows`, so **deny-wins is
structural** rather than a rule anyone has to remember to write in forty
places. The third tier is not part of the decision at all: this module records
that a classification is crypto-enforced, and something else holds the key.

**Why absolutes are not relation tuples.** In every Zanzibar-descended engine,
exclusion is *local to the permission definition where it is written* — so an
absolute would have to be repeated on every permission of every resource type
and remembered for each new one, where a single omission is a silent bypass.
Exclusion is also the one operator that cannot be precomputed into a closure,
which would forfeit the predicate this module exists to produce. The one mature
open-source ReBAC-over-a-hierarchy implementation has no deny mechanism at all.

## A security gap you should know about

Clearance-group membership is enforced to move only through a mandatory channel
— the type system makes a clearance write impossible to perform *accidentally*
or as a side effect of sharing. **What is not yet enforced is the actor's
authority** on that channel, so an ordinary principal can construct a mandatory
act naming themselves and join a clearance group. That is finding F9, it is
blocked on an unanswered design question, and the `examples/` corpus
demonstrates it against the real registry rather than describing it.

Until it is closed, the mandatory scenarios assert only that no *discretionary*
operation opens a gate, which is narrower than the design reads as claiming.

## What it does not do

Capability tokens, key material, connection pooling and tenant routing, audit
storage — each is a separate module. It is not an identity provider, and not a
policy-as-code engine.

## Documentation

- `docs/superpowers/specs/` — the design, including §17's findings register
- [`examples/`](examples) — 26 declarative use cases with READMEs, and `UNEXPRESSIBLE.md` for what the design cannot currently express and what each gap would cost
- [`CHARTER.md`](CHARTER.md) · [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
