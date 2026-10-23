# iam

[![ci](https://github.com/laenenai/iam/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/iam/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/iam.svg)](https://pkg.go.dev/github.com/laenenai/iam)

Who exists, what groups they are in, and what they are allowed to do —
answerable **inside a SQL query**.

Authorization for systems where the answer has to filter ten million rows in
the same statement as a vector search, not one row at a time.

> **Status: pre-1.0, and incomplete in a way worth reading before you adopt
> it.** The identity registry is implemented and tested against real Postgres.
> **The decision API (`Decide`, `Predicate`) is not built yet.** Three open
> findings are tracked in the design document's §17 — F3 (DAG containment), F4
> (attribute granularity) and F8 (the audit unit on the predicate path) — and
> two of them can still change the public API: F3, and F1's resolution which
> depends on it. The count was eight; four closed by deletion and one resolved
> when the deny mechanism and the third-party engine were removed on
> 2026-10-23. The `examples/` corpus marks which use cases work today, which
> are pending, and which the design currently cannot express at all.

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

## There is no deny mechanism

This is the thing to know before adopting it, and it is a decision rather than
a gap. `iam` has two tiers:

| Tier | Mechanism | Survives |
|---|---|---|
| **Discretionary** | relation tuples, usersets, inheritance, default-deny | nothing in particular — it is the everyday shareable, revocable layer, and the only thing that decides |
| **Cryptographic** | a key the deployment does not hold (`escrow`) | the administrator, the operator, a subpoena, a stolen backup, every future policy change |

The decision is `discretionary_allows` and nothing else, which is what makes
the whole decision a single SQL predicate: there is no live, unprojectable
second term a compiled fragment would have to be conjoined with.

So there are exactly **two honest strengths of "no"**:

- **"She may not see this"** → do not grant it. The absence of a grant is the
  only thing that refuses, and it is liftable by anyone who may share — which
  for a private letter or a household invoice is the property the owner
  actually asked for.
- **"Nobody may ever see this, whatever rule ever happens"** → a key the
  deployment does not hold. `iam` records one field, the marking's enforcement
  class; `keyring` holds the wrapping and `escrow` holds the shares.

There is nothing in between, and a middle option is not coming.

**Why, briefly.** There used to be a mandatory tier — classifications on
resources, clearances on principals, administered by a security function — and
it was the tier the module existed for. Two things killed it. A classification
*is* a deny, and a deny administered by policy is only as absolute as whoever
administers the policy: the `examples/` corpus demonstrated against the real
registry that any principal could perform the administering act, because "who
may classify" was never decided. And routing ordinary privacy through it turned
every preference into an absolute no owner could lift, while making
classification *assignment* cardinality the system's actual performance problem
— the measured gate turned a 0.46 ms query into 296 ms against a
closure join of 0.006 ms per row.

The general lesson, recorded in the design document: the design anchored on
"this principal may never see this", a rare case, and made it the template for
the common one.

**What this costs, stated plainly.** A legal conflict screen has no policy
mechanism: it is a matter outside the firm-wide container that nothing names
the screened principal on, and it survives nobody — anyone who may share the
matter can share it tomorrow. Privacy inside a shared container becomes grant
granularity, so a household writes one grant per episode rather than one per
graph. And one `kgs` leak channel is worse rather than unchanged: sending
content to a hosted model had two independent guards and now has one. The
`examples/` corpus carries each of these as a scenario that says so.

## What it does not do

Capability tokens, key material, connection pooling and tenant routing, audit
storage — each is a separate module. It is not an identity provider, and not a
policy-as-code engine.

## Documentation

- `docs/superpowers/specs/` — the design, including §17's findings register
- [`examples/`](examples) — 18 declarative use cases with READMEs, and `UNEXPRESSIBLE.md` for what the design cannot currently express and what each gap would cost
- [`CHARTER.md`](CHARTER.md) · [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
