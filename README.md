# iam

[![ci](https://github.com/laenenai/iam/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/iam/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/iam.svg)](https://pkg.go.dev/github.com/laenenai/iam)

Who exists, what groups they are in, and what they are allowed to do —
answerable **inside a SQL query**.

Authorization for systems where the answer has to filter ten million rows in
the same statement as a vector search, not one row at a time.

> **Status: pre-1.0, and smaller than the design document describes — on
> purpose.** The identity registry and the authorization layer are both
> implemented and tested against real Postgres, each with a conformance suite
> a consumer runs against its own wiring.
>
> What exists is **membership on containers, inherited down a tree**: a
> subject — a principal or a group — holds a permission on a container, and
> everything the container contains inherits it. `Decide` is the point check.
> A typed *residual* is the filtered-read surface, which a consumer renders
> into a restrictive row-level-security policy.
>
> What that is **not** is a Zanzibar engine. There are no arbitrary relation
> tuples, no usersets of usersets, no `X from Y`, no union over relations, no
> roles as objects, and no bottom-up navigational visibility. Four decisions
> removed most of what that machinery was for: no deny mechanism (2026-10-23),
> no third-party engine (2026-10-23), containment is a tree (F3, 2026-10-24),
> and the consumer's model settled on privacy-by-placement (2026-10-25).
> `internal/authz`'s package doc names each absence as a decision and says
> what it costs.
>
> **`Predicate`'s filtered-read contract is still unbuilt**, because finding
> F4 is open and it moves the return shape: either the authority hands back a
> permitted-*attribute* set the consumer applies — pushing part of the trust
> boundary into consumer code — or `iam` becomes a query rewriter across three
> query builders. Two open findings are tracked in the design document's §17:
> F4, and F8 (the audit unit on the filtered-read path). The count was eight;
> four closed by deletion and two resolved. The `examples/` corpus marks which
> use cases run against the real module today, which are pending, and which
> the design cannot express at all.

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

## Authorization: membership on containers, inherited down a tree

A consumer declares its containment tree once, places its resources in
containers, and stores one scalar column per row naming the container that row
lives in. That column is the whole of what it adds to its own schema.

```go
az, err := iam.NewPostgresAuthorizer(pool, iam.AuthorizerConfig{})
if err != nil {
	return err
}

// The declaration. A kind naming two containment parents is refused
// outright: the closure a decision reads is keyed on the *container*,
// which is what keeps it bounded by hierarchy depth rather than by how
// many resources exist.
if err := az.RegisterSchema(ctx, iam.Schema{
	Name:        "cogos",
	Version:     1,
	Kinds:       []iam.ContainerKind{
		{Name: "world"},
		{Name: "scope", Parents: []string{"world"}},
		{Name: "topic", Parents: []string{"scope"}},
	},
	Permissions: []iam.Permission{"read"},
}); err != nil {
	return err
}

// One grant on a container reaches everything inside it, at one row per
// share rather than one per resource. The subject may be a group, and
// then a membership change takes effect with no grant rewritten.
if _, err := az.Grant(ctx, iam.GrantSpec{
	TenantID:   tenantID,
	Container:  scope.ID,
	Permission: "read",
	Subject:    iam.GroupSubject(household.ID),
}); err != nil {
	return err
}

// The point check.
d, err := az.Decide(ctx, iam.Request{
	TenantID:   tenantID,
	Principal:  p.ID,
	Permission: "read",
	Container:  topic.ID,
})
// d.Allowed, d.Reason ("inherited"), d.Via (the grant responsible),
// d.Depth (how many hops up), d.Revision (the state it was computed at).
```

### The filtered read is a residual, not a string of SQL

`Filter` returns a typed expression, and a per-backend renderer turns it into
that backend's query language. SQL text never crosses the port, because a
consumer holding the string would make a second storage backend a breaking
change for all of them rather than a new renderer here — which is where OPA's
partial evaluation and Oso's data filtering both landed. Cassandra is the
known hard case and it is not a translation problem: CQL filters only on a
partition key and a clustering prefix, so there the containment key has to
*be* part of the table's key.

```go
residual, err := az.Filter(ctx, iam.FilterRequest{
	TenantID:   tenantID,
	Principal:  iam.SessionPrincipal(), // a policy is evaluated for every principal
	Permission: "read",
	Key:        iam.Key{Qualifier: "tenant_quads", Column: "graph_id"},
})
using, err := iam.RenderPostgresPolicy(residual)
// CREATE POLICY quad_read ON tenant_quads AS RESTRICTIVE USING (<using>);
```

`AS RESTRICTIVE` is not optional. Postgres OR-s permissive policies together
and AND-s restrictive ones on top, so a permissive authorization policy is
OR-ed away by any later permissive policy on the same table — which is how a
tenant predicate written that way became a measured cross-tenant disclosure in
this project on 2026-10-23. Restrictive composes with `tenancy`'s restrictive
tenant predicate on the same table: both in the database, neither widenable,
and a hand-written statement escapes neither.

The failure mode is **zero rows, never an error**. A session with no principal
context, or a malformed one, matches nothing and raises nothing — so there is
no existence oracle and no statement broken instead of filtered.

The role that evaluates the policy needs `USAGE` on the `iam` schema and
`SELECT` on five relations; `RenderPostgresPolicy`'s doc comment lists them
and flags the one worth looking at twice, because `iam.principals` carries no
row-level-security policy of its own yet.

## There is no deny mechanism

This is the thing to know before adopting it, and it is a decision rather than
a gap. `iam` has two tiers:

| Tier | Mechanism | Survives |
|---|---|---|
| **Discretionary** | grants on containers, group subjects, inheritance down the tree, default-deny | nothing in particular — it is the everyday shareable, revocable layer, and the only thing that decides |
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
  class — and, today, not even that: markings are unbuilt, so a consumer
  cannot yet ask this module *why* content is unreadable. `keyring` holds the
  wrapping and `escrow` holds the shares.

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
- `internal/authz`'s package doc — what the authorization layer is, and every absence named as a decision
- [`CHARTER.md`](CHARTER.md) · [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
