# Upgrading

`iam` is pre-1.0: a minor release may break the API. This file records the
steps for the central IAM rewrite, which supersedes the v0.3.0 identity
registry.

## From v0.3.0 to the central IAM rewrite

This is a rewrite, not an incremental API change. The old module answered
identity-registry questions; the new module answers authorization questions
from an event-sourced grant log. There are no live consumers and no data to
migrate.

### 1. Replace the registry entry points

`Registry`, `RegistryConfig`, `NewMemoryRegistry`, `NewPostgresRegistry`,
`Claims`, `ExternalSubject`, `ParseExternalSubject`, `Membership`,
`AgentRunSpec`, `PrincipalID`, `NewPrincipalID`, `ParsePrincipalID`,
`GroupID`, `NewGroupID`, `ParseGroupID`, `NewTenantID`, `Canonical`,
`PrincipalKindUser`, `PrincipalKindService`, `PrincipalKindAgentRun`,
`PrincipalStateUsable`, `PrincipalStateExpired`,
`PrincipalStateResyncRequired`, `PrincipalStateDeprovisioned`,
`PrincipalStateUnknown`, `GroupSourceClaim` and `GroupSourceLocal` are
removed.

The replacement is the facade:

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

identity := iam.Actor{ID: "identity", Role: iam.RoleIdentityAdapter}
if _, err := svc.LinkPrincipal(ctx, identity, iam.LinkPrincipalRequest{
	Tenant:     "laenen",
	Issuer:     "zitadel",
	ExternalID: "user-1",
	Subject:    owner,
}); err != nil {
	return err
}

ownerActor := iam.Actor{ID: "user-1", Tenant: "laenen", Role: iam.RoleUser, Subject: owner}
if _, err := svc.RegisterNode(ctx, ownerActor, iam.RegisterNodeRequest{
	Tenant: "laenen",
	URN:    "laenen/folder/home",
	Parent: tenant.Root,
}); err != nil {
	return err
}
```

Subjects now use URNs (`<tenant>/user/<id>`, `<tenant>/agent/<id>`,
`<tenant>/group/<id>`) instead of separate principal, group and agent-run ID
types.

### 2. Replace the migration API

`MigrateUp`, `MigrationStatus`, `Migration` and the
`github.com/laenenai/iam/db/migrations` package (also reported as
`package github.com/laenenai/iam/db/migrations`) are removed. Plan 1 has no
Postgres schema; the durable read models and their embedded migrations arrive
with the plan-3 Postgres adapter. Do not import the old migration package or
run the old migrations against an existing database.

### 3. Remove conditions and identity-provisioning helpers

`PrincipalCondition`, `EvaluateCondition`, `IssuerPolicy`,
`NewStaticIssuerPolicy`, `StaticIssuerPolicy`, `JITProvisioner`,
`NewJITProvisioner`, `Provisioner`, `KeySet`, `KeySource` and
`StubKeySource` are removed.

Identity lifecycle is now explicit:

- link with `LinkPrincipal`;
- change liveness with `DeactivatePrincipal` / `ReactivatePrincipal`;
- offboard with `DeletePrincipal`;
- authorization changes with `Grant` / `Revoke`.

There are no conditions, deny rules or read-time attributes. A subject either
holds a grant or does not.

### 4. Replace the conformance suite

`iamtest.RunRegistrySuite`, `iamtest.NoSecretLeaksInAnyRendering` and
`iamtest.RendersOnlyARedactionMarker` are removed. The adoption suite is now
`iamtest.RunSuite`, which runs through the facade only:

```go
iamtest.RunSuite(t, func(t *testing.T) *iam.IAM {
	svc, err := iam.NewMemory(context.Background(), iam.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
})
```

### 5. Replace the examples

The `examples`, `examples/agents`, `examples/discretionary`,
`examples/household`, `examples/scenario` and `examples/unexpressible`
packages are removed, reported as `package github.com/laenenai/iam/examples`,
`package github.com/laenenai/iam/examples/agents`,
`package github.com/laenenai/iam/examples/discretionary`,
`package github.com/laenenai/iam/examples/household`,
`package github.com/laenenai/iam/examples/scenario` and
`package github.com/laenenai/iam/examples/unexpressible`. The README quick start and `iamtest.RunSuite` are the
current usage corpus.

### 6. Replace the old errors

The following sentinels are removed: `ErrAgentRunExpired`,
`ErrCapabilityUnconfigured`, `ErrInvalidClaims`, `ErrInvalidConfig`,
`ErrInvalidExternalSubject`, `ErrInvalidPrincipal`,
`ErrIssuerNotRegistered`, `ErrMalformedID`, `ErrPrincipalDeprovisioned`,
`ErrPrincipalNotFound`, `ErrResyncRequired` and `ErrUnavailable`.

Use the new typed sentinels, principally `ErrInvalidActor`,
`ErrInvalidSubject`, `ErrInvalidURN`, `ErrInvalidRelation`, `ErrInvalidKind`,
`ErrNotFound`, `ErrConflict`, `ErrForbidden`, `ErrUnauthorized`,
`ErrUnsupported`, `ErrModelNotProjected` and `ErrIDGeneration`. Check errors
with `errors.Is`; do not string-match.

### 7. Raise the Go version

The module now requires Go 1.26.5, up from 1.25.6. Update the toolchain before
building.

### 8. Replace the golden-file task with compatibility tooling

The `api.txt` golden file, `TestAPIGolden` and the old `-update-api` generator
are removed. The old `api` task no longer exists.

Use:

```bash
mise run api-diff        # apidiff against the last root tag; pre-1.0 reports
mise run release-check   # gorelease; run from a clean checkout/tag
mise run check           # fmt, lint, build, race, generate-check, vuln, api-diff
```

`apidiff` compares the importable API and ignores `internal/...`. Before 1.0,
incompatible changes are reported and must be recorded here and in
`CHANGELOG.md`; at 1.0 and later they fail the gate. Do not reintroduce a
checked-in API snapshot.

The release workflow runs the normal gate and `gorelease` on a `vX.Y.Z` tag.
Only the root module is published; the nested F3 spike under
`docs/superpowers/spikes` is a throwaway module and must not be tagged or
released.
