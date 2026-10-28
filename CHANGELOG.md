# Changelog

All notable changes to `iam` are recorded here. The format is human-readable;
versions follow SemVer with the pre-1.0 rule that a minor release may break the
API. See `UPGRADING.md` for the migration steps.

## Unreleased

This is the central IAM rewrite. It replaces the v0.3.0 identity-registry API
outright; there are no live consumers and no data to migrate.

### Breaking changes

- **The registry/identity API is replaced by the event-sourced IAM facade.**
  `Registry`, `RegistryConfig`, `NewMemoryRegistry`, `NewPostgresRegistry`,
  `Claims`, `ExternalSubject`, `ParseExternalSubject`, `PrincipalID`,
  `NewPrincipalID`, `ParsePrincipalID`, `GroupID`, `NewGroupID`,
  `ParseGroupID`, `Membership`, `AgentRunSpec`, the `PrincipalKind*`,
  `PrincipalState*` and `GroupSource*` values, and `Canonical` are removed.
  Consumers bootstrap a tenant and use `RegisterNode`, `Grant`, `Check`,
  `ListObjects` and `ListSubjects` through the facade instead.
- **The Postgres migration API is removed.** `MigrateUp`, `MigrationStatus`,
  `Migration` and the `db/migrations` package are gone. Plan 1 is the
  in-memory reference core; durable migrations arrive with the plan-3
  Postgres adapter.
- **Conditions and identity-provisioning helpers are removed.**
  `PrincipalCondition`, `EvaluateCondition`, `IssuerPolicy`,
  `NewStaticIssuerPolicy`, `StaticIssuerPolicy`, `JITProvisioner`,
  `NewJITProvisioner`, `Provisioner`, `KeySet`, `KeySource` and
  `StubKeySource` are gone. Identity lifecycle is represented by the
  `LinkPrincipal`, `DeactivatePrincipal`, `ReactivatePrincipal` and
  `DeletePrincipal` commands.
- **The old errors are removed.** `ErrAgentRunExpired`,
  `ErrCapabilityUnconfigured`, `ErrInvalidClaims`, `ErrInvalidConfig`,
  `ErrInvalidExternalSubject`, `ErrInvalidPrincipal`,
  `ErrIssuerNotRegistered`, `ErrMalformedID`, `ErrPrincipalDeprovisioned`,
  `ErrPrincipalNotFound`, `ErrResyncRequired` and `ErrUnavailable` are
  replaced by the typed sentinels on the new facade.
- **The example packages are removed.** `examples`, `examples/agents`,
  `examples/discretionary`, `examples/household`, `examples/scenario` and
  `examples/unexpressible` are not part of the new module.
- **The registry conformance suite is removed.** `iamtest.RunRegistrySuite`,
  `iamtest.NoSecretLeaksInAnyRendering` and
  `iamtest.RendersOnlyARedactionMarker` are replaced by
  `iamtest.RunSuite`, which exercises the facade only.
- **The module floor moves to Go 1.26.5.** The previous module required Go
  1.25.6.

### Added

- The in-memory central IAM core: tenants and their single root, kinds and
  model publication, nodes and containment, grants and revocation, checks,
  groups, user principals with tenant/global liveness, reverse queries, the
  public facade, the adoption conformance suite, `scripts/api-diff.sh`,
  `CHANGELOG.md` and `UPGRADING.md`.
- The transport-independent `iam.Service` contract, split into `Reader`,
  `Writer`, `PrincipalResolver`, `IdentityAdmin` and `TenantProvisioner`, and
  `ResolvePrincipal` for external-identity resolution.
- A release workflow that runs the normal gate and `gorelease` on a tagged
  commit.

### Tooling and docs

- **The `api.txt` golden-file gate is removed**, along with
  `TestAPIGolden` and the old `-update-api` generator. Compatibility is now
  checked with `apidiff` against the last root tag (`mise run api-diff`) and
  validated at release time with `gorelease`. Internal packages are not part
  of the compatibility contract.
- `mise run check` now includes `fmt-check`, `lint`, `build`, `test-all`,
  `generate-check`, `vuln` and `api-diff`. The release-only `gorelease` check
  is `mise run release-check`.
- CI checks out full tags (`fetch-depth: 0`) and runs `mise run check`; the
  old per-tool workflow steps and golden-file step are gone.
- The release workflow publishes the root module only. The nested F3 spike
  under `docs/superpowers/spikes` is a throwaway module and is never released.
- The public-surface guidance in `CHARTER.md`, `CONVENTIONS.md` and `README.md`
  now describes `apidiff`/`gorelease` instead of a generated golden file.

## v0.3.0

- Previous published identity-registry API, superseded by the central IAM
  rewrite above.
