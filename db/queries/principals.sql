-- principals.sql holds every static statement this module runs against
-- iam.principals: the JIT upsert, the two lookup paths, agent-run
-- delegation and collection, and the deprovisioning cascade.
--
-- The reasoning for each statement lives here rather than in the Go that
-- calls it, because the statement is the artifact being reasoned about.
-- db/migrations/00002_identity.sql holds the schema's own reasoning, and
-- internal/registry/pgregistry documents which of these the port's
-- contract depends on.

-- name: UpsertPrincipalFromClaims :one
-- One statement covers both first sight and refresh. The id is bound only
-- for the INSERT branch: a conflict keeps the stored id, which is what
-- makes re-issuing an external identity leave every grant and audit row
-- pointing at the same principal.
--
-- The DO UPDATE's WHERE clause is the deprovisioning guard: a conflict on
-- a deprovisioned row updates nothing and returns no rows, so a fresh
-- token for a deprovisioned subject cannot revive it. Doing this in the
-- statement rather than after a read closes the window in which a
-- concurrent deprovisioning lands between the two.
--
-- synced_at is bound once and used for created_at as well: at first sight
-- the two instants are the same, and on a refresh created_at is not
-- touched.
INSERT INTO iam.principals (id, tenant_id, kind, display_name, issuer, subject, synced_at, created_at)
VALUES (
    sqlc.arg(id),
    sqlc.arg(tenant_id),
    sqlc.arg(kind),
    sqlc.arg(display_name),
    sqlc.arg(issuer),
    sqlc.arg(subject),
    sqlc.arg(synced_at),
    sqlc.arg(synced_at)
)
ON CONFLICT (tenant_id, issuer, subject) WHERE issuer <> ''
DO UPDATE SET
    kind = EXCLUDED.kind,
    display_name = EXCLUDED.display_name,
    synced_at = EXCLUDED.synced_at
WHERE principals.deprovisioned_at IS NULL
RETURNING *;

-- name: PrincipalByExternalSubject :one
-- The (issuer, subject) key, which is a unique key with id as its value
-- and never the other way round (design §8.1).
SELECT * FROM iam.principals
WHERE tenant_id = sqlc.arg(tenant_id)
  AND issuer = sqlc.arg(issuer)
  AND subject = sqlc.arg(subject);

-- name: PrincipalByID :one
SELECT * FROM iam.principals WHERE id = sqlc.arg(id);

-- name: CreateAgentRun :one
-- The run inherits its parent's tenant and nothing else: no group
-- membership and no clearance. Delegation is a discretionary act, and a
-- discretionary act that conferred a clearance would breach anti-goal A3.
INSERT INTO iam.principals
    (id, tenant_id, kind, display_name, delegated_by, expires_at, synced_at, created_at)
VALUES (
    sqlc.arg(id),
    sqlc.arg(tenant_id),
    'agent-run',
    sqlc.arg(display_name),
    sqlc.arg(delegated_by)::iam.ulid,
    sqlc.arg(expires_at)::timestamptz,
    sqlc.arg(synced_at),
    sqlc.arg(synced_at)
)
RETURNING *;

-- name: CollectExpiredAgentRuns :execrows
-- Memberships go with the principal through ON DELETE CASCADE; the
-- clearance trail does not, because its principal_id is deliberately not a
-- foreign key — the record of what a run was cleared for must outlive the
-- run (see 00002_identity.sql).
DELETE FROM iam.principals
WHERE kind = 'agent-run'
  AND expires_at IS NOT NULL
  AND expires_at <= sqlc.arg(as_of)::timestamptz;

-- name: DeprovisionPrincipalAndAgentRuns :exec
-- One statement marks the principal and cascades to its live agent runs.
-- Deprovisioning a user whose agents keep running with the authority she
-- delegated to them has not denied anything, and an agent run is
-- deliberately not subject to the staleness bound, so nothing else would
-- ever catch it. One level deep, since a run may not delegate a run.
--
-- `deprovisioned_at IS NULL` makes it idempotent in SQL as well as in Go:
-- an already-deprovisioned row keeps the instant access actually stopped
-- rather than having it rewritten.
--
-- Memberships are left in place: they stop matching at once because
-- iam.live_group_members excludes a deprovisioned principal, and keeping
-- the rows is what lets audit explain what the principal had access to.
--
-- The cascade half probes principals_delegated_by_idx, which exists for
-- exactly this statement.
UPDATE iam.principals
SET deprovisioned_at = sqlc.arg(deprovisioned_at)::timestamptz
WHERE deprovisioned_at IS NULL
  AND (
      id = sqlc.arg(id)
      OR (kind = 'agent-run' AND delegated_by = sqlc.arg(id)::iam.ulid)
  );
