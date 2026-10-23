-- clearance.sql holds every static statement this module runs against the
-- tier-2 tables: iam.clearance_groups, iam.clearance_group_members, and
-- the append-only trail in iam.clearance_group_changes.
--
-- These are separate tables from the tier-1 ones with separate foreign
-- keys, which is design §8.3's schema-level guarantee that an ordinary
-- group can never hold a clearance (see 00002_identity.sql). Nothing in
-- this file updates or deletes a trail entry, and the table refuses to be
-- edited anyway: iam.clearance_group_changes carries a BEFORE UPDATE OR
-- DELETE trigger that raises.
--
-- Every clearance-group id here is text rather than
-- domain.ClearanceGroupID, deliberately. That type is a struct with an
-- unexported field so that no package outside internal/domain can forge
-- one, and giving it sql.Scanner/driver.Valuer to satisfy a generator
-- would hand every package a way to build one from an arbitrary string.
-- The adapter converts through domain.ParseClearanceGroupID instead. See
-- sqlc.yaml's override for these columns.

-- name: ClearanceGroupByID :one
SELECT * FROM iam.clearance_groups WHERE id = sqlc.arg(id);

-- name: ClearanceGroupByName :one
SELECT * FROM iam.clearance_groups
WHERE tenant_id = sqlc.arg(tenant_id) AND name = sqlc.arg(name);

-- name: CreateClearanceGroup :one
-- channel is fixed at creation and never updated: a change arriving
-- through the other channel is refused, so a directory-synced compartment
-- cannot be quietly diverged from the directory that owns it.
INSERT INTO iam.clearance_groups (id, tenant_id, name, channel)
VALUES (sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(name), sqlc.arg(channel))
RETURNING *;

-- name: AddClearanceGroupMember :exec
-- The witnessing mandatory act is recorded on the membership row itself as
-- well as in the trail, so "under what authority does this principal hold
-- this clearance" is answerable without a join to history — which is why
-- a re-assertion is DO UPDATE and not DO NOTHING: the act on the row must
-- be the most recent one that granted it.
INSERT INTO iam.clearance_group_members
    (clearance_group_id, principal_id, channel, actor_principal_id, reason, acted_at)
VALUES (
    sqlc.arg(clearance_group_id),
    sqlc.arg(principal_id),
    sqlc.arg(channel),
    sqlc.arg(actor_principal_id),
    sqlc.arg(reason),
    sqlc.arg(acted_at)
)
ON CONFLICT (principal_id, clearance_group_id) DO UPDATE SET
    channel = EXCLUDED.channel,
    actor_principal_id = EXCLUDED.actor_principal_id,
    reason = EXCLUDED.reason,
    acted_at = EXCLUDED.acted_at;

-- name: RemoveClearanceGroupMember :exec
DELETE FROM iam.clearance_group_members
WHERE clearance_group_id = sqlc.arg(clearance_group_id)
  AND principal_id = sqlc.arg(principal_id);

-- name: RecordClearanceChange :exec
-- One entry on a clearance group's trail. Appended even when the
-- membership did not change: "someone re-asserted this clearance, and
-- why" is itself the audit record, and so is a withdrawal of a clearance
-- not held.
--
-- principal_id is NULL for a 'created' entry, which names no principal,
-- and the table's CHECK requires it to be present for every other kind.
INSERT INTO iam.clearance_group_changes
    (id, clearance_group_id, principal_id, kind, channel, actor_principal_id, reason, acted_at, recorded_at)
VALUES (
    sqlc.arg(id),
    sqlc.arg(clearance_group_id),
    sqlc.arg(principal_id),
    sqlc.arg(kind),
    sqlc.arg(channel),
    sqlc.arg(actor_principal_id),
    sqlc.arg(reason),
    sqlc.arg(acted_at),
    sqlc.arg(recorded_at)
);

-- name: ClearanceGroupsOfPrincipal :many
SELECT cg.* FROM iam.clearance_group_members m
JOIN iam.clearance_groups cg ON cg.id = m.clearance_group_id
WHERE m.principal_id = sqlc.arg(principal_id)
ORDER BY cg.name, cg.id;

-- name: ClearanceGroupMemberPrincipals :many
-- The whole principal row, for the same reason GroupMemberPrincipals
-- projects it: the staleness filter is applied in Go, from the same
-- domain.EvaluateCondition the in-memory adapter uses.
SELECT p.* FROM iam.clearance_group_members m
JOIN iam.principals p ON p.id = m.principal_id
WHERE m.clearance_group_id = sqlc.arg(clearance_group_id)
ORDER BY p.id;

-- name: ClearanceGroupChanges :many
-- Ordered by seq, not by id: two ULIDs minted inside the same millisecond
-- do not sort by creation time (their low bits are random entropy), so
-- "recorded order" needs the table's own monotonic column. seq itself is
-- not projected — it is the trail's internal ordering, not part of the
-- change the port returns.
SELECT id, principal_id, kind, channel, actor_principal_id, reason, acted_at, recorded_at
FROM iam.clearance_group_changes
WHERE clearance_group_id = sqlc.arg(clearance_group_id)
ORDER BY seq;
