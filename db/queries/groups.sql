-- groups.sql holds every static statement this module runs against the
-- tier-1 tables: iam.groups, iam.group_members, and the one probe that
-- has to ask both namespaces at once.
--
-- The claim reconciliation is the reason this file exists rather than the
-- statements living as Go string literals. It is four statements whose
-- correctness is a property of how they combine — insert what is wanted,
-- resolve the ids, add the memberships, then delete the claim-sourced ones
-- that are absent — and that argument is readable here, as SQL, in the
-- order it executes.

-- name: EnsureClaimGroups :exec
-- Step 1 of the claim reconciliation: every group the token names exists
-- afterwards.
--
-- ON CONFLICT DO NOTHING on (tenant_id, name), so a second sighting of the
-- same role upserts rather than duplicating, and the freshly minted ids
-- bound here are simply discarded for the names that already exist. For a
-- claim-derived group the name is the claim value exactly as the issuer
-- spelled it (see 00002_identity.sql).
--
-- `ROWS FROM (unnest(a), unnest(b))` and not the two-argument
-- `unnest(a, b)`: Postgres defines the latter as exactly the former when
-- it appears in a FROM clause, and sqlc's catalog knows unnest at arity
-- one only, so it rejects the shorthand at generation time. Same plan,
-- same semantics, spelled the long way.
INSERT INTO iam.groups (id, tenant_id, name)
SELECT i.id, sqlc.arg(tenant_id), i.name
FROM ROWS FROM (unnest(sqlc.arg(ids)::text[]), unnest(sqlc.arg(names)::text[])) AS i(id, name)
ON CONFLICT (tenant_id, name) DO NOTHING;

-- name: GroupIDsByName :many
-- Step 2: the ids of the groups the token names, whether this transaction
-- created them or they already existed. The ids minted for step 1 cannot
-- be assumed to be the stored ones, because a conflict kept the stored id.
SELECT id FROM iam.groups
WHERE tenant_id = sqlc.arg(tenant_id)
  AND name = ANY(sqlc.arg(names)::text[]);

-- name: AddClaimGroupMemberships :exec
-- Step 3: the principal is a claim-sourced member of each of them.
--
-- ON CONFLICT DO NOTHING rather than DO UPDATE, so a membership already
-- owned locally is not downgraded to claim-owned by the issuer also
-- asserting it — otherwise a later shrinking claim set would remove what
-- an operator wrote.
INSERT INTO iam.group_members (group_id, principal_id, source)
SELECT g, sqlc.arg(principal_id), 'claim'
FROM unnest(sqlc.arg(group_ids)::text[]) AS g
ON CONFLICT (principal_id, group_id) DO NOTHING;

-- name: PruneClaimGroupMemberships :exec
-- Step 4, and the half that makes the three above a reconciliation rather
-- than an accumulation: every claim-sourced membership the token no longer
-- asserts is deleted.
--
-- Scoped by source = 'claim', which is the whole point of the column: the
-- issuer is authoritative for the memberships it sourced and for nothing
-- else. An empty group_ids array makes this remove every claim-sourced
-- membership, which is the required reading of "the token no longer
-- asserts any role" — so this statement is run even when steps 1 to 3 are
-- skipped for having nothing to insert.
DELETE FROM iam.group_members
WHERE principal_id = sqlc.arg(principal_id)
  AND source = 'claim'
  AND group_id <> ALL(sqlc.arg(group_ids)::text[]);

-- name: EnsureGroup :exec
-- The administrative counterpart to EnsureClaimGroups, for one group.
INSERT INTO iam.groups (id, tenant_id, name)
VALUES (sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(name))
ON CONFLICT (tenant_id, name) DO NOTHING;

-- name: GroupByName :one
SELECT * FROM iam.groups
WHERE tenant_id = sqlc.arg(tenant_id) AND name = sqlc.arg(name);

-- name: GroupByID :one
-- The existence probe requireGroup needs. It replaced a two-namespace
-- UNION query that distinguished a group from a clearance group: with the
-- mandatory tier removed there is one namespace, so a row or no row is the
-- whole answer.
SELECT * FROM iam.groups WHERE id = sqlc.arg(id);

-- name: AddLocalGroupMember :exec
-- DO UPDATE SET source = 'local' and not DO NOTHING: an explicit
-- administrative add takes ownership of the membership away from the
-- issuer, so a later shrinking claim set cannot remove it.
INSERT INTO iam.group_members (group_id, principal_id, source)
VALUES (sqlc.arg(group_id), sqlc.arg(principal_id), 'local')
ON CONFLICT (principal_id, group_id) DO UPDATE SET source = 'local';

-- name: RemoveGroupMember :exec
DELETE FROM iam.group_members
WHERE group_id = sqlc.arg(group_id) AND principal_id = sqlc.arg(principal_id);

-- name: GroupsOfPrincipal :many
-- The principal's side of the membership table, which probes the
-- (principal_id, group_id) primary key.
SELECT g.* FROM iam.group_members m
JOIN iam.groups g ON g.id = m.group_id
WHERE m.principal_id = sqlc.arg(principal_id)
ORDER BY g.name, g.id;

-- name: GroupMemberPrincipals :many
-- The administrative direction, "who is in this group", which probes
-- group_members_group_idx. The whole principal row is projected and not
-- just its id, because the adapter filters the result through
-- domain.EvaluateCondition rather than in SQL (see pgregistry's package
-- doc for why the staleness rule lives in Go).
SELECT p.* FROM iam.group_members m
JOIN iam.principals p ON p.id = m.principal_id
WHERE m.group_id = sqlc.arg(group_id)
ORDER BY p.id;
