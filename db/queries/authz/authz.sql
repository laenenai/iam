-- Every statement the Postgres authorization adapter runs, except the
-- residual it renders for a consumer's own query — that one has no fixed
-- shape and is hand-composed in internal/authz/pgauthz/render.go, which is
-- CONVENTIONS' one standing exception to sqlc and says so in its own doc.
--
-- The statements here are type-checked against db/migrations at generation
-- time, so a column that does not exist or a parameter of the wrong type
-- fails before any test runs.
--
-- Every one of them runs inside a transaction that has already set
-- `app.tenant_id`, because these tables carry tenancy's restrictive
-- row-level-security policy: without the session context they return zero
-- rows rather than failing. See pgauthz's inTenantTx.

-- name: InsertContainer :one
INSERT INTO iam.containers (id, tenant_id, kind, parent_id, label, created_at)
VALUES (
    sqlc.arg(id),
    sqlc.arg(tenant_id),
    sqlc.arg(kind),
    sqlc.narg(parent_id),
    sqlc.arg(label),
    sqlc.arg(created_at)
)
RETURNING *;

-- name: ContainerByID :one
-- Tenant-scoped by parameter as well as by policy. The policy is the
-- backstop and this is the check: a module that relied on the policy alone
-- would silently stop scoping if the policy were ever dropped, which is
-- the failure mode that does not announce itself.
SELECT * FROM iam.containers
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- name: InsertClosure :exec
-- The whole of closure maintenance, in one statement, at container
-- creation.
--
-- The first branch is the reflexive row: a container contains itself at
-- depth 0, which is what lets a decision ask one question instead of two
-- (see db/migrations/00003_authorization.sql). The second copies the
-- parent's own closure down one level — so the work is proportional to the
-- *depth* of the tree, never to how many resources live in it, which is the
-- whole reason the closure is keyed on the container.
--
-- A root container has no parent, the second branch selects nothing, and
-- the statement writes exactly one row.
INSERT INTO iam.container_closure (tenant_id, container_id, ancestor_id, depth)
SELECT
    sqlc.arg(tenant_id) AS tenant_id,
    sqlc.arg(container_id) AS container_id,
    sqlc.arg(container_id) AS ancestor_id,
    0 AS depth
UNION ALL
SELECT
    sqlc.arg(tenant_id) AS tenant_id,
    sqlc.arg(container_id) AS container_id,
    cc.ancestor_id AS ancestor_id,
    cc.depth + 1 AS depth
FROM iam.container_closure cc
WHERE cc.container_id = sqlc.narg(parent_id);

-- name: Ancestors :many
-- The closure read back, nearest first: the container itself at depth 0,
-- then outwards to the root.
SELECT cc.ancestor_id FROM iam.container_closure cc
WHERE cc.container_id = sqlc.arg(container_id)
  AND cc.tenant_id = sqlc.arg(tenant_id)
ORDER BY cc.depth;

-- name: InsertGrant :execrows
-- ON CONFLICT DO NOTHING with no conflict target, so either partial unique
-- index catches a duplicate. The row count is the answer the adapter needs:
-- zero means the grant already existed, which must not append to the change
-- log — a log entry for a write that changed nothing makes a projection do
-- work for no reason and makes the log's length a function of retries.
INSERT INTO iam.grants (tenant_id, container_id, permission, principal_id, group_id, granted_at)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(container_id),
    sqlc.arg(permission),
    sqlc.narg(principal_id),
    sqlc.narg(group_id),
    sqlc.arg(granted_at)
)
ON CONFLICT DO NOTHING;

-- name: DeleteGrant :execrows
-- IS NOT DISTINCT FROM rather than =, because one of the two subject
-- columns is always NULL and `NULL = NULL` is NULL, which would delete
-- nothing and report success.
DELETE FROM iam.grants
WHERE tenant_id = sqlc.arg(tenant_id)
  AND container_id = sqlc.arg(container_id)
  AND permission = sqlc.arg(permission)
  AND principal_id IS NOT DISTINCT FROM sqlc.narg(principal_id)
  AND group_id IS NOT DISTINCT FROM sqlc.narg(group_id);

-- name: GrantsOnContainer :many
-- Only the grants written on this container. The inherited ones belong to
-- its ancestors and are read by asking about them, because a method that
-- merged the two would make "what did somebody write here" unanswerable.
--
-- The ORDER BY reproduces domain.Subject.String()'s own ordering, so this
-- adapter and the in-memory one return the same sequence. That it has to be
-- spelled out here is the cost of the subject being two columns rather than
-- one polymorphic id; the benefit is in the schema, where each column
-- carries a real foreign key.
SELECT * FROM iam.grants
WHERE container_id = sqlc.arg(container_id)
  AND tenant_id = sqlc.arg(tenant_id)
ORDER BY
    permission,
    CASE
        WHEN group_id IS NOT NULL THEN 'group:' || group_id || '#member'
        ELSE 'principal:' || principal_id
    END;

-- name: Decide :many
-- Design §7.1's point decision, as one statement.
--
-- One statement is the property worth protecting, not an optimization. The
-- principal's liveness, its group memberships and the grants are all
-- resolved in the same snapshot, so there is no window in which a
-- deprovisioning has been recorded and a decision still reads the
-- membership it removed. iam.live_principals and iam.live_group_members are
-- the two views that do it, and they are the same two artifacts the residual
-- renders into a consumer's own statement — so the Go path and the SQL path
-- cannot disagree about who is live.
--
-- It is `:many LIMIT 1` rather than `:one`, and the shape is worth a note
-- because the obvious alternative was tried and rejected. Folding
-- HeadRevision into this statement with a LEFT JOIN LATERAL makes it always
-- return one row, which reads better — and sqlc does not infer nullability
-- through the lateral, so every column of the matched grant was generated
-- as non-nullable and would have failed at run time on the first deny. The
-- alternatives were coalescing each column to a sentinel in SQL, which
-- throws away the typed ids at exactly the boundary they exist for, or this:
-- two statements in one repeatable-read transaction, which share one
-- snapshot and keep every column honestly typed.
--
-- `LIMIT 1` is not a sample. The ORDER BY makes the first row the one a
-- consumer needs to be told about, and the rest are other routes to the
-- same allow; a decision is a boolean plus one attribution, not a list.
--
-- ORDER BY is the explanation, not the verdict. `cc.depth` first, so a grant
-- written on the container itself outranks one inherited from an ancestor;
-- then `g.principal_id IS NULL`, which is false before true, so a grant
-- written to this principal by name outranks one reaching it through a
-- group; then the group id, so two groups that both confer the permission
-- attribute the allow deterministically. That ordering is why Decision
-- reports the outermost form that fired, which is what a consumer debugging
-- a decision needs to see first.
SELECT
    g.container_id,
    g.permission,
    g.principal_id,
    g.group_id,
    g.granted_at,
    cc.depth
FROM iam.container_closure cc
JOIN iam.grants g
  ON g.container_id = cc.ancestor_id
 AND g.permission = sqlc.arg(permission)
WHERE cc.container_id = sqlc.arg(container_id)
  AND cc.tenant_id = sqlc.arg(tenant_id)
  -- The principal must belong to this tenant. It is checked here and not
  -- left to the grants' own tenant scoping, because a membership can cross
  -- a tenant: iam.group_members has no tenant column and AddGroupMember
  -- does not compare one, so without this conjunct a principal in tenant B
  -- who had been added to a group in tenant A would be allowed by tenant
  -- A's group grant. The direct arm cannot go wrong that way — a grant's
  -- composite foreign key puts its principal in its own tenant — so this
  -- exists for the group arm and is written once, above both.
  AND EXISTS (
      SELECT 1 FROM iam.principals pr
      WHERE pr.id = sqlc.arg(principal_id)
        AND pr.tenant_id = sqlc.arg(tenant_id)
  )
  AND (
        (
          g.principal_id = sqlc.arg(principal_id)
          AND EXISTS (
              SELECT 1 FROM iam.live_principals lp
              WHERE lp.id = sqlc.arg(principal_id)
          )
        )
     OR EXISTS (
          SELECT 1 FROM iam.live_group_members lgm
          WHERE lgm.group_id = g.group_id
            AND lgm.principal_id = sqlc.arg(principal_id)
        )
  )
ORDER BY cc.depth, (g.principal_id IS NULL), g.group_id
LIMIT 1;

-- name: HeadRevision :one
-- The current authorization state of this deployment. Zero means no
-- authorization write has ever happened, which is a real value and not a
-- wildcard.
SELECT coalesce(max(revision), 0)::bigint AS revision FROM iam.authz_changelog
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: LockChangeLog :exec
-- Taken by every closure-affecting write, for the remainder of its
-- transaction, so that revisions are assigned in commit order with no gaps.
--
-- This is the alternative to a sequence, and the reason it is worth a lock:
-- a sequence allocates its number before the transaction commits, so a
-- reader can observe revision 5 while 4 is still in flight, and a cursor
-- stored at 5 then skips 4 forever. That is the dropped-revocation hazard
-- design §9.3 describes and §17 records under
-- `DefaultChangelogHorizonOffset = 0`. Design §15 leaves the choice open and
-- calls this side of it "more work"; the work is this statement.
--
-- It is the two-argument form, so the lock is per tenant: the first
-- argument is this module's own key, which keeps it from colliding with an
-- unrelated advisory lock taken by something else sharing the cluster, and
-- the second is the tenant. hashtext is 32-bit, so two tenants can collide
-- and serialize with each other; that costs throughput and never
-- correctness, because the revision is still assigned under *a* lock.
--
-- The cost, stated: closure-affecting writes within one tenant serialize
-- against each other. Reads take no lock at all.
SELECT pg_advisory_xact_lock(sqlc.arg(key)::int, hashtext(sqlc.arg(tenant_id)::text));

-- name: AppendChange :one
-- The revision is assigned inside the INSERT, as max+1, under the lock
-- above. Doing it in one statement rather than reading the maximum and then
-- inserting it removes the window where two writers could read the same
-- maximum — the lock already removes it, and this means correctness does not
-- depend on the lock being held in exactly the right place.
INSERT INTO iam.authz_changelog (
    revision, tenant_id, kind, container_id, permission, principal_id, group_id, recorded_at
)
VALUES (
    (SELECT coalesce(max(c.revision), 0) + 1 FROM iam.authz_changelog c WHERE c.tenant_id = sqlc.arg(tenant_id)),
    sqlc.arg(tenant_id),
    sqlc.arg(kind),
    sqlc.arg(container_id),
    sqlc.arg(permission),
    sqlc.narg(principal_id),
    sqlc.narg(group_id),
    sqlc.arg(recorded_at)
)
RETURNING revision;

-- name: ChangesAfter :many
-- One tenant's changes after a cursor, in revision order. The guarantee a
-- restartable projection needs — every change after the cursor, exactly once
-- — holds because revisions are gapless and assigned in commit order, so the
-- visibility of revision N implies the visibility of everything below it.
SELECT * FROM iam.authz_changelog
WHERE tenant_id = sqlc.arg(tenant_id)
  AND revision > sqlc.arg(after)
ORDER BY revision
LIMIT sqlc.arg(page_size);

-- name: PrincipalTenantID :one
-- Read when a grant names a principal, so that a grant to a principal that
-- does not exist, or belongs to another tenant, is refused in Go with an
-- error that says which. The composite foreign key in the schema refuses it
-- too; that one is the guarantee and this one is the diagnosis.
SELECT tenant_id FROM iam.principals WHERE id = sqlc.arg(id);

-- name: GroupTenantID :one
-- The same, for a grant naming a group.
SELECT tenant_id FROM iam.groups WHERE id = sqlc.arg(id);

-- name: SetTenantContext :exec
-- Establishes the tenant session context the row-level-security policy on
-- these tables keys off, for the remainder of the current transaction.
--
-- `true` is the is_local argument, and it is the whole reason every method
-- in this adapter runs inside a transaction even to read: a non-local
-- set_config would outlive the call on a pooled connection and the next
-- borrower of that connection would inherit somebody else's tenant. There
-- is no safe way to set this outside a transaction.
--
-- The GUC's name is a parameter rather than inlined, so that tenancy's
-- TenantGUC constant stays the single place it is spelled. A copy of the
-- string in a query file is a copy that a rename would not reach, and a
-- policy that no longer matches does not fail — it stops filtering.
SELECT set_config(sqlc.arg(name)::text, sqlc.arg(value)::text, true);
