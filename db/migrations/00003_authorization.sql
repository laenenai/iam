-- 00003_authorization.sql is the authorization layer: containers, the
-- containment closure keyed on the container, grants, and the change log a
-- separated deployment resumes a projection from. Plus one view,
-- iam.live_principals, and two composite keys on the identity tables so
-- that no containment edge or grant can cross a tenant.
--
-- ===========================================================================
-- THE ONE DECISION THIS FILE IS ABOUT: THE CLOSURE IS KEYED ON THE CONTAINER
-- ===========================================================================
--
-- Design §9.2 materializes two things that are expensive to compute and
-- cheap to store. One of them, the membership closure, already exists as
-- iam.live_group_members over iam.group_members (00002_identity.sql). The
-- other is the ancestry closure below, and the only real choice in this
-- file is what it is keyed on.
--
-- Keyed on the **container**: one row per (container, ancestor) pair, so
-- the table's size is a function of how many containers a tenant has
-- times the depth of its tree. Anti-goal A2 budgets depth 6.
--
-- Keyed on the **resource**: one row per (resource, ancestor) pair, so the
-- table's size is a function of resource cardinality — A2's ten million
-- rows times the same depth.
--
-- Finding F3's spike measured both on one 10,000,000-row fixture at the
-- budgeted proportions (docs/superpowers/spikes/2026-10-24-f3-dag-containment.md
-- §5):
--
--     keyed on the resource    106,495,540 rows      10.9 GB
--     keyed on the container        433,063 rows        37 MB
--
-- A factor of 246 in rows and 295 in bytes, for a table that has to be
-- maintained on every write and joined on every read. That is why the
-- closure below holds container_id and ancestor_id and no resource
-- anywhere: a consumer's row carries one scalar column naming its
-- container (finding F1's frozen containment key) and joins it to this
-- table. The resource's own edge to its container stays in the consumer's
-- table, where it already is, and is never copied here.
--
-- The second consequence of that keying is the one a reader is most
-- likely to miss: maintenance is bounded by *container* count, not by
-- resource count. F3's spike measured a single entity joining a deep
-- container at 1 closure row where the resource-keyed shape wrote 5,915
-- for a hub entity. Adding a grant and adding a group member each write
-- zero rows here.
--
-- ===========================================================================
-- CONTAINMENT IS A TREE, AND THAT IS A COLUMN RATHER THAN A CONVENTION
-- ===========================================================================
--
-- iam.containers.parent_id is one nullable column. One parent per
-- container, one container per resource, which is what makes the closure
-- above "bounded by hierarchy depth" true rather than aspirational
-- (design §9.2, finding F3, resolved 2026-10-24 by both specified
-- consumers' containment being a tree: CAS's `tenant > fileset >
-- document > slot`, and the respecified kgs/cogos four-tier named-graph
-- tree whose own ancestry walk is `UNION ALL` over a single
-- parent_graph_id, which is correct only for one parent).
--
-- The declaration-level half of the invariant — a consumer's *schema*
-- naming two parent kinds — is refused in Go, with the sizing numbers
-- above in the error: see domain.Schema.Validate and
-- domain.ErrMultipleContainmentParents. This file enforces the
-- instance-level half, and it enforces it by having nowhere to put a
-- second parent.
--
-- **There is no cycle check and no trigger, and that is sound rather than
-- optimistic.** A cycle in a single-parent graph requires an UPDATE that
-- repoints an existing row at one of its own descendants. No statement in
-- this module updates parent_id: a container's parent is set at INSERT,
-- when it can only reference a row that already exists, and re-parenting
-- is deliberately unbuilt (see the internal/authz package doc). Go still
-- carries a depth bound as a backstop, because the alternative to an
-- error on a corrupted tree is an authorization decision that never
-- returns (domain.ErrContainmentCycle).
--
-- ===========================================================================
-- THE CHANGE LOG, AND WHY IT IS HERE AFTER BEING ARGUED AWAY
-- ===========================================================================
--
-- iam.authz_changelog is an append-only record of every write that can
-- change an authorization answer, ordered by a gapless monotonic
-- revision, so that a reader resuming from a stored cursor sees every
-- change after it exactly once.
--
-- **This was omitted on a reasoning that was locally correct and globally
-- wrong, and the correction is worth recording rather than quietly
-- applied.** The argument for leaving it out was: the cursor existed to
-- let a projection worker resume; the projection existed because the
-- authority was OpenFGA, a separate store; with the closures *being* the
-- authority and living in the same Postgres the consumer queries, a
-- consumer joins them directly and there is no projection to resume. Every
-- clause of that is true of a co-located Postgres consumer. It is not true
-- of the architecture: `iam` has to become separable — other backends are
-- coming — and a consumer on another store must project the authorized set
-- locally. A projection without a resumable cursor cannot be restarted
-- safely, so the log is the seam that makes separation possible rather
-- than dead weight left over from an engine that was dropped. Design §11's
-- *service* shape reaches the same conclusion from the other direction.
--
-- **How the revision is assigned, and what it costs.** Not from a
-- sequence. A sequence allocates its number before the transaction
-- commits, so a reader can observe revision 5 while 4 is still in flight,
-- and a cursor stored at 5 then skips 4 forever — the dropped-revocation
-- hazard design §9.3 describes and §17 records under
-- `DefaultChangelogHorizonOffset = 0`. Instead every closure-affecting
-- write takes a per-tenant advisory lock for the remainder of its
-- transaction and assigns `max(revision) + 1` within that tenant under it.
-- Revision order is then commit order, with no gaps and no horizon offset
-- to tune, which is the first of the two options design §15 leaves open
-- and the one it calls "more work".
--
-- **The revision is per tenant, and that was forced rather than chosen.**
-- A deployment-wide counter was the first design and it cannot coexist
-- with the row-level-security policy on this table: under a tenant session
-- context, `max(revision)` is that tenant's maximum, so a global sequence
-- read through the policy would hand two tenants the same next value and
-- the primary key would reject the second. Per tenant is also the unit a
-- projection actually resumes — a consumer projects one tenant's
-- authorized set, not a deployment's — and it makes the lock per tenant,
-- so one tenant's writes no longer serialize against another's.
--
-- What it costs is stated rather than hidden: closure-affecting writes
-- *within one tenant* serialize against each other, and two tenants whose
-- names collide in the lock's 32-bit hash serialize with each other as
-- well, which costs throughput and nothing else. Reads take no lock at
-- all, and grants and containers are written rarely and read on every
-- statement, so this is the cheap side of the trade.
--
-- The log carries no foreign keys, deliberately. It is a log: it must
-- still describe a grant that has since been revoked and a container that
-- has since been deleted, and a foreign key would delete the record of the
-- very change a projection is trying to replay.
--
-- ===========================================================================
-- ROW-LEVEL SECURITY IS NOT IN THIS FILE, AND THAT IS DELIBERATE
-- ===========================================================================
--
-- The three tables below are tenant-scoped and every one of them carries
-- a policy — but the policy is created by `tenancy`'s EnableRLS, called
-- from internal/migrate.Up after goose finishes, not written here.
--
-- Two reasons. First, a hand-written tenant predicate in this file would
-- be a second copy of a convention that already exists, and on 2026-10-23
-- the version of it that every module had shipped was measured as a
-- cross-tenant disclosure: a *permissive* tenant policy is OR-ed away by
-- any later permissive policy on the same table, and a tenant seeing its
-- own single row saw two the moment a second policy existed.
-- tenancy.EnableRLS creates the predicate AS RESTRICTIVE, with a
-- permissive companion for it to AND against, which is the shape that
-- cannot be widened. Second, EnableRLS is idempotent by design so that it
-- can be re-asserted on every Up — it repairs a policy whose predicate
-- has drifted — and a CREATE POLICY in a one-shot migration cannot do
-- that.
--
-- The identity tables from 00002 remain without a policy, which is a
-- stated gap rather than a decision: giving them one requires the
-- registry adapter to establish a tenant session context on every
-- statement, which this increment does not build. See
-- internal/authz/pgauthz's package doc and the coverage test's exemption
-- map, which names them with that reason.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Composite keys on the identity tables, so no edge can cross a tenant
-- ---------------------------------------------------------------------------
--
-- A grant names a principal or a group; a container names its parent.
-- Each of those is an edge, and an edge that crossed a tenant would carry
-- a permission across the only isolation boundary this system has. The
-- cheapest way to make that unexpressible is a composite foreign key, and
-- a composite foreign key needs a unique constraint on the pair it
-- references. These two indexes are that, and nothing queries through
-- them: (id) alone is already the primary key, so they exist for
-- referential integrity rather than for a read path.
CREATE UNIQUE INDEX principals_id_tenant_key ON iam.principals (id, tenant_id);

CREATE UNIQUE INDEX groups_id_tenant_key ON iam.groups (id, tenant_id);

-- ---------------------------------------------------------------------------
-- Containers
-- ---------------------------------------------------------------------------
CREATE TABLE iam.containers (
    id          iam.ulid PRIMARY KEY,
    tenant_id   iam.ulid NOT NULL,

    -- The kind's name in the consumer's own registered schema (design
    -- §8.4: no consumer's types appear in this module's code). It is free
    -- text here because it is the consumer's vocabulary, and which kinds
    -- exist is checked in Go against the registered schema.
    kind        text NOT NULL CHECK (kind <> ''),

    -- One parent. See this file's header for why there is no second
    -- column, no join table and no cycle trigger.
    --
    -- ON DELETE RESTRICT: deleting a container that still contains
    -- others would have to decide what happens to the grants on the
    -- subtree, and silently removing them is a disclosure in the other
    -- direction (a resource that stops being contained stops being
    -- protected by the container's grant, but also stops being reachable
    -- at all). Container deletion is unbuilt; until it is designed, the
    -- database refuses rather than guesses.
    parent_id   iam.ulid REFERENCES iam.containers (id) ON DELETE RESTRICT,

    label       text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),

    -- A container is never its own parent. This catches the degenerate
    -- cycle; the general case is impossible by construction (header).
    CONSTRAINT containers_not_own_parent CHECK (parent_id IS NULL OR parent_id <> id),

    -- Referenced by the composite foreign key below, so a parent edge
    -- cannot leave the tenant.
    UNIQUE (id, tenant_id),
    CONSTRAINT containers_parent_same_tenant
        FOREIGN KEY (parent_id, tenant_id) REFERENCES iam.containers (id, tenant_id)
);

-- The downward direction: "what does this container hold directly". Used
-- when a container is created (to read its parent's closure) and by
-- administration.
CREATE INDEX containers_parent_idx
    ON iam.containers (parent_id)
    WHERE parent_id IS NOT NULL;

CREATE INDEX containers_tenant_idx ON iam.containers (tenant_id);

-- ---------------------------------------------------------------------------
-- The containment closure, keyed on the container
-- ---------------------------------------------------------------------------
--
-- One row per (container, ancestor) pair, **including the reflexive row**
-- at depth 0.
--
-- The reflexive row is not padding. Without it a decision is a union of
-- two queries — "is there a grant on this container" OR "is there a grant
-- on one of its ancestors" — and the joinable fragment a consumer ANDs
-- into an RLS policy becomes two EXISTS clauses that have to stay in step
-- with each other inside somebody else's policy text. With it, "the
-- container itself" is just depth 0 and the whole decision is one join
-- against one table. It costs one row per container.
--
-- depth is stored because it is what a consumer needs in order to explain
-- a decision: depth 0 means the grant is written here, depth 3 means it
-- is three hops up and that is the row to go and look at. Nothing joins
-- on it.
CREATE TABLE iam.container_closure (
    tenant_id     iam.ulid NOT NULL,
    container_id  iam.ulid NOT NULL REFERENCES iam.containers (id) ON DELETE CASCADE,
    ancestor_id   iam.ulid NOT NULL REFERENCES iam.containers (id) ON DELETE CASCADE,
    depth         integer NOT NULL CHECK (depth >= 0),

    -- (container_id, ancestor_id), in that order: the decision probes by
    -- container and joins outward to the grants on each ancestor, so
    -- container_id must lead for that probe to be an index-only scan on
    -- the primary key.
    PRIMARY KEY (container_id, ancestor_id)
);

-- The other direction: "everything below this container". Nothing in this
-- increment reads it — there is no visible_below, no subtree move and no
-- container delete — and it is here because every one of those three
-- reads it, and because the index that is missing when a maintenance path
-- arrives is the one that turns a subtree update into a sequential scan
-- of the whole closure.
CREATE INDEX container_closure_ancestor_idx
    ON iam.container_closure (ancestor_id, container_id);

CREATE INDEX container_closure_tenant_idx ON iam.container_closure (tenant_id);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- The whole rule language: a subject holds a permission on a container.
-- Design §8.2 permits four composition forms; a direct subject and a
-- group subject are two of them, the containment closure above is the
-- third, and the fourth — union over relations on the same object — has
-- nothing to union because there are no relations.
--
-- There are no negative rows, no exclusions and no conditions, and there
-- is no column where one could be added without a migration somebody has
-- to review. Design A3: a deny administered by policy is only as absolute
-- as whoever administers the policy, and an absolute that must survive a
-- future administrator is a key the deployment does not hold, which is
-- `escrow`.
CREATE TABLE iam.grants (
    tenant_id     iam.ulid NOT NULL,
    container_id  iam.ulid NOT NULL REFERENCES iam.containers (id) ON DELETE CASCADE,

    -- The consumer's own permission name, checked in Go against the
    -- registered schema's vocabulary before the row is written. A grant
    -- naming a permission no schema declares is refused at write time,
    -- because a misspelled permission is a grant that silently never
    -- fires.
    permission    text NOT NULL CHECK (permission <> ''),

    -- Exactly one of these. Two nullable typed columns rather than one
    -- polymorphic subject_id, because each one then carries a real
    -- foreign key: deleting a collected agent-run principal removes its
    -- grants, and a grant can never name a group that does not exist.
    -- The cost is that the decision's SQL has two arms instead of one,
    -- and that cost is paid once, in one place — see
    -- internal/authz/fragment.go.
    principal_id  iam.ulid REFERENCES iam.principals (id) ON DELETE CASCADE,
    group_id      iam.ulid REFERENCES iam.groups (id) ON DELETE CASCADE,

    granted_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT grants_exactly_one_subject
        CHECK ((principal_id IS NULL) <> (group_id IS NULL)),

    -- No edge leaves the tenant: not the container the grant is on, and
    -- not the subject it is written to.
    CONSTRAINT grants_container_same_tenant
        FOREIGN KEY (container_id, tenant_id) REFERENCES iam.containers (id, tenant_id),
    CONSTRAINT grants_principal_same_tenant
        FOREIGN KEY (principal_id, tenant_id) REFERENCES iam.principals (id, tenant_id),
    CONSTRAINT grants_group_same_tenant
        FOREIGN KEY (group_id, tenant_id) REFERENCES iam.groups (id, tenant_id)
);

-- Identity of a grant, so writing one twice is idempotent. Two partial
-- unique indexes rather than one four-column UNIQUE, because a NULL is
-- distinct from every other NULL in a unique index and the one-column
-- version would therefore permit the same grant twice.
CREATE UNIQUE INDEX grants_principal_key
    ON iam.grants (container_id, permission, principal_id)
    WHERE principal_id IS NOT NULL;

CREATE UNIQUE INDEX grants_group_key
    ON iam.grants (container_id, permission, group_id)
    WHERE group_id IS NOT NULL;

-- The read path's own index. The decision joins the closure's ancestors
-- to the grants on them and filters by permission, so (container_id,
-- permission) is the probe. The two partial unique indexes above have the
-- same leading columns and would serve it as a bitmap-or of two partial
-- scans; this index serves it as one, which is what the plan test
-- asserts.
CREATE INDEX grants_container_permission_idx
    ON iam.grants (container_id, permission);

CREATE INDEX grants_tenant_idx ON iam.grants (tenant_id);

-- ---------------------------------------------------------------------------
-- The change log and its resumable cursor
-- ---------------------------------------------------------------------------
--
-- See this file's header for why this table exists after having been
-- argued away, and for how `revision` is assigned without the gap a
-- sequence would leave.
--
-- revision is the primary key and is the cursor: a reader stores the
-- highest revision it has processed and resumes with `revision > cursor`.
-- Because revisions are assigned under one advisory lock held to commit,
-- the visibility of revision N implies the visibility of every revision
-- below it, which is exactly the "every change after the cursor, exactly
-- once" guarantee a projection needs in order to be restartable.
--
-- It is also the revision every decision carries. While `iam`'s tables and
-- the consumer's are in one database the decision reads the authority and
-- the revision is trivially current; when `iam` is a separate store it is
-- the token that distinguishes design §9.3's "lagging within a declared
-- bound" from §16.5's "diverged", and the reason it exists now is that
-- adding it later is a breaking change to every call site.
CREATE TABLE iam.authz_changelog (
    -- (tenant_id, revision) and not revision alone: the revision is per
    -- tenant, for the reason this file's header gives. tenant_id leads
    -- because every read of this table is one tenant's changes after a
    -- cursor, which is then an index-only range scan on the primary key.
    tenant_id     iam.ulid NOT NULL,
    revision      bigint NOT NULL,

    -- What happened. The set is closed to the three writes that can move
    -- an authorization answer in this layer; a fourth would be a schema
    -- change here, which is the review somebody should have to do.
    kind          text NOT NULL CHECK (kind IN ('container-created', 'grant-written', 'grant-revoked')),

    -- The container the change is about. For a grant it is the container
    -- the grant was written on; for a container it is the container
    -- created. A projection replaying the log needs the closure to find
    -- what moved below it, which is what
    -- container_closure_ancestor_idx is for.
    container_id  iam.ulid NOT NULL,

    -- The grant's permission and subject, empty/NULL for a container
    -- event. No foreign keys anywhere in this table: it is a log, and it
    -- must still describe the grant that has since been revoked.
    permission    text NOT NULL DEFAULT '',
    principal_id  iam.ulid,
    group_id      iam.ulid,

    recorded_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, revision),
    CONSTRAINT authz_changelog_revision_positive CHECK (revision > 0)
);

-- ---------------------------------------------------------------------------
-- iam.live_principals: the second artifact a decision joins
-- ---------------------------------------------------------------------------
--
-- iam.live_group_members (00002) already excludes a deprovisioned
-- principal and an expired agent run from the *group* side of a decision,
-- in the same statement that records the deprovisioning. This view is its
-- counterpart for the *direct* side, and without it the two sides would
-- disagree: a deprovisioned principal would stop matching grants written
-- to its groups and keep matching grants written to it by name, which is
-- the worst possible half-measure — deprovisioning would appear to work
-- in testing and leak on exactly the grants somebody wrote personally.
--
-- Its predicate is deliberately the same two exclusions, spelled the same
-- way, and deliberately **not** a third: the deployment's staleness bound
-- is configuration rather than a row, so it is not here, for the reason
-- iam.live_group_members' own comment gives at length. Design §8.1 puts
-- the bound on the way in.
--
-- A view rather than a materialized table, for the reason
-- iam.live_group_members gives: a materialized copy of a *denial* needs a
-- refresh path, and a stale denial is a disclosure (design §9.3).
CREATE VIEW iam.live_principals AS
SELECT p.id
FROM iam.principals p
WHERE p.deprovisioned_at IS NULL
  AND (p.expires_at IS NULL OR p.expires_at > now());

-- +goose Down
DROP VIEW IF EXISTS iam.live_principals;

DROP TABLE IF EXISTS iam.authz_changelog;

DROP TABLE IF EXISTS iam.grants;

DROP TABLE IF EXISTS iam.container_closure;

DROP TABLE IF EXISTS iam.containers;

DROP INDEX IF EXISTS iam.groups_id_tenant_key;

DROP INDEX IF EXISTS iam.principals_id_tenant_key;
