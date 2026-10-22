-- 00002_identity.sql is the identity registry: principals, ordinary
-- (tier-1) groups and their membership, clearance groups and their
-- membership, and the append-only trail every clearance change leaves.
--
-- ===========================================================================
-- THE SHAPE OF THIS SCHEMA IS DICTATED BY ONE REQUIREMENT: MEMBERSHIP MUST
-- BE JOINABLE INSIDE AN AUTHORIZATION PREDICATE.
-- ===========================================================================
--
-- Design §9 requires an authorization decision that compiles into a SQL
-- predicate the consumer embeds in its own statement, joined rather than
-- post-filtered, over a table of ten million rows (anti-goal A2). The
-- predicate has to answer "is this principal in the group this grant
-- names" inside the query plan. A group list in a token's claims cannot be
-- joined, which is design §8.1's one-line conclusion and the entire reason
-- this module stores identity at all rather than reading it per request.
--
-- Three consequences are visible in the DDL below and are not incidental:
--
--   1. iam.group_members' PRIMARY KEY is (principal_id, group_id), in that
--      order. The predicate probes by principal — one principal, many
--      candidate groups — so principal_id must lead, making
--      `principal_id = $1 AND group_id = ANY($2)` an index-only scan on
--      the primary key. A (group_id, principal_id) key would have forced
--      that probe into a scan or a bitmap-or over 200 overlapping groups
--      (A2's budget). The reverse index exists too, for administration
--      ("who is in this group"), which is a different question asked by a
--      different caller at a different frequency.
--   2. Membership is a narrow table of ids and nothing else. It is read on
--      the hottest path in the system, so nothing that is not needed to
--      answer the membership question lives in it.
--   3. iam.live_group_members (below) is the artifact the predicate joins,
--      and it is a view rather than a materialized table on purpose — see
--      its own comment.
--
-- ===========================================================================
-- CLEARANCE GROUPS ARE SEPARATE TABLES, NOT A FLAG
-- ===========================================================================
--
-- Design §8.3 requires that an ordinary tier-1 group can never hold a
-- clearance and that a clearance group can never be referenced in a tier-1
-- tuple. A `is_clearance boolean` column on iam.groups would have made
-- that a condition every future query must remember; separate tables with
-- separate foreign keys make it unrepresentable. A tier-1 membership row
-- cannot point at a clearance group because iam.group_members.group_id
-- references iam.groups, and the reverse likewise. Even a hand-written
-- statement in an incident cannot cross the tiers.
--
-- This is the schema-level third of a three-layer enforcement; the other
-- two are internal/domain.ClearanceGroupID (unconvertible to or from
-- GroupID, so the confusion cannot be written in Go) and the Registry port
-- (every clearance write demands a mandatory act no discretionary path can
-- construct).

-- +goose Up

-- ---------------------------------------------------------------------------
-- Principals
-- ---------------------------------------------------------------------------
--
-- id is minted (a fresh ULID) and is never a function of (issuer,
-- subject). Grants, classifications, audit chains and metering attribution
-- all reference it, so re-issuing or renaming an external identity rewrites
-- exactly one row here and no history anywhere (design §8.1, CAS §9.1).
-- (issuer, subject) is a unique *key* with id as its value, never the
-- other way round.
CREATE TABLE iam.principals (
    id                iam.ulid PRIMARY KEY,
    tenant_id         iam.ulid NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('user', 'service', 'agent-run')),
    display_name      text NOT NULL DEFAULT '',

    -- The external subject, empty for a principal that has none. A
    -- deployment with no IdP configured still works for service
    -- principals (anti-goal A1), so '' is legitimate here and the partial
    -- unique index below skips those rows rather than colliding them.
    issuer            text NOT NULL DEFAULT '',
    subject           text NOT NULL DEFAULT '',

    -- Agent-run fields. An agent run is a first-class principal with its
    -- own id, created by delegation, garbage-collected on a policy TTL —
    -- deliberately not a flag on its parent, because audit and metering
    -- must attribute per run (design §8.1, KGS §9.5).
    delegated_by      iam.ulid REFERENCES iam.principals (id) ON DELETE CASCADE,
    expires_at        timestamptz,

    -- synced_at is what the deployment's staleness bound is measured
    -- against. It is NOT NULL so staleness is always measurable: a NULL
    -- here would be a principal whose freshness cannot be evaluated, and
    -- the fail-closed reading of that is a denial, which is harder to
    -- debug than refusing the write.
    synced_at         timestamptz NOT NULL,

    -- Non-NULL from the instant a principal is deprovisioned. Design §8.1
    -- requires deprovisioning to deny immediately regardless of token
    -- validity; the row and its memberships survive so audit can still
    -- explain what the principal had access to.
    deprovisioned_at  timestamptz,

    created_at        timestamptz NOT NULL DEFAULT now(),

    -- An external subject is both halves or neither: half a key cannot be
    -- looked up and would silently never match.
    CONSTRAINT principals_external_subject_paired
        CHECK ((issuer = '') = (subject = '')),
    -- A user principal is always mirrored from an issuer. A service
    -- principal need not be.
    CONSTRAINT principals_user_has_external_subject
        CHECK (kind <> 'user' OR issuer <> ''),
    -- The agent-run shape, enforced here and not only in Go: an agent run
    -- must name its parent and carry a deadline, and nothing else may do
    -- either. A user or service principal does not expire — it is
    -- deprovisioned.
    CONSTRAINT principals_agent_run_shape CHECK (
        (kind = 'agent-run' AND delegated_by IS NOT NULL AND expires_at IS NOT NULL)
        OR
        (kind <> 'agent-run' AND delegated_by IS NULL AND expires_at IS NULL)
    )
);

-- The external-subject key. Partial, so the many service principals with
-- no external identity do not collide on ('', '').
CREATE UNIQUE INDEX principals_external_subject_key
    ON iam.principals (tenant_id, issuer, subject)
    WHERE issuer <> '';

-- Deprovisioning cascades to a principal's live agent runs in the same
-- statement (see the Registry port). This index is what makes that one
-- indexed update rather than a scan of every principal.
CREATE INDEX principals_delegated_by_idx
    ON iam.principals (delegated_by)
    WHERE delegated_by IS NOT NULL;

-- The garbage collector's probe.
CREATE INDEX principals_agent_run_expiry_idx
    ON iam.principals (expires_at)
    WHERE kind = 'agent-run';

-- ---------------------------------------------------------------------------
-- Ordinary (tier-1) groups and the joinable membership table
-- ---------------------------------------------------------------------------

CREATE TABLE iam.groups (
    id          iam.ulid PRIMARY KEY,
    tenant_id   iam.ulid NOT NULL,
    -- For a claim-derived group this is the claim value exactly as the
    -- issuer spelled it, so a second sighting of the same role upserts
    -- rather than duplicating.
    name        text NOT NULL CHECK (name <> ''),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE iam.group_members (
    group_id      iam.ulid NOT NULL REFERENCES iam.groups (id) ON DELETE CASCADE,
    principal_id  iam.ulid NOT NULL REFERENCES iam.principals (id) ON DELETE CASCADE,

    -- 'claim' means the issuer owns this row and a shrinking claim set
    -- removes it; 'local' means an operator or a consumer's sharing flow
    -- owns it and reconciliation must not touch it. Without the
    -- distinction, a JIT upsert whose token happens to omit a role would
    -- delete a membership the issuer was never the authority for.
    source        text NOT NULL CHECK (source IN ('claim', 'local')),
    added_at      timestamptz NOT NULL DEFAULT now(),

    -- (principal_id, group_id), in that order, is the predicate's probe
    -- order. See this file's header.
    PRIMARY KEY (principal_id, group_id)
);

-- The administrative direction: "who is in this group".
CREATE INDEX group_members_group_idx
    ON iam.group_members (group_id, principal_id);

-- ---------------------------------------------------------------------------
-- Clearance groups: separate tables, separate foreign keys
-- ---------------------------------------------------------------------------

CREATE TABLE iam.clearance_groups (
    id          iam.ulid PRIMARY KEY,
    tenant_id   iam.ulid NOT NULL,
    name        text NOT NULL CHECK (name <> ''),
    -- The authoritative channel for this group's membership, fixed at
    -- creation. A change arriving through the other channel is refused, so
    -- a directory-synced compartment cannot be quietly diverged from the
    -- directory that owns it.
    channel     text NOT NULL CHECK (channel IN ('classify-permission', 'directory-sync')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- The tenant-scoped names of a clearance group and an ordinary group may
-- coincide without either being a handle on the other: they are different
-- kinds of object in different namespaces. Conflating the namespaces would
-- make a tier-1 name a lever on a tier-2 object, which is precisely what
-- design §8.3 forbids.

CREATE TABLE iam.clearance_group_members (
    clearance_group_id  iam.ulid NOT NULL REFERENCES iam.clearance_groups (id) ON DELETE RESTRICT,
    principal_id        iam.ulid NOT NULL REFERENCES iam.principals (id) ON DELETE CASCADE,

    -- The witnessing mandatory act, recorded on the membership row itself
    -- as well as in the trail, so "under what authority does this
    -- principal hold this clearance" is answerable without a join to
    -- history.
    channel             text NOT NULL CHECK (channel IN ('classify-permission', 'directory-sync')),
    actor_principal_id  iam.ulid NOT NULL,
    reason              text NOT NULL CHECK (reason <> ''),
    acted_at            timestamptz NOT NULL,

    PRIMARY KEY (principal_id, clearance_group_id)
);

CREATE INDEX clearance_group_members_group_idx
    ON iam.clearance_group_members (clearance_group_id, principal_id);

-- The append-only trail. Design §8.3 requires clearance membership to be
-- audited; the `audit` module owns audit storage, so this is the
-- registry's own authoritative record of its own writes, which such a sink
-- mirrors rather than replaces.
CREATE TABLE iam.clearance_group_changes (
    -- seq, not the ULID, is the order. Two ULIDs minted inside the same
    -- millisecond do not sort by creation time (their low bits are random
    -- entropy), so reading a trail "in recorded order" needs a monotonic
    -- column of its own rather than an ordering the id almost provides.
    seq                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id                  iam.ulid NOT NULL UNIQUE,
    clearance_group_id  iam.ulid NOT NULL REFERENCES iam.clearance_groups (id) ON DELETE RESTRICT,

    -- Deliberately NOT a foreign key to iam.principals, and NULL for a
    -- 'created' entry. The trail outlives the rows it describes: an
    -- expired agent run is garbage-collected, and the record of what it
    -- was cleared for must survive that collection. A foreign key here
    -- would force the choice between cascading the history away and
    -- refusing to collect.
    principal_id        iam.ulid,

    kind                text NOT NULL CHECK (kind IN ('created', 'added', 'removed')),
    channel             text NOT NULL CHECK (channel IN ('classify-permission', 'directory-sync')),
    actor_principal_id  iam.ulid NOT NULL,
    reason              text NOT NULL CHECK (reason <> ''),
    acted_at            timestamptz NOT NULL,
    recorded_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clearance_group_changes_principal_for_membership CHECK (
        (kind = 'created' AND principal_id IS NULL)
        OR
        (kind <> 'created' AND principal_id IS NOT NULL)
    )
);

CREATE INDEX clearance_group_changes_group_idx
    ON iam.clearance_group_changes (clearance_group_id, seq);

-- Append-only is enforced by the table, not by the application. A
-- mandatory control whose history can be edited is not evidence of
-- anything, and the application-layer guarantee (this module offers no
-- method that updates or deletes a trail entry) does not survive a future
-- task, a migration, or a hand-run statement during an incident.
-- +goose StatementBegin
CREATE FUNCTION iam.clearance_group_changes_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'iam.clearance_group_changes is append-only (attempted % on entry %)',
        TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER clearance_group_changes_append_only
    BEFORE UPDATE OR DELETE ON iam.clearance_group_changes
    FOR EACH ROW
    EXECUTE FUNCTION iam.clearance_group_changes_append_only();

-- ---------------------------------------------------------------------------
-- The artifact the authorization predicate joins
-- ---------------------------------------------------------------------------
--
-- iam.live_group_members is the shape design §9's predicate embeds:
--
--   EXISTS (
--     SELECT 1 FROM iam.live_group_members lgm
--     WHERE lgm.principal_id = $1 AND lgm.group_id = <the grant's group>
--   )
--
-- A view and not a materialized table, because it must be exactly as fresh
-- as the rows it reads. A materialized copy would need a refresh path, and
-- a refresh path for a *denial* is design §9.3's hazard: a stale denial is
-- a disclosure. Postgres inlines this view into the caller's plan, so the
-- probe still lands on iam.group_members' primary key.
--
-- It excludes two kinds of principal and, deliberately, not a third:
--
--   * Deprovisioned principals, so a deprovisioning denies in SQL in the
--     same instant it is recorded, without any membership row being
--     deleted and no audit history lost.
--   * Expired agent runs, by the same reasoning: the run stops matching at
--     its deadline rather than whenever the collector next sweeps.
--   * It does NOT exclude principals past the deployment's staleness
--     bound, and that is not an oversight. The bound is deployment
--     configuration, not a row: baking it into a view would hardcode
--     policy into the schema and make changing it a migration. Design
--     §8.1 puts the bound earlier anyway — a principal staler than the
--     bound "forces a re-sync before the request proceeds", so it is
--     enforced on the way in, before a predicate is ever compiled. See
--     the Registry port, whose GroupsOf refuses a stale principal outright.
--
-- It carries no tenant_id, which is a deliberate narrowing and not an
-- omission. An earlier draft joined iam.groups to expose one, and the
-- plan test (TestPredicatePlanIsAnIndexProbe) showed the cost: the
-- predicate does not use the column, so the join was pure overhead the
-- planner resolved with a scan of iam.groups on every decision. Tenant
-- scoping is not lost — a group id is unique across the deployment and is
-- itself tenant-scoped, so a grant naming a group id has already named a
-- tenant, and a predicate that joined tenant_id as well would be checking
-- the same thing twice. Every column here is one the predicate reads.
CREATE VIEW iam.live_group_members AS
SELECT
    m.principal_id,
    m.group_id,
    m.source
FROM iam.group_members m
JOIN iam.principals p ON p.id = m.principal_id
WHERE p.deprovisioned_at IS NULL
  AND (p.expires_at IS NULL OR p.expires_at > now());

-- The tier-2 counterpart, for the mandatory gate. Kept as its own view
-- over its own tables so a query written against one tier cannot
-- accidentally resolve against the other, and narrowed for the same
-- reason as its tier-1 twin.
CREATE VIEW iam.live_clearance_group_members AS
SELECT
    m.principal_id,
    m.clearance_group_id
FROM iam.clearance_group_members m
JOIN iam.principals p ON p.id = m.principal_id
WHERE p.deprovisioned_at IS NULL
  AND (p.expires_at IS NULL OR p.expires_at > now());

-- +goose Down
DROP VIEW IF EXISTS iam.live_clearance_group_members;

DROP VIEW IF EXISTS iam.live_group_members;

DROP TRIGGER IF EXISTS clearance_group_changes_append_only ON iam.clearance_group_changes;

DROP FUNCTION IF EXISTS iam.clearance_group_changes_append_only();

DROP TABLE IF EXISTS iam.clearance_group_changes;

DROP TABLE IF EXISTS iam.clearance_group_members;

DROP TABLE IF EXISTS iam.clearance_groups;

DROP TABLE IF EXISTS iam.group_members;

DROP TABLE IF EXISTS iam.groups;

DROP TABLE IF EXISTS iam.principals;
