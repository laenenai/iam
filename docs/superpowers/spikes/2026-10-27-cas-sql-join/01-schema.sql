-- CAS SQL-join spike: schema.
--
-- Models the authorization read models the projector would maintain for
-- iam design §9.2/§11.2, plus a CAS-shaped consumer table. Nothing here is
-- proposed schema for the module; it exists to measure the join paths.
--
-- Two tenants:
--   laenen  10,000 filesets, 10,000,000 documents
--   acme     1,000 filesets,    100,000 documents
--
-- The tree is deliberately the shallow CAS tree the earlier design recorded:
-- tenant root > fileset > document. The generic closure still has a row per
-- node per ancestor, so a document has three closure rows (self, fileset,
-- root). The CAS-optimized path needs none of them: the consumer table
-- carries the document, fileset and root URNs.

drop schema if exists casjoin cascade;
create schema casjoin;
set search_path = casjoin, public;

-- ---------------------------------------------------------------------------
-- Tenant and relation vocabulary
-- ---------------------------------------------------------------------------

create table tenants (
    tenant_id text primary key
);

create table relations (
    relation text primary key,
    rank     smallint not null
);

insert into relations (relation, rank) values
    ('viewer', 1),
    ('commenter', 2),
    ('editor', 3),
    ('owner', 4);

-- ---------------------------------------------------------------------------
-- Subjects. Groups are flat and human-only, as in the design. Agents are
-- present so the join path does not accidentally assume users only.
-- ---------------------------------------------------------------------------

create table iam_subjects (
    tenant_id   text not null,
    subject_urn text not null,
    kind        text not null check (kind in ('user', 'agent', 'group')),
    live        boolean not null default true,
    primary key (tenant_id, subject_urn)
);

-- ---------------------------------------------------------------------------
-- Nodes and the tree closure. A node is a root, fileset or document.
-- ---------------------------------------------------------------------------

create table iam_nodes (
    tenant_id  text not null,
    urn        text not null,
    kind       text not null,          -- root | fileset | document
    parent_urn text,
    live       boolean not null default true,
    primary key (tenant_id, urn)
);

create table iam_node_closure (
    tenant_id      text not null,
    descendant_urn text not null,
    ancestor_urn   text not null,
    depth          smallint not null,
    primary key (tenant_id, descendant_urn, ancestor_urn)
);

-- ---------------------------------------------------------------------------
-- Direct grants. relation_rank is denormalized so the query can ask
-- "viewer or stronger" without a CASE or a relation table hop.
-- ---------------------------------------------------------------------------

create table iam_grants (
    tenant_id    text not null,
    grant_id     bigint not null,
    object_urn   text not null,
    subject_urn  text not null,
    relation     text not null,
    relation_rank smallint not null,
    granted_by   text not null,
    granted_at   timestamptz not null,
    live         boolean not null default true,
    primary key (tenant_id, grant_id)
);

-- ---------------------------------------------------------------------------
-- Group membership. Flat, as in v1. The member is a user or an agent.
-- ---------------------------------------------------------------------------

create table iam_group_members (
    tenant_id  text not null,
    group_urn  text not null,
    member_urn text not null,
    live       boolean not null default true,
    primary key (tenant_id, group_urn, member_urn)
);

-- ---------------------------------------------------------------------------
-- The deprovisioning filter. Deactivation updates this table and leaves the
-- grants and tuples in place; the query must consult it or the direct-grant
-- leak returns.
-- ---------------------------------------------------------------------------

create table iam_live_subjects (
    tenant_id   text not null,
    subject_urn text not null,
    live        boolean not null,
    primary key (tenant_id, subject_urn)
);

-- ---------------------------------------------------------------------------
-- The consumer table. CAS needs to filter these rows in the same statement
-- that lists them. It carries the direct and root ancestors so the
-- CAS-optimized path can avoid the generic closure table.
-- ---------------------------------------------------------------------------

create table cas_documents (
    tenant_id   text not null,
    id          bigint not null,
    urn         text not null,
    fileset_urn text not null,
    root_urn    text not null,
    title       text not null,
    body        text,
    created_at  timestamptz not null,
    primary key (tenant_id, id)
);

-- The application role used to prove RLS. It is created before any query
-- file is loaded, so 04-queries.sql can grant it select on accessible_urns.
drop role if exists casjoin_app;
create role casjoin_app nologin;
grant usage on schema casjoin to casjoin_app;
grant select on all tables in schema casjoin to casjoin_app;
