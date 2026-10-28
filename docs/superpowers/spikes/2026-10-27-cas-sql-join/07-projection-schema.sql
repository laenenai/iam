-- OpenFGA change-feed projection spike: schema.
--
-- Source tables are the fixture's expected state. The projection tables are
-- built only from OpenFGA's ReadChanges feed. If the two diverge, the feed
-- did not carry something the log would have.
--
-- The projection deliberately has no granted_by, grant_id or model version:
-- OpenFGA tuple changes do not carry them. Those columns stay in the source
-- tables and are the concrete evidence for why the log remains the record.

\set ON_ERROR_STOP on
drop schema if exists proj cascade;
create schema proj;
set search_path = proj, public;

-- ---------------------------------------------------------------------------
-- Source fixture (expected state)
-- ---------------------------------------------------------------------------

create table src_nodes (
    urn        text primary key,
    kind       text not null,
    parent_urn text,
    live       boolean not null default true
);

create table src_grants (
    grant_id      bigint primary key,
    object_urn    text not null,
    subject_urn   text not null,
    subject_kind  text not null check (subject_kind in ('user', 'group')),
    relation      text not null,
    relation_rank smallint not null,
    granted_by    text not null,
    granted_at    timestamptz not null,
    live          boolean not null default true
);

create table src_group_members (
    group_urn  text not null,
    member_urn text not null,
    primary key (group_urn, member_urn)
);

create table src_live_subjects (
    subject_urn text primary key,
    live        boolean not null
);

create table src_docs (
    id          bigint primary key,
    urn         text not null unique,
    fileset_urn text not null,
    title       text not null
);

-- ---------------------------------------------------------------------------
-- Projection built from OpenFGA ReadChanges
-- ---------------------------------------------------------------------------

create table iam_nodes_proj (
    tenant_id  text not null,
    urn        text not null,
    kind       text not null,
    parent_urn text,
    live       boolean not null default true,
    primary key (tenant_id, urn)
);

create table iam_grants_proj (
    tenant_id     text not null,
    object_urn    text not null,
    subject_urn   text not null,
    subject_kind  text not null check (subject_kind in ('user', 'agent', 'group')),
    relation      text not null,
    relation_rank smallint not null,
    granted_at    timestamptz,
    primary key (tenant_id, object_urn, subject_urn, relation)
);

create table iam_group_members_proj (
    tenant_id  text not null,
    group_urn  text not null,
    member_urn text not null,
    primary key (tenant_id, group_urn, member_urn)
);

create table iam_agents_proj (
    tenant_id      text not null,
    agent_urn      text not null,
    supervisor_urn text,
    can_act_for    text[] not null default '{}',
    primary key (tenant_id, agent_urn)
);

-- This table is intentionally not fed by ReadChanges: deactivation keeps the
-- tuples and only the log event changes liveness.
create table iam_live_subjects_proj (
    tenant_id   text not null,
    subject_urn text not null,
    live        boolean not null,
    primary key (tenant_id, subject_urn)
);

create table projection_cursor (
    id                int primary key default 1 check (id = 1),
    continuation_token text,
    changes_applied   bigint not null default 0,
    last_change_at    timestamptz,
    updated_at        timestamptz not null default now()
);
insert into projection_cursor (id) values (1);
