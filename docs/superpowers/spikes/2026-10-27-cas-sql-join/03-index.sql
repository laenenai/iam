-- CAS SQL-join spike: indexes, RLS, statistics.
--
-- The indexes are the ones the projector's read models need. The CAS page
-- index is the one a consumer would already have; it is included so the
-- authorization work is measured on top of a realistic ordered page.

\set ON_ERROR_STOP on
set search_path = casjoin, public;
\timing on

create index iam_nodes_parent_idx
    on iam_nodes (tenant_id, parent_urn);

create index iam_node_closure_ancestor_idx
    on iam_node_closure (tenant_id, ancestor_urn, descendant_urn);

create index iam_grants_lookup_idx
    on iam_grants (tenant_id, object_urn, relation_rank, subject_urn)
    where live;

create index iam_grants_subject_idx
    on iam_grants (tenant_id, subject_urn, relation_rank, object_urn)
    where live;

create index iam_group_members_member_idx
    on iam_group_members (tenant_id, member_urn, group_urn)
    where live;

create unique index cas_documents_urn_idx
    on cas_documents (tenant_id, urn);

create index cas_documents_page_idx
    on cas_documents (tenant_id, created_at desc, id desc);

create index cas_documents_fileset_idx
    on cas_documents (tenant_id, fileset_urn);

analyze;

-- ---------------------------------------------------------------------------
-- RLS. The benchmark runs as casjoin_app, which is not the table owner, so
-- these policies apply. The tenant comes from app.tenant, never from the
-- caller's predicate.
-- ---------------------------------------------------------------------------

grant select on all tables in schema casjoin to casjoin_app;

alter table casjoin.cas_documents       enable row level security;
alter table casjoin.iam_nodes           enable row level security;
alter table casjoin.iam_node_closure    enable row level security;
alter table casjoin.iam_grants          enable row level security;
alter table casjoin.iam_group_members   enable row level security;
alter table casjoin.iam_live_subjects   enable row level security;

create policy tenant_isolation on casjoin.cas_documents
    using (tenant_id = current_setting('app.tenant', true));
create policy tenant_isolation on casjoin.iam_nodes
    using (tenant_id = current_setting('app.tenant', true));
create policy tenant_isolation on casjoin.iam_node_closure
    using (tenant_id = current_setting('app.tenant', true));
create policy tenant_isolation on casjoin.iam_grants
    using (tenant_id = current_setting('app.tenant', true));
create policy tenant_isolation on casjoin.iam_group_members
    using (tenant_id = current_setting('app.tenant', true));
create policy tenant_isolation on casjoin.iam_live_subjects
    using (tenant_id = current_setting('app.tenant', true));

analyze;
