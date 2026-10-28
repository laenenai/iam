-- CAS SQL-join spike: query paths.
--
-- Four paths are compared:
--
--   closure     generic IAM read model: cas_documents -> iam_node_closure
--               -> iam_grants, with the live-subject filter and the node
--               tombstone filter. Document-driven: walks the page index and
--               tests each document. Fast when access is broad.
--   denorm      CAS-optimized: cas_documents carries urn, fileset_urn and
--               root_urn, so it joins iam_grants directly and never touches
--               iam_node_closure. Still document-driven.
--   grant       Grant-driven: resolve the subject's accessible ancestors
--               first, expand them to documents through the closure, then
--               sort the small candidate set. Fast when access is narrow.
--   listobjects the v1 baseline: IAM's ListObjects returns URNs, the consumer
--               puts them in a relation and joins cas_documents to it. The
--               cost of producing the URN list is measured separately.
--
-- All four apply the same relation ladder and the same liveness filter.

\set ON_ERROR_STOP on
set search_path = casjoin, public;

drop table if exists accessible_urns cascade;
create table accessible_urns (
    tenant_id   text not null,
    subject_urn text not null,
    urn         text not null,
    primary key (tenant_id, subject_urn, urn)
);
create index accessible_urns_lookup
    on accessible_urns (tenant_id, subject_urn, urn);

grant select on accessible_urns to casjoin_app;

-- ---------------------------------------------------------------------------
-- SQL text, kept in one place so correctness and benchmarks cannot drift.
-- $1 subject, $2 relation rank, $3 tenant.
-- ---------------------------------------------------------------------------

create or replace function sql_count(p_path text) returns text
language sql immutable as $fn$
select case p_path
when 'closure' then $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    )
    select count(*)
    from cas_documents d
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3
      and exists (
        select 1
        from iam_node_closure c
        join iam_grants g
          on g.tenant_id = c.tenant_id
         and g.object_urn = c.ancestor_urn
         and g.relation_rank >= $2
         and g.live
         and g.subject_urn in (select urn from my_subjects)
        where c.tenant_id = d.tenant_id and c.descendant_urn = d.urn
      )
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
$q$
when 'denorm' then $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    )
    select count(*)
    from cas_documents d
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3
      and exists (
        select 1
        from iam_grants g
        where g.tenant_id = d.tenant_id
          and g.object_urn in (d.urn, d.fileset_urn, d.root_urn)
          and g.relation_rank >= $2
          and g.live
          and g.subject_urn in (select urn from my_subjects)
      )
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
$q$
when 'grant' then $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    ),
    accessible_ancestors as (
        select distinct g.object_urn as ancestor_urn
        from iam_grants g
        where g.tenant_id = $3
          and g.relation_rank >= $2
          and g.live
          and g.subject_urn in (select urn from my_subjects)
    ),
    accessible_docs as (
        select distinct c.descendant_urn as urn
        from accessible_ancestors a
        join iam_node_closure c
          on c.tenant_id = $3 and c.ancestor_urn = a.ancestor_urn
    )
    select count(*)
    from cas_documents d
    join accessible_docs a on a.urn = d.urn
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
$q$
when 'listobjects' then $q$
    select count(*)
    from cas_documents d
    join accessible_urns a
      on a.tenant_id = d.tenant_id and a.urn = d.urn
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where a.tenant_id = $3 and a.subject_urn = $1
$q$
else null end
$fn$;

create or replace function sql_page(p_path text) returns text
language sql immutable as $fn$
select case p_path
when 'closure' then $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    )
    select d.id, d.urn, d.title, d.created_at
    from cas_documents d
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3
      and exists (
        select 1
        from iam_node_closure c
        join iam_grants g
          on g.tenant_id = c.tenant_id
         and g.object_urn = c.ancestor_urn
         and g.relation_rank >= $2
         and g.live
         and g.subject_urn in (select urn from my_subjects)
        where c.tenant_id = d.tenant_id and c.descendant_urn = d.urn
      )
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
    order by d.created_at desc, d.id desc
    limit 50
$q$
when 'denorm' then $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    )
    select d.id, d.urn, d.title, d.created_at
    from cas_documents d
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3
      and exists (
        select 1
        from iam_grants g
        where g.tenant_id = d.tenant_id
          and g.object_urn in (d.urn, d.fileset_urn, d.root_urn)
          and g.relation_rank >= $2
          and g.live
          and g.subject_urn in (select urn from my_subjects)
      )
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
    order by d.created_at desc, d.id desc
    limit 50
$q$
when 'grant' then $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    ),
    accessible_ancestors as (
        select distinct g.object_urn as ancestor_urn
        from iam_grants g
        where g.tenant_id = $3
          and g.relation_rank >= $2
          and g.live
          and g.subject_urn in (select urn from my_subjects)
    ),
    accessible_docs as (
        select distinct c.descendant_urn as urn
        from accessible_ancestors a
        join iam_node_closure c
          on c.tenant_id = $3 and c.ancestor_urn = a.ancestor_urn
    )
    select d.id, d.urn, d.title, d.created_at
    from cas_documents d
    join accessible_docs a on a.urn = d.urn
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
    order by d.created_at desc, d.id desc
    limit 50
$q$
when 'listobjects' then $q$
    select d.id, d.urn, d.title, d.created_at
    from cas_documents d
    join accessible_urns a
      on a.tenant_id = d.tenant_id and a.urn = d.urn
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where a.tenant_id = $3 and a.subject_urn = $1
    order by d.created_at desc, d.id desc
    limit 50
$q$
else null end
$fn$;

create or replace function sql_point() returns text
language sql immutable as $fn$
select $q$
    with my_subjects as (
        select $1::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = $3 and gm.member_urn = $1 and gm.live
    )
    select d.id, d.urn, d.title, d.created_at
    from cas_documents d
    join iam_nodes n
      on n.tenant_id = d.tenant_id and n.urn = d.urn and n.live
    where d.tenant_id = $3 and d.urn = $4
      and exists (
        select 1
        from iam_node_closure c
        join iam_grants g
          on g.tenant_id = c.tenant_id
         and g.object_urn = c.ancestor_urn
         and g.relation_rank >= $2
         and g.live
         and g.subject_urn in (select urn from my_subjects)
        where c.tenant_id = d.tenant_id and c.descendant_urn = d.urn
      )
      and exists (
        select 1 from iam_live_subjects s
        where s.tenant_id = d.tenant_id and s.subject_urn = $1 and s.live
      )
    limit 1
$q$
$fn$;

-- ---------------------------------------------------------------------------
-- Query wrappers.
-- ---------------------------------------------------------------------------

create or replace function query_count(
    p_path text, p_subject text, p_rank int, p_tenant text
) returns bigint
language plpgsql as $fn$
declare
    n bigint;
    q text;
begin
    q := sql_count(p_path);
    if q is null then
        raise exception 'unknown path %', p_path;
    end if;
    execute q into n using p_subject, p_rank, p_tenant;
    return n;
end
$fn$;

create or replace function query_page(
    p_path text, p_subject text, p_rank int, p_tenant text
) returns table (id bigint, urn text, title text, created_at timestamptz)
language plpgsql as $fn$
declare
    q text;
begin
    q := sql_page(p_path);
    if q is null then
        raise exception 'unknown path %', p_path;
    end if;
    return query execute q using p_subject, p_rank, p_tenant;
end
$fn$;

create or replace function query_point(
    p_subject text, p_rank int, p_tenant text, p_object text
) returns table (id bigint, urn text, title text, created_at timestamptz)
language plpgsql as $fn$
begin
    return query execute sql_point() using p_subject, p_rank, p_tenant, p_object;
end
$fn$;

-- ---------------------------------------------------------------------------
-- Populate the ListObjects baseline. This is the reference effective set:
-- closure + grants + group membership + live subject + live node. Its cost is
-- the cost of ListObjects, and it is measured separately from the join.
-- ---------------------------------------------------------------------------

create or replace function populate_accessible(
    p_subject text, p_rank int, p_tenant text
) returns bigint
language plpgsql as $fn$
declare
    n bigint;
begin
    delete from accessible_urns
    where tenant_id = p_tenant and subject_urn = p_subject;

    insert into accessible_urns (tenant_id, subject_urn, urn)
    with my_subjects as (
        select p_subject::text as urn
        union
        select gm.group_urn
        from iam_group_members gm
        where gm.tenant_id = p_tenant
          and gm.member_urn = p_subject
          and gm.live
    )
    select distinct p_tenant, p_subject, c.descendant_urn
    from iam_node_closure c
    join iam_grants g
      on g.tenant_id = c.tenant_id
     and g.object_urn = c.ancestor_urn
     and g.relation_rank >= p_rank
     and g.live
     and g.subject_urn in (select urn from my_subjects)
    join iam_nodes n
      on n.tenant_id = c.tenant_id and n.urn = c.descendant_urn
     and n.live and n.kind = 'document'
    join iam_live_subjects s
      on s.tenant_id = p_tenant and s.subject_urn = p_subject and s.live
    where c.tenant_id = p_tenant;

    get diagnostics n = row_count;
    return n;
end
$fn$;
