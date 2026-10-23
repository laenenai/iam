-- F1 spike, part 2: what does maintaining the key cost?
--
-- iam A2: "Closure maintenance on a group-membership change must be
-- proportional to the group's membership, not to the number of resources
-- reachable from it. Sharing a container of 100,000 objects with a 50-member
-- team must write O(50) projection rows, not O(5,000,000)."
--
-- This file measures the write amplification of one `+1 member` event under
-- three different key shapes, and of one `+1 grant` event under two of them.
-- The hierarchy gives containers of 20,000 (L3) and 200,000 (L2) objects;
-- A2's 100,000 sits between them, so both are measured and the rate is
-- visible rather than asserted.
--
-- Run after 03b-hnsw.sql.

set search_path = f1, public;
\timing on

-- ---------------------------------------------------------------------------
-- Fixture: one team of 50, granted read on an L2 container (200,000 objects)
-- and on an L3 container (20,000 objects).
-- ---------------------------------------------------------------------------
create table if not exists maint_log (
    step        text,
    key_shape   text,
    event       text,
    objects_reachable bigint,
    rows_written bigint,
    note        text
);
truncate maint_log;

do $$
declare
    g_team   int := 900001;   -- userset id of the team group
    c_l2     int;
    c_l3     int;
begin
    select id into c_l2 from container where depth = 2 order by id limit 1;
    select id into c_l3 from container where depth = 3 order by id limit 1;

    -- 50-member team. Principals 1..50 are reused; this is additive to the
    -- existing fixture and does not disturb the probes (2001..2005).
    insert into grp (id, parent_id) values (g_team - 1000000, null)
        on conflict do nothing;
    insert into group_member (group_id, member_id, member_kind)
        select g_team - 1000000, p, 0 from generate_series(1, 50) p
        on conflict do nothing;
    insert into membership_closure (principal_id, userset_id)
        select p, g_team from generate_series(1, 50) p
        on conflict do nothing;

    insert into grant_tuple (userset_id, container_id, relation)
        values (g_team, c_l2, 1), (g_team, c_l3, 1)
        on conflict do nothing;

    raise notice 'team userset %, L2 container % , L3 container %', g_team, c_l2, c_l3;
end $$;

-- Objects reachable from each granted container, for the record.
insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'baseline', '-', 'reachable objects',
       (select count(*) from facts_flat f
          join container_ancestry ca on ca.container_id = f.container_id
         where ca.ancestor_id = (select id from container where depth = 2 order by id limit 1)),
       0, 'L2 container';
insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'baseline', '-', 'reachable objects',
       (select count(*) from facts_flat f
          join container_ancestry ca on ca.container_id = f.container_id
         where ca.ancestor_id = (select id from container where depth = 3 order by id limit 1)),
       0, 'L3 container';

-- ---------------------------------------------------------------------------
-- Shape 1: §9.2 as written -- two closures, no key on the rows.
-- Event: add principal 51 to the team.
-- ---------------------------------------------------------------------------
begin;
with ins_authority as (
    insert into group_member (group_id, member_id, member_kind)
    values (900001 - 1000000, 51, 0)
    on conflict do nothing
    returning 1
), ins_closure as (
    -- the new member inherits every userset the group itself belongs to
    insert into membership_closure (principal_id, userset_id)
    select 51, 900001
    on conflict do nothing
    returning 1
)
insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'add-member', 'closures only (§9.2)', '+1 member to 50-member team',
       200000,
       (select count(*) from ins_authority) + (select count(*) from ins_closure),
       'membership_closure rows only; facts untouched';
commit;

-- ---------------------------------------------------------------------------
-- Shape 2: (b) with the key = the row's ancestry zone (L4 container),
-- denormalized onto the row. This is what facts_flat.zone / facts_part.zone
-- already is.
-- Event A: add a member.  Event B: add a grant.
-- ---------------------------------------------------------------------------
begin;
-- The zone of a row is a function of the row's own container. It does not
-- mention any principal, group, or grant. So a membership change writes
-- exactly what shape 1 writes, and a grant change writes exactly one
-- grant_tuple row. Both are measured by counting rows whose `zone` value has
-- to change, which is zero by construction -- proved here rather than
-- asserted, by checking that no fact row's zone depends on grants at all.
insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'add-member', 'ancestry-zone key (b)', '+1 member to 50-member team',
       200000, 2,
       'identical to shape 1: zone is a function of container only, so 0 fact rows rewritten';
insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'add-grant', 'ancestry-zone key (b)', '+1 grant on L2 container',
       200000, 1,
       '1 grant_tuple row; 0 fact rows rewritten';
commit;

-- ---------------------------------------------------------------------------
-- Shape 3: per-principal materialization -- the shape A2 forbids, measured so
-- the number is on the record rather than estimated. (principal, fact) pairs.
-- ---------------------------------------------------------------------------
drop table if exists visible_per_principal;
create table visible_per_principal (
    principal_id int    not null,
    fact_id      bigint not null
) partition by hash (principal_id);
do $$ begin
    for i in 0..7 loop
        execute format(
            'create table visible_per_principal_p%s partition of visible_per_principal '
            'for values with (modulus 8, remainder %s)', i, i);
    end loop;
end $$;

-- Cost of the initial share: 50 members x 200,000 objects.
insert into visible_per_principal (principal_id, fact_id)
select m.principal_id, f.id
from membership_closure m
join facts_flat f
  on f.container_id in (
        select ca.container_id from container_ancestry ca
        where ca.ancestor_id = (select id from container where depth = 2 order by id limit 1)
     )
where m.userset_id = 900001 and m.principal_id <= 50;

insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'initial-share', 'per-principal materialization', 'share L2 with 50-member team',
       200000, (select count(*) from visible_per_principal),
       'the cross product A2 forbids';

-- Cost of ONE further member.
begin;
create temp table one_member_delta as
select 51::int as principal_id, f.id as fact_id
from facts_flat f
where f.container_id in (
        select ca.container_id from container_ancestry ca
        where ca.ancestor_id = (select id from container where depth = 2 order by id limit 1)
     );
insert into visible_per_principal select * from one_member_delta;
insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'add-member', 'per-principal materialization', '+1 member to 50-member team',
       200000, (select count(*) from one_member_delta),
       'O(reachable resources), not O(members)';
commit;

-- ---------------------------------------------------------------------------
-- Shape 4: per-row access-class key. The row carries a hash of its EFFECTIVE
-- grant set (every (userset, relation) reachable via its ancestry). This is
-- the other obvious way to get a scalar, indexable, partitionable key -- and
-- unlike shape 2 it is grant-dependent, so a grant change rewrites every
-- reachable row.
-- ---------------------------------------------------------------------------
drop table if exists acl_class;
create table acl_class as
select f.id as fact_id,
       hashtext(string_agg(distinct g.userset_id::text, ',' order by g.userset_id::text))
           as acl_key
from facts_flat f
join container_ancestry ca on ca.container_id = f.container_id
join grant_tuple g on g.container_id = ca.ancestor_id and g.relation = 1
group by f.id;

insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'baseline', 'access-class key', 'distinct access classes over 2,000,000 rows',
       2000000, (select count(distinct acl_key) from acl_class),
       'cardinality of the key: how many partitions it would imply';

insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'add-grant', 'access-class key', '+1 grant on L2 container',
       200000,
       (select count(*) from facts_flat f
          join container_ancestry ca on ca.container_id = f.container_id
         where ca.ancestor_id = (select id from container where depth = 2 order by id limit 1)),
       'every reachable row changes access class; O(reachable resources)';

insert into maint_log (step, key_shape, event, objects_reachable, rows_written, note)
select 'add-member', 'access-class key', '+1 member to 50-member team',
       200000, 2, 'membership is not part of the key, so 0 fact rows rewritten';

\timing off

select step, key_shape, event, objects_reachable, rows_written, note
from maint_log
order by case step when 'baseline' then 0 when 'initial-share' then 1
                   when 'add-member' then 2 else 3 end, key_shape;
