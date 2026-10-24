-- F3 DAG-containment spike: fixture, generated server-side and deterministic.
--
-- Proportions are kgs A2's, scaled by ${SCALE} (1.0 = A2):
--
--     10,000,000 facts      2,000,000 entities      100,000 episodes
--         22,220 entity-sets in four nested levels, 5% of L3 double-parented
--          2,000 principals     200 overlapping groups     10,000 grants
--
-- Nothing uses random(): every assignment is a multiply-mod of the row's own
-- id, so two runs of this file produce byte-identical fixtures and a number
-- in the write-up can be re-derived.
--
-- Container id ranges, so an id in a transcript is self-describing:
--     1            tenant
--     2            graph
--     1000..       entity-set level 1
--     2000..       entity-set level 2
--     20000..      entity-set level 3
--     200000..     entity-set level 4
--     1000000..    episode

insert into container (id, kind, depth) values (1, 0, 0), (2, 1, 1);
insert into container_edge (child_id, parent_id) values (2, 1);

-- Entity-set levels. Fan-out 20 -> 200 -> 2,000 -> 20,000, ten children each.
insert into container (id, kind, depth)
select 1000 + g, 3, 2 from generate_series(0, ${N_ES1} - 1) g;
insert into container (id, kind, depth)
select 2000 + g, 3, 3 from generate_series(0, ${N_ES2} - 1) g;
insert into container (id, kind, depth)
select 20000 + g, 3, 4 from generate_series(0, ${N_ES3} - 1) g;
insert into container (id, kind, depth)
select 200000 + g, 3, 5 from generate_series(0, ${N_ES4} - 1) g;

insert into container_edge (child_id, parent_id)
select 1000 + g, 2 from generate_series(0, ${N_ES1} - 1) g;
insert into container_edge (child_id, parent_id)
select 2000 + g, 1000 + (g / 10) % ${N_ES1} from generate_series(0, ${N_ES2} - 1) g;
insert into container_edge (child_id, parent_id)
select 20000 + g, 2000 + (g / 10) % ${N_ES2} from generate_series(0, ${N_ES3} - 1) g;
insert into container_edge (child_id, parent_id)
select 200000 + g, 20000 + (g / 10) % ${N_ES3} from generate_series(0, ${N_ES4} - 1) g;

-- The second parent. Five per cent of level-3 sets are nested under a second
-- level-2 set, which is what makes container_ancestry itself a DAG closure and
-- not merely the fact level. "the school" under both "family" and "education".
-- The offset is 97 rather than a small number on purpose: a small offset keeps
-- the second parent inside the same level-1 branch, and then the DAG is local
-- and the measurement understates it. 97 puts it in a different branch, so a
-- level-3 set genuinely has two level-1 ancestors.
insert into container_edge (child_id, parent_id)
select 20000 + g, 2000 + ((g / 10) + 97) % ${N_ES2}
from generate_series(0, ${N_ES3} - 1) g
where g % 20 = 0
on conflict do nothing;

-- Episodes: one per ingested document, parented to the graph.
insert into container (id, kind, depth)
select 1000000 + g, 2, 2 from generate_series(0, ${N_EPISODE} - 1) g;
insert into container_edge (child_id, parent_id)
select 1000000 + g, 2 from generate_series(0, ${N_EPISODE} - 1) g;

-- ---------------------------------------------------------------------------
-- Entities and their entity-set membership.
--
-- Mean 1.5 direct memberships per entity: 20% of entities are in no set, 30%
-- in one, 30% in two, 20% in three. Seventy per cent of memberships land on
-- the finest level, 20% on level 3 and 10% on level 2, because a real
-- deployment grants on the coarse sets and files on the fine ones.
-- ---------------------------------------------------------------------------

-- generate_series is given bigint bounds throughout the fact and entity
-- generators: at scale 1.0 the mixing multiplications overflow int4 (g / 10 *
-- 7919 is 7.9e9 at g = 10,000,000), and the failure is a bare
-- "integer out of range" naming no column.
insert into entity (id, country)
select g, (g * 7) % 20 from generate_series(1::bigint, ${N_ENTITY}::bigint) g;

insert into entity_set_member (entity_id, set_id)
select entity_id, set_id
from (
    select e.id as entity_id,
           case when ll.lv < 70 then 200000 + (hh.hk % ${N_ES4})
                when ll.lv < 90 then  20000 + (hh.hk % ${N_ES3})
                else               2000 + (hh.hk % ${N_ES2}) end as set_id
    from entity e
    join generate_series(1, 3) k
      on k <= case when (e.id * 48271) % 100 < 20 then 0
                   when (e.id * 48271) % 100 < 50 then 1
                   when (e.id * 48271) % 100 < 80 then 2
                   else 3 end
    cross join lateral (select ((e.id * 48271 + k * 7919) % 2147483647) as hk) hh
    cross join lateral (select (hh.hk / 131) % 100 as lv) ll
) z
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Facts and their entity references.
--
-- A fact belongs to one episode. An episode is a document, and a document is
-- about a bounded pool of entities, so a fact draws its entities from the
-- hundred entities of its episode's topic -- otherwise every fact would reach
-- a uniformly random set of entity-sets and the DAG fan-out under test would
-- be an artefact of the generator rather than of the shape.
--
-- Sixty per cent of facts are attribute facts and reference one entity; 40%
-- are relation facts and reference two. One fact in ten references a HUB
-- entity out of a pool of 1,000 -- the ACME that appears in every document.
-- Hub entities are what make a single entity_set_member insert expensive, and
-- a fixture without them would make C1 and C4 look cheaper than they are.
-- ---------------------------------------------------------------------------

insert into fact (id, episode_id)
select g, 1000000 + (g % ${N_EPISODE}) from generate_series(1::bigint, ${N_FACT}::bigint) g;

-- The within-pool offset is derived from the fact's ORDINAL INSIDE its episode
-- (g / N_EPISODE) and not from g directly. An earlier version used (g * 37) %
-- 100, and because N_EPISODE is a multiple of 100 every fact of one episode
-- then had the same g mod 100 and therefore the same offset: the generator
-- produced one entity per topic, 1,400 referenced entities out of 2,000,000,
-- and a median entity degree of 500 instead of 7. The fan-out under test is a
-- property of the fixture, so a generator bug here is indistinguishable from a
-- finding -- which is why this comment is longer than the code.
insert into fact_entity (fact_id, entity_id)
select fact_id, entity_id
from (
    select g as fact_id,
           1 + ((g % ${N_EPISODE}) % ${N_TOPIC}) * 100
             + (((g / ${N_EPISODE}) * 37 + (g % ${N_EPISODE})) % 100) as entity_id
    from generate_series(1::bigint, ${N_FACT}::bigint) g
    union all
    select g,
           case when (g % 10) = 5
                then 1 + ((g / 10 * 7919) % ${N_HUB})
                else 1 + ((g % ${N_EPISODE}) % ${N_TOPIC}) * 100
                       + (((g / ${N_EPISODE}) * 61 + 13) % 100) end
    from generate_series(1::bigint, ${N_FACT}::bigint) g
    where (g % 5) < 2
) z
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Identity, groups and grants.
--
-- Every probe reaches its grant transitively -- principal -> leaf group ->
-- top group -> grant -- and carries eleven usersets, so the membership
-- closure join is not degenerate. Same construction as the F1 fixture.
-- ---------------------------------------------------------------------------

insert into principal select g from generate_series(1, ${N_PRINCIPAL} + 10) g;
insert into grp select g from generate_series(1, ${N_GROUP}) g;
insert into grp select 1000 + g from generate_series(0, 10 * 20) g;

-- Noise principals: five groups each, and the closure of that.
insert into group_member (group_id, principal_id)
select 1 + ((p * 31 + k * 13) % ${N_GROUP}), p
from generate_series(1, ${N_PRINCIPAL}) p, generate_series(1, 5) k
on conflict do nothing;
insert into membership_closure (principal_id, userset_id)
select principal_id, group_id from group_member
on conflict do nothing;

-- Probe principals 2001..2007.
insert into probe (name, principal, note) values
    ('p_graph', ${N_PRINCIPAL} + 1, 'grant on the graph'),
    ('p_es1',   ${N_PRINCIPAL} + 2, 'grant on one level-1 entity-set'),
    ('p_es2',   ${N_PRINCIPAL} + 3, 'grant on one level-2 entity-set'),
    ('p_es3',   ${N_PRINCIPAL} + 4, 'grant on one level-3 entity-set'),
    ('p_es4',   ${N_PRINCIPAL} + 5, 'grant on one level-4 entity-set'),
    ('p_epi',   ${N_PRINCIPAL} + 6, 'grant on ten episodes -- the tree-only principal'),
    ('p_mix',   ${N_PRINCIPAL} + 7, 'one level-3 set plus five episodes -- the household shape');

-- Eleven usersets per probe: a leaf group, the top group it is nested in, and
-- nine groups that grant nothing.
insert into membership_closure (principal_id, userset_id)
select p.principal, 1000 + (p.principal - ${N_PRINCIPAL}) * 20 + k
from probe p, generate_series(0, 10) k
on conflict do nothing;
insert into group_member (group_id, principal_id)
select 1000 + (p.principal - ${N_PRINCIPAL}) * 20, p.principal from probe p
on conflict do nothing;

-- The probes' grants, on the top group of each probe's chain.
insert into grant_tuple (userset_id, container_id, relation)
select 1000 + (p.principal - ${N_PRINCIPAL}) * 20 + 1, c.container_id, 1
from probe p
join lateral (
    select unnest(case p.name
        when 'p_graph' then array[2]
        when 'p_es1'   then array[1000]
        when 'p_es2'   then array[2000]
        when 'p_es3'   then array[20000]
        when 'p_es4'   then array[200000]
        when 'p_epi'   then array(select 1000000 + g from generate_series(0, 9) g)
        else                array[20005] || array(select 1000100 + g from generate_series(0, 4) g)
    end) as container_id
) c on true
on conflict do nothing;

-- A2's 10,000 grants, placed at every level. Graph-level grants are rare on
-- purpose: a tenth of ten thousand grants on the root would make every noise
-- principal omniscient and the fixture's selectivities meaningless.
insert into grant_tuple (userset_id, container_id, relation)
select 1 + (g % ${N_GROUP}),
       case when g % 1000 = 0            then 2
            when g % 10 = 1              then 1000    + (g % ${N_ES1})
            when g % 10 in (2, 3)        then 2000    + (g % ${N_ES2})
            when g % 10 in (4, 5, 6)     then 20000   + (g % ${N_ES3})
            when g % 10 in (7, 8)        then 200000  + (g % ${N_ES4})
            else                              1000000 + (g % ${N_EPISODE}) end,
       1
from generate_series(1, ${N_GRANT}) g
on conflict do nothing;

analyze;
