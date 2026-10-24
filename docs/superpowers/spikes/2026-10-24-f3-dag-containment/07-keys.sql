-- F3, question 2: what happens to F1's scalar containment key.
--
-- F1's key is "one scalar column per row holding the id of the row's ancestor
-- at a declared containment depth". A DAG has no single ancestor at a depth,
-- so five candidates are built side by side on the same 10,000,000 rows:
--
--   K1  ep_zone    int     the scalar key F1 specified, declared on the TREE
--                          dimension: the fact's episode. It exists in a DAG;
--                          the question is what it prunes.
--   K2  zones      int[]   every direct container, GIN. The array key F1
--                          predicted F3 would force.
--   K3  zones3     int[]   the same, lifted to entity-set level 3, so the
--                          array is shorter and the key set smaller.
--   K4  ep_zone + set_zones     one key per containment KIND.
--   K5  canon_zone int     a single designated canonical container per fact.
--
-- They live on one table rather than five so the comparison is between index
-- and query shapes and not between table layouts.

-- The lift is a property of the container, so it is computed once over 122,222
-- containers rather than per fact. (An earlier version of this file did it as
-- a correlated subquery inside the fact-level aggregate: 31,000,000
-- executions of a two-table join, which is not a measurement of anything.)
drop table if exists container_lift3 cascade;
create table container_lift3 as
select c.id as container_id,
       coalesce(
           (select min(ca.ancestor_id)
            from container_ancestry ca
            join container cc on cc.id = ca.ancestor_id
            where ca.container_id = c.id and cc.kind = 3 and cc.depth = 4),
           c.id) as lifted
from container c;
alter table container_lift3 add primary key (container_id);
analyze container_lift3;

drop table if exists fact_key cascade;

create table fact_key as
select f.id,
       f.episode_id                            as ep_zone,
       coalesce(z.zones,  array[f.episode_id]) as zones,
       coalesce(z.zones3, array[f.episode_id]) as zones3,
       coalesce(z.set_zones, '{}'::int[])      as set_zones,
       coalesce(z.canon,  f.episode_id)        as canon_zone
from fact f
left join (
    select fc.fact_id,
           array_agg(distinct fc.container_id)                          as zones,
           array_agg(distinct l.lifted)                                 as zones3,
           array_agg(distinct fc.container_id) filter (where c.kind = 3) as set_zones,
           (array_agg(fc.container_id order by c.depth desc, fc.container_id)
              filter (where c.kind = 3))[1]                             as canon
    from fact_container fc
    join container c on c.id = fc.container_id
    join container_lift3 l on l.container_id = fc.container_id
    group by fc.fact_id
) z on z.fact_id = f.id;

alter table fact_key add primary key (id);
create index fact_key_ep     on fact_key (ep_zone, id);
create index fact_key_canon  on fact_key (canon_zone, id);
create index fact_key_zones  on fact_key using gin (zones);
create index fact_key_zones3 on fact_key using gin (zones3);
create index fact_key_setz   on fact_key using gin (set_zones);
analyze fact_key;
