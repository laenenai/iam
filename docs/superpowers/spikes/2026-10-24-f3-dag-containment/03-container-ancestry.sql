-- F3: the small closure. container -> every ancestor by any path, incl. self.
--
-- This is the only closure C2, C4 and C5 materialize, and the whole question
-- F3 asks is whether it is enough. It is bounded by the number of CONTAINERS
-- (122,222 here), never by the number of facts, and it is a DAG closure --
-- UNION rather than UNION ALL, because the double-parented level-3 sets mean
-- the same ancestor is reached twice.

insert into container_ancestry (container_id, ancestor_id)
with recursive a (container_id, ancestor_id) as (
    select id, id from container
  union
    select a.container_id, e.parent_id
    from a
    join container_edge e on e.child_id = a.ancestor_id
)
select container_id, ancestor_id from a;

-- The view every fact-level strategy shares: a fact's DIRECT containers.
-- One episode, plus one row per (referenced entity, entity-set) pair. The
-- entity hop is what makes this a derived rather than a declared edge.
create or replace view fact_direct_container as
select f.id as fact_id, f.episode_id as container_id
from fact f
union all
select fe.fact_id, esm.set_id
from fact_entity fe
join entity_set_member esm on esm.entity_id = fe.entity_id;

analyze container_ancestry;
