-- F1 filtered-ANN spike: partitioned copy + indexes.
--
-- facts_part holds the same 2,000,000 rows as facts_flat, LIST-partitioned on
-- `zone` (the L4 container). One partition per zone, 1,000 partitions of
-- 2,000 rows. This is strategy (b): the authorization key is the partition
-- key, so the planner can prune the candidate set before any ANN work
-- happens, and each surviving partition carries its own HNSW graph.
--
-- 1,000 partitions is already near the practical ceiling for a partitioned
-- table that must be planned on every query; see the write-up on why this
-- does not scale in the number of zones.

set search_path = f1, public;

\timing on

-- 1,000 LIST partitions, one per L4 container.
do $$
declare z int;
begin
    for z in select id from container where depth = 4 order by id loop
        execute format(
            'create table facts_part_z%s partition of facts_part for values in (%s)',
            z, z);
    end loop;
end $$;

insert into facts_part (id, container_id, zone, embedding)
select id, container_id, zone, embedding from facts_flat;

-- Indexes on the flat table. The btree on `zone` is what makes strategy
-- (b3) (key as a qual, no partitioning) and the exact ground-truth scan
-- affordable at low selectivity.
create index facts_flat_zone on facts_flat (zone) include (container_id);
create index facts_flat_container on facts_flat (container_id);

\timing off

-- The HNSW builds live in 03b-hnsw.sql: they need
-- max_parallel_maintenance_workers = 0 in this container, and the reason is
-- worth reading before anyone repeats this on a laptop.
