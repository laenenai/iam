-- F3, strategy C1: §9.2's ancestry closure taken literally in a DAG --
-- fact -> every ancestor reachable by any path, materialized at fact
-- cardinality.
--
-- Batched by fact id so each DISTINCT fits in work_mem; an unbatched
-- INSERT ... SELECT DISTINCT over the whole table spills to disk and the
-- measurement becomes a measurement of temp I/O.

do $$
declare
    lo bigint;
    batch bigint := ${C1_BATCH};
begin
    for lo in 1 .. ${N_FACT} by batch loop
        insert into fact_ancestry (fact_id, ancestor_id)
        select distinct d.fact_id, ca.ancestor_id
        from fact_direct_container d
        join container_ancestry ca on ca.container_id = d.container_id
        where d.fact_id >= lo and d.fact_id < lo + batch;
    end loop;
end $$;
