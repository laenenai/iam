-- F3, strategy C4: fact -> its DIRECT containers only. The transitive part
-- stays in container_ancestry and is joined at read time.
--
-- The point of C4 against C1 is that a NESTING change (an entity-set moved or
-- re-parented) touches no row here at all, while it rewrites C1 at fact
-- cardinality. The point against C2 is that a MEMBERSHIP change (an entity
-- added to a set) still does touch it, once per fact referencing the entity.

do $$
declare
    lo bigint;
    batch bigint := ${C1_BATCH};
begin
    for lo in 1 .. ${N_FACT} by batch loop
        insert into fact_container (fact_id, container_id)
        select distinct d.fact_id, d.container_id
        from fact_direct_container d
        where d.fact_id >= lo and d.fact_id < lo + batch;
    end loop;
end $$;

alter table fact_container add primary key (fact_id, container_id);
create index fact_container_container on fact_container (container_id, fact_id);
analyze fact_container;
