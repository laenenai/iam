-- Independent (adversarial) layout: partitioned copy + per-partition HNSW.
set search_path = f1, public;
set max_parallel_maintenance_workers = 0;
set maintenance_work_mem = '6GB';
\timing on
insert into facts_part_i (id, container_id, zone, embedding)
select id, container_id, zone, embedding from facts_flat_i;
create index facts_part_i_container on facts_part_i (container_id);
create index facts_part_i_hnsw on facts_part_i
    using hnsw (embedding halfvec_cosine_ops) with (m = 16, ef_construction = 64);
analyze facts_part_i;
\timing off
