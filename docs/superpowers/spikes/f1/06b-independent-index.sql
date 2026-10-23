-- Independent (adversarial) layout: flat table indexes.
-- Split from the partitioned build so the two big serial HNSW builds can run
-- concurrently on separate cores -- a serial HNSW build is single-threaded, so
-- two of them cost roughly one build's wall-clock on a multi-core box.
set search_path = f1, public;
set max_parallel_maintenance_workers = 0;
set maintenance_work_mem = '6GB';
\timing on
create index facts_flat_i_zone on facts_flat_i (zone) include (container_id);
create index facts_flat_i_container on facts_flat_i (container_id);
create index facts_flat_i_hnsw on facts_flat_i
    using hnsw (embedding halfvec_cosine_ops) with (m = 16, ef_construction = 64);
analyze facts_flat_i;
\timing off
