-- Per-partition HNSW, plus the ANALYZEs. Split out of 03b-hnsw.sql only so
-- the two long builds can be restarted independently.
--
-- Measured build times on the environment in the write-up:
--   facts_flat_hnsw  (one graph, 2,000,000 elements)   18 min  4 s
--   facts_part_hnsw  (1,000 graphs of 2,000 elements)  ~11 min  (~0.65 s each)
-- A single partition's index built on its own takes ~0.54 s, so building all
-- 1,000 through the partitioned parent costs essentially the same as building
-- them one at a time -- there is no penalty for the one-statement form.
set search_path = f1, public;
set max_parallel_maintenance_workers = 0;
set maintenance_work_mem = '4GB';
\timing on

create index if not exists facts_part_hnsw on facts_part
    using hnsw (embedding halfvec_cosine_ops) with (m = 16, ef_construction = 64);

analyze facts_flat;
analyze facts_part;
analyze container;
analyze container_ancestry;
analyze membership_closure;
analyze grant_tuple;
analyze fact_classification;
analyze principal_clearance;
\timing off
