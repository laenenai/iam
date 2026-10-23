-- HNSW builds, split out of 03-index.sql.
--
-- max_parallel_maintenance_workers = 0 is forced here, not for speed but
-- because a parallel HNSW build allocates maintenance_work_mem in DYNAMIC
-- SHARED MEMORY, i.e. /dev/shm. A container with the default 64MB (or even
-- 2GB) /dev/shm fails the build outright:
--
--   ERROR: could not resize shared memory segment ... to 8586858464 bytes:
--          No space left on device
--
-- A serial build takes the same memory from the backend's own address space
-- and succeeds. Worth recording: it means "build an HNSW index on 2M vectors"
-- has a container-sizing precondition that has nothing to do with Postgres
-- tuning, and the error message does not say so.
set search_path = f1, public;
set max_parallel_maintenance_workers = 0;
set maintenance_work_mem = '8GB';

\timing on

create index facts_flat_hnsw on facts_flat
    using hnsw (embedding halfvec_cosine_ops) with (m = 16, ef_construction = 64);

create index facts_part_container on facts_part (container_id);

create index facts_part_hnsw on facts_part
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

select relname,
       pg_size_pretty(pg_total_relation_size(c.oid)) as total,
       pg_size_pretty(pg_relation_size(c.oid))       as heap,
       pg_size_pretty(pg_indexes_size(c.oid))        as indexes
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'f1' and relkind in ('r','p') and relname in ('facts_flat','facts_part')
order by relname;
