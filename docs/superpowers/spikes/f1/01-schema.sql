-- F1 filtered-ANN spike: schema.
--
-- Models iam design §9.2's two closures plus the tier-2 anti-join, over a
-- synthetic consumer table shaped like kgs's `facts`. Nothing here is
-- proposed schema for the module; it exists only to make the measured
-- predicate the real predicate rather than a single boolean column.

drop schema if exists f1 cascade;
create schema f1;
set search_path = f1, public;

-- ---------------------------------------------------------------------------
-- Containment hierarchy. Depth 6 (levels 0..5), per iam A2.
--   L0  1      tenant root
--   L1  2      graph
--   L2  10     section          (5 per L1)
--   L3  100    subsection       (10 per L2)
--   L4  1000   entity-set       (10 per L3)   <- the (b) zone key
--   L5  2000   leaf entity-set  (2 per L4)
-- 2,000 leaves x 1,000 facts = 2,000,000 facts.
-- ---------------------------------------------------------------------------
create table container (
    id        int      primary key,
    parent_id int      references container (id),
    depth     smallint not null
);
create index container_parent on container (parent_id);

-- §9.2 closure 2: ancestry. resource -> every ancestor on its containment
-- path, including itself. Bounded by hierarchy depth. Two indexes because the
-- predicate walks it upward (container -> ancestors) and the (b) key
-- resolution walks it downward (granted container -> descendants).
create table container_ancestry (
    container_id int not null,
    ancestor_id  int not null,
    primary key (container_id, ancestor_id)
);
create index container_ancestry_down on container_ancestry (ancestor_id, container_id);

-- ---------------------------------------------------------------------------
-- Identity. 2,000 principals, 200 groups, nested.
-- ---------------------------------------------------------------------------
create table principal (
    id int primary key
);

create table grp (
    id        int primary key,
    parent_id int references grp (id) -- nested groups, so the closure is transitive
);

-- Authority-side direct edges, kept so the maintenance cost of §9.2 closure 1
-- can be measured against A2's O(members) budget (see 05-maintenance.sql).
create table group_member (
    group_id    int      not null references grp (id),
    member_id   int      not null, -- principal id, or group id when kind=1
    member_kind smallint not null, -- 0 = principal, 1 = group
    primary key (group_id, member_id, member_kind)
);

-- §9.2 closure 1: membership. principal -> every userset it belongs to,
-- transitively, including the singleton userset that is the principal itself.
-- Userset ids are namespaced: principals keep their own ids, groups are
-- offset by GROUP_ID_BASE (1,000,000) so one column can hold both.
create table membership_closure (
    principal_id int not null,
    userset_id   int not null,
    primary key (principal_id, userset_id)
);
create index membership_closure_us on membership_closure (userset_id, principal_id);

-- ---------------------------------------------------------------------------
-- Tier 1 grants: (userset, container, relation). 10,000 of them, placed at
-- every level of the hierarchy. relation 1 = read.
-- ---------------------------------------------------------------------------
create table grant_tuple (
    userset_id   int      not null,
    container_id int      not null references container (id),
    relation     smallint not null,
    primary key (userset_id, container_id, relation)
);
create index grant_tuple_container on grant_tuple (container_id, relation, userset_id);

-- ---------------------------------------------------------------------------
-- Tier 2: classifications. iam F2 is explicit that A2's "500
-- classifications" must mean definitions, not assignments -- assignments are
-- at fact cardinality. So: 500 definitions, assignments on a fraction of all
-- 2,000,000 facts, and a per-principal clearance set. The gate is an
-- anti-join and it is evaluated live, per candidate row, in every strategy
-- below -- including (b). That is the point: (b) can pre-restrict the tier-1
-- set but cannot pre-restrict this.
-- ---------------------------------------------------------------------------
create table classification (
    id int primary key
);

create table fact_classification (
    fact_id           bigint not null,
    classification_id int    not null references classification (id),
    primary key (fact_id, classification_id)
);

create table principal_clearance (
    principal_id      int not null references principal (id),
    classification_id int not null references classification (id),
    primary key (principal_id, classification_id)
);

-- ---------------------------------------------------------------------------
-- The consumer table. halfvec(768) rather than vector(768): 768 float4s are
-- 3,076 bytes, over the 2,000-byte TOAST threshold, so a vector(768) column
-- is pushed out of line and every heap fetch becomes a TOAST fetch. halfvec
-- is 1,544 bytes and stays inline. kgs §13.5 already names halfvec as the
-- intended storage for the large graphs, so this is the configuration under
-- test, not a shortcut. 09-fullprec.sql repeats the key cases on vector(768)
-- with storage PLAIN to show what the choice costs.
--
-- `zone` is the L4 ancestor, denormalized onto the row. It is strategy (b)'s
-- candidate key. It is NOT per-principal: see 05-maintenance.sql.
-- ---------------------------------------------------------------------------
create table facts_flat (
    id           bigint       primary key,
    container_id int          not null, -- L5 leaf
    zone         int          not null, -- L4 ancestor, the (b) key
    embedding    halfvec(768) not null
);

-- Same rows, partitioned by the (b) key, so partition pruning can restrict
-- the candidate set before any ANN work happens and each partition carries
-- its own HNSW graph.
create table facts_part (
    id           bigint       not null,
    container_id int          not null,
    zone         int          not null,
    embedding    halfvec(768) not null
) partition by list (zone);
