-- F3 DAG-containment spike: schema.
--
-- The shape under test is kgs §9.3's containment path
--
--     tenant > graph > [compartment] > entity-set | episode > fact
--
-- with the two properties that make it a DAG rather than a tree:
--
--   1. a fact belongs to exactly one episode AND to zero or more entity-sets,
--      and its entity-set membership is not its own -- it is derived from the
--      entities the fact references (kgs §7.4: a fact relates entities; §9.3:
--      an entity-set is a grouping of ENTITIES);
--   2. entity-sets nest, and nesting is itself many-to-many in practice
--      ("school" under both "family" and "education").
--
-- Four containment-resolution strategies are built side by side so the same
-- authorization question can be asked of each. They differ only in WHERE the
-- transitive closure is materialized, which is exactly what F3 is about.
--
--   C1  fact_ancestry        fact -> every ancestor by any path. The naive
--                            DAG closure: §9.2's ancestry closure taken
--                            literally when containment stops being a tree.
--   C2  (no fact-level       fact.episode_id + fact_entity + entity_set_member
--       containment table)   + container_ancestry. Nothing authorization-
--                            relevant is stored at fact cardinality.
--   C4  fact_container       fact -> its DIRECT containers only, joined with
--                            container_ancestry at read time.
--   C5  (read-time)          resolve principal -> accessible container set by
--                            downward recursion, then test membership.
--
-- C3 -- a recursive CTE walked upward per candidate row -- is measured on the
-- page query only; see the write-up.

drop table if exists fact_ancestry, fact_container, fact_key, fact_entity, fact,
    entity_set_member, entity, grant_tuple, membership_closure, group_member,
    grp, principal, container_ancestry, container_edge, container, probe cascade;

-- ---------------------------------------------------------------------------
-- Containment: nodes and edges. A node may have several parents.
-- ---------------------------------------------------------------------------

-- kind: 0 tenant, 1 graph, 2 episode, 3 entity-set
create table container (
    id    int      primary key,
    kind  smallint not null,
    depth smallint not null
);

create table container_edge (
    child_id  int not null,
    parent_id int not null,
    primary key (child_id, parent_id)
);
create index container_edge_parent on container_edge (parent_id, child_id);

-- The small closure every strategy except C1 shares: container -> every
-- ancestor reachable by any path, including itself. Bounded by the number of
-- containers, not by the number of facts.
create table container_ancestry (
    container_id int not null,
    ancestor_id  int not null,
    primary key (container_id, ancestor_id)
);
create index container_ancestry_anc on container_ancestry (ancestor_id, container_id);

-- ---------------------------------------------------------------------------
-- Identity and grants: §9.2's membership closure and grant tuples, unchanged
-- from the F1 fixture apart from cardinality (kgs A2: 2,000 principals,
-- 200 overlapping groups, 10,000 grants placed at every level).
-- ---------------------------------------------------------------------------

create table principal (id int primary key);
create table grp (id int primary key);

create table group_member (
    group_id     int not null,
    principal_id int not null,
    primary key (group_id, principal_id)
);

create table membership_closure (
    principal_id int not null,
    userset_id   int not null,
    primary key (principal_id, userset_id)
);
create index membership_closure_userset on membership_closure (userset_id, principal_id);

create table grant_tuple (
    userset_id   int      not null,
    container_id int      not null,
    relation     smallint not null,
    primary key (userset_id, container_id, relation)
);
create index grant_tuple_container on grant_tuple (container_id, userset_id);

-- ---------------------------------------------------------------------------
-- The graph's own data.
-- ---------------------------------------------------------------------------

-- country exists only to give the predicate-defined entity-sets of §5 a
-- predicate to be defined over.
create table entity (
    id      bigint   primary key,
    country smallint not null
);

-- The mutable, authorization-relevant containment edge: which entities are in
-- which entity-set. Direct membership only.
create table entity_set_member (
    entity_id bigint not null,
    set_id    int    not null,
    primary key (entity_id, set_id)
);
create index entity_set_member_set on entity_set_member (set_id, entity_id);

-- The consumer's 10,000,000 rows.
create table fact (
    id         bigint primary key,
    episode_id int not null
);
create index fact_episode on fact (episode_id, id);

-- Which entities a fact references. Written once, at fact write, and never
-- again: a fact's references are immutable even though the SETS those
-- entities belong to are not. This is the table C2 leans on.
create table fact_entity (
    fact_id   bigint not null,
    entity_id bigint not null,
    primary key (fact_id, entity_id)
);
create index fact_entity_entity on fact_entity (entity_id, fact_id);

-- C1. Indexed in 05-c1-index.sql rather than here: the primary key is built
-- after the load so its build time is measured separately, which is half of
-- what question 1 asks about C1.
create table fact_ancestry (
    fact_id     bigint not null,
    ancestor_id int    not null
);

-- C4, indexed in 06 for the same reason.
create table fact_container (
    fact_id      bigint not null,
    container_id int    not null
);

-- The probes, so every later script and transcript names the same principals.
create table probe (
    name       text primary key,
    principal  int  not null,
    note       text not null
);
