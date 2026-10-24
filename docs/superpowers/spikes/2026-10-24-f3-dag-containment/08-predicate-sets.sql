-- F3, question 4: the predicate-defined entity-set.
--
-- kgs §9.3 allows an entity-set to be "definable either explicitly or by
-- predicate", and UNEXPRESSIBLE U5 records that such a set has no
-- authorization event: an ordinary data write, made by a principal holding no
-- authorization permission, moves an authorization answer.
--
-- Fifty predicate-defined sets are declared here over entity.country, which
-- is the cheapest possible predicate -- one indexed equality on one column of
-- the entity row. Anything measured here is therefore a FLOOR on the cost of
-- the mechanism, not an estimate of it.

drop table if exists predicate_set cascade;
create table predicate_set (
    set_id  int primary key,
    country smallint not null
);

-- Reuse 50 of the level-2 entity-sets as predicate-defined, so they sit in
-- the same containment DAG as the explicit ones and every read strategy above
-- applies to them unchanged.
insert into predicate_set (set_id, country)
select 2000 + g, g % 20 from generate_series(0, 49) g;

create index entity_country on entity (country, id);
analyze entity;
