-- Adversarial layout: same 2,000,000 rows, same authorization fixture, but
-- cluster assignment independent of the authorization zone. A principal's
-- accessible rows are then a uniform random sample of the vector space, which
-- is the case kgs §13.3 is actually worried about.
set search_path = f1, public;

drop table if exists facts_flat_i;
drop table if exists facts_part_i;

create table facts_flat_i (
    id           bigint       primary key,
    container_id int          not null,
    zone         int          not null,
    embedding    halfvec(768) not null
);

create table facts_part_i (
    id           bigint       not null,
    container_id int          not null,
    zone         int          not null,
    embedding    halfvec(768) not null
) partition by list (zone);

do $$
declare z int;
begin
    for z in select id from container where depth = 4 order by id loop
        execute format(
            'create table facts_part_i_z%s partition of facts_part_i for values in (%s)', z, z);
    end loop;
end $$;
