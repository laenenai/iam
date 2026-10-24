-- C1's indexes, built after the load. Both directions are needed and both are
-- part of C1's honest cost: (fact_id, ancestor_id) answers "may this principal
-- read this fact", (ancestor_id, fact_id) answers "which facts are under this
-- container", which is what a listing and a visible_below walk need.
alter table fact_ancestry add primary key (fact_id, ancestor_id);
create index fact_ancestry_anc on fact_ancestry (ancestor_id, fact_id);
analyze fact_ancestry;
