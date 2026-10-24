package f3spike

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// reportMaintenance writes maintenance.txt: question 1's write half. A2's
// budget is written in rows-per-event, so every event below is reported as
// the rows each strategy must write, measured against the built fixture
// rather than derived from the generator's parameters.
func reportMaintenance(ctx context.Context, t *testing.T, p *pg, prm params, res *results) {
	x := newTranscript("maintenance.txt")
	x.addf("F3 question 1 -- maintenance when containment is a DAG")
	x.addf("")
	x.addf("A2: \"Sharing a container of 100,000 objects with a 50-member team must write")
	x.addf("O(50) projection rows, not O(5,000,000).\" The DAG adds three events A2 never")
	x.addf("names, and they are the ones that decide this finding:")
	x.addf("")
	x.addf("  E3  an entity is added to an entity-set   -- a containment edge, at ENTITY cardinality")
	x.addf("  E4  an entity-set is nested under another -- a containment edge, at CONTAINER cardinality")
	x.addf("  E6  an entity-set is re-parented          -- E4 plus a removal")
	x.addf("")
	x.addf("Rows are counted, not written, so the fixture stays valid for every later")
	x.addf("section; the two timed cases say so explicitly.")

	nFact := prm.n("N_FACT")

	x.head("E1/E2: the events A2 does budget, unchanged by the DAG")
	x.addf("+1 grant on a container          grant_tuple 1 row;  no fact rows, any strategy")
	x.addf("+1 member to a 50-member group   group_member 1 + membership_closure 1 = 2 rows;")
	x.addf("                                 no fact rows, any strategy")
	x.addf("These are F1's measured numbers and the DAG does not touch them: a grant and a")
	x.addf("membership name no container, so no containment closure is a function of either.")

	x.head("E5: +1 fact ingested (the consumer's own write)")
	x.addf("%-6s %34s %14s", "strat", "rows per fact written", "at 10M facts")
	for _, r := range []struct {
		name string
		per  float64
		what string
	}{
		{"C2", 1 + res.Floats["fanout.c2"], "fact + fact_entity"},
		{"C4", 1 + res.Floats["fanout.c2"] + res.Floats["fanout.c4"], "+ fact_container"},
		{"C1", 1 + res.Floats["fanout.c2"] + res.Floats["fanout.c1"], "+ fact_ancestry"},
	} {
		x.addf("%-6s %10.3f  %-21s %14s", r.name, r.per, r.what, comma(int64(r.per*float64(nFact))))
		res.Floats["maint.e5."+r.name] = r.per
	}

	x.head("E3: an entity is added to an entity-set")
	x.addf("The event is one row of authorization state. What it costs depends entirely on")
	x.addf("whether the strategy stores containment at fact cardinality.")
	x.addf("")
	hubEntity, hubDeg := int64(0), int64(0)
	if err := p.pool.QueryRow(ctx, qHubEntity).Scan(&hubEntity, &hubDeg); err != nil {
		t.Fatalf("f3: hub entity: %v", err)
	}
	medianEntity := medianDegreeEntity(ctx, t, p)
	// Two target sets, because the cost depends on how much of the target's
	// ancestry the fact already reaches by another path: a level-2 set is
	// mostly already reached, a level-4 set is mostly new.
	targets := []struct {
		id    int64
		label string
	}{{2000, "level-2 set 2000"}, {200000, "level-4 set 200000"}}

	x.addf("%-22s %10s %10s %10s %10s  %s", "entity", "facts", "C2 rows", "C4 rows", "C1 rows", "target")
	for _, tg := range targets {
		for _, e := range []struct {
			label string
			id    int64
		}{
			{"median-degree", medianEntity},
			{"hub (highest degree)", hubEntity},
		} {
			deg := scalar[int64](ctx, t, p, qEntityDegree, e.id)
			c4 := scalar[int64](ctx, t, p, qDeltaEsmC4, e.id, tg.id)
			c1 := scalar[int64](ctx, t, p, qDeltaEsmC1, e.id, tg.id)
			x.addf("%-22s %10s %10d %10s %10s  %s", e.label, comma(deg), 1, comma(c4), comma(c1), tg.label)
			res.Counts["maint.e3.deg."+e.label] = deg
			res.Counts["maint.e3.c4."+e.label+"."+tg.label] = c4
			res.Counts["maint.e3.c1."+e.label+"."+tg.label] = c1
		}
	}
	x.addf("")
	x.addf("entity ids: median-degree %d, hub %d (degree %s)", medianEntity, hubEntity, comma(hubDeg))
	x.addf("")
	x.addf("C1's count can come in BELOW C4's for a shallow target, and that is a DAG")
	x.addf("property rather than a saving: the new ancestors are already reached by one of")
	x.addf("the fact's other paths, so the closure row exists and only its justification")
	x.addf("changed -- which is exactly why that row cannot be deleted by matching an")
	x.addf("ancestor id when the membership is removed. See E7.")

	x.head("E4: an entity-set is nested under another entity-set")
	x.addf("%-34s %12s %12s %12s %12s", "event", "facts under", "cont_anc", "C4 rows", "C1 rows")
	type nestCase struct {
		child, parent int64
		label         string
	}
	var nests []nestCase
	for _, child := range []int64{20000, 2000, 1000} {
		parent, ok := scalarOK[int64](ctx, p, qNewParentFor, child)
		if !ok || parent == 0 {
			continue
		}
		nests = append(nests, nestCase{child, parent, fmt.Sprintf("set %d under set %d", child, parent)})
	}
	for _, n := range nests {
		under := scalar[int64](ctx, t, p, qFactsUnder, n.child)
		ancRows := scalar[int64](ctx, t, p, qDeltaNestAncestry, n.child, n.parent)
		c1 := scalar[int64](ctx, t, p, qDeltaNestC1, n.child, n.parent)
		x.addf("%-34s %12s %12s %12d %12s", n.label, comma(under), comma(ancRows), 0, comma(c1))
		res.Counts["maint.e4.under."+n.label] = under
		res.Counts["maint.e4.anc."+n.label] = ancRows
		res.Counts["maint.e4.c1."+n.label] = c1
	}
	x.addf("")
	x.addf("C2 and C4 write ZERO rows for this event: neither stores a transitive edge, so")
	x.addf("re-nesting a container is a change to container_ancestry alone -- a table bounded")
	x.addf("by the number of containers. C1 pays it at fact cardinality.")

	x.head("E4, timed rather than counted")
	x.addf("The middle event above, actually applied inside a transaction and rolled back,")
	x.addf("so the figure is wall clock and not a row count.")
	x.addf("")
	for _, c := range nests {
		if c.child != 2000 {
			continue
		}
		dAnc := timedRollback(ctx, t, p, []string{
			fmt.Sprintf("insert into container_edge (child_id, parent_id) values (%d, %d)", c.child, c.parent),
			fmt.Sprintf(`insert into container_ancestry (container_id, ancestor_id)
			 select distinct d.container_id, a.ancestor_id
			 from container_ancestry d cross join container_ancestry a
			 where d.ancestor_id = %d and a.container_id = %d
			 on conflict do nothing`, c.child, c.parent),
		})
		x.addf("C2/C4  %s, container_ancestry repair only   %s", c.label, dur(dAnc))
		dC1 := timedRollback(ctx, t, p, []string{
			fmt.Sprintf(`insert into fact_ancestry (fact_id, ancestor_id)
			 select distinct fa.fact_id, a.ancestor_id
			 from fact_ancestry fa cross join container_ancestry a
			 where fa.ancestor_id = %d and a.container_id = %d
			 on conflict do nothing`, c.child, c.parent),
		})
		x.addf("C1     the same event propagated to fact_ancestry     %s", dur(dC1))
		res.Builds["maint.e4.timed.anc"] = dur(dAnc)
		res.Builds["maint.e4.timed.c1"] = dur(dC1)
	}

	x.head("E7: re-parenting, which F1 §9 flagged as unbudgeted and still is")
	x.addf("Moving a container is E4 plus the removal of the old edge. Under C1 the removal")
	x.addf("is the expensive half: a (fact, ancestor) row may be justified by a second path,")
	x.addf("so it cannot be deleted by matching the old ancestor -- every candidate row has")
	x.addf("to be re-derived. Counted here as the rows that would have to be re-examined:")
	for _, c := range []struct{ child int64 }{{2000}, {20000}} {
		under := scalar[int64](ctx, t, p, qFactsUnder, c.child)
		x.addf("  container %-7d facts beneath it %12s   C1 rows to re-derive %s",
			c.child, comma(under), comma(under*int64(res.Floats["fanout.c1"])))
	}
	x.addf("")
	x.addf("In a tree the delete is a match on the old ancestor id. In a DAG it is not, and")
	x.addf("that asymmetry is the one maintenance cost that has no cheap form under C1.")

	x.write(t, p.dir)
}

// timedRollback applies statements inside a transaction, times them, and
// rolls back, so a maintenance cost can be measured without invalidating the
// fixture every later section reads.
func timedRollback(ctx context.Context, t *testing.T, p *pg, stmts []string) time.Duration {
	t.Helper()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("f3: begin: %v", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil {
			t.Logf("f3: rollback: %v", err)
		}
	}()
	start := time.Now()
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			t.Fatalf("f3: timed stmt: %v\n%s", err, s)
		}
	}
	return time.Since(start)
}

// reportPredicateSets writes predicate-sets.txt: question 4's hard half. A
// predicate-defined entity-set has no authorization event (U5), and the
// question this section answers with numbers is what it would cost to be a
// container anyway.
func reportPredicateSets(ctx context.Context, t *testing.T, p *pg, res *results) {
	x := newTranscript("predicate-sets.txt")
	x.addf("F3 question 4 -- can a predicate-defined entity-set be an authorization container?")
	x.addf("")
	x.addf("Fifty predicate-defined sets, each one equality on one indexed column of the")
	x.addf("entity row -- the cheapest predicate there is. Every number here is therefore a")
	x.addf("FLOOR on the mechanism's cost, not an estimate of it.")

	eligible := scalar[int64](ctx, t, p, qPredEligibleEntities, int16(0))
	predRows := scalar[int64](ctx, t, p, qPredRows)
	predC1 := scalar[int64](ctx, t, p, qPredC1Rows)

	x.head("the membership nobody wrote")
	x.addf("entities satisfying one predicate            %14s", comma(eligible))
	x.addf("entity_set_member rows for 50 such sets      %14s", comma(predRows))
	x.addf("fact_ancestry rows those edges imply (C1)    %14s", comma(predC1))
	res.Counts["pred.eligible"] = eligible
	res.Counts["pred.esm_rows"] = predRows
	res.Counts["pred.c1_rows"] = predC1

	x.head("applying one refresh, timed and rolled back")
	d := timedRollback(ctx, t, p, []string{
		`insert into entity_set_member (entity_id, set_id)
		 select e.id, ps.set_id from predicate_set ps join entity e on e.country = ps.country
		 on conflict do nothing`,
	})
	x.addf("full refresh of 50 predicate-defined sets, membership only   %s", dur(d))
	res.Builds["pred.refresh"] = dur(d)

	x.head("the restrictive direction, priced on one row")
	x.addf("One UPDATE of entity.country -- an ordinary data write by a principal holding no")
	x.addf("authorization permission -- removes the entity from one predicate-defined set and")
	x.addf("adds it to another. What that removal has to retract:")
	x.addf("")
	hubEntity := int64(0)
	hubDeg := int64(0)
	if err := p.pool.QueryRow(ctx, qHubEntity).Scan(&hubEntity, &hubDeg); err != nil {
		t.Fatalf("f3: hub: %v", err)
	}
	for _, e := range []struct {
		label string
		id    int64
	}{
		{"median-degree entity", medianDegreeEntity(ctx, t, p)},
		{"hub entity", hubEntity},
	} {
		if e.id == 0 {
			continue
		}
		deg := scalar[int64](ctx, t, p, qEntityDegree, e.id)
		rows := scalar[int64](ctx, t, p, qPredOneEntity, e.id, int64(2000))
		x.addf("%-24s facts %8s   fact_ancestry rows to retract (C1) %8s",
			e.label, comma(deg), comma(rows))
		res.Counts["pred.retract."+e.label] = rows
	}
	x.addf("")
	x.addf("Under C2 the same removal is one row of entity_set_member -- and that is the")
	x.addf("whole of the difference. What C2 does NOT fix is which path the change rides:")
	x.addf("the write is a data write, so a REVOCATION travels design §9.3's permissive")
	x.addf("path, and §9.3's one rule is that the restrictive change propagates on the fast")
	x.addf("path. That is a semantic defect and no closure shape repairs it.")

	x.write(t, p.dir)
}

// reportExplain writes explain.txt: the plans behind the headline cells,
// because a latency without a plan is not evidence about an index join.
func reportExplain(ctx context.Context, t *testing.T, p *pg, probes []probeRow) {
	x := newTranscript("explain.txt")
	x.addf("F3 -- EXPLAIN (ANALYZE, BUFFERS) for the cases the write-up quotes")

	byName := map[string]*probeRow{}
	for i := range probes {
		byName[probes[i].Name] = &probes[i]
	}
	type kase struct {
		title string
		probe string
		sql   string
		args  func(pr *probeRow) []any
	}
	cases := []kase{
		{"page, no predicate", "p_es3", qPageNone, func(*probeRow) []any { return []any{int64(0)} }},
		{"page C1, entity-set grant", "p_es3", qPageC1, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"page C2, entity-set grant", "p_es3", qPageC2, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"page C2u, entity-set grant", "p_es3", qPageC2u, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"page C4, entity-set grant", "p_es3", qPageC4, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"page C5, entity-set grant", "p_es3", qPageC5, func(pr *probeRow) []any { return []any{pr.Accessible, int64(0)} }},
		{"page C4, episode grant", "p_epi", qPageC4, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"page C4, household shape", "p_mix", qPageC4, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"page C2u, household shape", "p_mix", qPageC2u, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"point C2, entity-set grant", "p_es3", qPointC2, func(pr *probeRow) []any { return []any{pr.Principal, int64(1)} }},
		{"key K2 only, entity-set grant", "p_es3", withKeyTest(qPageKeyOnly, keyTestK2), func(pr *probeRow) []any { return []any{pr.Accessible, int64(0)} }},
		{"key K2 + fragment, entity-set grant", "p_es3", withKeyTest(qPageKeySafe, keyTestK2), func(pr *probeRow) []any {
			return []any{pr.Accessible, int64(0), pr.Principal}
		}},
		{"key K1 only, entity-set grant", "p_es3", withKeyTest(qPageKeyOnly, keyTestK1), func(pr *probeRow) []any { return []any{pr.Accessible, int64(0)} }},
		{"key K2 + fragment, household shape", "p_mix", withKeyTest(qPageKeySafe, keyTestK2), func(pr *probeRow) []any {
			return []any{pr.Accessible, int64(0), pr.Principal}
		}},
		{"accessible-set resolution", "p_mix", qAccessible, func(pr *probeRow) []any { return []any{pr.Principal} }},
	}
	for _, c := range cases {
		pr, ok := byName[c.probe]
		if !ok {
			continue
		}
		x.head(c.title + " -- " + c.probe)
		x.addf("%s", explain(ctx, t, p, c.sql, c.args(pr)...))
	}
	x.write(t, p.dir)
}

// medianDegreeEntity returns an entity whose fact-reference degree is the
// fixture's median, so "what does one membership change cost" is answered for
// a typical entity as well as for the hub.
func medianDegreeEntity(ctx context.Context, t *testing.T, p *pg) int64 {
	t.Helper()
	return scalar[int64](ctx, t, p,
		`with d as (select entity_id, count(*) as n from fact_entity group by entity_id)
		 select entity_id from d
		 where n = (select (percentile_disc(0.5) within group (order by n))::bigint from d)
		 order by entity_id limit 1`)
}
