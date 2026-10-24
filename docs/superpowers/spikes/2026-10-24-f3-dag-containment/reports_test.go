package f3spike

import (
	"context"
	"fmt"
	"testing"
)

// reportFixture writes fixture.txt: what was built, how big it is, how long
// it took, what the DAG fan-out actually turned out to be, and -- the part
// without which none of the rest is evidence -- whether the four containment
// strategies agree on the authorization answer.
func reportFixture(ctx context.Context, t *testing.T, p *pg, prm params, probes []probeRow, res *results) {
	x := newTranscript("fixture.txt")
	x.addf("F3 DAG-containment spike -- fixture")
	x.addf("server: %s", res.Server)
	x.addf("scale:  %g  (1.0 = kgs A2: 10,000,000 facts, 2,000,000 entities)", prm.scale)
	x.addf("docker round trip, 300 x `select 1`: p50 %.2f ms, p95 %.2f ms", res.Baseline.P50, res.Baseline.P95)

	x.head("build time")
	for _, k := range []string{
		"01-schema.sql", "02-generate.sql", "03-container-ancestry.sql",
		"04-c1-fact-ancestry.sql", "05-c1-index.sql", "06-c4-fact-container.sql",
		"07-keys.sql", "08-predicate-sets.sql", "TOTAL",
	} {
		if v, ok := res.Builds[k]; ok {
			x.addf("%-28s %s", k, v)
		}
	}

	x.head("row counts")
	rows, err := p.pool.Query(ctx, qRowCounts)
	if err != nil {
		t.Fatalf("f3: row counts: %v", err)
	}
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			rows.Close()
			t.Fatalf("f3: scan row counts: %v", err)
		}
		x.addf("%-22s %16s", name, comma(n))
		res.Counts["rows."+name] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("f3: row counts rows: %v", err)
	}

	x.head("table and index size")
	x.addf("%-24s %14s %14s %14s", "relation", "rows (est)", "heap", "indexes")
	srows, err := p.pool.Query(ctx, qSizes)
	if err != nil {
		t.Fatalf("f3: sizes: %v", err)
	}
	for srows.Next() {
		var name string
		var est, heap, idx int64
		if err := srows.Scan(&name, &est, &heap, &idx); err != nil {
			srows.Close()
			t.Fatalf("f3: scan sizes: %v", err)
		}
		x.addf("%-24s %14s %11.0f MB %11.0f MB", name, comma(est), mb(heap), mb(idx))
		res.Counts["heap_bytes."+name] = heap
		res.Counts["index_bytes."+name] = idx
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		t.Fatalf("f3: sizes rows: %v", err)
	}

	x.head("the DAG fan-out: closure rows per fact")
	var faPer, fcPer, fePer float64
	if err := p.pool.QueryRow(ctx, qFanout).Scan(&faPer, &fcPer, &fePer); err != nil {
		t.Fatalf("f3: fanout: %v", err)
	}
	x.addf("C1  fact_ancestry  rows per fact  %8.3f   (every ancestor, any path)", faPer)
	x.addf("C4  fact_container rows per fact  %8.3f   (direct containers only)", fcPer)
	x.addf("C2  fact_entity    rows per fact  %8.3f   (immutable references)", fePer)
	res.Floats["fanout.c1"] = faPer
	res.Floats["fanout.c4"] = fcPer
	res.Floats["fanout.c2"] = fePer

	var fmin, fp50, fp95, fp999, fmax int64
	if err := p.pool.QueryRow(ctx, qFanoutDist).Scan(&fmin, &fp50, &fp95, &fp999, &fmax); err != nil {
		t.Fatalf("f3: fanout dist: %v", err)
	}
	x.addf("C1 per-fact distribution: min %d  p50 %d  p95 %d  p99.9 %d  max %d", fmin, fp50, fp95, fp999, fmax)
	res.Counts["fanout.c1.max"] = fmax
	res.Counts["fanout.c1.p999"] = fp999

	x.head("entity reference degree -- the multiplier on a membership change")
	var dmin, dp50, dp99, dmax int64
	var davg float64
	if err := p.pool.QueryRow(ctx, qDegreeStats).Scan(&dmin, &dp50, &dp99, &dmax, &davg); err != nil {
		t.Fatalf("f3: degree stats: %v", err)
	}
	x.addf("facts per entity: min %d  p50 %d  p99 %s  max %s  mean %.2f",
		dmin, dp50, comma(dp99), comma(dmax), davg)
	res.Counts["degree.p50"] = dp50
	res.Counts["degree.p99"] = dp99
	res.Counts["degree.max"] = dmax

	x.head("probes")
	x.addf("%-9s %-5s %7s %9s %14s %10s  %s", "probe", "princ", "grants", "accessib", "authorized", "selectiv", "note")
	for i := range probes {
		pr := &probes[i]
		pr.Authorized = scalar[int64](ctx, t, p, qAuthorizedCount, pr.Accessible)
		pr.Selectiv = 100 * float64(pr.Authorized) / float64(prm.n("N_FACT"))
		x.addf("%-9s %-5d %7d %9s %14s %9.4f%%  %s",
			pr.Name, pr.Principal, pr.NGranted, comma(int64(pr.NAccess)),
			comma(pr.Authorized), pr.Selectiv, pr.Note)
	}

	x.head("differential check: do the four strategies compute the same predicate?")
	x.addf("5,000 facts sampled across the table (id %% 2000 = 1), per probe.")
	x.addf("%-9s %8s %10s %10s %10s %10s", "probe", "sampled", "C1<>C2", "C1<>C4", "C1<>C5", "C1 true")
	for i := range probes {
		pr := &probes[i]
		var n, d2, d4, d5, nTrue int64
		if err := p.pool.QueryRow(ctx, qAgreement, pr.Principal, pr.Accessible).
			Scan(&n, &d2, &d4, &d5, &nTrue); err != nil {
			t.Fatalf("f3: agreement %s: %v", pr.Name, err)
		}
		x.addf("%-9s %8s %10d %10d %10d %10s", pr.Name, comma(n), d2, d4, d5, comma(nTrue))
		res.Counts["disagree.c2."+pr.Name] = d2
		res.Counts["disagree.c4."+pr.Name] = d4
		res.Counts["disagree.c5."+pr.Name] = d5
		if d2 != 0 || d4 != 0 || d5 != 0 {
			x.addf("  !! DISAGREEMENT -- every latency for %s below compares different questions", pr.Name)
		}
	}

	x.write(t, p.dir)
}

func mb(b int64) float64 { return float64(b) / (1024 * 1024) }

// reportRead writes read.txt: question 1's read half. One row per strategy,
// one column per probe, for the two shapes a consumer actually issues --
// A2's keyset page and §7.1's point decision.
func reportRead(ctx context.Context, t *testing.T, p *pg, probes []probeRow, res *results) {
	x := newTranscript("read.txt")
	x.addf("F3 -- read cost when containment is a DAG")
	x.addf("")
	x.addf("Every cell is p50 / p95 wall-clock ms over up to %d executions -- a cell whose", pageReps)
	x.addf("first execution exceeds 2 s drops to 5 and one past 20 s to 3; results.json")
	x.addf("carries the actual count per cell. Wall clock includes the")
	x.addf("Docker round trip measured at p50 %.2f / p95 %.2f ms. A cell reading", res.Baseline.P50, res.Baseline.P95)
	x.addf("`timeout` exceeded %s.", queryBudget)
	x.addf("")
	x.addf("  C1  fact_ancestry        the DAG closure materialized at fact cardinality")
	x.addf("  C2  two EXISTS arms      nothing authorization-mutable at fact cardinality")
	x.addf("  C2u one semi-join        C2 folded into a UNION ALL of direct containers")
	x.addf("  C3  recursive at read    no closure materialized anywhere")
	x.addf("  C4  fact_container       direct containers stored, transitive part joined")
	x.addf("  C5  bound key set        accessible container set resolved once, bound as int4[]")

	base := measure(ctx, t, p, pageReps, qPageNone, int64(0))
	res.Cells["page.none"] = base

	strategies := []struct {
		name string
		sql  string
		arg  func(pr *probeRow) []any
	}{
		{"C1", qPageC1, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"C2", qPageC2, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"C2u", qPageC2u, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"C3", qPageC3, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"C4", qPageC4, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"C5", qPageC5, func(pr *probeRow) []any { return []any{pr.Accessible, int64(0)} }},
	}

	x.head("keyset page, 50 rows, from the start of the table (p50 / p95 ms)")
	x.addf("%-5s %s", "", probeHeader(probes))
	x.addf("%-5s %s", "none", fmt.Sprintf("%21s", base.String()))
	for _, s := range strategies {
		line := fmt.Sprintf("%-5s", s.name)
		for i := range probes {
			cell := measure(ctx, t, p, pageReps, s.sql, s.arg(&probes[i])...)
			res.Cells["page."+s.name+"."+probes[i].Name] = cell
			line += fmt.Sprintf(" %21s", cell.String())
		}
		x.addf("%s", line)
	}

	x.head("rows returned of the 50 requested")
	for _, s := range strategies {
		line := fmt.Sprintf("%-5s", s.name)
		for i := range probes {
			c := res.Cells["page."+s.name+"."+probes[i].Name]
			if c.TimedOut {
				line += fmt.Sprintf(" %21s", "-")
			} else {
				line += fmt.Sprintf(" %21d", c.Rows)
			}
		}
		x.addf("%s", line)
	}

	x.head("point decision on one authorized fact (p50 / p95 ms, " + fmt.Sprint(pointReps) + " reps)")
	x.addf("%-5s %s", "", probeHeader(probes))
	for _, s := range []struct {
		name string
		sql  string
	}{{"C1", qPointC1}, {"C2", qPointC2}, {"C4", qPointC4}} {
		line := fmt.Sprintf("%-5s", s.name)
		for i := range probes {
			fid := firstAuthorized(ctx, t, p, &probes[i])
			cell := measure(ctx, t, p, pointReps, s.sql, probes[i].Principal, fid)
			res.Cells["point."+s.name+"."+probes[i].Name] = cell
			line += fmt.Sprintf(" %21s", cell.String())
		}
		x.addf("%s", line)
	}

	x.head("key-set resolution: principal -> accessible container set")
	x.addf("%-9s %11s %11s %s", "probe", "containers", "p95 ms", "note")
	for i := range probes {
		cell := measure(ctx, t, p, 30, qAccessible, probes[i].Principal)
		res.Cells["resolve."+probes[i].Name] = cell
		x.addf("%-9s %11s %11.2f %s", probes[i].Name, comma(int64(probes[i].NAccess)), cell.P95, probes[i].Note)
	}

	x.write(t, p.dir)
}

func probeHeader(probes []probeRow) string {
	s := ""
	for i := range probes {
		s += fmt.Sprintf(" %21s", probes[i].Name)
	}
	return s
}

// firstAuthorized picks one fact the probe may read, so the point decision is
// measured on a hit rather than on a miss.
func firstAuthorized(ctx context.Context, t *testing.T, p *pg, pr *probeRow) int64 {
	t.Helper()
	v, ok := scalarOK[int64](ctx, p,
		"select fact_id from fact_ancestry where ancestor_id = any($1::int[]) limit 1", pr.Accessible)
	if !ok {
		return 1
	}
	return v
}
