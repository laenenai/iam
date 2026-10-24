package f3spike

import (
	"context"
	"fmt"
	"testing"
)

// reportRecommended writes recommended.txt: the one combination the write-up
// ends up proposing, measured in its own right rather than inferred from two
// cells that each tested half of it.
//
// The shape is the K2 array key over the fact's direct containers, GIN
// indexed, pre-restricting a C2 fragment -- a fragment that stores nothing
// authorization-mutable at fact cardinality. Three comparisons stand beside
// it: the fragment with no key, the key with no fragment (F1 condition (i),
// so the exposure is priced rather than asserted), and the key paired with
// C4's fragment, which is the cheaper join over the more expensive table.
func reportRecommended(ctx context.Context, t *testing.T, p *pg, probes []probeRow, res *results) {
	x := newTranscript("recommended.txt")
	x.addf("F3 -- the recommended shape, measured as itself")
	x.addf("")
	x.addf("  C2 alone      the fragment with no key: what A2's 20 ms is measured against")
	x.addf("  K2 only       the key with no fragment -- unsafe, priced to show what it exposes")
	x.addf("  K2 + C2       the recommendation: array key pre-restricts, C2 fragment authorizes")
	x.addf("  K2 + C4       the same key over the fact_container fragment, for comparison")
	x.addf("")
	x.addf("p50 / p95 ms, up to %d executions.", pageReps)

	rows := []struct {
		name string
		sql  string
		args func(pr *probeRow) []any
	}{
		{"C2 alone", qPageC2u, func(pr *probeRow) []any { return []any{pr.Principal, int64(0)} }},
		{"K2 only", qPageKeyOnlyK2, func(pr *probeRow) []any { return []any{pr.Accessible, int64(0)} }},
		{"K2 + C2", qPageKeySafeC2, func(pr *probeRow) []any { return []any{pr.Accessible, int64(0), pr.Principal} }},
		{"K2 + C4", withKeyTest(qPageKeySafe, keyTestK2), func(pr *probeRow) []any {
			return []any{pr.Accessible, int64(0), pr.Principal}
		}},
	}

	x.head("keyset page, 50 rows (p50 / p95 ms)")
	x.addf("%-10s %s", "", probeHeader(probes))
	for _, r := range rows {
		line := fmt.Sprintf("%-10s", r.name)
		for i := range probes {
			if skipKeys(&probes[i]) && r.name != "C2 alone" {
				line += fmt.Sprintf(" %21s", "skipped")
				continue
			}
			cell := measure(ctx, t, p, pageReps, r.sql, r.args(&probes[i])...)
			res.Cells["rec."+r.name+"."+probes[i].Name] = cell
			line += fmt.Sprintf(" %21s", cell.String())
		}
		x.addf("%s", line)
	}

	x.head("what the key alone exposes, on the recommended key")
	x.addf("%-9s %14s %14s %12s", "probe", "candidates", "authorized", "unauth/50")
	for i := range probes {
		pr := &probes[i]
		if skipKeys(pr) {
			continue
		}
		cand := scalar[int64](ctx, t, p, qCandK2, pr.Accessible)
		unauth := scalar[int64](ctx, t, p, withKeyTest(qUnauthorizedInTop, keyTestK2), pr.Accessible, pr.Principal)
		x.addf("%-9s %14s %14s %12d", pr.Name, comma(cand), comma(pr.Authorized), unauth)
	}
	x.addf("")
	x.addf("Zero unauthorized rows is NOT a licence to drop the fragment. It is a property")
	x.addf("of this fixture, in which no grant is finer than a container: kgs §9.3 keeps a")
	x.addf("per-fact rule as an escape hatch, and K3 -- the same key one level coarser --")
	x.addf("exposes rows in keys.txt. F1 condition (i) stands.")

	x.head("plans")
	for i := range probes {
		pr := &probes[i]
		if pr.Name != "p_es3" && pr.Name != "p_mix" && pr.Name != "p_es1" {
			continue
		}
		x.head("K2 + C2 -- " + pr.Name)
		x.addf("%s", explain(ctx, t, p, qPageKeySafeC2, pr.Accessible, int64(0), pr.Principal))
	}

	x.write(t, p.dir)
}
