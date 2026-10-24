package f3spike

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pageReps and pointReps are F1's sample sizes, adjusted for how slow the
// slowest cell here is: F1 ran 30 queries per cell against a 2,000,000-row
// table; the page query here runs against 10,000,000 rows and the worst cell
// is seconds, so pages get 20 and the cheap point decision gets 100.
const (
	pageReps  = 20
	pointReps = 100
)

// probeRow is one measured principal, with the two container sets every
// question below is expressed in terms of.
type probeRow struct {
	Name       string  `json:"name"`
	Principal  int32   `json:"principal"`
	Note       string  `json:"note"`
	Granted    []int32 `json:"-"`
	Accessible []int32 `json:"-"`
	NGranted   int     `json:"granted_containers"`
	NAccess    int     `json:"accessible_containers"`
	Authorized int64   `json:"authorized_facts"`
	Selectiv   float64 `json:"selectivity_pct"`
}

// results is the machine-readable twin of the transcripts, the way F1's
// results-correlated.json is.
type results struct {
	Scale    float64            `json:"scale"`
	Params   map[string]string  `json:"params"`
	Server   string             `json:"server"`
	Baseline timing             `json:"roundtrip_baseline"`
	Probes   []probeRow         `json:"probes"`
	Cells    map[string]timing  `json:"cells"`
	Counts   map[string]int64   `json:"counts"`
	Floats   map[string]float64 `json:"floats"`
	Builds   map[string]string  `json:"builds"`
}

func newResults(prm params) *results {
	return &results{
		Scale: prm.scale, Params: prm.vals,
		Cells: map[string]timing{}, Counts: map[string]int64{},
		Floats: map[string]float64{}, Builds: map[string]string{},
	}
}

// TestF3 is the whole spike. It is one test rather than several because the
// fixture takes most of an hour to build and every question is asked of the
// same fixture; splitting it would either rebuild or share state across tests
// that Go is entitled to run in any order.
func TestF3(t *testing.T) {
	if os.Getenv("F3_SPIKE") == "" {
		t.Skip("f3: set F3_SPIKE=1 to run the DAG-containment spike (10,000,000 facts; not a CI test)")
	}
	ctx := context.Background()
	prm := newParams()
	p := start(ctx, t)
	res := newResults(prm)
	res.Server = scalar[string](ctx, t, p, "select version()")
	t.Logf("f3: scale %g, server %s", prm.scale, res.Server)

	if os.Getenv("F3_SKIP_BUILD") == "" {
		buildFixture(ctx, t, p, prm, res)
	}

	probes := loadProbes(ctx, t, p)
	res.Baseline = measure(ctx, t, p, 300, "select 1")

	reportFixture(ctx, t, p, prm, probes, res)
	reportRead(ctx, t, p, probes, res)
	reportKeys(ctx, t, p, probes, res)
	reportVisibleBelow(ctx, t, p, probes, res)
	reportMaintenance(ctx, t, p, prm, res)
	reportPredicateSets(ctx, t, p, res)
	reportExplain(ctx, t, p, probes)

	res.Probes = append(res.Probes, probes...)
	blob, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatalf("f3: marshal results: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.dir, "results.json"), blob, 0o600); err != nil {
		t.Fatalf("f3: write results.json: %v", err)
	}
}

// buildFixture runs the SQL files in order and records how long each took,
// because build cost is one of question 1's answers and not an incidental.
func buildFixture(ctx context.Context, t *testing.T, p *pg, prm params, res *results) {
	stages := []string{
		"01-schema.sql",
		"02-generate.sql",
		"03-container-ancestry.sql",
		"04-c1-fact-ancestry.sql",
		"05-c1-index.sql",
		"06-c4-fact-container.sql",
		"07-keys.sql",
		"08-predicate-sets.sql",
	}
	// The closure builds are the only place parallelism is allowed, and only
	// for the scan side of an INSERT ... SELECT. Measurement runs with
	// max_parallel_workers_per_gather = 0, as F1's did.
	total := time.Duration(0)
	for _, s := range stages {
		if s == "04-c1-fact-ancestry.sql" || s == "06-c4-fact-container.sql" || s == "07-keys.sql" {
			p.exec(ctx, t, "set max_parallel_workers_per_gather = 4")
		}
		d := p.runFile(ctx, t, s, prm)
		p.exec(ctx, t, "set max_parallel_workers_per_gather = 0")
		res.Builds[s] = dur(d)
		total += d
	}
	res.Builds["TOTAL"] = dur(total)
	p.exec(ctx, t, "vacuum analyze")
}

// loadProbes reads the probe table and resolves each probe's granted and
// accessible container sets.
func loadProbes(ctx context.Context, t *testing.T, p *pg) []probeRow {
	rows, err := p.pool.Query(ctx, "select name, principal, note from probe order by principal")
	if err != nil {
		t.Fatalf("f3: load probes: %v", err)
	}
	var out []probeRow
	for rows.Next() {
		var r probeRow
		if err := rows.Scan(&r.Name, &r.Principal, &r.Note); err != nil {
			rows.Close()
			t.Fatalf("f3: scan probe: %v", err)
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("f3: probe rows: %v", err)
	}
	for i := range out {
		out[i].Granted = scalar[[]int32](ctx, t, p, qGranted, out[i].Principal)
		out[i].Accessible = scalar[[]int32](ctx, t, p, qAccessible, out[i].Principal)
		out[i].NGranted = len(out[i].Granted)
		out[i].NAccess = len(out[i].Accessible)
	}
	return out
}
