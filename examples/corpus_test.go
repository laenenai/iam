package examples_test

import (
	"bytes"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/laenen-ai/iam"
	"github.com/laenen-ai/iam/examples"
	"github.com/laenen-ai/iam/examples/scenario"
)

// updateLedger rewrites examples/pending.txt instead of checking it:
//
//	go test ./examples/... -run TestLedger -update-ledger
var updateLedger = flag.Bool("update-ledger", false, "rewrite examples/pending.txt from the current corpus")

// corpusStalenessBound and corpusMaxAgentRunTTL are the deployment policy
// the corpus's registry is given. The bound is long enough that no
// scenario trips it by accident; the scenario that is *about* the bound
// drives the clock rather than waiting.
const (
	corpusStalenessBound = 15 * time.Minute
	corpusMaxAgentRunTTL = 24 * time.Hour
)

// newRegistry is the per-scenario factory. The corpus runs against the
// in-memory registry here; the same call with iam.NewPostgresRegistry is
// how it runs against the deployment adapter, and the same call from a
// consumer's own test package is how CAS runs it against its own wiring.
func newRegistry(t *testing.T) iam.Registry {
	t.Helper()
	reg, err := iam.NewMemoryRegistry(iam.RegistryConfig{
		StalenessBound: corpusStalenessBound,
		MaxAgentRunTTL: corpusMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("NewMemoryRegistry: %v", err)
	}
	return reg
}

func TestCorpus(t *testing.T) {
	scenario.RunCorpus(t, examples.All(), newRegistry)
}

// TestLedger keeps examples/pending.txt in step with the corpus. It is the
// second of the two mechanisms that stop a pending scenario from staying
// pending silently: the api.txt tripwire fires automatically when a
// capability lands, and this file makes every change to the set of pending
// and unexpressible scenarios a reviewed diff.
func TestLedger(t *testing.T) {
	t.Parallel()

	got := []byte(scenario.Ledger(examples.All()))
	if *updateLedger {
		if err := os.WriteFile("pending.txt", got, 0o600); err != nil {
			t.Fatalf("write pending.txt: %v", err)
		}
		t.Log("pending.txt rewritten")
		return
	}
	want, err := os.ReadFile("pending.txt")
	if err != nil {
		t.Fatalf("read pending.txt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pending.txt is stale: the corpus's status has changed.\n"+
			"Regenerate with: go test ./examples/... -run TestLedger -update-ledger\n\n"+
			"--- pending.txt\n%s\n--- corpus\n%s", want, got)
	}
}

// TestEveryScenarioIsWellFormed validates the corpus itself. A fixture
// naming a principal that does not exist, an unexpressible scenario with
// nothing executable behind its claim, or two scenarios sharing an id
// would otherwise be a corpus that passes without saying anything.
func TestEveryScenarioIsWellFormed(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for _, s := range examples.All() {
		if seen[s.ID] {
			t.Errorf("duplicate scenario id %q", s.ID)
		}
		seen[s.ID] = true
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", s.ID, err)
		}
	}
}
