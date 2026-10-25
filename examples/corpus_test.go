package examples_test

import (
	"bytes"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/laenenai/iam"
	"github.com/laenenai/iam/examples"
	"github.com/laenenai/iam/examples/scenario"
	"github.com/laenenai/iam/iamtest"
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

// newAuthority is the per-scenario factory: the identity registry a
// fixture's principals and groups are materialized against, and the
// authorizer its containers and grants are written to. The corpus runs
// against the in-memory adapters here; the same call with
// iam.NewPostgresRegistry and iam.NewPostgresAuthorizer is how it runs
// against the deployment adapters, and the same call from a consumer's own
// test package is how CAS runs it against its own wiring.
//
// One factory returns both halves because the authorizer composes the
// registry rather than keeping its own copy of membership: a decision
// joins live group membership, so two independently supplied halves would
// be two different answers to the same question.
func newAuthority(t *testing.T) iamtest.Authority {
	t.Helper()
	reg, err := iam.NewMemoryRegistry(iam.RegistryConfig{
		StalenessBound: corpusStalenessBound,
		MaxAgentRunTTL: corpusMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("NewMemoryRegistry: %v", err)
	}
	authorizer, err := iam.NewMemoryAuthorizer(reg, iam.AuthorizerConfig{})
	if err != nil {
		t.Fatalf("NewMemoryAuthorizer: %v", err)
	}
	return iamtest.Authority{Registry: reg, Authorizer: authorizer}
}

func TestCorpus(t *testing.T) {
	scenario.RunCorpus(t, examples.All(), newAuthority)
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
