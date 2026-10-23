package registry_test

import (
	"errors"
	"testing"
	"time"

	"github.com/laenenai/iam"
	"github.com/laenenai/iam/iamtest"
	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/registry"
)

// suiteStalenessBound and suiteMaxAgentRunTTL are the deployment policy the
// in-memory adapter is given for the conformance run. The bound is long
// enough that no subtest trips it by accident and the suite discovers it
// through domain.PrincipalCondition.Bound rather than being told.
const (
	suiteStalenessBound = 15 * time.Minute
	suiteMaxAgentRunTTL = 24 * time.Hour
)

// newMemoryRegistry is the per-subtest factory: a fresh, isolated registry
// for every subtest, with nothing to clean up because nothing outlives the
// value.
func newMemoryRegistry(t *testing.T) iam.Registry {
	t.Helper()
	reg, err := registry.NewMemory(registry.Config{
		StalenessBound: suiteStalenessBound,
		MaxAgentRunTTL: suiteMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	return reg
}

func TestMemory_PassesRegistrySuite(t *testing.T) {
	iamtest.RunRegistrySuite(t, newMemoryRegistry)
}

func TestNewMemory_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  registry.Config
	}{
		{"no staleness bound", registry.Config{MaxAgentRunTTL: time.Hour}},
		{"negative staleness bound", registry.Config{StalenessBound: -time.Hour, MaxAgentRunTTL: time.Hour}},
		{"no agent run ceiling", registry.Config{StalenessBound: time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := registry.NewMemory(tc.cfg); !errors.Is(err, iam.ErrInvalidConfig) {
				t.Fatalf("NewMemory error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// TestMemory_AgentRunTTLIsCapped covers the one piece of deployment policy
// the conformance suite cannot assert, because the suite does not know a
// registry's ceiling: a caller must not be able to mint an effectively
// permanent agent-run principal through a discretionary delegation.
func TestMemory_AgentRunTTLIsCapped(t *testing.T) {
	t.Parallel()

	reg, err := registry.NewMemory(registry.Config{StalenessBound: time.Hour, MaxAgentRunTTL: time.Hour})
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	ctx := t.Context()
	tenant := domain.NewTenantID(domain.SystemClock{})
	subject, err := domain.ParseExternalSubject("https://idp.example", "svc")
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}
	parent, err := reg.UpsertFromClaims(ctx, iam.Claims{
		TenantID: tenant,
		Subject:  subject,
		Kind:     iam.PrincipalKindService,
	})
	if err != nil {
		t.Fatalf("UpsertFromClaims: %v", err)
	}

	if _, err := reg.DelegateAgentRun(ctx, parent.ID, iam.AgentRunSpec{TTL: 2 * time.Hour}); !errors.Is(err, iam.ErrInvalidPrincipal) {
		t.Fatalf("DelegateAgentRun past the ceiling error = %v, want ErrInvalidPrincipal", err)
	}
	if _, err := reg.DelegateAgentRun(ctx, parent.ID, iam.AgentRunSpec{TTL: time.Hour}); err != nil {
		t.Fatalf("DelegateAgentRun at the ceiling: %v", err)
	}
}
