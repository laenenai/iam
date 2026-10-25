package authz_test

import (
	"testing"
	"time"

	"github.com/laenenai/iam"
	"github.com/laenenai/iam/iamtest"
)

// The in-memory authorizer runs the conformance suite, and the factory
// builds a fresh registry *and* a fresh authorizer over it for every
// subtest. That pairing is the contract rather than convenience: the group
// side of a decision is the registry's own membership, so a factory that
// reused one registry across subtests would let one subtest's
// deprovisioning change another's answer.
func TestMemoryAuthorizerConformance(t *testing.T) {
	iamtest.RunAuthorizerSuite(t, func(t *testing.T) iamtest.Authority {
		t.Helper()
		reg, err := iam.NewMemoryRegistry(iam.RegistryConfig{
			StalenessBound: time.Hour,
			MaxAgentRunTTL: time.Hour,
		})
		if err != nil {
			t.Fatalf("NewMemoryRegistry: %v", err)
		}
		az, err := iam.NewMemoryAuthorizer(reg, iam.AuthorizerConfig{})
		if err != nil {
			t.Fatalf("NewMemoryAuthorizer: %v", err)
		}
		return iamtest.Authority{Registry: reg, Authorizer: az}
	})
}

// A nil registry is refused rather than tolerated: an authorizer with no
// registry could still answer every direct grant and would answer every
// group grant with "no", which is a half-working authorization layer and
// the worst of the three possible states.
func TestNewMemoryAuthorizerRefusesANilRegistry(t *testing.T) {
	t.Parallel()
	if _, err := iam.NewMemoryAuthorizer(nil, iam.AuthorizerConfig{}); err == nil {
		t.Fatal("NewMemoryAuthorizer(nil) succeeded, want a refusal")
	}
}
