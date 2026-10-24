package idp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/iam/iamtest"
	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/idp"
	"github.com/laenenai/iam/internal/registry"
)

// recordingRegistry wraps a real registry and counts every call, so a test
// can assert not just "no principal was created" but "the registry was
// never touched at all".
type recordingRegistry struct {
	registry.Registry
	upserts  int
	resolves int
}

func (r *recordingRegistry) UpsertFromClaims(ctx context.Context, c registry.Claims) (domain.Principal, error) {
	r.upserts++
	return r.Registry.UpsertFromClaims(ctx, c)
}

func (r *recordingRegistry) ResolveExternal(ctx context.Context, tenant domain.TenantID, s domain.ExternalSubject) (domain.Principal, error) {
	r.resolves++
	return r.Registry.ResolveExternal(ctx, tenant, s)
}

func newRecordingRegistry(t *testing.T) *recordingRegistry {
	t.Helper()
	reg, err := registry.NewMemory(registry.Config{StalenessBound: time.Hour, MaxAgentRunTTL: time.Hour})
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	return &recordingRegistry{Registry: reg}
}

func mustSubject(t *testing.T, issuer, subject string) domain.ExternalSubject {
	t.Helper()
	s, err := domain.ParseExternalSubject(issuer, subject)
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}
	return s
}

// TestJITProvisioner_UnregisteredIssuerNeverReachesTheRegistry is the
// invariant this package exists to hold. Design §8.1: "a token from an
// unregistered issuer is rejected before any lookup." Not before any
// *write* — before any lookup, because a registry read is an attributable
// signal and, on this path, a write.
func TestJITProvisioner_UnregisteredIssuerNeverReachesTheRegistry(t *testing.T) {
	t.Parallel()

	tenant := domain.NewTenantID(domain.SystemClock{})
	policy := idp.NewStaticIssuerPolicy(map[domain.TenantID][]string{
		tenant: {"https://zitadel.example/oauth/v2"},
	})
	reg := newRecordingRegistry(t)
	prov, err := idp.NewJITProvisioner(policy, reg)
	if err != nil {
		t.Fatalf("NewJITProvisioner: %v", err)
	}

	claims := registry.Claims{
		TenantID: tenant,
		Subject:  mustSubject(t, "https://attacker.example", "anne"),
		Kind:     domain.PrincipalKindUser,
		Groups:   []string{"admins"},
	}
	if _, err := prov.Provision(t.Context(), claims); !errors.Is(err, domain.ErrIssuerNotRegistered) {
		t.Fatalf("Provision from an unregistered issuer error = %v, want ErrIssuerNotRegistered", err)
	}
	if reg.upserts != 0 || reg.resolves != 0 {
		t.Fatalf("the registry was consulted %d times (upserts) and %d times (resolves) for an unregistered issuer; it must not be touched at all",
			reg.upserts, reg.resolves)
	}

	// The registered issuer works, and the claim-derived group is upserted
	// rather than passed through.
	claims.Subject = mustSubject(t, "https://zitadel.example/oauth/v2", "anne")
	p, err := prov.Provision(t.Context(), claims)
	if err != nil {
		t.Fatalf("Provision from a registered issuer: %v", err)
	}
	groups, err := reg.GroupsOf(t.Context(), p.ID, time.Now())
	if err != nil {
		t.Fatalf("GroupsOf: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "admins" {
		t.Fatalf("GroupsOf = %+v, want the one claim-derived group", groups)
	}
}

func TestStaticIssuerPolicy(t *testing.T) {
	t.Parallel()

	a := domain.NewTenantID(domain.SystemClock{})
	b := domain.NewTenantID(domain.SystemClock{})
	policy := idp.NewStaticIssuerPolicy(map[domain.TenantID][]string{
		a: {"https://idp-a.example"},
		b: {"https://idp-b.example"},
	})
	ctx := t.Context()

	cases := []struct {
		name    string
		tenant  domain.TenantID
		issuer  string
		wantErr bool
	}{
		{"registered", a, "https://idp-a.example", false},
		{"another tenant's issuer", a, "https://idp-b.example", true},
		{"unknown tenant", domain.NewTenantID(domain.SystemClock{}), "https://idp-a.example", true},
		{"empty issuer", a, "", true},
		// Two OIDC issuer identifiers differing by a trailing slash are
		// two trust roots. Normalizing them would mean accepting a token
		// from one as a token from the other.
		{"trailing slash is a different issuer", a, "https://idp-a.example/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := policy.Accepts(ctx, tc.tenant, tc.issuer)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Accepts(%q, %q) = %v", tc.tenant, tc.issuer, err)
			}
			if tc.wantErr && !errors.Is(err, domain.ErrIssuerNotRegistered) {
				t.Fatalf("Accepts error = %v, want ErrIssuerNotRegistered", err)
			}
		})
	}

	// A tenant with no registered issuers accepts none: "unconfigured"
	// must not mean "accept anything".
	empty := idp.NewStaticIssuerPolicy(nil)
	if err := empty.Accepts(ctx, a, "https://idp-a.example"); !errors.Is(err, domain.ErrIssuerNotRegistered) {
		t.Fatalf("an empty policy accepted an issuer: %v", err)
	}

	empty.Register(a, "https://idp-a.example")
	if err := empty.Accepts(ctx, a, "https://idp-a.example"); err != nil {
		t.Fatalf("Accepts after Register: %v", err)
	}
}

// TestStubKeySourceRefusesWithOneNamedError pins the stubbed transport's
// behaviour: a deployment with no OIDC client configured starts and serves
// service principals (anti-goal A1), and anything needing an issuer's keys
// fails in exactly one recognizable way rather than degrading.
func TestStubKeySourceRefusesWithOneNamedError(t *testing.T) {
	t.Parallel()

	var src idp.KeySource = idp.StubKeySource{}
	set, err := src.KeySet(t.Context(), "https://idp.example")
	if !errors.Is(err, domain.ErrCapabilityUnconfigured) {
		t.Fatalf("KeySet error = %v, want ErrCapabilityUnconfigured", err)
	}
	if len(set.KeyIDs) != 0 || len(set.Raw) != 0 {
		t.Fatal("the stub returned key material")
	}
	// Invalidate is a no-op and must not panic on an uncached issuer.
	src.Invalidate("https://idp.example")
}

func TestNewJITProvisioner_RejectsNilDependencies(t *testing.T) {
	t.Parallel()

	reg := newRecordingRegistry(t)
	if _, err := idp.NewJITProvisioner(nil, reg); !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("NewJITProvisioner(nil policy) error = %v, want ErrInvalidConfig", err)
	}
	if _, err := idp.NewJITProvisioner(idp.NewStaticIssuerPolicy(nil), nil); !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("NewJITProvisioner(nil registry) error = %v, want ErrInvalidConfig", err)
	}
}

// TestKeySetRendersNoKeyMaterial holds idp.KeySet to CONVENTIONS.md's
// "Rendering a secret" convention through the named subtest.
//
// Raw's doc comment says the document is "never logged and never placed in an
// error". Before KeySet had rendering methods, nothing enforced that: %v
// printed the document's bytes, %#v printed them as a Go literal, and
// json.Marshal — which an exported []byte reaches directly — emitted the whole
// thing as base64.
//
// On substance a JWKS is public, so this is not a confidentiality fix. It is a
// fix for a type that declared an invariant it had no mechanism for, and it
// means the next KeySource adapter inherits the mechanism rather than having
// to notice it is needed.
func TestKeySetRendersNoKeyMaterial(t *testing.T) {
	t.Parallel()

	// A plausible JWKS document, with a sentinel where the modulus goes so
	// that a match in a rendering is a leak and not a coincidence.
	const sentinel = "CANARY-7f3a9c-modulus-must-not-render"
	raw := []byte(`{"keys":[{"kty":"RSA","kid":"k1","n":"` + sentinel + `","e":"AQAB"}]}`)

	ks := idp.KeySet{
		Issuer: "https://idp.example",
		KeyIDs: []string{"k1", "k2"},
		Raw:    raw,
	}

	iamtest.NoSecretLeaksInAnyRendering(t, ks, raw)
	// KeySet renders nothing but its type and the marker, so it is held to
	// the positive half too. The document it holds is a *public* JWKS, so
	// this is a type gaining the mechanism for an invariant it had already
	// declared rather than a confidentiality hole being closed — but a
	// reader of a log line still needs to be able to tell a withheld
	// document from an empty one.
	iamtest.RendersOnlyARedactionMarker(t, ks)

	// The other half of the convention: a placeholder that identifies
	// nothing is a log line nobody can act on. The issuer and the key id
	// count are not secrets and are what a rotation-aware caller is
	// diagnosing.
	rendered := ks.String()
	for _, want := range []string{"idp.KeySet", "https://idp.example", "KeyIDs: 2"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("KeySet.String() = %q, want it to contain %q", rendered, want)
		}
	}
}
