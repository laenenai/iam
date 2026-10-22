package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/laenen-ai/iam/internal/domain"
)

func TestParseExternalSubject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		issuer, subject string
		wantErr         bool
	}{
		{"oidc url and sub", "https://zitadel.example/oauth/v2", "281845098765432109", false},
		{"empty issuer", "", "sub", true},
		{"empty subject", "https://idp.example", "", true},
		{"leading space in issuer", " https://idp.example", "sub", true},
		{"trailing newline in subject", "https://idp.example", "sub\n", true},
		{"null byte", "https://idp.example", "su\x00b", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.ParseExternalSubject(tc.issuer, tc.subject)
			if tc.wantErr {
				if !errors.Is(err, domain.ErrInvalidExternalSubject) {
					t.Fatalf("error = %v, want ErrInvalidExternalSubject", err)
				}
				if !got.IsZero() {
					t.Fatal("a rejected external subject must be the zero value")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseExternalSubject: %v", err)
			}
			if got.Issuer != tc.issuer || got.Subject != tc.subject {
				t.Fatalf("got %+v, want issuer=%q subject=%q", got, tc.issuer, tc.subject)
			}
		})
	}
}

// TestParseExternalSubjectDoesNotNormalizeIssuer pins the decision not to
// canonicalize an issuer: two OIDC issuer identifiers that differ by a
// trailing slash are two trust roots, and silently merging them would mean
// a token from one is accepted as a token from the other.
func TestParseExternalSubjectDoesNotNormalizeIssuer(t *testing.T) {
	t.Parallel()

	a, err := domain.ParseExternalSubject("https://idp.example", "sub")
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}
	b, err := domain.ParseExternalSubject("https://idp.example/", "sub")
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}
	if a == b {
		t.Fatal("issuers differing by a trailing slash were merged; they are distinct trust roots")
	}
}

func TestPrincipalValidate(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	tenant := domain.NewTenantID(clock)
	parent := domain.NewPrincipalID(clock)
	subj, err := domain.ParseExternalSubject("https://idp.example", "sub")
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}
	now := clock.Now()

	base := func() domain.Principal {
		return domain.Principal{
			ID:       domain.NewPrincipalID(clock),
			TenantID: tenant,
			Kind:     domain.PrincipalKindUser,
			External: subj,
			SyncedAt: now,
		}
	}

	cases := []struct {
		name    string
		mutate  func(*domain.Principal)
		wantErr bool
	}{
		{"valid user", func(*domain.Principal) {}, false},
		{"valid service without external subject", func(p *domain.Principal) {
			p.Kind = domain.PrincipalKindService
			p.External = domain.ExternalSubject{}
		}, false},
		{"valid agent run", func(p *domain.Principal) {
			p.Kind = domain.PrincipalKindAgentRun
			p.External = domain.ExternalSubject{}
			p.DelegatedBy = parent
			p.ExpiresAt = now.Add(time.Hour)
		}, false},
		{"no id", func(p *domain.Principal) { p.ID = "" }, true},
		{"no tenant", func(p *domain.Principal) { p.TenantID = "" }, true},
		{"unknown kind", func(p *domain.Principal) { p.Kind = "robot" }, true},
		{"user without external subject", func(p *domain.Principal) { p.External = domain.ExternalSubject{} }, true},
		{"no synced_at", func(p *domain.Principal) { p.SyncedAt = time.Time{} }, true},
		{"agent run without parent", func(p *domain.Principal) {
			p.Kind = domain.PrincipalKindAgentRun
			p.ExpiresAt = now.Add(time.Hour)
		}, true},
		{"agent run without ttl", func(p *domain.Principal) {
			p.Kind = domain.PrincipalKindAgentRun
			p.DelegatedBy = parent
		}, true},
		{"user carrying a delegation", func(p *domain.Principal) { p.DelegatedBy = parent }, true},
		{"user carrying a ttl", func(p *domain.Principal) { p.ExpiresAt = now.Add(time.Hour) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := base()
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr {
				if !errors.Is(err, domain.ErrInvalidPrincipal) {
					t.Fatalf("Validate() error = %v, want ErrInvalidPrincipal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(): %v", err)
			}
		})
	}
}
