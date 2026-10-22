package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/laenen-ai/iam/internal/domain"
)

func TestParseIDsRejectMalformedInput(t *testing.T) {
	t.Parallel()

	bad := []string{"", "not-a-ulid", "0123456789abcdefghijklmnop", "01J0000000000000000000000", "01J00000000000000000000000X"}
	for _, s := range bad {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseTenantID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParseTenantID(%q) error = %v, want ErrMalformedID", s, err)
			}
			if _, err := domain.ParsePrincipalID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParsePrincipalID(%q) error = %v, want ErrMalformedID", s, err)
			}
			if _, err := domain.ParseGroupID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParseGroupID(%q) error = %v, want ErrMalformedID", s, err)
			}
			if _, err := domain.ParseChangeID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParseChangeID(%q) error = %v, want ErrMalformedID", s, err)
			}
			if _, err := domain.ParseClearanceGroupID(s); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParseClearanceGroupID(%q) error = %v, want ErrMalformedID", s, err)
			}
		})
	}
}

func TestNewIDsAreUniqueAndParseable(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	seen := make(map[string]bool)
	for range 128 {
		id := domain.NewPrincipalID(clock)
		if seen[string(id)] {
			t.Fatalf("NewPrincipalID returned a duplicate (%q) from a fixed clock: entropy is not being mixed in", id)
		}
		seen[string(id)] = true
		if _, err := domain.ParsePrincipalID(string(id)); err != nil {
			t.Fatalf("ParsePrincipalID of a minted id: %v", err)
		}
	}
}

// TestInternalIDIsNotDerivedFromExternalSubject pins design §8.1's
// central identity invariant: the internal id carries no function of the
// external subject, so two sightings of the same subject mint different
// ids and no amount of external renaming can be inferred from an id.
// The registry's own half of this — that a *re-sighting* resolves to the
// same stored id rather than a new one — is the suite's
// ReissuedExternalIdentityKeepsInternalID subtest.
func TestInternalIDIsNotDerivedFromExternalSubject(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	subj, err := domain.ParseExternalSubject("https://idp.example/", "anne@example.test")
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}

	first := domain.NewPrincipalID(clock)
	second := domain.NewPrincipalID(clock)
	if first == second {
		t.Fatal("two mints produced the same id")
	}
	for _, id := range []domain.PrincipalID{first, second} {
		if s := string(id); s == subj.Subject || s == subj.String() || len(s) != 26 {
			t.Fatalf("internal id %q looks derived from the external subject %q", s, subj)
		}
	}
}
