package domain

import (
	"errors"
	"testing"
	"time"
)

func TestActorValidate(t *testing.T) {
	user, err := NewUserSubject("laenen", "u1")
	if err != nil {
		t.Fatal(err)
	}

	valid := []Actor{
		{ID: "a1", Tenant: "laenen", Role: RoleUser, Subject: user},
		{ID: "a2", Role: RoleDeploymentAdmin},
		{ID: "a3", Role: RoleIdentityAdapter},
		{ID: "a4", Tenant: "laenen", Role: RoleIdentityAdapter},
		{ID: "a5", Tenant: "laenen", Role: RoleAuditor},
	}
	for _, a := range valid {
		if err := a.Validate(); err != nil {
			t.Fatalf("%#v: %v", a, err)
		}
	}

	invalid := []Actor{
		{Tenant: "laenen", Role: RoleUser, Subject: user},
		{ID: "a1", Tenant: "laenen", Role: "root", Subject: user},
		{ID: "a1", Role: RoleUser, Subject: user},
		{ID: "a1", Tenant: "other", Role: RoleUser, Subject: user},
		{ID: "a1", Role: RoleAuditor},
		{ID: "a1", Tenant: "laenen", Role: RoleUser},
	}
	for _, a := range invalid {
		if err := a.Validate(); !errors.Is(err, ErrInvalidActor) {
			t.Fatalf("%#v: %v", a, err)
		}
	}
}

func TestFixedClock(t *testing.T) {
	var clock FixedClock
	if got := clock.Now(); !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("zero clock: %v", got)
	}
	clock.Advance(2 * time.Minute)
	if got := clock.Now().Unix(); got != 120 {
		t.Fatalf("got %d", got)
	}
}

func TestNewGrantID(t *testing.T) {
	a, err := NewGrantID(FixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewGrantID(FixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || b == "" || a == b {
		t.Fatalf("a=%q b=%q", a, b)
	}
}
