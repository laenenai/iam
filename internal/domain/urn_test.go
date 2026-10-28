package domain

import (
	"errors"
	"testing"
)

func TestURNShape(t *testing.T) {
	u, err := ParseURN("laenen/folder/home")
	if err != nil {
		t.Fatal(err)
	}
	if u.Tenant() != "laenen" || u.Kind() != "folder" || u.ID() != "home" {
		t.Fatalf("bad parse: %#v", u)
	}

	for _, bad := range []string{"", "laenen/folder", "Laenen/folder/home", "laenen/Folder/home", "laenen/folder/home/extra", "laenen/folder/"} {
		if _, err := ParseURN(bad); !errors.Is(err, ErrInvalidURN) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestNewNodeURN(t *testing.T) {
	u, err := NewNodeURN("laenen", "document", "tax-2026")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.String(); got != "laenen/document/tax-2026" {
		t.Fatalf("got %q", got)
	}

	for _, tc := range []struct {
		name   string
		tenant TenantID
		kind   string
		id     string
	}{
		{"bad tenant", "Laenen", "document", "tax"},
		{"bad kind", "laenen", "Doc-ument", "tax"},
		{"empty id", "laenen", "document", ""},
	} {
		if _, err := NewNodeURN(tc.tenant, tc.kind, tc.id); !errors.Is(err, ErrInvalidURN) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}

func TestParseTenantID(t *testing.T) {
	got, err := ParseTenantID("laenen-ai")
	if err != nil || got != "laenen-ai" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ParseTenantID("Laenen"); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("uppercase tenant: %v", err)
	}
}
