package domain

import (
	"errors"
	"testing"
	"time"
)

func TestAggregateValidation(t *testing.T) {
	user, err := NewUserSubject("laenen", "u1")
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewGroupSubject("laenen", "g1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)

	node := Node{URN: "laenen/folder/home", Tenant: "laenen", Kind: "folder", Parent: "laenen/root/root", Live: true, CreatedAt: now, CreatedBy: "a"}
	if err := node.Validate(); err != nil {
		t.Fatal(err)
	}
	badNode := node
	badNode.Tenant = "other"
	if err := badNode.Validate(); !errors.Is(err, ErrInvalidURN) {
		t.Fatalf("node tenant mismatch: %v", err)
	}

	grant := Grant{ID: "01H", Tenant: "laenen", Object: "laenen/document/d1", Subject: user, Relation: Viewer, GrantedBy: "a", GrantedAt: now, Live: true}
	if err := grant.Validate(); err != nil {
		t.Fatal(err)
	}
	badGrant := grant
	badGrant.Relation = CanShare
	if err := badGrant.Validate(); !errors.Is(err, ErrInvalidRelation) {
		t.Fatalf("computed grant: %v", err)
	}

	grp := Group{URN: "laenen/group/g1", Tenant: "laenen", Name: "Family", Admin: user, Live: true, CreatedAt: now}
	if err := grp.Validate(); err != nil {
		t.Fatal(err)
	}
	badGroup := grp
	badGroup.Admin = group
	if err := badGroup.Validate(); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("group admin must be a user: %v", err)
	}

	p := Principal{URN: "laenen/user/u1", Tenant: "laenen", Issuer: "issuer", ExternalID: "external-1", Kind: SubjectUser, GlobalLive: true, TenantLive: true, Live: true, LinkedAt: now}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.TenantLive = false
	p.Live = false
	if p.EffectiveLive() {
		t.Fatal("effective live must be false")
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
