package projector_test

import (
	"testing"
	"time"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/projector"
)

func TestMemoryStoreQueries(t *testing.T) {
	store := projector.NewMemoryStore()
	user := domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}
	group := domain.Subject{URN: "t/group/g1", Kind: domain.SubjectGroup}
	now := time.Unix(100, 0)

	grant := domain.Grant{ID: "g1", Tenant: "t", Object: "t/document/d1", Subject: user, Relation: domain.Viewer, GrantedBy: "a", GrantedAt: now, Live: true}
	store.SetGrant(grant)
	if got := store.GrantsForObject("t", "t/document/d1"); len(got) != 1 || got[0].ID != "g1" {
		t.Fatalf("object grants: %#v", got)
	}
	if got := store.GrantsForSubject("t", user); len(got) != 1 || got[0].ID != "g1" {
		t.Fatalf("subject grants: %#v", got)
	}
	grant.Live = false
	store.SetGrant(grant)
	if got := store.GrantsForObject("t", "t/document/d1"); len(got) != 0 {
		t.Fatalf("revoked grant returned: %#v", got)
	}
	if got, ok := store.Grant("t", "g1"); !ok || got.Live {
		t.Fatalf("revoked grant not retained: %#v %v", got, ok)
	}

	store.SetGroup(domain.Group{URN: group.URN, Tenant: "t", Name: "Family", Admin: user, Live: true, CreatedAt: now})
	store.SetGroupMember("t", group.URN, user, true)
	store.SetGroupMember("t", group.URN, domain.Subject{URN: "t/user/u2", Kind: domain.SubjectUser}, false)
	if got := store.GroupMembers("t", group.URN); len(got) != 1 || got[0].URN != user.URN {
		t.Fatalf("members: %#v", got)
	}
	if got := store.GroupsForMember("t", user); len(got) != 1 {
		t.Fatalf("groups for member: %#v", got)
	}
	if got := store.GroupsForAdmin("t", user); len(got) != 1 {
		t.Fatalf("groups for admin: %#v", got)
	}

	store.SetNode(domain.Node{URN: "t/document/d1", Tenant: "t", Kind: "document", Live: true, CreatedAt: now, CreatedBy: "a"})
	if got := store.Nodes("t"); len(got) != 1 || got[0].URN != "t/document/d1" {
		t.Fatalf("nodes: %#v", got)
	}

	store.AddPendingKind(domain.KindSpec{Name: "document"})
	if _, ok := store.PendingKind("document"); !ok {
		t.Fatal("pending kind missing")
	}
	if _, ok := store.Kind("document"); ok {
		t.Fatal("pending kind published early")
	}
	store.PublishKinds(1)
	if _, ok := store.PendingKind("document"); ok {
		t.Fatal("published kind still pending")
	}
	if _, ok := store.Kind("document"); !ok || store.ModelVersion() != 1 {
		t.Fatalf("kind/model: %v %d", ok, store.ModelVersion())
	}
}
