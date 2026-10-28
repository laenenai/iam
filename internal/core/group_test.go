package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

func TestGroupMembershipChangesAccess(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g1", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	node := mustNode(t, svc, owner, tenant, "laenen/document/shared", "laenen/root/root")
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: domain.Subject{URN: group.Group.URN, Kind: domain.SubjectGroup}, Relation: domain.Viewer}); err != nil {
		t.Fatal(err)
	}
	d, err := svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer})
	if err != nil || !d.Allowed {
		t.Fatalf("group grant: %#v %v", d, err)
	}
	if _, err := svc.RemoveGroupMember(ctx, owner, RemoveGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	d, _ = svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer})
	if d.Allowed {
		t.Fatal("removed member still allows")
	}
}

func TestGroupLifecycleAndAdminAuthority(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	user2 := mustUser(t, tenant, "u2")
	user3 := mustUser(t, tenant, "u3")
	user4 := mustUser(t, tenant, "u4")
	for _, user := range []domain.Subject{user2, user3, user4} {
		linkUser(t, svc, tenant, user)
	}

	group, err := svc.CreateGroup(ctx, ownerOf(svc, tenant, user2), CreateGroupRequest{Tenant: tenant, GroupID: "g2", Name: "Friends"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddGroupMember(ctx, ownerOf(svc, tenant, user3), AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user4}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-admin add: %v", err)
	}
	tenantAdmin := domain.Actor{ID: "tenant-admin", Tenant: tenant, Role: domain.RoleTenantAdmin, Subject: owner.Subject}
	if _, err := svc.AddGroupMember(ctx, tenantAdmin, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user4}); err != nil {
		t.Fatalf("tenant admin add: %v", err)
	}
	if _, err := svc.AddGroupMember(ctx, ownerOf(svc, tenant, user2), AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user4}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate member: %v", err)
	}
	if _, err := svc.RemoveGroupMember(ctx, ownerOf(svc, tenant, user2), RemoveGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user3}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("removed a non-member: %v", err)
	}

	if _, err := svc.SetGroupAdmin(ctx, ownerOf(svc, tenant, user2), SetGroupAdminRequest{Tenant: tenant, Group: group.Group.URN, Admin: user3}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddGroupMember(ctx, ownerOf(svc, tenant, user2), AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user3}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("former admin still acts: %v", err)
	}
	if _, err := svc.AddGroupMember(ctx, ownerOf(svc, tenant, user3), AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user2}); err != nil {
		t.Fatalf("new admin add: %v", err)
	}

	if _, err := svc.DeleteGroup(ctx, tenantAdmin, DeleteGroupRequest{Tenant: tenant, Group: group.Group.URN, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if g, ok := svc.store.Group(tenant, group.Group.URN); !ok || g.Live {
		t.Fatalf("group still live: %#v", g)
	}
	if _, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g2", Name: "Again"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("group urn reused: %v", err)
	}
}

func TestGroupGrantOwnerAndDelete(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g3", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	node := mustNode(t, svc, owner, tenant, "laenen/document/owned", "laenen/root/root")
	groupSubject := domain.Subject{URN: group.Group.URN, Kind: domain.SubjectGroup}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: groupSubject, Relation: domain.Owner}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.CanShare}); !d.Allowed {
		t.Fatalf("group owner does not share: %#v", d)
	}

	if _, err := svc.DeleteGroup(ctx, owner, DeleteGroupRequest{Tenant: tenant, Group: group.Group.URN, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); d.Allowed {
		t.Fatal("deleted group grant still allows")
	}
}

func TestGroupMemberValidation(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g4", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	unlinked := mustUser(t, tenant, "u2")
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: unlinked}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("unlinked member: %v", err)
	}
	nested := domain.Subject{URN: "laenen/group/other", Kind: domain.SubjectGroup}
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: nested}); !errors.Is(err, domain.ErrInvalidSubject) {
		t.Fatalf("nested group member: %v", err)
	}
}

func TestTenantAdminGroupCommandsRequireLiveGroup(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	admin := tenantAdmin(tenant, owner.Subject)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)

	missing := domain.URN("laenen/group/missing")
	if _, err := svc.AddGroupMember(ctx, admin, AddGroupMemberRequest{Tenant: tenant, Group: missing, Member: user}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("add to missing group: %v", err)
	}
	if _, err := svc.SetGroupAdmin(ctx, admin, SetGroupAdminRequest{Tenant: tenant, Group: missing, Admin: user}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("admin of missing group: %v", err)
	}
	if _, err := svc.DeleteGroup(ctx, admin, DeleteGroupRequest{Tenant: tenant, Group: missing}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing group: %v", err)
	}
	if d := mustCheck(t, svc, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: mustRoot(t, svc, tenant), Relation: domain.Viewer}); d.Allowed {
		t.Fatal("a failed group command changed access")
	}

	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g5", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	node := mustNode(t, svc, owner, tenant, "laenen/document/shared", mustRoot(t, svc, tenant))
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: domain.Subject{URN: group.Group.URN, Kind: domain.SubjectGroup}, Relation: domain.Viewer}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteGroup(ctx, admin, DeleteGroupRequest{Tenant: tenant, Group: group.Group.URN}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); d.Allowed {
		t.Fatal("deleted group grant still allows")
	}
	if _, err := svc.AddGroupMember(ctx, admin, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("add to deleted group: %v", err)
	}
}
