package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

func TestListObjectsAndSubjects(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	g, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	objs, err := svc.ListObjects(ctx, ownerOf(svc, tenant, user), ListObjectsRequest{Tenant: tenant, Subject: user, Relation: domain.Viewer, Kind: "document"})
	if err != nil || len(objs.Objects) != 1 || objs.Objects[0] != doc.URN {
		t.Fatalf("%#v %v", objs, err)
	}
	subs, err := svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: doc.URN, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sg := range subs.Grants {
		if sg.GrantID == g.GrantID && sg.Subject == user && sg.Object == folder.URN {
			found = true
			if sg.GrantedAt.IsZero() {
				t.Fatal("provenance has no granted_at")
			}
		}
	}
	if !found {
		t.Fatalf("contributing grant missing: %#v", subs)
	}
	count, err := svc.AccessibleCount(ctx, ownerOf(svc, tenant, user), AccessibleCountRequest{Tenant: tenant, Subject: user, Relation: domain.Viewer, Kind: "document"})
	if err != nil || count.Count != 1 {
		t.Fatalf("count: %#v %v", count, err)
	}
}

func TestListSubjectsExpandsGroupsAndFiltersLiveness(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g1", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	g, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: domain.Subject{URN: group.Group.URN, Kind: domain.SubjectGroup}, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	subs, err := svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: doc.URN, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sg := range subs.Grants {
		if sg.GrantID == g.GrantID {
			found = true
			if sg.Subject != user || sg.ViaGroup != group.Group.URN || sg.Depth != 1 {
				t.Fatalf("group expansion: %#v", sg)
			}
		}
	}
	if !found {
		t.Fatalf("group grant missing: %#v", subs)
	}

	tenantAdmin := domain.Actor{ID: "tenant-admin", Tenant: tenant, Role: domain.RoleTenantAdmin, Subject: owner.Subject}
	if _, err := svc.DeactivatePrincipal(ctx, tenantAdmin, DeactivatePrincipalRequest{Tenant: tenant, Subject: user, Source: domain.SourceTenant, Reason: "away"}); err != nil {
		t.Fatal(err)
	}
	subs, err = svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: doc.URN, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range subs.Grants {
		if sg.GrantID == g.GrantID {
			t.Fatalf("deactivated member still listed: %#v", sg)
		}
	}
}

func TestListSubjectsCanDeleteIsNotInherited(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	onFolder := mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.CanDelete})
	onDoc := mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: doc.URN, Subject: user, Relation: domain.CanDelete})

	subs, err := svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: doc.URN, Relation: domain.CanDelete})
	if err != nil {
		t.Fatal(err)
	}
	seenDoc, seenFolder := false, false
	for _, sg := range subs.Grants {
		if sg.GrantID == onDoc.GrantID {
			seenDoc = true
			if sg.Depth != 0 {
				t.Fatalf("direct can_delete depth: %#v", sg)
			}
		}
		if sg.GrantID == onFolder.GrantID {
			seenFolder = true
		}
		if sg.Relation == domain.Viewer || sg.Relation == domain.Editor || sg.Relation == domain.Commenter {
			t.Fatalf("non-owner ladder grant listed for can_delete: %#v", sg)
		}
	}
	if !seenDoc || seenFolder {
		t.Fatalf("can_delete listing: seenDoc=%v seenFolder=%v %#v", seenDoc, seenFolder, subs)
	}

	viewer, err := svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: doc.URN, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range viewer.Grants {
		if sg.Relation == domain.CanDelete {
			t.Fatalf("can_delete leaked into viewer listing: %#v", sg)
		}
	}
}

func TestReverseQueryAuthorityAndValidation(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	node := mustNode(t, svc, owner, tenant, "laenen/document/d1", "laenen/root/root")
	user := mustUser(t, tenant, "u2")
	other := mustUser(t, tenant, "u3")
	linkUser(t, svc, tenant, user)
	linkUser(t, svc, tenant, other)
	mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Viewer})

	if _, err := svc.ListObjects(ctx, ownerOf(svc, tenant, user), ListObjectsRequest{Tenant: tenant, Subject: other, Relation: domain.Viewer}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("user listed another subject: %v", err)
	}
	admin := domain.Actor{ID: "tenant-admin", Tenant: tenant, Role: domain.RoleTenantAdmin, Subject: owner.Subject}
	if objs, err := svc.ListObjects(ctx, admin, ListObjectsRequest{Tenant: tenant, Subject: user, Relation: domain.Viewer, Kind: "document"}); err != nil || len(objs.Objects) != 1 {
		t.Fatalf("tenant admin listing: %#v %v", objs, err)
	}
	auditor := domain.Actor{ID: "auditor", Tenant: tenant, Role: domain.RoleAuditor}
	if _, err := svc.ListSubjects(ctx, auditor, ListSubjectsRequest{Tenant: tenant, Object: node.URN, Relation: domain.Viewer}); err != nil {
		t.Fatalf("auditor list subjects: %v", err)
	}
	if _, err := svc.ListSubjects(ctx, ownerOf(svc, tenant, user), ListSubjectsRequest{Tenant: tenant, Object: node.URN, Relation: domain.Viewer}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-owner list subjects: %v", err)
	}
	for _, relation := range []domain.Relation{domain.Parent, domain.Member, domain.Admin, domain.Relation("nope")} {
		if _, err := svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: node.URN, Relation: relation}); !errors.Is(err, domain.ErrInvalidRelation) {
			t.Fatalf("%s: %v", relation, err)
		}
	}
	agent := domain.Subject{URN: "laenen/agent/a1", Kind: domain.SubjectAgent}
	if _, err := svc.ListObjects(ctx, admin, ListObjectsRequest{Tenant: tenant, Subject: agent, Relation: domain.Viewer}); !errors.Is(err, domain.ErrUnsupported) {
		t.Fatalf("agent subject: %v", err)
	}
}

func TestDeactivatedTenantAdminCannotReadForOthers(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	node := mustNode(t, svc, owner, tenant, "laenen/document/d1", "laenen/root/root")
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Viewer})
	admin := tenantAdmin(tenant, owner.Subject)

	if _, err := svc.DeactivatePrincipal(ctx, identityAdapter(), DeactivatePrincipalRequest{Tenant: tenant, Subject: owner.Subject, Source: domain.SourceTenant, Reason: "away"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(ctx, admin, CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("deactivated tenant admin checked another subject: %v", err)
	}
	if _, err := svc.ListObjects(ctx, admin, ListObjectsRequest{Tenant: tenant, Subject: user, Relation: domain.Viewer}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("deactivated tenant admin listed for another subject: %v", err)
	}
	if _, err := svc.AccessibleCount(ctx, admin, AccessibleCountRequest{Tenant: tenant, Subject: user, Relation: domain.Viewer}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("deactivated tenant admin counted for another subject: %v", err)
	}
}
