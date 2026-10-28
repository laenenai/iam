// Package iamtest is the adoption conformance suite for an IAM wiring. It
// exercises the public facade only; an adapter passes by passing this suite
// unchanged.
package iamtest

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam"
)

// RunSuite runs the adoption contract against a facade constructor.
func RunSuite(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	t.Helper()
	t.Run("TenantBootstrap", func(t *testing.T) { testTenantBootstrap(t, newIAM) })
	t.Run("Kinds", func(t *testing.T) { testKinds(t, newIAM) })
	t.Run("Nodes", func(t *testing.T) { testNodes(t, newIAM) })
	t.Run("Grants", func(t *testing.T) { testGrants(t, newIAM) })
	t.Run("Groups", func(t *testing.T) { testGroups(t, newIAM) })
	t.Run("Principals", func(t *testing.T) { testPrincipals(t, newIAM) })
	t.Run("Reverse", func(t *testing.T) { testReverse(t, newIAM) })
	t.Run("Projection", func(t *testing.T) { testProjection(t, newIAM) })
	t.Run("ReviewFocus", func(t *testing.T) { testReviewFocus(t, newIAM) })
}

type fixture struct {
	t          *testing.T
	svc        *iam.IAM
	tenant     iam.TenantID
	root       iam.URN
	owner      iam.Subject
	ownerActor iam.Actor
}

func deploymentAdmin() iam.Actor {
	return iam.Actor{ID: "deployment-admin", Role: iam.RoleDeploymentAdmin}
}

func identityAdapter() iam.Actor {
	return iam.Actor{ID: "identity-adapter", Role: iam.RoleIdentityAdapter}
}

func userActor(tenant iam.TenantID, user iam.Subject) iam.Actor {
	return iam.Actor{ID: "actor:" + string(user.URN), Tenant: tenant, Role: iam.RoleUser, Subject: user}
}

func tenantAdmin(tenant iam.TenantID, user iam.Subject) iam.Actor {
	return iam.Actor{ID: "tenant-admin", Tenant: tenant, Role: iam.RoleTenantAdmin, Subject: user}
}

func auditor(tenant iam.TenantID) iam.Actor {
	return iam.Actor{ID: "auditor", Tenant: tenant, Role: iam.RoleAuditor}
}

func mustUser(t *testing.T, tenant iam.TenantID, id string) iam.Subject {
	t.Helper()
	user, err := iam.NewUserSubject(tenant, id)
	if err != nil {
		t.Fatalf("user %s/%s: %v", tenant, id, err)
	}
	return user
}

func link(t *testing.T, svc *iam.IAM, tenant iam.TenantID, issuer, externalID string, subject iam.Subject) {
	t.Helper()
	if _, err := svc.LinkPrincipal(context.Background(), identityAdapter(), iam.LinkPrincipalRequest{
		Tenant:     tenant,
		Issuer:     issuer,
		ExternalID: externalID,
		Subject:    subject,
	}); err != nil {
		t.Fatalf("link %s: %v", subject.URN, err)
	}
}

func newFixture(t *testing.T, newIAM func(t *testing.T) *iam.IAM) *fixture {
	t.Helper()
	svc := newIAM(t)
	tenant := iam.TenantID("t")
	owner := mustUser(t, tenant, "u1")
	created, err := svc.CreateTenant(context.Background(), deploymentAdmin(), iam.CreateTenantRequest{
		Tenant:     tenant,
		RootID:     "root",
		FirstOwner: owner,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	link(t, svc, tenant, "issuer", "external-u1", owner)
	return &fixture{t: t, svc: svc, tenant: tenant, root: created.Root, owner: owner, ownerActor: userActor(tenant, owner)}
}

func (f *fixture) node(actor iam.Actor, urn, parent iam.URN) iam.Node {
	f.t.Helper()
	result, err := f.svc.RegisterNode(context.Background(), actor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: urn, Parent: parent})
	if err != nil {
		f.t.Fatalf("register %s: %v", urn, err)
	}
	return result.Node
}

func (f *fixture) grant(actor iam.Actor, object iam.URN, subject iam.Subject, relation iam.Relation) iam.GrantResult {
	f.t.Helper()
	result, err := f.svc.Grant(context.Background(), actor, iam.GrantRequest{Tenant: f.tenant, Object: object, Subject: subject, Relation: relation})
	if err != nil {
		f.t.Fatalf("grant %s on %s: %v", relation, object, err)
	}
	return result
}

func (f *fixture) check(actor iam.Actor, subject iam.Subject, object iam.URN, relation iam.Relation) iam.Decision {
	f.t.Helper()
	decision, err := f.svc.Check(context.Background(), actor, iam.CheckRequest{Tenant: f.tenant, Subject: subject, Object: object, Relation: relation})
	if err != nil {
		f.t.Fatalf("check %s on %s: %v", relation, object, err)
	}
	return decision
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("err=%v want %v", err, target)
	}
}

func testTenantBootstrap(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	if f.root != "t/root/root" {
		t.Fatalf("root=%s", f.root)
	}
	if d := f.check(f.ownerActor, f.owner, f.root, iam.Owner); !d.Allowed || d.Revision == 0 {
		t.Fatalf("owner check: %#v", d)
	}
	_, err := f.svc.CreateTenant(context.Background(), deploymentAdmin(), iam.CreateTenantRequest{Tenant: f.tenant, RootID: "root", FirstOwner: f.owner})
	wantErr(t, err, iam.ErrConflict)
	_, err = f.svc.CreateTenant(context.Background(), deploymentAdmin(), iam.CreateTenantRequest{Tenant: f.tenant, RootID: "other", FirstOwner: f.owner})
	wantErr(t, err, iam.ErrConflict)
	_, err = f.svc.CreateTenant(context.Background(), f.ownerActor, iam.CreateTenantRequest{Tenant: "x", RootID: "root", FirstOwner: mustUser(t, "x", "u1")})
	wantErr(t, err, iam.ErrForbidden)
}

func testKinds(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	names := make(map[string]bool)
	for _, kind := range iam.DefaultKinds() {
		names[kind.Name] = true
	}
	for _, name := range []string{iam.RootKind, "folder", "document", "album", "photo", "space", "message"} {
		if !names[name] {
			t.Fatalf("default kind %s missing", name)
		}
	}
	graph := iam.KindSpec{Name: "graph", Relations: []iam.Relation{iam.Owner, iam.Editor, iam.Commenter, iam.Viewer}}
	if err := f.svc.RegisterKind(context.Background(), deploymentAdmin(), iam.RegisterKindRequest{Kind: graph}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.PublishModel(context.Background(), deploymentAdmin(), iam.PublishModelRequest{Version: 2}); err != nil {
		t.Fatal(err)
	}
	g := f.node(f.ownerActor, "t/graph/g1", f.root)
	_, err := f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: "t/graph/g2", Parent: g.URN})
	wantErr(t, err, iam.ErrInvalidKind)
	err = f.svc.RegisterKind(context.Background(), deploymentAdmin(), iam.RegisterKindRequest{Kind: graph})
	wantErr(t, err, iam.ErrConflict)
	err = f.svc.RegisterKind(context.Background(), deploymentAdmin(), iam.RegisterKindRequest{Kind: iam.KindSpec{Name: iam.RootKind, ContainsAny: true}})
	wantErr(t, err, iam.ErrInvalidKind)
	err = f.svc.RegisterKind(context.Background(), deploymentAdmin(), iam.RegisterKindRequest{Kind: iam.KindSpec{Name: "bad", Relations: []iam.Relation{iam.CanShare}}})
	wantErr(t, err, iam.ErrInvalidKind)
	err = f.svc.PublishModel(context.Background(), deploymentAdmin(), iam.PublishModelRequest{Version: 2})
	wantErr(t, err, iam.ErrConflict)
}

func testNodes(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	folder := f.node(f.ownerActor, "t/folder/home", f.root)
	doc := f.node(f.ownerActor, "t/document/tax", folder.URN)
	if d := f.check(f.ownerActor, f.owner, doc.URN, iam.Owner); !d.Allowed {
		t.Fatal("creator is not owner")
	}
	_, err := f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: folder.URN, Parent: f.root})
	wantErr(t, err, iam.ErrConflict)
	_, err = f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: "t/root/other", Parent: f.root})
	wantErr(t, err, iam.ErrForbidden)

	otherOwner := mustUser(t, "other", "u1")
	_, err = f.svc.CreateTenant(context.Background(), deploymentAdmin(), iam.CreateTenantRequest{Tenant: "other", RootID: "root", FirstOwner: otherOwner})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: "t/document/cross", Parent: "other/root/root"})
	if err == nil {
		t.Fatal("cross-tenant parent accepted")
	}

	err = f.svc.DeleteNode(context.Background(), f.ownerActor, iam.DeleteNodeRequest{Tenant: f.tenant, URN: folder.URN})
	wantErr(t, err, iam.ErrConflict)
	if err := f.svc.DeleteNode(context.Background(), f.ownerActor, iam.DeleteNodeRequest{Tenant: f.tenant, URN: doc.URN}); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: doc.URN, Parent: folder.URN})
	wantErr(t, err, iam.ErrConflict)

	second := f.node(f.ownerActor, "t/folder/second", f.root)
	child := f.node(f.ownerActor, "t/document/second", second.URN)
	outsider := mustUser(t, f.tenant, "u2")
	link(t, f.svc, f.tenant, "issuer", "external-u2", outsider)
	err = f.svc.DeleteSubtree(context.Background(), userActor(f.tenant, outsider), iam.DeleteSubtreeRequest{Tenant: f.tenant, URN: second.URN})
	wantErr(t, err, iam.ErrForbidden)
	if err := f.svc.DeleteSubtree(context.Background(), f.ownerActor, iam.DeleteSubtreeRequest{Tenant: f.tenant, URN: second.URN}); err != nil {
		t.Fatal(err)
	}
	for _, urn := range []iam.URN{second.URN, child.URN} {
		if d := f.check(f.ownerActor, f.owner, urn, iam.Viewer); d.Allowed {
			t.Fatalf("%s survived subtree delete", urn)
		}
	}
}

func testGrants(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	folder := f.node(f.ownerActor, "t/folder/home", f.root)
	doc := f.node(f.ownerActor, "t/document/tax", folder.URN)
	user := mustUser(t, f.tenant, "u2")
	link(t, f.svc, f.tenant, "issuer", "external-u2", user)
	act := userActor(f.tenant, user)

	f.grant(f.ownerActor, folder.URN, user, iam.Viewer)
	if d := f.check(act, user, doc.URN, iam.Viewer); !d.Allowed || d.Reason != iam.ReasonInherited {
		t.Fatalf("inherited: %#v", d)
	}
	if d := f.check(act, user, doc.URN, iam.CanView); !d.Allowed {
		t.Fatal("can_view denied")
	}
	if d := f.check(act, user, doc.URN, iam.CanEdit); d.Allowed {
		t.Fatal("can_edit allowed for a viewer")
	}
	_, err := f.svc.Grant(context.Background(), f.ownerActor, iam.GrantRequest{Tenant: f.tenant, Object: folder.URN, Subject: user, Relation: iam.Viewer})
	wantErr(t, err, iam.ErrConflict)
	agent := iam.Subject{URN: "t/agent/a1", Kind: iam.SubjectAgent}
	_, err = f.svc.Grant(context.Background(), f.ownerActor, iam.GrantRequest{Tenant: f.tenant, Object: doc.URN, Subject: agent, Relation: iam.Owner})
	wantErr(t, err, iam.ErrUnsupported)
	_, err = f.svc.Grant(context.Background(), f.ownerActor, iam.GrantRequest{Tenant: f.tenant, Object: doc.URN, Subject: user, Relation: iam.CanShare})
	wantErr(t, err, iam.ErrInvalidRelation)
	_, err = f.svc.Grant(context.Background(), f.ownerActor, iam.GrantRequest{Tenant: f.tenant, Object: doc.URN, Subject: user, Relation: iam.CanView})
	wantErr(t, err, iam.ErrInvalidRelation)

	folderDelete := f.grant(f.ownerActor, folder.URN, user, iam.CanDelete)
	if d := f.check(act, user, doc.URN, iam.CanDelete); d.Allowed {
		t.Fatal("can_delete inherited")
	}
	_, err = f.svc.Grant(context.Background(), act, iam.GrantRequest{Tenant: f.tenant, Object: doc.URN, Subject: user, Relation: iam.CanDelete})
	wantErr(t, err, iam.ErrForbidden)
	f.grant(f.ownerActor, doc.URN, user, iam.CanDelete)
	if d := f.check(act, user, doc.URN, iam.CanDelete); !d.Allowed {
		t.Fatal("direct can_delete denied")
	}
	if _, err := f.svc.Revoke(context.Background(), f.ownerActor, iam.RevokeRequest{Tenant: f.tenant, GrantID: folderDelete.GrantID}); err != nil {
		t.Fatal(err)
	}
}

func testGroups(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	u2 := mustUser(t, f.tenant, "u2")
	u3 := mustUser(t, f.tenant, "u3")
	u4 := mustUser(t, f.tenant, "u4")
	for i, user := range []iam.Subject{u2, u3, u4} {
		link(t, f.svc, f.tenant, "issuer", string(rune('2'+i)), user)
	}
	group, err := f.svc.CreateGroup(context.Background(), f.ownerActor, iam.CreateGroupRequest{Tenant: f.tenant, GroupID: "g1", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AddGroupMember(context.Background(), f.ownerActor, iam.AddGroupMemberRequest{Tenant: f.tenant, Group: group.Group.URN, Member: u2}); err != nil {
		t.Fatal(err)
	}
	node := f.node(f.ownerActor, "t/document/shared", f.root)
	f.grant(f.ownerActor, node.URN, iam.Subject{URN: group.Group.URN, Kind: iam.SubjectGroup}, iam.Viewer)
	if d := f.check(userActor(f.tenant, u2), u2, node.URN, iam.Viewer); !d.Allowed {
		t.Fatal("group member denied")
	}
	if _, err := f.svc.RemoveGroupMember(context.Background(), f.ownerActor, iam.RemoveGroupMemberRequest{Tenant: f.tenant, Group: group.Group.URN, Member: u2}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(userActor(f.tenant, u2), u2, node.URN, iam.Viewer); d.Allowed {
		t.Fatal("removed member allowed")
	}
	if _, err := f.svc.SetGroupAdmin(context.Background(), f.ownerActor, iam.SetGroupAdminRequest{Tenant: f.tenant, Group: group.Group.URN, Admin: u2}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AddGroupMember(context.Background(), userActor(f.tenant, u2), iam.AddGroupMemberRequest{Tenant: f.tenant, Group: group.Group.URN, Member: u3}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AddGroupMember(context.Background(), userActor(f.tenant, u4), iam.AddGroupMemberRequest{Tenant: f.tenant, Group: group.Group.URN, Member: u4}); !errors.Is(err, iam.ErrForbidden) {
		t.Fatalf("non-admin add: %v", err)
	}
	if _, err := f.svc.DeleteGroup(context.Background(), tenantAdmin(f.tenant, f.owner), iam.DeleteGroupRequest{Tenant: f.tenant, Group: group.Group.URN}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(userActor(f.tenant, u3), u3, node.URN, iam.Viewer); d.Allowed {
		t.Fatal("deleted group grant allowed")
	}
	_, err = f.svc.CreateGroup(context.Background(), f.ownerActor, iam.CreateGroupRequest{Tenant: f.tenant, GroupID: "g1", Name: "Again"})
	wantErr(t, err, iam.ErrConflict)
}

func testPrincipals(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	svc := newIAM(t)
	owners := make(map[iam.TenantID]iam.Subject)
	for _, tenant := range []iam.TenantID{"a", "b", "c"} {
		owner := mustUser(t, tenant, "u1")
		owners[tenant] = owner
		_, err := svc.CreateTenant(context.Background(), deploymentAdmin(), iam.CreateTenantRequest{Tenant: tenant, RootID: "root", FirstOwner: owner})
		if err != nil {
			t.Fatal(err)
		}
	}
	link(t, svc, "a", "issuer", "external-shared", owners["a"])
	link(t, svc, "b", "issuer", "external-shared", owners["b"])
	if _, err := svc.DeactivatePrincipal(context.Background(), identityAdapter(), iam.DeactivatePrincipalRequest{Tenant: "a", Subject: owners["a"], Source: iam.SourceGlobal}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []iam.TenantID{"a", "b"} {
		d, err := svc.Check(context.Background(), userActor(tenant, owners[tenant]), iam.CheckRequest{Tenant: tenant, Subject: owners[tenant], Object: iam.URN(tenant.String() + "/root/root"), Relation: iam.Owner})
		if err != nil || d.Allowed {
			t.Fatalf("%s global deactivation: %#v %v", tenant, d, err)
		}
	}
	if _, err := svc.ReactivatePrincipal(context.Background(), identityAdapter(), iam.ReactivatePrincipalRequest{Tenant: "a", Subject: owners["a"], Source: iam.SourceTenant}); err != nil {
		t.Fatal(err)
	}
	d, _ := svc.Check(context.Background(), userActor("a", owners["a"]), iam.CheckRequest{Tenant: "a", Subject: owners["a"], Object: "a/root/root", Relation: iam.Owner})
	if d.Allowed {
		t.Fatal("tenant reactivation overrode global")
	}
	link(t, svc, "c", "issuer", "external-shared", owners["c"])
	d, _ = svc.Check(context.Background(), userActor("c", owners["c"]), iam.CheckRequest{Tenant: "c", Subject: owners["c"], Object: "c/root/root", Relation: iam.Owner})
	if d.Allowed {
		t.Fatal("late link started live")
	}
	if _, err := svc.ReactivatePrincipal(context.Background(), identityAdapter(), iam.ReactivatePrincipalRequest{Tenant: "a", Subject: owners["a"], Source: iam.SourceGlobal}); err != nil {
		t.Fatal(err)
	}
	d, _ = svc.Check(context.Background(), userActor("a", owners["a"]), iam.CheckRequest{Tenant: "a", Subject: owners["a"], Object: "a/root/root", Relation: iam.Owner})
	if !d.Allowed {
		t.Fatal("global reactivation did not restore")
	}

	f := newFixture(t, newIAM)
	user := mustUser(t, f.tenant, "u2")
	link(t, f.svc, f.tenant, "issuer", "external-delete", user)
	group, err := f.svc.CreateGroup(context.Background(), userActor(f.tenant, user), iam.CreateGroupRequest{Tenant: f.tenant, GroupID: "g1", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AddGroupMember(context.Background(), userActor(f.tenant, user), iam.AddGroupMemberRequest{Tenant: f.tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	node := f.node(f.ownerActor, "t/document/d1", f.root)
	grant := f.grant(f.ownerActor, node.URN, user, iam.Viewer)
	if _, err := f.svc.DeletePrincipal(context.Background(), tenantAdmin(f.tenant, f.owner), iam.DeletePrincipalRequest{Tenant: f.tenant, Subject: user}); !errors.Is(err, iam.ErrForbidden) {
		t.Fatalf("tenant admin delete: %v", err)
	}
	if _, err := f.svc.DeletePrincipal(context.Background(), identityAdapter(), iam.DeletePrincipalRequest{Tenant: f.tenant, Subject: user}); err != nil {
		t.Fatal(err)
	}
	d, _ = f.svc.Check(context.Background(), userActor(f.tenant, user), iam.CheckRequest{Tenant: f.tenant, Subject: user, Object: node.URN, Relation: iam.Viewer})
	if d.Allowed {
		t.Fatal("deleted principal allowed")
	}
	_ = grant
	_, err = f.svc.LinkPrincipal(context.Background(), identityAdapter(), iam.LinkPrincipalRequest{Tenant: f.tenant, Issuer: "issuer", ExternalID: "external-delete", Subject: user})
	wantErr(t, err, iam.ErrConflict)
	fresh := mustUser(t, f.tenant, "u3")
	if _, err := f.svc.LinkPrincipal(context.Background(), identityAdapter(), iam.LinkPrincipalRequest{Tenant: f.tenant, Issuer: "issuer", ExternalID: "external-delete", Subject: fresh}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.LinkPrincipal(context.Background(), f.ownerActor, iam.LinkPrincipalRequest{Tenant: f.tenant, Issuer: "issuer", ExternalID: "x", Subject: fresh}); !errors.Is(err, iam.ErrForbidden) {
		t.Fatalf("user link: %v", err)
	}
}

func testReverse(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	folder := f.node(f.ownerActor, "t/folder/home", f.root)
	doc := f.node(f.ownerActor, "t/document/tax", folder.URN)
	user := mustUser(t, f.tenant, "u2")
	link(t, f.svc, f.tenant, "issuer", "external-u2", user)
	grant := f.grant(f.ownerActor, folder.URN, user, iam.Viewer)
	act := userActor(f.tenant, user)
	objects, err := f.svc.ListObjects(context.Background(), act, iam.ListObjectsRequest{Tenant: f.tenant, Subject: user, Relation: iam.Viewer, Kind: "document"})
	if err != nil || len(objects.Objects) != 1 || objects.Objects[0] != doc.URN {
		t.Fatalf("list objects: %#v %v", objects, err)
	}
	count, err := f.svc.AccessibleCount(context.Background(), act, iam.AccessibleCountRequest{Tenant: f.tenant, Subject: user, Relation: iam.Viewer, Kind: "document"})
	if err != nil || count.Count != 1 {
		t.Fatalf("count: %#v %v", count, err)
	}
	subjects, err := f.svc.ListSubjects(context.Background(), f.ownerActor, iam.ListSubjectsRequest{Tenant: f.tenant, Object: doc.URN, Relation: iam.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range subjects.Grants {
		if entry.GrantID == grant.GrantID {
			found = true
			if entry.Subject != user || entry.Object != folder.URN || entry.Depth != 1 || entry.GrantedBy == "" {
				t.Fatalf("provenance: %#v", entry)
			}
		}
	}
	if !found {
		t.Fatalf("contributing grant missing: %#v", subjects)
	}
	if _, err := f.svc.ListSubjects(context.Background(), act, iam.ListSubjectsRequest{Tenant: f.tenant, Object: doc.URN, Relation: iam.Viewer}); !errors.Is(err, iam.ErrForbidden) {
		t.Fatalf("non-owner list subjects: %v", err)
	}
	if _, err := f.svc.ListSubjects(context.Background(), auditor(f.tenant), iam.ListSubjectsRequest{Tenant: f.tenant, Object: doc.URN, Relation: iam.Viewer}); err != nil {
		t.Fatalf("auditor list subjects: %v", err)
	}
	if _, err := f.svc.ListSubjects(context.Background(), f.ownerActor, iam.ListSubjectsRequest{Tenant: f.tenant, Object: doc.URN, Relation: iam.Parent}); !errors.Is(err, iam.ErrInvalidRelation) {
		t.Fatalf("parent relation: %v", err)
	}
}

func testProjection(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	node := f.node(f.ownerActor, "t/document/d1", f.root)
	user := mustUser(t, f.tenant, "u2")
	link(t, f.svc, f.tenant, "issuer", "external-u2", user)
	act := userActor(f.tenant, user)
	grant := f.grant(f.ownerActor, node.URN, user, iam.Viewer)
	if d := f.check(act, user, node.URN, iam.Viewer); !d.Allowed {
		t.Fatal("grant not projected")
	}
	revoked, err := f.svc.Revoke(context.Background(), f.ownerActor, iam.RevokeRequest{Tenant: f.tenant, GrantID: grant.GrantID})
	if err != nil {
		t.Fatal(err)
	}
	if revoked <= grant.Revision {
		t.Fatalf("revision did not advance: %d then %d", grant.Revision, revoked)
	}
	for i := 0; i < 2; i++ {
		if d := f.check(act, user, node.URN, iam.Viewer); d.Allowed {
			t.Fatal("revoked grant allowed")
		}
	}
	regrant := f.grant(f.ownerActor, node.URN, user, iam.Viewer)
	if regrant.Revision <= revoked {
		t.Fatal("re-grant revision did not advance")
	}
	if err := f.svc.DeleteNode(context.Background(), f.ownerActor, iam.DeleteNodeRequest{Tenant: f.tenant, URN: node.URN}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if d := f.check(act, user, node.URN, iam.Viewer); d.Allowed {
			t.Fatal("deleted node allowed")
		}
	}
	objects, err := f.svc.ListObjects(context.Background(), act, iam.ListObjectsRequest{Tenant: f.tenant, Subject: user, Relation: iam.Viewer, Kind: "document"})
	if err != nil || len(objects.Objects) != 0 {
		t.Fatalf("deleted node listed: %#v %v", objects, err)
	}
}

func testReviewFocus(t *testing.T, newIAM func(t *testing.T) *iam.IAM) {
	f := newFixture(t, newIAM)
	folder := f.node(f.ownerActor, "t/folder/home", f.root)
	doc := f.node(f.ownerActor, "t/document/tax", folder.URN)
	user := mustUser(t, f.tenant, "u2")
	link(t, f.svc, f.tenant, "issuer", "external-u2", user)
	act := userActor(f.tenant, user)
	f.grant(f.ownerActor, doc.URN, user, iam.Viewer)
	group, err := f.svc.CreateGroup(context.Background(), f.ownerActor, iam.CreateGroupRequest{Tenant: f.tenant, GroupID: "g1", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AddGroupMember(context.Background(), f.ownerActor, iam.AddGroupMemberRequest{Tenant: f.tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	f.grant(f.ownerActor, doc.URN, iam.Subject{URN: group.Group.URN, Kind: iam.SubjectGroup}, iam.Viewer)
	f.grant(f.ownerActor, folder.URN, user, iam.Viewer)

	admin := tenantAdmin(f.tenant, f.owner)
	if _, err := f.svc.DeactivatePrincipal(context.Background(), admin, iam.DeactivatePrincipalRequest{Tenant: f.tenant, Subject: user, Source: iam.SourceTenant}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(act, user, doc.URN, iam.Viewer); d.Allowed {
		t.Fatal("deactivation left an arm open")
	}
	if _, err := f.svc.ReactivatePrincipal(context.Background(), admin, iam.ReactivatePrincipalRequest{Tenant: f.tenant, Subject: user, Source: iam.SourceTenant}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(act, user, doc.URN, iam.Viewer); !d.Allowed {
		t.Fatal("reactivation did not restore")
	}

	deleteGrant := f.grant(f.ownerActor, folder.URN, user, iam.CanDelete)
	if d := f.check(act, user, doc.URN, iam.CanDelete); d.Allowed {
		t.Fatal("can_delete inherited")
	}
	_, err = f.svc.Grant(context.Background(), act, iam.GrantRequest{Tenant: f.tenant, Object: doc.URN, Subject: user, Relation: iam.CanDelete})
	wantErr(t, err, iam.ErrForbidden)
	_, err = f.svc.Grant(context.Background(), f.ownerActor, iam.GrantRequest{Tenant: f.tenant, Object: doc.URN, Subject: user, Relation: iam.CanShare})
	wantErr(t, err, iam.ErrInvalidRelation)
	_ = deleteGrant

	_, err = f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: "t/root/other", Parent: folder.URN})
	wantErr(t, err, iam.ErrForbidden)
	_, err = f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: folder.URN, Parent: f.root})
	wantErr(t, err, iam.ErrConflict)

	if err := f.svc.DeleteNode(context.Background(), f.ownerActor, iam.DeleteNodeRequest{Tenant: f.tenant, URN: doc.URN}); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RegisterNode(context.Background(), f.ownerActor, iam.RegisterNodeRequest{Tenant: f.tenant, URN: doc.URN, Parent: folder.URN})
	wantErr(t, err, iam.ErrConflict)
	if _, err := f.svc.DeleteGroup(context.Background(), admin, iam.DeleteGroupRequest{Tenant: f.tenant, Group: group.Group.URN}); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.CreateGroup(context.Background(), f.ownerActor, iam.CreateGroupRequest{Tenant: f.tenant, GroupID: "g1", Name: "Again"})
	wantErr(t, err, iam.ErrConflict)
}
