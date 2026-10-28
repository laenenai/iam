package projector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/engine"
	"github.com/laenenai/iam/internal/eventlog"
	"github.com/laenenai/iam/internal/projector"
)

func TestProjectNodeGrantAndDelete(t *testing.T) {
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	eng := engine.NewMemory()
	p := projector.New(log, store, eng, domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	events := []domain.Event{
		domain.NodeRegistered{URN: "t/folder/f1", Kind: "folder", CreatedBy: "a"},
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", Parent: "t/folder/f1", CreatedBy: "a"},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, Relation: domain.Viewer, GrantedBy: "a"},
		domain.NodeDeleted{URN: "t/document/d1", Reason: "test"},
	}
	appendAll(t, log, ws, events...)
	if err := p.Project(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if got := p.Applied(ws); got != 4 {
		t.Fatalf("applied=%d", got)
	}
	if _, ok := store.Node("t", "t/document/d1"); !ok {
		t.Fatal("node read model missing")
	}
	if ok, _, _ := eng.Check(context.Background(), domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, domain.Viewer, "t/document/d1"); ok {
		t.Fatal("deleted node still allows")
	}
	if err := p.Project(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := eng.Check(context.Background(), domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, domain.Viewer, "t/document/d1"); ok {
		t.Fatal("replay resurrected a deleted grant")
	}
}

func TestProjectGrantRevocationAndGroups(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	eng := engine.NewMemory()
	p := projector.New(log, store, eng, domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	user := domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}
	group := domain.Subject{URN: "t/group/g1", Kind: domain.SubjectGroup}

	appendAll(t, log, ws,
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", CreatedBy: "a"},
		domain.GroupCreated{Group: group.URN, Name: "Family", Admin: user, CreatedBy: "a"},
		domain.MemberAdded{Group: group.URN, Member: user, AddedBy: "a"},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: group, Relation: domain.Viewer, GrantedBy: "a"},
	)
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := eng.Check(ctx, user, domain.Viewer, "t/document/d1"); !ok {
		t.Fatal("group member denied")
	}
	if len(store.GroupMembers("t", group.URN)) != 1 {
		t.Fatal("member missing")
	}

	appendAll(t, log, ws, domain.MemberRemoved{Group: group.URN, Member: user, RemovedBy: "a"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := eng.Check(ctx, user, domain.Viewer, "t/document/d1"); ok {
		t.Fatal("removed member still allowed")
	}

	appendAll(t, log, ws, domain.GroupDeleted{Group: group.URN, Reason: "test"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if g, ok := store.Group("t", group.URN); !ok || g.Live {
		t.Fatalf("group still live: %#v", g)
	}
	if len(store.GroupsForAdmin("t", user)) != 0 {
		t.Fatal("deleted group still answers admin queries")
	}

	appendAll(t, log, ws, domain.NodeRegistered{URN: "t/document/d2", Kind: "document", CreatedBy: "a"},
		domain.GrantIssued{GrantID: "g2", Object: "t/document/d2", Subject: user, Relation: domain.Viewer, GrantedBy: "a"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	appendAll(t, log, ws, domain.GrantRevoked{GrantID: "g2", Object: "t/document/d2", RevokedBy: "a", Reason: "test"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if g, ok := store.Grant("t", "g2"); !ok || g.Live {
		t.Fatalf("revoked grant: %#v %v", g, ok)
	}
	if ok, _, _ := eng.Check(ctx, user, domain.Viewer, "t/document/d2"); ok {
		t.Fatal("revoked grant still allows")
	}
}

func TestProjectPrincipalLifecycle(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	eng := engine.NewMemory()
	p := projector.New(log, store, eng, domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	user := domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}
	group := domain.Subject{URN: "t/group/g1", Kind: domain.SubjectGroup}

	appendAll(t, log, ws,
		domain.PrincipalLinked{Issuer: "issuer", ExternalID: "e1", Subject: user},
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", CreatedBy: "a"},
		domain.GroupCreated{Group: group.URN, Name: "Family", Admin: user, CreatedBy: "a"},
		domain.MemberAdded{Group: group.URN, Member: user, AddedBy: "a"},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: user, Relation: domain.Viewer, GrantedBy: "a"},
	)
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if !store.Live("t", user) {
		t.Fatal("linked user not live")
	}
	if ok, _, _ := eng.Check(ctx, user, domain.Viewer, "t/document/d1"); !ok {
		t.Fatal("linked user denied")
	}

	appendAll(t, log, ws, domain.PrincipalDeactivated{Subject: user, Source: domain.SourceTenant, Reason: "away"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if store.Live("t", user) {
		t.Fatal("deactivated user still live")
	}
	if ok, _, _ := eng.Check(ctx, user, domain.Viewer, "t/document/d1"); !ok {
		t.Fatal("deactivation must leave tuples in place")
	}

	appendAll(t, log, ws,
		domain.PrincipalReactivated{Subject: user, Source: domain.SourceTenant, Reason: "back"},
		domain.PrincipalDeactivated{Subject: user, Source: domain.SourceGlobal, Reason: "left"},
		domain.PrincipalReactivated{Subject: user, Source: domain.SourceTenant, Reason: "still left"},
	)
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if store.Live("t", user) {
		t.Fatal("tenant reactivation overrode a global deactivation")
	}

	appendAll(t, log, ws, domain.PrincipalDeleted{Subject: user, Reason: "offboard"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if store.Live("t", user) {
		t.Fatal("deleted user still live")
	}
	if g, ok := store.Grant("t", "g1"); !ok || g.Live {
		t.Fatalf("direct grant survived deletion: %#v", g)
	}
	if ok, _, _ := eng.Check(ctx, user, domain.Viewer, "t/document/d1"); ok {
		t.Fatal("deleted user still allowed")
	}
	if len(store.GroupMembers("t", group.URN)) != 0 {
		t.Fatal("membership survived deletion")
	}
	if len(store.GroupsForAdmin("t", user)) != 0 {
		t.Fatal("admin edge survived deletion")
	}
	if g, ok := store.Group("t", group.URN); !ok || g.Admin.URN != "" {
		t.Fatalf("admin field not cleared: %#v", g)
	}
}

func TestProjectModelAndFutureVersion(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	eng := engine.NewMemory()
	p := projector.New(log, store, eng, domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")

	appendWithModel(t, log, eventlog.PlatformWorkspace, 1, domain.KindRegistered{Version: 1, Kind: domain.KindSpec{Name: "document", Relations: []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer}}})
	appendWithModel(t, log, eventlog.PlatformWorkspace, 1, domain.ModelPublished{Version: 1})
	appendWithModel(t, log, ws, 1, domain.NodeRegistered{URN: "t/document/d1", Kind: "document", CreatedBy: "a"})
	if err := p.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if store.ModelVersion() != 1 {
		t.Fatalf("model version=%d", store.ModelVersion())
	}
	if _, ok := store.Kind("document"); !ok {
		t.Fatal("kind not published")
	}

	appendWithModel(t, log, ws, 2, domain.NodeRegistered{URN: "t/document/d2", Kind: "document", CreatedBy: "a"})
	err := p.Project(ctx, ws)
	if !errors.Is(err, domain.ErrModelNotProjected) {
		t.Fatalf("future model: %v", err)
	}
	if p.Applied(ws) != 1 {
		t.Fatalf("failed event advanced applied position: %d", p.Applied(ws))
	}
}
