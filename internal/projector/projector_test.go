package projector_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

type flakyEngine struct {
	base        engine.Engine
	failDeletes int
}

func (f *flakyEngine) Write(ctx context.Context, tuples ...engine.Tuple) error {
	return f.base.Write(ctx, tuples...)
}

func (f *flakyEngine) Delete(ctx context.Context, tuples ...engine.Tuple) error {
	if f.failDeletes > 0 {
		f.failDeletes--
		return errors.New("injected delete failure")
	}
	return f.base.Delete(ctx, tuples...)
}

func (f *flakyEngine) Check(ctx context.Context, subject domain.Subject, relation domain.Relation, object domain.URN) (bool, domain.Reason, error) {
	return f.base.Check(ctx, subject, relation, object)
}

func TestGroupDeletedRetryCleansAccessAfterEngineFailure(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	base := engine.NewMemory()
	flaky := &flakyEngine{base: base, failDeletes: 2}
	p := projector.New(log, store, flaky, domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	user := domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}
	group := domain.Subject{URN: "t/group/g1", Kind: domain.SubjectGroup}

	appendAll(t, log, ws,
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", CreatedBy: "a"},
		domain.GroupCreated{Group: group.URN, Name: "Family", Admin: user, CreatedBy: "a"},
		domain.MemberAdded{Group: group.URN, Member: user, AddedBy: "a"},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: group, Relation: domain.Viewer, GrantedBy: "a"},
		domain.GroupDeleted{Group: group.URN, Reason: "test"},
	)
	if err := p.Project(ctx, ws); err == nil {
		t.Fatal("expected the injected engine failure")
	}
	var err error
	for i := 0; i < 3; i++ {
		if err = p.Project(ctx, ws); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("retries: %v", err)
	}
	if ok, _, _ := base.Check(ctx, user, domain.Viewer, "t/document/d1"); ok {
		t.Fatal("retry left deleted-group access open")
	}
	if members := store.GroupMembers("t", group.URN); len(members) != 0 {
		t.Fatalf("retry left members: %#v", members)
	}
}

func TestReplayFromZeroReproducesReadModel(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	user := domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}
	group := domain.Subject{URN: "t/group/g1", Kind: domain.SubjectGroup}
	appendAll(t, log, ws,
		domain.NodeRegistered{URN: "t/folder/f1", Kind: "folder", CreatedBy: "a"},
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", Parent: "t/folder/f1", CreatedBy: "a"},
		domain.GroupCreated{Group: group.URN, Name: "Family", Admin: user, CreatedBy: "a"},
		domain.MemberAdded{Group: group.URN, Member: user, AddedBy: "a"},
		domain.MemberRemoved{Group: group.URN, Member: user, RemovedBy: "a"},
		domain.PrincipalLinked{Issuer: "issuer", ExternalID: "e1", Subject: user},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: user, Relation: domain.Viewer, GrantedBy: "a"},
		domain.GrantIssued{GrantID: "g2", Object: "t/document/d1", Subject: group, Relation: domain.Editor, GrantedBy: "a"},
		domain.GrantRevoked{GrantID: "g2", Object: "t/document/d1", RevokedBy: "a"},
	)

	firstStore := projector.NewMemoryStore()
	firstEngine := engine.NewMemory()
	first := projector.New(log, firstStore, firstEngine, domain.FixedClock{})
	if err := first.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}

	var later domain.FixedClock
	later.Advance(48 * time.Hour)
	secondStore := projector.NewMemoryStore()
	secondEngine := engine.NewMemory()
	second := projector.New(log, secondStore, secondEngine, later)
	if err := second.Project(ctx, ws); err != nil {
		t.Fatal(err)
	}

	firstNode, _ := firstStore.Node("t", "t/document/d1")
	secondNode, _ := secondStore.Node("t", "t/document/d1")
	if !firstNode.CreatedAt.Equal(secondNode.CreatedAt) {
		t.Fatalf("node timestamp drifted: %v vs %v", firstNode.CreatedAt, secondNode.CreatedAt)
	}
	firstGrant, _ := firstStore.Grant("t", "g1")
	secondGrant, _ := secondStore.Grant("t", "g1")
	if !firstGrant.GrantedAt.Equal(secondGrant.GrantedAt) {
		t.Fatalf("grant timestamp drifted: %v vs %v", firstGrant.GrantedAt, secondGrant.GrantedAt)
	}
	firstGroup, _ := firstStore.Group("t", group.URN)
	secondGroup, _ := secondStore.Group("t", group.URN)
	if !firstGroup.CreatedAt.Equal(secondGroup.CreatedAt) {
		t.Fatalf("group timestamp drifted: %v vs %v", firstGroup.CreatedAt, secondGroup.CreatedAt)
	}
	firstPrincipal, _ := firstStore.Principal("t", user)
	secondPrincipal, _ := secondStore.Principal("t", user)
	if !firstPrincipal.LinkedAt.Equal(secondPrincipal.LinkedAt) {
		t.Fatalf("principal timestamp drifted: %v vs %v", firstPrincipal.LinkedAt, secondPrincipal.LinkedAt)
	}
	for _, store := range []projector.Store{firstStore, secondStore} {
		if node, ok := store.Node("t", "t/document/d1"); !ok || !node.Live {
			t.Fatalf("node: %#v %v", node, ok)
		}
		if grant, ok := store.Grant("t", "g1"); !ok || !grant.Live {
			t.Fatalf("grant: %#v %v", grant, ok)
		}
		if grant, ok := store.Grant("t", "g2"); !ok || grant.Live {
			t.Fatalf("revoked grant: %#v %v", grant, ok)
		}
		if members := store.GroupMembers("t", group.URN); len(members) != 0 {
			t.Fatalf("members: %#v", members)
		}
	}
	firstOK, _, _ := firstEngine.Check(ctx, user, domain.Viewer, "t/document/d1")
	secondOK, _, _ := secondEngine.Check(ctx, user, domain.Viewer, "t/document/d1")
	if firstOK != secondOK || !firstOK {
		t.Fatalf("engine drift: %v vs %v", firstOK, secondOK)
	}
}

func TestProjectorRejectsTenantWorkspaceMismatch(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	p := projector.New(log, store, engine.NewMemory(), domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	appendAll(t, log, ws, domain.NodeRegistered{URN: "other/document/d1", Kind: "document", CreatedBy: "a"})
	err := p.Project(ctx, ws)
	if !errors.Is(err, domain.ErrInvalidURN) {
		t.Fatalf("wrong workspace: %v", err)
	}
	if p.Applied(ws) != 0 {
		t.Fatalf("invalid event advanced applied: %d", p.Applied(ws))
	}
}

func TestProjectorRejectsCrossTenantEdge(t *testing.T) {
	ctx := context.Background()
	log := eventlog.NewMemory(domain.FixedClock{})
	store := projector.NewMemoryStore()
	p := projector.New(log, store, engine.NewMemory(), domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	appendAll(t, log, ws,
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", CreatedBy: "a"},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: domain.Subject{URN: "other/user/u1", Kind: domain.SubjectUser}, Relation: domain.Viewer, GrantedBy: "a"},
	)
	err := p.Project(ctx, ws)
	if !errors.Is(err, domain.ErrInvalidURN) {
		t.Fatalf("cross-tenant grant: %v", err)
	}
	if p.Applied(ws) != 1 {
		t.Fatalf("invalid event advanced applied: %d", p.Applied(ws))
	}
}
