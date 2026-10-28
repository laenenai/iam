# Central IAM Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working in-memory implementation of the rewritten `iam` core: tenants, one root, kinds, nodes, grants, groups, user principals, the event log record, a projector, a reference engine, checks, reverse queries, the public facade and the conformance suite.

**Architecture:** Commands validate against the published kind model and the actor's authority, then append typed events to the event log. A projector applies each event to an in-memory read model and a relation-tuple engine. Checks apply the live-subject and live-node filters, then evaluate the default owner/editor/commenter/viewer model plus the non-inheriting `can_delete` relation.

**Tech Stack:** Go 1.26.5, standard library, `github.com/oklog/ulid/v2` for grant ids, `gofumpt`, `golangci-lint`, `mise`.

**Spec:** `docs/superpowers/specs/2026-10-27-central-iam-design.md`

**Plan split:** This is plan 1 of 5. Plan 2 adds agents, supervision, maturity, delegation, HITL and `AuthorizeAction`. Plan 3 adds es-lite, the `Sealer`/OpenBao, Postgres read models, the OpenFGA projector, consistency and rebuild. Plan 4 adds the CAS SQL join. Plan 5 adds the Connect-Go service, tenant service credentials and deployment.

## Global Constraints

- `go 1.26.5`; `CGO_ENABLED=0`; no new dependency except `github.com/oklog/ulid/v2 v2.1.2`.
- URNs are `<tenant>/<kind>/<id>`; tenant, kind and id match `[a-z0-9][a-z0-9_-]{0,127}`. Subjects use `<tenant>/user/<id>`, `<tenant>/agent/<id>` or `<tenant>/group/<id>`.
- Exactly one root per tenant, kind `root`, created only by `CreateTenant`. Every other node has exactly one live parent in the same tenant.
- The default relation ladder is `owner > editor > commenter > viewer`, ranked 4/3/2/1. `can_delete` is the one global relation, rank 0, does not inherit, and only an owner may grant it.
- `can_share` is `owner`; agents never hold it. Plan 1 refuses agent subjects and agent principals with `ErrUnsupported`; plan 2 removes that refusal.
- The event log is the record. Nothing writes the engine outside the projector.
- Every read filters through the live-subject and live-node projections. A deactivated, suspended or deleted subject denies through direct, group and inherited grants alike.
- A deleted node or group URN is retired and cannot be re-registered or re-created.
- No deny mechanism, no classification, no read-time attributes, no `fmt.Print*`, no `panic`.
- Public API changes are a reviewed diff against `api.txt`. The facade carries aliases and constructors only; logic lives in `internal/`.
- Out of scope for this plan: agents, supervision, HITL, durable adapters, sealing, Postgres, OpenFGA, CAS, the service and deployment, audit/point-in-time/rebuild.

## Review Focus

- A deactivated or deleted live user must stop matching through a direct grant, a group membership and an inherited grant, and must resume only when the same principal is reactivated.
- A `can_delete` grant must never inherit and must never be accepted from a non-owner; `can_share` must never be granted directly.
- A second parent, a cross-tenant parent, or a root child of a non-root kind must be refused before any event is appended.
- A deleted node or group URN must not be reusable, even though the log keeps its history.
- Replaying the log a second time must produce the same read model and engine state, including deletions and revocations.

---

### Task 1: Module floor and old-surface removal

**Files:**
- Modify: `go.mod`, `mise.toml`
- Delete: `iam.go`, `api.txt`, `api_test.go`, `sqlc.yaml`, `db/`, `examples/`, `iamtest/`, `internal/`
- Create: `doc.go`

**Interfaces:**
- Consumes: nothing.
- Produces: an empty root package `iam`, a Go 1.26.5 module, and mise tasks `fmt`, `fmt-check`, `lint`, `test`, `build`, `test-all`, `api`, `check`.

- [ ] **Step 1: Delete the old API and adapters**

Remove the files and directories listed above. Keep `docs/`, `.github/`, `.golangci.yml`, `LICENSE`, `SECURITY.md`, `README.md`, `CHARTER.md`, `.gitignore`; `README.md` and `CHARTER.md` are rewritten in Task 13.

- [ ] **Step 2: Create the root package placeholder**

```go
// Package iam is a central identity-and-authorization library built on an
// event-sourced grant log. See docs/superpowers/specs/2026-10-27-central-iam-design.md.
package iam
```

- [ ] **Step 3: Set the module floor**

In `go.mod`, set `go 1.26.5`. In `mise.toml`, set `go = "1.26.5"`, remove the `sqlc` tool and the `generate` task, and keep the `fmt`, `fmt-check`, `lint`, `test`, `build`, `test-all`, `api` and `check` tasks.

- [ ] **Step 4: Verify the clean floor**

Run: `go mod tidy && go build ./... && go test ./...`
Expected: all three pass; `go.mod` has no unused requirement.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: clear the old iam surface for the central rewrite"
```

---

### Task 2: Domain primitives

**Files:**
- Create: `internal/domain/clock.go`, `internal/domain/errors.go`, `internal/domain/ids.go`, `internal/domain/tenant.go`, `internal/domain/urn.go`, `internal/domain/subject.go`, `internal/domain/relation.go`, `internal/domain/actor.go`, `internal/domain/revision.go`
- Test: `internal/domain/urn_test.go`, `internal/domain/subject_test.go`, `internal/domain/relation_test.go`, `internal/domain/actor_test.go`

**Interfaces:**
- Consumes: `go get github.com/oklog/ulid/v2@v2.1.2`.
- Produces:
  - `type TenantID string`, `type URN string`, `type SubjectKind string`, `type Subject struct { URN URN; Kind SubjectKind }`, `type Relation string`, `type GrantID string`, `type Revision uint64`.
  - `ParseTenantID(string) (TenantID, error)`, `ParseURN(string) (URN, error)`, `NewNodeURN(TenantID, string, string) (URN, error)`, `NewSubjectURN(TenantID, SubjectKind, string) (URN, error)`.
  - `(URN) Tenant() TenantID`, `(URN) Kind() string`, `(URN) ID() string`, `(URN) String() string`.
  - `NewUserSubject(TenantID, string) (Subject, error)`, `NewGroupSubject(TenantID, string) (Subject, error)`, `ParseSubject(URN) (Subject, error)`, `(Subject) Validate() error`, `(Subject) String() string`.
  - Relation constants `Parent`, `Owner`, `Editor`, `Commenter`, `Viewer`, `CanShare`, `CanDelete`, `CanView`, `CanEdit`, `CanComment`, `Member`, `Admin`; `(Relation) Rank() int`, `(Relation) IsBase() bool`, `(Relation) IsGrantable() bool`.
  - `type ActorRole string` with `RoleUser`, `RoleAgent`, `RoleTenantAdmin`, `RoleDeploymentAdmin`, `RoleIdentityAdapter`, `RoleAuditor`; `type Actor struct { ID string; Subject Subject; Tenant TenantID; Role ActorRole }`; `(Actor) Validate() error`.
  - `type Clock interface { Now() time.Time }`, `SystemClock`, `FixedClock` with `Advance`.
  - `NewGrantID(Clock) GrantID`.
  - Sentinels: `ErrInvalidTenant`, `ErrInvalidURN`, `ErrInvalidSubject`, `ErrInvalidRelation`, `ErrInvalidKind`, `ErrInvalidActor`, `ErrNotFound`, `ErrConflict`, `ErrForbidden`, `ErrUnauthorized`, `ErrStale`, `ErrModelNotProjected`, `ErrUnknownEvent`, `ErrUnsupported`.

- [ ] **Step 1: Write the failing primitive tests**

```go
func TestURNShape(t *testing.T) {
	u, err := ParseURN("laenen/folder/home")
	if err != nil { t.Fatal(err) }
	if u.Tenant() != "laenen" || u.Kind() != "folder" || u.ID() != "home" { t.Fatalf("bad parse: %#v", u) }

	for _, bad := range []string{"", "laenen/folder", "Laenen/folder/home", "laenen/Folder/home", "laenen/folder/home/extra", "laenen/folder/"} {
		if _, err := ParseURN(bad); !errors.Is(err, ErrInvalidURN) { t.Fatalf("%q: %v", bad, err) }
	}
}

func TestSubjectNeedsSubjectKind(t *testing.T) {
	if _, err := ParseSubject(URN("laenen/folder/home")); !errors.Is(err, ErrInvalidSubject) { t.Fatal("a node kind is not a subject") }
	u, err := NewUserSubject("laenen", "u1")
	if err != nil { t.Fatal(err) }
	if u.Kind != SubjectUser || u.URN != "laenen/user/u1" { t.Fatalf("%#v", u) }
}

func TestRelationRanks(t *testing.T) {
	if Viewer.Rank() != 1 || Commenter.Rank() != 2 || Editor.Rank() != 3 || Owner.Rank() != 4 { t.Fatal("rank ladder") }
	if CanDelete.Rank() != 0 || !CanDelete.IsGrantable() { t.Fatal("can_delete is global and grantable") }
	if CanShare.IsGrantable() { t.Fatal("can_share is computed") }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/domain -run 'TestURNShape|TestSubjectNeedsSubjectKind|TestRelationRanks' -v`
Expected: FAIL with undefined `ParseURN`, `ParseSubject`, `Viewer`.

- [ ] **Step 3: Implement the primitives**

Use one slug regexp for tenant, kind and id. `ParseURN` splits exactly three `/`-separated segments in this order: tenant, kind, id. `ParseSubject` accepts only `user`, `agent` and `group` kinds. `Subject.Validate` requires the URN kind to equal the subject kind and the tenant to be non-empty. `Relation.Rank` returns the pinned values; `IsBase` is true for the four ladder relations; `IsGrantable` is true for the four base relations and `CanDelete`, false for `CanShare`, `CanView`, `CanEdit`, `CanComment`, `Parent`, `Member`, `Admin`.

`Actor.Validate` requires `ID`; a valid role; a tenant for every role except deployment admin and a global identity adapter; and a subject whose tenant matches for `RoleUser`, `RoleAgent` and `RoleTenantAdmin`. `NewGrantID` uses a ULID with the clock timestamp and `crypto/rand`; it panics only on entropy failure, matching the old module's documented choice.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/domain -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/domain
git commit -m "feat(domain): add urn, subject, relation and actor primitives"
```

---

### Task 3: Domain events and aggregates

**Files:**
- Create: `internal/domain/event.go`, `internal/domain/node.go`, `internal/domain/grant.go`, `internal/domain/group.go`, `internal/domain/principal.go`, `internal/domain/kind.go`, `internal/domain/reason.go`
- Test: `internal/domain/event_test.go`, `internal/domain/kind_test.go`, `internal/domain/aggregate_test.go`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `type Event interface { EventType() string; Stream() string }`.
  - Events `NodeRegistered{URN, Kind, Parent URN, CreatedBy string}`, `NodeDeleted{URN URN, Reason string}`, `GrantIssued{GrantID, Object URN, Subject Subject, Relation Relation, GrantedBy, Reason string}`, `GrantRevoked{GrantID, Object URN, RevokedBy, Reason string}`, `GroupCreated{Group URN, Name string, Admin Subject, CreatedBy string}`, `GroupAdminChanged{Group URN, Admin Subject, ChangedBy string}`, `MemberAdded{Group URN, Member Subject, AddedBy string}`, `MemberRemoved{Group URN, Member Subject, RemovedBy string}`, `GroupDeleted{Group URN, Reason string}`, `PrincipalLinked{Issuer, ExternalID string, Subject Subject}`, `PrincipalDeactivated{Subject Subject, Source DeactivationSource, Reason string}`, `PrincipalReactivated{Subject Subject, Source DeactivationSource, Reason string}`, `PrincipalDeleted{Subject Subject, Reason string}`, `KindRegistered{Version int, Kind KindSpec}`, `ModelPublished{Version int}`.
  - `type DeactivationSource string` with `SourceGlobal = "global"`, `SourceTenant = "tenant"`.
  - `Node{URN URN; Tenant TenantID; Kind string; Parent URN; Live bool; CreatedAt time.Time; CreatedBy string}`, `Grant{ID GrantID; Tenant TenantID; Object URN; Subject Subject; Relation Relation; GrantedBy string; GrantedAt time.Time; Live bool}`, `Group{URN URN; Tenant TenantID; Name string; Admin Subject; Live bool; CreatedAt time.Time}`, `Principal{URN URN; Tenant TenantID; Issuer, ExternalID string; Kind SubjectKind; GlobalLive, TenantLive, Live, Deleted bool; LinkedAt time.Time}`.
  - `KindSpec{Name string; Contains []string; ContainsAny bool; Relations []Relation}`, `KindSpec.Validate() error`, `DefaultKinds() []KindSpec`, `const RootKind = "root"`.
  - `Reason` constants `ReasonNoGrant`, `ReasonDirect`, `ReasonUserset`, `ReasonInherited`.

- [ ] **Step 1: Write the failing event/model tests**

```go
func TestEventStreams(t *testing.T) {
	if got := (NodeRegistered{URN: "t/folder/f1", Kind: "folder"}).Stream(); got != "node:folder_f1" { t.Fatal(got) }
	if got := (GrantIssued{Object: "t/document/d1"}).Stream(); got != "acl:document_d1" { t.Fatal(got) }
	if got := (GroupCreated{Group: "t/group/g1"}).Stream(); got != "group:g1" { t.Fatal(got) }
	if got := (PrincipalLinked{Subject: Subject{URN: "t/user/u1", Kind: SubjectUser}}).Stream(); got != "principal:user_u1" { t.Fatal(got) }
	if got := (ModelPublished{Version: 3}).Stream(); got != "model:3" { t.Fatal(got) }
}

func TestKindSpec(t *testing.T) {
	root := KindSpec{Name: RootKind, ContainsAny: true}
	if err := root.Validate(); err != nil { t.Fatal(err) }
	bad := KindSpec{Name: "folder", Relations: []Relation{CanShare}}
	if err := bad.Validate(); !errors.Is(err, ErrInvalidKind) { t.Fatal("computed relations are not declared") }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/domain -run 'TestEventStreams|TestKindSpec' -v`
Expected: FAIL with undefined event types.

- [ ] **Step 3: Implement events and aggregate values**

Each event's `Stream` derives from its URN: `node:<kind>_<id>`, `acl:<kind>_<id>`, `group:<id>`, `principal:<subject-kind>_<id>`, `model:<version>`. `EventType` is a stable dotted name such as `node.registered`, `grant.issued`, `principal.deactivated`.

`KindSpec.Validate` requires a slug name; `root` must set `ContainsAny` and no relations; a non-root kind must not set `ContainsAny`; contained names are slugs; relations are a duplicate-free subset of the four base relations, so `can_delete`, `can_share` and computed relations are refused. `DefaultKinds` contains root, folder, document, album, photo, space and message; folder contains folder/document/album; album contains photo; space contains folder/message; leaf kinds contain nothing.

`Node`, `Grant`, `Group` and `Principal` validate their tenant/URN agreement and required fields. `Principal.Live` is `GlobalLive && TenantLive && !Deleted`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/domain -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/domain
git commit -m "feat(domain): add typed events, kinds and aggregate values"
```

---

### Task 4: Event log port and in-memory adapter

**Files:**
- Create: `internal/eventlog/eventlog.go`, `internal/eventlog/memory.go`
- Create: `internal/eventlog/eventlogtest/suite.go`
- Test: `internal/eventlog/memory_test.go`

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `type Workspace string`, `const PlatformWorkspace Workspace = "_platform"`, `TenantWorkspace(domain.TenantID) Workspace`.
  - `type Envelope struct { Actor, Command, CorrelationID, CausationID string; ModelVersion int; OccurredAt time.Time; Event domain.Event }`.
  - `type Recorded struct { Workspace Workspace; Revision domain.Revision; Envelope Envelope; RecordedAt time.Time }`.
  - `type EventLog interface { Append(ctx context.Context, ws Workspace, envelopes ...Envelope) (domain.Revision, error); Read(ctx context.Context, ws Workspace, from domain.Revision, limit int) ([]Recorded, error); Head(ctx context.Context, ws Workspace) (domain.Revision, error) }`.
  - `func NewMemory(clock domain.Clock) *Memory`.

- [ ] **Step 1: Write the failing event-log suite**

```go
func TestMemoryEventLog(t *testing.T) { RunSuite(t, func(t *testing.T) EventLog { return NewMemory(domain.FixedClock{}) }) }

func TestAppendReturnsGaplessRevisions(t *testing.T) {
	log := NewMemory(domain.FixedClock{})
	ws := TenantWorkspace("t")
	rev, err := log.Append(context.Background(), ws, testEnvelope("a"), testEnvelope("b"))
	if err != nil || rev != 2 { t.Fatalf("rev=%d err=%v", rev, err) }
	recs, err := log.Read(context.Background(), ws, 1, 10)
	if err != nil || len(recs) != 2 || recs[0].Revision != 1 || recs[1].Revision != 2 { t.Fatalf("%#v %v", recs, err) }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/eventlog -v`
Expected: FAIL with undefined `NewMemory`, `RunSuite`.

- [ ] **Step 3: Implement the port and the memory adapter**

`Append` rejects an empty workspace, a nil event, and an envelope with an empty actor; it writes all envelopes under one lock, stamps `RecordedAt` from the clock, and returns the new head. `Read` returns records with `Revision >= from`, at most `limit` (0 means a default of 128); it never returns a gap. `Head` returns 0 for an unknown workspace. Workspaces are isolated. The suite covers append/read/head, gapless revisions, isolation, limit, replay reading the same records, and rejection of a nil event.

The suite defines a private `testEvent` implementing `domain.Event` and a `testEnvelope(event string)` helper; the memory test calls `RunSuite(t, func(t *testing.T) EventLog { return NewMemory(domain.FixedClock{}) })`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/eventlog -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/eventlog
git commit -m "feat(eventlog): add the event log port and memory adapter"
```

---

### Task 5: Engine port and reference engine

**Files:**
- Create: `internal/engine/engine.go`, `internal/engine/memory.go`
- Create: `internal/engine/enginetest/suite.go`
- Test: `internal/engine/memory_test.go`

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `type Tuple struct { Object domain.URN; Relation domain.Relation; Subject domain.URN; Userset bool }`.
  - `type Engine interface { Write(ctx context.Context, tuples ...Tuple) error; Delete(ctx context.Context, tuples ...Tuple) error; Check(ctx context.Context, subject domain.Subject, relation domain.Relation, object domain.URN) (bool, domain.Reason, error) }`.
  - `func NewMemory() *Memory`.

- [ ] **Step 1: Write the failing engine suite**

```go
func TestMemoryEngine(t *testing.T) { RunSuite(t, func(t *testing.T) Engine { return NewMemory() }) }

func TestOwnerImplicationsAndInheritance(t *testing.T) {
	e := NewMemory()
	ctx := context.Background()
	mustWrite(t, e, Tuple{Object: "t/folder/root", Relation: domain.Owner, Subject: "t/user/u1"})
	mustWrite(t, e, Tuple{Object: "t/document/d1", Relation: domain.Parent, Subject: "t/folder/root"})
	for _, rel := range []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer, domain.CanShare, domain.CanDelete} {
		ok, _, err := e.Check(ctx, domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, rel, "t/document/d1")
		if err != nil || !ok { t.Fatalf("%s: %v %v", rel, ok, err) }
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/engine -v`
Expected: FAIL with undefined `NewMemory`.

- [ ] **Step 3: Implement the reference engine**

Store tuples as a set keyed by `(object, relation, subject, userset)`. `Check` maps `can_view`/`can_edit`/`can_comment`/`can_share` to the four base relations, and evaluates:

- `owner = direct owner OR owner(parent)`;
- `editor = direct editor OR owner(object) OR editor(parent)`;
- `commenter = direct commenter OR editor(object) OR commenter(parent)`;
- `viewer = direct viewer OR commenter(object) OR viewer(parent)`;
- `can_delete = direct can_delete OR owner(object)`, with direct can_delete never inherited.

A direct tuple matches a user/agent subject by URN equality; a `Userset` tuple names a group and matches when the checked user is a live `group#member` tuple. Groups are flat. `Member` and `Admin` are direct relations. Return `ReasonInherited` when the matching path crossed a parent, otherwise `ReasonUserset` for a group match, otherwise `ReasonDirect`; deny is `ReasonNoGrant`. The suite covers direct grants, owner implications, inheritance, group usersets, `can_delete` non-inheritance, `can_delete` from owner, and deny.

Add `internal/engine/helpers_test.go` with `mustWrite(t, engine, tuples...)` and `mustDelete(t, engine, tuples...)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/engine -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/engine
git commit -m "feat(engine): add the reference relation engine"
```

---

### Task 6: Projector and in-memory read model

**Files:**
- Create: `internal/projector/store.go`, `internal/projector/memory.go`, `internal/projector/projector.go`
- Test: `internal/projector/projector_test.go`

**Interfaces:**
- Consumes: Tasks 3-5.
- Produces:
  - `type Store interface` with `SetNode`, `Node`, `Nodes`, `SetGrant`, `Grant`, `GrantsForObject`, `GrantsForSubject`, `GroupsForMember`, `GroupsForAdmin`, `SetGroup`, `Group`, `SetGroupMember`, `GroupMembers`, `SetPrincipal`, `Principal`, `Live`, `AddPendingKind`, `PendingKind`, `PublishKinds`, `Kind`, `ModelVersion`.
  - `func NewMemoryStore() *MemoryStore`.
  - `func New(log eventlog.EventLog, store Store, eng engine.Engine, clock domain.Clock) *Projector`.
  - `(*Projector) Project(ctx context.Context, ws eventlog.Workspace) error`, `(*Projector) Applied(ws eventlog.Workspace) domain.Revision`, `(*Projector) AppliedAt(ws eventlog.Workspace) time.Time`.

- [ ] **Step 1: Write the failing projection test**

```go
func TestProjectNodeGrantAndDelete(t *testing.T) {
	log := eventlog.NewMemory(domain.FixedClock{})
	store := NewMemoryStore()
	eng := engine.NewMemory()
	p := New(log, store, eng, domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	events := []domain.Event{
		domain.NodeRegistered{URN: "t/folder/f1", Kind: "folder", CreatedBy: "a"},
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", Parent: "t/folder/f1", CreatedBy: "a"},
		domain.GrantIssued{GrantID: "g1", Object: "t/document/d1", Subject: domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, Relation: domain.Viewer, GrantedBy: "a"},
		domain.NodeDeleted{URN: "t/document/d1", Reason: "test"},
	}
	appendAll(t, log, ws, events...)
	if err := p.Project(context.Background(), ws); err != nil { t.Fatal(err) }
	if got := p.Applied(ws); got != 4 { t.Fatalf("applied=%d", got) }
	if _, ok := store.Node("t", "t/document/d1"); !ok { t.Fatal("node read model missing") }
	if ok, _, _ := eng.Check(context.Background(), domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, domain.Viewer, "t/document/d1"); ok { t.Fatal("deleted node still allows") }
	// Replay the same log and assert the same read model and the same deny.
	if err := p.Project(context.Background(), ws); err != nil { t.Fatal(err) }
	if ok, _, _ := eng.Check(context.Background(), domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, domain.Viewer, "t/document/d1"); ok { t.Fatal("replay resurrected a deleted grant") }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/projector -run TestProjectNodeGrantAndDelete -v`
Expected: FAIL with undefined `NewMemoryStore`.

- [ ] **Step 3: Implement the store and projector**

The store uses maps keyed by tenant and URN/id; `GrantsForObject` and `GrantsForSubject` return live grants only; `Grant` returns even a revoked grant so `Revoke` can distinguish live from absent; `GroupMembers` returns live members only; `Live` derives from the principal's effective live or the group's live flag. The model methods keep pending kinds separate from published kinds; `PublishKinds(version)` promotes pending kinds and sets the model version.

The projector projects the platform workspace first, then the requested workspace. It reads from `Applied+1` in batches; for each record it refuses to apply a tenant event whose `Envelope.ModelVersion` exceeds the store's model version, applies the event, and advances the applied position. `apply` is type-switched and idempotent:

- node registered → read-model node + parent tuple;
- node deleted → delete the node's live grant tuples and parent tuple, mark the node dead;
- grant issued/revoked → upsert/mark the grant and write/delete the tuple;
- group created/admin/member/deleted → read-model group/members and admin/member tuples;
- principal linked/deactivated/reactivated/deleted → read-model principal and cleanup tuples;
- kind registered/model published → pending/published model.

`PrincipalDeleted` marks the subject's live grants revoked, removes its group memberships, clears any group-admin edge, and deletes the corresponding engine tuples. The `Group` and `Principal` URNs are retired for creation checks later.

Add `internal/projector/helpers_test.go` with `appendAll(t, log, ws, events...)`, which wraps each event in a test envelope and appends them, and `mustWrite(t, engine, tuples...)`. The same helper names are used by the engine and core tests where shown.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/projector -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/projector
git commit -m "feat(projector): project events into the read model and engine"
```

---

### Task 7: Core IAM, tenant bootstrap and model publication

**Files:**
- Create: `internal/core/iam.go`, `internal/core/tenant.go`, `internal/core/kind.go`
- Test: `internal/core/tenant_test.go`, `internal/core/kind_test.go`

**Interfaces:**
- Consumes: Tasks 4-6.
- Produces:
  - `type Config struct { Staleness time.Duration; Clock domain.Clock }`.
  - `type IAM struct` with `NewMemory(ctx context.Context, cfg Config) (*IAM, error)`.
  - `CreateTenantRequest{Tenant domain.TenantID; RootID string; FirstOwner domain.Subject}`, `Tenant{ID domain.TenantID; Root domain.URN; OwnerGrant domain.GrantID; Revision domain.Revision}`.
  - `RegisterKindRequest{Kind domain.KindSpec}`, `PublishModelRequest{Version int}`.
  - `(*IAM) CreateTenant(ctx, Actor, CreateTenantRequest) (Tenant, error)`, `RegisterKind`, `PublishModel`.

- [ ] **Step 1: Write the failing bootstrap test**

```go
func TestCreateTenantAndPublishKind(t *testing.T) {
	svc := newTestIAM(t)
	admin := domain.Actor{ID: "deployment-admin", Role: domain.RoleDeploymentAdmin}
	owner, _ := domain.NewUserSubject("laenen", "u1")
	tenant, err := svc.CreateTenant(context.Background(), admin, CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: owner})
	if err != nil { t.Fatal(err) }
	if tenant.Root != "laenen/root/root" || tenant.OwnerGrant == "" { t.Fatalf("%#v", tenant) }
	if _, err := svc.CreateTenant(context.Background(), admin, CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: owner}); !errors.Is(err, domain.ErrConflict) { t.Fatal("duplicate tenant") }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/core -run TestCreateTenantAndPublishKind -v`
Expected: FAIL with undefined `NewMemory`.

- [ ] **Step 3: Implement the core wiring and bootstrap**

`NewMemory` creates the memory event log, store, engine and projector; seeds `KindRegistered` for every `DefaultKinds()` entry and `ModelPublished{Version: 1}` in the platform workspace; then projects the platform. `Config.Staleness` defaults to 5s; `Config.Clock` defaults to `domain.SystemClock{}`.

`CreateTenant` requires `RoleDeploymentAdmin`, validates the tenant slug, root id and first-owner user subject, refuses an existing root in that tenant, appends `NodeRegistered` for `laenen/root/root` and `GrantIssued` for the owner, and returns the root, grant id and revision. The first-owner grant is written without the live-subject check because the owner principal may be linked after bootstrap; the check will deny until the principal is linked and live.

`RegisterKind` requires deployment admin, validates the spec, refuses `root` and duplicate pending/published names, and appends `KindRegistered` to the platform workspace with `Version = store.ModelVersion()+1`. `PublishModel` requires deployment admin, the next version, and at least one pending kind, then appends `ModelPublished`.

Add `internal/core/helpers_test.go` with the shared fixtures used by Tasks 7-12: `newTestIAM(t)`, `deploymentAdmin()`, `identityAdapter()`, `bootstrap(t) (svc, ownerActor, tenant)`, `mustTenant`, `mustUser`, `linkUser`, `linkAsIdentity`, `mustNode`, `mustRoot`, `ownerOf`, `ownerOfTenant`. They construct only public/internal types and fail the test on error; they are test scaffolding, not production code.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/core -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core
git commit -m "feat(core): add tenant bootstrap and model publication"
```

---

### Task 8: Nodes, containment and deletion

**Files:**
- Create: `internal/core/node.go`
- Test: `internal/core/node_test.go`

**Interfaces:**
- Consumes: Task 7.
- Produces:
  - `RegisterNodeRequest{Tenant domain.TenantID; URN domain.URN; Parent domain.URN}`, `NodeResult{Node domain.Node; Revision domain.Revision}`.
  - `DeleteNodeRequest{Tenant domain.TenantID; URN domain.URN; Reason string}`, `DeleteSubtreeRequest{Tenant domain.TenantID; URN domain.URN; Reason string}`.
  - `(*IAM) RegisterNode(ctx, Actor, RegisterNodeRequest) (NodeResult, error)`, `DeleteNode`, `DeleteSubtree`.

- [ ] **Step 1: Write the failing node tests**

```go
func TestRegisterNodeRules(t *testing.T) {
	svc, owner, tenant := bootstrap(t)
	n, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/folder/home", Parent: "laenen/root/root"})
	if err != nil { t.Fatal(err) }
	d, err := svc.Check(ctx, owner, CheckRequest{Tenant: tenant, Subject: owner.Subject, Object: n.Node.URN, Relation: domain.Owner})
	if err != nil || !d.Allowed { t.Fatalf("creator must be owner: %v %v", d, err) }
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/folder/home", Parent: "laenen/root/root"}); !errors.Is(err, domain.ErrConflict) { t.Fatal("duplicate urn") }
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/root/other", Parent: "laenen/root/root"}); !errors.Is(err, domain.ErrForbidden) { t.Fatal("second root") }
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/document/cross", Parent: "other/root/root"}); err == nil { t.Fatal("cross-tenant parent") }
}
```

Add a deleted-URN reuse assertion to the same test: register a node, delete it (with no children), then attempt the same URN and expect `ErrConflict`. Add a second-parent assertion by attempting to register the same URN again with a different parent and expecting `ErrConflict`; the URN's existing row is what makes a second parent unrepresentable.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/core -run TestRegisterNodeRules -v`
Expected: FAIL with undefined `RegisterNode`.

- [ ] **Step 3: Implement node commands**

`RegisterNode` requires a live user actor, validates the URN and tenant match, refuses root kind/parentless non-root registration, loads the published kind and live parent, checks the parent's kind containment (`root`/`ContainsAny` accepts any published kind; otherwise `Contains` must name the child kind), refuses an existing URN even if deleted, checks `can_share` on the parent, and appends `NodeRegistered` plus the creator's automatic `owner` grant in one batch. The creator is `actor.Subject`; a deployment-admin or identity-adapter actor without a user subject is refused.

`DeleteNode` requires the node live, no live children, and `can_share` or `can_delete` on the node; it refuses the root. `DeleteSubtree` requires `owner` on the node, refuses the root, collects the subtree post-order, and appends one `NodeDeleted` per node. A deleted URN stays refused for registration.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/core -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core
git commit -m "feat(core): add node registration, containment and deletion"
```

---

### Task 9: Grants, revocation and checks

**Files:**
- Create: `internal/core/grant.go`
- Test: `internal/core/grant_test.go`

**Interfaces:**
- Consumes: Tasks 7-8.
- Produces:
  - `GrantRequest{Tenant domain.TenantID; Object domain.URN; Subject domain.Subject; Relation domain.Relation; Reason string}`, `GrantResult{GrantID domain.GrantID; Revision domain.Revision}`.
  - `RevokeRequest{Tenant domain.TenantID; GrantID domain.GrantID; Reason string}`.
  - `CheckRequest{Tenant domain.TenantID; Subject domain.Subject; Object domain.URN; Relation domain.Relation}`, `Decision{Allowed bool; Reason domain.Reason; Revision domain.Revision}`.
  - `(*IAM) Grant`, `Revoke`, `Check`.

- [ ] **Step 1: Write the failing grant/check tests**

```go
func TestGrantInheritanceAndRevocation(t *testing.T) {
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	g, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.Viewer})
	if err != nil { t.Fatal(err) }
	d, err := svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer})
	if err != nil || !d.Allowed || d.Reason != domain.ReasonInherited { t.Fatalf("inherited: %#v %v", d, err) }
	if _, err := svc.Revoke(ctx, owner, RevokeRequest{Tenant: tenant, GrantID: g.GrantID}); err != nil { t.Fatal(err) }
	d, _ = svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer})
	if d.Allowed { t.Fatal("revoked grant still allows") }
}
```

Add a `can_delete` subtest: the owner grants it directly to a user, the user can delete the object; the same relation on an ancestor does not confer deletion on a descendant; a non-owner grant attempt is refused with `ErrForbidden`; a direct `can_share` grant is refused with `ErrInvalidRelation`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/core -run TestGrantInheritanceAndRevocation -v`
Expected: FAIL with undefined `Grant`.

- [ ] **Step 3: Implement grant commands and checks**

`Grant` requires a live user actor, live subject (user principal or live group; agent subjects return `ErrUnsupported`), live object, a published kind, a grantable relation, and a live `(subject, relation)` uniqueness check. `can_delete` requires the actor to hold `owner` and is non-inheriting; every other grantable relation requires `can_share`. `owner` to a group is allowed; `owner` to an agent is refused. The event records `granted_by = actor.ID` and the reason.

`Revoke` loads the live grant, requires `can_share` on the grant's object, and appends `GrantRevoked` with the object so the projector can delete the tuple.

`Check` requires the acting subject to equal the requested subject unless the actor is `RoleTenantAdmin` or `RoleAuditor`; it validates tenant/URN agreement, projects to the current head, denies when the subject or node is not live or the node is unknown, then evaluates the engine relation. A denied check is a `Decision{Allowed:false, Reason:ReasonNoGrant}`, not an error; tenant mismatches and invalid requests are errors. `Check` refuses agent subjects with `ErrUnsupported` in this plan.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/core -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core
git commit -m "feat(core): add grants, revocation and checks"
```

---

### Task 10: Groups and group membership

**Files:**
- Create: `internal/core/group.go`
- Test: `internal/core/group_test.go`

**Interfaces:**
- Consumes: Task 9.
- Produces:
  - `CreateGroupRequest{Tenant domain.TenantID; GroupID string; Name string}`, `GroupResult{Group domain.Group; Revision domain.Revision}`.
  - `AddGroupMemberRequest{Tenant domain.TenantID; Group domain.URN; Member domain.Subject}`, `RemoveGroupMemberRequest`, `SetGroupAdminRequest{Tenant domain.TenantID; Group domain.URN; Admin domain.Subject}`, `DeleteGroupRequest{Tenant domain.TenantID; Group domain.URN; Reason string}`.
  - `(*IAM) CreateGroup`, `AddGroupMember`, `RemoveGroupMember`, `SetGroupAdmin`, `DeleteGroup`.

- [ ] **Step 1: Write the failing group tests**

```go
func TestGroupMembershipChangesAccess(t *testing.T) {
	svc, owner, tenant := bootstrap(t)
	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g1", Name: "Family"})
	if err != nil { t.Fatal(err) }
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil { t.Fatal(err) }
	node := mustNode(t, svc, owner, tenant, "laenen/document/shared", "laenen/root/root")
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: domain.Subject{URN: group.Group.URN, Kind: domain.SubjectGroup}, Relation: domain.Viewer}); err != nil { t.Fatal(err) }
	d, err := svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer})
	if err != nil || !d.Allowed { t.Fatalf("group grant: %#v %v", d, err) }
	if _, err := svc.RemoveGroupMember(ctx, owner, RemoveGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil { t.Fatal(err) }
	d, _ = svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer})
	if d.Allowed { t.Fatal("removed member still allows") }
}
```

Add a group lifecycle subtest: a non-admin cannot add a member; a tenant admin can; `DeleteGroup` makes group grants deny; recreating the same group URN is refused with `ErrConflict`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/core -run TestGroupMembershipChangesAccess -v`
Expected: FAIL with undefined `CreateGroup`.

- [ ] **Step 3: Implement group commands**

`CreateGroup` accepts any live user in the tenant, refuses an already-used group URN even if deleted, and makes the creator the admin. `AddGroupMember`/`RemoveGroupMember`/`SetGroupAdmin`/`DeleteGroup` accept the current group admin or a `RoleTenantAdmin`; members and admins must be live user subjects (groups are flat and human-only). `DeleteGroup` marks the group dead; the URN stays retired. A group grant is a `Subject{Kind: SubjectGroup}`; the projector writes it as a `group#member` userset tuple.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/core -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core
git commit -m "feat(core): add groups and membership"
```

---

### Task 11: Principal lifecycle and global deactivation

**Files:**
- Create: `internal/core/principal.go`
- Modify: `internal/core/iam.go` (external-identity index fields)
- Test: `internal/core/principal_test.go`

**Interfaces:**
- Consumes: Task 10.
- Produces:
  - `LinkPrincipalRequest{Tenant domain.TenantID; Issuer, ExternalID string; Subject domain.Subject}`, `PrincipalResult{Principal domain.Principal; Revision domain.Revision}`.
  - `DeactivatePrincipalRequest`/`ReactivatePrincipalRequest{Tenant domain.TenantID; Subject domain.Subject; Source domain.DeactivationSource; Reason string}`, `DeletePrincipalRequest{Tenant domain.TenantID; Subject domain.Subject; Reason string}`.
  - `(*IAM) LinkPrincipal`, `DeactivatePrincipal`, `ReactivatePrincipal`, `DeletePrincipal`.

- [ ] **Step 1: Write the failing principal tests**

```go
func TestGlobalDeactivationFansOutAndSurvivesRelink(t *testing.T) {
	svc := newTestIAM(t)
	admin := deploymentAdmin()
	ownerA, ownerB := mustUser(t, "a", "u1"), mustUser(t, "b", "u1")
	mustTenant(t, svc, admin, "a", ownerA)
	mustTenant(t, svc, admin, "b", ownerB)
	linkAsIdentity(t, svc, "a", "issuer", "external-1", ownerA)
	linkAsIdentity(t, svc, "b", "issuer", "external-1", ownerB)
	if _, err := svc.DeactivatePrincipal(ctx, identityAdapter(), DeactivatePrincipalRequest{Tenant: "a", Subject: ownerA, Source: domain.SourceGlobal, Reason: "left"}); err != nil { t.Fatal(err) }
	for _, tc := range []struct{ tenant string; subj domain.Subject }{ {"a", ownerA}, {"b", ownerB} } {
		d, _ := svc.Check(ctx, ownerOfTenant(tc.tenant), CheckRequest{Tenant: tc.tenant, Subject: tc.subj, Object: mustRoot(t, svc, tc.tenant), Relation: domain.Owner})
		if d.Allowed { t.Fatalf("global deactivation missed %s", tc.tenant) }
	}
	late := mustUser(t, "c", "u1")
	mustTenant(t, svc, admin, "c", late)
	linkAsIdentity(t, svc, "c", "issuer", "external-1", late)
	d, _ := svc.Check(ctx, ownerOfTenant("c"), CheckRequest{Tenant: "c", Subject: late, Object: mustRoot(t, svc, "c"), Relation: domain.Owner})
	if d.Allowed { t.Fatal("late link started live") }
}
```

Add a liveness subtest: deactivate a user who has a direct grant, a group grant and an inherited grant; all three checks deny, and reactivating the same principal restores all three without re-granting.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/core -run TestGlobalDeactivationFansOutAndSurvivesRelink -v`
Expected: FAIL with undefined `DeactivatePrincipal`.

- [ ] **Step 3: Implement principal lifecycle**

`LinkPrincipal` requires `RoleIdentityAdapter`; the subject must be a user (agent principals return `ErrUnsupported`), the URN must match its tenant, and `(issuer, external id)` must not already name a live principal in that tenant. Append `PrincipalLinked`; if the in-memory external index records a global deactivation for that external id, append `PrincipalDeactivated{Source: SourceGlobal}` immediately after, so a late link starts non-live.

`DeactivatePrincipal` with `SourceTenant` requires `RoleTenantAdmin` or `RoleIdentityAdapter`; with `SourceGlobal` it requires `RoleIdentityAdapter`. A global deactivation updates the external index and appends a tenant-source event to every tenant linked to that external id; retries skip tenants already in that state. `ReactivatePrincipal` mirrors it; a tenant reactivation cannot override a global deactivation because effective live is the AND of the two states.

`DeletePrincipal` requires `RoleIdentityAdapter`, appends `PrincipalDeleted`, and retires the subject URN: direct grants, group memberships and group-admin edges are removed, and dependent agents are out of scope until plan 2. The external index keeps the mapping for audit; a later link must use a new subject URN.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/core -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core
git commit -m "feat(core): add principal lifecycle and global deactivation"
```

---

### Task 12: Reverse queries

**Files:**
- Create: `internal/core/query.go`
- Test: `internal/core/query_test.go`

**Interfaces:**
- Consumes: Tasks 9-11.
- Produces:
  - `ListObjectsRequest{Tenant domain.TenantID; Subject domain.Subject; Relation domain.Relation; Kind string}`, `ListObjectsResult{Objects []domain.URN; Revision domain.Revision}`.
  - `AccessibleCountRequest` and `AccessibleCountResult{Count int; Revision domain.Revision}`.
  - `ListSubjectsRequest{Tenant domain.TenantID; Object domain.URN; Relation domain.Relation}`, `SubjectGrant{Subject domain.Subject; ViaGroup domain.URN; GrantID domain.GrantID; Object domain.URN; Relation domain.Relation; GrantedBy string; Depth int}`, `ListSubjectsResult{Grants []SubjectGrant; Revision domain.Revision}`.
  - `(*IAM) ListObjects`, `AccessibleCount`, `ListSubjects`.

- [ ] **Step 1: Write the failing reverse-query tests**

```go
func TestListObjectsAndSubjects(t *testing.T) {
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	g, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.Viewer})
	if err != nil { t.Fatal(err) }
	objs, err := svc.ListObjects(ctx, ownerOf(svc, tenant, user), ListObjectsRequest{Tenant: tenant, Subject: user, Relation: domain.Viewer, Kind: "document"})
	if err != nil || len(objs.Objects) != 1 || objs.Objects[0] != doc.URN { t.Fatalf("%#v %v", objs, err) }
	subs, err := svc.ListSubjects(ctx, owner, ListSubjectsRequest{Tenant: tenant, Object: doc.URN, Relation: domain.Viewer})
	if err != nil { t.Fatal(err) }
	found := false
	for _, sg := range subs.Grants { if sg.GrantID == g.GrantID && sg.Subject == user && sg.Object == folder.URN { found = true } }
	if !found { t.Fatalf("contributing grant missing: %#v", subs) }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/core -run TestListObjectsAndSubjects -v`
Expected: FAIL with undefined `ListObjects`.

- [ ] **Step 3: Implement reverse queries**

`ListObjects` and `AccessibleCount` require the requested subject to equal the actor's subject unless the actor is `RoleTenantAdmin` or `RoleAuditor`; they project, reject agent subjects, iterate live nodes of the requested kind, and call `Check` for each. `ListObjects` returns sorted URNs; `AccessibleCount` returns the length. The design's scalable SQL path is plan 4; this is the reference implementation.

`ListSubjects` requires `can_share` on the object or `RoleAuditor`. It walks the node's live ancestor chain (including the object at depth 0), collects live grants whose rank is at least the requested rank, plus direct `can_delete` grants on the object only when the requested relation is `can_delete`. A user/agent grant yields one entry; a group grant expands to its live members with `ViaGroup` set. Each entry keeps its contributing grant id, grant object, relation, grantor and depth. The result is sorted by subject URN, grant object and grant id. `can_delete` on an ancestor is excluded because it does not inherit; owner on an ancestor is included because owner does. `can_view`, `can_edit` and `can_comment` map to viewer/editor/commenter; `can_share` maps to owner; `can_delete` is the special case above. `parent`, `member`, `admin` and any unknown relation are rejected with `ErrInvalidRelation`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/core -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/core
git commit -m "feat(core): add list objects, list subjects and accessible count"
```

---

### Task 13: Public facade, conformance suite, golden API and docs

**Files:**
- Create: `iam.go`, `iamtest/suite.go`, `iamtest/suite_test.go`, `api_test.go`
- Modify: `README.md`, `CHARTER.md`, `api.txt` (generated)
- Test: `iamtest/suite_test.go`, `api_test.go`

**Interfaces:**
- Consumes: Tasks 7-12.
- Produces:
  - `type IAM = core.IAM`, `type Config = core.Config`, `func NewMemory(ctx context.Context, cfg Config) (*IAM, error)`.
  - Type aliases for every public domain/core type and request/result listed in Tasks 2-12.
  - `iamtest.RunSuite(t *testing.T, newIAM func(t *testing.T) *iam.IAM)`.
  - `api.txt` generated by `go test . -run TestAPIGolden -update-api`.

- [ ] **Step 1: Write the failing facade/suite test**

```go
func TestMemorySuite(t *testing.T) {
	iamtest.RunSuite(t, func(t *testing.T) *iam.IAM {
		v, err := iam.NewMemory(context.Background(), iam.Config{})
		if err != nil { t.Fatal(err) }
		return v
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./iamtest -run TestMemorySuite -v`
Expected: FAIL with undefined `iam.NewMemory`.

- [ ] **Step 3: Implement the facade and suite**

The facade re-exports domain/core types as aliases, sentinels and constants, and forwards `NewMemory` to `core.NewMemory`; it carries no logic. The suite is the adoption contract and runs through the facade only. Its subtests are:

- `TenantBootstrap`: root, first owner, duplicate tenant, owner check after linking.
- `Kinds`: default kinds, staged registration, publish, duplicate/root refusal, containment rules.
- `Nodes`: creator owner, inheritance, duplicate URN, second root, cross-tenant parent, deleted URN reuse, live-child deletion refusal, subtree owner-only.
- `Grants`: direct/group/inherited checks, rank aliases, duplicate grant, owner-to-agent refusal, `can_delete` owner-only/non-inheriting, revoke, computed relation refusal.
- `Groups`: creator admin, member add/remove, group-grant access changes, group-admin authority, delete, URN reuse refusal.
- `Principals`: tenant/global deactivate/reactivate, late link after global deactivation, delete cleanup, identity-adapter-only link/delete.
- `Reverse`: `ListObjects` kind filter, `AccessibleCount`, `ListSubjects` provenance and group expansion, `ListSubjects` owner/auditor authority.
- `Projection`: replay twice, applied revision, event-log-driven state, deletion/revocation idempotence.
- `ReviewFocus`: the five cases in this plan's Review Focus section.

The `iamtest` package does not import `testing` from production code; it is the sibling conformance package. The test factory is called once per subtest with that subtest's `*testing.T`.

Recreate `api_test.go` from the old golden generator (find the deleting commit with `git log --diff-filter=D -- api_test.go`, then `git show <commit>^:api_test.go`) with `apiPackages = []string{".", "iamtest", "internal/domain", "internal/eventlog", "internal/engine", "internal/projector", "internal/core"}`. Generate `api.txt` with `mise api`, then run `TestAPIGolden` without `-update-api` and expect no diff.

Rewrite `CHARTER.md` for the new boundary: central IAM, event log record, OpenFGA derived in plan 3, `Sealer` port with OpenBao custody, no deny/classification, no consumer resource model, no credentials. Rewrite `README.md` for the new API and mark the in-memory core as the current milestone, with the remaining plan split. Reference this plan and the design.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./... -v`
Expected: PASS, including `TestMemorySuite` and `TestAPIGolden`.

- [ ] **Step 5: Commit**

```bash
git add iam.go iamtest api_test.go api.txt README.md CHARTER.md
git commit -m "feat: expose the in-memory IAM facade and conformance suite"
```

---

### Task 14: Final verification

**Files:**
- Modify: none
- Test: full repository

- [ ] **Step 1: Format and lint**

Run: `mise fmt-check && mise lint`
Expected: both exit 0.

- [ ] **Step 2: Build and run the full suite**

Run: `mise build && mise test && mise test-all`
Expected: all pass; `mise test` uses `-short` and starts no containers.

- [ ] **Step 3: Regenerate and verify the golden API**

Run: `mise api && git diff --exit-code api.txt && go test . -run TestAPIGolden -v`
Expected: `api.txt` is already current; the golden test passes.

- [ ] **Step 4: Check the old surface is gone**

Run: `grep -R "NewPostgresRegistry\|internal/authz\|internal/registry\|internal/idp\|NewMemoryAuthorizer" --include='*.go' .`
Expected: no matches.

- [ ] **Step 5: Run the gate**

Run: `mise check`
Expected: exit 0. If it fails, fix the reported issue and rerun from Step 1.

- [ ] **Step 6: Commit the verification**

```bash
git add -A
git commit -m "test: verify the central IAM core gate"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-27-central-iam-core.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** — a fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task myself in this session, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end.

For this plan I recommend **subagent-driven**, because the tasks build on exact interfaces and a mistaken event/projection choice in an early task would propagate into every later task.
