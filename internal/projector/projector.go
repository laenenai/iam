package projector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/engine"
	"github.com/laenenai/iam/internal/eventlog"
)

const batchSize = 256

// Projector applies the log to the read model and the engine. It is the only
// writer to either. Project is serialized; every handler is idempotent so an
// at-least-once adapter can redeliver a batch.
type Projector struct {
	mu sync.Mutex

	log    eventlog.EventLog
	store  Store
	engine engine.Engine
	clock  domain.Clock

	applied   map[eventlog.Workspace]domain.Revision
	appliedAt map[eventlog.Workspace]time.Time
}

func New(log eventlog.EventLog, store Store, eng engine.Engine, clock domain.Clock) *Projector {
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &Projector{
		log:       log,
		store:     store,
		engine:    eng,
		clock:     clock,
		applied:   make(map[eventlog.Workspace]domain.Revision),
		appliedAt: make(map[eventlog.Workspace]time.Time),
	}
}

func (p *Projector) Project(ctx context.Context, ws eventlog.Workspace) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.projectWorkspace(ctx, eventlog.PlatformWorkspace); err != nil {
		return err
	}
	if ws == eventlog.PlatformWorkspace {
		return nil
	}
	return p.projectWorkspace(ctx, ws)
}

func (p *Projector) Applied(ws eventlog.Workspace) domain.Revision {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.applied[ws]
}

func (p *Projector) AppliedAt(ws eventlog.Workspace) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.appliedAt[ws]
}

func (p *Projector) projectWorkspace(ctx context.Context, ws eventlog.Workspace) error {
	for {
		from := p.applied[ws] + 1
		records, err := p.log.Read(ctx, ws, from, batchSize)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			if ws != eventlog.PlatformWorkspace && record.Envelope.ModelVersion > p.store.ModelVersion() {
				return fmt.Errorf("%w: revision %d needs model %d, have %d", domain.ErrModelNotProjected, record.Revision, record.Envelope.ModelVersion, p.store.ModelVersion())
			}
			if err := p.apply(ctx, ws, record); err != nil {
				return fmt.Errorf("project %s revision %d: %w", ws, record.Revision, err)
			}
			p.applied[ws] = record.Revision
		}
	}
	p.appliedAt[ws] = p.clock.Now()
	return nil
}

func (p *Projector) apply(ctx context.Context, ws eventlog.Workspace, record eventlog.Recorded) error {
	switch event := record.Envelope.Event.(type) {
	case domain.NodeRegistered:
		node := domain.Node{
			URN:       event.URN,
			Tenant:    event.URN.Tenant(),
			Kind:      event.Kind,
			Parent:    event.Parent,
			Live:      true,
			CreatedAt: p.clock.Now(),
			CreatedBy: event.CreatedBy,
		}
		p.store.SetNode(node)
		if event.Parent != "" {
			return p.engine.Write(ctx, parentTuple(event.URN, event.Parent))
		}
		return nil

	case domain.NodeDeleted:
		tenant := event.URN.Tenant()
		for _, grant := range p.store.GrantsForObject(tenant, event.URN) {
			if err := p.engine.Delete(ctx, grantTuple(grant)); err != nil {
				return err
			}
		}
		if node, ok := p.store.Node(tenant, event.URN); ok {
			if node.Parent != "" {
				if err := p.engine.Delete(ctx, parentTuple(node.URN, node.Parent)); err != nil {
					return err
				}
			}
			node.Live = false
			p.store.SetNode(node)
		}
		return nil

	case domain.GrantIssued:
		grant := domain.Grant{
			ID:        event.GrantID,
			Tenant:    event.Object.Tenant(),
			Object:    event.Object,
			Subject:   event.Subject,
			Relation:  event.Relation,
			GrantedBy: event.GrantedBy,
			GrantedAt: p.clock.Now(),
			Live:      true,
		}
		p.store.SetGrant(grant)
		return p.engine.Write(ctx, grantTuple(grant))

	case domain.GrantRevoked:
		tenant := event.Object.Tenant()
		grant, ok := p.store.Grant(tenant, event.GrantID)
		if !ok {
			return fmt.Errorf("%w: grant %s", domain.ErrNotFound, event.GrantID)
		}
		grant.Live = false
		p.store.SetGrant(grant)
		return p.engine.Delete(ctx, grantTuple(grant))

	case domain.GroupCreated:
		group := domain.Group{
			URN:       event.Group,
			Tenant:    event.Group.Tenant(),
			Name:      event.Name,
			Admin:     event.Admin,
			Live:      true,
			CreatedAt: p.clock.Now(),
		}
		p.store.SetGroup(group)
		return p.engine.Write(ctx, adminTuple(event.Group, event.Admin))

	case domain.GroupAdminChanged:
		tenant := event.Group.Tenant()
		group, ok := p.store.Group(tenant, event.Group)
		if !ok {
			return fmt.Errorf("%w: group %s", domain.ErrNotFound, event.Group)
		}
		if group.Admin.URN != "" {
			if err := p.engine.Delete(ctx, adminTuple(event.Group, group.Admin)); err != nil {
				return err
			}
		}
		group.Admin = event.Admin
		p.store.SetGroup(group)
		return p.engine.Write(ctx, adminTuple(event.Group, event.Admin))

	case domain.MemberAdded:
		if _, ok := p.store.Group(event.Group.Tenant(), event.Group); !ok {
			return fmt.Errorf("%w: group %s", domain.ErrNotFound, event.Group)
		}
		p.store.SetGroupMember(event.Group.Tenant(), event.Group, event.Member, true)
		return p.engine.Write(ctx, memberTuple(event.Group, event.Member))

	case domain.MemberRemoved:
		p.store.SetGroupMember(event.Group.Tenant(), event.Group, event.Member, false)
		return p.engine.Delete(ctx, memberTuple(event.Group, event.Member))

	case domain.GroupDeleted:
		tenant := event.Group.Tenant()
		group, ok := p.store.Group(tenant, event.Group)
		if !ok {
			return fmt.Errorf("%w: group %s", domain.ErrNotFound, event.Group)
		}
		for _, member := range p.store.GroupMembers(tenant, event.Group) {
			p.store.SetGroupMember(tenant, event.Group, member, false)
			if err := p.engine.Delete(ctx, memberTuple(event.Group, member)); err != nil {
				return err
			}
		}
		if group.Admin.URN != "" {
			if err := p.engine.Delete(ctx, adminTuple(event.Group, group.Admin)); err != nil {
				return err
			}
		}
		group.Live = false
		p.store.SetGroup(group)
		return nil

	case domain.PrincipalLinked:
		principal := domain.Principal{
			URN:        event.Subject.URN,
			Tenant:     event.Subject.URN.Tenant(),
			Issuer:     event.Issuer,
			ExternalID: event.ExternalID,
			Kind:       event.Subject.Kind,
			GlobalLive: true,
			TenantLive: true,
			Live:       true,
			LinkedAt:   p.clock.Now(),
		}
		p.store.SetPrincipal(principal)
		return nil

	case domain.PrincipalDeactivated:
		return p.setPrincipalLiveness(event.Subject, event.Source, false)

	case domain.PrincipalReactivated:
		return p.setPrincipalLiveness(event.Subject, event.Source, true)

	case domain.PrincipalDeleted:
		return p.deletePrincipal(ctx, event.Subject)

	case domain.KindRegistered:
		if ws != eventlog.PlatformWorkspace {
			return fmt.Errorf("%w: model events belong to %s", domain.ErrInvalidKind, eventlog.PlatformWorkspace)
		}
		if err := event.Kind.Validate(); err != nil {
			return err
		}
		p.store.AddPendingKind(event.Kind)
		return nil

	case domain.ModelPublished:
		if ws != eventlog.PlatformWorkspace {
			return fmt.Errorf("%w: model events belong to %s", domain.ErrConflict, eventlog.PlatformWorkspace)
		}
		if event.Version <= p.store.ModelVersion() {
			return nil
		}
		if event.Version != p.store.ModelVersion()+1 {
			return fmt.Errorf("%w: model version %d, have %d", domain.ErrConflict, event.Version, p.store.ModelVersion())
		}
		p.store.PublishKinds(event.Version)
		return nil

	default:
		return fmt.Errorf("%w: %T", domain.ErrUnknownEvent, record.Envelope.Event)
	}
}

func (p *Projector) setPrincipalLiveness(subject domain.Subject, source domain.DeactivationSource, live bool) error {
	tenant := subject.URN.Tenant()
	principal, ok := p.store.Principal(tenant, subject)
	if !ok {
		return fmt.Errorf("%w: principal %s", domain.ErrNotFound, subject.URN)
	}
	switch source {
	case domain.SourceGlobal:
		principal.GlobalLive = live
	case domain.SourceTenant:
		principal.TenantLive = live
	default:
		return fmt.Errorf("%w: deactivation source %q", domain.ErrInvalidSubject, source)
	}
	principal.Live = principal.EffectiveLive()
	p.store.SetPrincipal(principal)
	return nil
}

func (p *Projector) deletePrincipal(ctx context.Context, subject domain.Subject) error {
	tenant := subject.URN.Tenant()
	principal, ok := p.store.Principal(tenant, subject)
	if !ok {
		return fmt.Errorf("%w: principal %s", domain.ErrNotFound, subject.URN)
	}
	principal.Deleted = true
	principal.Live = false
	p.store.SetPrincipal(principal)

	for _, grant := range p.store.GrantsForSubject(tenant, subject) {
		grant.Live = false
		p.store.SetGrant(grant)
		if err := p.engine.Delete(ctx, grantTuple(grant)); err != nil {
			return err
		}
	}
	for _, group := range p.store.GroupsForMember(tenant, subject) {
		p.store.SetGroupMember(tenant, group.URN, subject, false)
		if err := p.engine.Delete(ctx, memberTuple(group.URN, subject)); err != nil {
			return err
		}
	}
	for _, group := range p.store.GroupsForAdmin(tenant, subject) {
		if err := p.engine.Delete(ctx, adminTuple(group.URN, subject)); err != nil {
			return err
		}
		group.Admin = domain.Subject{}
		p.store.SetGroup(group)
	}
	return nil
}

func parentTuple(child, parent domain.URN) engine.Tuple {
	return engine.Tuple{Object: child, Relation: domain.Parent, Subject: parent}
}

func grantTuple(grant domain.Grant) engine.Tuple {
	return engine.Tuple{
		Object:   grant.Object,
		Relation: grant.Relation,
		Subject:  grant.Subject.URN,
		Userset:  grant.Subject.Kind == domain.SubjectGroup,
	}
}

func adminTuple(group domain.URN, admin domain.Subject) engine.Tuple {
	return engine.Tuple{Object: group, Relation: domain.Admin, Subject: admin.URN}
}

func memberTuple(group domain.URN, member domain.Subject) engine.Tuple {
	return engine.Tuple{Object: group, Relation: domain.Member, Subject: member.URN}
}
