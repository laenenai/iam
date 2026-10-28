package core

import (
	"context"
	"fmt"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

type RegisterKindRequest struct {
	Kind domain.KindSpec
}

type PublishModelRequest struct {
	Version int
}

func (i *IAM) RegisterKind(ctx context.Context, actor domain.Actor, req RegisterKindRequest) error {
	if err := authorize(actor, domain.RoleDeploymentAdmin); err != nil {
		return err
	}
	if req.Kind.Name == domain.RootKind {
		return fmt.Errorf("%w: %s is IAM's own kind", domain.ErrInvalidKind, domain.RootKind)
	}
	if err := req.Kind.Validate(); err != nil {
		return err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	if err := i.project(ctx, eventlog.PlatformWorkspace); err != nil {
		return err
	}
	if _, ok := i.store.Kind(req.Kind.Name); ok {
		return fmt.Errorf("%w: kind %s is published", domain.ErrConflict, req.Kind.Name)
	}
	if _, ok := i.store.PendingKind(req.Kind.Name); ok {
		return fmt.Errorf("%w: kind %s is pending", domain.ErrConflict, req.Kind.Name)
	}
	version := i.store.ModelVersion() + 1
	if _, err := i.appendEvents(ctx, eventlog.PlatformWorkspace, actor, "RegisterKind", domain.KindRegistered{Version: version, Kind: req.Kind}); err != nil {
		return err
	}
	return i.project(ctx, eventlog.PlatformWorkspace)
}

func (i *IAM) PublishModel(ctx context.Context, actor domain.Actor, req PublishModelRequest) error {
	if err := authorize(actor, domain.RoleDeploymentAdmin); err != nil {
		return err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	if err := i.project(ctx, eventlog.PlatformWorkspace); err != nil {
		return err
	}
	if req.Version != i.store.ModelVersion()+1 {
		return fmt.Errorf("%w: model version %d, have %d", domain.ErrConflict, req.Version, i.store.ModelVersion())
	}
	if len(i.store.PendingKinds()) == 0 {
		return fmt.Errorf("%w: no pending kinds", domain.ErrConflict)
	}
	if _, err := i.appendEvents(ctx, eventlog.PlatformWorkspace, actor, "PublishModel", domain.ModelPublished{Version: req.Version}); err != nil {
		return err
	}
	return i.project(ctx, eventlog.PlatformWorkspace)
}
