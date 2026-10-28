// Package core wires the event log, projector, read model and engine into the
// IAM commands and queries. The facade exposes this package; logic lives here.
package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/engine"
	"github.com/laenenai/iam/internal/eventlog"
	"github.com/laenenai/iam/internal/projector"
)

const defaultStaleness = 5 * time.Second

type Config struct {
	Staleness time.Duration
	Clock     domain.Clock
}

// IAM is the in-memory reference implementation of the central IAM core.
type IAM struct {
	cfg   Config
	clock domain.Clock

	log       eventlog.EventLog
	store     projector.Store
	engine    engine.Engine
	projector *projector.Projector

	commandMu sync.Mutex
}

func NewMemory(ctx context.Context, cfg Config) (*IAM, error) {
	if cfg.Clock == nil {
		cfg.Clock = domain.SystemClock{}
	}
	if cfg.Staleness <= 0 {
		cfg.Staleness = defaultStaleness
	}
	log := eventlog.NewMemory(cfg.Clock)
	store := projector.NewMemoryStore()
	eng := engine.NewMemory()
	svc := &IAM{
		cfg:       cfg,
		clock:     cfg.Clock,
		log:       log,
		store:     store,
		engine:    eng,
		projector: projector.New(log, store, eng, cfg.Clock),
	}
	if err := svc.seedModel(ctx); err != nil {
		return nil, err
	}
	return svc, nil
}

func (i *IAM) seedModel(ctx context.Context) error {
	kinds := domain.DefaultKinds()
	envelopes := make([]eventlog.Envelope, 0, len(kinds)+1)
	now := i.clock.Now()
	for _, kind := range kinds {
		envelopes = append(envelopes, eventlog.Envelope{
			Actor:        "bootstrap",
			Command:      "BootstrapModel",
			ModelVersion: 1,
			OccurredAt:   now,
			Event:        domain.KindRegistered{Version: 1, Kind: kind},
		})
	}
	envelopes = append(envelopes, eventlog.Envelope{
		Actor:        "bootstrap",
		Command:      "BootstrapModel",
		ModelVersion: 1,
		OccurredAt:   now,
		Event:        domain.ModelPublished{Version: 1},
	})
	if _, err := i.log.Append(ctx, eventlog.PlatformWorkspace, envelopes...); err != nil {
		return err
	}
	return i.projector.Project(ctx, eventlog.PlatformWorkspace)
}

func (i *IAM) project(ctx context.Context, ws eventlog.Workspace) error {
	return i.projector.Project(ctx, ws)
}

func (i *IAM) appendEvents(ctx context.Context, ws eventlog.Workspace, actor domain.Actor, command string, events ...domain.Event) (domain.Revision, error) {
	envelopes := make([]eventlog.Envelope, 0, len(events))
	now := i.clock.Now()
	for _, event := range events {
		envelopes = append(envelopes, eventlog.Envelope{
			Actor:        actor.ID,
			Command:      command,
			ModelVersion: i.store.ModelVersion(),
			OccurredAt:   now,
			Event:        event,
		})
	}
	return i.log.Append(ctx, ws, envelopes...)
}

func authorize(actor domain.Actor, roles ...domain.ActorRole) error {
	if err := actor.Validate(); err != nil {
		return err
	}
	for _, role := range roles {
		if actor.Role == role {
			return nil
		}
	}
	return fmt.Errorf("%w: role %q", domain.ErrForbidden, actor.Role)
}
