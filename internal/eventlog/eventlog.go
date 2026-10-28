// Package eventlog defines the append-only record and its adapters.
package eventlog

import (
	"context"
	"errors"
	"time"

	"github.com/laenenai/iam/internal/domain"
)

// Workspace is one isolated, ordered log. Every workspace maps to a tenant;
// PlatformWorkspace is the single exception, holding the deployment-wide model
// stream.
type Workspace string

// PlatformWorkspace is the deployment-wide model workspace.
const PlatformWorkspace Workspace = "_platform"

// TenantWorkspace returns the workspace for one tenant.
func TenantWorkspace(tenant domain.TenantID) Workspace {
	return Workspace(tenant)
}

// Errors returned by the memory adapter and expected from adapters.
var (
	ErrInvalidWorkspace = errors.New("eventlog: invalid workspace")
	ErrInvalidEnvelope  = errors.New("eventlog: invalid envelope")
)

// Envelope is the plaintext metadata around one sealed event payload.
type Envelope struct {
	Actor         string
	Command       string
	CorrelationID string
	CausationID   string
	ModelVersion  int
	OccurredAt    time.Time
	Event         domain.Event
}

// Recorded is one envelope at its immutable position in a workspace.
type Recorded struct {
	Workspace  Workspace
	Revision   domain.Revision
	Envelope   Envelope
	RecordedAt time.Time
}

// EventLog is the record. Appends are atomic per workspace and revisions are
// gapless.
type EventLog interface {
	Append(ctx context.Context, ws Workspace, envelopes ...Envelope) (domain.Revision, error)
	Read(ctx context.Context, ws Workspace, from domain.Revision, limit int) ([]Recorded, error)
	Head(ctx context.Context, ws Workspace) (domain.Revision, error)
}
