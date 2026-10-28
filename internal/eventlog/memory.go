package eventlog

import (
	"context"
	"fmt"
	"sync"

	"github.com/laenenai/iam/internal/domain"
)

const defaultReadLimit = 128

// Memory is an in-memory EventLog for the reference implementation and tests.
type Memory struct {
	mu      sync.Mutex
	clock   domain.Clock
	streams map[Workspace][]Recorded
}

func NewMemory(clock domain.Clock) *Memory {
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &Memory{clock: clock, streams: make(map[Workspace][]Recorded)}
}

func (m *Memory) Append(ctx context.Context, ws Workspace, envelopes ...Envelope) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if ws == "" {
		return 0, fmt.Errorf("%w: empty", ErrInvalidWorkspace)
	}
	for i, envelope := range envelopes {
		if envelope.Event == nil {
			return 0, fmt.Errorf("%w: envelope %d has no event", ErrInvalidEnvelope, i)
		}
		if envelope.Actor == "" {
			return 0, fmt.Errorf("%w: envelope %d has no actor", ErrInvalidEnvelope, i)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	records := m.streams[ws]
	rev := domain.Revision(len(records))
	now := m.clock.Now()
	for _, envelope := range envelopes {
		rev++
		records = append(records, Recorded{
			Workspace:  ws,
			Revision:   rev,
			Envelope:   envelope,
			RecordedAt: now,
		})
	}
	m.streams[ws] = records
	return rev, nil
}

func (m *Memory) Read(ctx context.Context, ws Workspace, from domain.Revision, limit int) ([]Recorded, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ws == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidWorkspace)
	}
	if limit <= 0 {
		limit = defaultReadLimit
	}
	if from < 1 {
		from = 1
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	records := m.streams[ws]
	start := int(from - 1)
	if start >= len(records) {
		return nil, nil
	}
	end := start + limit
	if end > len(records) {
		end = len(records)
	}
	out := make([]Recorded, end-start)
	copy(out, records[start:end])
	return out, nil
}

func (m *Memory) Head(ctx context.Context, ws Workspace) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if ws == "" {
		return 0, fmt.Errorf("%w: empty", ErrInvalidWorkspace)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return domain.Revision(len(m.streams[ws])), nil
}
