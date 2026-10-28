package projector_test

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/engine"
	"github.com/laenenai/iam/internal/eventlog"
)

type testEvent struct {
	name string
}

func (e testEvent) EventType() string { return e.name }
func (e testEvent) Stream() string    { return "test:" + e.name }

func testEnvelope(event domain.Event, modelVersion int) eventlog.Envelope {
	return eventlog.Envelope{
		Actor:        "test-actor",
		Command:      "test-command",
		ModelVersion: modelVersion,
		Event:        event,
	}
}

func appendAll(t *testing.T, log eventlog.EventLog, ws eventlog.Workspace, events ...domain.Event) {
	t.Helper()
	envelopes := make([]eventlog.Envelope, 0, len(events))
	for _, event := range events {
		envelopes = append(envelopes, testEnvelope(event, 0))
	}
	if _, err := log.Append(context.Background(), ws, envelopes...); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func appendWithModel(t *testing.T, log eventlog.EventLog, ws eventlog.Workspace, modelVersion int, event domain.Event) {
	t.Helper()
	if _, err := log.Append(context.Background(), ws, testEnvelope(event, modelVersion)); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func mustWrite(t *testing.T, e engine.Engine, tuples ...engine.Tuple) {
	t.Helper()
	if err := e.Write(context.Background(), tuples...); err != nil {
		t.Fatalf("write: %v", err)
	}
}
