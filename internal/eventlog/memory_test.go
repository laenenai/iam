package eventlog_test

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
	"github.com/laenenai/iam/internal/eventlog/eventlogtest"
)

func TestMemoryEventLog(t *testing.T) {
	eventlogtest.RunSuite(t, func(_ *testing.T) eventlog.EventLog {
		return eventlog.NewMemory(domain.FixedClock{})
	})
}

type memoryTestEvent string

func (e memoryTestEvent) EventType() string { return "memory.test" }
func (e memoryTestEvent) Stream() string    { return "memory:test" }

func testEnvelope(event string) eventlog.Envelope {
	return eventlog.Envelope{Actor: "a", Command: "test", Event: memoryTestEvent(event)}
}

func TestAppendReturnsGaplessRevisions(t *testing.T) {
	log := eventlog.NewMemory(domain.FixedClock{})
	ws := eventlog.TenantWorkspace("t")
	rev, err := log.Append(context.Background(), ws, testEnvelope("a"), testEnvelope("b"))
	if err != nil || rev != 2 {
		t.Fatalf("rev=%d err=%v", rev, err)
	}
	records, err := log.Read(context.Background(), ws, 1, 10)
	if err != nil || len(records) != 2 || records[0].Revision != 1 || records[1].Revision != 2 {
		t.Fatalf("%#v %v", records, err)
	}
}
