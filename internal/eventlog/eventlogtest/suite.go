// Package eventlogtest is the conformance suite for an EventLog adapter.
package eventlogtest

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

type testEvent struct {
	name string
}

func (e testEvent) EventType() string { return "test." + e.name }
func (e testEvent) Stream() string    { return "test:" + e.name }

func testEnvelope(event string) eventlog.Envelope {
	return eventlog.Envelope{
		Actor:   "test-actor",
		Command: "test-command",
		Event:   testEvent{name: event},
	}
}

// RunSuite runs the authoritative contract for an event log adapter.
func RunSuite(t *testing.T, newLog func(t *testing.T) eventlog.EventLog) {
	t.Helper()

	t.Run("AppendReadHead", func(t *testing.T) {
		log := newLog(t)
		ws := eventlog.TenantWorkspace("t")
		rev, err := log.Append(context.Background(), ws, testEnvelope("a"), testEnvelope("b"))
		if err != nil || rev != 2 {
			t.Fatalf("append: rev=%d err=%v", rev, err)
		}
		head, err := log.Head(context.Background(), ws)
		if err != nil || head != 2 {
			t.Fatalf("head: %d %v", head, err)
		}
		records, err := log.Read(context.Background(), ws, 1, 10)
		if err != nil || len(records) != 2 {
			t.Fatalf("read: %#v %v", records, err)
		}
		for i, rec := range records {
			if rec.Revision != domain.Revision(i+1) || rec.Workspace != ws {
				t.Fatalf("record %d: %#v", i, rec)
			}
			if rec.Envelope.Actor != "test-actor" || rec.Envelope.Event.EventType() != "test."+string(rune('a'+i)) {
				t.Fatalf("envelope %d: %#v", i, rec.Envelope)
			}
			if rec.RecordedAt.IsZero() {
				t.Fatalf("record %d has zero recorded-at", i)
			}
		}
	})

	t.Run("GaplessRevisions", func(t *testing.T) {
		log := newLog(t)
		ws := eventlog.TenantWorkspace("t")
		for i := 0; i < 5; i++ {
			if _, err := log.Append(context.Background(), ws, testEnvelope("x")); err != nil {
				t.Fatal(err)
			}
		}
		records, err := log.Read(context.Background(), ws, 1, 0)
		if err != nil || len(records) != 5 {
			t.Fatalf("read: %d %v", len(records), err)
		}
		for i, rec := range records {
			if rec.Revision != domain.Revision(i+1) {
				t.Fatalf("gap at %d: %#v", i, rec)
			}
		}
	})

	t.Run("WorkspaceIsolation", func(t *testing.T) {
		log := newLog(t)
		a := eventlog.TenantWorkspace("a")
		b := eventlog.TenantWorkspace("b")
		if _, err := log.Append(context.Background(), a, testEnvelope("a")); err != nil {
			t.Fatal(err)
		}
		if head, err := log.Head(context.Background(), b); err != nil || head != 0 {
			t.Fatalf("head b: %d %v", head, err)
		}
		if records, err := log.Read(context.Background(), b, 1, 10); err != nil || len(records) != 0 {
			t.Fatalf("read b: %#v %v", records, err)
		}
		if rev, err := log.Append(context.Background(), b, testEnvelope("b")); err != nil || rev != 1 {
			t.Fatalf("append b: %d %v", rev, err)
		}
	})

	t.Run("LimitAndFrom", func(t *testing.T) {
		log := newLog(t)
		ws := eventlog.TenantWorkspace("t")
		if _, err := log.Append(context.Background(), ws, testEnvelope("a"), testEnvelope("b"), testEnvelope("c")); err != nil {
			t.Fatal(err)
		}
		records, err := log.Read(context.Background(), ws, 1, 2)
		if err != nil || len(records) != 2 || records[0].Revision != 1 || records[1].Revision != 2 {
			t.Fatalf("limit: %#v %v", records, err)
		}
		records, err = log.Read(context.Background(), ws, 2, 0)
		if err != nil || len(records) != 2 || records[0].Revision != 2 {
			t.Fatalf("from: %#v %v", records, err)
		}
		records, err = log.Read(context.Background(), ws, 4, 10)
		if err != nil || len(records) != 0 {
			t.Fatalf("past head: %#v %v", records, err)
		}
	})

	t.Run("ReplayIsStable", func(t *testing.T) {
		log := newLog(t)
		ws := eventlog.TenantWorkspace("t")
		if _, err := log.Append(context.Background(), ws, testEnvelope("a"), testEnvelope("b")); err != nil {
			t.Fatal(err)
		}
		first, err := log.Read(context.Background(), ws, 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		second, err := log.Read(context.Background(), ws, 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("replay differs: %#v vs %#v", first, second)
		}
	})

	t.Run("RejectsInvalidAppends", func(t *testing.T) {
		log := newLog(t)
		ws := eventlog.TenantWorkspace("t")
		if _, err := log.Append(context.Background(), "", testEnvelope("a")); err == nil {
			t.Fatal("empty workspace accepted")
		}
		if _, err := log.Append(context.Background(), ws, eventlog.Envelope{Actor: "a"}); err == nil {
			t.Fatal("nil event accepted")
		}
		if _, err := log.Append(context.Background(), ws, eventlog.Envelope{Event: testEvent{name: "a"}}); err == nil {
			t.Fatal("empty actor accepted")
		}
		if head, err := log.Head(context.Background(), ws); err != nil || head != 0 {
			t.Fatalf("failed appends advanced head: %d %v", head, err)
		}
	})

	t.Run("ConcurrentAppendsAreGapless", func(t *testing.T) {
		log := newLog(t)
		ws := eventlog.TenantWorkspace("t")
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := log.Append(context.Background(), ws, testEnvelope("x")); err != nil {
					t.Errorf("append: %v", err)
				}
			}()
		}
		wg.Wait()
		records, err := log.Read(context.Background(), ws, 1, 0)
		if err != nil || len(records) != 20 {
			t.Fatalf("read: %d %v", len(records), err)
		}
		for i, rec := range records {
			if rec.Revision != domain.Revision(i+1) {
				t.Fatalf("gap at %d: %#v", i, rec)
			}
		}
	})
}
