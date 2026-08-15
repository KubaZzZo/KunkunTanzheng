package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestStoreRecordsReportAndDerivesNodeState(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	node, err := store.CreateNode(ctx, "web-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	report := probe.Report{NodeID: node.ID, CPUPercent: 12.5, MemoryUsedBytes: 100, RootFilesystemUsedBytes: 200, Load1: 0.5, IngressBytesPerSecond: 3, EgressBytesPerSecond: 4}
	if err := store.RecordReport(ctx, report, now); err != nil {
		t.Fatalf("RecordReport() error = %v", err)
	}

	got, err := store.Node(ctx, node.ID, now)
	if err != nil {
		t.Fatalf("Node() error = %v", err)
	}
	if got.State != probe.StateOnline || got.LastReportAt == nil || !got.LastReportAt.Equal(now) {
		t.Fatalf("stored node = %#v, want online with report time", got)
	}
	if got.LatestSample == nil || got.LatestSample.CPUPercent != report.CPUPercent {
		t.Fatalf("latest sample = %#v, want report sample", got.LatestSample)
	}

	delayed, err := store.Node(ctx, node.ID, now.Add(91*time.Second))
	if err != nil || delayed.State != probe.StateDelayed {
		t.Fatalf("delayed node = %#v, error = %v", delayed, err)
	}
	offline, err := store.Node(ctx, node.ID, now.Add(181*time.Second))
	if err != nil || offline.State != probe.StateOffline {
		t.Fatalf("offline node = %#v, error = %v", offline, err)
	}
}

func TestStoreRejectsDisabledNodeReportsWithoutChangingLastReport(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	node, err := store.CreateNode(ctx, "db-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	if err := store.DisableNode(ctx, node.ID); err != nil {
		t.Fatalf("DisableNode() error = %v", err)
	}
	err = store.RecordReport(ctx, probe.Report{NodeID: node.ID}, now)
	if !errors.Is(err, ErrNodeDisabled) {
		t.Fatalf("RecordReport() error = %v, want ErrNodeDisabled", err)
	}
	got, err := store.Node(ctx, node.ID, now)
	if err != nil || got.LastReportAt != nil || got.State != probe.StateOffline {
		t.Fatalf("node after disabled report = %#v, error = %v", got, err)
	}
}

func TestStorePurgesSamplesOlderThanRetention(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	node, err := store.CreateNode(ctx, "cache-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	if err := store.RecordReport(ctx, probe.Report{NodeID: node.ID}, now.Add(-31*24*time.Hour)); err != nil {
		t.Fatalf("RecordReport(old) error = %v", err)
	}
	if err := store.RecordReport(ctx, probe.Report{NodeID: node.ID}, now); err != nil {
		t.Fatalf("RecordReport(current) error = %v", err)
	}
	if err := store.PurgeSamplesBefore(ctx, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("PurgeSamplesBefore() error = %v", err)
	}
	samples, err := store.SamplesSince(ctx, node.ID, now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("SamplesSince() error = %v", err)
	}
	if len(samples) != 1 || !samples[0].ReceivedAt.Equal(now) {
		t.Fatalf("retained samples = %#v, want only current sample", samples)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
