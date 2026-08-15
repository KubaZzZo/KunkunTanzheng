package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestStoreMaintainsRetentionAndCreatesBackup(t *testing.T) {
	ctx := context.Background()
	database := filepath.Join(t.TempDir(), "probe.db")
	store, err := Open(database)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	node, err := store.CreateNode(ctx, "backup-node", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	if err := store.RecordReport(ctx, probe.Report{NodeID: node.ID}, now.Add(-31*24*time.Hour)); err != nil {
		t.Fatalf("RecordReport(old) error = %v", err)
	}
	if err := store.RecordReport(ctx, probe.Report{NodeID: node.ID}, now); err != nil {
		t.Fatalf("RecordReport(current) error = %v", err)
	}
	if err := store.MaintainSamples(ctx, now, 2*1024*1024*1024); err != nil {
		t.Fatalf("MaintainSamples() error = %v", err)
	}
	samples, err := store.SamplesSince(ctx, node.ID, now.Add(-90*24*time.Hour))
	if err != nil || len(samples) != 1 || !samples[0].ReceivedAt.Equal(now) {
		t.Fatalf("samples after maintenance = %#v, error=%v", samples, err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := store.BackupTo(ctx, backup); err != nil {
		t.Fatalf("BackupTo() error = %v", err)
	}
	restored, err := Open(backup)
	if err != nil {
		t.Fatalf("Open(backup) error = %v", err)
	}
	defer restored.Close()
	if _, err := restored.Node(ctx, node.ID, now); err != nil {
		t.Fatalf("backup Node() error = %v", err)
	}
}

func TestStoreKeepsSevenDailyBackups(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	directory := t.TempDir()
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for day := 0; day < 8; day++ {
		if _, err := store.BackupDaily(ctx, directory, start.AddDate(0, 0, day)); err != nil {
			t.Fatalf("BackupDaily(day %d) error = %v", day, err)
		}
	}
	entries, err := filepath.Glob(filepath.Join(directory, "probe-*.db"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("backup count = %d, want 7", len(entries))
	}
}

func TestBackupStatementUsesBoundDestination(t *testing.T) {
	if got := backupStatement(); got != "VACUUM INTO ?" {
		t.Fatalf("backupStatement() = %q, want parameterized VACUUM", got)
	}
}
