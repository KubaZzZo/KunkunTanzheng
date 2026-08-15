package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestStoreListsAndRemovesNodes(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	first, err := store.CreateNode(ctx, "api-01", now)
	if err != nil {
		t.Fatalf("CreateNode(first) error = %v", err)
	}
	second, err := store.CreateNode(ctx, "db-01", now)
	if err != nil {
		t.Fatalf("CreateNode(second) error = %v", err)
	}
	if err := store.RecordReport(ctx, probe.Report{NodeID: second.ID}, now); err != nil {
		t.Fatalf("RecordReport() error = %v", err)
	}
	nodes, err := store.ListNodes(ctx, now)
	if err != nil {
		t.Fatalf("ListNodes() error = %v", err)
	}
	if len(nodes) != 2 || nodes[0].DisplayName != "api-01" || nodes[0].State != probe.StatePending || nodes[1].State != probe.StateOnline {
		t.Fatalf("nodes = %#v", nodes)
	}
	if err := store.RemoveNode(ctx, first.ID); err != nil {
		t.Fatalf("RemoveNode() error = %v", err)
	}
	if _, err := store.Node(ctx, first.ID, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("removed Node() error = %v, want ErrNodeNotFound", err)
	}
}
