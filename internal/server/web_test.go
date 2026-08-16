package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestMonitorWorkflowCreatesFiltersDisablesAndRemovesNode(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	monitor := NewMonitorHandler(store, EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })

	createForm := url.Values{"display_name": {"web-01"}}
	create := monitorRequest(http.MethodPost, "/nodes", createForm.Encode(), "monitor.example.test")
	created := httptest.NewRecorder()
	monitor.ServeHTTP(created, create)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), "PROBE_ENROLL_CODE") {
		t.Fatalf("create status/body = %d/%q", created.Code, created.Body.String())
	}
	nodes, err := store.ListNodes(ctx, now)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes() = %#v, %v", nodes, err)
	}
	node := nodes[0]

	dashboard := httptest.NewRecorder()
	monitor.ServeHTTP(dashboard, monitorRequest(http.MethodGet, "/?q=web&state=pending", "", "monitor.example.test"))
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "web-01") || strings.Contains(dashboard.Body.String(), "PROBE_ENROLL_CODE") {
		t.Fatalf("dashboard status/body = %d/%q", dashboard.Code, dashboard.Body.String())
	}

	disable := httptest.NewRecorder()
	monitor.ServeHTTP(disable, monitorRequest(http.MethodPost, "/nodes/"+node.ID+"/disable", "", "monitor.example.test"))
	if disable.Code != http.StatusSeeOther {
		t.Fatalf("disable status = %d, want 303", disable.Code)
	}
	detail := httptest.NewRecorder()
	monitor.ServeHTTP(detail, monitorRequest(http.MethodGet, "/nodes/"+node.ID, "", "monitor.example.test"))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "offline") {
		t.Fatalf("detail status/body = %d/%q", detail.Code, detail.Body.String())
	}

	remove := httptest.NewRecorder()
	monitor.ServeHTTP(remove, monitorRequest(http.MethodPost, "/nodes/"+node.ID+"/remove", "", "monitor.example.test"))
	if remove.Code != http.StatusSeeOther {
		t.Fatalf("remove status = %d, want 303", remove.Code)
	}
	if _, err := store.Node(ctx, node.ID, now); err == nil {
		t.Fatal("removed node remains readable")
	}
}

func TestNodeDetailRenders24HourTrendChart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	node, err := store.CreateNode(ctx, "chart-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	if err := store.RecordReport(ctx, probe.Report{NodeID: node.ID, CPUPercent: 12.5, MemoryUsedBytes: 1024, RootFilesystemUsedBytes: 2048, Load1: 0.5, IngressBytesPerSecond: 64, EgressBytesPerSecond: 128}, now.Add(-time.Hour)); err != nil {
		t.Fatalf("RecordReport() error = %v", err)
	}
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	monitor := NewMonitorHandler(store, EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })

	detail := httptest.NewRecorder()
	monitor.ServeHTTP(detail, monitorRequest(http.MethodGet, "/nodes/"+node.ID, "", "monitor.example.test"))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `id="trend-chart"`) || !strings.Contains(detail.Body.String(), `data-trend=`) {
		t.Fatalf("detail status/body = %d/%q", detail.Code, detail.Body.String())
	}

	script := httptest.NewRecorder()
	monitor.ServeHTTP(script, httptest.NewRequest(http.MethodGet, "https://monitor.example.test/static/trend.js", nil))
	if script.Code != http.StatusOK || !strings.Contains(script.Body.String(), "renderTrend") {
		t.Fatalf("trend script status/body = %d/%q", script.Code, script.Body.String())
	}
}

func TestTrafficUsageIntegratesReportedRates(t *testing.T) {
	start := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	inbound, outbound := trafficUsage([]Sample{
		{ReceivedAt: start},
		{ReceivedAt: start.Add(30 * time.Second), IngressBytesPerSecond: 10, EgressBytesPerSecond: 4},
		{ReceivedAt: start.Add(60 * time.Second), IngressBytesPerSecond: 20, EgressBytesPerSecond: 8},
	})
	if inbound != 900 || outbound != 360 {
		t.Fatalf("trafficUsage() = %d/%d, want 900/360", inbound, outbound)
	}
}

func TestMonitorRenamesNodeFromDetailPage(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	node, err := store.CreateNode(ctx, "web-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	monitor := newTestMonitor(t, store, now)

	detail := httptest.NewRecorder()
	monitor.ServeHTTP(detail, monitorRequest(http.MethodGet, "/nodes/"+node.ID, "", "monitor.example.test"))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `action="/nodes/`+node.ID+`/rename"`) || !strings.Contains(detail.Body.String(), `name="display_name"`) || !strings.Contains(detail.Body.String(), `value="web-01"`) {
		t.Fatalf("detail page = %d/%q", detail.Code, detail.Body.String())
	}

	rename := httptest.NewRecorder()
	monitor.ServeHTTP(rename, monitorRequest(http.MethodPost, "/nodes/"+node.ID+"/rename", url.Values{"display_name": {"edge-web-01"}}.Encode(), "monitor.example.test"))
	if rename.Code != http.StatusSeeOther || rename.Header().Get("Location") != "/nodes/"+node.ID {
		t.Fatalf("rename response = %d, location %q", rename.Code, rename.Header().Get("Location"))
	}
	got, err := store.Node(ctx, node.ID, now)
	if err != nil || got.DisplayName != "edge-web-01" {
		t.Fatalf("Node() = %#v, %v", got, err)
	}
}

func TestMonitorRejectsInvalidNodeRename(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	node, err := store.CreateNode(ctx, "web-01", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	monitor := newTestMonitor(t, store, now)

	invalid := httptest.NewRecorder()
	monitor.ServeHTTP(invalid, monitorRequest(http.MethodPost, "/nodes/"+node.ID+"/rename", url.Values{"display_name": {"   "}}.Encode(), "monitor.example.test"))
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "display name must be between 1 and 128 bytes") || !strings.Contains(invalid.Body.String(), `value="   "`) {
		t.Fatalf("invalid rename response = %d/%q", invalid.Code, invalid.Body.String())
	}
	got, err := store.Node(ctx, node.ID, now)
	if err != nil || got.DisplayName != "web-01" {
		t.Fatalf("Node() = %#v, %v", got, err)
	}

	for _, request := range []*http.Request{
		monitorRequest(http.MethodGet, "/nodes/"+node.ID+"/rename", "", "monitor.example.test"),
		monitorRequest(http.MethodPost, "/nodes/missing/rename", "", "monitor.example.test"),
	} {
		response := httptest.NewRecorder()
		monitor.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want 404", request.Method, request.URL.Path, response.Code)
		}
	}
}

func newTestMonitor(t *testing.T, store *Store, now time.Time) *MonitorHandler {
	t.Helper()
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	return NewMonitorHandler(store, EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })
}

func monitorRequest(method, target, body, host string) *http.Request {
	request := httptest.NewRequest(method, "https://"+host+target, strings.NewReader(body))
	request.Host = host
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return request
}
