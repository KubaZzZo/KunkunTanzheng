package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestIngestAcceptsValidCertificateReport(t *testing.T) {
	fixture := newIngestFixture(t)
	report := probe.Report{NodeID: fixture.node.ID, CPUPercent: 25, Load1: 0.5}
	response := fixture.request(t, report)
	if response.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
	node, err := fixture.store.Node(context.Background(), fixture.node.ID, fixture.now)
	if err != nil || node.LatestSample == nil || node.LatestSample.CPUPercent != 25 {
		t.Fatalf("stored node = %#v, error=%v", node, err)
	}
}

func TestIngestAcceptsCaddyCertificateSerialQuery(t *testing.T) {
	fixture := newIngestFixture(t)
	payload, err := json.Marshal(probe.Report{NodeID: fixture.node.ID, CPUPercent: 12})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/reports?"+clientCertificateSerialQuery+"="+fixture.certificate.SerialNumber.Text(16), bytes.NewReader(payload))
	response := httptest.NewRecorder()
	fixture.ingest.HandleReport(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
}

func TestIngestRejectsMissingOrMismatchedCertificate(t *testing.T) {
	fixture := newIngestFixture(t)
	payload, err := json.Marshal(probe.Report{NodeID: fixture.node.ID})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	missing := httptest.NewRecorder()
	fixture.ingest.HandleReport(missing, httptest.NewRequest(http.MethodPost, "/v1/reports", bytes.NewReader(payload)))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing certificate status = %d, want 401", missing.Code)
	}

	mismatched := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/reports", bytes.NewReader([]byte(`{"node_id":"another-node"}`)))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{fixture.certificate}}
	fixture.ingest.HandleReport(mismatched, request)
	if mismatched.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched certificate status = %d, want 401", mismatched.Code)
	}
}

func TestIngestRejectsRevokedCertificateAndOversizedBody(t *testing.T) {
	fixture := newIngestFixture(t)
	over := probe.Report{NodeID: fixture.node.ID}
	payload, err := json.Marshal(over)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	payload = append([]byte(strings.Repeat(" ", probe.MaxReportJSONBytes-len(payload)+1)), payload...)
	response := fixture.requestRaw(payload)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413", response.Code)
	}

	if err := fixture.store.DisableNode(context.Background(), fixture.node.ID); err != nil {
		t.Fatalf("DisableNode() error = %v", err)
	}
	response = fixture.request(t, probe.Report{NodeID: fixture.node.ID})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked certificate status = %d, want 401", response.Code)
	}
}

func TestIngestLimitsEachNodeToFourReportsPerMinute(t *testing.T) {
	fixture := newIngestFixture(t)
	for i := 0; i < 4; i++ {
		response := fixture.request(t, probe.Report{NodeID: fixture.node.ID})
		if response.Code != http.StatusNoContent {
			t.Fatalf("report %d status = %d, want 204", i+1, response.Code)
		}
	}
	response := fixture.request(t, probe.Report{NodeID: fixture.node.ID})
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("limited report status = %d, want 429", response.Code)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("429 response has no Retry-After header")
	}
}

func TestSlidingWindowLimiterRemovesExpiredKeys(t *testing.T) {
	now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	limiter := NewSlidingWindowLimiter(2, time.Minute, func() time.Time { return now })
	if allowed, _ := limiter.Allow("stale"); !allowed {
		t.Fatal("first event was unexpectedly limited")
	}
	now = now.Add(2 * time.Minute)
	if allowed, _ := limiter.Allow("fresh"); !allowed {
		t.Fatal("fresh event was unexpectedly limited")
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, ok := limiter.events["stale"]; ok {
		t.Fatal("expired limiter key was retained")
	}
}

type ingestFixture struct {
	store       *Store
	ingest      IngestService
	node        Node
	certificate *x509.Certificate
	now         time.Time
}

func newIngestFixture(t *testing.T) ingestFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	store := openTestStore(t)
	node, err := store.CreateNode(ctx, "ingest-node", now)
	if err != nil {
		t.Fatalf("CreateNode() error = %v", err)
	}
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	enrollment := EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}
	code, err := enrollment.CreateEnrollmentCode(ctx, node.ID)
	if err != nil {
		t.Fatalf("CreateEnrollmentCode() error = %v", err)
	}
	issued, err := enrollment.Enroll(ctx, code, newTestCSR(t))
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	return ingestFixture{
		store:       store,
		node:        node,
		certificate: parseCertificatePEM(t, issued.CertificatePEM),
		now:         now,
		ingest: IngestService{
			Store: store,
			CA:    ca,
			Now:   func() time.Time { return now },
			ReportLimiter: NewSlidingWindowLimiter(4, time.Minute, func() time.Time {
				return now
			}),
		},
	}
}

func (f ingestFixture) request(t *testing.T, report probe.Report) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return f.requestRaw(payload)
}

func (f ingestFixture) requestRaw(payload []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/reports", bytes.NewReader(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.certificate}}
	response := httptest.NewRecorder()
	f.ingest.HandleReport(response, request)
	return response
}
