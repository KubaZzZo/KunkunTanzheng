package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/agent"
	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestEndToEndEnrollmentReportingAndRevocation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := openTestStore(t)
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	enrollment := EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}
	monitor := NewMonitorHandler(store, enrollment, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })
	ingest := IngestService{Store: store, CA: ca, Now: func() time.Time { return now }, ReportLimiter: NewSlidingWindowLimiter(4, time.Minute, func() time.Time { return now })}
	application := NewApplication(
		ApplicationConfig{MonitorHost: "monitor.example.test", IngestHost: "ingest.example.test", EnrollHost: "enroll.example.test"},
		monitor,
		ingest,
		EnrollmentHandler{Service: enrollment, Limiter: NewSlidingWindowLimiter(5, 15*time.Minute, func() time.Time { return now })},
		CertificateRenewalHandler{Ingest: ingest, CA: ca},
	)

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll":
			r.Host = "enroll.example.test"
		case "/v1/reports", "/v1/certificates/renew":
			r.Host = "ingest.example.test"
		default:
			r.Host = "monitor.example.test"
		}
		application.ServeHTTP(w, r)
	}))
	testServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequestClientCert}
	testServer.StartTLS()
	defer testServer.Close()
	monitorClient := *testServer.Client()
	monitorClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	create := newEndToEndRequest(http.MethodPost, testServer.URL+"/nodes", url.Values{"display_name": {"edge-01"}}.Encode())
	created, err := testServer.Client().Do(create)
	if err != nil {
		t.Fatalf("create node request: %v", err)
	}
	createBody := readResponseBody(t, created)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, body=%q", created.StatusCode, createBody)
	}
	match := regexp.MustCompile(`PROBE_ENROLL_CODE=&#39;([^&]+)&#39;`).FindStringSubmatch(createBody)
	if len(match) != 2 {
		t.Fatalf("could not find enrollment code in %q", createBody)
	}
	nodes, err := store.ListNodes(ctx, now)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes() = %#v, %v", nodes, err)
	}
	node := nodes[0]

	credentials := t.TempDir()
	certificatePath := filepath.Join(credentials, "client.crt")
	keyPath := filepath.Join(credentials, "client.key")
	caPath := filepath.Join(credentials, "ca.crt")
	if err := (agent.EnrollmentClient{Client: testServer.Client(), Endpoint: testServer.URL + "/v1/enroll"}).Enroll(ctx, match[1], certificatePath, keyPath, caPath); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	reporter := agent.Reporter{Client: endToEndMTLSClient(t, testServer, certificatePath, keyPath), Endpoint: testServer.URL + "/v1/reports"}
	report := probe.Report{NodeID: node.ID, CPUPercent: 15, MemoryUsedBytes: 1024, RootFilesystemUsedBytes: 2048, Load1: 0.4, IngressBytesPerSecond: 64, EgressBytesPerSecond: 32}
	if err := reporter.Send(ctx, report); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	dashboard := newEndToEndRequest(http.MethodGet, testServer.URL+"/?state=online", "")
	dashboardResponse, err := testServer.Client().Do(dashboard)
	if err != nil {
		t.Fatalf("dashboard request: %v", err)
	}
	dashboardBody := readResponseBody(t, dashboardResponse)
	if dashboardResponse.StatusCode != http.StatusOK || !strings.Contains(dashboardBody, "edge-01") || !strings.Contains(dashboardBody, "online") {
		t.Fatalf("dashboard status/body = %d/%q", dashboardResponse.StatusCode, dashboardBody)
	}

	disable := newEndToEndRequest(http.MethodPost, testServer.URL+"/nodes/"+node.ID+"/disable", "")
	disableResponse, err := monitorClient.Do(disable)
	if err != nil {
		t.Fatalf("disable request: %v", err)
	}
	_ = readResponseBody(t, disableResponse)
	if disableResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("disable status = %d, want 303", disableResponse.StatusCode)
	}
	if err := reporter.Send(ctx, report); !errors.Is(err, agent.ErrAuthentication) {
		t.Fatalf("Send() after revoke error = %v, want ErrAuthentication", err)
	}
}

func newEndToEndRequest(method, target, body string) *http.Request {
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return request
}

func endToEndMTLSClient(t *testing.T, testServer *httptest.Server, certificatePath, keyPath string) *http.Client {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair() error = %v", err)
	}
	transport := testServer.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

func readResponseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(contents)
}
