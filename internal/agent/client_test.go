package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

func TestReporterRejectsOversizedReportBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	reporter := Reporter{Client: server.Client(), Endpoint: server.URL}
	report := probe.Report{NodeID: strings.Repeat("x", probe.MaxReportJSONBytes)}

	if err := reporter.Send(context.Background(), report); err == nil {
		t.Fatal("Send() error = nil, want oversized report error")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server requests = %d, want 0", got)
	}
}

func TestReporterRetriesLatestReportAfterRateLimit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := Reporter{
		Client:   server.Client(),
		Endpoint: server.URL,
		Wait: func(context.Context, time.Duration) error {
			return nil
		},
	}
	if err := reporter.SendWithRetry(context.Background(), validReportForClient()); err != nil {
		t.Fatalf("SendWithRetry() error = %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("server requests = %d, want 2", got)
	}
}

func TestReporterStopsOnAuthenticationFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	reporter := Reporter{
		Client:   server.Client(),
		Endpoint: server.URL,
		Wait: func(context.Context, time.Duration) error {
			return errors.New("wait should not be called")
		},
	}
	err := reporter.SendWithRetry(context.Background(), validReportForClient())
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("SendWithRetry() error = %v, want ErrAuthentication", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server requests = %d, want 1", got)
	}
}

func TestReporterStopsBeforeSendingWhenCredentialCheckFails(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := Reporter{
		Client:   server.Client(),
		Endpoint: server.URL,
		BeforeReport: func(context.Context) error {
			return ErrAuthentication
		},
	}
	err := reporter.Run(context.Background(), func() (probe.Report, error) { return validReportForClient(), nil }, time.Hour, nil)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Run() error = %v, want ErrAuthentication", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server requests = %d, want 0", got)
	}
}

func TestNewMTLSClientUsesPlatformTrustForPublicServer(t *testing.T) {
	certificate, key, ca := renewalCredential(t)
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "client.crt")
	keyPath := filepath.Join(directory, "client.key")
	caPath := filepath.Join(directory, "ca.crt")
	for path, contents := range map[string][]byte{certificatePath: certificate, keyPath: key, caPath: ca} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	client, err := NewMTLSClient(certificatePath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewMTLSClient() error = %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if transport.TLSClientConfig.RootCAs != nil {
		t.Fatal("NewMTLSClient() replaced platform server trust with the Agent client CA")
	}
	if len(transport.TLSClientConfig.Certificates) != 1 || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS config = %#v", transport.TLSClientConfig)
	}
}

func validReportForClient() probe.Report {
	return probe.Report{NodeID: "node-01", CPUPercent: 10, Load1: 0.5}
}
