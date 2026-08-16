package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestApplicationFailsClosedForUnknownHostAndRoutes(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t)
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	monitor := NewMonitorHandler(store, EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })
	app := NewApplication(ApplicationConfig{MonitorHost: "monitor.example.test", IngestHost: "ingest.example.test", EnrollHost: "enroll.example.test"}, monitor, IngestService{Store: store, CA: ca, Now: func() time.Time { return now }}, EnrollmentHandler{Service: EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}}, CertificateRenewalHandler{Ingest: IngestService{Store: store, CA: ca, Now: func() time.Time { return now }}, CA: ca})

	unknown := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://unknown.example.test/", nil)
	request.Host = "unknown.example.test"
	app.ServeHTTP(unknown, request)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown host status = %d, want 404", unknown.Code)
	}

	monitorIngest := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://monitor.example.test/v1/reports", nil)
	request.Host = "monitor.example.test"
	app.ServeHTTP(monitorIngest, request)
	if monitorIngest.Code != http.StatusNotFound {
		t.Fatalf("monitor ingest status = %d, want 404", monitorIngest.Code)
	}

	ingest := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://ingest.example.test/v1/reports", nil)
	request.Host = "ingest.example.test"
	app.ServeHTTP(ingest, request)
	if ingest.Code != http.StatusUnauthorized {
		t.Fatalf("ingest missing certificate status = %d, want 401", ingest.Code)
	}

	publicMonitor := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "https://monitor.example.test/", nil)
	request.Host = "monitor.example.test"
	app.ServeHTTP(publicMonitor, request)
	if publicMonitor.Code != http.StatusOK {
		t.Fatalf("public monitor status = %d, want 200", publicMonitor.Code)
	}

	for _, path := range []string{"/login", "/setup"} {
		response := httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodGet, "https://monitor.example.test"+path, nil)
		request.Host = "monitor.example.test"
		app.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("removed auth route %s status = %d, want 404", path, response.Code)
		}
	}
}
