package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestApplicationFailsClosedForUnknownHostAndRoutes(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t)
	auth, err := NewAuthService(store, strings.Repeat("r", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	monitor := NewMonitorHandler(store, auth, EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })
	setup, err := NewSetupManager(auth, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSetupManager() error = %v", err)
	}
	app := NewApplication(ApplicationConfig{MonitorHost: "monitor.example.test", IngestHost: "ingest.example.test", EnrollHost: "enroll.example.test"}, monitor, IngestService{Store: store, CA: ca, Now: func() time.Time { return now }}, EnrollmentHandler{Service: EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}}, CertificateRenewalHandler{Ingest: IngestService{Store: store, CA: ca, Now: func() time.Time { return now }}, CA: ca}, setup)

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

	_ = context.Background()
}

func TestApplicationCompletesOneTimeSetupOverHTTP(t *testing.T) {
	now := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	store := openTestStore(t)
	auth, err := NewAuthService(store, strings.Repeat("s", 32), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	ca, err := LoadOrCreateCertificateAuthority(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCertificateAuthority() error = %v", err)
	}
	monitor := NewMonitorHandler(store, auth, EnrollmentService{Store: store, CA: ca, Now: func() time.Time { return now }}, "https://ingest.example.test/v1/reports", "https://enroll.example.test/v1/enroll", func() time.Time { return now })
	setup, err := NewSetupManager(auth, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSetupManager() error = %v", err)
	}
	token, secret, pending := setup.Pending()
	if !pending {
		t.Fatal("setup token is not pending")
	}
	app := NewApplication(ApplicationConfig{MonitorHost: "monitor.example.test", IngestHost: "ingest.example.test", EnrollHost: "enroll.example.test"}, monitor, IngestService{}, EnrollmentHandler{}, CertificateRenewalHandler{}, setup)

	get := httptest.NewRequest(http.MethodGet, "https://monitor.example.test/setup?token="+url.QueryEscape(token), nil)
	get.Host = "monitor.example.test"
	getResponse := httptest.NewRecorder()
	app.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), "Set up Server Probe") {
		t.Fatalf("setup GET status/body = %d/%q", getResponse.Code, getResponse.Body.String())
	}

	form := url.Values{"token": {token}, "password": {"password"}, "totp": {TOTPCode(secret, now)}}
	post := httptest.NewRequest(http.MethodPost, "https://monitor.example.test/setup", strings.NewReader(form.Encode()))
	post.Host = "monitor.example.test"
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://monitor.example.test")
	postResponse := httptest.NewRecorder()
	app.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusCreated || !strings.Contains(postResponse.Body.String(), "Recovery codes") {
		t.Fatalf("setup POST status/body = %d/%q", postResponse.Code, postResponse.Body.String())
	}
	if _, err := auth.Authenticate(context.Background(), "password", TOTPCode(secret, now)); err != nil {
		t.Fatalf("Authenticate() after setup error = %v", err)
	}

	used := httptest.NewRecorder()
	app.ServeHTTP(used, get)
	if used.Code != http.StatusNotFound {
		t.Fatalf("used setup token status = %d, want 404", used.Code)
	}
}
