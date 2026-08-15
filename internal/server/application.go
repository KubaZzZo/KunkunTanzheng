package server

import (
	"net"
	"net/http"
	"strings"
)

type ApplicationConfig struct {
	MonitorHost string
	IngestHost  string
	EnrollHost  string
}

type Application struct {
	config     ApplicationConfig
	monitor    *MonitorHandler
	ingest     IngestService
	enrollment EnrollmentHandler
	renewal    CertificateRenewalHandler
	setup      *SetupManager
}

func NewApplication(config ApplicationConfig, monitor *MonitorHandler, ingest IngestService, enrollment EnrollmentHandler, renewal CertificateRenewalHandler, setup *SetupManager) *Application {
	config.MonitorHost = canonicalHost(config.MonitorHost)
	config.IngestHost = canonicalHost(config.IngestHost)
	config.EnrollHost = canonicalHost(config.EnrollHost)
	return &Application{config: config, monitor: monitor, ingest: ingest, enrollment: enrollment, renewal: renewal, setup: setup}
}

func (a *Application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch canonicalHost(r.Host) {
	case a.config.MonitorHost:
		if r.URL.Path == "/setup" {
			a.handleSetup(w, r)
			return
		}
		if a.monitor == nil {
			http.NotFound(w, r)
			return
		}
		a.monitor.ServeHTTP(w, r)
	case a.config.IngestHost:
		switch r.URL.Path {
		case "/v1/reports":
			a.ingest.HandleReport(w, r)
		case "/v1/certificates/renew":
			a.renewal.HandleRenew(w, r)
		default:
			http.NotFound(w, r)
		}
	case a.config.EnrollHost:
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		a.enrollment.HandleEnroll(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *Application) handleSetup(w http.ResponseWriter, r *http.Request) {
	if a.setup == nil || a.monitor == nil {
		http.NotFound(w, r)
		return
	}
	token, secret, pending := a.setup.Pending()
	if !pending {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if r.URL.Query().Get("token") != token {
			http.NotFound(w, r)
			return
		}
		a.monitor.render(w, http.StatusOK, "setup.html", pageData{Title: "Set up Server Probe", SetupToken: token, TOTPSecret: secret})
		return
	}
	if r.Method != http.MethodPost || !sameOrigin(r) || r.FormValue("token") != token {
		http.NotFound(w, r)
		return
	}
	recoveryCodes, err := a.setup.Complete(r.Context(), token, r.FormValue("password"), r.FormValue("totp"))
	if err != nil {
		a.monitor.render(w, http.StatusBadRequest, "setup.html", pageData{Title: "Set up Server Probe", SetupToken: token, TOTPSecret: secret, Error: "Unable to complete setup."})
		return
	}
	a.monitor.render(w, http.StatusCreated, "recovery.html", pageData{Title: "Recovery codes", RecoveryCodes: recoveryCodes})
}

func canonicalHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if value, _, err := net.SplitHostPort(host); err == nil {
		host = value
	}
	return strings.TrimSuffix(host, ".")
}
