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
}

func NewApplication(config ApplicationConfig, monitor *MonitorHandler, ingest IngestService, enrollment EnrollmentHandler, renewal CertificateRenewalHandler) *Application {
	config.MonitorHost = canonicalHost(config.MonitorHost)
	config.IngestHost = canonicalHost(config.IngestHost)
	config.EnrollHost = canonicalHost(config.EnrollHost)
	return &Application{config: config, monitor: monitor, ingest: ingest, enrollment: enrollment, renewal: renewal}
}

func (a *Application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch canonicalHost(r.Host) {
	case a.config.MonitorHost:
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

func canonicalHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if value, _, err := net.SplitHostPort(host); err == nil {
		host = value
	}
	return strings.TrimSuffix(host, ".")
}
