package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kunkuntanzheng/server-probe/internal/agent"
	"github.com/kunkuntanzheng/server-probe/internal/probe"
)

type config struct {
	Endpoint       string
	NodeID         string
	CertFile       string
	KeyFile        string
	CAFile         string
	Interval       time.Duration
	EnrollEndpoint string
	EnrollCode     string
	RenewEndpoint  string
}

func main() {
	if runtime.GOOS != "linux" {
		log.Print("probe-agent only supports Linux")
		return
	}
	config, err := loadConfig(os.LookupEnv)
	if err != nil {
		log.Printf("invalid configuration: %v", err)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := ensureCredentials(ctx, config); err != nil {
		log.Printf("initialize agent credentials: %v", err)
		return
	}
	client, err := agent.NewMTLSClient(config.CertFile, config.KeyFile, config.CAFile)
	if err != nil {
		log.Printf("initialize mTLS client: %v", err)
		return
	}
	reporter := agent.Reporter{Client: client, Endpoint: config.Endpoint}
	configureCertificateRenewal(&reporter, config)
	collector := agent.NewCollector(nil, nil)
	err = reporter.Run(ctx, func() (report probe.Report, err error) {
		return collector.Sample(config.NodeID)
	}, config.Interval, func(err error) {
		log.Printf("report failed: %v", err)
	})
	if err != nil && err != context.Canceled {
		log.Printf("agent stopped: %v", err)
	}
}

func loadConfig(lookup func(string) (string, bool)) (config, error) {
	endpoint, err := required(lookup, "PROBE_ENDPOINT")
	if err != nil {
		return config{}, err
	}
	nodeID, err := required(lookup, "PROBE_NODE_ID")
	if err != nil {
		return config{}, err
	}
	interval := 30 * time.Second
	if raw, ok := lookup("PROBE_INTERVAL"); ok && strings.TrimSpace(raw) != "" {
		interval, err = time.ParseDuration(raw)
		if err != nil || interval <= 0 {
			return config{}, fmt.Errorf("PROBE_INTERVAL must be a positive duration")
		}
	}
	enrollCode := optional(lookup, "PROBE_ENROLL_CODE", "")
	enrollEndpoint := optional(lookup, "PROBE_ENROLL_ENDPOINT", "")
	if enrollCode != "" && enrollEndpoint == "" {
		return config{}, fmt.Errorf("PROBE_ENROLL_ENDPOINT is required when PROBE_ENROLL_CODE is set")
	}
	renewEndpoint := optional(lookup, "PROBE_RENEW_ENDPOINT", "")
	if renewEndpoint == "" {
		renewEndpoint, err = deriveRenewalEndpoint(endpoint)
		if err != nil {
			return config{}, err
		}
	}
	return config{
		Endpoint:       endpoint,
		NodeID:         nodeID,
		CertFile:       optional(lookup, "PROBE_CERT", "/var/lib/probe-agent/client.crt"),
		KeyFile:        optional(lookup, "PROBE_KEY", "/var/lib/probe-agent/client.key"),
		CAFile:         optional(lookup, "PROBE_CA", "/var/lib/probe-agent/ca.crt"),
		Interval:       interval,
		EnrollEndpoint: enrollEndpoint,
		EnrollCode:     enrollCode,
		RenewEndpoint:  renewEndpoint,
	}, nil
}

func configureCertificateRenewal(reporter *agent.Reporter, config config) {
	renewer := agent.CertificateRenewer{
		Endpoint:        config.RenewEndpoint,
		CertificatePath: config.CertFile,
		KeyPath:         config.KeyFile,
		CAPath:          config.CAFile,
	}
	nextCheck := time.Time{}
	reporter.BeforeReport = func(ctx context.Context) error {
		now := time.Now()
		if now.Before(nextCheck) {
			return nil
		}
		nextCheck = now.Add(time.Hour)
		renewer.Client = reporter.Client
		renewed, err := renewer.RenewIfDue(ctx)
		if err != nil || !renewed {
			return err
		}
		client, err := agent.NewMTLSClient(config.CertFile, config.KeyFile, config.CAFile)
		if err != nil {
			return fmt.Errorf("reload renewed mTLS client: %w", err)
		}
		reporter.Client = client
		return nil
	}
}

func deriveRenewalEndpoint(reportEndpoint string) (string, error) {
	parsed, err := url.Parse(reportEndpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", fmt.Errorf("PROBE_ENDPOINT must be an HTTPS URL")
	}
	parsed.Path = "/v1/certificates/renew"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func ensureCredentials(ctx context.Context, config config) error {
	paths := []string{config.CertFile, config.KeyFile, config.CAFile}
	existing := 0
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			existing++
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect agent credential: %w", err)
		}
	}
	if existing == len(paths) {
		return nil
	}
	if existing != 0 {
		return fmt.Errorf("agent credentials are incomplete; remove them before registering again")
	}
	if config.EnrollCode == "" || config.EnrollEndpoint == "" {
		return fmt.Errorf("agent credentials are absent; set enrollment configuration")
	}
	return (agent.EnrollmentClient{Endpoint: config.EnrollEndpoint}).Enroll(ctx, config.EnrollCode, config.CertFile, config.KeyFile, config.CAFile)
}

func required(lookup func(string) (string, bool), name string) (string, error) {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return strings.TrimSpace(value), nil
}

func optional(lookup func(string) (string, bool), name, fallback string) string {
	value, ok := lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
