package main

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRequiresIdentityAndEndpoint(t *testing.T) {
	_, err := loadConfig(func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "PROBE_ENDPOINT") {
		t.Fatalf("loadConfig() error = %v, want missing endpoint", err)
	}
}

func TestLoadConfigUsesSecureDefaults(t *testing.T) {
	values := map[string]string{
		"PROBE_ENDPOINT": "https://ingest.example.test/v1/reports",
		"PROBE_NODE_ID":  "node-01",
	}
	config, err := loadConfig(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if config.Interval != 30*time.Second {
		t.Fatalf("interval = %s, want 30s", config.Interval)
	}
	if config.CertFile != "/var/lib/probe-agent/client.crt" || config.KeyFile != "/var/lib/probe-agent/client.key" || config.CAFile != "/var/lib/probe-agent/ca.crt" {
		t.Fatalf("unexpected credential paths: %#v", config)
	}
	if config.RenewEndpoint != "https://ingest.example.test/v1/certificates/renew" {
		t.Fatalf("renewal endpoint = %q", config.RenewEndpoint)
	}
}

func TestLoadConfigRejectsNonPositiveInterval(t *testing.T) {
	values := map[string]string{
		"PROBE_ENDPOINT": "https://ingest.example.test/v1/reports",
		"PROBE_NODE_ID":  "node-01",
		"PROBE_INTERVAL": "0s",
	}
	_, err := loadConfig(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err == nil {
		t.Fatal("loadConfig() error = nil, want invalid interval")
	}
}

func TestLoadConfigRequiresEnrollmentEndpointWhenCodeIsPresent(t *testing.T) {
	values := map[string]string{
		"PROBE_ENDPOINT":    "https://ingest.example.test/v1/reports",
		"PROBE_NODE_ID":     "node-01",
		"PROBE_ENROLL_CODE": "one-time-code",
	}
	_, err := loadConfig(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err == nil || !strings.Contains(err.Error(), "PROBE_ENROLL_ENDPOINT") {
		t.Fatalf("loadConfig() error = %v, want missing enrollment endpoint", err)
	}
}
