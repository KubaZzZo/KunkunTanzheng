package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRequiresDistinctPublicHosts(t *testing.T) {
	_, err := loadConfig(func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "PROBE_MONITOR_HOST") {
		t.Fatalf("loadConfig() error = %v, want missing monitor host", err)
	}
}

func TestPublishAgentCAPublicCertificateWritesOnlyCertificate(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "public", "agent-ca.crt")
	want := []byte("public certificate")
	if err := publishAgentCAPublicCertificate(destination, want); err != nil {
		t.Fatalf("publishAgentCAPublicCertificate() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("public certificate = %q, want %q", got, want)
	}
}

func TestLoadConfigRejectsOverlappingPrivateDirectories(t *testing.T) {
	values := map[string]string{
		"PROBE_MONITOR_HOST":           "monitor.example.test",
		"PROBE_INGEST_HOST":            "ingest.example.test",
		"PROBE_ENROLL_HOST":            "enroll.example.test",
		"PROBE_DATA_DIRECTORY":         "/var/lib/shared",
		"PROBE_SECRETS_DIRECTORY":      "/var/lib/shared",
		"PROBE_AGENT_CA_DIRECTORY":     "/var/lib/agent-ca",
		"PROBE_AGENT_CA_PUBLIC_DIRECTORY": "/var/lib/agent-ca-public",
	}
	_, err := loadConfig(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("loadConfig() error = %v, want private directory separation error", err)
	}
}

func TestLoadConfigUsesPrivateRuntimeDefaults(t *testing.T) {
	values := map[string]string{
		"PROBE_MONITOR_HOST": "monitor.example.test",
		"PROBE_INGEST_HOST":  "ingest.example.test",
		"PROBE_ENROLL_HOST":  "enroll.example.test",
	}
	config, err := loadConfig(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if config.ListenAddress != ":8080" || config.DataDirectory != "/var/lib/server-probe" {
		t.Fatalf("config = %#v", config)
	}
	if config.SecretsDirectory == config.DataDirectory || config.AgentCADirectory == config.DataDirectory || config.SecretsDirectory == config.AgentCADirectory {
		t.Fatalf("private persistence paths must be distinct: %#v", config)
	}
}
