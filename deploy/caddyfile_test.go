package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestCaddyfileRestrictsRoutesAndMethods(t *testing.T) {
	contents, err := os.ReadFile("Caddyfile")
	if err != nil {
		t.Fatalf("ReadFile(Caddyfile) error = %v", err)
	}
	config := string(contents)
	for _, required := range []string{
		"/static/trend.js",
		"@monitor-read {\n    method GET",
		"@monitor-write {\n    method POST",
		"@enroll {\n    method POST",
		"@ingest {\n    method POST",
		"trust_pool file /srv/probe-ca/agent-ca.crt",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("Caddyfile is missing %q", required)
		}
	}
	if strings.Contains(config, "probe-data") {
		t.Fatal("Caddyfile must not read the Probe Server private data volume")
	}
}
