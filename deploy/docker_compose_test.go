package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestComposeKeepsProbeServerPrivateAndCaddyPublic(t *testing.T) {
	contents, err := os.ReadFile("../docker-compose.yml")
	if err != nil {
		t.Fatalf("ReadFile(docker-compose.yml) error = %v", err)
	}
	config := string(contents)
	for _, required := range []string{
		"  probe-server:\n",
		"  caddy:\n",
		"networks:\n  private:\n    internal: true\n  public:\n",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("docker-compose.yml is missing %q", required)
		}
	}
	probeServer := config[strings.Index(config, "  probe-server:\n"):strings.Index(config, "\n  caddy:\n")]
	if strings.Contains(probeServer, "      - public") {
		t.Fatal("Probe Server must not join the public network")
	}
	caddy := config[strings.Index(config, "  caddy:\n"):strings.Index(config, "\nvolumes:\n")]
	if !strings.Contains(caddy, "    networks:\n      - private\n      - public") {
		t.Fatal("Caddy must join both the private and public networks")
	}
}
