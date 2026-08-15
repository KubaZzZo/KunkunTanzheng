# Server Probe MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a self-hosted, single-administrator Linux server probe with outbound-only agents, secure report ingestion, and an operational monitoring view.

**Architecture:** A Go Linux Agent samples `/proc` and the root filesystem, then reports a bounded JSON payload to a Go probe server. The server uses SQLite for node, certificate, sample, and administrator state; server receive time is authoritative. Caddy is the only public listener and routes the three defined hostnames to the private server.

**Tech Stack:** Go, `net/http`, `html/template`, SQLite 3 through `modernc.org/sqlite`, `golang.org/x/crypto`, Docker Compose, Caddy, systemd.

---

### Task 1: Establish the Go workspace and shared domain model

**Files:**
- Create: `go.mod`
- Create: `internal/probe/model.go`
- Test: `internal/probe/model_test.go`

- [ ] **Step 1: Write failing tests for report validation and state boundaries.**

```go
func TestNodeStateBoundaries(t *testing.T) {
    now := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
    if got := NodeStateAt(&now, now.Add(-90*time.Second), false); got != StateOnline { t.Fatal(got) }
    if got := NodeStateAt(&now, now.Add(-91*time.Second), false); got != StateDelayed { t.Fatal(got) }
    if got := NodeStateAt(&now, now.Add(-181*time.Second), false); got != StateOffline { t.Fatal(got) }
}
```

- [ ] **Step 2: Run `go test ./internal/probe` and verify it fails because the package is absent.**
- [ ] **Step 3: Define the report contract, node states, and validation limits.**
- [ ] **Step 4: Run `go test ./internal/probe` and verify it passes.**

### Task 2: Implement a test-driven Linux metric collector

**Files:**
- Create: `internal/agent/metrics.go`
- Test: `internal/agent/metrics_test.go`

- [ ] **Step 1: Write failing tests using fixture content for `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, and `/proc/net/dev`.**
- [ ] **Step 2: Run `go test ./internal/agent -run 'Test(Parse|Calculate)'` and verify each new behavior fails.**
- [ ] **Step 3: Parse the required values and calculate CPU/network deltas with reset-safe zero rates.**
- [ ] **Step 4: Run `go test ./internal/agent` and verify it passes.**

### Task 3: Implement the outbound-only Agent reporting loop

**Files:**
- Create: `internal/agent/client.go`
- Create: `cmd/probe-agent/main.go`
- Test: `internal/agent/client_test.go`
- Create: `deploy/systemd/probe-agent.service`

- [ ] **Step 1: Write failing transport tests for bounded report bodies, `429` retry handling, and terminal authentication failures.**
- [ ] **Step 2: Run `go test ./internal/agent -run TestReporter` and verify they fail.**
- [ ] **Step 3: Add mTLS HTTP transport, latest-sample-only retry behavior, and the `30s` default ticker.**
- [ ] **Step 4: Add a hardened systemd unit with a dedicated non-login user and no inbound listener.**
- [ ] **Step 5: Run `go test ./internal/agent` and verify it passes.**

### Task 4: Persist schema and node state in SQLite

**Files:**
- Create: `internal/server/store.go`
- Create: `internal/server/store_test.go`
- Modify: `internal/probe/model.go`

- [ ] **Step 1: Write failing integration tests using a temporary SQLite database for migrations, report transactions, state derivation, and sample retention.**
- [ ] **Step 2: Run `go test ./internal/server -run 'Test(Store|Retention)'` and verify the tests fail.**
- [ ] **Step 3: Implement WAL initialization, indexed schema migrations, atomic report storage, and 30-day/2-GiB cleanup.**
- [ ] **Step 4: Run `go test ./internal/server` and verify it passes.**

### Task 5: Build enrollment, certificate issuance, and ingest authorization

**Files:**
- Create: `internal/server/certificates.go`
- Create: `internal/server/ingest.go`
- Test: `internal/server/ingest_test.go`

- [ ] **Step 1: Write failing tests for expiring one-time enrollment codes, valid client certificates, revoked certificates, 8-KiB reports, and per-node rate limits.**
- [ ] **Step 2: Run `go test ./internal/server -run 'Test(Enroll|Ingest)'` and verify they fail.**
- [ ] **Step 3: Implement a local CA, 30-day node certificates, enrollment and renewal handlers, certificate serial revocation, request limits, and transactional report ingestion.**
- [ ] **Step 4: Run `go test ./internal/server` and verify it passes.**

### Task 6: Build administrator bootstrap, authentication, and CSRF protection

**Files:**
- Create: `internal/server/auth.go`
- Test: `internal/server/auth_test.go`
- Modify: `internal/server/store.go`

- [ ] **Step 1: Write failing tests for Argon2id password checks, TOTP/recovery-code verification, 12-hour secure sessions, login limits, and rejected invalid CSRF requests.**
- [ ] **Step 2: Run `go test ./internal/server -run 'Test(Auth|CSRF|Login)'` and verify they fail.**
- [ ] **Step 3: Implement console-only initial setup token, password plus TOTP login, hashed recovery codes, server sessions, same-origin enforcement, and CSRF validation.**
- [ ] **Step 4: Run `go test ./internal/server` and verify it passes.**

### Task 7: Render the administrator monitoring workflow

**Files:**
- Create: `internal/server/web.go`
- Create: `web/templates/*.html`
- Create: `web/static/app.css`
- Test: `internal/server/web_test.go`

- [ ] **Step 1: Write failing HTTP tests for login protection, dashboard filters, node detail trends, node creation, disable, and removal.**
- [ ] **Step 2: Run `go test ./internal/server -run TestWeb` and verify they fail.**
- [ ] **Step 3: Add server-rendered dashboard/detail pages and CSRF-protected management forms. Never render secrets after their one allowed display.**
- [ ] **Step 4: Run `go test ./internal/server` and verify it passes.**

### Task 8: Wire the server binary and deployable runtime

**Files:**
- Create: `cmd/probe-server/main.go`
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `deploy/Caddyfile`
- Create: `deploy/backup.sh`
- Create: `.dockerignore`
- Modify: `README.md`

- [ ] **Step 1: Write a failing smoke test that starts the application with a temporary database and asserts unknown hosts/routes fail closed.**
- [ ] **Step 2: Run `go test ./cmd/probe-server` and verify it fails.**
- [ ] **Step 3: Wire HTTPS-aware host routing, private application binding, non-root runtime images, named volumes, daily SQLite backups, and only Caddy port `443`.**
- [ ] **Step 4: Run `go test ./...`, `go vet ./...`, `gosec ./...`, and `govulncheck ./...`; resolve failures before release.**

### Task 9: Verify the acceptance path

**Files:**
- Test: `internal/server/e2e_test.go`
- Modify: `README.md`

- [ ] **Step 1: Add an end-to-end test covering node creation, enrollment, mTLS report acceptance, dashboard state, disable/revocation, and rejected follow-up reports.**
- [ ] **Step 2: Run `go test ./... -race` and verify all packages pass.**
- [ ] **Step 3: Document the build, administrator bootstrap, deployment, agent install, backup, and restore commands.**
