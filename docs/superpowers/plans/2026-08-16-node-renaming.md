# Node Renaming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename an existing monitoring node without changing its identity, credentials, reports, or state.

**Architecture:** The store validates and updates only `nodes.display_name`; a form-only monitor route calls it and redirects to the same detail page. Invalid form posts re-render the existing detail data with the submitted name and error. No schema or Agent protocol changes are needed.

**Tech Stack:** Go 1.25.13, `net/http`, `html/template`, SQLite, Docker Compose, Caddy.

---

## File Structure

- Modify: `internal/server/store.go` - name validation and one-column update.
- Modify: `internal/server/store_test.go` - storage behavior.
- Modify: `internal/server/web.go` - route, redirect, and error rendering.
- Modify: `internal/server/web_test.go` - handler behavior.
- Modify: `internal/server/templates/node.html` - rename form.
- Modify: `internal/server/static/app.css` - responsive form layout.

### Task 1: Store Rename Method

**Files:**
- Modify: `internal/server/store.go:142-171`
- Modify: `internal/server/store_test.go`

- [ ] **Step 1: Write failing tests**

Add tests calling `store.RenameNode(ctx, node.ID, "  public-web-01  ")` after recording a `CPUPercent: 12.5` report. Assert the stored node has the same ID, an online state, unchanged latest sample, and name `public-web-01`. Add a second test that attempts `"   "` and `strings.Repeat("a", 129)`, requires each call to fail, then asserts the name is still `web-01`.

- [ ] **Step 2: Verify failure**

Run: `$env:GOTOOLCHAIN='go1.25.13'; & 'D:\CodeTools\Go\go\bin\go.exe' test ./internal/server -run 'TestStore(Renames|RejectsInvalidRename)' -count=1`

Expected: FAIL because `Store.RenameNode` is undefined.

- [ ] **Step 3: Implement the smallest store API**

Extract the current `CreateNode` trim-and-length check into:

```go
func normalizeDisplayName(displayName string) (string, error) {
    displayName = strings.TrimSpace(displayName)
    if displayName == "" || len(displayName) > 128 {
        return "", fmt.Errorf("display name must be between 1 and 128 bytes")
    }
    return displayName, nil
}
```

Use it from `CreateNode` and add this method:

```go
func (s *Store) RenameNode(ctx context.Context, nodeID, displayName string) error {
    displayName, err := normalizeDisplayName(displayName)
    if err != nil { return err }
    result, err := s.db.ExecContext(ctx, "UPDATE nodes SET display_name = ? WHERE id = ?", displayName, nodeID)
    if err != nil { return fmt.Errorf("rename node: %w", err) }
    changed, err := result.RowsAffected()
    if err != nil { return fmt.Errorf("count renamed nodes: %w", err) }
    if changed == 0 { return ErrNodeNotFound }
    return nil
}
```

- [ ] **Step 4: Verify pass and commit**

Run the Step 2 command; expected PASS. Then run:

```powershell
git add internal/server/store.go internal/server/store_test.go
git commit -m "feat: allow node renaming"
```

### Task 2: HTTP Route and Detail Form

**Files:**
- Modify: `internal/server/web.go:25-201`
- Modify: `internal/server/web_test.go`
- Modify: `internal/server/templates/node.html`
- Modify: `internal/server/static/app.css`

- [ ] **Step 1: Write failing handler tests**

Create a node named `web-01`. Assert `GET /nodes/{id}` returns `200` with `action="/nodes/{id}/rename"`, `name="display_name"`, and `value="web-01"`. Submit `POST /nodes/{id}/rename` with `display_name=edge-web-01`; assert `303`, `Location: /nodes/{id}`, and the stored new name. Submit whitespace-only input and assert `400`, the exact validation message, `value="   "`, and that the stored name remains unchanged. Assert `GET /nodes/{id}/rename` and `POST /nodes/missing/rename` return `404`.

- [ ] **Step 2: Verify failure**

Run: `$env:GOTOOLCHAIN='go1.25.13'; & 'D:\CodeTools\Go\go\bin\go.exe' test ./internal/server -run 'TestMonitor(Renames|RejectsInvalidNodeRename)' -count=1`

Expected: FAIL because the route and form do not exist.

- [ ] **Step 3: Implement route and template**

Add `DisplayName string` to `pageData`. In `nodeRoute`, handle `rename` only for POST. Parse the form, call `RenameNode`, return `404` for `ErrNodeNotFound`, re-render the detail page with `400`, the original form string, and `err.Error()` for validation failures; redirect successful posts with `303` to `/nodes/{id}`. Factor detail data loading so GET and invalid POST both render metrics, samples, and traffic.

Add this form adjacent to the existing node actions and render an optional `.Error` message next to it:

```html
<form class="rename" method="post" action="/nodes/{{.Node.ID}}/rename">
  <label for="display-name">服务器名称</label>
  <input id="display-name" name="display_name" required maxlength="128" value="{{.DisplayName}}">
  <button type="submit">保存名称</button>
</form>
```

Include `.rename` in the existing flex layout selector and mobile wrapping rule; retain existing color and 4px-radius tokens.

- [ ] **Step 4: Verify pass and commit**

Run the Step 2 command; expected PASS. Then run:

```powershell
& 'D:\CodeTools\Go\go\bin\gofmt.exe' -w internal/server/store.go internal/server/store_test.go internal/server/web.go internal/server/web_test.go
git add internal/server/store.go internal/server/store_test.go internal/server/web.go internal/server/web_test.go internal/server/templates/node.html internal/server/static/app.css
git commit -m "feat: add node rename form"
```

### Task 3: Full Local Verification

**Files:** None.

- [ ] **Step 1: Run the complete suite**

```powershell
$env:GOTOOLCHAIN='go1.25.13'
& 'D:\CodeTools\Go\go\bin\go.exe' test ./...
& 'D:\CodeTools\Go\go\bin\go.exe' vet ./...
```

Expected: all tests and vet checks pass.

### Task 4: Remote Acceptance Test

**Files:** None.

- [ ] **Step 1: Inspect then deploy**

Use SSH to find the existing deployment directory, Compose state, and monitor hostname without printing secret `.env` values. Preserve the server `.env`, transfer only the committed source revision, and run `docker compose up -d --build`.

- [ ] **Step 2: Verify HTTPS behavior**

Confirm both containers run and only TCP 443 is published. Create or select a test node, rename it through the monitor host, verify the `303` and rendered name, restart only `probe-server`, and confirm the name and existing metrics persist.

### Task 5: Publish the Pull Request

**Files:** None.

- [ ] **Step 1: Review and push**

Run `git status --short` and `git diff origin/main...HEAD --check`; confirm `.playwright-cli/` remains untracked and excluded. Push a non-force feature branch with upstream tracking.

- [ ] **Step 2: Create the PR**

Open a PR to `main` titled `feat: rename monitored servers`. Include constraints, local checks, remote HTTPS/Compose results, and deferred enhancements. Exclude credentials, enrollment codes, certificates, and full environment values.
