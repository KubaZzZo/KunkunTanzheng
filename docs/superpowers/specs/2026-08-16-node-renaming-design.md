# Node Renaming Constraints and Design

**Status:** Approved for implementation

## Project Constraints

- The product is a self-hosted monitoring service for up to 50 Linux nodes.
- The central service remains a Go `net/http` application using SQLite; no new runtime, database, or frontend build system is introduced.
- Nodes are monitored through outbound Agent reports only. This feature must not create an inbound Agent listener, remote command channel, or new public endpoint.
- Only Caddy may expose TCP 443. The Probe Server and SQLite database remain on the Compose private network.
- The monitor UI intentionally has no built-in login, user account, role, or TOTP flow. Deployment must continue to restrict access externally with Cloudflare Access, an IP allowlist, or a private network.
- Existing user changes and the untracked `.playwright-cli/` directory are outside this feature and must not be modified or committed.
- Existing node IDs, Agent certificates, enrollment records, reports, and history are immutable from the perspective of a rename. A name is display metadata only.
- The current Go test suite must pass before deployment. Remote testing must use the supplied server only after local verification is green, and no credentials are written into repository files or documentation.

## Goal

Allow an administrator to rename an already-created node from its detail page without affecting its monitoring identity or history.

## User Flow

1. The administrator opens `/nodes/{nodeID}`.
2. The page displays the current node name in a dedicated rename form.
3. The administrator submits a new name to `POST /nodes/{nodeID}/rename`.
4. On success, the server updates only `nodes.display_name` and redirects with `303 See Other` to `/nodes/{nodeID}`.
5. The dashboard and detail page then show the new name. Existing reports and the Agent continue to use the unchanged node ID.

## Validation and Errors

- The server trims leading and trailing whitespace before validation and storage.
- A valid name contains from 1 to 128 bytes after trimming. The rule matches node creation so both paths accept the same values.
- An invalid form submission returns `400 Bad Request` and re-renders the node detail page with the current metrics, history, and a visible validation error. No data is changed.
- A request for a missing node returns `404 Not Found`.
- Only the `POST` route is accepted; other methods return `404 Not Found` consistently with existing node actions.
- The endpoint accepts normal form posts only. It does not introduce a JSON API.

## Architecture

The persistence layer gains a focused `RenameNode(ctx, nodeID, displayName)` method. It shares the existing name normalization and validation rule with `CreateNode`, then updates one column in the existing `nodes` table. No migration is needed.

The monitor handler adds a route branch for `rename`, a handler that calls the store method, and a small helper for rendering the node detail with an optional error. The page data carries the current form value so invalid submissions preserve the user input for correction.

The detail template adds a regular form next to the existing disable and remove actions. The dashboard stays read-only for naming, preventing accidental edits while scanning node status.

## Tests

- Store test: a valid rename updates only the node display name and retains its ID, state, latest report, and sample history.
- Store test: empty-after-trimming and over-128-byte names return the existing validation error and leave the stored name unchanged.
- HTTP test: a valid detail-page form post redirects with `303` and the subsequent page renders the new name.
- HTTP test: invalid input renders an error with `400`, preserves the supplied value, and does not change the stored name.
- HTTP test: a missing node and unsupported method receive `404`.

## Explicitly Deferred

- Inline editing on the dashboard.
- Name history, change attribution, and audit logs.
- Node tags, groups, thresholds, alerts, and notes. These are separate enhancements, not prerequisites for renaming.
- Built-in login, users, roles, TOTP, or public API authentication.

## Deployment and Acceptance

After local tests pass, rebuild the existing Docker Compose deployment on the supplied test server. Verify the monitor page over its configured HTTPS host, rename one existing or newly created node, confirm that its ID and metrics remain visible, and confirm the new name persists after a container restart. No database schema change or Agent reinstall is expected.
