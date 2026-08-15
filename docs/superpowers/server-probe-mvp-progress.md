# Server Probe MVP Progress and Constraints

## Checkpoint Status

This is a development checkpoint, not a production release. The MVP is implemented locally and must meet the verification gates below before deployment.

## MVP Boundaries

- Support at most 50 Linux amd64 or arm64 nodes.
- The Agent only samples Linux `/proc` and the root filesystem, then makes outbound HTTPS connections. It never opens an inbound listener.
- The product provides one administrator, node enrollment, monitoring views, certificate renewal, disablement, and removal.
- Do not add remote shell, command execution, file transfer, process inspection, log collection, port scanning, public status pages, multi-user roles, external alert channels, or cloud-managed dependencies to this MVP.

## Security Invariants

- Caddy is the only container allowed to bind public TCP 443. The application and SQLite database are private to the Compose network.
- Caddy only accepts the defined hostname, method, and path combinations. It is responsible for public TLS; the Agent uses mTLS for enrollment, reporting, and renewal.
- Agent private keys, Agent CA private material, application authentication material, SQLite data, and the public CA certificate use separate persistent storage. Caddy receives only the public CA certificate as a read-only mount.
- The server runs as a non-root user with a read-only root filesystem except for declared writable directories.
- Do not log enrollment codes, private keys, session cookies, TOTP secrets, recovery codes, or complete authorization headers.
- Administrator access requires Argon2id password verification, TOTP or a one-time recovery code, server-side 12-hour sessions, same-origin validation, and CSRF validation for state changes.
- Registration and failed administrator login attempts are rate-limited by source IP. Agent reports are bounded to 8 KiB and limited per node.

## Data and Operational Constraints

- Server receipt time is authoritative for node state and chart data.
- Raw samples are retained for 30 days. Daily maintenance removes expired samples and prunes oldest samples under a 2 GiB database size limit while preserving current node state.
- SQLite uses WAL mode. Daily online backups retain the seven most recent copies in an administrator-controlled private location.
- Agent failure handling keeps only the newest in-memory sample and uses bounded backoff. Expired or revoked Agent credentials stop normal reporting.

## Verification Gates

Use Go 1.25.13:

```powershell
$env:GOTOOLCHAIN = 'go1.25.13'
$env:GOPROXY = 'https://goproxy.cn,direct'
& 'D:\CodeTools\Go\go\bin\go.exe' test -count=1 ./...
& 'D:\CodeTools\Go\go\bin\go.exe' vet ./...
& 'D:\CodeTools\Go\go\bin\go.exe' run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
& 'D:\CodeTools\Go\go\bin\go.exe' run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 ./...
& 'D:\CodeTools\Go\go\bin\go.exe' run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
```

Before deployment, also run `docker compose config`, validate Caddy routing and mTLS through the deployed proxy, and run `go test -race ./...` on a host with CGO and a C compiler.

## Current Environment Limits

- Docker is not installed on the current workstation, so Compose validation and live Caddy integration testing are pending.
- CGO is disabled in the current Go environment, so race testing is pending on a suitable build host.
- This checkout has no configured Git remote. A remote URL must be added before the local checkpoint commit can be pushed.
- On 2026-08-15, `gosec@v2.28.0` reported 13 findings. They are limited to configured credential paths, owner-only directory modes, the public CA certificate mode, the node redirect path, and RFC 6238 HMAC-SHA-1 interoperability. This checkpoint is not release-eligible until those findings are concretely remediated or narrowly justified with reviewed source-level suppressions and the scan exits successfully.

## Next Work

1. Clear or narrowly justify the 13 static security findings with reviewed source-level changes, then rerun every verification gate until `gosec` exits successfully.
2. Perform the pending Docker/Caddy and race-test validation in a capable environment.
3. Configure the repository remote and publish this checkpoint branch.
