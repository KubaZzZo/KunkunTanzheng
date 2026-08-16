# Server Probe

Server Probe is a self-hosted monitoring MVP for up to 50 Linux servers. Each Agent sends outbound HTTPS reports every 30 seconds; the central service stores raw samples in SQLite and exposes a monitoring UI.

The public surface is deliberately limited: only Caddy publishes TCP 443. The Probe Server and SQLite database are private to the Compose network. There are no remote commands, inbound Agent listeners, public status pages, or multi-user accounts.

## Build and test

The repository is locked to Go 1.25.13. On this workstation, use `D:\CodeTools\Go\go\bin\go.exe` with `GOTOOLCHAIN=go1.25.13`; the Go command downloads that fixed toolchain once into its local cache.

```powershell
$env:GOTOOLCHAIN = 'go1.25.13'
& 'D:\CodeTools\Go\go\bin\go.exe' test ./...
& 'D:\CodeTools\Go\go\bin\go.exe' vet ./...
```

Build a Linux Agent for the target architecture from a trusted build host:

```powershell
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
& 'D:\CodeTools\Go\go\bin\go.exe' build -trimpath -ldflags='-s -w' -o probe-agent ./cmd/probe-agent
```

Use `GOARCH=arm64` for ARM64 hosts.

## Deploy the central service

Create DNS `A` or `AAAA` records for three distinct names, all pointing at the Compose host:

- `monitor.tanzhen.zhuoruan.xyz`
- `ingest.tanzhen.zhuoruan.xyz`
- `enroll.tanzhen.zhuoruan.xyz`

Create three Cloudflare DNS records pointing to the Compose host. The monitor URL is `https://monitor.tanzhen.zhuoruan.xyz`; `tanzhen.zhuoruan.xyz` can remain the zone apex or redirect target. Keep the three service hostnames distinct because the ingest hostname requires Agent mTLS while enrollment is intentionally public.

Allow only inbound TCP 443 at the host firewall. Do not publish port 8080 or the database volume. Prepare a private host backup directory owned by the non-root container UID:

```sh
sudo install -d -m 0700 -o 65532 -g 65532 /srv/server-probe/backups
```

Create `.env` next to `docker-compose.yml`:

```dotenv
PROBE_MONITOR_HOST=monitor.tanzhen.zhuoruan.xyz
PROBE_INGEST_HOST=ingest.tanzhen.zhuoruan.xyz
PROBE_ENROLL_HOST=enroll.tanzhen.zhuoruan.xyz
PROBE_BACKUP_HOST_DIRECTORY=/srv/server-probe/backups
```

Start the service:

```sh
docker compose up -d --build
docker compose logs -f probe-server
```

Fresh `probe-data`, `agent-ca-private`, and `agent-ca-public` named volumes are initialized from image directories owned by UID/GID `65532`. SQLite and the Agent CA private key are isolated in the first two volumes; only the public CA certificate is copied into `agent-ca-public` for Caddy. Caddy waits for that certificate before starting its mTLS listener.

The monitor UI has no built-in login. Restrict `monitor.tanzhen.zhuoruan.xyz` with Cloudflare Access, an IP allowlist, or a private network before exposing it publicly; node creation, disablement, and removal are otherwise unauthenticated.

## Enroll an Agent

In the monitor UI, create a server and use the one-time command displayed exactly once. It includes the node ID, the report endpoint, enrollment endpoint, and ten-minute enrollment code.

For systemd deployment, install the binary at `/usr/local/bin/probe-agent`, copy `deploy/systemd/probe-agent.service` to `/etc/systemd/system/`, and create `/etc/probe-agent/probe-agent.env` with the environment values shown by the UI:

```dotenv
PROBE_NODE_ID=node-id-from-the-ui
PROBE_ENDPOINT=https://ingest.tanzhen.zhuoruan.xyz/v1/reports
PROBE_ENROLL_ENDPOINT=https://enroll.tanzhen.zhuoruan.xyz/v1/enroll
PROBE_ENROLL_CODE=one-time-code-from-the-ui
```

Enable the dedicated service account and start it:

```sh
sudo useradd --system --home /var/lib/probe-agent --shell /usr/sbin/nologin probe-agent
sudo install -d -m 0700 -o probe-agent -g probe-agent /etc/probe-agent
sudo chmod 0600 /etc/probe-agent/probe-agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now probe-agent
```

After a successful registration, remove `PROBE_ENROLL_CODE` and `PROBE_ENROLL_ENDPOINT` from the environment file. Credentials live under `/var/lib/probe-agent` with `0700` directory and `0600` file permissions. The Agent renews its 30-day client certificate when it enters the final seven days and stops reporting after an expired or revoked credential.

## Backups and restore

The server writes an online SQLite backup once per day to `PROBE_BACKUP_HOST_DIRECTORY` and retains the latest seven files. Keep that directory private and copy it off-host using the organisation's backup system.

To restore, stop only `probe-server`, replace `probe.db` in the `probe-data` volume with a chosen `probe-YYYY-MM-DD.db` backup, remove the corresponding `probe.db-wal` and `probe.db-shm` files, then start `probe-server` again. Leave Caddy running. Verify the latest report times in the monitor UI after the service returns.
