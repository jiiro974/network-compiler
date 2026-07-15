# Security and credentials

`netc` parses configuration files, runs deterministic queries, and can optionally reach live devices for **read-only** diagnostics and collection. Live access is never the default for the HTTP server, and configuration-changing commands are refused unless an explicit write capability is enabled (it is not enabled anywhere in the stock CLI).

## Dependencies

The project uses the Go standard library everywhere except SSH transport:

- **`golang.org/x/crypto`** — required only in `internal/diag/transport` for native SSH sessions and `known_hosts` verification. It is not imported elsewhere.
- **`netc collect run --exec-runner`** shells out to the system `ssh` binary instead of the native client; that path still lives under `internal/diag/transport` but does not open an in-process SSH connection.

There is no `internal/creds` package yet. Credentials are passed via CLI flags today (see [Credential handling](#credential-handling)).

## Truth path vs observational path

- **Truth path** (parse → IR → query, path, compliance, diff): file- and inventory-based only. No LLM, no live device output merged into IR or path results.
- **Observational path** (`netc diag`, `POST /api/diag`, `netc path validate`, `POST /api/path/validate`): live ping/traceroute/show/exec output is redacted, parsed for display, and compared side-by-side with predictions. It never feeds back into the deterministic path engine.

## Diagnostics (`netc diag`, `POST /api/diag`)

### Command classification

Every request is classified before execution (`internal/diag/classify.go`):

| Class | Examples | Default behavior |
|-------|----------|------------------|
| `diagnostic` | `ping`, `traceroute`, `show`, `display …` | Runs when runner is live |
| `exec` | Arbitrary shell commands not matching diagnostic prefixes | Requires an approval token |
| `config` | `configure terminal`, `set …`, `commit`, `write …`, `reload`, `no …`, etc. | **Denied** — `status: denied`, no execution |

Config-class commands are blocked with reason *"classe config refusée : capacité config-write absente (charte read-only)"*. The service exposes `WithConfigWriteCap(true)` for tests only; the stock CLI never enables it.

### Runners

| Runner | Network access | Notes |
|--------|----------------|-------|
| `simulate` (HTTP default) | None | Scripted fixtures; safe for local UI development |
| `ssh` | Yes | Native client in `internal/diag/transport`; `known_hosts` enforced |
| `exec` | Yes | Shells out to system `ssh` |

Start the server with `--runner simulate` (default) unless you intend live diagnostics. Binding defaults to `127.0.0.1:8787`; do not expose a live runner on an untrusted interface.

### SSH host keys

For the native `ssh` runner:

- Host key verification uses a `known_hosts` file.
- If `--known-hosts` is omitted, `~/.ssh/known_hosts` is used when available.
- Connection is refused when no valid `known_hosts` file can be loaded.
- `--insecure-host-key` skips verification (development only; never in production).

### Secret redaction

Diagnostic and collection output passes through `internal/secretredact` before JSON emission. Parsed config evidence should also pass through `secretredact.Redact` when surfaced in reports or tests.

### Audit

Each diagnostic run records an audit entry (command, class, status, approval, actor). Collection runs can append JSONL audit lines via `--audit-log`.

## Collection guard (`netc collect`)

Live collection requires a **planned, hash-verified** run. Ad-hoc target lists are not executed directly.

1. **`netc collect plan`** — reads explicit targets (`targets.jsonl`) and a guard config (`guard.yaml`), emits a deterministic JSON plan with a SHA-256 hash.
2. **`netc collect verify`** — confirms the plan file matches `--confirm-plan-sha256`.
3. **`netc collect run`** — executes only allowed targets and commands from a verified plan; refuses to start if the hash was not confirmed.

Guard controls (`internal/guard`):

- Allow/deny CIDRs for management IPs (IPv4 and IPv6).
- Command allow-list and deny patterns (blocks configuration-mode commands).
- Per-run limits (max targets, timeouts, no ping sweep / port scan / subnet expansion).
- Neighbor expansion requires human promotion when enabled.
- Inventory-only target mode rejects LLDP/CDP neighbors as targets unless promoted.

Use **`--simulate`** for local runs without network access (embedded fixtures under `internal/collect/simulate/`). Live runs use the same SSH/`known_hosts` rules as diagnostics.

## HTTP API exposure

Read-only GET endpoints serve parsed inventory data (summary, devices, query, path, compliance, diff, policy, VLAN path). Vendor names are listed at:

```text
GET /api/vendors
```

Returns the sorted list of registered parser vendors (same source as `parser.Vendors()`). No secrets or live network access.

Endpoints that can trigger live network access when `netc serve` is started with `--runner ssh` or `--runner exec`:

```text
POST /api/diag
POST /api/path/validate
```

The UI does not execute commands itself; it forwards requests to these server endpoints. Approval tokens for `exec`-class commands are validated server-side.

`GET /api/query/help` is not implemented yet (`query.Help()` is planned but not merged).

## Credential handling

There is no credentials file loader in the tree today. Use CLI flags and keep secrets out of shell history where possible (env vars, secret managers).

| Context | Flags | Notes |
|---------|-------|-------|
| `netc serve` (live diag) | `--diag-user`, `--diag-secret` | Optional; passed to `diag.CredRef` |
| `netc collect run` (live) | `--user` (default `admin`) | Password not yet wired via flag; SSH agent or future creds support |
| `netc diag` / `netc path validate` | — | Uses runner defaults; no credential flags on CLI yet |

**Intended environment variables** (not implemented; reserved for a future `internal/creds` package):

| Variable | Purpose |
|----------|---------|
| `NETC_SSH_USER` | Default SSH username |
| `NETC_SSH_PASSWORD` | Default SSH password (avoid in production; prefer agent) |
| `NETC_KNOWN_HOSTS` | Path to `known_hosts` file |
| `NETC_DIAG_APPROVAL_TOKEN` | Pre-approved token for `exec`-class commands in automation |

**Planned credential priority** (when `internal/creds` lands):

1. SSH agent.
2. Environment variables (`NETC_*`).
3. Local credentials file with `0600` permissions.

## What not to commit

Never commit:

- Passwords, API tokens, SNMP communities, private keys, or approval tokens.
- Raw device dumps, `show running-config` captures, or collect output that may contain secrets.
- Live collect plans or audit logs with real management IPs unless sanitized.
- `.env`, `*.secrets`, `credentials.yml`, `credentials.yaml`, `credentials.json`.
- `private/`, `dumps/`, and any local inventory built from production configs.

Keep test fixtures synthetic or redacted. Run `secretredact` on evidence blocks before checking in config snippets.

## Reporting security issues

Open a private issue or contact the maintainers directly. Do not file public issues that include live credentials, host keys, or unsanitized device output.
