# `netc diag` JSON contract — LOCKED (v1)

Single source of truth for the diagnostics/exec layer: CLI `netc diag`, endpoints
`POST /api/diag` and `POST /api/path/validate`, and the path-view UI overlay.

**Truth-path separation (normative):** diagnostic output is *observational and live*.
It is non-deterministic, redacted, and MUST NEVER feed the compiled path/verdict engine
(`internal/path`) or any IR decision. The compiler stays deterministic; diag only
*observes* the running network and is displayed alongside — never inside — the truth path.

**Locking rules:** `snake_case` keys; Go structs carry matching JSON tags; `omitempty`
fields may be absent; no rename/retype without bumping to v2; adding an optional field is
backward-compatible.

## Command classes (allowlist / gate)

- `diagnostic` — read-only, runs freely: `ping`, `traceroute`, `show`/`display`/`get`.
- `exec` — arbitrary non-config command; requires an **approval** (see `approval`) and an
  RBAC capability. Returns `status: "needs_approval"` until granted.
- `config` — anything entering config mode or writing/erasing/reloading. **Denied by
  default** (`status: "denied"`), even with approval, unless the caller holds the explicit
  `config-write` capability. Enforced by a deny-list, not an allowlist.

## Request — `POST /api/diag`
```json
{
  "target": "edge-sw1",
  "command": "ping",
  "args": { "dst": "10.0.99.1", "count": 5, "source": "", "vrf": "", "raw": "" },
  "runner": "ssh",
  "approval_token": ""
}
```
Fields:
- `target`: device hostname (resolved via store) or literal `ip:<addr>`.
- `command`: `ping` | `traceroute` | `show` | `exec`.
- `args`: command-specific. `dst` for ping/traceroute; `raw` carries the literal command
  for `show`/`exec`; `count`/`source`/`vrf` optional.
- `runner`: `ssh` | `exec` (server default if omitted).
- `approval_token`: opaque token from the approval provider; required for `exec`.

## Response — DiagResult
```json
{
  "target": "edge-sw1",
  "vendor": "cisco-ios",
  "command": "ping",
  "class": "diagnostic",
  "rendered_command": "ping 10.0.99.1 repeat 5",
  "runner": "ssh",
  "status": "ok",
  "approval": null,
  "started_at": "2026-07-15T10:00:00Z",
  "duration_ms": 842,
  "exit_code": 0,
  "raw_output": "!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms",
  "parsed": {
    "ping": { "sent": 5, "received": 5, "loss_pct": 0, "rtt_min_ms": 1, "rtt_avg_ms": 1, "rtt_max_ms": 2 }
  },
  "audit_id": "01J...ULID"
}
```
Fields:
- `class`: `diagnostic` | `exec` | `config`.
- `rendered_command`: the exact per-vendor command string that was sent (after mapping).
- `status`: `ok` | `unreachable` | `timeout` | `denied` | `needs_approval` | `error`.
- `approval`: object when relevant, else `null`:
  `{ "required": true, "granted": false, "id": "", "approver": "", "ticket": "", "reason": "" }`
- `raw_output`: device output, **redacted** via `internal/secretredact`. Live, non-deterministic.
- `parsed`: optional structured extract. `ping` shape above; `traceroute`:
  `{ "hops": [ { "ttl": 1, "host": "10.0.99.1", "rtt_ms": 1.2 } ] }`. Absent for `show`/`exec`.
- `exit_code`: transport/command exit code (`0` ok). `-1` when not applicable.
- `audit_id`: id of the audit-log entry recording who/when/what/approval.

## Request — `POST /api/path/validate`
Body is a `Flow` (same shape as `/api/path`) plus optional `{ "runner": "ssh" }`.
The engine first computes the deterministic `Path`, then runs reachability checks along
its predicted hops (ping each hop's `next_hop`, and ping `flow.dst` from the last hop).

## Response — PathValidation
```json
{
  "flow": { "src": "10.0.10.55", "dst": "192.168.50.20", "proto": "tcp", "dport": 443 },
  "predicted_verdict": "delivered",
  "checks": [
    { "from_device": "edge-sw1", "type": "ping", "target": "10.0.99.1",   "observed": "reachable",   "result": { "loss_pct": 0,   "rtt_avg_ms": 1,  "audit_id": "01J..." } },
    { "from_device": "core-rtr1","type": "ping", "target": "10.0.99.254", "observed": "reachable",   "result": { "loss_pct": 0,   "rtt_avg_ms": 2,  "audit_id": "01J..." } },
    { "from_device": "edge-fw1", "type": "ping", "target": "192.168.50.20","observed": "unreachable", "result": { "loss_pct": 100, "rtt_avg_ms": 0,  "audit_id": "01J..." } }
  ],
  "observed_verdict": "unreachable",
  "agreement": "mismatch"
}
```
Fields:
- `predicted_verdict`: from the deterministic engine (`delivered` | `dropped_acl` | …).
- `checks[]`: one per predicted hop. `observed`: `reachable` | `unreachable` | `inconclusive`.
  `result` is a trimmed DiagResult summary (never the full raw output here).
- `observed_verdict`: `reachable` | `unreachable` | `partial` | `inconclusive`.
- `agreement`: `match` | `mismatch` — predicted (compiled truth) vs observed (live). A
  `mismatch` is the high-value signal: config says one thing, the wire says another
  (drift, transient failure, out-of-band ACL, etc.).

## Statuses / enums (exact values)
- DiagResult.status: `ok` `unreachable` `timeout` `denied` `needs_approval` `error`
- class: `diagnostic` `exec` `config`
- check.observed: `reachable` `unreachable` `inconclusive`
- observed_verdict: `reachable` `unreachable` `partial` `inconclusive`
- agreement: `match` `mismatch`

Fixtures for these live under `internal/server/assets/fixtures/diag/`.
