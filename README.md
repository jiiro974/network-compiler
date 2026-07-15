# network-compiler

MVP of a deterministic network configuration compiler. The CLI is `netc`.

Security model, credential handling, and live-access controls: [SECURITY.md](SECURITY.md).

It parses Cisco IOS-like and Juniper Junos `set` configuration files into a small canonical IR, then runs deterministic queries with file/line/block evidence.

## Quick start

A ready-made demo inventory ships at `testdata/inventory.jsonl` (18 devices from `testdata/corpus/`). To serve the UI locally:

```sh
go run ./cmd/netc serve --input testdata/inventory.jsonl --runner simulate
```

Then open http://127.0.0.1:8787/ (dashboard) or http://127.0.0.1:8787/path (path tracer + diagnostics).

To rebuild the inventory after corpus changes:

```sh
go run ./cmd/netc ingest --input ./testdata/corpus --vendor auto --out testdata/inventory.jsonl
```

## Commands

```sh
go run ./cmd/netc ingest --input ./testdata --out inventory.jsonl
go run ./cmd/netc inventory --input inventory.jsonl
go run ./cmd/netc parse ./testdata/cisco-sw1.cfg
go run ./cmd/netc query --input inventory.jsonl --limit 10 --brief "vlan 42"
go run ./cmd/netc query --input ./testdata/cisco-sw1.cfg "interfaces trunk"
go run ./cmd/netc query --input ./testdata/cisco-sw1.cfg "default route"
go run ./cmd/netc parse --vendor auto ./testdata/corpus/juniper-junos/edge-sw1.set.conf
go run ./cmd/netc query --vendor auto --input ./testdata/corpus/juniper-junos/edge-sw1.set.conf --brief "vlan 10"
go run ./cmd/netc check --vendor auto --input ./testdata/corpus/juniper-junos/edge-sw1.set.conf --policy examples/policy.json --summary
go run ./cmd/netc diff --before ./testdata/cisco-sw1.cfg --after ./testdata/cisco-sw1.cfg
go run ./cmd/netc check --input inventory.jsonl --ntp 10.10.10.1,10.10.10.2 --syslog 10.10.20.5 --forbid-snmp-community public --summary
go run ./cmd/netc check --input inventory.jsonl --policy examples/policy.json --summary
go run ./cmd/netc discover --input ./testdata/discovery --out discovery.jsonl
go run ./cmd/netc discover --input ./testdata/discovery --summary
go run ./cmd/netc collect plan --targets ./testdata/guard/targets.jsonl --guard ./testdata/guard/guard.yaml --out collect-plan.json --summary
go run ./cmd/netc collect verify --plan collect-plan.json --confirm-plan-sha256 <sha256>
go run ./cmd/netc collect run --plan collect-plan.json --confirm-plan-sha256 <sha256> --out ./collect-out --simulate
go run ./cmd/netc serve --input inventory.jsonl --policy examples/policy.json --addr 127.0.0.1:8787
go run ./cmd/netc serve --input inventory.jsonl --discovery discovery.jsonl --policy examples/policy.json --addr 127.0.0.1:8787
go run ./cmd/netc serve --input testdata/inventory.jsonl --runner simulate --addr 127.0.0.1:8787
go run ./cmd/netc serve --input inventory.jsonl --runner ssh --known-hosts ~/.ssh/known_hosts --targets ./testdata/guard/targets.jsonl --diag-user admin --addr 127.0.0.1:8787
go run ./cmd/netc path --store inventory.jsonl --src 10.0.10.55 --dst 192.168.50.20 --proto tcp --dport 443 --json
go run ./cmd/netc path validate --store inventory.jsonl --src 10.0.10.55 --dst 192.168.50.20 --proto tcp --dport 443 --runner ssh --json
go run ./cmd/netc diag --store inventory.jsonl --target edge-sw1 --ping 10.0.99.1 --count 5 --runner ssh --json
go run ./cmd/netc diag --store inventory.jsonl --target edge-fw1 --show "show ip route" --json
go run ./cmd/netc diag --store inventory.jsonl --target edge-fw1 --exec "show session all" --approve <token> --json
```

Example `policy.json`:

```json
{
  "required_ntp_servers": ["10.10.10.1", "10.10.10.2"],
  "required_syslog_hosts": ["10.10.20.5"],
  "forbidden_snmp_communities": ["public"]
}
```

The HTTP UI exposes Query, VLAN Path, Path Tracer, Compliance, Diff, and Device views. `VLAN Path` uses config facts for VLAN access/trunk membership and, when `--discovery discovery.jsonl` is provided, overlays candidate physical links inferred from LLDP/CDP/topology facts. The Path Tracer page (`/path`) renders deterministic hop-by-hop flow analysis and can run live diagnostics against each hop when `netc serve` is started with a real or simulated diag runner.

API endpoints are:

```text
GET /api/summary
GET /api/devices?q=SW-A-02
GET /api/device?brief=1&name=SW-A-02
GET /api/policy
GET /api/vendors
GET /api/query?brief=1&limit=20&q=vlan%202048
GET /api/vlan-path?vlan=2048&include_broad=1
GET /api/check/summary
GET /api/check?limit=100
GET /api/diff?before=/path/before.cfg&after=/path/after.cfg
GET /api/path?src=10.0.10.55&dst=192.168.50.20&proto=tcp&dport=443
POST /api/diag
POST /api/path/validate
```

`GET /path` serves the Path Tracer HTML UI. `GET /api/path` returns the same deterministic path JSON as `netc path --json`.

`POST /api/diag` accepts a `DiagRequest` body (target, command, args, optional runner and approval_token) and returns a redacted `DiagResult`. Example:

```json
{
  "target": "edge-sw1",
  "command": "ping",
  "args": { "dst": "10.0.99.1", "count": 5 },
  "runner": "ssh"
}
```

`POST /api/path/validate` compares a predicted path against live ping checks from each hop. Example:

```json
{
  "src": "10.0.10.55",
  "dst": "192.168.50.20",
  "proto": "tcp",
  "dport": 443,
  "runner": "ssh"
}
```

When serving with `--runner simulate` (the default), diagnostics return scripted fixture behavior suitable for local UI development. Use `--runner ssh` or `--runner exec` for real network access, optionally with `--targets targets.jsonl` to resolve management IPs and `--diag-user` / `--diag-secret` for SSH credentials.

## Scope

- Discovery is read-only and file-based in the MVP. `netc discover` reads raw command outputs from per-device directories and emits candidate facts only.
- No RAG in the truth path.
- No external Go dependencies except `golang.org/x/crypto`, isolated to `internal/diag/transport` for SSH host-key verification and in-process SSH sessions.
- No generated parser dependency yet: the current parser foundation uses a small stdlib lexer plus explicit vendor parsers.
- Every parsed object should carry evidence.
- Diag output is observational and live: it never feeds back into the deterministic path engine. `netc path validate` and `POST /api/path/validate` compare predicted vs observed side by side without merging.

Discovery input can use this shape:

```text
raw-discovery/
  sw1/
    metadata.json
    show-lldp-neighbors-detail.txt
    show-cdp-neighbors-detail.txt
    show-arp.txt
    show-mac-address-table.txt
    show-ip-interface-brief.txt
    show-running-config.txt
```

Discovery output is JSONL of candidate facts with source, evidence, confidence, and status. It does not write a validated inventory. LLDP/CDP links are merged when coherent; interface descriptions can create weak candidate links; MAC table entries create medium-confidence attachment candidates, never validated links. Conflicts are exposed as facts instead of hidden.

## Collection Guard

Live collection must be planned before it can run. `netc collect plan` reads an explicit target inventory and a guard config, then writes a deterministic JSON plan with a SHA256 hash. The guard blocks targets outside allowed CIDRs, deny-listed CIDRs, neighbors that were not promoted by a human, non-read-only commands, and runs that exceed configured limits. `netc collect verify` checks the plan hash before any runner can use it. `netc collect run` executes the allowed commands from a verified plan and writes discovery-compatible output under `--out` (use `--simulate` for scripted local runs without network access).

Target input is JSONL or a JSON array:

```json
{"device":"sw1","management_ip":"10.0.1.10","source":"inventory","commands":["show lldp neighbors detail","show arp"]}
```

Guard configs can be JSON or simple YAML. The bundled fixture shows the intended controls:

```sh
go run ./cmd/netc collect plan --targets ./testdata/guard/targets.jsonl --guard ./testdata/guard/guard.yaml --out collect-plan.json --summary
```

## Vendors

- `cisco`: Cisco IOS-like configs.
- `juniper`: Juniper Junos `set` exports.
- `auto`: heuristic detection, currently `set ...` means Juniper, otherwise Cisco.
