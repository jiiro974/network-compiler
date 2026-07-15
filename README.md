# network-compiler

MVP of a deterministic network configuration compiler. The CLI is `netc`.

It parses Cisco IOS-like and Juniper Junos `set` configuration files into a small canonical IR, then runs deterministic queries with file/line/block evidence.

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
go run ./cmd/netc serve --input inventory.jsonl --policy examples/policy.json --addr 127.0.0.1:8787
```

Example `policy.json`:

```json
{
  "required_ntp_servers": ["10.10.10.1", "10.10.10.2"],
  "required_syslog_hosts": ["10.10.20.5"],
  "forbidden_snmp_communities": ["public"]
}
```

The HTTP UI exposes Query, Compliance, Diff, and Device views. API endpoints are:

```text
GET /api/summary
GET /api/devices?q=SW-A-02
GET /api/device?brief=1&name=SW-A-02
GET /api/policy
GET /api/vendors
GET /api/query?brief=1&limit=20&q=vlan%202048
GET /api/check/summary
GET /api/check?limit=100
GET /api/diff?before=/path/before.cfg&after=/path/after.cfg
```

## Scope

- No live collection in the MVP.
- No RAG in the truth path.
- No external dependencies.
- No generated parser dependency yet: the current parser foundation uses a small stdlib lexer plus explicit vendor parsers.
- Every parsed object should carry evidence.

## Vendors

- `cisco`: Cisco IOS-like configs.
- `juniper`: Juniper Junos `set` exports.
- `auto`: heuristic detection, currently `set ...` means Juniper, otherwise Cisco.
