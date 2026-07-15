# `netc path` JSON contract

`netc path` and `GET /api/path` return a deterministic path trace. The engine uses only parsed IR objects; no LLM participates in route, ACL, policy, NAT, or verdict decisions.

## Request flow

```json
{
  "src": "10.0.10.55",
  "dst": "192.168.50.20",
  "proto": "tcp",
  "dport": 443
}
```

Fields:

- `src`: source IPv4 address.
- `dst`: destination IPv4 address.
- `proto`: protocol string, lowercased by the engine for matching.
- `dport`: destination port. Omitted from JSON when zero.

## Response

```json
{
  "flow": {
    "src": "10.0.10.55",
    "dst": "192.168.50.20",
    "proto": "tcp",
    "dport": 443
  },
  "hops": [
    {
      "device": "edge1",
      "vendor": "cisco",
      "ingress_iface": "lan10",
      "route_match": {
        "destination": "192.168.50.0/24",
        "next_hop": "10.0.12.2",
        "interface": "to-core",
        "evidence": {
          "file": "edge1.cfg",
          "start_line": 30,
          "end_line": 30,
          "raw_block": "ip route 192.168.50.0/24 10.0.12.2",
          "parser": "test"
        }
      },
      "egress_iface": "to-core",
      "next_hop": "10.0.12.2"
    }
  ],
  "verdict": "delivered",
  "reason": {
    "file": "core1.cfg",
    "start_line": 20,
    "end_line": 20,
    "raw_block": "interface server50",
    "parser": "test"
  }
}
```

`hops[]` fields:

- `device`, `vendor`: current IR device.
- `ingress_iface`: interface where the flow enters the device.
- `ingress_zone`: firewall zone for `ingress_iface`, when zones exist.
- `route_match`: selected `ir.Route` with evidence.
- `acl_match`: selected `ir.ACLEntry` with evidence.
- `policy_match`: selected `ir.SecurityPolicy` with evidence.
- `nat_applied`: selected `ir.NATRule` with evidence. NAT is reported but the flow is not rewritten.
- `egress_iface`: interface where the flow leaves the device.
- `egress_zone`: firewall zone for `egress_iface`, when zones exist.
- `next_hop`: next-hop IP, or destination IP for directly connected delivery.

`verdict` values:

- `delivered`: a device owns an interface subnet containing `flow.dst`.
- `dropped_acl`: first matching ACL entry denied the flow.
- `dropped_policy`: first matching firewall security policy denied the flow, or policies exist and no policy matched.
- `no_route`: no L3 route matched, or the selected next hop could not be resolved to another device.
- `loop`: a device repeats in the trace or the 16-hop limit is exceeded.

`reason` is the evidence for the final decision: destination interface evidence for `delivered`, matched entry/policy evidence for drops, device or route evidence for route failures, and loop evidence from the repeated device or last route.

## Deterministic decision rules

- Device and interface candidates are sorted by hostname then interface name before next-hop resolution.
- The start device is the first sorted interface subnet containing `flow.src`.
- Direct delivery is checked before static routes on each device.
- Route choice uses longest-prefix match, then lowest administrative distance, then original route order.
- ACL attachment is not modeled in the current IR. The engine applies a documented deterministic fallback: the first ACL entry on the device matching `proto` and `dport` is used.
- Firewall policy is evaluated only when `security_policies` are present. Zones are derived from exact interface names in `zones[].interfaces`.
- NAT uses first matching `from_zone` and `to_zone` rule and does not mutate the flow.
