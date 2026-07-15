# Security and credentials

The MVP parses configuration files only. It must not connect to live devices by default and must not push changes.

Rules:

- Do not commit passwords, tokens, SNMP communities, private keys, or device dumps containing secrets.
- Do not log secrets.
- Do not include raw secrets in JSON output, reports, tests, or fixtures. Evidence should pass through `secretredact`.
- Keep `.env`, `*.secrets`, `credentials.yml`, `credentials.json`, `private/`, and `dumps/` local.
- Keep `credentials.yaml` local too.
- Future live collection must be read-only. It is intentionally not implemented while the project keeps the zero external dependency rule.

Future credential priority:

1. SSH agent.
2. Environment variables.
3. Local credentials file with `0600` permissions.

Future live collectors must reject dangerous commands such as `configure terminal`, `commit`, `write memory`, `copy running-config startup-config`, `delete`, `reload`, `set`, `edit`, and configuration-mode `no ...` commands.

SSH collection decision:

- Native SSH in Go requires `golang.org/x/crypto/ssh`.
- To keep zero dependencies, the current product remains file/inventory based.
- If live collection becomes mandatory, prefer a read-only collector with strict `known_hosts`; otherwise shelling out to system `ssh` is the only no-runtime-dependency route.
