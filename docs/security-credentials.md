# Security and credentials

`netc` MVP parses files only. It must not collect live data by default and must
not require network credentials for normal operation.

## Repository rules

- Do not commit passwords, API tokens, SNMP communities, private keys, dumps, or
  raw device exports containing secrets.
- Do not put secrets in fixtures. Test fixtures must use fake placeholders such
  as `<redacted>` or `example-only`.
- Do not write secrets to logs, terminal output, reports, or JSON artifacts.
- Keep `.env`, `*.secrets`, `credentials.yml`, `credentials.yaml`,
  `credentials.json`, `private/`, and `dumps/` local and ignored by Git.
- Run all user-visible config output through a redactor before logging,
  reporting, or serializing it.

## Future live collection

Live collection is a future feature and must be explicitly enabled. It must be
read-only: no configuration mode, no commit/write commands, and no destructive
network commands.

Credential lookup order for future collection:

1. SSH agent.
2. Environment variables.
3. Local credentials file with mode `0600`.

Future code must reject local credentials files that are group-readable,
world-readable, group-writable, or world-writable.

Allowed command posture: discovery and show/read commands only. Do not document
or implement workflows using commands such as `configure terminal`, `commit`,
`write memory`, `copy running-config startup-config`, `reload`, `delete`,
`clear`, `debug`, interface shutdown/no shutdown, or any command that changes
device state.

## Redaction policy

Mask complete lines containing these case-insensitive indicators:

- `password`
- `secret`
- `key`
- `community`
- `token`
- `authorization`
- `enable secret`
- `snmp-server community`

The replacement line should preserve indentation where practical and replace the
content with `<redacted>`.
