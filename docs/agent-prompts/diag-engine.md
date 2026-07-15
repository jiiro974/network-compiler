# Tâche Codex — moteur de diagnostic & exécution (`netc diag`)

## Contexte du dépôt

Dépôt Go `network-compiler` (Go 1.24, déterministe, evidence-first). Tu ajoutes une
**couche de diagnostic live** au-dessus du compilateur : lancer des commandes read-only
(ping, traceroute, show) — et, sous approbation, des commandes arbitraires — vers les
équipements de l'IR, puis **valider** un chemin calculé en le confrontant au réseau réel.

> **Contrat verrouillé** — le format d'échange est défini de façon autoritative dans
> `docs/diag-json-schema.md` (clés `snake_case`, enums, exemples, fixtures). Il prime sur
> tout extrait de code ci-dessous.

> **Séparation du chemin de vérité (non négociable)** — la sortie diag est *observationnelle
> et live* : non déterministe, redigée, et elle ne doit JAMAIS alimenter le moteur
> `internal/path` ni une décision d'IR. Le compilateur reste déterministe ; le diag
> *observe* seulement. Aucun croisement des deux flux, sauf dans `/api/path/validate` qui
> les met côte à côte pour comparer (jamais fusionner).

Packages à connaître : `internal/ir`, `internal/parser`, `internal/store`,
`internal/path` (moteur de chemin, tâche `path-tracer.md`), `internal/secretredact`
(redaction — à réutiliser), `internal/server` (API HTTP), `cmd/netc/main.go` (dispatch).

## Décisions d'architecture déjà tranchées (ne pas ré-arbitrer)

- **Portée** : `diagnostic` (allowlist, libre) + `exec` (commande arbitraire **sous
  approbation** + capacité RBAC) + `config` (**refusé par défaut**, deny-list, seulement si
  capacité `config-write` explicite). Voir les classes dans le schéma.
- **Transport pluggable** : une interface `Runner`, avec **deux implémentations réelles** +
  une fausse :
  - `ExecRunner` — shell-out via `os/exec` vers les binaires locaux `ping`/`traceroute`/`ssh`
    (zéro dépendance Go).
  - `SSHRunner` — client SSH in-process via `golang.org/x/crypto/ssh` (dépendance acceptée,
    **isolée dans `internal/diag/transport`**). Reprendre la sécurité du repo de référence :
    vérification `known_hosts` obligatoire, refus de connexion sans host key
    (override explicite `--insecure-host-key`).
  - `FakeRunner` — sorties scriptées pour les tests, aucun accès réseau.
- `golang.org/x/crypto` n'est autorisé que dans `internal/diag/transport`. Le reste du
  dépôt demeure stdlib-only.

## Livrables

### 1. Package `internal/diag`
- `Runner` interface : `Run(ctx, target Target, cmd RenderedCommand) (RawResult, error)`.
- `Target{ Host, Address, Vendor string; Creds CredRef }` résolu depuis le store.
- **Command mapping par vendeur** : une table qui rend la commande logique
  (`ping dst count`, `traceroute dst`, `show raw`) vers la syntaxe du vendeur. Couvrir au
  minimum cisco-ios, juniper, pan-os, mikrotik, arista, fortigate ; défaut générique
  sinon. Ex. cisco `ping <dst> repeat <n>`, juniper `ping <dst> count <n>`,
  mikrotik `/ping <dst> count=<n>`, pan-os `ping host <dst> count <n>`.
- **Allowlist / deny-list** : `classify(command) → diagnostic|exec|config`. La deny-list
  `config` matche `configure`, `conf t`, `set `, `edit `, `commit`, `delete`, `write`,
  `erase`, `reload`, `request system`, `copy run`, etc. — refus dur sans capacité.
- **Approval** : interface `ApprovalProvider{ Check(token string, cmd, target) (Approval, error) }`.
  Fournir une implémentation par défaut `StaticApprovals` (config/liste) pour les tests ;
  laisser l'intégration RBAC réelle branchable. Une commande `exec` sans approbation
  valide renvoie `status: needs_approval` (aucune exécution).
- **Redaction** : passer tout `raw_output` par `internal/secretredact` avant de le renvoyer
  ou de le logger.
- **Timeouts** : `ctx` avec deadline par commande (défaut 10 s, configurable).
- **Audit** : chaque tentative (autorisée, refusée, approuvée) écrit une entrée
  append-only (qui/quand/cible/commande/classe/approval/résultat) et renvoie son `audit_id`.
- **Parsers de sortie** : extraire `parsed.ping` (sent/received/loss/rtt) et
  `parsed.traceroute` (hops) de façon best-effort et tolérante aux formats vendeurs.
  Absence de parse ⇒ `parsed` omis, jamais d'erreur fatale.
- `Diagnose(ctx, req DiagRequest) (DiagResult, error)` orchestre : résolution cible →
  classify → approval → render → run → redact → parse → audit.

### 2. Validation de chemin — `internal/diag` + `internal/path`
- `ValidatePath(ctx, flow) (PathValidation, error)` : calcule d'abord le `Path`
  déterministe (via `internal/path`, sans le modifier), puis pour chaque hop lance un
  `ping` du `next_hop` depuis l'équipement courant (et un `ping flow.dst` depuis le
  dernier hop). Agrège `observed_verdict` et calcule `agreement` (predicted vs observed).
- **Ne jamais** laisser le résultat live influencer le `Path` : c'est une comparaison, pas
  une correction.

### 3. CLI
Ajouter au dispatch de `cmd/netc/main.go` :
```
netc diag --target edge-sw1 --ping 10.0.99.1 --count 5 [--runner ssh|exec] [--json]
netc diag --target edge-sw1 --traceroute 192.168.50.20 [--json]
netc diag --target edge-sw1 --show "show ip route" [--json]
netc diag --target edge-sw1 --exec "..." --approve <token> [--json]
netc path validate --src 10.0.10.55 --dst 192.168.50.20 --proto tcp --dport 443 [--json]
```
Sortie texte lisible par défaut ; `--json` conforme au schéma.

### 4. Endpoints HTTP (`internal/server`)
- `POST /api/diag` → `DiagResult`.
- `POST /api/path/validate` → `PathValidation`.
- Mêmes conventions d'erreur (`writeError`) que les handlers existants. Ces JSON sont le
  contrat de la vue UI : **stables et conformes au schéma**.

### 5. Tests
- `internal/diag` avec `FakeRunner` : mapping par vendeur, classify (diag/exec/config),
  refus config, `needs_approval`, redaction du `raw_output`, parse ping/traceroute,
  timeout. **≥ 85 % de couverture**.
- `ValidatePath` : cas `match` (delivered + reachable) et `mismatch` (delivered mais
  ping en échec) via `FakeRunner`, sur des `Device` construits en dur.
- Golden JSON pour un `DiagResult` et un `PathValidation` (aligne sur les fixtures
  `internal/server/assets/fixtures/diag/`).
- Aucun test ne doit toucher le réseau : `FakeRunner` uniquement.

## Contraintes (bloquantes)
- `x/crypto` **uniquement** dans `internal/diag/transport`. Reste du dépôt : stdlib.
- Sécurité : allowlist par défaut ; `exec` gated par approbation ; `config` refusé sauf
  capacité explicite ; `known_hosts` vérifié ; secrets redigés ; timeout par commande ;
  tout est audité.
- Déterminisme du compilateur préservé : `internal/path` inchangé dans sa logique.
- `gofmt -l` vide, `go vet ./...` propre, `go build/test ./...` verts.

## Critères d'acceptation
1. `netc diag --target edge-sw1 --ping 10.0.99.1 --json` (via `FakeRunner` en test)
   renvoie un `DiagResult` conforme, `raw_output` redigé, `parsed.ping` renseigné.
2. Une commande `exec` sans `--approve` renvoie `status: needs_approval` sans exécuter.
3. Une commande de classe `config` renvoie `status: denied` sans capacité `config-write`.
4. `netc path validate ...` renvoie un `PathValidation` avec `agreement` `match`/`mismatch`.
5. `/api/diag` et `/api/path/validate` renvoient le même JSON que la CLI `--json`.
6. Couverture `internal/diag` ≥ 85 %, portes de qualité vertes, `x/crypto` isolé.

## Ordre de travail suggéré
1. `Runner` + `FakeRunner` + command mapping + classify + tests (aucun réseau).
2. Approval + audit + redaction + parsers ping/traceroute.
3. `Diagnose`, puis `ValidatePath` (réutilise `internal/path`).
4. CLI `diag` et `path validate`, puis endpoints HTTP + fixtures.
5. `ExecRunner` (os/exec) puis `SSHRunner` (x/crypto, known_hosts) en dernier.

## Hors périmètre
- Écritures de configuration (charte read-only ; `config` reste refusé par défaut).
- Orchestration multi-équipements complexe / ordonnancement. La vue UI (tâche séparée).
