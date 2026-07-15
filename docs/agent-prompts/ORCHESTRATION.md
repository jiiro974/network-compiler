# Orchestration — fonctionnalité « chemin réseau » (netc)

Dépôt : `network-compiler` (Go 1.24, déterministe, evidence-first). Stdlib-only,
**sauf** `internal/diag/transport` qui peut utiliser `golang.org/x/crypto` (isolé).

Contrats gelés (**aucun agent ne les modifie**) :
- `docs/path-json-schema.md` (v1) — chemin compilé.
- `docs/diag-json-schema.md` (v1) — diagnostic/exec live + validation de chemin.

Portes de qualité entre chaque étape : `gofmt -l` vide, `go vet ./...` propre,
`go build ./...` et `go test ./...` verts, couverture ≥ 85 % sur `internal/path`
et `internal/diag`.

## Piste A — chemin (fondation, à faire en premier)
1. `path-tracer.md` — moteur `internal/path` + CLI `netc path` + `GET /api/path`.
2. `path-viewer-ui.md` — vue HTML `/path`.

## Piste B — diagnostic & exécution (dépend du chemin)
3. `diag-engine.md` — `internal/diag` (Runner exec+ssh, allowlist, approbation, audit,
   redaction), CLI `netc diag` / `netc path validate`, endpoints `POST /api/diag` et
   `POST /api/path/validate`. Dépend de `internal/path` (pour `ValidatePath`).
4. `diag-viewer-ui.md` — bouton « Valider le chemin » + diagnostic par hop dans la vue.
   Dépend de la Piste A (UI) et de l'étape 3 (endpoints).

Ordre global : **1 → 3** côté moteur (2 et 4 peuvent avancer en parallèle sur fixtures).

## Fixtures (permettent aux agents UI de démarrer sans backend)
- Chemin : `internal/server/assets/fixtures/*.json` (un par verdict).
- Diag : `internal/server/assets/fixtures/diag/*.json` (ping ok, needs_approval,
  config denied, path_validate match / mismatch).

## Garde-fous transverses
- La sortie diag est **observationnelle** : jamais dans le chemin de vérité déterministe.
  `/api/path/validate` compare prédit vs observé, ne les fusionne pas.
- Sécurité 100 % côté serveur (allowlist, approbation, redaction, audit) ; l'UI n'exécute
  rien. Les commandes de classe `config` sont refusées par défaut (charte read-only).
