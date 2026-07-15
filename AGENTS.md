# AGENTS.md — network-compiler

Contexte agent partagé par tous les outils (Cursor, Codex/GPT, Claude). Lu
automatiquement — **ne pas copier-coller les prompts** : y référer par chemin.

## Le projet
`netc` est un *network compiler* déterministe : il parse des configs multi-vendeurs,
les normalise en une IR canonique, répond à des requêtes et **attache une preuve**
(fichier / ligne / bloc brut) à chaque décision. Pas de LLM dans le chemin de vérité.

Module Go `network-compiler`, Go 1.24. Packages : `internal/ir`, `internal/parser`,
`internal/store`, `internal/query`, `internal/diff`, `internal/compliance`,
`internal/report`, `internal/server`, `cmd/netc`. Corpus de test multi-vendeur sous
`testdata/corpus/`.

## Répartition des rôles (workflow outillé)
- **Claude (dans Cursor)** : écrit/maintient les specs (`docs/`, `docs/agent-prompts/`)
  et **audite** le code. Voir la règle Cursor `10-spec-and-audit`.
- **GPT-5.5 (Codex)** : écrit le code à partir des specs. Voir `20-go-coding` + ce fichier.

Pour lancer une tâche, l'agent codeur lit le prompt de tâche concerné dans
`docs/agent-prompts/` et le schéma gelé associé — rien à coller.

## Contrats gelés (NE PAS MODIFIER)
Ajouter un champ optionnel est la seule évolution tolérée, et doit être répercutée dans
le fichier + bump de version.
- `docs/path-json-schema.md` — sortie de `netc path` / `GET /api/path`.
- `docs/diag-json-schema.md` — `netc diag`, `POST /api/diag`, `POST /api/path/validate`.

## Invariants (tous agents, toujours)
- **Déterminisme** : mêmes entrées → mêmes octets. Trier toute itération de map avant
  de produire un résultat. Aucun aléa, aucun LLM dans le chemin de vérité.
- **Evidence-first** : toute décision référence l'objet IR (et son `Evidence`) qui l'a
  produite. Pas de décision boîte noire.
- **Stdlib uniquement**, SAUF `internal/diag/transport` qui peut utiliser
  `golang.org/x/crypto` (isolé là, nulle part ailleurs).
- **Diag = observationnel** : la sortie live (ping/traceroute/exec) n'entre JAMAIS dans
  le chemin de vérité ; `/api/path/validate` compare prédit vs observé, ne fusionne pas.
- **Sécurité côté serveur** : allowlist, approbation, redaction, audit. L'UI n'exécute
  rien. Les commandes de classe `config` sont refusées par défaut (charte read-only).

## Portes de qualité (avant de considérer une tâche finie)
```
gofmt -l .          # doit être vide
go vet ./...        # propre
go build ./...      # ok
go test ./...       # vert
```
Couverture ≥ 85 % sur tout nouveau package de logique (`internal/path`, `internal/diag`).

## Plan de travail (4 agents, 2 pistes)
Détail et dépendances : `docs/agent-prompts/DISPATCH.md` et `ORCHESTRATION.md`.
- Piste A (fondation) : `path-tracer.md` (moteur) → `path-viewer-ui.md` (vue `/path`).
- Piste B (au-dessus, dépend de A) : `diag-engine.md` (moteur) → `diag-viewer-ui.md`.
- Ordre moteur obligatoire : `path-tracer` → `diag-engine`. Les UI peuvent avancer en
  parallèle sur les fixtures `internal/server/assets/fixtures/`.

## Conventions Go
Voir `20-go-coding`. En bref : `gofmt`, erreurs enveloppées (`%w`), pas de panique en
chemin normal, tests table-driven, noms exportés documentés, tags JSON `snake_case`
conformes aux schémas gelés.
