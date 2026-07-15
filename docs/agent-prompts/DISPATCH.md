# Prompt de dispatch Codex — fonctionnalité chemin + diagnostic (4 agents)

Copier-coller ce prompt à l'orchestrateur Codex.

---

Tu es l'orchestrateur d'une fonctionnalité sur le dépôt Go `network-compiler`
(Go 1.24, déterministe, evidence-first). Tu livres DEUX pistes via QUATRE agents, dans
l'ordre des dépendances.

CONTRATS GELÉS (aucun agent ne les modifie ; ajout d'un champ optionnel = seule évolution,
à répercuter dans le fichier + bump v2) :
- `docs/path-json-schema.md` — chemin compilé.
- `docs/diag-json-schema.md` — diagnostic/exec live + validation de chemin.

INVARIANTS TRANSVERSES (à faire respecter par chaque agent) :
- Stdlib uniquement, SAUF `internal/diag/transport` qui peut utiliser
  `golang.org/x/crypto` (isolé là, nulle part ailleurs).
- Le compilateur reste déterministe et evidence-first. La sortie diag est
  OBSERVATIONNELLE : jamais dans le chemin de vérité ; `/api/path/validate` compare
  prédit vs observé, ne les fusionne pas.
- Sécurité 100 % côté serveur (allowlist, approbation, redaction, audit) ; l'UI n'exécute
  rien. Les commandes de classe `config` sont refusées par défaut (charte read-only).

PORTES DE QUALITÉ (après CHAQUE agent, bloquantes) :
- `gofmt -l .` vide · `go vet ./...` propre · `go build ./...` et `go test ./...` verts
- couverture ≥ 85 % sur le package livré (`internal/path`, puis `internal/diag`).
Si une porte échoue, corrige avant de passer à l'agent suivant.

──────────────── PISTE A — CHEMIN (fondation) ────────────────

AGENT 1 — backend chemin. Exécute `docs/agent-prompts/path-tracer.md` :
moteur `internal/path` (`Trace`), extension IR firewall (Zone/SecurityPolicy/NATRule,
champs optionnels avec evidence), CLI `netc path --json`, endpoint `GET /api/path`.
Sortie IDENTIQUE à `docs/path-json-schema.md`. Génère les fixtures
`internal/server/assets/fixtures/*.json` (une par verdict) + un golden test.
→ passer les portes de qualité.

AGENT 2 — UI chemin. Exécute `docs/agent-prompts/path-viewer-ui.md` :
vue HTML autonome `/path` (`//go:embed`) consommant `GET /api/path`, rendu strictement
dérivé du JSON gelé, galerie des 5 verdicts via fixtures, design system respecté
(flat, sémantique, deux graisses, casse de phrase, mono, clair+sombre, clavier, sr-only).
Peut démarrer sur les fixtures sans attendre l'Agent 1 ; intégration finale sur l'endpoint réel.
→ passer les portes de qualité.

──────────────── PISTE B — DIAGNOSTIC & EXEC (au-dessus) ────────────────

AGENT 3 — backend diag. Exécute `docs/agent-prompts/diag-engine.md` :
`internal/diag` avec `Runner` (ExecRunner os/exec + SSHRunner x/crypto isolé + FakeRunner),
mapping de commandes par vendeur, classes diagnostic/exec/config (allowlist + deny-list),
approbation (exec), refus config par défaut, redaction, timeouts, audit ; `ValidatePath`
(réutilise `internal/path`, sans le modifier) ; CLI `netc diag` et `netc path validate` ;
endpoints `POST /api/diag` et `POST /api/path/validate`. Sortie IDENTIQUE à
`docs/diag-json-schema.md`. Tests via FakeRunner uniquement (aucun réseau), fixtures
`internal/server/assets/fixtures/diag/*.json`.
Dépend de l'Agent 1 (moteur `internal/path`). → passer les portes de qualité.

AGENT 4 — UI diag. Exécute `docs/agent-prompts/diag-viewer-ui.md` :
bouton « Valider le chemin » (overlay observé sur le ruban + bandeau agreement
match/mismatch), diagnostic par hop (ping/traceroute/show), tous les statuts dont
`needs_approval`, distinction visuelle stricte prédit (déterministe) vs observé (live),
aucune exécution côté client. Dépend de l'Agent 2 (vue chemin) et de l'Agent 3 (endpoints) ;
peut démarrer sur les fixtures `fixtures/diag/`.
→ passer les portes de qualité.

ORDRE GLOBAL : 1 → 3 côté moteur (obligatoire). 2 et 4 peuvent avancer en parallèle sur
les fixtures. Intégration finale : 2 sur `/api/path`, 4 sur `/api/diag` + `/api/path/validate`.

DÉFINITION DE FINI :
1. `netc path --src 10.0.10.55 --dst 192.168.50.20 --proto tcp --dport 443 --json`
   produit le JSON conforme à `path-json-schema.md`.
2. `netc path validate ...` et `netc diag --target edge-sw1 --ping 10.0.99.1 --json`
   produisent des JSON conformes à `diag-json-schema.md`.
3. `GET /path` affiche le chemin (barre de flux, métriques, verdict, ruban, hops en
   accordéon, evidence) ; « Valider le chemin » superpose l'état observé + agreement.
4. `exec` sans approbation → `needs_approval` ; `config` → `denied` ; rien ne s'exécute
   côté client.
5. Toutes les portes de qualité passent ; `x/crypto` isolé dans `internal/diag/transport` ;
   les deux contrats gelés sont inchangés (ou versionnés v2 et documentés).

Lis d'abord `docs/agent-prompts/ORCHESTRATION.md`, les deux schémas gelés, puis les quatre
prompts de tâche. Commence par l'Agent 1.

---
