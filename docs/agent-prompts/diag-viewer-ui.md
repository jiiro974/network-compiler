# Tâche Codex — diagnostic dans la vue chemin (UI)

## Contexte

Enrichir la **vue web du chemin** (`/path`, tâche `path-viewer-ui.md`) avec le
**diagnostic live** : depuis un chemin calculé, l'opérateur lance un ping / traceroute
vers les autres équipements pour *valider la réponse réelle* et la comparer au verdict
compilé.

> **Contrat verrouillé** — formats définis dans `docs/diag-json-schema.md`
> (`DiagResult`, `PathValidation`, endpoints `POST /api/diag`, `POST /api/path/validate`).
> Seule source de vérité. Coder strictement dessus ; dégrader proprement si un champ
> optionnel manque.

> **Prédit vs observé** — la vue doit distinguer visuellement le **verdict compilé**
> (déterministe, la « vérité » de netc) du **résultat live** (observation, faillible).
> Ne jamais présenter le live comme la vérité : ce sont deux couches superposées.

Design system inchangé (flat, sémantique vert/rouge/neutre, deux graisses, casse de
phrase, mono pour la sortie, clair+sombre, clavier, `sr-only`). Réutiliser le langage
visuel des maquettes déjà validées.

## Fonctionnalités à implémenter (priorisées)

### P0
1. **Bouton « Valider le chemin »** dans l'en-tête de la vue : appelle
   `POST /api/path/validate` avec le flux courant, puis **superpose** le résultat sur le
   ruban et les hops :
   - pastille par équipement passant de « prédit » (neutre) à **observé** :
     vert `reachable`, rouge `unreachable`, gris `inconclusive`.
   - bandeau de synthèse `agreement` : **match** (vert, « le réseau confirme le calcul »)
     ou **mismatch** (ambre/rouge, « divergence calcul ↔ réseau »). Le mismatch est
     l'information à la plus forte valeur — le rendre proéminent.
2. **Action par hop** : sur chaque carte de hop, un menu compact « diagnostiquer »
   → `ping next_hop`, `traceroute dst`, `show …`. Appelle `POST /api/diag` et affiche le
   `DiagResult` sous le hop (statut, `rendered_command` en mono, `parsed.ping`
   sent/recv/loss/rtt, et `raw_output` redigé repliable).
3. **États de statut** tous gérés : `ok`, `unreachable`, `timeout`, `denied`,
   `needs_approval`, `error` — chacun couleur + icône + libellé clairs.
4. **Flux d'approbation** : si `status: needs_approval`, afficher un encart d'approbation
   (motif, cible, commande) avec un champ token / bouton « demander l'approbation »
   (`sendPrompt` ou POST re-tenté avec `approval_token`). Ne jamais exécuter côté client :
   tout passe par l'API.

### P1
5. **Comparaison prédit/observé par hop** : côte à côte, la décision compilée (route/policy
   + evidence) et l'observation live (reachable + rtt). Surligner les hops en désaccord.
6. **Traceroute rendu** : `parsed.traceroute.hops[]` en petite liste ttl/host/rtt, alignée
   visuellement sur le ruban quand c'est possible.
7. **Provenance / audit** : afficher `audit_id` et l'horodatage sur chaque résultat
   (traçabilité), en discret.
8. **Sécurité visible** : badge de **classe** de commande (`diagnostic`/`exec`/`config`) et
   mention « sortie redigée » sur `raw_output`. Les commandes `config` apparaissent
   désactivées/refusées, jamais exécutables depuis l'UI.

### P2
9. **Re-run / rafraîchir** un check sans recharger ; historique léger des dernières
   validations (localStorage — app servie, pas un artifact).
10. **Export** du `PathValidation` en JSON ; permalien encodant flux + « validé ».

## Contraintes (bloquantes)
- Rendu strictement dérivé des JSON `DiagResult` / `PathValidation`. Champs optionnels
  absents ⇒ dégradation propre.
- **Aucune exécution côté client** : l'UI ne fait qu'appeler les endpoints ; toute la
  sécurité (allowlist, approbation, redaction, audit) est côté serveur.
- Distinction visuelle stricte **prédit (déterministe) vs observé (live)**.
- Design system respecté, clair+sombre, clavier, `sr-only`, pas de scroll imbriqué.
- Pas de dépendance externe ajoutée (ou CDN allowlisté justifié).

## Critères d'acceptation
1. « Valider le chemin » superpose l'état observé sur le ruban et affiche le bandeau
   `agreement` (démontrable via les fixtures `fixtures/diag/`).
2. Un hop peut être diagnostiqué (ping/traceroute/show) et son `DiagResult` s'affiche
   avec statut, commande rendue, stats parsées, sortie redigée repliable.
3. Les 6 statuts et le cas `needs_approval` (avec encart d'approbation) se rendent depuis
   les fixtures.
4. Un scénario `mismatch` (calcul dit livré, ping échoue) est clairement mis en avant.
5. Aucune commande `config` n'est exécutable depuis l'UI ; badge de classe visible.
6. Clair/sombre OK, clavier OK, dérivé strictement du contrat.

## Ordre de travail suggéré
1. Rendre un `PathValidation` de fixture : overlay ruban + bandeau `agreement` (P0.1).
2. Action par hop + `DiagResult` de fixture, tous statuts + approbation (P0.2–P0.4).
3. Comparaison prédit/observé, traceroute, provenance, badges sécurité (P1).
4. Brancher les vrais endpoints, puis P2.

## Hors périmètre
- Le moteur diag et le contrat (tâche `diag-engine.md`, schéma verrouillé).
- Toute logique de sécurité côté client (elle est serveur).
