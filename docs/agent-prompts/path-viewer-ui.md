# Tâche Codex — vue HTML du chemin réseau (améliorations UI)

## Contexte

Construire/faire évoluer la **vue web du traçage de chemin** de `netc`. Elle consomme
le JSON de l'endpoint `/api/path`.

> **Contrat verrouillé** — le format JSON est défini de façon autoritative dans
> `docs/path-json-schema.md` (clés `snake_case`, enum `verdict`, exemples + fixtures).
> C'est la **seule** source de vérité du format. Ne pas se fier à un extrait de code :
> lire ce fichier et coder la vue strictement dessus. Si un champ manque pour l'UI,
> c'est une demande d'évolution du schéma (v2), pas une improvisation.

Principes produit à respecter :
- **Evidence-first** : aucune décision n'est une boîte noire ; chaque hop doit pouvoir
  révéler le bloc de conf exact (fichier:ligne, ligne matchée surlignée).
- **Déterministe** : la vue ne fait que *rendre* le JSON. Elle n'invente rien, ne
  recalcule pas de décision, ne réordonne pas les hops.
- **Multi-vendeur** : badge vendeur lisible par hop.

Le design de référence est validé (deux maquettes : chemin multi-hop + détail
firewall permit/deny, plus la maquette « cible » enrichie). Reprends **exactement** ce
langage visuel :
- surfaces plates, blanches ; bordures `0.5px`, radius `12px` sur cartes, `8px` sur
  contrôles ; **pas** de gradient / ombre / glow.
- casse de phrase partout (jamais de TITRE ni Title Case) ; deux graisses seulement
  (400 / 500) ; conf en `monospace`.
- couleurs **sémantiques** : vert = livré/permit, rouge = bloqué, neutre = traversé,
  accent = élément sélectionné. Chaque couleur doit fonctionner en clair **et** sombre.
- icônes Tabler outline.

## Cible technique

- **Un seul fichier HTML autonome** (CSS + JS inline, aucune étape de build).
  Placement suggéré : `internal/server/assets/path.html`, servi par `internal/server`
  sur `GET /path` (ajouter la route + un `//go:embed` de l'asset). Pas de dépendance
  externe si évitable ; si un lib est vraiment nécessaire, uniquement via CDN allowlisté.
- La page lit `src/dst/proto/dport` depuis la query string, appelle `GET /api/path`,
  et rend le `Path`. Rechargeable et **partageable par URL**.
- Accessibilité : résumé `sr-only` en tête, `aria-label` sur les boutons icône,
  focus rings, contraste OK dans les deux thèmes, navigation clavier.

## Améliorations à implémenter (priorisées)

### P0 — cœur de l'expérience
1. **Barre de flux éditable** : champs `source`, `destination`, `proto`, `port` +
   bouton `Tracer` qui appelle `/api/path` et rerend sans recharger la page. Met à
   jour la query string (état partageable).
2. **Hops en accordéon** : *chaque* hop est dépliable vers son evidence (pas seulement
   un pré-sélectionné). Un chevron indique l'état ; l'état ouvert/fermé est mémorisé
   par index (localStorage OK — c'est une app servie, pas un artifact).
3. **Bloc d'evidence enrichi** :
   - numéros de ligne ; **ligne matchée surlignée** (fond accent/vert/rouge selon la
     nature de la décision) ; **±3 lignes de contexte grisées** (opacité réduite).
   - bouton **copier** le bloc brut ; bouton **ouvrir** `fichier:ligne`
     (schéma d'URL éditeur configurable, ex. `vscode://file/{path}:{line}` ; fallback :
     `sendPrompt`/`openLink`). Scroll horizontal si lignes longues.
4. **Bannière de verdict** proéminente, colorée selon l'enum `Verdict`, avec l'objet
   responsable (`Path.Reason`) en **chip cliquable** qui déplie et scrolle jusqu'au hop
   fautif.
5. **Tous les états de `Verdict` gérés** : `delivered`, `no_route`, `dropped_acl`,
   `dropped_policy`, `loop` — chacun avec couleur + icône + contenu explicatif distincts
   (y compris états « vides » : aucun chemin, boucle détectée).

### P1 — lisibilité & navigation
6. **Ruban d'aperçu** horizontal : source ● → hops → ● dest, avec **pastille de statut**
   par équipement (vert/rouge/neutre), clic = scroll vers le hop, survol = tooltip
   (device, vendeur, décision). Se replie en vertical sur écran étroit.
7. **Rangée de métriques** : nombre de sauts, d'équipements, de vendeurs traversés,
   verdict. (Cartes `--surface-1`, label 13px muted, valeur 24px/500.)
8. **Chips zone / VLAN** cohérents et une **carte des icônes vendeur**
   (cisco/juniper/pan-os/fortigate/mikrotik/aruba…). Badge vendeur sur chaque hop.
9. **Pipeline firewall** : quand un hop possède `IngressZone`/`PolicyMatch`, rendre les
   sous-étapes `ingress+zone → route → policy → NAT → egress+zone` (comme la maquette
   firewall). Sinon rendu L3 simple `route (+ACL)`. **Piloté par la présence des champs
   dans le JSON**, jamais deviné.
10. **Légende** compacte des couleurs/verdicts.
11. **Responsive** : ruban horizontal en large, empilé en étroit ; **aucun scroll
    imbriqué** ; hauteur auto.

### P2 — puissance
12. **Mode diff de chemin** : superposer un `Path` `before` et `after` (source :
    package `internal/diff`) et surligner les hops/décisions qui changent.
13. **Filtre** « points de décision seulement » vs « pipeline complet ».
14. **Navigation clavier** : `↑/↓` entre hops, `Entrée` pour déplier, `c` pour copier
    l'evidence du hop focus.
15. **Export** : copier le `Path` en JSON ; lien permalien encodant le flux.

## Contraintes (bloquantes)
- Rendu **strictement** dérivé du JSON `/api/path`. Si un champ optionnel est absent
  (`PolicyMatch`, `IngressZone`, `Reason`…), dégrader proprement sans erreur.
- Respect intégral du design system ci-dessus (flat, sémantique, deux graisses,
  casse de phrase, mono pour la conf).
- Fonctionne en thème clair et sombre (tester les deux).
- Pas de framework lourd ; vanilla JS suffit. Fichier lisible et commenté sobrement.
- Ne pas modifier le moteur `internal/path` ni le contrat JSON ; si un champ manque
  pour l'UI, l'ajouter est une demande séparée à documenter, pas à improviser.

## Critères d'acceptation
1. `GET /path?src=10.0.10.55&dst=192.168.50.20&proto=tcp&dport=443` affiche le chemin
   complet : barre de flux, métriques, bannière de verdict, ruban, hops en accordéon,
   evidence enrichie, légende.
2. Chaque hop peut être déplié/replié indépendamment ; l'evidence montre la ligne
   matchée surlignée + contexte grisé + boutons copier/ouvrir fonctionnels.
3. Les cinq verdicts se rendent correctement à partir de fixtures JSON (livrer une
   **galerie d'états** : une page ou un mode qui charge un JSON d'exemple par verdict,
   sous `internal/server/assets/fixtures/`).
4. Un hop firewall (zones + policy) affiche le pipeline complet ; un hop L3 affiche le
   rendu simple — sans code spécifique vendeur, uniquement selon les champs présents.
5. Clair/sombre OK, navigation clavier OK, `sr-only` présent, aucun scroll imbriqué.
6. Aucune dépendance externe ajoutée (ou uniquement CDN allowlisté, justifié).

## Ordre de travail suggéré
1. Servir `path.html` (`//go:embed`, route `/path`) + parseur du JSON `/api/path`.
2. Rendu statique d'un `Path` de fixture : ruban + hops + evidence (P0.2, P0.3).
3. Bannière de verdict + galerie des 5 états (P0.4, P0.5) via fixtures.
4. Barre de flux live (P0.1), métriques et légende (P1.7, P1.10).
5. Pipeline firewall conditionnel (P1.9), ruban interactif (P1.6), responsive (P1.11).
6. P2 selon le temps disponible.

## Hors périmètre
- Le moteur de trace et le contrat JSON (déjà spécifiés ailleurs).
- Authentification / multi-tenant. Édition de conf depuis la vue (lecture seule).
