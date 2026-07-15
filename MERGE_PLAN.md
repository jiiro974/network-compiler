# Plan de fusion — B absorbe le code pertinent de A

**Base cible :** `network-compiler` (repo B, `/Users/jro/dev/network-compiler`)
**Source :** `github.com/jro/netc` (repo A, `~/Documents/claude/network-compiler`)
**Principe :** B reste le tronc. On importe de A ce qui a de la valeur *nette*, en le
réécrivant vers l'IR et les contrats de B. On ne copie aucun fichier de A tel quel.

---

## 1. Pourquoi B est la base (et pas A)

| Point d'intégration | A (`netc`) | B (`network-compiler`) | Conséquence |
|---|---|---|---|
| Contrat parser | `Parse(file, src) (*ir.Config, error)` + `Registry` | `ParseFile(path) (ir.Device, error)` | On garde le contrat B, on lui ajoute un registre |
| `Evidence` | pointeur `*Evidence` | valeur `Evidence` | Réécriture des parsers de A |
| `Device` | séparé d'un `Config` | auto-porteur (embed collections) | Réécriture |
| `TrunkVLANs` | `string` | `[]int` | Conversion dans le portage |
| `Mode` | type `InterfaceMode` | `string` | Conversion |
| `Services` (NTP/Syslog/SNMP) | **absent** | **présent** + consommé par `compliance` | A doit apprendre à peupler `Services` |
| Couches aval | — | `diff`, `compliance`, `server` (API HTTP) | Actifs uniques de B, à préserver |

B a déjà `diff`, `compliance` (100 % couvert), un serveur HTTP et zéro dépendance.
Ce sont les acquis à ne pas casser. A apporte surtout **de l'ingestion** : un 2e
vendeur (Juniper) et la collecte SSH.

## 2. Ce qu'on prend de A — et ce qu'on laisse

**On prend (par valeur décroissante) :**

1. **Parser Juniper** (`internal/parser/juniper`) — rend B multi-vendeur. Plus gros gain.
2. **Le pattern `Registry`** (dispatch par vendeur) — B en a besoin dès qu'il a 2 parsers.
3. **Redacteur regex** (`internal/redact` de A) — plus robuste que le `secretredact`
   par mots-clés de B (gère `enable secret 5 <hash>`, `username X password Y`, etc.).
4. **Collecte SSH read-only** (`internal/collect` + `internal/creds`) — Phase 2, avec
   vérification host-key correcte. **Coûte la dépendance `golang.org/x/crypto`.** → voir §5.

**On laisse :**

- L'IR de A (pointeurs, `Config`), le `store` JSONL de A (B a déjà le sien), le
  câblage CLI de A, le parser Cisco de A (celui de B est déjà couvert à ~88 % et
  peuple déjà `Services`).

## 3. Séquencement (par phases, chaque phase compile + tests verts)

### Phase 0 — Filet de sécurité (prérequis)
- Mettre B sous git (aucun des deux repos n'est versionné actuellement) : `git init`,
  commit initial de l'état courant. Indispensable avant toute greffe.
- Fixer une CI locale minimale : `go build ./... && go vet ./... && go test ./...`.
- Geler un golden test de bout en bout sur `testdata/cisco-sw1.cfg` (sortie `parse`
  et `query`) pour détecter toute régression pendant la fusion.

### Phase 1 — Registre de parsers (fondation multi-vendeur)
- Créer `internal/parser/registry.go` dans B, adapté au contrat B :
  `Register(vendor string, p Parser)`, `Get(vendor) (Parser, bool)`, `Vendors() []string`.
- Router `parse`/`ingest` via le registre au lieu du Cisco codé en dur ; conserver le
  flag `--vendor` existant (défaut `cisco`).
- Ajouter une autodétection optionnelle du vendeur (heuristique : présence de
  `set ` en début de lignes → juniper ; sinon cisco) derrière `--vendor auto`.
- *Critère de sortie :* Cisco passe par le registre, tests inchangés verts.

### Phase 2 — Portage du parser Juniper vers l'IR de B
C'est le cœur du travail. Le Juniper de A produit `*ir.Config` (IR de A) ; il faut
un `juniper.Parser` qui implémente `ParseFile(path) (ir.Device, error)` de B.
- Copier la logique d'arbre (`node`, `tree`, `child`, `leafValue`, `splitLines`) — elle
  est vendeur-agnostique et réutilisable telle quelle.
- Adapter les points de sortie :
  - `Evidence` pointeur → valeur.
  - `TrunkVLANs string` → `[]int` (parser les listes `members`).
  - `Mode InterfaceMode` → `string` (`"access"`/`"trunk"`/`"routed"`).
  - Émettre un `ir.Device` auto-porteur, pas un `Config`.
  - **Peupler `ir.Services`** depuis Junos (`system ntp server`, `syslog host`,
    `snmp community`) pour que `compliance` fonctionne aussi sur Juniper.
- Reprendre les tests Juniper de A en les réécrivant sur l'IR de B (objectif ≥ 85 %
  comme le parser Cisco).
- *Critère de sortie :* `parse --vendor juniper testdata/junos-*.conf` sort un IR
  valide avec évidence, et `check`/`query`/`diff` marchent dessus.

### Phase 3 — Durcir la redaction
- Remplacer l'implémentation interne de `secretredact` par le moteur regex de A
  (mais **garder le nom de package `secretredact` et sa signature publique** pour ne
  rien casser en aval).
- Fusionner les jeux de tests : ceux de B (100 %) + les cas positionnels de A
  (`enable secret 5`, `username … password …`, `snmp-server community …`).
- *Critère de sortie :* couverture maintenue à 100 %, nouveaux cas couverts.

### Phase 4 — Collecte SSH (conditionnée à la décision §5)
- Si validée : porter `internal/collect` + `internal/creds` de A, brancher la sortie
  du collecteur dans `ingest` → parser via le registre → store.
- Conserver le défaut sûr de A : refus de connexion sans `known_hosts`, override
  explicite `--insecure-host-key`, collecte **read-only** uniquement.
- Ajouter la sous-commande `collect` au dispatch de `main.go`.
- *Critère de sortie :* `collect` en mode simulate (FakeRunner) testé sans équipement.

### Phase 5 — Exposition et doc
- Étendre l'API HTTP de B (`internal/server`) : endpoint `/api/vendors`, et exposer
  les résultats `collect`/multi-vendeur.
- Mettre à jour `README.md` et `SECURITY.md` de B (nouveaux vendeurs, éventuelle
  dépendance, commande `collect`). Rester honnête sur les dépendances — c'est le
  piège dans lequel A était tombé au départ.

## 4. Risques et points d'attention

- **Divergence des `testdata`** : les `cisco-sw1.cfg` des deux repos diffèrent. Ne pas
  supposer une équivalence de sortie ; figer les golden files côté B uniquement.
- **`Evidence` valeur vs pointeur** : source de bugs silencieux au portage (un zéro-value
  `Evidence{}` n'est pas `nil`). Vérifier chaque site d'émission.
- **`Services` obligatoire** : tout nouveau parser qui ne peuple pas `Services` rend la
  conformité aveugle sur ce vendeur — à traiter comme un manque, pas une option.
- **Ne pas régresser les couches aval** : `diff`, `compliance`, `server` sont les
  différenciateurs de B ; tests de non-régression à chaque phase.

## 5. Décision requise — politique de dépendances

La collecte SSH (Phase 4) impose `golang.org/x/crypto` (la stdlib Go n'a pas de client
SSH). Cela romprait l'invariant « zéro dépendance » revendiqué par B.

- **Option A — accepter la dépendance** : on gagne la collecte live, atout majeur de A.
  `x/crypto` est quasi-officiel (maintenu par l'équipe Go). Recommandé si la collecte
  sur équipements réels est un objectif produit.
- **Option B — rester stdlib pur** : on abandonne la Phase 4 (ou on shell-out vers le
  binaire `ssh` du système), on ne prend de A que Juniper + le redacteur regex.
  Recommandé si « zéro dépendance » est un principe non négociable.

**Reco par défaut :** faire Phases 0→3 dans tous les cas (aucune dépendance ajoutée),
puis trancher §5 avant la Phase 4.

## 6. Résumé exécutable

1. `git init` sur B + golden tests (Phase 0)
2. Registre multi-vendeur (Phase 1)
3. Porter Juniper vers l'IR de B, avec `Services` (Phase 2)
4. Durcir `secretredact` avec les regex de A (Phase 3)
5. **Décider §5**, puis éventuellement porter la collecte SSH (Phase 4)
6. API + doc à jour (Phase 5)

Les phases 0 à 3 n'ajoutent aucune dépendance et livrent déjà le gain principal :
un compilateur multi-vendeur, mieux blindé côté secrets, sur la base la plus propre.
