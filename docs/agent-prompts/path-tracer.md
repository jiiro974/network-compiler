# Tâche Codex — moteur de traçage de chemin réseau (`netc path`)

## Contexte du dépôt

Tu travailles dans le dépôt Go `network-compiler` (module `network-compiler`, Go 1.24,
**zéro dépendance externe — stdlib uniquement**). C'est un « network compiler »
déterministe : il parse des configs, les normalise en une IR canonique, et répond à
des requêtes en attachant une **preuve** (fichier/ligne/bloc brut) à chaque objet.
Aucun LLM dans le chemin de vérité. Rien n'est inventé : on ne rend que ce que l'IR contient.

Packages existants à connaître (ne pas les casser) :

- `internal/ir` — types canoniques. `Device` embarque `Interfaces`, `VLANs`, `Routes`,
  `ACLs`, `Services`, et un `Evidence` (valeur, pas pointeur). Champs clés :
  - `Evidence{File, StartLine, EndLine, RawBlock, Parser}`
  - `Interface{Name, Description, Mode string, AccessVLAN int, TrunkVLANs []int, IPv4 string, Shutdown bool, Evidence}`
  - `Route{Destination, NextHop, Interface, AdministrativeDistance, VRF string, Evidence}`
  - `ACL{Name, Entries []ACLEntry}` ; `ACLEntry{Action, Protocol, Match, Raw string, Evidence}`
  - `Services{NTPServers, SyslogHosts, SNMPCommunities []ServiceTarget}`
- `internal/parser` — interface `Parser{ ParseFile(path string) (ir.Device, error) }`.
- `internal/store` — `MemoryStore` + `WriteJSONL/ReadJSONL([]ir.Device)`.
- `internal/query`, `internal/diff`, `internal/compliance`, `internal/report`.
- `internal/server` — API HTTP (`/api/summary`, `/api/devices`, `/api/query`, `/api/check`…).
- `cmd/netc/main.go` — dispatch des sous-commandes (`parse`, `query`, `ingest`,
  `inventory`, `check`, `diff`, `serve`).

Conventions du dépôt : tests table-driven, forte couverture, `gofmt`/`go vet` propres,
tout objet porte une `Evidence`.

## Objectif

Ajouter une fonctionnalité **traçage de chemin** : étant donné un flux
(`src`, `dst`, `proto`, `dport`), calculer de façon déterministe le chemin saut par
saut à travers les équipements de l'IR, avec la **preuve de configuration** de chaque
décision, et un **verdict** final. La fonctionnalité doit alimenter une future vue
HTML (schéma JSON stable). Elle doit gérer les **routeurs/switches L3** (décision =
route + ACL) **et les pare-feux** (décision = zone source/dest + règle de politique).

## Livrables

### 1. Extension de l'IR (`internal/ir`) — support pare-feu
Ajouter, tous avec `Evidence` et tags JSON `omitempty`, et les rattacher à `Device`
en champs optionnels pour ne rien casser :

- `Zone{Name string, Interfaces []string, Evidence}`
- `SecurityPolicy{Name, FromZone, ToZone, Application, Service, Action string, Evidence}`
  (`Action` ∈ `allow|deny`)
- `NATRule{Name, FromZone, ToZone, Kind string /* source|destination */, Translated string, Evidence}`
- Sur `Device` : `Zones []Zone`, `SecurityPolicies []SecurityPolicy`, `NATRules []NATRule`
  (`json:"...,omitempty"`).

Les parsers actuels n'émettent pas encore ces objets : c'est acceptable. Le moteur doit
se comporter correctement quand ils sont absents (un équipement sans zones est traité
comme un routeur L3 pur). Peupler zones/policies depuis les parsers pare-feu
(PAN-OS `set rulebase security rules ...`, FortiGate `config firewall policy`) est un
**sous-objectif secondaire** : fais-le pour au moins un vendeur (PAN-OS) si le temps
le permet, sinon laisse un TODO et des tests avec des `Device` construits en dur.

### 2. Nouveau package `internal/path` — le moteur
> **Contrat verrouillé** — le format de sérialisation est défini de façon
> autoritative dans `docs/path-json-schema.md` (clés `snake_case`). Les structs
> ci-dessous **doivent** porter les tags JSON correspondants (ex. `json:"ingress_zone,omitempty"`).
> Ce schéma prime en cas de divergence.

Types :

```go
type Flow struct { Src, Dst, Proto string; DPort int }

type Verdict string // "delivered" | "dropped_acl" | "dropped_policy" | "no_route" | "loop"

type Hop struct {
    Device       string
    Vendor       string
    IngressIface string
    IngressZone  string          `json:",omitempty"`
    RouteMatch   *ir.Route       `json:",omitempty"`
    ACLMatch     *ir.ACLEntry    `json:",omitempty"`
    PolicyMatch  *ir.SecurityPolicy `json:",omitempty"`
    NATApplied   *ir.NATRule     `json:",omitempty"`
    EgressIface  string
    EgressZone   string          `json:",omitempty"`
    NextHop      string
}

type Path struct {
    Flow    Flow
    Hops    []Hop
    Verdict Verdict
    // Reason pointe l'objet responsable du verdict final (evidence incluse).
    Reason  *ir.Evidence `json:",omitempty"`
}

func Trace(devices []ir.Device, flow Flow) (Path, error)
```

Règles de traçage (déterministes, pas d'heuristique floue) :

- **Résolution de topologie** : construire un index `IP → Device` et
  `subnet → Device` en scannant les `Interface.IPv4` de chaque `Device`. Le prochain
  saut se résout en trouvant l'équipement qui possède l'IP du `NextHop` (ou dont une
  interface est dans le même sous-réseau que le next-hop).
- **Décision L3 par équipement** : match **longest-prefix** sur `Device.Routes` pour
  `flow.Dst`. Route par défaut `0.0.0.0/0` en dernier recours. En cas d'égalité,
  départager par `AdministrativeDistance` puis ordre stable. Si aucune route → verdict
  `no_route`, `Reason` = evidence du device.
- **ACL** (si présentes sur l'interface d'egress/ingress) : première entrée qui matche
  `proto/dport`. Si `deny` → verdict `dropped_acl`, `Reason` = evidence de l'entrée.
- **Pare-feu** (si `Device.Zones`/`SecurityPolicies` non vides) : déterminer zone
  d'ingress et zone d'egress à partir des interfaces, puis first-match sur
  `SecurityPolicies` (`FromZone/ToZone/Service`). `deny` → `dropped_policy`.
  Appliquer `NATRules` si applicables (renseigner `NATApplied`, ne pas réécrire le
  flux pour le MVP — juste tracer).
- **Anti-boucle** : borne le nombre de sauts (ex. 16) ; dépassement → verdict `loop`.
- Le flux atteint sa destination quand un équipement possède directement le
  sous-réseau de `flow.Dst` → verdict `delivered`.

### 3. Sous-commande CLI `path`
Dans `cmd/netc/main.go`, ajouter `path` au dispatch :

```
netc path --store store.jsonl --src 10.0.10.55 --dst 192.168.50.20 --proto tcp --dport 443 [--json]
```

Sortie texte lisible par défaut (une ligne par hop + verdict), `--json` pour le `Path`
sérialisé. Réutiliser `internal/report` pour le rendu si pertinent.

### 4. Endpoint HTTP `/api/path`
Dans `internal/server`, ajouter `mux.HandleFunc("/api/path", s.handlePath)` qui lit
`src`, `dst`, `proto`, `dport` en query params et renvoie le `Path` en JSON
(mêmes règles d'erreur `writeError` que les handlers existants). **Ce JSON est le
contrat de la future vue HTML** — garde-le stable et documenté.

### 5. Tests
- `internal/path/path_test.go` — table-driven, **≥ 85 % de couverture**. Couvrir :
  chemin livré multi-équipements, `no_route`, `dropped_acl`, `dropped_policy`, boucle,
  et un chemin traversant un pare-feu (zones + policy). Construire les `Device` en dur
  et/ou parser des fichiers de `testdata/corpus/`.
- Un **golden test JSON** pour au moins un `Path` complet (fichier `testdata/`),
  pour verrouiller le contrat vis-à-vis de la vue HTML.
- `cmd/netc` : test de la commande `path` (le package a déjà des tests de main).

## Contraintes (bloquantes)
- **Stdlib uniquement** — aucune nouvelle dépendance dans `go.mod`.
- **Déterminisme total** : mêmes entrées → même `Path` octet pour octet. Trier toute
  itération de map avant de produire un résultat. Aucun LLM, aucune aléa.
- **Evidence obligatoire** : chaque décision tracée référence l'objet IR (et donc son
  `Evidence`) qui l'a produite. Pas de décision « boîte noire ».
- `gofmt -l` vide, `go vet ./...` propre, `go build ./...` et `go test ./...` verts.
- Ne pas modifier le comportement des packages existants (`query`, `diff`,
  `compliance`, `server`) au-delà des ajouts décrits.

## Critères d'acceptation
1. `go build ./... && go vet ./... && go test ./...` passent, couverture `internal/path` ≥ 85 %.
2. `netc path --src 10.0.10.55 --dst 192.168.50.20 --proto tcp --dport 443 --json`
   renvoie un `Path` avec ≥ 1 hop, un `Verdict`, et une `Evidence` par décision.
3. Un scénario firewall (zones + policy) produit `dropped_policy` avec la bonne
   `Evidence` quand une règle `deny` matche, et `delivered` sinon.
4. `/api/path` renvoie le même JSON que la CLI `--json`.
5. Le schéma JSON est documenté dans `docs/path-json-schema.md` (types, champs,
   valeurs de `Verdict`).

## Ordre de travail suggéré
1. Étendre l'IR (types + champs `Device`) et compiler.
2. Écrire `internal/path` avec `Device` construits en dur + tests (L3 d'abord, puis firewall).
3. Câbler la CLI `path`, puis l'endpoint `/api/path`.
4. (Si temps) peupler zones/policies dans le parser PAN-OS et ajouter un test bout-en-bout
   depuis `testdata/corpus/paloalto-panos/`.
5. Documenter le schéma JSON.

## Hors périmètre (ne pas faire)
- Réécriture d'adresse par le NAT (on trace, on n'altère pas le flux).
- Collecte live / SSH. ECMP multi-chemins (un seul chemin déterministe pour le MVP).
- La vue HTML elle-même (une autre tâche la branchera sur `/api/path`).
