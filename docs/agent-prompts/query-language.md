# Tâche Codex — langage de requête simple (`netc query`)

## Contexte

`internal/query` répond à des requêtes texte sur l'inventaire IR. Syntaxe actuelle
(rigide, anglais, tokens exacts) :

```
vlan 42 | vlan 42 access | vlan 42 trunks
interface GigabitEthernet1/0/1
interfaces trunk
interfaces access vlan 42
default route
acl 101
device sw1
```

Préfixe optionnel `find` déjà supporté. Chaque résultat porte `Evidence`.

Packages touchés : `internal/query`, `cmd/netc/main.go` (option `--help-queries`),
`internal/server/ui.go` (hints UI), tests existants **ne doivent pas régresser**.

## Objectif

Étendre le parseur avec un **langage intuitif** (FR + EN, synonymes, formulations
naturelles) tout en restant **100 % déterministe** (pas de LLM, pas de fuzzy matching
aléatoire).

## Livrables

### 1. Refactor parseur (`internal/query`)

- Extraire la logique dans `parse.go` (ou `lang.go`) : normalisation → intent → args.
- **`normalizeQuery(q)`** : lowercase, trim, collapse spaces, strip optional `find`,
  strip trailing `?`, map FR accents optionnel (é→e minimal).
- **Table d'intents** ordonnée (first match wins, ordre documenté).

### 2. Intents à supporter (minimum)

Conserver **tous** les patterns existants + ajouter :

| Intent | Exemples acceptés (non exhaustif) |
|--------|-----------------------------------|
| `help` | `help`, `?`, `aide`, `commands` |
| `vlan` | `vlan 42`, `where is vlan 42`, `who uses vlan 42`, `ou est vlan 42`, `vlan 42 access/trunks/declared/used` |
| `interface` | `interface Gi0/1`, `intf Gi0/1`, `port Gi0/1` |
| `trunks` | `trunks`, `trunk ports`, `ports trunk`, `interfaces trunk`, `interfaces en trunk` |
| `access_vlan` | `access vlan 42`, `vlan 42 access ports`, `ports access vlan 42`, `interfaces access vlan 42` |
| `default_route` | `default route`, `default gateway`, `route 0/0`, `route par defaut`, `passerelle par defaut` |
| `route_dst` | `route to 192.168.50.0`, `routes vers 10.0.0.0/8`, `route for 192.168.50.0` (longest-prefix match sur `Route.Destination`) |
| `acl` | `acl 101`, `access-list 101`, `acl USERS-IN` |
| `device` | `device sw1`, `host sw1`, `equipement sw1`, `switch sw1` |
| `ntp` | `ntp`, `ntp servers`, `serveurs ntp` |
| `syslog` | `syslog`, `logging`, `syslog hosts`, `serveurs syslog` |
| `snmp` | `snmp`, `snmp communities`, `communautes snmp` |
| `zones` | `zones`, `firewall zones` (devices avec `Zones` non vides) |
| `policies` | `policies`, `security policies`, `politiques` (liste `SecurityPolicies`) |

### 3. Erreurs utiles

Si aucun intent ne matche :

```go
return nil, fmt.Errorf("requete non reconnue: %q (tapez 'help' pour la liste)", q)
```

`help` renvoie un `Result` de type `help` avec `Summary` = liste compacte des
patterns (ou plusieurs Results, un par ligne — choisir une forme stable).

### 4. CLI

```
netc query --input inventory.jsonl "help"
netc query --help-queries   # imprime les patterns sur stdout (sans inventaire)
```

### 5. UI (`internal/server/ui.go`)

Remplacer le hint statique par 4–6 exemples du langage intuitif :

```
vlan 42 · trunks · default route · ntp · route to 192.168.50.0 · help
```

### 6. Tests

- `internal/query/query_test.go` + `parse_test.go` : table-driven pour chaque intent
  et synonymes FR/EN.
- **Tous les tests existants verts** (régression zéro).
- Couverture `internal/query` ≥ **85 %**.

## Contraintes

- Déterminisme : même requête → mêmes résultats octet pour octet.
- Evidence-first : réutiliser les finders existants ; pas de résultat sans evidence.
- Stdlib only.
- Ne pas modifier les schémas gelés path/diag.
- `gofmt`, `go vet`, `go test ./...` verts.

## Critères d'acceptation

1. `netc query --input testdata/inventory.jsonl "ou est vlan 10"` retourne des résultats cohérents avec `vlan 10`.
2. `netc query ... "route par defaut"` ≡ `default route`.
3. `netc query ... "ntp"` liste les serveurs NTP avec evidence.
4. `netc query ... "help"` liste les patterns.
5. Requête inconnue → message avec suggestion `help`.
6. Couverture ≥ 85 %, tests existants passent.

## Hors périmètre

- Requêtes en langage libre / NLP / LLM.
- Modifier le format JSON de `Result` (sauf type `help` déjà compatible).
- Query cross-device graph (topology) — requêtes IR locales seulement.
