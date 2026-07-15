# Corpus multi-vendeur — configs d'exemple

Jeu de configurations d'exemple pour tester/développer les parsers du
network-compiler. **Topologie logique identique dans chaque fichier** pour
pouvoir exercer aussi `diff` et `compliance` d'un vendeur à l'autre :

- hostname `edge-sw1` / `edge-rtr1`
- VLAN 10 `USERS`, VLAN 20 `VOICE`, VLAN 99 `MGMT`
- port d'accès (VLAN 10), port trunk (10/20/99), 1 port désactivé
- interface L3 / SVI sur VLAN 99 = `10.0.99.2/24`
- route par défaut via `10.0.99.1` + route statique `192.168.50.0/24` via `10.0.99.254`
- services : NTP `10.0.0.123`, syslog `10.0.0.50`, communauté SNMP `public`

> ⚠️ Les secrets présents (mots de passe, communautés) sont **factices** et
> servent justement à tester le redacteur. Aucun secret réel n'est commité.

L'inventaire JSONL agrégé pour `netc serve` / `netc query` vit dans
`../inventory.jsonl` (régénérer avec `netc ingest --input ./testdata/corpus --vendor auto --out testdata/inventory.jsonl`).

> Les configs sont synthétiques mais fidèles à la syntaxe documentée de chaque
> OS (voir Sources), pour éviter de committer des dumps réels contenant des IP
> ou identifiants de tiers.

## Familles de syntaxe (ce qui compte pour le parser)

| Dossier | Vendeur / OS | Famille | Particularités à parser |
|---|---|---|---|
| `fs-fsos/` | FS.com FSOS (S5800/S5860) | IOS-like | interfaces `eth-0-N`, `ip address x/len`, `vlan database`, `switchport trunk allowed only` |
| `arista-eos/` | Arista EOS | IOS-like | quasi-Cisco ; `ip address`/`ip route` en **préfixe** `x/len` |
| `huawei-vrp/` | Huawei VRP | VRP | séparateurs `#`, `interface Vlanif`, `port link-type`, `port trunk allow-pass vlan`, `ip route-static` |
| `juniper-junos/` | Juniper Junos (EX/QFX) | set-form | `set ...`, `family ethernet-switching`, `vlan members`, `irb.N`, VLAN nommé |
| `vyos/` | VyOS (lignée Vyatta) | set-form | `set interfaces ethernet ethN vif N`, `set protocols static route`, valeurs quotées |
| `mikrotik-routeros/` | MikroTik RouterOS | script `.rsc` | commandes par chemin `/ip route add`, paires `clé=valeur`, bridge vlan-filtering |
| `aruba-os-switch/` | ArubaOS-Switch (ex-ProCurve) | VLAN-centric | appartenance déclarée **sous le bloc `vlan`** via `tagged`/`untagged <ports>`, pas sous l'interface |
| `hpe-procurve/` | HP ProCurve (classic, 2610/5400zl) | VLAN-centric | **même lignée qu'ArubaOS-Switch** ; `untagged`/`tagged` sous `vlan`, `timesync sntp` |
| `aruba-cx/` | ArubaOS-CX (6200/6300/8320) | IOS-like | interfaces `1/1/N`, L2 par défaut, `vlan access`/`vlan trunk allowed` **sur l'interface**, `ip address x/len` |
| `hpe-comware/` | HPE Comware 7 (FlexFabric, ex-H3C) | Comware | séparateurs `#`, `Vlan-interface`, `port link-type`, `port trunk permit vlan`, `ip route-static <net> <mask-len>` |
| `cisco-nxos/` | Cisco NX-OS (Nexus 9000/3000) | IOS-like | `feature ...` obligatoire, `switchport`, `ip address x/len`, `ip route x/len nh` |
| `cisco-iosxr/` | Cisco IOS-XR (ASR9000/NCS) | IOS-like | stanzas fermées par `!`, `ipv4 address x masque`, sous-interfaces dot1q, `router static / address-family ipv4 unicast` |
| `extreme-exos/` | Extreme EXOS (X440/X460) | verbe-en-tête | `create vlan .. tag`, `configure vlan .. add ports .. tagged/untagged`, `configure iproute add` |
| `nokia-sros/` | Nokia SR OS (7750) | hiérarchique | `configure ...`, distinction `port` vs `router interface`, `static-route-entry` |
| `ubiquiti-edgeos/` | Ubiquiti EdgeOS (EdgeRouter) | set-form | Vyatta (frère de VyOS) ; VLANs en `eth N vif <id>` |
| `paloalto-panos/` | Palo Alto PAN-OS (pare-feu) | set-form | `set network interface ethernet .. layer3`, VLAN = sous-interfaces `tag`, zones, routes sous `virtual-router` |
| `fortinet-fortigate/` | Fortinet FortiGate (pare-feu) | FortiOS blocs | `config / edit / set / next / end`, VLAN = interface `type vlan vlanid`, `config router static` |

### Les trois CLI HPE (piège classique)

« HPE » n'est pas une syntaxe unique — trois familles cohabitent, à parser séparément :

- **ProCurve / ArubaOS-Switch** (`hpe-procurve/`, `aruba-os-switch/`) — même OS,
  VLAN-centric. L'appartenance VLAN est **hors interface**.
- **ArubaOS-CX** (`aruba-cx/`) — OS récent, style Cisco, appartenance **sur l'interface**.
- **Comware** (`hpe-comware/`) — héritage H3C, très présent en datacenter (FlexFabric).
  Proche de Huawei VRP côté mots-clés (`port link-type`, `ip route-static`) mais
  distinct (`port trunk permit vlan`, `Vlan-interface`).

Cisco IOS existe déjà dans `testdata/cisco-sw1.cfg` (famille IOS-like de référence).

## Implication pour le plan de fusion

Trois grands groupes de parsers à prévoir dans B :

1. **IOS-like** (Cisco IOS/NX-OS/IOS-XR, FS.com, Arista, ArubaOS-CX, +/- Huawei/Comware)
   — un parser ligne-à-ligne paramétrable couvre l'essentiel ; les variantes sont
   surtout le nommage d'interface et `x/len` vs `masque`. Meilleur ratio effort/couverture.
2. **set-form** (Juniper, VyOS, EdgeOS, PAN-OS) — le parser d'arbre Juniper de A se
   généralise ; les autres sont proches mais avec des mots-clés/chemins différents.
   PAN-OS et EdgeOS restent des dialectes distincts malgré la forme `set`.
3. **Cas particuliers** (MikroTik script, ProCurve/ArubaOS-Switch et Extreme EXOS
   VLAN-centric, Nokia hiérarchique, FortiGate en blocs `config/edit`) — chacun
   demande une passe dédiée. Chez ProCurve/Aruba-Switch, EXOS et MikroTik,
   l'appartenance VLAN est déclarée **hors interface**, ce que l'IR de B (VLAN portés
   par `Device`) gère bien mais qui casse un parser purement « par bloc d'interface ».

### Pare-feux (topologie différente)

PAN-OS et FortiGate sont des **pare-feux** : pas de VLAN L2 « switch » mais des
sous-interfaces taguées portant des zones de sécurité. L'IR de B les modélise via
interfaces + routes ; les zones/policies sortent du périmètre actuel de l'IR (piste
d'extension si besoin). PAN-OS réel est récupérable en direct via le connecteur `pafw`
si tu veux tester sur une vraie conf plutôt que sur cet exemple.

## Sources (syntaxe de référence)

- FS.com FSOS — [FSOS config guide](https://img-en.fs.com/file/user_manual/n-series-switches-fsos-configuration-guide.pdf), [HON's Wiki](https://wiki.hon.one/networking/fs-fsos-switches/), [Dr. A's Wiki](https://dra.cs.southern.edu/NetworkConfiguration/FsComSwitchConfiguration)
- Juniper Junos — [Configure Static Routes](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html), [glyph.sh cheatsheet](https://glyph.sh/cheatsheets/juniper-junos/)
- MikroTik RouterOS — [IP Routing](https://help.mikrotik.com/docs/spaces/ROS/pages/328084/IP+Routing), [Configuration Management](https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management), [Bridging and Switching](https://help.mikrotik.com/docs/spaces/ROS/pages/328068/Bridging+and+Switching)
- VyOS — [Static protocol docs](https://docs.vyos.io/en/latest/configuration/protocols/static.html), [bertvv cheat-sheet](https://bertvv.github.io/cheat-sheets/VyOS.html)
- Huawei VRP — [Typical Static Route Configuration](https://support.huawei.com/enterprise/en/doc/EDOC1000069520/743f6e24/typical-static-route-configuration), [Typical VLAN Configuration](https://support.huawei.com/enterprise/en/doc/EDOC1000069520/b699322c/typical-vlan-configuration)
- Arista EOS — [Sample Configurations](https://www.arista.com/en/um-eos/eos-sample-configurations), [EOS config cheat sheet](https://www.cisconetsolutions.com/arista-eos-configuration-cheat-sheet/)
- ArubaOS-Switch / ProCurve — [Aruba 2530 Mgmt & Config Guide](https://www.intesiscon.com/ficheros/manuales-tecnicos/206-Switch-hp-aruba-j97773a.pdf), [VLAN config](https://www.arubanetworks.com/techdocs/central/2.5.2/content/switches/cfg/conf_vlan.htm)
- ArubaOS-CX — [vlan trunk allowed (CLI ref)](https://arubanetworking.hpe.com/techdocs/AOS-CX/AOSCX-CLI-Bank/cli_8400/Content/Chp_VLANs/VLAN_cmds/vla-tru-all.htm), [AOS-CX 10.05 Fundamentals Guide](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.05/HTML/5200-7295/index.html)
- HPE Comware — [Working with Comware OS (basics)](https://kral2.fr/working-with-comware-os-hpe-flexfabric-switching-basics/), [HP 5820 VLAN Configuration](https://support.hpe.com/hpesc/public/docDisplay?docId=c03182828&docLocale=en_US)
- Cisco NX-OS / IOS-XR — syntaxe standard (feature toggles, `router static / address-family`) ; référence connue, pas de source unique.
- Extreme EXOS — [VLAN Configuration Examples](https://documentation.extremenetworks.com/exos_32.1/GUID-9FC94E71-1F71-46E6-A726-416BE5D640FF.shtml), [EXOS Basic Commands Cheat Sheet](https://hantechnote.wordpress.com/wp-content/uploads/2021/12/exos-commands-cheat-sheet_e99f93.pdf)
- Ubiquiti EdgeOS — lignée Vyatta (voir sources VyOS ci-dessus)
- Palo Alto PAN-OS — [Palo Alto Firewall Configuration through CLI](https://www.letsconfig.com/palo-alto-firewall-configuration-through-cli/)
- Fortinet FortiGate — [FortiGate Initial Config via CLI](https://layer77.net/2019/06/05/fortigate-initial-config-via-cli/), [FortiOS 7.6 First Config Steps](https://blog.boll.ch/fortigate-with-fortios-7-6-first-configuration-steps/)
- Nokia SR OS — [IP Router Config Command Reference](https://infocenter.nokia.com/public/7750SR140R4/topic/com.sr.router.config/html/ip_router_cli.html), [Static Routes on Nokia](https://ipcisco.com/lesson/static-routes-on-nokia-routers/)
