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
| `nokia-sros/` | Nokia SR OS (7750) | hiérarchique | `configure ...`, distinction `port` vs `router interface`, `static-route-entry` |

Cisco IOS existe déjà dans `testdata/cisco-sw1.cfg` (famille IOS-like de référence).

## Implication pour le plan de fusion

Trois grands groupes de parsers à prévoir dans B :

1. **IOS-like** (Cisco, FS.com, Arista, +/- Huawei) — un parser ligne-à-ligne
   paramétrable couvre l'essentiel ; les variantes sont surtout le nommage
   d'interface et `x/len` vs `masque`. Meilleur ratio effort/couverture.
2. **set-form** (Juniper, VyOS) — le parser d'arbre Juniper de A se généralise ;
   VyOS est proche mais pas identique (mots-clés différents).
3. **Cas particuliers** (MikroTik script, Aruba VLAN-centric, Nokia hiérarchique)
   — chacun demande une passe dédiée ; l'appartenance VLAN d'Aruba et de MikroTik
   est déclarée **hors interface**, ce que l'IR de B (VLAN portés par `Device`)
   gère bien mais qui casse un parser purement « par bloc d'interface ».

## Sources (syntaxe de référence)

- FS.com FSOS — [FSOS config guide](https://img-en.fs.com/file/user_manual/n-series-switches-fsos-configuration-guide.pdf), [HON's Wiki](https://wiki.hon.one/networking/fs-fsos-switches/), [Dr. A's Wiki](https://dra.cs.southern.edu/NetworkConfiguration/FsComSwitchConfiguration)
- Juniper Junos — [Configure Static Routes](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html), [glyph.sh cheatsheet](https://glyph.sh/cheatsheets/juniper-junos/)
- MikroTik RouterOS — [IP Routing](https://help.mikrotik.com/docs/spaces/ROS/pages/328084/IP+Routing), [Configuration Management](https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management), [Bridging and Switching](https://help.mikrotik.com/docs/spaces/ROS/pages/328068/Bridging+and+Switching)
- VyOS — [Static protocol docs](https://docs.vyos.io/en/latest/configuration/protocols/static.html), [bertvv cheat-sheet](https://bertvv.github.io/cheat-sheets/VyOS.html)
- Huawei VRP — [Typical Static Route Configuration](https://support.huawei.com/enterprise/en/doc/EDOC1000069520/743f6e24/typical-static-route-configuration), [Typical VLAN Configuration](https://support.huawei.com/enterprise/en/doc/EDOC1000069520/b699322c/typical-vlan-configuration)
- Arista EOS — [Sample Configurations](https://www.arista.com/en/um-eos/eos-sample-configurations), [EOS config cheat sheet](https://www.cisconetsolutions.com/arista-eos-configuration-cheat-sheet/)
- ArubaOS-Switch — [Aruba 2530 Mgmt & Config Guide](https://www.intesiscon.com/ficheros/manuales-tecnicos/206-Switch-hp-aruba-j97773a.pdf), [VLAN config](https://www.arubanetworks.com/techdocs/central/2.5.2/content/switches/cfg/conf_vlan.htm)
- Nokia SR OS — [IP Router Config Command Reference](https://infocenter.nokia.com/public/7750SR140R4/topic/com.sr.router.config/html/ip_router_cli.html), [Static Routes on Nokia](https://ipcisco.com/lesson/static-routes-on-nokia-routers/)
