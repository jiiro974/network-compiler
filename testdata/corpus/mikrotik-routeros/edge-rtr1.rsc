# MikroTik RouterOS - /export style script (.rsc)
# Syntax family: path-command script, "add" statements with key=value
# name = edge-rtr1
/system identity set name=edge-rtr1
/system ntp client set enabled=yes servers=10.0.0.123
/system logging action add name=remote target=remote remote=10.0.0.50
/snmp community add name=public read-access=yes
/snmp set enabled=yes
/interface bridge add name=bridge-users vlan-filtering=yes
/interface vlan add name=vlan10-users interface=bridge-users vlan-id=10
/interface vlan add name=vlan20-voice interface=bridge-users vlan-id=20
/interface vlan add name=vlan99-mgmt interface=bridge-users vlan-id=99
/interface bridge port add bridge=bridge-users interface=ether1 pvid=10 comment=user-access
/interface bridge port add bridge=bridge-users interface=ether24 comment=uplink-core
/interface bridge vlan add bridge=bridge-users tagged=ether24 vlan-ids=10,20,99
/interface disable ether48
/ip address add address=10.0.99.2/24 interface=vlan99-mgmt comment=management
/ip route add dst-address=0.0.0.0/0 gateway=10.0.99.1
/ip route add dst-address=192.168.50.0/24 gateway=10.0.99.254
