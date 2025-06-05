
import time
import json
import csv
from rich.console import Console
from rich.table import Table
from pysnmp.hlapi import *

console = Console()

def snmp_get_v3(ip, user, auth_key, priv_key, oid, auth_proto, priv_proto):
    iterator = getCmd(
        SnmpEngine(),
        UsmUserData(user, auth_key, priv_key, authProtocol=auth_proto, privProtocol=priv_proto, securityLevel='authPriv'),
        UdpTransportTarget((ip, 161), timeout=2.0, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        return None
    elif errorStatus:
        return None
    else:
        for varBind in varBinds:
            return varBind[1]

def snmp_walk_v3(ip, user, auth_key, priv_key, oid, auth_proto, priv_proto):
    results = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        UsmUserData(user, auth_key, priv_key, authProtocol=auth_proto, privProtocol=priv_proto, securityLevel='authPriv'),
        UdpTransportTarget((ip, 161), timeout=2.0, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            return []
        for varBind in varBinds:
            results.append((str(varBind[0]), str(varBind[1])))
    return results

def interface_discovery(ip, user, auth_key, priv_key, auth_proto, priv_proto):
    descrs = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.2', auth_proto, priv_proto)
    statuses = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.8', auth_proto, priv_proto)
    speeds = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.5', auth_proto, priv_proto)

    table = Table(title="Interface Discovery")
    table.add_column("Index", style="cyan")
    table.add_column("Description")
    table.add_column("Status")
    table.add_column("Speed (bps)")

    data = []
    for i in range(len(descrs)):
        index = descrs[i][0].split('.')[-1]
        desc = descrs[i][1]
        status = "up" if statuses[i][1] == '1' else "down"
        speed = speeds[i][1]
        table.add_row(index, desc, status, speed)
        data.append({'index': index, 'description': desc, 'status': status, 'speed': speed})

    console.print(table)
    return data

def ip_neighbor_discovery(ip, user, auth_key, priv_key, auth_proto, priv_proto):
    neighbors = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.4.22.1.2', auth_proto, priv_proto)

    table = Table(title="IP Neighbors")
    table.add_column("IP Address", style="magenta")
    table.add_column("MAC Address")

    data = []
    for oid, mac in neighbors:
        parts = oid.split('.')[-4:]
        ip_addr = '.'.join(parts)
        table.add_row(ip_addr, mac)
        data.append({'ip_address': ip_addr, 'mac_address': mac})

    console.print(table)
    return data

def traffic_monitor(ip, user, auth_key, priv_key, auth_proto, priv_proto, interval=5):
    in_octets_1 = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.10', auth_proto, priv_proto)
    out_octets_1 = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.16', auth_proto, priv_proto)
    time.sleep(interval)
    in_octets_2 = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.10', auth_proto, priv_proto)
    out_octets_2 = snmp_walk_v3(ip, user, auth_key, priv_key, '1.3.6.1.2.1.2.2.1.16', auth_proto, priv_proto)

    table = Table(title="Interface Traffic (bps)")
    table.add_column("Index", style="green")
    table.add_column("In (bps)")
    table.add_column("Out (bps)")

    data = []
    for i in range(len(in_octets_1)):
        idx = in_octets_1[i][0].split('.')[-1]
        in_bps = (int(in_octets_2[i][1]) - int(in_octets_1[i][1])) * 8 // interval
        out_bps = (int(out_octets_2[i][1]) - int(out_octets_1[i][1])) * 8 // interval
        table.add_row(idx, str(in_bps), str(out_bps))
        data.append({'index': idx, 'in_bps': in_bps, 'out_bps': out_bps})

    console.print(table)
    return data

def export_data(data, filename, mode='json'):
    if mode == 'json':
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    elif mode == 'csv':
        keys = data[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)

def main():
    ip = input("Enter target IP address: ")
    user = input("Enter SNMPv3 username: ")
    auth_key = input("Enter SNMPv3 auth password: ")
    priv_key = input("Enter SNMPv3 priv password: ")

    auth_proto = usmHMACSHAAuthProtocol
    priv_proto = usmDESPrivProtocol

    while True:
        console.print("\n[bold yellow]Select Feature:[/bold yellow]")
        console.print("1. Interface Discovery\n2. IP Neighbor Discovery\n3. Traffic Monitor\n4. Export Last Data\n5. Exit")
        choice = input("Choice: ")

        if choice == '1':
            last_data = interface_discovery(ip, user, auth_key, priv_key, auth_proto, priv_proto)
        elif choice == '2':
            last_data = ip_neighbor_discovery(ip, user, auth_key, priv_key, auth_proto, priv_proto)
        elif choice == '3':
            last_data = traffic_monitor(ip, user, auth_key, priv_key, auth_proto, priv_proto)
        elif choice == '4':
            mode = input("Export as [json/csv]: ")
            filename = input("Filename (with extension): ")
            export_data(last_data, filename, mode)
            print(f"Data exported to {filename}")
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
