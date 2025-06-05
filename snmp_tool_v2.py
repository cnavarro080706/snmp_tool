
import time
import csv
import json
from rich.console import Console
from rich.table import Table
from pysnmp.hlapi import *

console = Console()

def snmp_walk(community, ip, oid):
    result = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication:
            console.print(f"[red]SNMP Error: {errorIndication}[/red]")
            break
        elif errorStatus:
            console.print(f"[red]SNMP Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}[/red]")
            break
        else:
            for varBind in varBinds:
                result.append((str(varBind[0]), str(varBind[1])))
    return result

def snmp_get(community, ip, oid):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )
    if errorIndication:
        console.print(f"[red]SNMP Error: {errorIndication}[/red]")
    elif errorStatus:
        console.print(f"[red]SNMP Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}[/red]")
    else:
        for varBind in varBinds:
            return str(varBind[1])
    return None

def interface_discovery(ip, community):
    console.print("[bold green]Discovering interfaces...[/bold green]")
    descr = snmp_walk(community, ip, '1.3.6.1.2.1.2.2.1.2')  # ifDescr
    status = snmp_walk(community, ip, '1.3.6.1.2.1.2.2.1.8')  # ifOperStatus

    table = Table(title="Interface Discovery")
    table.add_column("Index")
    table.add_column("Description")
    table.add_column("Status")
    summary = []

    for i in range(len(descr)):
        idx = descr[i][0].split('.')[-1]
        table.add_row(idx, descr[i][1], "up" if status[i][1] == '1' else "down")
        summary.append({
            'index': idx,
            'description': descr[i][1],
            'status': 'up' if status[i][1] == '1' else 'down'
        })

    console.print(table)
    return summary

def neighbor_discovery(ip, community):
    console.print("[bold green]Discovering IP neighbors...[/bold green]")
    entries = snmp_walk(community, ip, '1.3.6.1.2.1.4.22.1.2')  # ipNetToMediaPhysAddress
    table = Table(title="IP Neighbor Table")
    table.add_column("IP Address")
    table.add_column("MAC Address")
    neighbors = []
    for oid, mac in entries:
        ip_addr = oid.split('.')[-4:]
        ip_str = '.'.join(ip_addr)
        table.add_row(ip_str, mac)
        neighbors.append({'ip': ip_str, 'mac': mac})
    console.print(table)
    return neighbors

def monitor_traffic(ip, community, interval=5, iterations=3):
    console.print(f"[bold green]Monitoring traffic every {interval} seconds ({iterations} iterations)...[/bold green]")
    in_oid = '1.3.6.1.2.1.2.2.1.10'  # ifInOctets
    out_oid = '1.3.6.1.2.1.2.2.1.16' # ifOutOctets
    descr_oid = '1.3.6.1.2.1.2.2.1.2' # ifDescr

    descrs = snmp_walk(community, ip, descr_oid)
    results = []

    for i in range(iterations):
        in_data = snmp_walk(community, ip, in_oid)
        out_data = snmp_walk(community, ip, out_oid)
        timestamp = time.time()
        time.sleep(interval)
        in_data_next = snmp_walk(community, ip, in_oid)
        out_data_next = snmp_walk(community, ip, out_oid)
        timestamp_next = time.time()

        delta_t = timestamp_next - timestamp
        table = Table(title=f"Interface Traffic (Iteration {i+1})")
        table.add_column("Interface")
        table.add_column("In Rate (bps)")
        table.add_column("Out Rate (bps)")

        for j in range(len(descrs)):
            iface = descrs[j][1]
            in_rate = (int(in_data_next[j][1]) - int(in_data[j][1])) * 8 / delta_t
            out_rate = (int(out_data_next[j][1]) - int(out_data[j][1])) * 8 / delta_t
            table.add_row(iface, f"{in_rate:.2f}", f"{out_rate:.2f}")
            results.append({
                'interface': iface,
                'in_bps': round(in_rate, 2),
                'out_bps': round(out_rate, 2),
                'timestamp': timestamp_next
            })
        console.print(table)
    return results

def export_data(data, filename, file_format='csv'):
    console.print(f"[blue]Exporting data to {filename} as {file_format}...[/blue]")
    if file_format == 'csv':
        keys = data[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, keys)
            writer.writeheader()
            writer.writerows(data)
    elif file_format == 'json':
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

def main():
    ip = input("Enter device IP address: ").strip()
    community = input("Enter SNMP community string: ").strip()
    interval = int(input("Enter polling interval in seconds [default 5]: ") or "5")
    iterations = int(input("Enter number of iterations [default 3]: ") or "3")

    interface_data = []
    neighbor_data = []
    traffic_data = []

    while True:
        print("\n[1] Interface Discovery")
        print("[2] IP Neighbor Discovery")
        print("[3] Traffic Monitoring")
        print("[4] Export All Data")
        print("[5] Exit")

        choice = input("Select an option: ").strip()
        if choice == '1':
            interface_data = interface_discovery(ip, community)
        elif choice == '2':
            neighbor_data = neighbor_discovery(ip, community)
        elif choice == '3':
            traffic_data = monitor_traffic(ip, community, interval, iterations)
        elif choice == '4':
            if interface_data:
                export_data(interface_data, 'interfaces.csv', 'csv')
            if neighbor_data:
                export_data(neighbor_data, 'neighbors.json', 'json')
            if traffic_data:
                export_data(traffic_data, 'traffic.json', 'json')
        elif choice == '5':
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
