# Project Goal: SNMP Network Traffic Monitoring Application

The objective of this project is to develop a Python-based SNMP monitoring application capable of retrieving and displaying traffic data from network devices such as Arista switches, Cisco routers, and Cisco switches.

## ✅ Features Included:

Device Interface Discovery

IP Neighbor Discovery

Interface Traffic Monitoring (with live bps calculation)

Summary Export to CSV/JSON

Interactive Menu-Driven UI using rich for visual tables

## Functional Requirements

The application will include the following core features:

1. Device Interface Discovery
Automatically discover all active and inactive interfaces on the specified network device.

Retrieve interface descriptions, status, speeds, and operational state via SNMP.

2. IP Neighbor Discovery
Use SNMP queries to identify directly connected IP neighbors from the device’s perspective.

Present neighbor information clearly to assist in network topology visualization.

3. Traffic Monitoring per Interface

Continuously poll SNMP counters such as:

    ifInOctets, ifOutOctets (bytes in/out)

    ifInErrors, ifOutErrors (interface error statistics)

    ifInDiscards, ifOutDiscards (discarded packets)

Calculate and display live or near-real-time traffic rates (bps, errors/sec, etc.) based on polling interval.

## Usage Example

`python monitor_snmp.py --ip 192.168.1.1 --community public --interval 5`

## ✅ Key Benefits

Cross-vendor support (Cisco, Arista, and other SNMP-compliant devices)

Lightweight and fast, suitable for live diagnostics or polling-based monitoring

Pythonic and extensible, ideal for future integration with dashboards or alerting systems