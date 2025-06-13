# SDN Firewall Project

This is an SDN firewall implementation based on Ryu controller and Mininet, providing MAC address filtering and DDoS attack protection capabilities.

## Features

- MAC address whitelist filtering
- DDoS attack detection and protection
- Internal/External network isolation
- Automatic MAC address learning
- Automatic flow table rule deployment

## Security-Enhanced SDN (mac-filtering) logic
This project implements an SDN-based firewall that separates an internal (secure) network from an external (DMZ) segment, using MAC address filtering to control access.

- Internal Ports: All traffic between hosts on internal ports is permitted. Connections initiated from internal to external ports are also allowed without restrictions.
 -    External Ports:Traffic coming from external ports into the internal network is only allowed if the device's MAC address is in a whitelist.
    Communication between devices connected to external ports (external-to-external) is permitted.
   
## DDoS mitigation in SDN logic
The project also includes a DDoS detection and mitigation mechanism within the SDN controller.

The system monitors how many requests each device on the external segment sends to each device inside the internal network.
   -  For every device inside the internal network, the system keeps track of both the number of requests from each individual external device and the overall total number of requests from all external devices.
   -  If the number of requests from one external device exceeds a certain limit, or the total number of requests from all external devices combined exceeds another limit within a short time window, the system identifies this as a potential DDoS attack.
   -  When an attack is detected, further traffic from the detected external device is temporarily blocked for a set period.
   -  DDoS detection and blocking are applied only to connections coming from external devices into the internal network. 

## System Requirements

- Python 3.x
- Ryu Controller
- Mininet
- Open vSwitch

## Installation

```bash
pip install ryu
pip install mininet
```

## Running Instructions

1. First, start the Ryu controller:
```bash
ryu-manager sdn_firewall.py
```

2. In another terminal, run the Mininet topology:
```bash
sudo python mininet_topology.py
```

## Network Topology

The project uses a simple star topology:
- 1 OpenFlow switch (s1)
- 4 hosts (h1-h4)
- All hosts connected to the same switch

## Security Policies

- MAC Address Whitelist:
  - h1 (00:00:00:00:00:01)
  - h2 (00:00:00:00:00:02)
  - h4 (00:00:00:00:00:04)

- DDoS Protection:
  - Time window: 5 seconds
  - Threshold: 2 different source IPs

## Testing Methods

1. In Mininet CLI, you can test connectivity using:
```bash
h1 ping h2
h1 ping h3
h2 ping h4
```

2. Test DDoS protection:
```bash
h3 ping -c 100 h1
```

## Notes

- Ensure the Ryu controller is running before starting the firewall application
- Root privileges required to run Mininet
- Default controller listening address is 127.0.0.1:6633 
