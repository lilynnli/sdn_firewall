# SDN Firewall Project

This is an SDN firewall implementation based on Ryu controller and Mininet, providing MAC address filtering and DDoS attack protection capabilities.

## Features

- MAC address whitelist filtering
- DDoS attack detection and protection
- Internal/External network isolation
- Automatic MAC address learning
- Automatic flow table rule deployment

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