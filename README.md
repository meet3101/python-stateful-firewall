# Python Stateful Firewall

A stateful packet-filtering firewall built in Python using Scapy. It goes beyond simple static allow/deny rules by tracking real TCP connection state, and includes automatic detection and blocking of SYN flood attacks.

## Features
- Rule-based packet filtering (YAML config) — allow/deny by protocol, port, source IP
- **Stateful connection tracking** — automatically allows return traffic for connections that were legitimately initiated, without re-matching every rule
- **SYN flood detection & auto-blocking** — tracks SYN packet rate per source IP; if an IP exceeds a threshold within a time window, it's automatically blocked
- Full test suite (pytest) for the rule engine
- Attack simulation script to demonstrate detection live

## Architecture
Incoming Packet
|
v
[Blocklist Check] --> if blocked, drop silently
|
v
[SYN Flood Detector] --> if rate exceeded, auto-block + alert
|
v
[Connection State Table] --> if established, ALLOW (skip rule check)
|
v
[Rule Engine] --> match against YAML rules --> ALLOW / DENY (default: DENY)
## Tech Stack
- Python 3.10
- Scapy (packet sniffing/crafting)
- PyYAML (rule configuration)
- Pytest (testing)

## How to Run

```bash
# Set up environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the firewall (requires sudo for packet capture)
sudo venv/bin/python src/firewall.py
```

## Demo

**Normal traffic — stateful ALLOW tracking:**
A single incoming request on port 80 is allowed by rule match; the response traffic is automatically permitted via the connection state table, without a second rule lookup.

![Allow established demo](docs/screenshots/allow-established-demo.png)

**SYN flood attack — detection and auto-block:**
A simulated SYN flood from a single spoofed IP is detected once it crosses the rate threshold (50 SYNs / 10s), after which every further packet from that IP is automatically blocked.

```bash
sudo venv/bin/python tests/simulate_synflood.py
```

![SYN flood autoblock demo](docs/screenshots/synflood-autoblock-demo.png)

## Rule Configuration Example (`config/rules.yaml`)

```yaml
rules:
  - action: allow
    proto: tcp
    dst_port: 22
  - action: deny
    proto: udp
    src: 10.0.0.0/8
  - action: allow
    proto: tcp
    dst_port: 80
```

## Testing

```bash
pytest
```

## Limitations / Future Work
- Currently logs decisions rather than dropping packets at the kernel level (would require NFQUEUE/iptables integration for true enforcement)
- Rate-limiting thresholds are static — could be made adaptive based on traffic baseline
- No persistence of blocklist across restarts

## What I Learned
Building the stateful connection table required understanding TCP's three-way handshake and how firewalls distinguish "new" vs "established" traffic — the core concept behind how real stateful firewalls (like iptables' conntrack module) work under the hood.