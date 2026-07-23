# Python Stateful Firewall

A stateful packet-filtering firewall built in Python using Scapy. It goes beyond simple static allow/deny rules by tracking real TCP connection state, and includes automatic detection and blocking of SYN flood attacks.

## Features
- Rule-based packet filtering (YAML config) — allow/deny by protocol, port, source IP
- **Stateful connection tracking** — automatically allows return traffic for connections that were legitimately initiated, without re-matching every rule
- **SYN flood detection & auto-blocking** — tracks SYN packet rate per source IP; if an IP exceeds a threshold within a time window, it's automatically blocked
- Full test suite (pytest) for the rule engine
- Attack simulation script to demonstrate detection live

## Architecture