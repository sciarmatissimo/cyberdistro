"""CyberDistro Sentinel — passive network security monitor.

Three layers:
  1. engines   — Suricata (signatures), Zeek (structured protocol logs) and the
                 Sentinel passive sensor (ARP/DHCP/mDNS) produce raw records;
  2. core      — ``events`` normalises them, ``rules`` correlates them into
                 incidents, ``store`` keeps the incident database and
                 ``status`` decides the colour (green/yellow/red/grey);
  3. assistant — explains incidents. Hand-written cards always work; the local
                 LLM only rephrases verified facts and every answer passes a
                 verifier. The model never decides the colour.
"""

__version__ = "0.1.0"
