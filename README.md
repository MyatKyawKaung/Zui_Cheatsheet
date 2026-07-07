# Zui PCAP Investigation Cheatsheet

A SOC/DFIR cheatsheet for investigating PCAP files in Zui using Zeek, Suricata, and Zed queries.

## Purpose

This repository provides a practical analyst reference for offline PCAP investigation in Zui. It includes query examples and investigation pivots for:

- Dataset overview
- Suricata alert triage
- Connection analysis
- DNS investigation
- HTTP investigation
- TLS/SSL investigation
- File transfer analysis
- FTP exfiltration review
- SMB / DCE-RPC / lateral movement pivots
- Beaconing and C2 hunting
- IOC searching
- Evidence collection and cautious reporting language

## Important Safety Note

This cheatsheet is intended for passive/offline packet analysis only.

When handling malicious PCAP files, do not browse, curl, ping, resolve live, authenticate to, or otherwise contact suspicious or malicious domains, IPs, URLs, FTP servers, or C2 infrastructure observed in PCAP evidence. Use the packet capture, local logs, offline artifacts, and trusted threat-intelligence portals without directly interacting with attacker infrastructure.

## Cheatsheet

See:

[ZUI_PCAP_Investigation_Cheatsheet.md](./ZUI_PCAP_Investigation_Cheatsheet.md)

## Intended Audience

- SOC analysts
- CyberSecurity students practicing PCAP investigation

## Disclaimer

This material is provided for defensive security analysis and education. It should be used only with packet captures and systems that you are authorized to analyze.
