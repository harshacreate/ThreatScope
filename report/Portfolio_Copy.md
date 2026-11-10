# ThreatScope — portfolio copy

## GitHub
**Description:** Reproducible SOC detection lab: four log sources + PCAP, five MITRE ATT&CK-mapped rules with playbooks, TShark/Suricata offline, Nmap/ZAP locked to an internal demo target, and a ground-truth benchmark with threshold sweeps for every rule. CSP, audit logs, rate limits, optional token auth. Flask · Docker.

**Topics:** `cybersecurity` `siem` `soc` `detection-engineering` `mitre-attack` `suricata` `wireshark` `nmap` `owasp-zap` `docker`

## LinkedIn — Projects section
**ThreatScope — SOC Detection Lab with Ground-Truth Rule Evaluation**
Built a SIEM-lite lab that parses auth, firewall, web and process logs plus PCAPs, raises ATT&CK-mapped alerts (T1110, T1078, T1046, T1041, T1059) with evidence and response playbooks, and integrates TShark, Suricata, Nmap and OWASP ZAP, with scans locked to an internal-only Docker network. Every rule is measured against injected ground truth over 25 seeds (150 TP, 0 FP), and threshold sweeps show each rule's safe operating band. Hardened with CSP, audit logging, rate limits and optional token auth; 13 automated tests.
*Skills:* Detection Engineering · SIEM · MITRE ATT&CK · Suricata · Wireshark/TShark · Nmap · OWASP ZAP · Python · Docker

## Resume bullets
- Built **ThreatScope**, a Flask/Docker SOC lab with five sliding-window detection rules mapped to MITRE ATT&CK, alert triage UI with playbooks, and TShark/Suricata PCAP analysis.
- Engineered a **ground-truth benchmark** (25 seeds, threshold sweeps) validating every rule: 150 TP / 0 FP, and identified safe threshold bands (e.g. brute force 3–16 per 120 s).
- Isolated Nmap and OWASP ZAP to an internal-only Compose network with fixed targets; added CSP, audit logging, rate limits and constant-time token auth; fixed a networking defect that left the console unreachable.
