# ThreatScope — demonstration script (7 minutes)

**Setup:** `docker compose up --build -d` (ZAP needs a minute), open http://localhost:8103, check the status pill.

| Time | Do | Say |
|---|---|---|
| 0:00 | Overview | "A local SOC lab. 918 synthetic events from four sources, 6 alerts across five ATT&CK techniques." |
| 0:45 | Click the Critical exfil alert | "Evidence first, playbook second — the playbook follows the NIST incident-handling lifecycle." |
| 1:30 | Brute-force slider to 20 → Run | "The 16-failure attack disappears. Thresholds decide what you see." |
| 2:15 | Packet inspection | "Real TShark and Suricata on a PCAP: 62 packets, 3 IDS alerts." |
| 3:00 | Run Nmap, then ZAP | "Targets are constants and the lab network has no route out — this cannot scan anything I don't own. ZAP found 16 header issues on the demo target — exactly the headers my dashboard sets." |
| 4:30 | Detection quality → Run benchmark | "25 seeds of fresh noise: 150 true positives, 0 false positives. The sweep shows the safe band: 3–16 for brute force." |
| 5:45 | Mention auth + hardening | "Optional bearer token, audit logs, rate limits, CSP." |
| 6:30 | Close | "Detection rules deserve tests and measurements, like any other code. Questions?" |
