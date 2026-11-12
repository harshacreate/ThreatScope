# ThreatScope demo scripts

## 75-second walkthrough (draft)

**Status:** Script draft only; no video has been recorded.

**Before recording:** Start the stack in advance with `docker compose up --build -d`. The first run pulls the OWASP ZAP image (~1.5 GB), so keep that setup time outside the short walkthrough. Open `http://localhost:8103` and confirm the dashboard is ready.

| Time | Show | Say |
|---|---|---|
| 0:00–0:15 | Briefly show the local startup command, then the dashboard and its status. | “ThreatScope is a local SOC detection lab. The bundled events are synthetic, and scan tools are confined to the internal demo network.” |
| 0:15–0:35 | Open one brute-force alert; point to its evidence and response playbook. | “Eight failed logins from one source inside 120 seconds trigger this T1110 alert. The evidence shows why it fired; the playbook gives an analyst a next step.” |
| 0:35–0:58 | Run the benchmark from Detection Quality; show per-rule TP, FP, FN and the threshold sweep. | “This replays injected incidents against seeded synthetic noise over 25 runs. The current README reports 150 true positives, zero false positives, and zero false negatives across the rules.” |
| 0:58–1:15 | Show the rule-level results and the limitations note. | “Those perfect counts apply only to the simple synthetic scenarios the rules were designed for. They are a repeatable baseline, not production accuracy or an external-data evaluation.” |

## Full walkthrough (7 minutes)

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
