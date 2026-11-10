# ThreatScope

**A reproducible SOC detection lab with ground-truth rule evaluation.**

Design Project III · Semester V (2025–26) · B.Tech, specialisation in Cyber Security, DISC, Hindustan Institute of Technology and Science, Chennai · by **Malepati Sree Harsha**

![tests](https://img.shields.io/badge/tests-13%20passing-2ea44f) ![python](https://img.shields.io/badge/python-3.12-3776AB) ![docker](https://img.shields.io/badge/docker-compose-2496ED) ![license](https://img.shields.io/badge/license-MIT-blue) ![focus](https://img.shields.io/badge/focus-detection%20engineering-4f8a1e) ![attack](https://img.shields.io/badge/MITRE-ATT%26CK-red)

![ThreatScope SOC console](docs/screenshots/01-soc-overview.png)

> **Lab scope:** all bundled telemetry is synthetic (documentation IP ranges). Nmap and OWASP ZAP can reach only the bundled `demo-target` container on an internal Docker network with no route out. Use only data you are authorized to inspect.

ThreatScope parses authentication, firewall, web and process logs plus packet captures. It raises **MITRE ATT&CK-mapped alerts** with evidence and response playbooks, and runs **TShark, Suricata, Nmap and OWASP ZAP** inside an isolated lab. Its research contribution is a **ground-truth benchmark**: every rule is scored against injected incidents over 25 seeds, with threshold sweeps that show where each rule starts to fail.

## Key results (measured)

| Result | Value |
|---|---|
| Bundled evidence | 918 events → 6 alerts across 5 ATT&CK techniques |
| Ground truth over 25 seeds (default thresholds) | **150 TP · 0 FP · 0 FN** |
| Safe threshold bands | brute force **3–16** failures / 120 s · port scan **5–28** ports / 60 s |
| Real tools on the bundled PCAP / lab | TShark 62 packets · Suricata 3 alerts · Nmap 1 open port · ZAP 16 passive findings |
| Automated tests | **13 / 13 passing** |
| Full dashboard call (parse + 5 rules + TShark + Suricata) | p50 126.9 ms · p95 143.5 ms |

| Rule | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| `brute_force_login` | 25 | 0 | 0 | 1.00 | 1.00 |
| `data_exfil` | 25 | 0 | 0 | 1.00 | 1.00 |
| `impossible_travel` | 25 | 0 | 0 | 1.00 | 1.00 |
| `port_scan` | 25 | 0 | 0 | 1.00 | 1.00 |
| `suspicious_process` | 50 | 0 | 0 | 1.00 | 1.00 |

![Threshold sweep](docs/diagrams/chart-threshold-sweep.png)

Perfect scores reflect simple synthetic noise and rules written for these scenarios. The sweeps are the informative part: they show the thresholds at which benign noise starts to fire, and where an attack slips under the rule.

## Detections

| Rule | ATT&CK | Logic |
|---|---|---|
| `brute_force_login` | T1110 | ≥ 8 failures from one IP within 120 s (tunable) |
| `impossible_travel` | T1078 | Same user logs in from internal and external IPs within 600 s |
| `port_scan` | T1046 | ≥ 15 distinct ports from one IP within 60 s (tunable) |
| `data_exfil` | T1041 | ≥ 5 MB transferred by one source |
| `suspicious_process` | T1059 | Encoded PowerShell, curl/wget, reverse shells, shells spawned by web servers |

## Architecture and isolation

![Deployment](docs/diagrams/deployment.png)

Only the dashboard publishes a port, on 127.0.0.1:8103. It joins an extra `web` network because Docker does not publish ports for containers that are only on an internal network. Fixing that silent bug was part of this release. `demo-target` and ZAP live only on `lab` (`internal: true`).

## Quick start

```bash
docker compose up --build -d      # first run pulls OWASP ZAP (~1.5 GB)
open http://localhost:8103
docker compose down
```

Optional authentication: set `THREATSCOPE_API_TOKEN` (see `.env.example`). Every `/api/` call then needs `Authorization: Bearer <token>`, and the console prompts for it.

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
make test        # 13 tests
make evaluate    # fixture rule counts
make benchmark   # ground truth + threshold sweeps
make run         # http://127.0.0.1:8000 (TShark/Suricata/Nmap show as unavailable outside Docker)
```

## Security

Scan targets are constants in code and the lab network is internal-only. The platform has strict CSP and OWASP headers, an audit log for scans and authentication failures, and rate limits (Nmap 4/min, ZAP 2/min, uploads 20/min). Optional bearer-token authentication uses a constant-time comparison. Uploads are processed in memory and temporary PCAPs are deleted. Containers are non-root with `no-new-privileges` and memory limits. See [SECURITY.md](SECURITY.md).

## Documentation

| Document | |
|---|---|
| [Project report (PDF)](report/ThreatScope_Project_Report.pdf) · [Word](report/ThreatScope_Project_Report.docx) | IEEE-style report: literature survey, SRS, UML/DFD, implementation, testing, results, references |
| [Presentation (PowerPoint)](report/ThreatScope_Presentation.pptx) · [PDF](report/ThreatScope_Presentation.pdf) | Review / viva slides with speaker notes |
| [Synopsis](report/ThreatScope_Synopsis.pdf) | Two-page project synopsis |
| [Demo script](report/Demo_Script.md) | Timed live-demonstration walkthrough |
| [Viva questions](report/Viva_Questions.md) | Likely examiner / interviewer questions with answers |
| [Portfolio copy](report/Portfolio_Copy.md) | GitHub description, LinkedIn and resume text |
| [Showcase page](docs/index.html) | Landing page for GitHub Pages (Settings → Pages → `main` / `docs`) |
| [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) | Threat model, disclosure process, workflow, history |

## Limitations and roadmap

- Synthetic, simple telemetry. Next: replay a licensed labelled dataset.
- Single-source rules. Next: cross-source actor correlation (scan → brute force → exfil).
- Shared token, no roles. Next: per-analyst accounts and case management.
- Rules in Python. Next: Sigma rules tested with the same benchmark harness.

## Repository layout

```
├── .dockerignore
├── .env.example
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── Makefile
├── PROJECT_OVERVIEW.md
├── README.md
├── SECURITY.md
├── Start.command
├── docker-compose.yml
├── docs/
│   ├── README.md
│   ├── diagrams/  (11 images)
│   ├── index.html
│   └── screenshots/  (7 images)
├── requirements.txt
├── scripts/
│   └── loadtest.py
├── tests/
│   ├── test_security.py
│   └── test_threatscope.py
└── threatscope/
    ├── __init__.py
    ├── app.py
    ├── benchmark.py
    ├── data/
    │   ├── auth.log
    │   ├── firewall.log
    │   ├── process.log
    │   ├── sample-traffic.pcap
    │   └── web.log
    ├── demo_target.py
    ├── detect.py
    ├── evaluate.py
    ├── gen_data.py
    ├── nettools.py
    ├── rules/
    │   └── local-demo.rules
    ├── static/
    │   └── index.html
    └── web_security.py
```

## License and data

MIT, see [LICENSE](LICENSE). Bundled logs and the PCAP are locally generated synthetic data. Tool images remain under their upstream licenses.
