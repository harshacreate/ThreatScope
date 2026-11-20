# ThreatScope

ThreatScope reads sample computer logs and network traffic to find possible attacks. It shows alerts, the evidence behind them, and links to MITRE ATT&CK.

Design Project III, Semester V (2025–26), B.Tech Cyber Security, Hindustan Institute of Technology and Science. Project by Malepati Sree Harsha.

![ThreatScope dashboard](docs/screenshots/01-soc-overview.png)

## Safety and test data

The logs and network traffic in this project are made for testing. Nmap and OWASP ZAP can reach only the sample target inside a private Docker network. They cannot scan outside it.

## Results

The rules were checked on sample data in 25 test runs.

| Check | Result |
|---|---:|
| Events checked | 918 |
| Alerts shown | 6 |
| Correct alerts across test runs | 150 |
| False alerts across test runs | 0 |
| Automated tests | 14 passed |

These results apply only to the sample cases the rules were built to find. They do not show how the rules would work on real systems.

A separate public sample had no labels for safe events, so false alerts could not be counted. One rule missed its PowerShell example. See [Real data notes](docs/REAL_DATA.md).

## What it does

- Reads login, firewall, web, and process logs.
- Checks sample network traffic with TShark and Suricata.
- Uses Nmap and OWASP ZAP only on the sample target.
- Shows alerts with evidence and next steps.
- Compares rule results with known sample events.

## Run it

With Docker:

```bash
docker compose up --build -d
open http://localhost:8103
docker compose down
```

Without Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make test
make evaluate
make run
```

Some network tools work only with Docker. See [Security notes](SECURITY.md) before using the app.

## Limits

The sample data is made up. The public sample has no labels for safe events, and the rules cover only a few cases. This is a learning project, not a security monitor for real systems.

The code is under the MIT license.
