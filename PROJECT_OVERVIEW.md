# ThreatScope project overview

ThreatScope is a local lab for reading logs and sample network traffic. It finds possible attacks and shows alerts with the evidence.

## What it does

- Reads login, firewall, web, and process logs.
- Checks sample network traffic with TShark and Suricata.
- Uses Nmap and OWASP ZAP only on the sample target in a private Docker network.
- Shows alerts with links to MITRE ATT&CK and next steps.
- Checks each rule against known sample events.

## Main files

- `threatscope/detect.py` reads events and checks the rules.
- `threatscope/gen_data.py` makes sample logs.
- `threatscope/nettools.py` runs the network tools.
- `threatscope/app.py` starts the web app.
- `threatscope/demo_target.py` starts the sample target.
- `threatscope/static/index.html` has the web page.

## Data and limits

The logs and network traffic are made for this project. The public sample has no labels for safe events, so false alerts cannot be counted.

Nmap and OWASP ZAP can reach only the sample target in the private Docker network. This is a learning project, not a security monitor for real systems.

## Run it

```bash
docker compose up --build -d
make test
make evaluate
```

Open http://localhost:8103. See the README for more details.
