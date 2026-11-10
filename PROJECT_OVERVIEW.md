# ThreatScope — project overview

**Course:** Design Project III · Semester V · 2025–26 · **Author:** Malepati Sree Harsha · **Focus:** local SOC triage and detection engineering

## Goal

Build an explainable defensive lab that parses multiple event types, correlates simple detections, and inspects a synthetic packet capture while keeping active tools inside a local Compose network.

## Components

- `threatscope/detect.py` — event parsers and rule logic.
- `threatscope/gen_data.py` and `threatscope/data/` — deterministic synthetic log fixtures.
- `threatscope/nettools.py` — PCAP generation, TShark/Suricata adapters, and target-locked Nmap/ZAP calls.
- `threatscope/app.py` — Flask API, upload handling, and summary endpoints.
- `threatscope/demo_target.py` — intentionally vulnerable demo service, exposed only to the private Compose network.
- `threatscope/static/index.html` — interactive analyst dashboard.
- `tests/` — parser, rule, API, and scanner-scope tests.

## Data and scope

The checked-in events are synthetic and use documentation ranges. No public incident data is bundled. Uploaded logs are processed for the current request only; uploaded captures use temporary files. The Nmap and ZAP wrappers do not accept a target from the client.

## Run and verify

```bash
docker compose up --build -d
make test
make evaluate
```

Open `http://localhost:8103`. See the main README for limitations and tool scope.
