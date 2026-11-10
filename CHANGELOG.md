# Changelog

All notable changes to ThreatScope are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [1.1.0] - Unreleased (prepared; tag after review and merge)

### Added / changed
- Optional bearer-token authentication for all `/api/` routes (`THREATSCOPE_API_TOKEN`); the console prompts for the token on HTTP 401.
- Fixed Compose networking: the dashboard now joins an extra non-internal `web` network so the 127.0.0.1:8103 mapping works; scan targets stay on the internal `lab` network.
- Ground-truth benchmark (`threatscope/benchmark.py`, `GET /api/benchmark`, `make benchmark`, UI card *Detection quality*): per-rule TP/FP/FN, precision and recall over 25 seeds plus threshold sweeps.
- HTTP hardening layer (`web_security.py`): CSP and OWASP security headers, request IDs, structured access + audit logs, JSON errors, rate limits on scans and uploads.
- Mobile layout fixed (no horizontal overflow at 320–390 px), upload drop-zone rendering fixed, animated stat counters, 44 px touch targets.
- Security and benchmark tests.
- Academic report, presentation, synopsis, diagrams, demo script and viva notes under `report/`; showcase page under `docs/`.
- Added the pinned Mordor real-data adapter and honest scenario-level miss results in `docs/REAL_DATA.md`.
- Added a validated Sigma subset for SSH, firewall port scans, selected Sysmon process events, and ordered scan-to-brute-force correlation.
- Added deterministic source-IP evidence trails for firewall scan → SSH brute force → web egress, with dashboard rendering and ordering, duplicate, missing-key, and time-boundary handling.

## [1.0.0] - 2026-11-10

### Added
- First complete release: Flask API, interactive dashboard, external tool integrations,
  Docker image and Compose file, unit tests and GitHub Actions CI.
