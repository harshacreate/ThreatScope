# Change log

This page lists the main ThreatScope changes. It uses the [Keep a Changelog format](https://keepachangelog.com/en/1.1.0/). Version numbers use [SemVer](https://semver.org/).

## [1.1.0] - 2026-11-10

### Added and changed

- Added an optional access token for every /api/ route. Set it with THREATSCOPE_API_TOKEN. If a request gets HTTP 401, the console asks for the token.
- Fixed the Compose networks. The dashboard now also uses a web network, so Docker can show it at 127.0.0.1:8103. Scan targets still use the private lab network.
- Added a test with known results in threatscope/benchmark.py, at GET /api/benchmark, from make benchmark and in the Detection Quality card. It shows true alerts, false alerts and missed alerts for each rule. It tests 25 sets of events and tries different limits.
- Added web_security.py for CSP and OWASP security headers, request IDs, access and audit logs, JSON errors, and limits for scans and uploads.
- Fixed the phone layout so it has no side-to-side scrolling at widths from 320 to 390 pixels. Fixed the upload area, added moving number counts, and made tap areas 44 pixels tall.
- Added security and benchmark tests.
- Added the report, slides, short report, diagrams, demo script and interview notes under report/. Added the project page under docs/.

## [1.0.0] - 2026-11-10

### Added

- First full release. It has a Flask API, a working dashboard, links to outside tools, a Docker image and Compose file, unit tests and GitHub Actions checks.
