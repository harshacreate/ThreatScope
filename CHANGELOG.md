Change log

This page lists the main changes to ThreatScope.

Version 1.1.0: 2026-11-10

Added and changed

Added an optional access token for every API route. Set it with THREATSCOPE_API_TOKEN. If a request has no valid token, it gets HTTP 401 and the console asks for the token.

Changed the Docker Compose networks. The dashboard now uses a web network and opens at 127.0.0.1:8103. Scan targets stay inside the private lab network.

Added a test with known results in threatscope/benchmark.py, at GET /api/benchmark, from make benchmark, and in the Detection Quality card. It shows correct alerts, wrong alerts, and missed attacks for each rule. It checks 25 sets of events with different alert limits.

Added web_security.py for browser security headers, request IDs, access and audit logs, JSON error replies, and limits for scans and uploads.

Fixed the phone layout so screens 320 to 390 pixels wide do not scroll sideways. Fixed the upload area, added moving number counts, and made tap areas 44 pixels high.

Added security and benchmark tests.

Added the report, slides, short report, diagrams, demo steps, interview questions, and project page.

Added Sigma rules for SSH, firewall port scans, some Sysmon process events, and scan then login attacks in the right order.

Added evidence trails that link firewall scans, SSH login attacks, and web traffic leaving the system by source IP. They check time order, missing IP values, and repeated events.

Version 1.0.0: 2026-11-10

Added

First full release. It includes a Flask API, a dashboard, links to outside tools, a Docker image and Compose file, tests, and GitHub Actions checks.
