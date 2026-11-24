Security

ThreatScope is a learning project for Design Project III, Semester V of B.Tech Cyber Security. It runs on your computer with local data. Do not use it on a public network.

Supported versions

1.1.x (main): Yes

Earlier versions: No

Report a security issue

Do not report a security issue in a public issue. Open GitHub's Security tab and choose Report a vulnerability. Include the version or commit, steps to repeat the problem, and what happened.

I aim to reply within 7 days. If I confirm the issue, I aim to share a fix or plan within 30 days. I can add your name to the change log if you ask.

You may test your own copy on your computer. Do not test a system or account unless you own it or have permission.

What this app reads

ThreatScope reads log files and packet captures. They may contain private data. It shows scan results from the sample container. Your browser and the Flask app run on the same computer. There are no user accounts. The API can use one shared access token.

A scan reaches outside the lab: Nmap and ZAP always use the fixed target demo-target. A request cannot change it. The Docker lab network has no path out (internal: true).

Someone uses the API without permission: If set, THREATSCOPE_API_TOKEN is needed for every /api/ call. The token check takes the same time for every value. Failed checks are logged without the token.

Someone on the local network opens the dashboard: Only 127.0.0.1 is open. The sample target and ZAP open no ports.

Uploaded data stays after a scan: Logs stay in memory. Packet captures use a temporary file that is deleted after the scan. The app does not save the data.

A file is bad or too large: Limits are 12 MB per request, 10 MB per file, and 8 files at a time. The app skips bad log lines and allows 20 uploads per minute.

Too many scans or tests run at once: Limits are 4 Nmap runs, 2 ZAP runs, and 6 benchmark runs per minute. Scan tools also have time limits.

The container has too much access: It runs as user 10001, blocks new permissions, limits memory, and uses temporary space for /tmp.

Log text tries to run a script: The page safely shows text from logs and uses a same-origin Content Security Policy.

How the app stays safer

Each API route checks the input type, size, and allowed range. Errors use JSON.

Each reply has security headers. API replies use Cache-Control: no-store so the browser does not save them.

Logs include a request ID, but not the request contents.

A server error shows a general message. The full error stays in the server log.

Program calls use fixed arguments, do not use a shell, and have time limits.

The Docker app does not run as the root user. CI runs the tests after each push.

Limits

This project has not had an outside security review. Its one shared API token is optional. There are no user accounts or roles. By default, the app runs for one person on one computer. See the README for other limits.
