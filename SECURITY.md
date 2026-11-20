# Security

ThreatScope is an educational project for Design Project III, Semester V of B.Tech Cyber Security. It is made to run on your own computer with local data. It is not made for use on a public network.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x (main) | Yes |
| Earlier versions | No |

## Report a security issue

Do not post a security issue in a public issue. Use GitHub’s private report form: open the **Security** tab and choose **Report a vulnerability**. Include the version or commit, steps to repeat the problem, and what happened.

Expected response: a reply within 7 days. For a confirmed issue, a fix or plan is expected within 30 days. Credit can be added to the changelog if you ask.

You may test your own local copy. Do not test a system or account unless you own it or have permission.

## What this app handles

ThreatScope reads log files and packet captures. These may hold private data. It also saves scan results for the demo container. The browser and Flask app run on the same computer. It has no user accounts. The API can use one shared access token.

| Risk | What the app does |
|---|---|
| Scans sent outside the lab | Nmap and ZAP always use the fixed target `demo-target`. A request cannot change it. The Docker lab network has no route out (`internal: true`). |
| Someone uses the API without permission | If set, `THREATSCOPE_API_TOKEN` is needed for every `/api/` call. The token check takes the same time for each value. Failed checks are logged without the token. |
| Dashboard open to the local network | The only open port listens on `127.0.0.1`. The demo target and ZAP open no ports. |
| Uploaded data kept after a scan | Logs are read in memory. Packet captures use a temporary file that is deleted after the scan. The app does not save this data. |
| Bad or large uploads | Limits are 12 MB per request, 10 MB per file, and 8 files at a time. The app skips bad log lines and allows 20 uploads per minute. |
| Too many scan or test runs | Limits are 4 Nmap runs, 2 ZAP runs, and 6 benchmark runs per minute. Scan tools also have time limits. |
| Container has too much access | It runs as user 10001, blocks new permissions, has memory limits, and uses temporary storage for `/tmp`. |
| Script attacks in log text | The page escapes text from logs and uses a same-origin Content Security Policy. |

## How the code is kept safer

- Each API route checks input type, size, and range. Errors use JSON.
- Each reply has security headers. API replies are marked `Cache-Control: no-store`.
- Logs include a request ID, but never the request data.
- Users see a general error for a server fault. The full error stays in the server log.
- Program calls use fixed argument lists, no shell, and time limits.
- The Docker app runs as a non-root user. CI runs the tests on every push.

## Limits

This project has not had an outside security review. Its one shared API token is optional. There are no user accounts or roles. By default, the app runs for one user on one computer. See the README for other limits.
