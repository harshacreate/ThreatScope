# Security policy

ThreatScope is an educational security tool (Design Project III, Semester V, B.Tech with specialisation in Cyber Security). It is
designed to run on your own machine, on loopback, with bundled or user-supplied local data.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x (main) | Yes |
| < 1.1 | No |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
vulnerability reporting instead: open the repository's **Security** tab and choose
**Report a vulnerability**. Include the version or commit, steps to reproduce, and the
impact you observed.

What to expect:

- Acknowledgement within 7 days.
- A fix or mitigation plan within 30 days for confirmed issues.
- Credit in the changelog if you would like it.

Good-faith research on your own local install is welcome. Do not test against systems or
accounts you do not own or are not authorized to assess.

## Threat model

**Assets:** uploaded logs and packet captures (may contain sensitive data), scan results of the demo container.

**Trust boundary:** the browser and the Flask process on the same machine. The app is not
designed to be exposed to a network and has no user accounts; binding it to a public
interface is out of scope.

| Threat | Mitigation in this codebase |
|---|---|
| Scanner pointed at systems you do not own | Nmap and ZAP targets are backend constants (`demo-target`); no request field can change them. The lab network is `internal: true` with no route out. |
| Unauthorized use of the API | Optional bearer token (`THREATSCOPE_API_TOKEN`) on every `/api/` route, constant-time comparison, failures audit-logged without the token value. |
| Dashboard exposed to the LAN | The only published port is bound to 127.0.0.1; demo target and ZAP publish nothing. |
| Uploaded evidence retained | Logs are parsed in memory; PCAPs go to a temporary file deleted after analysis; nothing is persisted. |
| Malformed or huge uploads | 12 MB request cap, 10 MB per file, 8 files per upload, tolerant parsers that skip bad lines, rate limit of 20 uploads/min. |
| Tool abuse / DoS | Rate limits: Nmap 4/min, ZAP 2/min, benchmark 6/min; tool subprocesses run with timeouts. |
| Container breakout impact | Non-root user (uid 10001), `no-new-privileges`, memory limits, tmpfs for /tmp. |
| XSS from log content | All log-derived strings are HTML-escaped; strict same-origin CSP. |

## Secure-development practices

- Input validation on every API route (type, length and range checks) with JSON error bodies.
- Security headers on every response (see `threatscope/web_security.py`) and `Cache-Control: no-store` on API responses.
- Structured access logs with a request ID; request bodies are never logged.
- Generic 500 responses: stack traces go to the server log, not the client.
- Subprocess calls use argument lists (no shell) and timeouts.
- Container runs as a non-root user; tests run in CI on every push.

## Known limitations

This project has not had an independent security audit. Authentication is optional (a single shared API token,
no user accounts or roles) because the default deployment is single-user and loopback-only. See the README's *Limitations* section for functional limits.
