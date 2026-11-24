ThreatScope

Short description

Reads sample logs and network traffic to find signs of attacks. Shows alerts, evidence, and related MITRE ATT&CK methods.

Project summary

I made ThreatScope as a local security lab. It reads sample login, firewall, web, and process logs. It also checks sample network traffic and shows possible attacks.

In 25 test runs, the rules found 150 sample attacks and raised no false alerts. These results apply only to the sample data used here. A separate public sample did not have labels for safe events, so its false alert rate could not be counted.

Resume notes

Made a local page for checking sample logs and network traffic.

Added alerts with evidence and next steps.

Kept Nmap and OWASP ZAP inside a private Docker network with a fixed sample target.

See the main README and Real data notes for the test details and limits.
