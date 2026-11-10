# ThreatScope — viva and interview questions

**1. Your benchmark shows perfect precision and recall. Isn't that suspicious?** Yes, and the report says so. The generator injects known scenarios into simple benign noise, and the rules were written for them. The benchmark proves the rules behave as designed and, more usefully, the threshold sweeps show *where* they break (2 failures → false positives; 20 → misses the attack). It is not a real-world accuracy estimate (Sommer & Paxson, 2010).

**2. How does the sliding window work?** A deque of timestamps per source IP. On each failure, append and pop from the left while the oldest is older than the window. If the length reaches the threshold, alert once for that IP. Amortised O(1) per event.

**3. How can an attacker evade your brute-force rule?** Stay below the threshold per window (low-and-slow), rotate source IPs, or spray one password across many accounts. Countermeasures: per-account and per-password-spray rules, longer windows, and correlation across sources.

**4. How do you guarantee Nmap can't scan the internet?** Two layers: the target is a constant in code (no request field reaches the scanner), and the Compose lab network is `internal: true`, so there's no route out even if the code were changed.

**5. What was the Compose bug?** The dashboard was only on the internal network. Docker doesn't publish ports for containers on internal-only networks, so 127.0.0.1:8103 silently didn't work. The fix adds a second, non-internal network for the dashboard only.

**6. What is the difference between a tactic and a technique in ATT&CK?** A tactic is the adversary's goal (Credential Access); a technique is how they achieve it (T1110 Brute Force). Mapping alerts to techniques supports coverage analysis; it doesn't prove a detection works.

**7. Why is passive ZAP scanning acceptable but active scanning not used?** Passive scanning only inspects responses the spider receives; active scanning sends attack payloads. Even on our own container, the lab keeps to the least intrusive mode needed for the lesson.

**8. Why constant-time comparison for the token?** A normal string comparison can return early at the first differing character, which in principle leaks timing information about the token. `hmac.compare_digest` takes the same time regardless.

**9. What are the risks of parsing uploaded PCAPs?** Packet dissectors have had memory-safety bugs. Mitigations: non-root container, no-new-privileges, memory limits, size limits, temporary files deleted after use, rate limits. A sandboxed worker would be stronger.

**10. How would you make this production-grade?** Real log shipping (syslog/Beats), Sigma rules, cross-source correlation, per-user accounts and roles, case management, persistent storage with retention policy, and evaluation on licensed labelled data.
