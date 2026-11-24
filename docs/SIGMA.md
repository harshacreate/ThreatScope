Sigma rules and how they differ

ThreatScope uses its Python rules in the dashboard. This folder also has Sigma rules, a shared format for security rules. These rules cover SSH login failures, firewall port scans, a scan followed by a login attack, and some Windows process events.

Check the rules

Use Python 3.9 or newer. Install the pinned Sigma CLI and pySigma versions with these commands:

```bash
python -m pip install -r requirements-sigma.txt
sigma version
sigma check --fail-on-error --fail-on-issues rules/sigma/
```

The check looks for rule format and information errors. A passing check does not mean that every SIEM tool can run every kind of rule. Sigma has rules that count events, count unique values, use time limits, or check that events happen in order. Tool support can vary. See the [Sigma correlation guide](https://sigmahq.io/docs/meta/correlations.html) and [Sigma rule format](https://sigmahq.io/docs/basics/rules.html).

Fields used by the rules

The Sigma rules expect log fields to have common names. The sample logs in ThreatScope use shorter lines. A log reader or SIEM parser must change them to the fields below.

Rule data: Linux SSH sign-in; Fields the Sigma rules expect: `Message`, `SourceIp`, `TargetUserName`; Fields in the ThreatScope sample: Finds `Failed password`; reads the source IP and user from each sign-in line

Rule data: Firewall; Fields the Sigma rules expect: `Action`, `SourceIp`, `DestinationIp`, `DestinationPort`; Fields in the ThreatScope sample: Reads `action`, `src`, `dst`, `dport` key and value pairs

Rule data: Windows process; Fields the Sigma rules expect: Sysmon `Image`, `ParentImage`, `CommandLine`, `Computer`, `User`; Fields in the ThreatScope sample: Not in the general `process.log`; use the Sysmon field map in the real data guide

Compare with the sample test

Run `python -m threatscope.evaluate` to see the Python rule counts. The table compares those counts with the Sigma rules on the same saved sample logs.

Sigma rule: `threatscope_linux_ssh_brute_force`; What is in the sample: 16 failed SSH sign-ins from `203.0.113.9` in 75 seconds; Sigma result: 1 source IP group with at least 8 events in 2 minutes; Python result: 1 `brute_force_login` alert; What this shows: Same count on this sample

Sigma rule: `threatscope_firewall_port_scan`; What is in the sample: 28 denied ports from `198.51.100.7` in 28 seconds; Sigma result: 1 source IP group with at least 15 different ports in 1 minute; Python result: 1 `port_scan` alert; What this shows: Same count on this sample

Sigma rule: `threatscope_scan_then_bruteforce`; What is in the sample: The scan and login attack use different IP addresses; Sigma result: 0 linked attack sequences; Python result: 0 linked alerts; What this shows: Both miss the link on this sample

Sigma rule: `threatscope_windows_suspicious_process`; What is in the sample: The sample uses a custom text format, not Sysmon; Sigma result: Not checked; Python result: Python alerts are counted separately; What this shows: This sample does not fit this rule

These results only compare the saved sample logs. They do not show that the rules give the same results on all logs. Some SIEM tools group time in fixed blocks, while ThreatScope checks a moving time range. Some tools do not support `temporal_ordered` or `value_count`. The Python port scan rule counts different ports across all firewall actions. The Sigma rule here counts only denied connections. These choices can lead to different results.

ThreatScope event sequence check

ThreatScope also has its own rule for linked events. It keeps each rule alert and adds a separate `correlated_alerts` result when it finds a `port_scan → brute_force_login → data_exfil` sequence from the same non-empty source IP within 30 minutes. At least 5 MB of web events, after repeat events are removed, must follow the login alert. The full sequence must fit within 30 minutes. The dashboard shows the source, rule, times, byte counts, and a sample of the web requests.

This ThreatScope rule is specific to this app. It is not the same as the Sigma scan-to-login rule.

The Sigma files have their own author details and ATT&CK tags. They were not copied from SigmaHQ.
