# Sigma representations and supported differences

ThreatScope keeps its Python rules as the executable dashboard rules. This
directory adds a portable Sigma subset for SSH failure bursts, firewall port
scans, their ordered correlation, and selected Windows process events.

## Validate

Python 3.9 or newer is needed for the pinned [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) and pySigma releases:

```bash
python -m pip install -r requirements-sigma.txt
sigma version
sigma check --fail-on-error --fail-on-issues rules/sigma/
```

The check validates rule syntax and metadata through Sigma CLI / pySigma. It does
not prove that a SIEM backend supports a particular correlation type. Sigma's
format defines event-count, value-count, temporal, and ordered-temporal
correlations; backend support can differ. See the [Sigma correlation guide](https://sigmahq.io/docs/meta/correlations.html)
and [Sigma rule format](https://sigmahq.io/docs/basics/rules.html).

## Input field mapping

The Sigma rules assume the following normalized event fields. ThreatScope's
bundled fixture uses short text lines, so this table is an explicit adapter
contract for a log shipper or SIEM parser.

| Rule data | Normalized fields | ThreatScope fixture mapping |
|---|---|---|
| Linux SSH auth | `Message`, `SourceIp`, `TargetUserName` | Match `Failed password`; parser captures source IP and user from each auth line |
| Firewall | `Action`, `SourceIp`, `DestinationIp`, `DestinationPort` | `action`, `src`, `dst`, `dport` key/value fields |
| Windows process | Sysmon `Image`, `ParentImage`, `CommandLine`, `Computer`, `User` | Not represented by the generic `process.log`; use the documented Sysmon mapping |

## Synthetic fixture comparison

Run `python -m threatscope.evaluate` for the Python rule counts. The Sigma
aggregation contracts below were checked against the same checked-in fixture
events and thresholds:

| Sigma detection | Fixture evidence | Sigma expected result | Python rule result | Difference |
|---|---|---:|---:|---|
| `threatscope_linux_ssh_brute_force` | 16 failed SSH events from `203.0.113.9` over 75 seconds | 1 source-IP group at ≥8 events / 2m | 1 `brute_force_login` alert | Matching count for this fixture |
| `threatscope_firewall_port_scan` | 28 denied destination ports from `198.51.100.7` over 28 seconds | 1 source-IP group at ≥15 distinct ports / 1m | 1 `port_scan` alert | Matching count for this fixture |
| `threatscope_scan_then_bruteforce` | The fixture uses different actor IPs for scanning and brute force | 0 correlated sequences | 0 correlated alerts | Matching negative fixture |
| `threatscope_windows_suspicious_process` | The checked-in process fixture is a custom text format, not Sysmon | Not evaluated | Python alerts remain separately measured | Schema is intentionally unsupported here |

The agreement above is a fixture-level comparison, not broad semantic parity.
Sigma time buckets can be fixed-window depending on the backend, while
ThreatScope uses rolling windows. Some backends do not implement
`temporal_ordered` or `value_count`. The Python port-scan rule counts distinct
ports across firewall actions; the Sigma subset deliberately counts denied
connections. These differences can change results outside this fixture.

ThreatScope's Python multi-source engine keeps every per-rule alert intact and
adds an evidence trail for ordered `port_scan → brute_force_login → data_exfil`
matches sharing a non-empty source IP within 30 minutes. At least 5 MB of
deduplicated web events must follow the brute-force alert, and the full chain
must fit within 30 minutes. Its endpoint returns these separately as
`correlated_alerts`; the dashboard displays source, rule, timestamps, byte
counts, and sampled request evidence. This application-specific correlation is
not claimed to be equivalent to the Sigma scan → brute-force correlation.

Sigma rule files use original authoring metadata and ATT&CK tags. They are not
copied from SigmaHQ.
