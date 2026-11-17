# Real-data evaluation

## Result

The evaluation uses the OTRF Security-Datasets (Mordor) atomic Windows Local PowerShell Execution sample. The archive contains 2,067 JSON-lines events, including five Sysmon Process Create events. The upstream sample documents one PowerShell execution scenario with technique T1059.001, but publishes no event-level benign/malicious labels and no benign scenario split.

| Rule | Hits | Misses | False alerts | Result unit |
|---|---:|---:|---:|---|
| brute_force_login | N/A | N/A | N/A | No labeled authentication scenarios |
| impossible_travel | N/A | N/A | N/A | No labeled anomalous-login scenarios |
| port_scan | N/A | N/A | N/A | This is not a labeled port-scan scenario |
| data_exfil | N/A | N/A | N/A | No byte-volume or exfiltration ground truth |
| suspicious_process | 0 | 1 | N/A | One positive PowerShell execution scenario |

The adapter mapped the five Sysmon Process Create records into ThreatScope's existing process-event schema. The current suspicious_process rule emitted zero alerts and missed the documented scenario. Its command-line matcher searches for the literal “powershell -enc”; the observed encoded PowerShell command uses a quoted executable path and has flags between the executable name and -enc. The sample does not identify benign events, so false-alert counts cannot be computed. The other four rules have no applicable labels in this sample.

These scenario-level counts are not comparable to ThreatScope's synthetic event-level benchmark. They are a narrow check of one documented attack scenario, not a general performance estimate.

## Source, version, and license

- Dataset: OTRF Security-Datasets (Mordor), atomic Windows execution.
- Dataset ID: SDWIN-190518182022.
- Version: upstream repository commit d9d40ef123d2c87d5d3df28c96bcab4f0faccc87.
- Archive: [empire_launcher_vbs.zip at the pinned commit](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip), SHA-256 812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c.
- License: the LICENSE file at the pinned commit is MIT, which permits research use. The upstream README also contains a GPL-3.0 reference to a legacy repository; this inconsistency is disclosed here. The raw archive is downloaded for local evaluation and is not redistributed.
- Scenario documentation: [Local PowerShell Execution, Threat Hunter Playbook](https://threathunterplaybook.com/hunts/windows/190410-LocalPwshExecution/notebook.html).
- Ground truth: one scenario-level positive, technique T1059.001. No event-level labels and no benign scenarios are available in this source snapshot.

## Field mapping and split

| OTRF Sysmon field | ThreatScope field |
|---|---|
| EventID 1 | Filter to Process Create records |
| UtcTime, then EventTime | ProcessEvent timestamp |
| Hostname | host |
| User, then AccountName | user |
| Image basename | process |
| ParentImage basename | parent |
| CommandLine | command |

Only suspicious_process is applicable to this scenario. The event set is treated as one attack scenario; no event is assigned a benign label. The source does not provide the positive/negative labels needed to estimate false alerts for any rule.

## Reproduction

From the repository root:

    python -m pip install -r requirements.txt
    python -m threatscope.real_data --download --data-dir threatscope/data/real-data

The downloader pins the upstream commit and verifies the archive SHA-256 before parsing. It reads the JSON-lines file directly from the ZIP; no raw logs are extracted into the repository. The data/real-data/ directory is ignored by Git.
