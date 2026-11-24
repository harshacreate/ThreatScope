ThreatScope real-data test

Result

This test uses one OTRF Security-Datasets (Mordor) sample: Local PowerShell Execution on Windows. The saved file has 2,067 JSON lines, including five Sysmon Process Create events. The source describes one PowerShell attack using technique T1059.001. It does not label each event as safe or harmful, and it has no safe test case.

Rule: brute_force_login; Hits: N/A; Misses: N/A; False alerts: N/A; What the data can show: No labeled login tests

Rule: impossible_travel; Hits: N/A; Misses: N/A; False alerts: N/A; What the data can show: No labeled unusual-login tests

Rule: port_scan; Hits: N/A; Misses: N/A; False alerts: N/A; What the data can show: This is not a port-scan test

Rule: data_exfil; Hits: N/A; Misses: N/A; False alerts: N/A; What the data can show: No ground truth for data volume or theft

Rule: suspicious_process; Hits: 0; Misses: 1; False alerts: N/A; What the data can show: One known PowerShell attack case

A small adapter changed the five Sysmon process events into the format ThreatScope uses. The suspicious_process rule gave no alerts and missed the known attack. The rule looks for the exact text “powershell -enc”. In this sample, the program path is in quotes and other flags appear between “powershell” and “-enc”. The data has no safe events, so we cannot count false alerts. It also cannot test the other four rules.

These counts are for one attack case. They cannot be compared with the test that uses made-up events. This check does not show how well the app works in general.

Source and license

Dataset: OTRF Security-Datasets (Mordor), Windows execution sample.

Dataset ID: SDWIN-190518182022.

Version: source repository commit d9d40ef123d2c87d5d3df28c96bcab4f0faccc87.

File: [empire_launcher_vbs.zip at that commit](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip). SHA-256: 812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c.

The LICENSE file at that commit says MIT. The README also refers to GPL-3.0 for an older project. This difference is noted here. The test downloads the file for local use and does not share it again.

Scenario details: [Local PowerShell Execution, Threat Hunter Playbook](https://threathunterplaybook.com/hunts/windows/190410-LocalPwshExecution/notebook.html).

Known result: one attack case using T1059.001. This saved data has no labels for single events and no safe cases.

Field mapping

EventID 1: Keep Process Create events

UtcTime, then EventTime: ProcessEvent time

Hostname: host

User, then AccountName: user

Image basename: process

ParentImage basename: parent

CommandLine: command

Only suspicious_process can be checked with this sample. We treat all the events as one attack case. We do not label any event as safe. Since the source has no safe and harmful labels for single events, it cannot show false-alert counts for any rule.

Run the test again

From the project folder, run:

    python -m pip install -r requirements.txt
    python -m threatscope.real_data --download --data-dir threatscope/data/real-data

The download step uses the saved source commit and checks the file's SHA-256 before it reads the data. It reads the JSON lines from the ZIP file without unpacking raw logs into the project. Git ignores the data/real-data/ folder.
