"""Detection engine: parse logs into events, run rules, emit ATT&CK-mapped alerts.

Rules are intentionally small and readable. Each returns Alerts with a severity,
the MITRE ATT&CK technique, the supporting evidence, and a response playbook.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional


@dataclass
class Alert:
    rule: str
    technique: str
    tactic: str
    severity: str
    title: str
    time: str
    source: str
    evidence: str
    playbook: List[str]


ATTACK = {
    "T1110": ("Credential Access", "Brute Force"),
    "T1078": ("Defense Evasion", "Valid Accounts (anomalous login)"),
    "T1046": ("Discovery", "Network Service Scanning"),
    "T1041": ("Exfiltration", "Exfiltration Over C2 / large egress"),
    "T1071": ("Command and Control", "Application Layer Protocol"),
    "T1059": ("Execution", "Command and Scripting Interpreter"),
}

PLAYBOOKS = {
    "T1110": ["Lock/rate-limit the targeted account and source IP.",
              "Confirm no successful login followed the burst.",
              "Force password reset + MFA; add the IP to a watchlist."],
    "T1078": ["Revoke active sessions for the account.",
              "Review all actions from the anomalous IP.",
              "Enforce conditional access (geo / device)."],
    "T1046": ["Confirm the scanning source and whether it is authorized.",
              "Check exposed services on the targeted host.",
              "Tighten firewall / segment the host; alert on repeat scans."],
    "T1041": ["Identify the destination and data classification.",
              "Contain the host; block the egress destination.",
              "Open an incident if regulated data left the network."],
    "T1071": ["Inspect the flagged flow and signature.",
              "Block the destination; hunt for related beacons."],
    "T1059": ["Confirm whether the command was expected for this host and account.",
              "Collect the parent process, command line, and nearby events.",
              "Contain the host if execution was unauthorized; preserve evidence."],
}


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

@dataclass
class AuthEvent:
    ts: datetime; user: str; src_ip: str; ok: bool

@dataclass
class FwEvent:
    ts: datetime; src_ip: str; dst_ip: str; dst_port: int; action: str

@dataclass
class WebEvent:
    ts: datetime; src_ip: str; method: str; path: str; status: int; bytes: int

@dataclass
class ProcessEvent:
    ts: datetime; host: str; user: str; parent: str; process: str; command: str


def parse_auth(lines: List[str]) -> List[AuthEvent]:
    out = []
    for ln in lines:
        m = re.search(r"^(\S+)\s+(Accepted|Failed) password for (\S+) from (\d+\.\d+\.\d+\.\d+)", ln)
        if m:
            out.append(AuthEvent(datetime.fromisoformat(m.group(1)), m.group(3),
                                 m.group(4), m.group(2) == "Accepted"))
    return out


def parse_fw(lines: List[str]) -> List[FwEvent]:
    out = []
    for ln in lines:
        m = re.search(r"^(\S+)\s+src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+dport=(\d+)\s+action=(\w+)", ln)
        if m:
            out.append(FwEvent(datetime.fromisoformat(m.group(1)), m.group(2),
                               m.group(3), int(m.group(4)), m.group(5)))
    return out


def parse_web(lines: List[str]) -> List[WebEvent]:
    out = []
    for ln in lines:
        m = re.search(r'^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+"(\w+)\s+(\S+)"\s+(\d+)\s+(\d+)', ln)
        if m:
            out.append(WebEvent(datetime.fromisoformat(m.group(1)), m.group(2), m.group(3),
                                m.group(4), int(m.group(5)), int(m.group(6))))
    return out


def parse_process(lines: List[str]) -> List[ProcessEvent]:
    out = []
    for line in lines:
        m = re.search(r'^(\S+) host=(\S+) user=(\S+) parent=(\S+) process=(\S+) command="(.*)"$', line)
        if m:
            try:
                out.append(ProcessEvent(datetime.fromisoformat(m.group(1)), *m.groups()[1:]))
            except ValueError:
                continue
    return out


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

def _mk(rule, tech, sev, title, ts, src, ev):
    tactic, name = ATTACK[tech]
    return Alert(rule, tech, tactic, sev, title, ts.strftime("%Y-%m-%d %H:%M:%S"),
                 src, ev, PLAYBOOKS[tech])


def detect_brute_force(events: List[AuthEvent], threshold=8, window=120) -> List[Alert]:
    fails: Dict[str, deque] = defaultdict(deque)
    fired, alerts = set(), []
    for e in events:
        if e.ok:
            continue
        q = fails[e.src_ip]; q.append(e.ts)
        while q and (e.ts - q[0]) > timedelta(seconds=window):
            q.popleft()
        if len(q) >= threshold and e.src_ip not in fired:
            fired.add(e.src_ip)
            alerts.append(_mk("brute_force_login", "T1110", "High", "Password brute force",
                              e.ts, e.src_ip, f"{len(q)} failed logins from {e.src_ip} within {window}s"))
    return alerts


def _is_external(ip: str) -> bool:
    """Treat addresses outside configured private/link-local ranges as external.

    The bundled fixtures use RFC 5737 documentation addresses for safe examples;
    those are still outside the lab's private address ranges.
    """
    try:
        import ipaddress
        address = ipaddress.ip_address(ip)
        private_ranges = [ipaddress.ip_network(x) for x in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
            "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]
        return not any(address.version == net.version and address in net for net in private_ranges)
    except Exception:
        return False


def detect_impossible_travel(events: List[AuthEvent], window=600) -> List[Alert]:
    """Flag a successful login from a *public* IP shortly after one from a
    *private* IP (or vice-versa) for the same user — the classic account-takeover
    signal. Internal-to-internal logins are normal and do not fire."""
    last: Dict[str, tuple] = {}
    fired: set = set()
    alerts = []
    for e in events:
        if not e.ok:
            continue
        prev = last.get(e.user); last[e.user] = (e.ts, e.src_ip)
        if (prev and prev[1] != e.src_ip and e.user not in fired
                and _is_external(prev[1]) != _is_external(e.src_ip)
                and (e.ts - prev[0]) <= timedelta(seconds=window)):
            fired.add(e.user)
            ext = e.src_ip if _is_external(e.src_ip) else prev[1]
            alerts.append(_mk("impossible_travel", "T1078", "High", "Impossible travel login",
                              e.ts, e.user,
                              f"user {e.user} logged in from {prev[1]} then {e.src_ip} within window (external IP {ext})"))
    return alerts


def detect_port_scan(events: List[FwEvent], threshold=15, window=60) -> List[Alert]:
    ports: Dict[str, deque] = defaultdict(deque)
    seen: Dict[str, set] = defaultdict(set)
    fired, alerts = set(), []
    for e in events:
        q = ports[e.src_ip]; q.append((e.ts, e.dst_port)); seen[e.src_ip].add(e.dst_port)
        while q and (e.ts - q[0][0]) > timedelta(seconds=window):
            old = q.popleft()
        distinct = len({p for _, p in q})
        if distinct >= threshold and e.src_ip not in fired:
            fired.add(e.src_ip)
            alerts.append(_mk("port_scan", "T1046", "Medium", "Port scan",
                              e.ts, e.src_ip, f"{distinct} distinct ports probed from {e.src_ip} within {window}s"))
    return alerts


def detect_exfil(events: List[WebEvent], byte_threshold=5_000_000) -> List[Alert]:
    totals: Dict[str, int] = defaultdict(int)
    peak_ts: Dict[str, datetime] = {}
    alerts = []
    for e in events:
        totals[e.src_ip] += e.bytes
        peak_ts[e.src_ip] = e.ts
    for ip, total in totals.items():
        if total >= byte_threshold:
            alerts.append(_mk("data_exfil", "T1041", "Critical", "Large data egress",
                              peak_ts[ip], ip, f"{total/1e6:.1f} MB transferred to/from {ip}"))
    return alerts


_SUSPICIOUS_COMMANDS = (
    "powershell -enc", "powershell -encodedcommand", "curl ", "wget ",
    "nc -e", "bash -i", "python -c", "chmod +x /tmp", "base64 -d",
)


def detect_suspicious_process(events: List[ProcessEvent]) -> List[Alert]:
    alerts = []
    for event in events:
        command = event.command.lower()
        parent = event.parent.lower()
        indicator = next((x for x in _SUSPICIOUS_COMMANDS if x in command), None)
        web_shell = parent in {"nginx", "apache2", "httpd", "www-data"} and event.process.lower() in {"sh", "bash", "python", "perl"}
        if indicator or web_shell:
            reason = f"command matched {indicator}" if indicator else "script shell launched by a web-server parent"
            alerts.append(_mk("suspicious_process", "T1059", "High", "Suspicious process execution",
                              event.ts, event.host,
                              f"host={event.host} user={event.user} parent={event.parent} process={event.process}; {reason}: {event.command[:220]}"))
    return alerts


def run_all(auth: List[AuthEvent], fw: List[FwEvent], web: List[WebEvent],
            bf_threshold=8, scan_threshold=15, proc: Optional[List[ProcessEvent]] = None) -> List[Alert]:
    alerts = []
    alerts += detect_brute_force(auth, threshold=bf_threshold)
    alerts += detect_impossible_travel(auth)
    alerts += detect_port_scan(fw, threshold=scan_threshold)
    alerts += detect_exfil(web)
    alerts += detect_suspicious_process(proc or [])
    return alerts
