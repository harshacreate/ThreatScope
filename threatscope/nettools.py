"""Adapters for tools used by the ThreatScope local lab.

Network scanning is intentionally locked to the compose service named
``demo-target``. Uploaded packet captures are written only to a temporary
directory and removed when analysis completes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Dict, List
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

DEMO_TARGET = "demo-target"
DEMO_TARGET_URL = "http://demo-target:5001/"


def available(name: str) -> bool:
    return shutil.which(name) is not None


def generate_pcap(path: str) -> bool:
    """Write a deterministic teaching PCAP with scan and HTTP-export patterns."""
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except Exception:
        return False
    packets = []
    for port in range(20, 50):
        packets.append(IP(src="198.51.100.7", dst="10.0.0.1") /
                       TCP(sport=44000 + port, dport=port, flags="S"))
    def add_http_flow(src, dst, sport, path, host):
        client = IP(src=src, dst=dst)
        server = IP(src=dst, dst=src)
        cport = TCP(sport=sport, dport=80, seq=1000, flags="S")
        sport_tcp = TCP(sport=80, dport=sport, seq=2000, ack=1001, flags="SA")
        packets.extend([client / cport, server / sport_tcp,
                        client / TCP(sport=sport, dport=80, seq=1001, ack=2001, flags="A")])
        payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fixture\r\n\r\n".encode()
        packets.append(client / TCP(sport=sport, dport=80, seq=1001, ack=2001, flags="PA") / Raw(load=payload))
    for i in range(5):
        add_http_flow("10.0.0.12", "10.0.0.1", 51000 + i, "/index.html", "demo.local")
    for i in range(3):
        add_http_flow("10.0.0.23", "203.0.113.50", 52000 + i,
                      f"/export/dump{i}.csv", "demo.external")
    for index, packet in enumerate(packets):
        packet.time = 1_709_280_000 + index
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    wrpcap(path, packets)
    return True


def tshark_summary(pcap: str) -> Dict:
    if not available("tshark") or not os.path.isfile(pcap):
        return {"available": False, "note": "tshark or a packet capture is unavailable"}
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap, "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.dstport", "-e", "_ws.col.Protocol"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)}
    if result.returncode:
        return {"available": True, "error": result.stderr[-500:] or "tshark could not parse the capture"}
    rows = [line.split("\t") for line in result.stdout.splitlines() if line.strip()]
    talkers: Dict[str, int] = {}
    ports: Dict[str, int] = {}
    protocols: Dict[str, int] = {}
    for row in rows:
        src, dport, proto = row[0] if len(row) > 0 else "", row[2] if len(row) > 2 else "", row[3] if len(row) > 3 else ""
        if src:
            talkers[src] = talkers.get(src, 0) + 1
        if dport:
            ports[dport] = ports.get(dport, 0) + 1
        if proto:
            protocols[proto] = protocols.get(proto, 0) + 1
    top = lambda counts: [{"name": key, "count": count} for key, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:8]]
    return {"available": True, "packets": len(rows), "top_talkers": top(talkers),
            "top_ports": top(ports), "protocols": top(protocols)}


def suricata_alerts(pcap: str, rules: str) -> Dict:
    if not available("suricata") or not os.path.isfile(pcap):
        return {"available": False, "note": "Suricata or a packet capture is unavailable"}
    with tempfile.TemporaryDirectory(prefix="threatscope-suri-") as outdir:
        try:
            result = subprocess.run(
                ["suricata", "-r", pcap, "-S", rules, "-l", outdir, "-k", "none"],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {"available": True, "error": str(exc)}
        eve_path = os.path.join(outdir, "eve.json")
        alerts: List[Dict] = []
        if os.path.exists(eve_path):
            with open(eve_path, encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if item.get("event_type") == "alert":
                        alert = item.get("alert", {})
                        alerts.append({"signature": alert.get("signature", "unknown"),
                                       "severity": alert.get("severity"), "src": item.get("src_ip"),
                                       "dest": item.get("dest_ip"), "category": alert.get("category")})
        distinct = {item["signature"]: item for item in alerts}
        return {"available": result.returncode == 0 or bool(eve_path),
                "alert_count": len(alerts), "signatures": list(distinct.values())[:20],
                "error": None if result.returncode == 0 else result.stderr[-500:]}


def nmap_scan(target: str = DEMO_TARGET) -> Dict:
    """Scan only the private bundled demo service; reject every other target."""
    if target != DEMO_TARGET:
        return {"available": False, "error": "Nmap target is fixed to the bundled demo container."}
    if not available("nmap"):
        return {"available": False, "note": "Nmap is installed in the Docker image."}
    try:
        result = subprocess.run(["nmap", "-sT", "-Pn", "-n", "-p", "5001", "--reason", DEMO_TARGET],
                                capture_output=True, text=True, timeout=45, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)}
    if result.returncode not in (0, 1):
        return {"available": True, "error": result.stderr[-500:] or "Nmap scan failed"}
    ports = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)", line)
        if match:
            ports.append({"port": int(match.group(1)), "protocol": match.group(2),
                          "state": match.group(3), "service": match.group(4)})
    return {"available": True, "target": DEMO_TARGET, "ports": ports,
            "open_count": sum(row["state"] == "open" for row in ports), "scope": "Bundled local demo container only"}


def _zap_api(component: str, endpoint: str, method: str = "view", **params):
    query = urlencode(params)
    url = f"http://zap:8080/JSON/{component}/{method}/{endpoint}/{('?' + query) if query else ''}"
    with urlopen(url, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def zap_baseline_scan() -> Dict:
    """Run a ZAP spider + passive scan against the internal bundled demo only."""
    if os.getenv("THREATSCOPE_ZAP_ENABLED", "1") != "1":
        return {"available": False, "note": "The ZAP service is disabled."}
    try:
        started = _zap_api("spider", "scan", "action", url=DEMO_TARGET_URL, maxChildren=20, recurse="true")
        scan_id = started.get("scan")
        if scan_id is None:
            return {"available": True, "error": "ZAP did not return a spider job id."}
        for _ in range(45):
            status = int(_zap_api("spider", "status", scanId=scan_id).get("status", 0))
            if status >= 100:
                break
            time.sleep(1)
        else:
            return {"available": True, "error": "ZAP spider exceeded its 45-second demo budget."}
        for _ in range(20):
            pending = int(_zap_api("pscan", "recordsToScan").get("recordsToScan", 0))
            if pending == 0:
                break
            time.sleep(1)
        payload = _zap_api("core", "alerts", baseurl=DEMO_TARGET_URL, start=0, count=100)
        alerts = []
        for item in payload.get("alerts", []):
            alerts.append({"name": item.get("name"), "risk": item.get("risk"),
                           "confidence": item.get("confidence"), "url": item.get("url"),
                           "parameter": item.get("param"), "evidence": item.get("evidence"),
                           "solution": item.get("solution")})
        return {"available": True, "target": DEMO_TARGET_URL, "scan_type": "spider + passive baseline",
                "spider_percent": status, "alert_count": len(alerts), "alerts": alerts,
                "scope": "Bundled local demo container only; no active scan was run"}
    except (URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
        return {"available": False, "error": f"ZAP service unavailable: {exc.__class__.__name__}"}
