"""Flask API and local-only SOC dashboard for the synthetic ThreatScope lab."""

from __future__ import annotations

import os
import tempfile
from collections import Counter
from dataclasses import asdict

from flask import Flask, jsonify, request, send_from_directory

from threatscope import nettools
from threatscope.detect import (parse_auth, parse_fw, parse_process, parse_web,
                                run_all)

ROOT = os.path.dirname(__file__)
DATA = os.path.join(ROOT, "data")
STATIC = os.path.join(ROOT, "static")
RULES = os.path.join(ROOT, "rules", "local-demo.rules")
SAMPLE_PCAP = os.path.join(DATA, "sample-traffic.pcap")

app = Flask(__name__, static_folder=STATIC, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024


def _read_lines(name: str):
    with open(os.path.join(DATA, name), encoding="utf-8") as handle:
        return handle.read().splitlines()


def _load_demo():
    return {
        "auth": parse_auth(_read_lines("auth.log")),
        "firewall": parse_fw(_read_lines("firewall.log")),
        "web": parse_web(_read_lines("web.log")),
        "process": parse_process(_read_lines("process.log")),
    }


def _threshold(value, default, low, high):
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, result))


def _summarize(events, bf_threshold=8, scan_threshold=15):
    alerts = run_all(events["auth"], events["firewall"], events["web"],
                     bf_threshold=bf_threshold, scan_threshold=scan_threshold,
                     proc=events.get("process", []))
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    alerts.sort(key=lambda a: (order.get(a.severity, 4), a.time, a.rule))
    sources = Counter(a.source for a in alerts)
    techniques = sorted({a.technique for a in alerts})
    # Fixed-size chart buckets make the replay display stable between sessions.
    buckets = Counter(a.time[11:13] + ":00" for a in alerts)
    timeline = [{"label": f"{hour:02d}:00", "count": buckets.get(f"{hour:02d}:00", 0)}
                for hour in range(9, 12)]
    return {
        "alerts": [asdict(a) for a in alerts],
        "summary": {
            "events": sum(len(v) for v in events.values()),
            "alerts": len(alerts),
            "critical": sum(a.severity == "Critical" for a in alerts),
            "high": sum(a.severity == "High" for a in alerts),
            "medium": sum(a.severity == "Medium" for a in alerts),
            "hosts": len({a.source for a in alerts}),
        },
        "input_counts": {"auth": len(events["auth"]), "firewall": len(events["firewall"]),
                         "web": len(events["web"]), "process": len(events.get("process", []))},
        "top_sources": [{"source": key, "count": count} for key, count in sources.most_common(5)],
        "timeline": timeline,
        "techniques": techniques,
        "tool_status": {"tshark": nettools.available("tshark"),
                        "suricata": nettools.available("suricata"),
                        "nmap": nettools.available("nmap"),
                        "zap": os.getenv("THREATSCOPE_ZAP_ENABLED", "0") == "1"},
        "thresholds": {"brute_force": bf_threshold, "port_scan": scan_threshold},
        "dataset_label": "SYNTHETIC FIXTURE",
    }


@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/health")
def health():
    return "ok"


@app.route("/api/dashboard")
def dashboard():
    events = _load_demo()
    bf = _threshold(request.args.get("brute_force"), 8, 3, 30)
    scan = _threshold(request.args.get("port_scan"), 15, 5, 100)
    result = _summarize(events, bf, scan)
    if not os.path.isfile(SAMPLE_PCAP):
        nettools.generate_pcap(SAMPLE_PCAP)
    result["pcap"] = nettools.tshark_summary(SAMPLE_PCAP)
    result["suricata"] = nettools.suricata_alerts(SAMPLE_PCAP, RULES)
    return jsonify(result)


@app.route("/api/upload", methods=["POST"])
def upload():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "choose at least one supported log or PCAP file"}), 400
    events = {"auth": [], "firewall": [], "web": [], "process": []}
    packet_result = None
    warnings = []
    for uploaded in files[:8]:
        name = os.path.basename(uploaded.filename or "").lower()
        raw = uploaded.read()
        if len(raw) > 10 * 1024 * 1024:
            return jsonify({"error": "each uploaded file is limited to 10 MB"}), 413
        if name.endswith((".pcap", ".pcapng")):
            suffix = ".pcapng" if name.endswith(".pcapng") else ".pcap"
            with tempfile.NamedTemporaryFile(prefix="threatscope-upload-", suffix=suffix) as handle:
                handle.write(raw)
                handle.flush()
                packet_result = {
                    "tshark": nettools.tshark_summary(handle.name),
                    "suricata": nettools.suricata_alerts(handle.name, RULES),
                }
            continue
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        name_key = next((key for key in events if key in name), None)
        candidates = [name_key] if name_key else list(events)
        parsed = False
        parsers = {"auth": parse_auth, "firewall": parse_fw,
                   "web": parse_web, "process": parse_process}
        for key in candidates:
            found = parsers[key](lines)
            if found:
                events[key].extend(found)
                parsed = True
        if not parsed:
            warnings.append(f"{uploaded.filename or 'file'}: no supported event lines parsed")
    if not any(events.values()) and packet_result is None:
        return jsonify({"error": "no supported events were found in the uploaded files",
                        "warnings": warnings}), 400
    bf = _threshold(request.form.get("brute_force"), 8, 3, 30)
    scan = _threshold(request.form.get("port_scan"), 15, 5, 100)
    result = _summarize(events, bf, scan)
    result["dataset_label"] = "USER-UPLOADED LOCAL FILES"
    result["warnings"] = warnings
    result["pcap"] = packet_result
    return jsonify(result)


@app.route("/api/nmap-demo", methods=["POST"])
def nmap_demo():
    # No request data is forwarded to the scanner. The wrapper locks its target.
    return jsonify(nettools.nmap_scan())


@app.route("/api/zap-demo", methods=["POST"])
def zap_demo():
    # The ZAP wrapper owns its fixed demo URL; browser input cannot change scope.
    return jsonify(nettools.zap_baseline_scan())


def main():
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")))


if __name__ == "__main__":
    main()
