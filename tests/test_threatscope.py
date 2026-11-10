from io import BytesIO

from threatscope import app as webapp
from threatscope import nettools
from threatscope.detect import (detect_brute_force, detect_impossible_travel,
                                detect_port_scan, detect_suspicious_process,
                                parse_auth, parse_fw, parse_process, parse_web,
                                run_all)


def lines(name):
    from pathlib import Path
    return (Path(__file__).parents[1] / "threatscope" / "data" / name).read_text().splitlines()


def test_bundled_log_fixtures_parse_and_detect():
    auth = parse_auth(lines("auth.log"))
    firewall = parse_fw(lines("firewall.log"))
    web = parse_web(lines("web.log"))
    process = parse_process(lines("process.log"))
    assert len(auth) > 150 and len(firewall) > 250 and len(web) > 200 and len(process) > 50
    rules = {alert.rule for alert in run_all(auth, firewall, web, proc=process)}
    assert {"brute_force_login", "impossible_travel", "port_scan", "data_exfil",
            "suspicious_process"} <= rules


def test_parsers_skip_malformed_rows():
    assert parse_auth(["not a log line", "2026-03-01T10:00:00 Failed password for user from 198.51.100.3"])
    assert parse_fw(["bad", "2026-03-01T10:00:00 src=10.0.0.1 dst=10.0.0.2 dport=22 action=DENY"])
    assert parse_web(['2026-03-01T10:00:00 10.0.0.2 "GET /x" 200 123'])
    assert parse_process(['2026-03-01T10:00:00 host=lab user=test parent=bash process=python command="python -m pytest"'])


def test_detection_thresholds_change_expected_matches():
    events = parse_auth(lines("auth.log"))
    assert detect_brute_force(events, threshold=15)
    assert not detect_brute_force(events, threshold=30)
    assert detect_impossible_travel(events)
    assert detect_port_scan(parse_fw(lines("firewall.log")), threshold=20)
    assert not detect_port_scan(parse_fw(lines("firewall.log")), threshold=40)
    assert detect_suspicious_process(parse_process(lines("process.log")))


def test_nmap_rejects_arbitrary_targets(monkeypatch):
    monkeypatch.setattr(nettools, "available", lambda _: True)
    monkeypatch.setattr(nettools.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not scan")))
    result = nettools.nmap_scan("example.com")
    assert result["available"] is False
    assert "fixed" in result["error"]


def test_dashboard_and_local_only_scan_api(monkeypatch):
    client = webapp.app.test_client()
    assert client.get("/health").data == b"ok"
    page = client.get("/")
    assert page.status_code == 200 and b"ThreatScope" in page.data
    dashboard = client.get("/api/dashboard?brute_force=8&port_scan=15").get_json()
    assert dashboard["dataset_label"] == "SYNTHETIC FIXTURE"
    assert dashboard["summary"]["alerts"] >= 4
    assert "T1059" in dashboard["techniques"]
    monkeypatch.setattr(webapp.nettools, "nmap_scan", lambda: {"available": False, "note": "test stub"})
    assert client.post("/api/nmap-demo", json={"target": "example.com"}).status_code == 200


def test_upload_logs_is_in_memory_and_bad_files_are_rejected():
    client = webapp.app.test_client()
    response = client.post("/api/upload", data={
        "files": [(BytesIO(b"2026-03-01T10:00:00 Failed password for alice from 203.0.113.9\n"), "auth.log")],
        "brute_force": "3", "port_scan": "15",
    }, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["dataset_label"] == "USER-UPLOADED LOCAL FILES"
    bad = client.post("/api/upload", data={}, content_type="multipart/form-data")
    assert bad.status_code == 400
