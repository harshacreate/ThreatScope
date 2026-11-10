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


def test_otrf_sysmon_process_event_adapter_maps_without_network():
    from threatscope.real_data import adapt_sysmon_process_create
    record = {
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": "2020-09-04 20:09:55.760",
        "Hostname": "WORKSTATION5.example",
        "User": "EXAMPLE\\analyst",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "C:\\Windows\\System32\\wscript.exe",
        "CommandLine": '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -noP -enc payload',
    }
    event = adapt_sysmon_process_create(record)
    assert event is not None
    assert event.host == "WORKSTATION5.example"
    assert event.parent == "wscript.exe"
    assert event.process == "powershell.exe"
    assert event.command.endswith("-noP -enc payload")
    assert adapt_sysmon_process_create(dict(record, EventID=3)) is None


def test_detection_thresholds_change_expected_matches():
    events = parse_auth(lines("auth.log"))
    assert detect_brute_force(events, threshold=15)
    assert not detect_brute_force(events, threshold=30)
    assert detect_impossible_travel(events)
    assert detect_port_scan(parse_fw(lines("firewall.log")), threshold=20)
    assert not detect_port_scan(parse_fw(lines("firewall.log")), threshold=40)
    assert detect_suspicious_process(parse_process(lines("process.log")))


def test_multi_source_correlation_orders_deduplicates_and_keeps_evidence():
    from threatscope.detect import Alert, correlate_alerts
    def alert(rule, time, actor="198.51.100.50", evidence=None):
        return Alert(rule, "T1046", "Discovery", "Medium", rule, time, actor,
                     evidence or rule, [])
    scan = alert("port_scan", "2026-03-01 09:00:00", evidence="15 denied ports")
    brute = alert("brute_force_login", "2026-03-01 09:15:00", evidence="8 SSH failures")
    exfil = alert("data_exfil", "2026-03-01 09:30:00", evidence="6 MB egress")
    from datetime import datetime, timedelta
    from threatscope.detect import WebEvent
    start = datetime(2026, 3, 1, 9, 15, 1)
    web = [WebEvent(start + timedelta(seconds=i), "198.51.100.50", "GET", f"/x{i}", 200, 300_000)
           for i in range(17)]
    result = correlate_alerts([exfil, brute, scan, scan], web)
    assert len(result) == 1
    assert result[0]["stages"] == ["port_scan", "brute_force_login", "data_exfil"]
    assert [row["source_type"] for row in result[0]["evidence"]] == [
        "firewall", "authentication", "web"]
    assert len(result[0]["evidence"]) == 3


def test_raw_multi_source_fixture_emits_separate_correlation_and_rule_alerts():
    from datetime import datetime, timedelta
    from threatscope.detect import (AuthEvent, FwEvent, WebEvent, correlate_alerts,
                                    run_all)
    start = datetime(2026, 3, 1, 9, 0, 0)
    actor = "198.51.100.50"
    firewall = [FwEvent(start + timedelta(seconds=i), actor, "10.0.0.8", 20 + i, "DENY")
                for i in range(15)]
    auth = [AuthEvent(start + timedelta(seconds=20 + i * 5), "analyst", actor, False)
            for i in range(8)]
    web = [WebEvent(start + timedelta(seconds=65 + i), actor, "GET", "/export", 200, 300_000)
           for i in range(17)]
    alerts = run_all(auth, firewall, web)
    assert {a.rule for a in alerts} >= {"port_scan", "brute_force_login", "data_exfil"}
    assert len(alerts) == 3
    trails = correlate_alerts(alerts, web)
    assert len(trails) == 1 and len(trails[0]["evidence"]) == 3


def test_multi_source_correlation_boundaries_missing_keys_and_unrelated_actors():
    from threatscope.detect import Alert, correlate_alerts
    def alert(rule, time, actor):
        return Alert(rule, "T1046", "Discovery", "Medium", rule, time, actor, rule, [])
    scan = alert("port_scan", "2026-03-01 09:00:00", "198.51.100.50")
    boundary = alert("brute_force_login", "2026-03-01 09:30:00", "198.51.100.50")
    from datetime import datetime, timedelta
    from threatscope.detect import WebEvent
    web_boundary = [WebEvent(datetime(2026, 3, 1, 9, 30, 0), "198.51.100.50", "GET",
                             f"/boundary/{i}", 200, 300_000) for i in range(17)]
    assert len(correlate_alerts([scan, boundary], web_boundary, window_seconds=1800)) == 1
    outside = alert("brute_force_login", "2026-03-01 09:30:01", "198.51.100.50")
    assert correlate_alerts([scan, outside], web_boundary, window_seconds=1800) == []
    reversed_stage = alert("port_scan", "2026-03-01 09:10:00", "203.0.113.8")
    earlier_brute = alert("brute_force_login", "2026-03-01 09:00:00", "203.0.113.8")
    unrelated_web = [WebEvent(datetime(2026, 3, 1, 9, 10, 1), "203.0.113.8", "GET",
                              f"/bad/{i}", 200, 300_000) for i in range(17)]
    assert correlate_alerts([reversed_stage, earlier_brute], unrelated_web) == []
    unrelated = alert("brute_force_login", "2026-03-01 09:10:00", "203.0.113.9")
    assert correlate_alerts([scan, unrelated], web_boundary) == []
    assert correlate_alerts([scan, alert("brute_force_login", "2026-03-01 09:10:00", "")], web_boundary) == []
    duplicate_under_threshold = web_boundary[:16] + [web_boundary[0]]
    assert correlate_alerts([scan, alert("brute_force_login", "2026-03-01 09:10:00", "198.51.100.50")],
                            duplicate_under_threshold) == []


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
    assert dashboard["summary"]["correlated_alerts"] == 0
    assert dashboard["correlated_alerts"] == []
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


def test_benchmark_finds_every_injected_incident_without_noise_alerts():
    from threatscope.benchmark import GROUND_TRUTH, run
    report = run(seeds=5)
    assert report["overall"]["tp"] == 5 * len(GROUND_TRUTH)
    assert report["overall"]["fp"] == 0 and report["overall"]["fn"] == 0
    # A threshold above the injected burst size must miss it (the sweep is real).
    sweep = {row["threshold"]: row for row in report["sweeps"]["brute_force_threshold"]}
    assert sweep[20]["recall"] == 0.0
