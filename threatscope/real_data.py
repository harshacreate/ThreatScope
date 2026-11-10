"""Scenario-level evaluation against one pinned OTRF Security-Datasets sample.

The upstream sample has no benign/malicious event labels. This adapter uses its
documented Local PowerShell Execution scenario as one positive scenario, maps
Sysmon Process Create events into ThreatScope's process-event schema, and leaves
false-alert counts unavailable because the source contains no labeled benign
scenarios. It never uploads or executes dataset content.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import sys
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from threatscope.detect import ProcessEvent, detect_suspicious_process


DATASET_ID = "SDWIN-190518182022"
DATASET_VERSION = "OTRF/Security-Datasets commit d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
DATASET_LICENSE = "MIT at the pinned repository commit; upstream README also has a GPL-3.0 reference"
DATASET_URL = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
    "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/"
    "execution/host/empire_launcher_vbs.zip"
)
DATASET_SHA256 = "812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c"
DATASET_DOC = (
    "https://threathunterplaybook.com/hunts/windows/190410-LocalPwshExecution/notebook.html"
)
EXPECTED_TECHNIQUE = "T1059.001"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        DATASET_URL, headers={"User-Agent": "ThreatScope-real-data-evaluation/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            with temporary.open("wb") as output:
                shutil.copyfileobj(response, output)
        actual = _sha256(temporary)
        if actual != DATASET_SHA256:
            raise ValueError(
                "Mordor archive checksum mismatch: expected {}, received {}.".format(
                    DATASET_SHA256, actual
                )
            )
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _records_from_zip(archive: Path) -> List[Dict]:
    with zipfile.ZipFile(str(archive)) as bundle:
        names = [name for name in bundle.namelist() if name.lower().endswith(".json")]
        if len(names) != 1:
            raise ValueError(
                "Expected one JSON-lines file in the OTRF archive; found {}.".format(
                    len(names)
                )
            )
        with bundle.open(names[0]) as raw:
            stream = io.TextIOWrapper(raw, encoding="utf-8")
            return [json.loads(line) for line in stream if line.strip()]


def _timestamp(event: Dict) -> Optional[datetime]:
    value = event.get("UtcTime") or event.get("EventTime") or event.get("@timestamp")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def adapt_sysmon_process_create(event: Dict) -> Optional[ProcessEvent]:
    """Map one Sysmon event ID 1 record into ThreatScope's existing schema."""
    if str(event.get("EventID")) != "1":
        return None
    if event.get("Channel") != "Microsoft-Windows-Sysmon/Operational":
        return None
    timestamp = _timestamp(event)
    if timestamp is None:
        return None

    def image_name(value: str) -> str:
        return value.replace("/", "\\").rsplit("\\", 1)[-1]

    image = str(event.get("Image") or "")
    parent_image = str(event.get("ParentImage") or "")
    return ProcessEvent(
        ts=timestamp,
        host=str(event.get("Hostname") or event.get("host") or "unknown"),
        user=str(event.get("User") or event.get("AccountName") or "unknown"),
        parent=image_name(parent_image),
        process=image_name(image),
        command=str(event.get("CommandLine") or ""),
    )


def evaluate_records(records: Iterable[Dict]) -> Dict:
    rows = list(records)
    process_events = [
        event for row in rows
        if (event := adapt_sysmon_process_create(row)) is not None
    ]
    alerts = detect_suspicious_process(process_events)
    target_scenario_count = 1
    hits = min(len(alerts), target_scenario_count)
    misses = target_scenario_count - hits

    per_rule = {
        "brute_force_login": {
            "hits": None, "misses": None, "false_alerts": None,
            "status": "not scorable: no labeled authentication scenarios",
        },
        "impossible_travel": {
            "hits": None, "misses": None, "false_alerts": None,
            "status": "not scorable: no labeled travel/anomalous-login scenarios",
        },
        "port_scan": {
            "hits": None, "misses": None, "false_alerts": None,
            "status": "not scorable: this is not a labeled port-scan scenario",
        },
        "data_exfil": {
            "hits": None, "misses": None, "false_alerts": None,
            "status": "not scorable: no labeled exfiltration scenarios or byte-volume ground truth",
        },
        "suspicious_process": {
            "hits": hits, "misses": misses, "false_alerts": None,
            "status": (
                "one positive Local PowerShell Execution scenario; no benign "
                "scenario labels, so false alerts are not estimable"
            ),
        },
    }
    return {
        "dataset": {
            "name": "OTRF Security-Datasets (Mordor), atomic Windows execution",
            "id": DATASET_ID,
            "version": DATASET_VERSION,
            "license": DATASET_LICENSE,
            "archive_sha256": DATASET_SHA256,
            "scenario_reference": DATASET_DOC,
            "expected_technique": EXPECTED_TECHNIQUE,
        },
        "split": (
            "One documented attack scenario; 2,067 JSON-lines events, including "
            "five Sysmon Process Create events. Event-level benign/malicious "
            "labels and a benign scenario split are not published."
        ),
        "mapping": (
            "Sysmon EventID 1: UtcTime/EventTime -> timestamp; Hostname -> host; "
            "User/AccountName -> user; Image and ParentImage basenames -> process "
            "and parent; CommandLine -> command. Only suspicious_process is "
            "applicable to this scenario."
        ),
        "source_events": len(rows),
        "mapped_process_create_events": len(process_events),
        "alerts": len(alerts),
        "alerted_rules": [alert.rule for alert in alerts],
        "per_rule": per_rule,
        "limitations": [
            "The upstream sample is an attack scenario, not a labeled benign/malicious event corpus.",
            "False-alert counts cannot be estimated without benign ground truth.",
            "The upstream repository LICENSE is MIT at the pinned commit, while its README contains a GPL-3.0 reference; the archive is downloaded for local evaluation and is not redistributed.",
            "Scenario-level hit/miss counts are not comparable to the repository's synthetic event-level benchmark.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", type=Path, default=Path("threatscope/data/real-data"),
        help="ignored directory for the verified archive (default: threatscope/data/real-data)",
    )
    parser.add_argument(
        "--download", action="store_true",
        help="download the pinned public dataset if it is not already present",
    )
    args = parser.parse_args()
    archive = args.data_dir / "empire_launcher_vbs.zip"
    try:
        if not archive.exists():
            if not args.download:
                raise FileNotFoundError("Mordor archive is missing; rerun with --download.")
            _download(archive)
        elif _sha256(archive) != DATASET_SHA256:
            raise ValueError("Mordor archive checksum does not match the pinned version.")
        print(json.dumps(evaluate_records(_records_from_zip(archive)), indent=2))
    except (FileNotFoundError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print("real-data evaluation failed: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
