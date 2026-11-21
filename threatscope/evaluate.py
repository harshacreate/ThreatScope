"""Print the same score counts for the sample detection data each time."""

from __future__ import annotations

import json

from threatscope.app import _load_demo, _summarize


def main():
    result = _summarize(_load_demo())
    counts = {}
    for alert in result["alerts"]:
        counts[alert["rule"]] = counts.get(alert["rule"], 0) + 1
    print(json.dumps({"dataset": result["dataset_label"],
                      "events": result["summary"]["events"],
                      "alerts": result["summary"]["alerts"],
                      "by_rule": counts,
                      "techniques": result["techniques"]}, indent=2))


if __name__ == "__main__":
    main()
