"""Score the detection rules against known injected incidents.

Usage: ``python -m threatscope.benchmark`` (prints JSON).

``gen_data`` embeds a fixed set of attack scenarios inside random benign noise.
Because the injected incidents are known, every alert can be labelled a true or
false positive. Repeating this over many seeds varies the noise, and a threshold
sweep shows how the brute-force and port-scan thresholds trade missed incidents
against noise. These are SYNTHETIC results: they show the rules behave as
designed, not how they would perform on production telemetry.
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from typing import Dict, List, Tuple

from threatscope import gen_data
from threatscope.detect import (parse_auth, parse_fw, parse_process, parse_web,
                                run_all)

# (rule, source) pairs that gen_data injects on purpose.
GROUND_TRUTH = {
    ("brute_force_login", "203.0.113.9"),
    ("impossible_travel", "bob"),
    ("port_scan", "198.51.100.7"),
    ("data_exfil", "10.0.0.23"),
    ("suspicious_process", "workstation-01"),
    ("suspicious_process", "web-01"),
}
RULES = sorted({rule for rule, _ in GROUND_TRUTH})


def _events(seed: int):
    rng = random.Random(seed)
    return (parse_auth(gen_data.gen_auth(rng)), parse_fw(gen_data.gen_fw(rng)),
            parse_web(gen_data.gen_web(rng)), parse_process(gen_data.gen_process(rng)))


def _score(alerts) -> Dict[str, Dict[str, int]]:
    found = {(a.rule, a.source) for a in alerts}
    per_rule = {}
    for rule in RULES:
        truth = {s for r, s in GROUND_TRUTH if r == rule}
        got = {s for r, s in found if r == rule}
        per_rule[rule] = {"tp": len(truth & got), "fp": len(got - truth), "fn": len(truth - got)}
    return per_rule


def _rates(tp: int, fp: int, fn: int) -> Tuple[float, float]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return round(precision, 3), round(recall, 3)


def run(seeds: int = 25) -> Dict:
    totals = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for seed in range(1, seeds + 1):
        auth, fw, web, proc = _events(seed)
        for rule, c in _score(run_all(auth, fw, web, proc=proc)).items():
            for k in c:
                totals[rule][k] += c[k]
    per_rule = []
    for rule in RULES:
        t = totals[rule]
        p, r = _rates(t["tp"], t["fp"], t["fn"])
        per_rule.append({"rule": rule, **t, "precision": p, "recall": r})
    tp = sum(x["tp"] for x in per_rule); fp = sum(x["fp"] for x in per_rule)
    fn = sum(x["fn"] for x in per_rule)
    p, r = _rates(tp, fp, fn)

    def sweep(rule: str, key: str, values: List[int]):
        rows = []
        for v in values:
            agg = {"tp": 0, "fp": 0, "fn": 0}
            for seed in range(1, seeds + 1):
                auth, fw, web, proc = _events(seed)
                c = _score(run_all(auth, fw, web, proc=proc, **{key: v}))[rule]
                for k in agg:
                    agg[k] += c[k]
            pp, rr = _rates(**agg)
            rows.append({"threshold": v, **agg, "precision": pp, "recall": rr})
        return rows

    return {
        "dataset": "SYNTHETIC: gen_data noise with injected incidents",
        "seeds": seeds,
        "per_rule": per_rule,
        "overall": {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r},
        "sweeps": {
            "brute_force_threshold": sweep("brute_force_login", "bf_threshold", [2, 3, 4, 6, 8, 12, 16, 20]),
            "port_scan_threshold": sweep("port_scan", "scan_threshold", [3, 5, 10, 15, 20, 28, 35]),
        },
    }


def main():
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
