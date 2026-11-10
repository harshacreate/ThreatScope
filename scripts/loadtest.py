"""Small dependency-free load test for a locally running instance.

Usage:
    python scripts/loadtest.py                      # default base URL
    python scripts/loadtest.py --base http://127.0.0.1:PORT --requests 200 --workers 8

Sends the same request many times from a thread pool and reports throughput and
p50 / p95 / max latency per endpoint. Only point it at your own local instance:
rate-limited endpoints are deliberately excluded.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT_BASE = "http://127.0.0.1:8103"
ENDPOINTS = [
    ("full dashboard (918 events + tshark + Suricata)", "GET", "/api/dashboard", None),
    ("health check", "GET", "/health", None),
]


def _call(base, method, path, body):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()
        status = resp.status
    return (time.perf_counter() - start) * 1000, status


def run(base, requests, workers):
    results = []
    for name, method, path, body in ENDPOINTS:
        _call(base, method, path, body)                      # warm-up
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            samples = list(pool.map(lambda _: _call(base, method, path, body), range(requests)))
        wall = time.perf_counter() - start
        lat = sorted(s[0] for s in samples)
        results.append({
            "endpoint": f"{method} {path}", "name": name, "requests": requests,
            "workers": workers, "errors": sum(1 for _, code in samples if code >= 400),
            "throughput_rps": round(requests / wall, 1),
            "p50_ms": round(statistics.median(lat), 1),
            "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 1),
            "max_ms": round(lat[-1], 1),
        })
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--requests", type=int, default=200)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    rows = run(args.base.rstrip("/"), args.requests, args.workers)
    print(json.dumps({"base": args.base, "results": rows}, indent=2))


if __name__ == "__main__":
    main()
