#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker Desktop is required. Start Docker Desktop and run this file again."
  exit 1
fi
docker compose up --build -d
for i in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:8103/health >/dev/null; then break; fi
  sleep 2
done
open -a Safari http://127.0.0.1:8103
