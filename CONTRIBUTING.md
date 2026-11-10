# Contributing

Thanks for taking a look at ThreatScope.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env        # optional; defaults work
make test
make run                    # http://127.0.0.1:8000
```

The full toolchain (external security tools) is only guaranteed inside Docker:

```bash
docker compose up --build -d   # http://localhost:8103
```

## Workflow

1. Create a branch from `main` (`feature/<short-name>` or `fix/<short-name>`).
2. Keep commits small and focused; write messages in the imperative ("Add X", "Fix Y").
3. Add or update tests in `tests/` for every behaviour change. `make test` must pass.
4. Update `README.md` and `CHANGELOG.md` when behaviour or usage changes.
5. Open a pull request describing **what** changed, **why**, and how you tested it.

## Code style

- Python 3.9+ with type hints on public functions.
- Keep parsing, detection/analysis logic, tool adapters and the web layer in separate modules.
- Never log request bodies or secrets. Never add a feature that lets the browser choose a
  scan or lookup target outside the documented scope.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
