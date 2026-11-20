# Contributing

Thanks for taking a look at ThreatScope.

## Set up

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env        # optional; defaults work
make test
make run                    # http://127.0.0.1:8000
```

All external security tools are supported in Docker:

```bash
docker compose up --build -d   # http://localhost:8103
```

## Make a change

1. Start a branch from `main`. Name it `feature/<short-name>` or `fix/<short-name>`.
2. Keep each commit small. Use a short message such as `Add X` or `Fix Y`.
3. Add or update tests for each change. Run `make test` and check that it passes.
4. Update `README.md` and `CHANGELOG.md` when the app or its use changes.
5. Open a pull request. Say what changed, why, and how you tested it.

## Code

- Use Python 3.9 or newer. Add type hints to public functions.
- Keep input reading, security checks, tool calls, and web code in separate files.
- Do not log request data or secrets. Do not let the browser choose a scan or lookup target outside the stated limits.

## Security issues

Do not post security issues in public. See [SECURITY.md](SECURITY.md) for how to report one.
