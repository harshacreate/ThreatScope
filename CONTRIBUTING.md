Contributing to ThreatScope

Set it up

Run these commands from the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env        # optional; the defaults work
make test
make run                    # http://127.0.0.1:8000
```

You can run the extra security tools with Docker:

```bash
docker compose up --build -d   # http://localhost:8103
```

Make a change

1. Make a branch from `main`. Name it `feature/<short-name>` or `fix/<short-name>`.
2. Keep each commit small. Use a short message, such as `Add X` or `Fix Y`.
3. Add or change tests for your work. Run `make test` and check that it passes.
4. Update `README.md` and `CHANGELOG.md` if you change the app or how people use it.
5. Open a pull request. Say what you changed, why, and how you checked it.

Code rules

- Use Python 3.9 or newer. Add type notes to public functions.
- Keep input reading, security checks, tool calls, and web code in separate files.
- Do not save request data or secrets in logs. Keep scan and lookup targets within the set limits.

Security issues

Do not post security issues in public. Follow [SECURITY.md](SECURITY.md) to report one.
