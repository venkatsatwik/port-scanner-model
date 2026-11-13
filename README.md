# PortSentinel

**PortSentinel is the main project in this portfolio.** It is a local Python application with a browser dashboard for viewing local connection data and checking TCP ports.

> Use only on computers and networks you own or have explicit permission to assess. The HTTP server binds to `127.0.0.1` by default. Do not expose it to an untrusted network.

## Run locally

Requires Python 3; no third-party Python packages are needed.

From the repository root:

```bash
python server.py
```

Then open <http://localhost:8080>. On Windows, run `scripts/run.bat` or `scripts/run.ps1`. The original root-level `run.bat` and `run.ps1` launchers are retained for compatibility.

## Repository structure

```text
.
├── server.py              # HTTP server and API routes
├── scanner.py             # TCP checks and local connection audit logic
├── static/                # Frontend HTML, CSS, and JavaScript
├── scripts/               # Optional Windows launch helpers
├── tests/                 # Offline unit tests (no network scans)
├── run.bat                # Compatibility launcher
├── run.ps1                # Compatibility launcher
├── .gitignore
└── README.md
```

## Run tests

The tests use Python's standard library and do not send network traffic:

```bash
python -m unittest discover -s tests -v
```

## Notes and limitations

- This is an educational project, not a certified security product.
- Connection collection and process attribution vary by operating system and permissions.
- If system connection data is unavailable, the application may show simulated demo data; treat it as sample data, not a real audit.
- Risk labels are heuristic and may produce false positives or false negatives.
- Port checks create TCP connections to the selected host. Only assess targets you are authorized to assess.
- The dashboard is intended for local use and does not provide authentication for remote access.

## Branch workflow

- `main` is the stable branch.
- `develop` is for integration and organization work.
- Create feature branches from `develop`, then merge completed and checked work back into `develop`; promote to `main` when it is ready.
