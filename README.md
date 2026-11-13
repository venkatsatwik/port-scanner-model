# PortSentinel

**PortSentinel is the featured project in this portfolio.** It is a local Python application with a browser-based dashboard for viewing local connection data and checking TCP ports.

> Use only on computers and networks you own or have explicit permission to assess. The server binds to loopback (`127.0.0.1`) by default. Do not expose it to an untrusted network.

## Run locally

Requires Python 3. From the repository root, run:

```bash
python server.py
```

Open <http://localhost:8080>. On Windows, `run.bat` or `run.ps1` can launch the server and open the browser.

No third-party Python packages are currently required.

## Repository structure

```text
.
├── server.py       # Local HTTP server and API routes
├── scanner.py      # TCP checks and local connection audit logic
├── static/         # Browser dashboard (HTML, CSS, JavaScript)
├── run.bat         # Windows Command Prompt launcher
├── run.ps1         # PowerShell launcher
├── .gitignore      # Python caches and local development files
└── README.md       # This guide
```

## Notes and limitations

- This is an educational project, not a certified security product.
- Connection collection and process attribution vary by operating system and permissions.
- If system connection data is unavailable, the application may show simulated demo data; treat it as sample data, not a real audit.
- Risk labels are heuristic and can produce false positives or false negatives.
- Port checks create TCP connections to the selected host. Only scan targets you are authorized to assess.
- The dashboard is intended for local use. It does not provide authentication or production-grade protection for remote access.

## Development

The project currently has no automated test suite. Before making a larger reorganization, add tests and update launcher paths together with any module moves to avoid breaking startup.
