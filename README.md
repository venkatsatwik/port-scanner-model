# 🛡️ PortSentinel — PC Security & Port Auditor

**PortSentinel** is an open-source, zero-dependency cybersecurity tool and local network auditor built with **Python**, **Sockets**, and a modern **Web Dashboard**.

It is designed to give you complete visibility into:
1. **Open Ports & Sockets:** Which local ports are currently open, listening, or closed on your PC.
2. **"Secret" / Hidden Connections:** Background outbound network connections initiated by apps on your computer, mapped directly to their **Windows Executable Name and PID** (e.g. `chrome.exe`, `discord.exe`, or unknown `.exe` processes).
3. **Security Risk Rating & Analysis:** Evaluates open ports against known security vulnerabilities (e.g. unencrypted Telnet, exposed SMB/EternalBlue, unsecured database listeners) and generates a **0–100 Security Health Score**.
4. **Explicit User Authorization:** Ensures scans only execute when you explicitly grant permission on the dashboard.

---

## 📸 Key Features

- **⚡ Fast Multi-Threaded Port Scanner:** Configurable worker threads (40–120) for lightning-fast socket sweeps across top common ports or the full `1–65535` port spectrum.
- **🕵️ Process-Attributed Connection Inspector:** Uses OS socket tables and process mapping to correlate remote IP connections with the exact application responsible.
- **🔒 Zero External Dependencies:** Built 100% on Python's built-in standard library (`http.server`, `socket`, `threading`, `json`, `subprocess`). No `pip install` required!
- **🌐 Sleek Cyber-Defense UI:** Dark glassmorphism theme, real-time progress bar, responsive tables with risk color-coding, and search filters.
- **💾 One-Click JSON Audit Export:** Export complete system connection states and scan findings for auditing or comparison.

---

## 🚀 Quick Start (Running PortSentinel)

### Option 1: Double-Click Launcher (Windows)
Simply double-click:
```text
run.bat
```
This script will automatically detect Python, start the web server on `http://localhost:8080`, and open your default browser.

### Option 2: Running via Terminal
In PowerShell or Command Prompt:
```powershell
cd C:\Users\satwi\.gemini\antigravity\scratch\port-sentinel

# Start server
python server.py
```
Then open your browser to **[http://localhost:8080](http://localhost:8080)**.

---

## 📂 Project Structure

```text
port-sentinel/
├── static/
│   ├── index.html       # Web Dashboard markup & permission modal
│   ├── style.css        # Cybersecurity dark theme & responsive layout
│   └── app.js           # Real-time polling, UI state, & API calls
├── scanner.py           # Core scanning engine, banner grabber, & security rules
├── server.py            # Zero-dependency Python HTTP server & REST API
├── run.bat              # Windows batch launcher (auto browser popup)
├── run.ps1              # PowerShell launcher
├── .gitignore           # Git ignore file for Python & OS files
├── README.md            # Project documentation & security guide
└── GITHUB_GUIDE.md      # Beginner's step-by-step tutorial to publish on GitHub
```

---

## 🔍 How It Works Under The Hood

### 1. TCP 3-Way Handshake Port Scan
When checking whether a port is "On" (Open) or "Off" (Closed):
```text
PortSentinel                  Target Host
    │                             │
    │────── SYN (Probe) ─────────>│
    │<───── SYN-ACK (Open!) ──────│  --> Marked as OPEN
    │────── RST (Tear-down) ─────>│
    │                             │
    │────── SYN (Probe) ─────────>│
    │<───── RST (Closed) ─────────│  --> Marked as CLOSED
```
Python's `socket.connect_ex((ip, port))` returns `0` if the connection succeeds, indicating an open listener.

### 2. Identifying "Secret" Connections
When malware or background utilities connect out to external command-and-control servers or telemetry trackers, they establish outbound TCP connections. 
PortSentinel runs a system query against the Windows network table (`netstat -ano`) and resolves the Process ID (`PID`) through the Windows task list.

### 3. Security Risk Engine
Each open port is classified into:
- 🟢 **SAFE:** Standard encrypted services (e.g. Port 443 HTTPS, Port 22 SSH).
- 🟡 **MEDIUM:** Unencrypted web servers (Port 80 HTTP) or development ports (Port 8080, 5000).
- 🔴 **HIGH / CRITICAL:** Known dangerous protocols if exposed without authentication:
  - Port 23 (Telnet - cleartext passwords)
  - Port 445 (SMB - file sharing exploits like WannaCry/EternalBlue)
  - Port 3389 (RDP - Remote Desktop brute-force target)
  - Ports 3306, 5432, 6379, 27017 (Databases listening on public interfaces)

---

## 🤝 Contributing & Learning

Check out [`GITHUB_GUIDE.md`](./GITHUB_GUIDE.md) for a comprehensive step-by-step tutorial on:
1. Setting up Git on your PC.
2. Initializing this repository.
3. Making commits and pushing your code to GitHub.

---

## ⚖️ Legal & Ethical Notice
This tool is intended for educational purposes and authorized personal computer auditing only. Scanning networks or computers without explicit permission from the owner is illegal in many jurisdictions. Always obtain proper authorization.
