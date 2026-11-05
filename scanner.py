"""
PortSentinel - Port Scanner & Local Security Audit Engine
Designed for educational security audits, detecting open ports, active 'secret' connections,
and evaluating system exposure risks.
"""

import socket
import threading
import time
import subprocess
import re
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

# Well-known port definitions and security risk assessments
KNOWN_PORTS: Dict[int, Dict[str, Any]] = {
    20: {"name": "FTP-Data", "risk": "LOW", "desc": "File Transfer Protocol (Data channel)"},
    21: {"name": "FTP-Control", "risk": "HIGH", "desc": "FTP transmits credentials and data in cleartext. Upgrade to SFTP or FTPS."},
    22: {"name": "SSH", "risk": "SAFE", "desc": "Secure Shell - Encrypted remote access. Ensure key authentication is enforced."},
    23: {"name": "Telnet", "risk": "CRITICAL", "desc": "Unencrypted terminal access. Highly insecure; credentials sent in cleartext."},
    25: {"name": "SMTP", "risk": "MEDIUM", "desc": "Simple Mail Transfer Protocol. Vulnerable to open relay misuse if misconfigured."},
    53: {"name": "DNS", "risk": "SAFE", "desc": "Domain Name System server."},
    80: {"name": "HTTP", "risk": "MEDIUM", "desc": "Unencrypted web traffic. Prefer HTTPS (Port 443)."},
    88: {"name": "Kerberos", "risk": "SAFE", "desc": "Authentication service often seen on Windows Active Directory."},
    110: {"name": "POP3", "risk": "HIGH", "desc": "Unencrypted email retrieval. Use POP3S (Port 995)."},
    135: {"name": "MS-RPC", "risk": "HIGH", "desc": "Microsoft RPC Endpoint Mapper. Often probed in network reconnaissance attacks."},
    137: {"name": "NetBIOS-Name", "risk": "HIGH", "desc": "NetBIOS Name Service. Can leak hostname and internal network info."},
    139: {"name": "NetBIOS-SSN", "risk": "HIGH", "desc": "NetBIOS Session Service. Legacy protocol; disable if not required."},
    143: {"name": "IMAP", "risk": "HIGH", "desc": "Unencrypted email access. Use IMAPS (Port 993)."},
    389: {"name": "LDAP", "risk": "MEDIUM", "desc": "Lightweight Directory Access Protocol. Should be secured with TLS (Port 636)."},
    443: {"name": "HTTPS", "risk": "SAFE", "desc": "Encrypted web traffic (TLS/SSL)."},
    445: {"name": "SMB", "risk": "CRITICAL", "desc": "Server Message Block (Windows File Sharing). Historically targeted by EternalBlue/WannaCry. Never expose to public networks."},
    993: {"name": "IMAPS", "risk": "SAFE", "desc": "Encrypted IMAP over TLS."},
    995: {"name": "POP3S", "risk": "SAFE", "desc": "Encrypted POP3 over TLS."},
    1433: {"name": "MS-SQL", "risk": "HIGH", "desc": "Microsoft SQL Server database. Dangerous if exposed on public interfaces."},
    1521: {"name": "Oracle-DB", "risk": "HIGH", "desc": "Oracle Database listener. Keep bound to localhost or protected VLAN."},
    2049: {"name": "NFS", "risk": "HIGH", "desc": "Network File System. Misconfigured NFS shares can expose entire filesystems."},
    3306: {"name": "MySQL", "risk": "HIGH", "desc": "MySQL Database. Should strictly listen on 127.0.0.1 unless properly secured."},
    3389: {"name": "RDP", "risk": "HIGH", "desc": "Remote Desktop Protocol. Prime target for automated brute-force and credential stuffing attacks."},
    5000: {"name": "Dev-Server", "risk": "MEDIUM", "desc": "Common development server port (Flask, Express, Docker)."},
    5432: {"name": "PostgreSQL", "risk": "HIGH", "desc": "PostgreSQL Database. Never expose directly without strict firewall rules."},
    5900: {"name": "VNC", "risk": "HIGH", "desc": "Virtual Network Computing remote desktop. Frequently lacks robust authentication."},
    6379: {"name": "Redis", "risk": "CRITICAL", "desc": "In-memory database. Frequently installed without authentication; severe RCE risk if exposed."},
    8000: {"name": "Dev-HTTP", "risk": "LOW", "desc": "Common alternative HTTP or local development server."},
    8080: {"name": "HTTP-Proxy", "risk": "MEDIUM", "desc": "Common HTTP alternate / Tomcat / proxy service."},
    8443: {"name": "HTTPS-Alt", "risk": "SAFE", "desc": "Alternative secure HTTPS service."},
    8888: {"name": "Jupyter/App", "risk": "MEDIUM", "desc": "Development notebook or microservice port."},
    9200: {"name": "Elasticsearch", "risk": "HIGH", "desc": "Elasticsearch REST API. Often targeted for data leaks when left public."},
    11211: {"name": "Memcached", "risk": "CRITICAL", "desc": "Memory cache. Often exploited for amplification DDoS attacks and unauthorized data reading."},
    27017: {"name": "MongoDB", "risk": "HIGH", "desc": "MongoDB database. Widely exploited for ransom when bound without auth on 0.0.0.0."}
}

# Top 100 most frequent ports for quick scans
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 137, 139, 143, 161, 389,
    443, 445, 465, 500, 515, 587, 636, 873, 902, 993, 995, 1025, 1080, 1194,
    1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 3000,
    3128, 3306, 3389, 4243, 5000, 5432, 5672, 5900, 5985, 5986, 6379, 6667,
    7000, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9418,
    9999, 10000, 11211, 27017
]

class SecurityScanner:
    def __init__(self):
        self.is_scanning = False
        self.cancel_requested = False
        self.progress = {
            "status": "idle",       # idle, scanning, completed, stopped, error
            "target": "",
            "mode": "",
            "total_ports": 0,
            "scanned_ports": 0,
            "percentage": 0,
            "start_time": 0,
            "elapsed_seconds": 0,
            "open_ports": [],
            "error_message": ""
        }
        self.lock = threading.Lock()

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            # Update elapsed time if scanning
            if self.is_scanning and self.progress["start_time"] > 0:
                self.progress["elapsed_seconds"] = round(time.time() - self.progress["start_time"], 1)
            return dict(self.progress)

    def stop_scan(self):
        self.cancel_requested = True

    def grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """Attempt to grab service banner or HTTP header."""
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send HTTP request if web port, else wait for greeting
            if port in [80, 8080, 8000, 3000, 5000]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            elif port in [21, 22, 23, 25, 110]:
                pass # Many plaintext services send a welcome banner immediately
            else:
                s.sendall(b"\r\n")

            data = s.recv(512)
            if data:
                text = data.decode("utf-8", errors="ignore").strip()
                # Extract first line or Server header
                lines = text.splitlines()
                for line in lines:
                    if line.lower().startswith("server:"):
                        banner = line
                        break
                if not banner and lines:
                    banner = lines[0][:80]
            s.close()
        except Exception:
            pass
        return banner

    def check_port(self, ip: str, port: int, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        """Check if a single port is open via TCP connect."""
        if self.cancel_requested:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            
            if result == 0:
                info = KNOWN_PORTS.get(port, {
                    "name": "Unknown",
                    "risk": "MEDIUM" if port < 1024 else "LOW",
                    "desc": "Non-standard or custom service"
                })
                banner = self.grab_banner(ip, port, timeout=0.8)
                return {
                    "port": port,
                    "service": info["name"],
                    "risk": info["risk"],
                    "description": info["desc"],
                    "banner": banner
                }
        except Exception:
            pass
        return None

    def start_scan_async(self, target: str, mode: str = "quick", custom_start: int = 1, custom_end: int = 1024, concurrency: int = 80):
        """Start scan in background thread."""
        with self.lock:
            if self.is_scanning:
                return False, "A scan is already in progress."
            self.is_scanning = True
            self.cancel_requested = False

        thread = threading.Thread(
            target=self._run_scan,
            args=(target, mode, custom_start, custom_end, concurrency),
            daemon=True
        )
        thread.start()
        return True, "Scan started successfully."

    def _run_scan(self, target: str, mode: str, custom_start: int, custom_end: int, concurrency: int):
        try:
            # Resolve target
            try:
                ip = socket.gethostbyname(target)
            except Exception as e:
                with self.lock:
                    self.progress["status"] = "error"
                    self.progress["error_message"] = f"Failed to resolve host '{target}': {str(e)}"
                    self.is_scanning = False
                return

            # Determine port list
            if mode == "quick":
                port_list = sorted(list(set(TOP_PORTS)))
            elif mode == "all":
                port_list = list(range(1, 65536))
            elif mode == "custom":
                start_p = max(1, min(custom_start, 65535))
                end_p = max(1, min(custom_end, 65535))
                if start_p > end_p:
                    start_p, end_p = end_p, start_p
                port_list = list(range(start_p, end_p + 1))
            else: # default pc audit
                port_list = sorted(list(KNOWN_PORTS.keys()))

            total = len(port_list)
            with self.lock:
                self.progress["status"] = "scanning"
                self.progress["target"] = f"{target} ({ip})"
                self.progress["mode"] = mode
                self.progress["total_ports"] = total
                self.progress["scanned_ports"] = 0
                self.progress["percentage"] = 0
                self.progress["start_time"] = time.time()
                self.progress["elapsed_seconds"] = 0
                self.progress["open_ports"] = []
                self.progress["error_message"] = ""

            # Concurrency limit based on mode
            workers = min(concurrency, 150)
            scanned_count = 0
            open_results = []

            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_port = {
                    executor.submit(self.check_port, ip, port, 0.6): port
                    for port in port_list
                }

                for future in as_completed(future_to_port):
                    if self.cancel_requested:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    res = future.result()
                    if res:
                        open_results.append(res)
                        with self.lock:
                            self.progress["open_ports"] = sorted(open_results, key=lambda x: x["port"])

                    scanned_count += 1
                    if scanned_count % 5 == 0 or scanned_count == total:
                        with self.lock:
                            self.progress["scanned_ports"] = scanned_count
                            self.progress["percentage"] = int((scanned_count / total) * 100)
                            self.progress["elapsed_seconds"] = round(time.time() - self.progress["start_time"], 1)

            with self.lock:
                if self.cancel_requested:
                    self.progress["status"] = "stopped"
                else:
                    self.progress["status"] = "completed"
                    self.progress["percentage"] = 100
                self.progress["elapsed_seconds"] = round(time.time() - self.progress["start_time"], 1)
                self.is_scanning = False

        except Exception as e:
            with self.lock:
                self.progress["status"] = "error"
                self.progress["error_message"] = str(e)
                self.is_scanning = False

# ====================================================================
# Active Connection & Secret Connection Detector (System Inspection)
# ====================================================================

def get_process_map() -> Dict[str, str]:
    """Map Windows PID to Process Executable Name using tasklist."""
    pid_to_name = {}
    if os.name == 'nt':
        try:
            output = subprocess.check_output(
                ['tasklist', '/FO', 'CSV', '/NH'],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2.0
            )
            for line in output.splitlines():
                parts = line.strip().split('","')
                if len(parts) >= 2:
                    proc_name = parts[0].replace('"', '')
                    proc_pid = parts[1].replace('"', '')
                    pid_to_name[proc_pid] = proc_name
        except Exception:
            pass
    return pid_to_name

def inspect_active_connections() -> Dict[str, Any]:
    """
    Parse active TCP/UDP connections on the PC.
    Detects listening ports, outbound connections, process identities,
    and flags suspicious/secret connections.
    """
    connections = []
    pid_map = get_process_map()
    
    # Run netstat -ano
    cmd = ['netstat', '-ano']
    try:
        raw_output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=2.0)
        lines = raw_output.splitlines()
    except Exception as e:
        # Fallback simulated data if sandbox blocks netstat
        return get_mock_security_audit()

    for line in lines:
        parts = line.strip().split()
        # TCP format: Proto, Local Address, Foreign Address, State, PID
        # UDP format: Proto, Local Address, Foreign Address, PID
        if len(parts) >= 4 and parts[0].upper() in ['TCP', 'UDP']:
            proto = parts[0].upper()
            local_addr = parts[1]
            foreign_addr = parts[2]
            
            if proto == 'TCP':
                state = parts[3] if len(parts) >= 5 else "UNKNOWN"
                pid = parts[4] if len(parts) >= 5 else "N/A"
            else:
                state = "LISTENING"
                pid = parts[3] if len(parts) >= 4 else "N/A"

            # Parse IP and port
            local_ip, local_port = _split_ip_port(local_addr)
            foreign_ip, foreign_port = _split_ip_port(foreign_addr)
            
            proc_name = pid_map.get(pid, f"PID {pid}")
            
            # Security assessment of the connection
            assessment = assess_connection_security(proto, local_port, foreign_ip, foreign_port, state, proc_name)

            connections.append({
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "foreign_ip": foreign_ip,
                "foreign_port": foreign_port,
                "state": state,
                "pid": pid,
                "process_name": proc_name,
                "is_outbound": foreign_ip not in ["0.0.0.0", "*:*", "127.0.0.1", "::", "[::]"],
                "suspicion_level": assessment["level"], # SAFE, MEDIUM, SUSPICIOUS
                "reason": assessment["reason"]
            })

    # If no connections were returned (e.g. sandbox restriction), provide demo audit data
    if not connections:
        return get_mock_security_audit()

    # Calculate overall security health score (0 - 100)
    score_data = calculate_health_score(connections)

    return {
        "success": True,
        "connections_count": len(connections),
        "connections": connections,
        "security_score": score_data["score"],
        "rating": score_data["rating"],
        "summary": score_data["summary"],
        "recommendations": score_data["recommendations"]
    }

def _split_ip_port(addr_str: str) -> (str, int):
    """Split IPv4 or IPv6 address and port."""
    try:
        if addr_str.startswith("["): # IPv6 like [::1]:8080
            idx = addr_str.rfind(":")
            return addr_str[1:idx-1], int(addr_str[idx+1:])
        elif ":" in addr_str:
            ip, port = addr_str.rsplit(":", 1)
            return ip, int(port) if port.isdigit() else 0
        return addr_str, 0
    except Exception:
        return addr_str, 0

def assess_connection_security(proto: str, l_port: int, f_ip: str, f_port: int, state: str, proc: str) -> Dict[str, str]:
    """Determine if a connection looks safe, normal, or potentially suspicious."""
    proc_lower = proc.lower()
    
    # Listening port check
    if state == "LISTENING":
        if l_port in KNOWN_PORTS and KNOWN_PORTS[l_port]["risk"] in ["CRITICAL", "HIGH"]:
            return {
                "level": "SUSPICIOUS",
                "reason": f"Open dangerous listener port {l_port} ({KNOWN_PORTS[l_port]['name']})."
            }
        return {"level": "SAFE", "reason": "Standard local listening port"}

    # Established outbound connection checks ("Secret Connections")
    if state == "ESTABLISHED":
        # Known common browser/system processes
        trusted_procs = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "code.exe", "svchost.exe", "steam.exe", "discord.exe", "spotify.exe"]
        
        # Check standard HTTPS / HTTP outbound
        if f_port in [443, 80, 8080, 8443]:
            return {"level": "SAFE", "reason": f"Standard web traffic ({f_port}) by {proc}"}
            
        # Uncommon external port
        if f_port > 1024 and not any(tp in proc_lower for tp in trusted_procs):
            return {
                "level": "SUSPICIOUS",
                "reason": f"Application '{proc}' is secretly connected to external port {f_port} on {f_ip}."
            }
            
        if f_port in [6667, 1337, 4444, 5555]: # Classic IRC / Metasploit / RAT ports
            return {
                "level": "CRITICAL",
                "reason": f"Connection on known malicious/reverse-shell port {f_port} by {proc}!"
            }

    return {"level": "SAFE", "reason": "Routine system activity"}

def calculate_health_score(connections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate overall PC security rating from 0 to 100."""
    score = 100
    recommendations = []
    suspicious_count = 0
    critical_count = 0
    open_listeners = 0

    for c in connections:
        if c.get("state") == "LISTENING":
            open_listeners += 1
            if c.get("suspicion_level") == "CRITICAL":
                score -= 25
                critical_count += 1
                recommendations.append(f"Close critical listening port {c['local_port']} ({c['process_name']})")
            elif c.get("suspicion_level") == "SUSPICIOUS":
                score -= 10
                suspicious_count += 1
                recommendations.append(f"Inspect listener on port {c['local_port']} ({c['process_name']})")
        elif c.get("suspicion_level") == "SUSPICIOUS":
            score -= 8
            suspicious_count += 1
            recommendations.append(f"Review external connection to {c['foreign_ip']}:{c['foreign_port']} by {c['process_name']}")

    score = max(20, min(100, score))
    
    if score >= 90:
        rating = "EXCELLENT"
        summary = "No alarming secret connections or exposed vulnerable ports detected."
    elif score >= 75:
        rating = "GOOD"
        summary = "PC has minor network activity or non-standard ports that deserve a quick review."
    elif score >= 50:
        rating = "WARNING"
        summary = "Several non-standard connections or exposed service ports require attention."
    else:
        rating = "CRITICAL"
        summary = "High risk ports or suspicious outbound communication detected!"

    if not recommendations:
        recommendations.append("All network listeners appear normal. Keep your operating system firewall active.")

    return {
        "score": score,
        "rating": rating,
        "summary": summary,
        "recommendations": list(set(recommendations))[:5]
    }

def get_mock_security_audit() -> Dict[str, Any]:
    """Safe fallback demo data for sandbox environments."""
    mock_conns = [
        {"protocol": "TCP", "local_ip": "0.0.0.0", "local_port": 135, "foreign_ip": "0.0.0.0", "foreign_port": 0, "state": "LISTENING", "pid": "880", "process_name": "svchost.exe", "is_outbound": False, "suspicion_level": "SUSPICIOUS", "reason": "MS-RPC Listener (ensure Windows Firewall blocks public access)"},
        {"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 8080, "foreign_ip": "0.0.0.0", "foreign_port": 0, "state": "LISTENING", "pid": "4210", "process_name": "python.exe", "is_outbound": False, "suspicion_level": "SAFE", "reason": "Local PortSentinel web dashboard"},
        {"protocol": "TCP", "local_ip": "192.168.1.105", "local_port": 54210, "foreign_ip": "142.250.190.46", "foreign_port": 443, "state": "ESTABLISHED", "pid": "10420", "process_name": "chrome.exe", "is_outbound": True, "suspicion_level": "SAFE", "reason": "Standard HTTPS connection to Google CDN"},
        {"protocol": "TCP", "local_ip": "192.168.1.105", "local_port": 58319, "foreign_ip": "13.107.42.16", "foreign_port": 443, "state": "ESTABLISHED", "pid": "3210", "process_name": "msedge.exe", "is_outbound": True, "suspicion_level": "SAFE", "reason": "Standard secure connection (Microsoft telemetry / update)"},
        {"protocol": "TCP", "local_ip": "192.168.1.105", "local_port": 60122, "foreign_ip": "198.51.100.22", "foreign_port": 8888, "state": "ESTABLISHED", "pid": "7844", "process_name": "background_worker.exe", "is_outbound": True, "suspicion_level": "SUSPICIOUS", "reason": "Uncommon external port 8888 by non-browser application."}
    ]
    score_data = calculate_health_score(mock_conns)
    return {
        "success": True,
        "connections_count": len(mock_conns),
        "connections": mock_conns,
        "security_score": score_data["score"],
        "rating": score_data["rating"],
        "summary": score_data["summary"],
        "recommendations": score_data["recommendations"],
        "is_simulated": True
    }
