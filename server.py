"""
PortSentinel - Local Web Server & Security Dashboard
Zero-dependency Python HTTP Server & REST API.
"""

import http.server
import socketserver
import json
import os
import sys
import socket
import platform
import urllib.parse
from typing import Dict, Any

from scanner import SecurityScanner, inspect_active_connections

# Global scanner instance
scanner = SecurityScanner()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

class SentinelRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handles REST API and serves static web assets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        """Handle CORS pre-flight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # REST API Routes
        if path == "/api/status":
            status = scanner.get_status()
            self._send_json(200, status)
            return

        elif path == "/api/connections":
            # Real-time audit of local sockets, processes, and secret connections
            audit = inspect_active_connections()
            self._send_json(200, audit)
            return

        elif path == "/api/system-info":
            try:
                hostname = socket.gethostname()
                host_ip = socket.gethostbyname(hostname)
            except Exception:
                hostname = "localhost"
                host_ip = "127.0.0.1"

            info = {
                "hostname": hostname,
                "local_ip": host_ip,
                "os": f"{platform.system()} {platform.release()}",
                "python_version": sys.version.split()[0],
                "platform": platform.platform()
            }
            self._send_json(200, info)
            return

        # Serve frontend files
        if path == "/" or path == "":
            self.path = "/index.html"

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read JSON body
        content_length = int(self.headers.get("Content-Length", 0))
        body = {}
        if content_length > 0:
            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                body = json.loads(raw_body)
            except Exception as e:
                self._send_json(400, {"success": False, "error": f"Invalid JSON: {str(e)}"})
                return

        if path == "/api/scan/start":
            # Security consent validation
            if not body.get("consent"):
                self._send_json(403, {
                    "success": False,
                    "error": "Security audit permission was not confirmed. User consent is required."
                })
                return

            target = body.get("target", "127.0.0.1").strip()
            if not target:
                target = "127.0.0.1"

            mode = body.get("mode", "quick")
            start_port = int(body.get("start_port", 1))
            end_port = int(body.get("end_port", 1024))
            concurrency = int(body.get("concurrency", 80))

            success, msg = scanner.start_scan_async(
                target=target,
                mode=mode,
                custom_start=start_port,
                custom_end=end_port,
                concurrency=concurrency
            )

            status_code = 200 if success else 400
            self._send_json(status_code, {"success": success, "message": msg})
            return

        elif path == "/api/scan/stop":
            scanner.stop_scan()
            self._send_json(200, {"success": True, "message": "Scan cancel signal received."})
            return

        self._send_json(404, {"error": "API endpoint not found"})


def run_server(port: int = 8080):
    handler = SentinelRequestHandler
    # Allow port reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"============================================================")
        print(f"  [+] PortSentinel Security Server is running!")
        print(f"  [+] Open your browser to: http://localhost:{port}")
        print(f"  [+] Press Ctrl+C in this terminal to stop the server.")
        print(f"============================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down PortSentinel server gracefully...")
            httpd.server_close()

if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port)
