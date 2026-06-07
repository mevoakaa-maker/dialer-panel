#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, os, sys, ssl, threading, subprocess, base64, math
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = 8443  # HTTPS portu

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/list":
            try: files = os.listdir(BASE)
            except: files = []
            self.send_json({"files": files})
            return

        if path == "/api/file":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [""])[0]
            fpath = safe_path(name)
            if not fpath:
                self.send_json({"error": "invalid"}, 400); return
            if not os.path.exists(fpath):
                self.send_json({"exists": False, "content": ""}); return
            with open(fpath, "r", encoding="utf-8-sig", errors="replace") as f:
                content = f.read()
            self.send_json({"exists": True, "content": content})
            return

        self.send_response(404); self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if path == "/api/file":
            try:
                data = json.loads(body.decode("utf-8"))
                name = data.get("name", "")
                content = data.get("content", "")
                fpath = safe_path(name)
                if not fpath:
                    self.send_json({"error": "invalid"}, 400); return
                with open(fpath, "w", encoding="utf-8", newline="\n") as f:
                    f.write(content)
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        if path == "/api/run":
            try:
                data = json.loads(body.decode("utf-8"))
                cmd = data.get("cmd", "")
                allowed = ["nextcall.bat", "pause.bat", "resume_after_manual.bat", "auto_hangup.bat"]
                if cmd not in allowed:
                    self.send_json({"error": "not allowed"}, 403); return
                fpath = safe_path(cmd)
                if not fpath or not os.path.exists(fpath):
                    self.send_json({"error": "not found"}, 404); return
                subprocess.Popen(["cmd", "/c", fpath], cwd=BASE, creationflags=0x08000000)
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        self.send_response(404); self.end_headers()

def safe_path(name):
    if not name or "/" in name or "\\" in name or ".." in name:
        return None
    ok_ext = {".csv", ".txt", ".json", ".bat", ".vbs", ".ahk", ".flag", ".lock", ".ps1", ".html", ".xlsx"}
    _, ext = os.path.splitext(name)
    if ext.lower() not in ok_ext and ext != "":
        return None
    return os.path.join(BASE, name)

def create_cert():
    """Self-signed sertifika olustur"""
    cert_file = os.path.join(BASE, "cert.pem")
    key_file = os.path.join(BASE, "key.pem")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    try:
        # openssl ile sertifika olustur
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file, "-out", cert_file,
            "-days", "3650", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"
        ], check=True, capture_output=True)
        return cert_file, key_file
    except:
        return None, None

if __name__ == "__main__":
    print(f"")
    print(f"  Dialer Panel basliyor...")
    print(f"  Klasor : {BASE}")

    cert, key = create_cert()
    if cert and key:
        print(f"  Adres  : https://localhost:{PORT}")
        print(f"  Kapatmak icin: Ctrl+C")
        print(f"")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server = HTTPServer(("0.0.0.0", PORT), Handler)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    else:
        # SSL olmadan HTTP
        PORT_HTTP = 8080
        print(f"  Adres  : http://localhost:{PORT_HTTP}")
        print(f"  Kapatmak icin: Ctrl+C")
        print(f"")
        server = HTTPServer(("0.0.0.0", PORT_HTTP), Handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nKapatildi.")
