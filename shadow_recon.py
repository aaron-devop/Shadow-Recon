import socket
import threading
import requests
import ssl
import sys
import datetime
import os
from urllib.parse import urlparse
from queue import Queue

# --- CONFIGURATION ---
TARGET = "" 
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
THREADS = 50
TIMEOUT = 1.5

# Store results
results = {
    "open_ports": [],
    "headers": {},
    "ssl_info": None,
    "vulnerabilities": []
}

# --- MODULES ---

def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((TARGET, port))
        if result == 0:
            # Banner Grabbing
            try:
                banner = ""
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode().strip()
            except:
                banner = "Unknown Service"
            
            results["open_ports"].append({"port": port, "banner": banner[:50]})
        sock.close()
    except:
        pass

def threader():
    while True:
        worker = q.get()
        scan_port(worker)
        q.task_done()

q = Queue()

def analyze_headers(url):
    try:
        if not url.startswith("http"): url = "http://" + url
        r = requests.get(url, timeout=3, allow_redirects=True)
        headers = r.headers
        
        # Security Header Checks
        missing = []
        if 'X-Frame-Options' not in headers: missing.append("X-Frame-Options (Clickjacking Risk)")
        if 'Content-Security-Policy' not in headers: missing.append("Content-Security-Policy (XSS Risk)")
        if 'Strict-Transport-Security' not in headers and url.startswith("https"): missing.append("HSTS (Man-in-the-Middle Risk)")
        if 'X-Content-Type-Options' not in headers: missing.append("X-Content-Type-Options (MIME Sniffing)")

        results["headers"] = dict(headers)
        if missing:
            results["vulnerabilities"].extend(missing)
            
    except Exception as e:
        print(f"[!] HTTP Error: {e}")

def check_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(3)
            s.connect((host, 443))
            cert = s.getpeercert()
            
            # Parse Cert
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            not_after = cert['notAfter']
            
            results["ssl_info"] = {
                "issued_to": subject.get('commonName'),
                "issued_by": issuer.get('commonName'),
                "expires": not_after
            }
    except:
        results["ssl_info"] = "No SSL/TLS or Connection Failed"

def generate_report():
    filename = f"recon_report_{TARGET}.html"
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SHADOW-RECON REPORT: {TARGET}</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #f4f4f9; color: #333; padding: 20px; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #2c3e50; }}
            .section {{ background: #fff; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .danger {{ color: #e74c3c; font-weight: bold; }}
            .safe {{ color: #27ae60; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
        </style>
    </head>
    <body>
        <h1>🛡️ SHADOW-RECON REPORT</h1>
        <p><strong>Target:</strong> {TARGET} | <strong>Date:</strong> {datetime.datetime.now()}</p>
        
        <div class="section">
            <h2>🔓 Open Ports & Services</h2>
            <table>
                <tr><th>Port</th><th>Service Banner (Raw)</th></tr>
                {''.join(f"<tr><td>{p['port']}</td><td>{p['banner']}</td></tr>" for p in results['open_ports'])}
            </table>
        </div>

        <div class="section">
            <h2>⚠️ Security Vulnerabilities (Headers)</h2>
            <ul>
                {''.join(f"<li class='danger'>{v}</li>" for v in results['vulnerabilities']) or "<li class='safe'>No basic header vulnerabilities found.</li>"}
            </ul>
        </div>

        <div class="section">
            <h2>🔒 SSL/TLS Certificate</h2>
            <pre>{str(results['ssl_info'])}</pre>
        </div>
    </body>
    </html>
    """
    with open(filename, "w") as f:
        f.write(html)
    print(f"\n[+] Report generated: {filename}")

# --- MAIN ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 shadow_recon.py <target_ip_or_domain>")
        sys.exit(1)
        
    TARGET = sys.argv[1]
    print(f"[*] Starting Shadow-Recon on {TARGET}...")
    
    # 1. Port Scan
    print("[*] Scanning ports...")
    for x in range(THREADS):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
        
    for port in COMMON_PORTS:
        q.put(port)
        
    q.join()
    
    # 2. HTTP Analysis
    print("[*] Analyzing HTTP Headers...")
    analyze_headers(TARGET)
    
    # 3. SSL Check
    print("[*] Checking SSL Certificate...")
    check_ssl(TARGET)
    
    # 4. Report
    generate_report()
