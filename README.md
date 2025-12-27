# 👁️ SHADOW-RECON

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/security-reconnaissance-red?style=for-the-badge&logo=kali-linux&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**An automated Network Reconnaissance and Vulnerability Assessment tool for System Administrators and Ethical Hackers.**

Shadow-Recon is designed to perform the initial phase of a security audit (Phase 1: Information Gathering). It maps the attack surface of a target server by identifying open ports, analyzing service banners, checking for missing security headers, and auditing SSL/TLS configurations.

## ⚡ CAPABILITIES

### 1. Multi-Threaded Port Scanner
* Scans common service ports (TCP) using socket connections.
* **Banner Grabbing:** Attempts to capture the service version (e.g., `SSH-2.0-OpenSSH_8.2`).

### 2. HTTP Security Header Analysis
Checks for the presence of critical security headers to prevent common web attacks:
* `X-Frame-Options` (Prevents Clickjacking)
* `Content-Security-Policy` (Mitigates XSS)
* `Strict-Transport-Security` (Enforces HTTPS)
* `X-Content-Type-Options` (Prevents MIME Sniffing)

### 3. SSL/TLS Audit
* Retrieves certificate validity, issuer, and expiration date to prevent "Expired Certificate" downtime or Man-in-the-Middle risks.

### 4. Automated Reporting
* Generates a structured **HTML Report** (`recon_report_<target>.html`) summarizing all findings for documentation purposes.

## 🛠️ INSTALLATION & USAGE

### Requirements
* Python 3.x
* `requests` library

```bash
pip install requests
```

### Execution
Run the script providing the target Domain or IP address:

```bash
# Basic usage
python3 shadow_recon.py example.com

# OR with IP
python3 shadow_recon.py 192.168.1.100
```

### Output
The tool will display progress in the terminal and generate an HTML file in the same directory.

## ⚠️ DISCLAIMER

**FOR EDUCATIONAL AND DEFENSIVE USE ONLY.**
This tool is intended for System Administrators to audit their own networks. Scanning targets without explicit permission is illegal and punishable by law. The author assumes no responsibility for misuse.

## 📜 LICENSE
MIT License
