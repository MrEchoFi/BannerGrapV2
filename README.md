<div align="center">
    <img src="https://github.com/MrEchoFi/BannerGrapV2/blob/master/BannerGrapV2_Security_Scanner_Tool_1d0e04fd-c100-4173-88b9-52a99f69fc2b.jpeg?raw=true" alt="gif" width="730" height="auto" />

</div>

<div align="center">
	
  <h1>🎯 BannerGrapV2</h1>

### Advanced Network Reconnaissance & Vulnerability Discovery Tool

[![GitHub Stars](https://img.shields.io/github/stars/MrEchoFi/BannerGrapV2?style=for-the-badge&logo=github)](https://github.com/MrEchoFi/BannerGrapV2/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/MrEchoFi/BannerGrapV2?style=for-the-badge&logo=github)](https://github.com/MrEchoFi/BannerGrapV2/network/members)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)](https://github.com/MrEchoFi/BannerGrapV2)

**A blazing-fast, comprehensive reconnaissance tool built in Go for modern security professionals.**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [✨ Features](#-features) • [🤝 Contributing](#-contributing) • [💬 Community](#-community)


## Video For Better Understanding:


https://github.com/user-attachments/assets/d4bfc9ff-5fc2-4932-bc7e-e6d827cabf0b
<!-- Add a demo GIF showing your tool in action -->

</div>

---

## 🌟 Why BannerGrapV2?

BannerGrapV2 is a next-generation reconnaissance tool designed for **both Red Teams and Blue Teams**, combining speed, accuracy, and comprehensive reporting into a single powerful package.

**By this DevSecOps Based' tool you can-> Recon, vuln discovery, brute force, attack surface mapping, reporting, exploit probing,Asset inventory, vuln management, credential hygiene, exposure monitoring, IR, compliance.**

### 🎯 Perfect For:
- 🔴 **Red Team Operations** - Attack surface mapping and exploitation
- 🔵 **Blue Team Defense** - Asset inventory and vulnerability management
- 🐛 **Bug Bounty Hunters** - Quick reconnaissance and discovery
- 🛡️ **Security Auditors** - Compliance and security assessments
- 🔧 **DevSecOps Engineers** - CI/CD security integration

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Reconnaissance
- **Multi-threaded** banner grabbing
- **Service fingerprinting** across 1000+ protocols
- **SSL/TLS certificate** analysis
- **HTTP header** enumeration
- **DNS information** gathering
- **Integration with Nmap**

</td>
<td width="50%">

### 🛡️ Security Analysis
- **Vulnerability detection** engine
- **Weak credential** detection
- **Misconfiguration** identification
- **Exploit suggestion** framework

</td>
</tr>
<tr>
<td width="50%">

### ⚡ Performance
- **Concurrent scanning** (up to 10,000 hosts)
- **Adaptive rate limiting**
- **Smart timeout handling**
- **Memory-efficient** design
- **Resume failed scans**

</td>
<td width="50%">

### 📊 Reporting
- **JSON, XML, HTML, CSV** output formats
- **Beautiful terminal** output with colors
- **Executive summaries**
- **Integration-ready** APIs

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites
- Go 1.23 or higher (see `go.mod`)
- Linux, macOS, or Windows
- Root/Administrator privileges (for some scan types)

### Installation

#### Option 1: Download Pre-built Binary (Recommended)

Prebuilt, stripped binaries are available for every major platform/architecture:

| Platform | Architecture | Binary |
|---|---|---|
| Linux | x86_64 | `bannergrapv2-linux-amd64` |
| Linux | arm64 | `bannergrapv2-linux-arm64` |
| macOS | Intel (x86_64) | `bannergrapv2-darwin-amd64` |
| macOS | Apple Silicon (arm64) | `bannergrapv2-darwin-arm64` |
| Windows | x86_64 | `bannergrapv2-windows-amd64.exe` |

```bash
# Linux (x86_64)
curl -L https://github.com/MrEchoFi/BannerGrapV2/releases/latest/download/bannergrapv2-linux-amd64 -o bannergrapv2

# Linux (arm64)
curl -L https://github.com/MrEchoFi/BannerGrapV2/releases/latest/download/bannergrapv2-linux-arm64 -o bannergrapv2

# macOS (Intel)
curl -L https://github.com/MrEchoFi/BannerGrapV2/releases/latest/download/bannergrapv2-darwin-amd64 -o bannergrapv2

# macOS (Apple Silicon)
curl -L https://github.com/MrEchoFi/BannerGrapV2/releases/latest/download/bannergrapv2-darwin-arm64 -o bannergrapv2

chmod +x bannergrapv2
sudo mv bannergrapv2 /usr/local/bin/

bannergrapv2 -version
bannergrapv2 -h
```

```powershell
# Windows (PowerShell, x86_64)
Invoke-WebRequest -Uri "https://github.com/MrEchoFi/BannerGrapV2/releases/latest/download/bannergrapv2-windows-amd64.exe" -OutFile "bannergrapv2.exe"

.\bannergrapv2.exe -version
```

**Verify the download (recommended):** every release ships a `CHECKSUMS.txt` with SHA-256 sums for all five binaries.

```bash
curl -L https://github.com/MrEchoFi/BannerGrapV2/releases/latest/download/CHECKSUMS.txt -o CHECKSUMS.txt
sha256sum --ignore-missing -c CHECKSUMS.txt
```

#### Option 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/MrEchoFi/BannerGrapV2.git
cd BannerGrapV2

# Build for your current platform
go build -o bannergrapv2 .

# Optional: Install globally
sudo mv bannergrapv2 /usr/local/bin/
```

**Cross-compile for other platforms:**
```bash
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bannergrapv2-linux-amd64      .
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bannergrapv2-linux-arm64      .
GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bannergrapv2-darwin-amd64     .
GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bannergrapv2-darwin-arm64     .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bannergrapv2-windows-amd64.exe .
```

#### Option 3: Install via Go
```bash
go install github.com/MrEchoFi/BannerGrapV2@latest
```
#### Option 4: Install via Docker
```bash
# using "Docker" for Containerized performence with safety/lab:

git clone <github link>
cd BannerGrapV2

[+] run the tool and follow its 'bannerGrap_Guid or Usage.txt'; 
but specially read & follow this-> 'New_advanced_bashScripts.md' for full usage of guidelines. 
By this guidline u can use this tool in aggressive mode, basic mode and intermediate mode.

# Build the Docker image
docker build -t bannerv2 .

# then run:
 docker run bannerv2

### Test Tool in Container with more clean (Optional):
docker run --rm bannerv2 

[+]NOTE: follow the guidline- 'New_advanced_bashScripts.md' for better bash scripting.
```
#### Option 5: Install via Kubernetes + Docker
```bash
 ### Minikube Setup:
 
# This will spin up your local K8s cluster using your WSL2 Docker
         
minikube start --driver=docker

# Optional: enable the default storageclass and dashboard
         
minikube addons enable default-storageclass
minikube addons enable dashboard

# OR You can directly run this :
             
chmod +x start_banner.sh
# then run: 
./start_banner.sh

[+] run the tool and follow its 'bannerGrap_Guid or Usage.txt'; 
but specially read & follow this-> 'New_advanced_bashScripts.md' for full usage of guidelines.  
By this guidline u can use this tool in aggressive mode, basic mode and intermediate mode.

 # Convert using 'chmod':

chmod +x run_bannerv2.sh

# THEN Run like this:
./run_bannerv2.sh <target ip> <port> --proto http https --threads 20 --timeout 8 --o scan.csv --v

[+] //follow the guidline- 'New_advanced_bashScripts.md' for better bash scripting .. 
```

### 🔑 NVD API Key Configuration (Recommended)

BannerGrapV2 can cross-check every service/version it fingerprints against the **National Vulnerability Database (NVD) CVE API 2.0** to report real, matching CVEs — not just a static local list. This live lookup is gated behind an `NVD_API_KEY` environment variable.

- **Without a key:** the tool still works fully for banner grabbing, fingerprinting, etc. — NVD lookups are silently skipped (you'll see `NVD_API_KEY not set - skipping NVD lookup` if you run with `NVD_DEBUG=1`).
- **With a key:** you get much higher NVD rate limits (see below) and CVE results get merged into your scan output.

#### 1. Get a free NVD API key
1. Go to the NVD API key request page: **https://nvd.nist.gov/developers/request-an-api-key**
2. Enter your email address and submit the request.
3. NIST emails you an activation link — click it to activate the key.
4. Copy the key from the activation email (looks like a UUID, e.g. `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

Without a key, NVD allows only 5 requests per 30 seconds; with a key, that jumps to 50 requests per 30 seconds, which matters once you're scanning more than a handful of hosts.

#### 2. Configure the key for this project
The repo ships a template file, `.env.example`:
```bash
NVD_API_KEY="your-nvd-api-key-here"
```

Copy it to `.env` and paste in your real key:
```bash
cp .env.example .env
# then edit .env and replace "your-nvd-api-key-here" with the key NIST emailed you
```

`.env` is already listed in `.gitignore`, so your key is never committed — **never** commit a real key or put it directly in `.env.example`.

At startup the tool automatically loads `.env` from the current working directory (see `loadDotEnv` in `bannerGrap.go`), so no extra flag is needed — just run `bannergrapv2` from the directory containing your `.env` file.

Alternatively, export it directly in your shell instead of using a `.env` file (an exported/environment value always takes precedence over `.env`):
```bash
# Linux/macOS
export NVD_API_KEY="your-nvd-api-key-here"
bannergrapv2 example.com

# Windows (PowerShell)
$env:NVD_API_KEY="your-nvd-api-key-here"
.\bannergrapv2.exe example.com
```

#### 3. Verify it's working
Run any scan with `NVD_DEBUG=1` to see NVD lookup diagnostics on stderr:
```bash
NVD_DEBUG=1 bannergrapv2 example.com
```
If the key is picked up correctly, you'll see NVD candidate/query debug lines instead of the `NVD_API_KEY not set` message.

### Basic Usage

```bash
Flags:
  -f string
        File containing newline-separated targets (host or host:port)
  -proto string
        Protocol to use: http (default), https, ftp, smtp, ssh, telnet, custom
  -port string
        Override port for every target (overrides both target ports and defaults)
  -payload string
        Custom payload to send (default is protocol-specific)
  -timeout int
        Connection + read timeout in seconds (default 5)
  -threads int
        Number of simultaneous connections (default 10)
  -o string
        Output file path (.json or .csv, txt  inferred by extension; console if empty)

   -h    help


# Version & Help:

go run bannerGrap.go --version
go run bannerGrap.go -h

# Scan a single host
go run bannerGrap.go example.com

go run bannerGrap.go example.com:80

# or,
bannergrapv2 192.168.1.1

# Scan multiple hosts
bannergrapv2 -f targets.txt
# or,
go run bannerGrap.go -f targets.txt
go run bannerGrap.go -f targets.txt -proto http
go run bannerGrap.go -f targets.txt -proto https
go run bannerGrap.go -f targets.txt -proto ftp
go run bannerGrap.go -f targets.txt -proto smtp
go run bannerGrap.go -f targets.txt -proto ssh
go run bannerGrap.go -f targets.txt -proto telnet
go run bannerGrap.go -f targets.txt -proto custom
go run bannerGrap.go -f targets.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
go run bannerGrap.go -f targets.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10
go run bannerGrap.go -f targets.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5

# Custom Payloads: Send your own payload(SMTP VRFY or EXPN, FTP USER, etc.)
	    
go run bannerGrap.go -proto smtp -payload "VRFY postmaster\r\n" mail.example.com
go run bannerGrap.go -proto smtp -payload "EXPN postmaster\r\n" mail.example.com
go run bannerGrap.go -proto ftp -payload "USER anonymous\r\n" ftp.example.com
go run bannerGrap.go -proto ssh -payload "SSH-2.0-OpenSSH_7.4\r\n" ssh.example.com
go run bannerGrap.go -proto telnet -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" telnet.example.com
go run bannerGrap.go -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" custom.example.com
go run bannerGrap.go -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" custom.example.com:8080
go run bannerGrap.go -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" custom.example.com:8080 -timeout 10
	
# Scan with custom ports
bannergrapv2 192.168.1.1 -ports 80,443,8080,3306

### Save with output ###
# JSON output:

go run bannerGrap.go -f hosts.txt -o results.json
# CSV output:

go run bannerGrap.go -f hosts.txt -o results.csv
# Text output:

go run bannerGrap.go -f hosts.txt -o results.txt
# Console output:

go run bannerGrap.go -f hosts.txt
# JSON output with custom payload:

go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.json

# CSV output with custom payload:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.csv

#Text output with custom payload:

go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.txt

#Console output with custom payload:

go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

#JSON output with custom payload and timeout:

go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.json

# CSV output with custom payload and timeout:

go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.csv
	
# Text output with custom payload and timeout and threads and port and protocol:

go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.txt
    
# Full scan with all features

# “Extreme” Combined:

[+] Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to CSV:

   go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.csv

  //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to JSON:

  go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.json

  //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to console:

  go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.txt

  //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to console:

  go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.txt


[+] //  Massive HTTPS Scan with Custom Header & CSV Output: Scan 10 000 domains over TLS, 500 threads, 2 s timeout, dump to CSV-
 
 go run bannerGrap.go \
  -f ten_thousand_domains.txt \
  -proto https \
  -port 443 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 500 \
  -timeout 2 \
  -o https_scan_results.csv

 //  Massive HTTPS Scan with Custom Header & JSON Output: Scan 10 000 domains over TLS, 500 threads, 2 s timeout, dump to JSON-

 go run bannerGrap.go \
  -f ten_thousand_domains.txt \
  -proto https \
  -port 443 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 500 \
  -timeout 2 \
  -o https_scan_results.json

 //  Massive HTTPS Scan with Custom Header & Console Output: Scan 10 000 domains over TLS, 500 threads, 2 s timeout, dump to console-

 go run bannerGrap.go \
  -f ten_thousand_domains.txt \
  -proto https \
  -port 443 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 500 \
  -timeout 2 \
  -o https_scan_results.txt

 3.3] Ultra-Fast HTTP Sweep on IP Range: Hit 192.168.1.1–254 on port 80 with 254 threads and 1 s timeout-

 go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto http \
  -port 80 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 254 \
  -timeout 1 \
  -o http_sweep.csv

//////
go run banner_grabber.go \
  -f <(for i in $(seq 1 254); do echo \"192.168.1.$i\"; done) \
  -proto http \
  -threads 254 \
  -timeout 1
  -o http_sweep.csv
  -o http_sweep.json
  -o http_sweep.txt

[+} SMTP Banner Harvesting in Bulk (JSON): Pull EHLO banners from mail servers list, override port to 25, output JSON-
      
//Pull EHLO banners from mail servers list, override port to 25, output JSON-

go run bannerGrap.go \
  -f mail_hosts.txt \
  -proto smtp \
  -port 25 \
  -threads 100 \
  -timeout 5 \
  -o smtp_banners.json

//Pull HTTP banners from web servers list, override port to 80, output CSV-

 go run bannerGrap.go \
  -f web_hosts.txt \
  -proto http \
  -port 80 \
  -threads 50 \
  -timeout 3 \
  -o http_banners.csv
//Pull FTP banners from FTP servers list, override port to 21, output JSON-
  go run bannerGrap.go \
  -f ftp_hosts.txt \
  -proto ftp \
  -port 21 \
  -threads 20 \
  -timeout 2 \
  -o ftp_banners.json

//Pull SSH banners from SSH servers list, output JSON-

 go run bannerGrap.go \
  -f ssh_hosts.txt \
  -proto ssh \
  -threads 10 \
  -timeout 5 \
  -o ssh_banners.json

//Pull Telnet banners from Telnet servers list, output CSV-

 go run bannerGrap.go \
  -f telnet_hosts.txt \
  -proto telnet \
  -threads 10 \
  -timeout 5 \
  -o telnet_banners.csv

//Pull custom banners from custom servers list, output JSON-

  go run bannerGrap.go \
  -f custom_hosts.txt \
  -proto custom \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" \
  -threads 10 \
  -timeout 5 \
  -o custom_banners.json

[+] FTP Anonymous Banner Grab: Scan FTP servers (file lists mixed hostnames & IPs), force port 21, no custom payload needed-

go run bannerGrap.go \
  -f ftp_targets.txt \
  -proto ftp \
  -port 21 \
  -threads 150 \
  -timeout 4 \
  -o ftp_banners.csv

[+] SSH Welcome Message Blitz: Read SSH welcomes from 1 000 hosts, port 22, high concurrency, console output-

go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto ssh \
  -port 22 \
  -threads 300 \
  -timeout 3

[+] Telnet Service Fingerprinting: Connect to Telnet on mixed IPv4 & IPv6 targets, port 23-

go run bannerGrap.go \
  -f mixed_targets.txt \
  -proto telnet \
  -port 23 \
  -threads 100 \
  -timeout 5 \
  -o telnet_fingerprints.json

[+] Custom TCP Payload for Proprietary Service: Send a proprietary “HELLO\n” payload to a custom daemon on port 9000-

go run bannerGrap.go \
  -f custom_daemon_hosts.txt \
  -proto custom \
  -port 9000 \
  -payload "HELLO\n" \
  -threads 50 \
  -timeout 6 \
  -o daemon_responses.csv

 [+] Mixed-Protocol One-Liner:Scan HTTP, then HTTPS, then SMTP sequentially (three invocations) on a single host:

go run bannerGrap.go example.com                       # HTTP:80  
go run bannerGrap.go -proto https example.com          # HTTPS:443  
go run bannerGrap.go -proto smtp example.com:25        # SMTP:25


[+] Internal LAN Audit: Check local hostnames and IPs in internal_targets.txt, console output-
 
 go run banner_grabber.go \
  -f internal_targets.txt \
  -threads 50 \
  -timeout 3
 
 [+]IPv6-Only Enumeration:Scan a list of IPv6 hosts on HTTPS, 100 threads-
  
go run bannerGrap.go \
  -f ipv6_hosts.txt \
  -proto https \
  -port 443 \
  -threads 100 \
  -timeout 4 \
```

---

## 📖 Documentation

### 🎓 Tutorials
- [Getting Started Guide](docs/bannerGrap_Guide_of_Usage.md)
- [Advanced Usage](docs/New_advanced_bashScripts.md)
- [Scan Techniques](docs/scan-techniques.md)
- [Output Formats](docs/output-formats.md)

### 📚 Reference
- [Command-Line Options](docs/cli-reference.md)
- [Configuration File](docs/configuration.md)

### 💡 Use Cases
- [Bug Bounty Workflow](docs/bug-bounty.md)
- [Penetration Testing](docs/pentesting.md)
- [Security Auditing](docs/auditing.md)
- [CI/CD Integration](docs/cicd.md)

---

## 🎯 Command-Line Options


---

## 🔥 Examples

### Example 1: Quick Web Server Scan
```bash
bannergrapv2 example.com -ports 80,443 -ssl-check -http-headers
```

**Output:**
```bash
__________                                      ________                                        
\______   \_____    ____   ____   ___________  /  _____/___________  ______        ____   ____  
 |    |  _/\__  \  /    \ /    \_/ __ \_  __ \/   \  __\_  __ \__  \ \____ \      / ___\ /  _ \ 
 |    |   \ / __ \|   |  \   |  \  ___/|  | \/\    \_\  \  | \// __ \|  |_> >    / /_/  >  <_> )
 |______  /(____  /___|  /___|  /\___  >__|    \______  /__|  (____  /   __/ /\  \___  / \____/ 
        \/      \/     \/     \/     \/               \/           \/|__|    \/ /_____/         


[+] Target: example.com (93.184.216.34)
[+] Open Ports: 80, 443
PORT    SERVICE    VERSION              VULNERABILITIES
80      HTTP       nginx/1.18.0         None detected
443     HTTPS      nginx/1.18.0 (TLS)   TLS 1.0 Deprecated (Low)
[+] SSL Certificate:
Subject: CN=example.com
Issuer: DigiCert Inc
Valid: 2024-01-01 to 2025-01-01
Grade: A
[✓] Scan completed in 2.34s

```

### Example 2: Network Reconnaissance
```bash
go run bannerGrap.go 192.168.1.0/24 -threads 200 -output network-scan.json

or,

bannergrapv2 192.168.1.0/24 -threads 200 -output network-scan.json
```

### Example 3: Vulnerability Assessment
```bash
bannergrapv2 vulnerable-site.com -vuln-scan -format html -output vuln-report.html
```

### Example 4: CI/CD Integration
```bash
# .github/workflows/security-scan.yml
bannergrapv2 production-hosts.txt -vuln-scan -format json -output scan-results.json
```

---

## 🛠️ Advanced Configuration

Create a `config.yaml` file:

```yaml
# BannerGrapV2 Configuration

general:
  threads: 100
  timeout: 10
  retries: 3
  verbose: true

scan:
  common_ports: true
  port_range: "1-10000"
  service_detection: true
  ssl_analysis: true

vulnerability:
  enabled: true
  cve_database: "local"  # or "online"
  min_severity: "medium"

output:
  format: "json"
  directory: "./reports"
  timestamp: true

brute_force:
  enabled: false
  username_list: "usernames.txt"
  password_list: "passwords.txt"
```

Run with config:
```bash
bannergrapv2 -config config.yaml -target 192.168.1.1
```

---

## 🏗️ Project Structure or Project Tree

```bash
├── bannerGrap
├── bannerGrap.go
├── bannerGrap_test.go
├── bannergrapv2-darwin-amd64
├── bannergrapv2-darwin-arm64
├── bannergrapv2-linux-amd64
├── bannergrapv2-linux-arm64
├── BannerGrapV2_Security_Scanner_Tool_1d0e04fd-c100-4173-88b9-52a99f69fc2b.jpeg
├── bannergrapv2-windows-amd64.exe
├── CHECKSUMS.txt
├── bannerv2-deploy.yaml
├── bannerv2-job.yaml
├── bannerv2-service.yaml
├── build_and_run.sh
├── CONTRIBUTING.md
├── Dockerfile
├── docs
│   ├── auditing.md
│   ├── bannerGrap_Guide_of_Usage.md
│   ├── bug-bounty.md
│   ├── cicd.md
│   ├── cli-reference.md
│   ├── configuration.md
│   ├── New_advanced_bashScripts.md
│   ├── output-formats.md
│   ├── pentesting.md
│   └── scan-techniques.md
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── report.html
├── run_bannerv2.sh
├── SECURITY.md
└── start_banner.sh

```
---

## 🤝 Contributing

We love contributions! 🎉

### Ways to Contribute:
- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the project

### Quick Contribution Guide:

1. **Fork the repository**
2. **Create your feature branch**
```bash
   git checkout -b feature/AmazingFeature
```
3. **Commit your changes**
```bash
   git commit -m 'Add some AmazingFeature'
```
4. **Push to the branch**
```bash
   git push origin feature/AmazingFeature
```
5. **Open a Pull Request**

Read our [Contributing Guide](CONTRIBUTING.md) for detailed information.

### 🐛 Found a Bug?
[Open an issue](https://github.com/MrEchoFi/BannerGrapV2/issues/new?template=bug_report.md)

### 💡 Have a Feature Request?
[Request a feature](https://github.com/MrEchoFi/BannerGrapV2/issues/new?template=feature_request.md)

---

## 🔒 Security

### Responsible Disclosure
Found a security vulnerability? Please **DO NOT** open a public issue.

Email: **tanjibisham777@gmail.com**

See our [Security Policy](SECURITY.md) for more information.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Thanks to all [contributors](https://github.com/MrEchoFi/BannerGrapV2/graphs/contributors)
- Inspired by tools like Nmap, Masscan, and Shodan
- Built with ❤️ using [Go](https://golang.org)

---

## 📊 Project Stats

![GitHub commit activity](https://img.shields.io/github/commit-activity/m/MrEchoFi/BannerGrapV2?style=for-the-badge)
![GitHub last commit](https://img.shields.io/github/last-commit/MrEchoFi/BannerGrapV2?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/MrEchoFi/BannerGrapV2?style=for-the-badge)
![GitHub pull requests](https://img.shields.io/github/issues-pr/MrEchoFi/BannerGrapV2?style=for-the-badge)

---

## 💬 Community

Join our growing community!

[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?style=for-the-badge&logo=discord)](https://discord.gg/ntTW959Y)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/md-abu-naser-nayeem-mrechofi-b29496332)

---

## 🗺️ Roadmap

- [x] Core banner grabbing functionality
- [x] Multi-threaded scanning
- [x] Basic vulnerability detection
- [ ] Plugin system
- [ ] Integration with Metasploit & Nmap
- [ ] Docker container support
- [ ] Kubernetes operator

See the [open issues](https://github.com/MrEchoFi/BannerGrapV2/issues) for a full list of proposed features.

---

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=MrEchoFi/BannerGrapV2&type=Date)](https://star-history.com/#MrEchoFi/BannerGrapV2&Date)

---

# How It Helps in the Cyber World:

<li>Penetration Testing:
Quickly identifies exposed and vulnerable services across networks.</li>

<li>Red Team Operations:
Automates reconnaissance and initial access vector discovery.</li>

<li>Blue Team/Defensive Security:
Assists in asset inventory, vulnerability management, and attack surface reduction.</li>

<li>DevSecOps Operation:
Identify vulnerabilities and can do exploits, reconnaissance, find hidden banner & dir etc. </li>

<li>Education & Research:
Teaches protocol analysis, vulnerability detection, and Go security programming.</li>


## 👨‍💻 About the Developer

**MrEchoFi** (Md. Abu Naser Nayeem / Tanjib Isham)
- 🔍 Cybersecurity Researcher
- 🛡️ DevSecOps & Penetration Testing Specialist
- 🌐 Portfolio: [https://echo-fi-portfolio-node-js.vercel.app](https://echo-fi-portfolio-node-js.vercel.app)

---

<div align="center">

### ⭐ If you find BannerGrapV2 useful, please give it a star!

**Best Regards ~ [MrEchoFi](https://github.com/MrEchoFi)**
----------------------------------------------------------
**Happy HackNight**

[⬆ Back to Top](#-bannergrapv2)

</div>
