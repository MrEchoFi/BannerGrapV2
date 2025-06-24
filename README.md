# BannerGrap: Advanced Multi-Protocol Security Scanner
BannerGrap is a powerful, modular, and extensible Go-based security scanner designed for advanced reconnaissance and vulnerability assessment across a wide range of network services.
It combines classic banner grabbing with active vulnerability probing, CVE/exploit matching, brute force stubs, and reporting, making it a valuable tool for penetration testers, red teamers, and defenders.

# Key Features:

Multi-Protocol Support:
Scan HTTP, HTTPS, HTTP/2, WebSocket, FTP, SMTP, SSH, Telnet, and more.

Banner Grabbing:
Collects service banners and fingerprints for rapid identification.

Signature-Based Vulnerability Detection:
Detects 50+ popular server products and flags known vulnerable versions.

Active Probes:
Includes safe, practical stubs for Heartbleed, Shellshock, and Log4Shell detection.

CVE/Exploit DB Integration:
Matches banners to known CVEs using regex and can be extended for real DB integration.

Brute Force & Enumeration Stubs:
Framework for credential brute forcing and service enumeration.

Reporting:
Outputs results in JSON, CSV, and HTML formats for easy integration and sharing.

Concurrency:
Fast, multi-threaded scanning for large-scale assessments.

Extensible:
Plugin system and modular codebase for easy feature expansion.

# Usage: 
`Usage: go run bannerGrap.go
-> & read these two files of its usage:
[i] bannerGrap_Guid or Usage.txt
[ii] New_advanced_bashScripts.md
-> Btw 2nd file i mean New_advanced_bashScripts.md is for version 2.0 speacily but the bannerGrap_Guid or Usage.txt is also important cause in this file it have all usages like basic to aggresive usage..
Options:

-f targets.txt      File with list of targets (host[:port] per line)
-proto protocol     Protocol: http, https, http2, websocket, ftp, smtp, ssh, telnet, custom
-port PORT       Override port for all targets
-payload PAYLOAD   Custom payload (default based on protocol)
-timeout N      Timeout (s) per connection/read
-threads N      Number of concurrent scans
-max N        Maximum banner bytes to read
-o output.json|csv  Output file (.json or .csv)
-report-html file.html Output HTML report
-brute-userlist FILE Username list for brute force (optional)
-brute-passlist FILE Password list for brute force (optional)
-plugin-dir DIR   Directory for custom plugins/scripts (optional)
-v          Verbose: print progress per target
-version      Show version and exit

# How It Helps in the Cyber World

Penetration Testing:
Quickly identifies exposed and vulnerable services across networks.

Red Team Operations:
Automates reconnaissance and initial access vector discovery.

Blue Team/Defensive Security:
Assists in asset inventory, vulnerability management, and attack surface reduction.

Education & Research:
Teaches protocol analysis, vulnerability detection, and Go security programming.

# How to Contribute:

 Create a feature branch, and submit a pull request.
Add new vulnerability signatures, active probes, or protocol modules.
Improve reporting, performance, or add integrations (e.g., SIEM, ticketing).
Report bugs or suggest features via issues.

Credit:
Developed by MrEchoFi (Md. Abu Naser Nayeem [Tanjib Isham]) and contributors.

