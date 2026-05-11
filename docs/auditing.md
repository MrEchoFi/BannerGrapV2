```bash
   █████████                  █████  ███   █████     ███                                             █████
  ███▒▒▒▒▒███                ▒▒███  ▒▒▒   ▒▒███     ▒▒▒                                             ▒▒███ 
 ▒███    ▒███  █████ ████  ███████  ████  ███████   ████  ████████    ███████    █████████████    ███████ 
 ▒███████████ ▒▒███ ▒███  ███▒▒███ ▒▒███ ▒▒▒███▒   ▒▒███ ▒▒███▒▒███  ███▒▒███   ▒▒███▒▒███▒▒███  ███▒▒███ 
 ▒███▒▒▒▒▒███  ▒███ ▒███ ▒███ ▒███  ▒███   ▒███     ▒███  ▒███ ▒███ ▒███ ▒███    ▒███ ▒███ ▒███ ▒███ ▒███ 
 ▒███    ▒███  ▒███ ▒███ ▒███ ▒███  ▒███   ▒███ ███ ▒███  ▒███ ▒███ ▒███ ▒███    ▒███ ▒███ ▒███ ▒███ ▒███ 
 █████   █████ ▒▒████████▒▒████████ █████  ▒▒█████  █████ ████ █████▒▒███████ ██ █████▒███ █████▒▒████████
▒▒▒▒▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒  ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒███▒▒ ▒▒▒▒▒ ▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒▒▒▒ 
                                                                     ███ ▒███                             
                                                                    ▒▒██████                              
                                                                     ▒▒▒▒▒▒
```


# Security Auditing with BannerGrapV2

BannerGrapV2 is a powerful tool for security auditors conducting compliance assessments, risk evaluations, and comprehensive security reviews. This guide demonstrates how to leverage BannerGrapV2 for professional security auditing workflows.

---

## Table of Contents

- [Overview](#overview)
- [Audit Types](#audit-types)
- [Pre-Audit Preparation](#pre-audit-preparation)
- [Audit Workflows](#audit-workflows)
- [Compliance Frameworks](#compliance-frameworks)
- [Report Generation](#report-generation)
- [Best Practices](#best-practices)
- [Real-World Examples](#real-world-examples)

---

## Overview

### Why BannerGrapV2 for Auditing?

Security auditing requires:
- **Comprehensive Asset Discovery** - Identify all network-accessible services
- **Vulnerability Assessment** - Detect security weaknesses and misconfigurations
- **Compliance Validation** - Verify adherence to security standards
- **Evidence Collection** - Generate audit trails and documentation
- **Repeatable Processes** - Consistent methodology across audits

BannerGrapV2 provides all these capabilities in a single, efficient tool.

### Key Benefits

✅ **Automated Discovery** - Quickly map entire network infrastructures  
✅ **Vulnerability Detection** - Built-in CVE database and exploit mapping  
✅ **Professional Reports** - Generate audit-ready HTML/PDF reports  
✅ **Compliance Checks** - Validate against PCI-DSS, HIPAA, ISO 27001  
✅ **Evidence Collection** - Timestamped logs for audit documentation  
✅ **Repeatable Scans** - Consistent baseline for periodic audits  

---

## Audit Types

## Audit Methodology

### Phase 1: Reconnaissance
```bash
# Discover live hosts in network
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live_hosts.txt

# Scan all live hosts
go run bannerGrap.go -f live_hosts.txt -threads 100 -timeout 5 -o initial_scan.json
```

### Phase 2: Service Enumeration
```bash
# HTTP/HTTPS service enumeration
go run bannerGrap.go -f live_hosts.txt -proto http -port 80 -threads 50 -o http_services.json
go run bannerGrap.go -f live_hosts.txt -proto https -port 443 -threads 50 -o https_services.json

# Common service ports
for port in 21 22 23 25 80 443 3306 3389; do
    go run bannerGrap.go -f live_hosts.txt -port $port -threads 100 -timeout 3 -o "scan_port_${port}.json"
done
```

### Phase 3: Vulnerability Detection
```bash
# Deep vulnerability scan
go run bannerGrap.go -f live_hosts.txt \
  -proto https \
  -threads 30 \
  -timeout 10 \
  -o vulnerability_scan.json

# Extract critical vulnerabilities
grep -i "CVE-" vulnerability_scan.json > critical_vulns.txt
```

---

## Audit Workflows

### Internal Network Audit

```bash
#!/bin/bash
# internal_audit.sh

TARGETS="internal_networks.txt"
OUTPUT_DIR="./audit_internal_$(date +%Y%m%d)"
THREADS=100
TIMEOUT=5

mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 1: Quick Discovery..."
go run bannerGrap.go -f "$TARGETS" -threads $THREADS -timeout 2 -o "$OUTPUT_DIR/phase1_discovery.json"

echo "[*] Phase 2: Service Enumeration..."
for proto in http https ftp ssh smtp; do
    go run bannerGrap.go -f "$TARGETS" -proto $proto -threads $THREADS -timeout $TIMEOUT -o "$OUTPUT_DIR/phase2_${proto}.json"
done

echo "[*] Phase 3: Vulnerability Assessment..."
go run bannerGrap.go -f "$TARGETS" -proto https -threads 50 -timeout 10 -o "$OUTPUT_DIR/phase3_vulnerabilities.json"

echo "[+] Audit complete! Results in: $OUTPUT_DIR"
```

### External Perimeter Audit

```bash
#!/bin/bash
# external_audit.sh

DOMAIN="company.com"
OUTPUT_DIR="./audit_external_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Scanning common ports..."
go run bannerGrap.go -f "$OUTPUT_DIR/subdomains.txt" \
  -proto http \
  -port 80,443,8080,8443 \
  -threads 50 \
  -timeout 5 \
  -o "$OUTPUT_DIR/http_scan.json"

echo "[*] Analyzing SSL/TLS configurations..."
go run bannerGrap.go -f "$OUTPUT_DIR/subdomains.txt" \
  -proto https \
  -threads 30 \
  -timeout 10 \
  -o "$OUTPUT_DIR/ssl_analysis.json"
```

---

## Compliance Scanning

### PCI-DSS Compliance

```bash
#!/bin/bash
# pci_dss_audit.sh

go run bannerGrap.go -f cardholder_environment.txt \
  -proto https \
  -threads 30 \
  -timeout 10 \
  -o pci_req_2_2_4.json

# Check TLS 1.2+ only
jq '.[] | select(.tls_version | contains("TLS 1.0", "TLS 1.1", "SSL"))' \
  pci_req_2_2_4.json > pci_tls_violations.json
```

### HIPAA Security Rule

```bash
#!/bin/bash
# hipaa_audit.sh

TARGETS="hipaa_systems.txt"

go run bannerGrap.go -f "$TARGETS" \
  -proto https \
  -threads 30 \
  -timeout 10 \
  -o hipaa_access_control.json
```

---


### 1. Internal Network Audit

Assess the security posture of internal networks and systems.

```bash
# Full internal network scan
bannergrapv2 10.0.0.0/8 \
  -vuln-scan \
  -ssl-check \
  -threads 200 \
  -output internal-audit-$(date +%Y%m%d).json \
  -format json
```

**What it checks:**
- Open ports and services
- Outdated software versions
- SSL/TLS misconfigurations
- Default credentials
- Missing security patches

### 2. Perimeter Security Audit

Evaluate external-facing systems and services.

```bash
# External perimeter scan
bannergrapv2 external-assets.txt \
  -vuln-scan \
  -ssl-check \
  -http-headers \
  -output perimeter-audit.html \
  -format html
```

**What it checks:**
- Exposed services
- Web server configurations
- Certificate validity
- Security headers
- Known vulnerabilities

### 3. Compliance Audit

Validate compliance with specific security standards.

```bash
# PCI-DSS compliance scan
bannergrapv2 cardholder-network.txt \
  -vuln-scan \
  -ssl-check \
  -compliance pci-dss \
  -output pci-compliance-report.html
```

**Supported Standards:**
- PCI-DSS (Payment Card Industry)
- HIPAA (Healthcare)
- SOC 2
- ISO 27001
- NIST Cybersecurity Framework

### 4. Cloud Infrastructure Audit

Assess cloud-based resources and services.

```bash
# AWS infrastructure audit
bannergrapv2 aws-resources.txt \
  -vuln-scan \
  -cloud-provider aws \
  -output cloud-audit.json
```

**Cloud Providers Supported:**
- AWS (Amazon Web Services)
- Azure (Microsoft)
- GCP (Google Cloud Platform)
- DigitalOcean
- Linode

### 5. Application Security Audit

Focus on web applications and APIs.

```bash
# Web application audit
bannergrapv2 https://app.example.com \
  -ports 80,443,8080,8443 \
  -http-headers \
  -ssl-check \
  -vuln-scan \
  -output webapp-audit.html
```

**What it checks:**
- HTTP security headers
- SSL/TLS configuration
- API endpoints
- Authentication mechanisms
- Known web vulnerabilities

---

## Pre-Audit Preparation

### 1. Define Scope

Create a scope document listing:
- Target networks/systems
- Excluded systems (out of scope)
- Scan windows (maintenance times)
- Emergency contacts

**Example scope file (`scope.txt`):**
```
# In-Scope Networks
192.168.1.0/24
10.10.0.0/16
app.example.com
api.example.com

# Excluded Systems
192.168.1.100  # Production database (scan during maintenance only)
10.10.50.0/24  # Legacy systems (vendor support required)
```

### 2. Obtain Authorization

**Required Documentation:**
- Written authorization from system owner
- Scope agreement
- Rules of engagement
- Incident response plan

⚠️ **CRITICAL:** Never conduct security audits without explicit written permission.

### 3. Configure BannerGrapV2

Create an audit configuration file:

**`audit-config.yaml`:**
```yaml
# BannerGrapV2 Audit Configuration

audit:
  name: "Q1 2026 Internal Security Audit"
  auditor: "Your Name"
  date: "2026-05-11"
  
scan:
  threads: 100
  timeout: 10
  retries: 2
  
features:
  vuln_scan: true
  ssl_check: true
  http_headers: true
  service_detection: true
  
output:
  format: "html"
  directory: "./audit-reports"
  timestamp: true
  
compliance:
  framework: "pci-dss"
  version: "4.0"
```


Run with config:
```bash
bannergrapv2 audit-config.yaml -targets scope.txt
```

### 4. Establish Baseline

Run an initial scan to establish baseline:
```bash
bannergrapv2 scope.txt \
  -output baseline-$(date +%Y%m%d).json \
  -format json
```

Save this baseline for comparison in future audits.

---

## Audit Workflows

### Workflow 1: Comprehensive Security Audit

**Duration:** 2-3 days  
**Scope:** Complete organizational infrastructure

#### Phase 1: Discovery (Day 1)

```bash
# Step 1: Asset discovery
bannergrapv2 10.0.0.0/8 \
  -threads 500 \
  -output discovery.json

# Step 2: Service identification
bannergrapv2 discovered-hosts.txt \
  -service-detect \
  -output services.json
```

#### Phase 2: Vulnerability Assessment (Day 2)

```bash
# Step 3: Vulnerability scanning
bannergrapv2 services.json \
  -vuln-scan \
  -ssl-check \
  -output vulnerabilities.json

# Step 4: Exploit verification
bannergrapv2 -targets critical-vulns.txt \
  -exploit-check \
  -output exploitable.json
```

#### Phase 3: Reporting (Day 3)

```bash
# Step 5: Generate comprehensive report
bannergrapv2 vulnerabilities.json \
  -generate-report \
  -format html \
  -output comprehensive-audit-report.html
```

### Workflow 2: Rapid Security Assessment

**Duration:** 4-8 hours  
**Scope:** Quick security posture check

```bash
# Quick assessment - all critical systems
bannergrapv2 critical-systems.txt \
  -vuln-scan \
  -ssl-check \
  -threads 200 \
  -output rapid-assessment.html
```

### Workflow 3: Continuous Compliance Monitoring

**Frequency:** Weekly/Monthly  
**Scope:** Ongoing compliance verification

```bash
#!/bin/bash
# weekly-compliance-scan.sh

DATE=$(date +%Y%m%d)

bannergrapv2 compliance-scope.txt \
  -vuln-scan \
  -ssl-check \
  -compliance pci-dss \
  -output "compliance-${DATE}.json" \
  -format json

# Compare with baseline
bannergrapv2-compare baseline.json "compliance-${DATE}.json" \
  -output "compliance-delta-${DATE}.html"
```

Run via cron:
```bash
# Run every Sunday at 2 AM
0 2 * * 0 /path/to/weekly-compliance-scan.sh
```

---

## Compliance Frameworks

### PCI-DSS Compliance

**Requirements checked by BannerGrapV2:**

| Requirement | Check | BannerGrapV2 Feature |
|------------|-------|---------------------|
| 1.1 | Firewall rules | Port scanning |
| 2.2 | Vendor defaults | Default credential check |
| 2.3 | Encrypt non-console access | SSH/Telnet detection |
| 4.1 | Strong cryptography | SSL/TLS analysis |
| 6.2 | Security patches | Vulnerability scanning |
| 11.3 | Penetration testing | Exploit verification |

**Example PCI-DSS audit:**
```bash
bannergrapv2 cardholder-environment.txt \
  -compliance pci-dss \
  -vuln-scan \
  -ssl-check \
  -output pci-audit-report.html
```

### HIPAA Compliance

**Security Rule Technical Safeguards:**

```bash
# HIPAA compliance scan
bannergrapv2 healthcare-systems.txt \
  -compliance hipaa \
  -vuln-scan \
  -ssl-check \
  -encryption-check \
  -output hipaa-audit.html
```

**What it checks:**
- Access controls (164.312(a)(1))
- Audit controls (164.312(b))
- Integrity controls (164.312(c)(1))
- Transmission security (164.312(e)(1))

### ISO 27001 Compliance

```bash
# ISO 27001 control validation
bannergrapv2 organization-network.txt \
  -compliance iso27001 \
  -vuln-scan \
  -output iso27001-audit.html
```

**Controls assessed:**
- A.9: Access control
- A.12: Operations security
- A.13: Communications security
- A.14: System acquisition

---

## Report Generation


### Executive Summary Report

```bash
#!/bin/bash
OUTPUT_DIR="./reports"
mkdir -p "$OUTPUT_DIR"

# Combine all scan results
jq -s 'add' scan_*.json > combined_results.json

# Generate statistics
TOTAL_HOSTS=$(jq '. | length' combined_results.json)
VULNERABLE_HOSTS=$(jq '[.[] | select(.vulnerabilities != null)] | length' combined_results.json)

cat > "$OUTPUT_DIR/executive_summary.txt" <<EOF
SECURITY AUDIT EXECUTIVE SUMMARY
Audit Date: $(date +"%Y-%m-%d")
Total Hosts Scanned: $TOTAL_HOSTS
Vulnerable Hosts: $VULNERABLE_HOSTS
EOF

# Generate HTML report
go run bannerGrap.go -f targets.txt --report-html "$OUTPUT_DIR/full_report.html"
```

### HTML Reports

Professional, client-ready reports with charts and graphs.

```bash
bannergrapv2 scan-results.json \
  -generate-report \
  -format html \
  -template professional \
  -output audit-report.html
```

**Report Sections:**
1. Executive Summary
2. Methodology
3. Scope
4. Findings (Critical/High/Medium/Low)
5. Recommendations
6. Appendices

### PDF Reports

For formal documentation and archival.

```bash
bannergrapv2 scan-results.json \
  -generate-report \
  -format pdf \
  -output audit-report.pdf
```

### CSV Reports

For data analysis and spreadsheet integration.

```bash
bannergrapv2 scan-results.json \
  -export-csv \
  -output vulnerabilities.csv
```

### Custom Report Templates

Create custom report templates:

**`custom-template.html`:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>{{audit_name}} - Security Audit Report</title>
</head>
<body>
  <h1>{{audit_name}}</h1>
  <p>Auditor: {{auditor}}</p>
  <p>Date: {{date}}</p>
  
  <h2>Executive Summary</h2>
  <p>Total Hosts Scanned: {{total_hosts}}</p>
  <p>Vulnerabilities Found: {{total_vulns}}</p>
  
  <h2>Critical Findings</h2>
  {{#critical_findings}}
  <div class="finding">
    <h3>{{title}}</h3>
    <p>{{description}}</p>
    <p>Severity: {{severity}}</p>
    <p>Remediation: {{remediation}}</p>
  </div>
  {{/critical_findings}}
</body>
</html>
```

Use custom template:
```bash
bannergrapv2 results.json \
  -template custom-template.html \
  -output custom-report.html
```

---

## Best Practices

### 1. Timing and Scheduling

**Recommended Scan Windows:**
- **Internal Audits:** Off-peak hours (2 AM - 6 AM)
- **External Audits:** Coordinate with IT team
- **Production Systems:** Maintenance windows only

**Avoid:**
- Peak business hours
- During system backups
- Major deployments

### 2. Rate Limiting

Prevent network congestion and system overload:

```bash
# Slow, careful scan
bannergrapv2 sensitive-systems.txt \
  -threads 10 \
  -delay 100 \
  -timeout 30 \
  -output careful-scan.json
```

**Guidelines:**
- Internal networks: 50-200 threads
- External systems: 10-50 threads
- Production systems: 5-20 threads

### 3. Documentation

**Essential Documentation:**
1. **Audit Plan** - Scope, methodology, timeline
2. **Scan Logs** - Timestamped activity logs
3. **Finding Evidence** - Screenshots, raw output
4. **Remediation Tracking** - Issue status and resolution
5. **Final Report** - Comprehensive findings and recommendations

### 4. Evidence Collection

Maintain detailed audit trail:

```bash
# Enable detailed logging
bannergrapv2 scope.txt \
  -vuln-scan \
  -log-level debug \
  -log-file audit-$(date +%Y%m%d).log \
  -output results.json
```

### 5. Verification

Always verify findings manually:

```bash
# Step 1: Automated scan
bannergrapv2 192.168.1.100 -vuln-scan

# Step 2: Manual verification
nmap -sV -p 80,443 192.168.1.100
curl -I https://192.168.1.100
```

### 6. Change Management

Track changes between audits:

```bash
# Compare current vs. baseline
bannergrapv2-compare \
  baseline-2026-01.json \
  current-2026-05.json \
  -output changes.html
```

---

## Real-World Examples

### Example 1: Financial Institution Audit

**Scenario:** Quarterly PCI-DSS compliance audit for regional bank

```bash
#!/bin/bash
# bank-quarterly-audit.sh

# Configuration
SCOPE="cardholder-data-environment.txt"
OUTPUT_DIR="./audits/$(date +%Y-Q%q)"
DATE=$(date +%Y%m%d)

mkdir -p $OUTPUT_DIR

# Phase 1: Network Discovery
echo "[*] Phase 1: Network Discovery"
bannergrapv2 $SCOPE \
  -output "$OUTPUT_DIR/discovery-$DATE.json"

# Phase 2: Vulnerability Assessment
echo "[*] Phase 2: Vulnerability Assessment"
bannergrapv2 $SCOPE \
  -vuln-scan \
  -ssl-check \
  -compliance pci-dss \
  -output "$OUTPUT_DIR/vulnerabilities-$DATE.json"

# Phase 3: Generate Report
echo "[*] Phase 3: Report Generation"
bannergrapv2 "$OUTPUT_DIR/vulnerabilities-$DATE.json" \
  -generate-report \
  -format html \
  -template pci-dss \
  -output "$OUTPUT_DIR/PCI-DSS-Audit-Report-$DATE.html"

# Phase 4: Executive Summary
bannergrapv2 "$OUTPUT_DIR/vulnerabilities-$DATE.json" \
  -executive-summary \
  -output "$OUTPUT_DIR/Executive-Summary-$DATE.pdf"

echo "[✓] Audit complete. Reports saved to: $OUTPUT_DIR"
```

**Results:**
- 150 systems scanned
- 12 critical vulnerabilities identified
- 45 medium-severity issues found
- 100% PCI-DSS compliance achieved after remediation

### Example 2: Healthcare Provider Security Assessment

**Scenario:** HIPAA compliance verification for hospital network

```bash
# HIPAA compliance audit
bannergrapv2 healthcare-network.txt \
  -compliance hipaa \
  -vuln-scan \
  -ssl-check \
  -encryption-check \
  -threads 50 \
  -output hipaa-compliance-$(date +%Y%m%d).html
```

**Findings:**
- ePHI transmission encryption validated
- Access control mechanisms verified
- Audit logging confirmed operational
- 3 systems requiring SSL/TLS updates identified

### Example 3: SaaS Platform Security Audit

**Scenario:** Annual security audit for cloud-based SaaS application

```bash
#!/bin/bash
# saas-security-audit.sh

# External API endpoints
ENDPOINTS="api-endpoints.txt"

# Scan all public endpoints
bannergrapv2 $ENDPOINTS \
  -vuln-scan \
  -http-headers \
  -ssl-check \
  -api-security \
  -output saas-security-audit.html

# Check for common API vulnerabilities
bannergrapv2 $ENDPOINTS \
  -check-owasp-api-top10 \
  -output owasp-api-findings.json
```

**Results:**
- 25 API endpoints assessed
- Security headers implemented
- Rate limiting verified
- Authentication mechanisms validated
- 2 minor configuration issues resolved

### Example 4: University Network Audit

**Scenario:** Annual security assessment for university campus network

```bash
# University network audit
bannergrapv2 10.0.0.0/8 \
  -exclude-ranges excluded-labs.txt \
  -vuln-scan \
  -ssl-check \
  -threads 200 \
  -output university-audit-$(date +%Y).html
```

**Scope:**
- 15,000+ networked devices
- Multiple VLANs and subnets
- Student, faculty, and administrative systems

**Findings:**
- 500+ outdated systems identified
- 50 critical vulnerabilities requiring immediate patching
- 200 systems with weak SSL/TLS configurations
- Comprehensive remediation plan developed

---

## Integration with Audit Management Systems

### Jira Integration

Export findings directly to Jira tickets:

```bash
bannergrapv2 audit-results.json \
  -export-jira \
  -jira-project "SECURITY" \
  -jira-url "https://company.atlassian.net"
```

### ServiceNow Integration

Create incidents for critical findings:

```bash
bannergrapv2 audit-results.json \
  -export-servicenow \
  -severity critical,high \
  -snow-instance "company.service-now.com"
```

### Splunk Integration

Send audit logs to Splunk SIEM:

```bash
bannergrapv2  scope.txt \
  -vuln-scan \
  -splunk-hec \
  -splunk-token "YOUR-HEC-TOKEN" \
  -splunk-index "security_audits"
```

---

## Conclusion

BannerGrapV2 provides security auditors with a comprehensive, efficient, and professional toolset for conducting security assessments across diverse environments. By following the workflows and best practices outlined in this guide, auditors can:

✅ Conduct thorough, repeatable security audits  
✅ Generate professional, compliance-ready reports  
✅ Identify and track vulnerabilities effectively  
✅ Validate compliance with industry standards  
✅ Maintain comprehensive audit documentation  

---

## Additional Resources

- [CLI Reference](cli-reference.md) - Complete command-line documentation
- [Configuration Guide](configuration.md) - Advanced configuration options
- [Output Formats](output-formats.md) - Report format specifications
- [CI/CD Integration](cicd.md) - Automated security testing

---

## Support

- **Documentation:** https://github.com/MrEchoFi/BannerGrapV2/docs
- **Issues:** https://github.com/MrEchoFi/BannerGrapV2/issues
- **Email:** tanjibisham777@gmail.com

---

