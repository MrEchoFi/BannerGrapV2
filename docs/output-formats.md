# Output Formats

BannerGrapV2 is designed to serve both terminal users and automation pipelines. The README lists JSON, XML, HTML, and CSV as supported reporting formats, and the source shows a structured result object that carries the target, banner, fingerprint, TLS details, vulnerability notes, exploit notes, enumeration data, brute-force results, and the final rendered report.

## Formats

### Console
The default when no output file is supplied.

Best for:

- quick ad-hoc scans
- local troubleshooting
- live review during an assessment

### JSON
Best for automation, SIEM ingestion, dashboards, and downstream parsing.

Why it works well:

- preserves structured fields
- easy to feed into scripts and APIs
- good for archives and comparisons

### CSV
Best for spreadsheet work and quick sorting/filtering in data tools.

Why it works well:

- easy to open in Excel or LibreOffice
- useful for triage tables
- friendly for bulk review by non-developers

### TXT
Best for simple human-readable exports.

Why it works well:

- easy to read in any editor
- simple to diff in Git
- good for lightweight handoffs

### HTML
Best for shareable reports and presentation.

Why it works well:

- readable in a browser
- suitable for screenshots and reviews
- nice for sending results to teammates who do not want raw JSON

## Fields included in a BannerResult

The current source defines these result fields:

- `host`
- `port`
- `protocol`
- `banner`
- `error`
- `fingerprint`
- `tls_version`
- `cipher`
- `cert_issuer`
- `cert_cn`
- `vulnerabilities`
- `exploits`
- `enumeration`
- `bruteforce`
- `report`

That structure is the best guide for how each format should look.

## Practical recommendations

- Use **JSON** for automation and API integration.
- Use **CSV** for reporting to security teams and managers.
- Use **TXT** when you want a compact, readable transcript.
- Use **HTML** when you want the result to look polished in a browser.
- Use the **console** for rapid iteration.

## File naming

A simple pattern is:

```bash
results.json
results.csv
results.txt
results.html
```

For campaign work, add a target or date stamp:

```bash
acme-2026-05-11.json
external-surface-2026-05-11.csv
```

## Example commands

```bash
go run bannerGrap.go -f hosts.txt -o results.json
go run bannerGrap.go -f hosts.txt -o results.csv
go run bannerGrap.go -f hosts.txt -o results.txt
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.json
```

## Publishing tip

If the goal is to grow the project’s audience, publish a few screenshots of the HTML report and a sample JSON output block in the README or releases page. That instantly shows value to both technical users and non-technical reviewers.

# More Examples

```bash

# JSON output:
      go run bannerGrap.go -f hosts.txt -o results.json
# CSV output: 
      go run bannerGrap.go -f hosts.txt -o results.csv
# Text output: 
      go run bannerGrap.go -f hosts.txt -o results.txt
# Console output:
      go run bannerGrap.go -f hosts.txt

------------------------------------------------------------------------------------------------------------------------------

# JSON output with custom payload:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.json
# CSV output with custom payload:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.csv
# Text output with custom payload:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.txt
# Console output with custom payload:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
# JSON output with custom payload and timeout:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.json
# CSV output with custom payload and timeout:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.csv
# Text output with custom payload and timeout:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.txt

------------------------------------------------------------------------------------------------------------------------------

# Console output with custom payload and timeout:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10
# JSON output with custom payload and timeout and threads:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -o results.json
# CSV output with custom payload and timeout and threads:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -o results.csv
# Text output with custom payload and timeout and threads:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -o results.txt
# Console output with custom payload and timeout and threads:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5
# JSON output with custom payload and timeout and threads and port:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -o results.json
# CSV output with custom payload and timeout and threads and port:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -o results.csv
# Text output with custom payload and timeout and threads and port:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -o results.txt
# Console output with custom payload and timeout and threads and port:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80
# JSON output with custom payload and timeout and threads and port and protocol:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.json
# CSV output with custom payload and timeout and threads and port and protocol:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.csv
# Text output with custom payload and timeout and threads and port and protocol:
go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.txt
```
