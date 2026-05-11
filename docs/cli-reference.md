# CLI Reference

BannerGrapV2 is a Go-based network reconnaissance and banner-grabbing tool. The README documents the core command-line surface as a small set of flags for target selection, protocol choice, payload control, concurrency, timeout, and output routing. The current source also shows support for rich per-target results such as banner text, fingerprints, TLS metadata, vulnerabilities, exploit notes, enumeration output, brute-force results, and a generated report field.

## Synopsis

```bash
bannerGrap.go [target] [options]
```

A target can be provided directly as a single host, a host with a port, or through a newline-separated file.

## Target input

### Positional target
Provide a single host directly:

```bash
go run bannerGrap.go example.com
go run bannerGrap.go example.com:80
go run bannerGrap.go 192.168.1.1
```

### File input
Use `-f` to scan multiple targets from a file:

```bash
go run bannerGrap.go -f targets.txt
```

The README describes the file as containing newline-separated targets in the form `host` or `host:port`.

## Options documented in the README

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-f` | string | none | File containing newline-separated targets. |
| `-proto` | string | `http` | Protocol to use: `http`, `https`, `ftp`, `smtp`, `ssh`, `telnet`, or `custom`. |
| `-port` | string | target/default port | Override the port for every target. |
| `-payload` | string | protocol-specific | Custom payload to send. |
| `-timeout` | int | `5` | Connection and read timeout in seconds. |
| `-threads` | int | `10` | Number of simultaneous connections. |
| `-o` | string | console output | Output file path. Extension determines the format. |
| `-h` | bool | n/a | Show help. |

## What the tool does with these flags

- `-proto` controls the wire protocol and the scanner’s behavior for the target service.
- `-port` forces one port across all scanned targets.
- `-payload` lets you send a custom request or handshake string.
- `-timeout` bounds connection and read time for each scan.
- `-threads` controls concurrent work.
- `-o` switches from console output to a file.

## Output routing

According to the README:

- `.json` writes JSON output
- `.csv` writes CSV output
- `.txt` writes text output
- no `-o` keeps results in the console

## Examples

```bash
# Scan one host
go run bannerGrap.go example.com

# Scan a target list with HTTP
go run bannerGrap.go -f targets.txt -proto http

# Scan the same list with HTTPS
go run bannerGrap.go -f targets.txt -proto https

# Send a custom request
go run bannerGrap.go -f targets.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

# Write JSON output
go run bannerGrap.go -f targets.txt -o results.json

# Increase timeout and concurrency
go run bannerGrap.go -f targets.txt -timeout 10 -threads 50
```

## Notes for maintainers

The README also shows a few advanced example invocations such as `--version`, `-ports`, `-config`, and `-target`. Those are best treated as example-driven or work-in-progress surfaces unless they are implemented in the current binary you ship.
