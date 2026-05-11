# Configuration

BannerGrapV2’s README includes a `config.yaml` template that describes how a structured configuration file should look. The current source tree also shows the runtime working primarily through CLI flags, so this page should be read as the canonical configuration template for the project rather than proof of a fully wired config loader.

## Recommended config shape

```yaml
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

## Section-by-section meaning

### `general`
Core runtime settings.

- `threads`: number of concurrent workers.
- `timeout`: per-target timeout in seconds.
- `retries`: retry budget for transient failures.
- `verbose`: enable more detailed terminal output.

### `scan`
Discovery and fingerprinting behavior.

- `common_ports`: scan a known list of common ports.
- `port_range`: fallback or expanded port range.
- `service_detection`: enable banner/service identification.
- `ssl_analysis`: collect TLS metadata when HTTPS is in play.

### `vulnerability`
Risk-analysis controls.

- `enabled`: turn vulnerability checks on or off.
- `cve_database`: choose a local or online data source.
- `min_severity`: ignore findings below a threshold.

### `output`
Reporting controls.

- `format`: preferred report format.
- `directory`: where reports should be written.
- `timestamp`: append time-based uniqueness to filenames.

### `brute_force`
Credential-check workflow.

- `enabled`: opt into brute-force checks.
- `username_list`: path to usernames.
- `password_list`: path to passwords.

## Example workflow

A clean operational pattern is:

1. Keep the config file in the repo root as `config.yaml`.
2. Use it as the shared baseline for repeatable scans.
3. Store environment-specific overrides in separate files, such as `config.lab.yaml` or `config.prod.yaml`.
4. Keep the output directory outside tracked source when results are sensitive.

## Good defaults

For a community-friendly release, the safest defaults are:

- moderate thread counts
- short but realistic timeouts
- JSON output for automation
- HTML or TXT output for handoff
- brute-force disabled unless you are in a controlled lab

## Example command shown in the README

```bash
go run bannerGrap.go -config config.yaml -target 192.168.1.1
```

If that wiring changes in a future release, keep this YAML as the authoritative schema and update the runtime flags to match it.
