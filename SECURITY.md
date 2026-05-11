# Security Policy

BannerGrapV2 is a dual-use security tool. It should be used only on systems you are authorized to test.

## Reporting a vulnerability

Report security issues privately whenever possible. Good reports include:

- a short description of the issue
- the affected file or feature
- the version or commit you tested
- clear reproduction steps
- any logs, crash output, or screenshots
- the security impact you observed

## What to report

Please report:

- remote crashes
- unexpected command execution
- authentication bypasses
- unsafe parsing behavior
- path traversal or file overwrite bugs
- dependency vulnerabilities that affect the project
- exposed secrets or unsafe defaults

## What not to post publicly

Avoid publishing full exploit details in a public issue before a fix is available. Keep proof-of-concept data minimal until the maintainers can review it.

## Safe handling expectations

When possible, use:

- sanitized hostnames
- test targets
- trimmed logs
- minimal reproduction steps

## Response process

A good security report should be acknowledged, reproduced, fixed, and then documented. After a fix lands, update release notes or changelogs so users know what changed.

## Scope

The security review should cover:

- the Go binary
- supporting scripts
- output serialization
- report generation
- any packaging or deployment manifests checked into the repository

## Responsible use

Do not use the tool to attack third-party systems, brute-force accounts, or probe targets without permission. That protects the project, the users, and the community around it.
