```bash
  ░██████    ░██████   ░███    ░██ ░██████████░█████████  ░██████░████████   ░██     ░██ ░██████████░██████░███    ░██   ░██████                             ░██ 
 ░██   ░██  ░██   ░██  ░████   ░██     ░██    ░██     ░██   ░██  ░██    ░██  ░██     ░██     ░██      ░██  ░████   ░██  ░██   ░██                            ░██ 
░██        ░██     ░██ ░██░██  ░██     ░██    ░██     ░██   ░██  ░██    ░██  ░██     ░██     ░██      ░██  ░██░██  ░██ ░██            ░█████████████   ░████████ 
░██        ░██     ░██ ░██ ░██ ░██     ░██    ░█████████    ░██  ░████████   ░██     ░██     ░██      ░██  ░██ ░██ ░██ ░██  █████     ░██   ░██   ░██ ░██    ░██ 
░██        ░██     ░██ ░██  ░██░██     ░██    ░██   ░██     ░██  ░██     ░██ ░██     ░██     ░██      ░██  ░██  ░██░██ ░██     ██     ░██   ░██   ░██ ░██    ░██ 
 ░██   ░██  ░██   ░██  ░██   ░████     ░██    ░██    ░██    ░██  ░██     ░██  ░██   ░██      ░██      ░██  ░██   ░████  ░██  ░███     ░██   ░██   ░██ ░██   ░███ 
  ░██████    ░██████   ░██    ░███     ░██    ░██     ░██ ░██████░█████████    ░██████       ░██    ░██████░██    ░███   ░█████░█ ░██ ░██   ░██   ░██  ░█████░██ 
                                                                                                                                                                 
                                                                                                                                                                 
```
# Contributing to BannerGrapV2

Thanks for helping improve BannerGrapV2.

This project is a Go-based reconnaissance and banner-grabbing tool, so contributions should keep three goals in mind: accuracy, clarity, and responsible use.

## Before you start

- Use the tool only in environments you are authorized to test.
- Keep changes small and reviewable.
- Prefer clear code and clear docs over clever code.

## Ways to contribute

- Fix bugs
- Improve documentation
- Add tests
- Refine output formatting
- Improve error handling
- Add new protocol coverage or safer detection logic
- Suggest examples that make the project easier to learn

## Local setup

```bash
git clone https://github.com/MrEchoFi/BannerGrapV2.git
cd BannerGrapV2
go build ./...
```

If the repo contains runnable examples or scripts, test them in a lab environment before submitting changes.

## Pull request checklist

- Use a focused branch name
- Keep commits readable
- Update docs when behavior changes
- Add or update tests when practical
- Confirm the project still builds
- Avoid breaking existing examples unless the change is intentional

## Good documentation contributions

Documentation is a huge part of project growth. Helpful updates include:

- clearer flag descriptions
- copy-paste-safe examples
- output samples
- deployment notes
- troubleshooting steps
- safer wording for dual-use features

## Style guidance

- Keep text direct and easy to scan
- Use consistent terminology for targets, ports, and protocols
- Prefer concrete examples over vague claims
- Match the project’s existing Go and Markdown style

## Issues

Use issues for:

- bug reports
- feature ideas
- documentation gaps
- build problems
- output inconsistencies

Include:

- what you expected
- what happened instead
- the command you used
- your platform and Go version
- any logs or output that help reproduce the problem

## Community mindset

Open source grows when people can understand it quickly. Good contributions make the tool easier to trust, easier to test, and easier to share.

If you ship a useful fix, add a short note in the release notes or README so new users can discover it quickly.
