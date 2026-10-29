# SiteGuard Community

[![Tests](https://github.com/ma45zf/siteguard-community/actions/workflows/tests.yml/badge.svg)](https://github.com/ma45zf/siteguard-community/actions/workflows/tests.yml)

An early-stage, free, offline static security checker for **local Python projects**. SiteGuard Community is built for learning and defensive code review. It does not crawl, attack, or audit live websites.

## Features (v0.1.0)

- AST-based Python syntax analysis and checks for `eval` / `exec`, `subprocess` calls with `shell=True`, `app.run(debug=True)`, and pickle deserialization.
- Human-readable output or machine-readable JSON.
- Optional nonzero exit status for high-severity findings.
- Runs locally with Python 3.10+ and no runtime dependencies.

## Usage

Clone the repository, then from its root:

```bash
python -m siteguard /path/to/your/project
python -m siteguard /path/to/your/project --format json
python -m siteguard /path/to/your/project --fail-on-high
python -m unittest discover -s tests -v
```

Only inspect projects you own or have permission to analyze. No source files are executed or sent to a server.

## Limitations

The findings are **heuristics**, not confirmed vulnerabilities. This tool can miss issues and report false positives. It currently supports only local Python files; it is **not** a comprehensive website scanner or penetration testing tool. Files over 1 MB and symlinks are skipped.

## Open source

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), [ROADMAP.md](ROADMAP.md) and [SECURITY.md](SECURITY.md). Licensed under MIT (see LICENSE).
