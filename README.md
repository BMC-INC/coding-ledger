# Coding Ledger

**Understand the cost and outcomes of AI-assisted development from the records already on your machine.**

Coding Ledger connects Git history with local coding-assistant activity to produce
an offline dashboard of token usage, API-equivalent cost, time estimates, and
session-to-commit outcomes. It is built for individual developers and independent
builders who want a work record without uploading prompts or source code.

[Getting started](#getting-started) · [Reference](docs/reference.md) · [Releases](https://github.com/BMC-INC/coding-ledger/releases) · [Report an issue](https://github.com/BMC-INC/coding-ledger/issues)

## What you can do

- Compare AI usage with commits and, optionally, merged GitHub pull requests.
- Review daily activity, project trends, attribution, and gaps in source coverage.
- Keep a local SQLite ledger with repeatable, resumable scans.
- Generate a self-contained HTML dashboard and shareable aggregate reports.
- Add macOS Screen Time evidence to account for work that produces no commit.

The scanner uses Python 3.10+ and the standard library. Chart.js is bundled with
the application for offline dashboards; no browser CDN is needed by the current
source build. PDF and image export requires Chrome, Chromium, or Edge.

## Project status

The CLI, scanner, dashboard, reports, and offline license verification are
implemented. Automated tests cover source parsing, privacy exclusions, deduplication,
attribution, pricing, and reporting. macOS is the primary environment; Screen Time
and the scheduled scan are macOS-specific. Hosted accounts and team administration
are outside the current product.

The latest published release is **v1.0.0**. The main branch includes subsequent
source-import and packaging improvements. Use the source installation below to
get those improvements; PyPI and Homebrew installations follow the published release.

This project is **source-available under Elastic License 2.0**, not OSI open source.
The scanner and reports are free; selected dashboard views and the ROI share card
require an offline Pro license. See [Free versus Pro](docs/reference.md#free-versus-pro)
and the [license](LICENSE).

## Getting started

Requirements: Python 3.10+, Git, and local repositories or supported assistant logs.
Start with an explicit project folder so the scan covers the work you intend to measure.

```bash
git clone https://github.com/BMC-INC/coding-ledger.git
cd coding-ledger
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

coding-ledger init --author "Your Name,you@example.com"
coding-ledger scan --roots "$HOME/Projects" --sources git,claude,codex
coding-ledger roi
coding-ledger today
coding-ledger dashboard --open
```

To use the release instead, install with `pipx install coding-ledger`,
`uv tool install coding-ledger`, or follow the
[Homebrew tap](https://github.com/BMC-INC/homebrew-coding-ledger).
The published v1.0.0 Python wheel does not bundle the dashboard chart asset;
source installation above includes the offline packaging fix.

Run `coding-ledger doctor` to see which sources are discoverable.
Use `coding-ledger --help` or `coding-ledger scan --help` for options.
Data is stored in `~/.coding-ledger/`; set `CODING_LEDGER_DIR` to choose another location.

## Supported evidence

| Source | What it contributes |
| --- | --- |
| Git | Author-filtered commits, changed-line counts, and commit timestamps |
| Claude Code and Codex | Local session metadata and token usage when present |
| Gemini, Grok Build, Cursor, Aider, VS Code, Antigravity | Available session or editor metadata; coverage varies by source |
| GitHub (optional) | Merged PRs and aggregate history through your authenticated `gh` CLI |
| macOS Screen Time (optional) | Allowlisted coding-app foreground intervals |

Rescans deduplicate commit and session evidence. Interrupted scans retain imported
records and display their incomplete state. The
[reference](docs/reference.md#sources) describes source paths and attribution rules.

## How to read the numbers

**API-equivalent cost is an estimate, not your invoice.** Token counts are priced
with the configured per-model rates. Unknown models remain unpriced; sources
without usage fields remain coverage gaps. Update `~/.coding-ledger/pricing.json`
when rates or models change.

**Time and outcome attribution are heuristics.** Session timestamps, commit-density
proxies, and editor activity cannot prove who typed each line or whether work was
valuable. Session-to-commit matching uses a visible seven-day window. A subscription
multiple compares API-equivalent value with the price you enter; it is not measured
profit or business ROI.

## Privacy and network use

Scanning and reporting run locally. The ledger stores timestamps, source paths,
project identifiers, and aggregate counts. It does not persist prompt or response
text, source code, tool arguments, tool output, or credentials. Treat the database
and detailed dashboard as private because they identify projects and local paths.

Optional GitHub commands contact GitHub through `gh`. Installing packages and
opening purchase links also requires a network connection. Local dashboard viewing
and offline license verification do not require a service account or telemetry.
The [public export command](docs/reference.md#public-exports) omits project and
repository names; review any artifact before sharing it.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m pip wheel . --no-deps --wheel-dir dist
```

CI runs the tests on Python 3.10 and 3.14 and checks that an installed wheel contains
the offline chart asset. For a contribution, include the problem, a reproducible
example using synthetic data, and the checks you ran. Do not attach real assistant
logs or your personal ledger to public issues.

Built by [ExecLayer / BMC-INC](https://github.com/BMC-INC).
