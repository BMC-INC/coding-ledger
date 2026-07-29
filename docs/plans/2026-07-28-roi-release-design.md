# ROI Release Design

Date: 2026-07-28
Status: Approved, not yet implemented

## Decision

The first paid wedge is AI ROI analytics: token spend ingested from local agent
logs and tied to shipped outcomes. Monetization ships in the same release as an
offline Pro license key. The scanner, ledger, reports, and basic dashboard stay
free and open. Everything remains local-first with no phone-home and no hosted
component in this release.

Positioning: "Know what your AI actually returns."

## Free versus Pro boundary

Free:

- all scanning, the SQLite ledger, status, reports (including the full `roi`
  JSON/markdown block), basic dashboard with headline ROI totals
- existing public scorecard exports (HTML, PDF, LinkedIn image)
- `today` daily pulse command

Pro (offline license):

- dashboard ROI deep-dive: per-tool, per-project, per-model breakdowns, trends,
  unconverted-spend view
- model comparison views
- ROI share card export (1200x1350, same rendering pipeline as the existing
  social image)

## Workstream 1: token spend ingestion

- Claude Code: sum per-message `message.usage` fields (`input_tokens`,
  `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`)
  per session with a per-model breakdown from `message.model`. Verified present
  in local logs on 2026-07-28. No `costUSD` field exists in current logs.
- Codex: `event_msg` payloads of type `token_count` carry cumulative
  `total_token_usage` (`input_tokens`, `cached_input_tokens`,
  `cache_write_input_tokens`, `output_tokens`, `reasoning_output_tokens`,
  `total_tokens`). The last event in a session is the session total. Verified
  present in local logs on 2026-07-28.
- Grok: ingest usage fields if present in `events.jsonl`, otherwise labeled
  unavailable.
- Gemini, Antigravity, Cursor, Aider, VS Code: spend-unavailable. Shown as
  coverage gaps, never inferred.
- Token aggregates are stored in session event meta. No prompts, responses,
  tool arguments, or output are stored, consistent with the existing privacy
  boundary.
- Pricing: embedded static model pricing table (USD per Mtok for input, output,
  cache read, cache write) with a user override at
  `~/.coding-ledger/pricing.json`. Every dollar figure is labeled
  "API-equivalent value."
- Optional user config for subscription price enables the headline stat:
  subscription ROI multiple (API-equivalent value divided by monthly price).
- Backfill uses the existing `scan --reprocess-sessions` path and stays
  idempotent.

## Workstream 2: outcome linking

- Extend the existing session-to-commit matcher to produce: cost per shipped
  commit by tool, by project, and by month; conversion rate per tool;
  unconverted spend (sessions with no matched commit inside the visible
  window); trends over time.
- Optional `--gh-prs` scan flag: merged PRs and time-to-merge for authored PRs
  via `gh`. Zero hours, outcome evidence only.

## Workstream 3: surfaces

- `roi` subcommand: terminal table per tool, project, and month.
- `today` subcommand: today plus this week's pulse (your hours, AI hours,
  spend, commits, streak) reading only the DB for a fast path.
- Dashboard: new AI ROI section. Headline totals free, deep-dive Pro.
- Report: full `roi` block in JSON and markdown, free, to preserve open-data
  credibility.

## Workstream 4: Pro license mechanics

- License is a signed JSON blob (email, issue date, plan, optional expiry)
  verified with Ed25519. The public key is embedded in the script. A small
  pure-Python verify-only implementation is vendored to keep the
  zero-dependency guarantee.
- New subcommands: `license install <file-or-string>`, `license status`.
- Gating is honor-based and rendering-only. No network calls.
- `tools/sign_license.py` issues licenses. The private key never enters the
  repo.
- Sales via a Stripe or Gumroad payment link. Opening price suggestion: $49
  per year or $99 early lifetime. Pricing is not load-bearing for the build.

## Workstream 5: funnel and packaging

- `pyproject.toml` with a `coding-ledger` console script so `uvx coding-ledger`
  and `pipx install` work. `python3 coding_ledger.py` keeps working.
- Homebrew tap formula in BMC-INC as the final packaging step.
- README repositioned around ROI with the new quickstart.

## Workstream 6: tests and verification

- Fixture tests: Claude usage summation, Codex cumulative-total handling,
  pricing math, day allocation of spend, `roi` report block, license verify
  (valid, tampered, expired), `today` output.
- Idempotent-rescan test extended to cover token backfill.
- Existing CI (unittest via GitHub Actions) runs the suite.
- Release requires: full test suite green, dashboard generation clean, browser
  console check, clean tracked worktree, matching local and remote commits,
  passing CI, tagged release.

## Sequencing (work-units, in order)

1. Token ingestion (Claude, Codex) plus pricing table plus backfill.
2. ROI computation, `roi` and `today` commands, report block.
3. Dashboard ROI section, license verify, `license` subcommands, sign tool.
4. ROI share card export (Pro).
5. `--gh-prs` outcome scan.
6. Packaging, README repositioning, brew tap, tagged release.

## Out of scope this release

- Hosted tier, accounts, verified live profiles
- Team analytics
- Menu-bar app
- Gemini token ingestion (until usage fields are confirmed in local files)
