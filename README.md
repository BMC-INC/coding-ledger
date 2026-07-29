# Coding Ledger

**Know what your AI actually returns.**

By ExecLayer Inc. Source-available under the [Elastic License 2.0](LICENSE):
free to use and modify, not OSI open source.

Coding Ledger reads the receipts already on your machine — Git history, Claude
Code and Codex session logs, editor activity, macOS Screen Time — and turns
them into an evidence-backed answer to three questions no other tool answers
together:

1. **How much did your AI work cost?** Token usage from local agent logs,
   priced at API list rates ("API-equivalent value" — what it would have cost,
   not what you paid on a subscription).
2. **What did it return?** Spend tied to shipped commits and merged PRs:
   cost per shipped commit, conversion rate per tool, unconverted spend,
   monthly trends, and your subscription ROI multiple.
3. **How do you actually work?** Human-versus-AI attribution, total involved
   time verified against Screen Time, streaks, badges, and a shareable
   builder field report.

Everything runs locally. No prompts, source code, secrets, or tool output are
ever stored. It is a single Python 3.10+ standard-library application with
zero dependencies; the generated dashboard is self-contained and works
offline.

## Quick start

```bash
pipx install coding-ledger        # or: uvx coding-ledger
# or: brew tap BMC-INC/coding-ledger && brew install coding-ledger
# from a clone, python3 coding_ledger.py works identically

coding-ledger init --author "Your Name,you@example.com"
coding-ledger scan --roots "$HOME/Projects"
coding-ledger roi                 # AI spend tied to shipped outcomes
coding-ledger today               # today and this week at a glance
coding-ledger dashboard --open
```

## AI ROI

The `roi` command and the dashboard's AI ROI section tie token spend to
shipped outcomes:

- Token usage is read from local Claude Code and Codex logs (Grok when its
  logs carry usage). Sources without usage fields (Gemini, Cursor, Aider,
  VS Code, Antigravity) are shown as coverage gaps, never inferred.
- Dollar figures are **API-equivalent value at list prices**. The embedded
  pricing table is overridable at `~/.coding-ledger/pricing.json`
  (`{"model-pattern": {"input": .., "output": .., "cache_read": ..,
  "cache_write": ..}}` in USD per million tokens). Unknown models are
  labeled unpriced, never guessed.
- `roi --set-subscription 200` stores your monthly subscription price and
  unlocks the headline multiple: monthly API-equivalent value ÷ price.
- `scan --gh-prs` also records merged authored PRs via `gh` (repo, number,
  timestamps only) as zero-hour outcome evidence.
- Backfill after upgrading:
  `scan --sources claude,codex --reprocess-sessions`.

## Free versus Pro

Free: all scanning, the SQLite ledger, status, `roi`, `today`, full
JSON/markdown reports, headline dashboard ROI totals, and the existing public
scorecard exports.

Pro (offline license, no phone-home): the dashboard ROI deep-dive (per-tool
conversion, per-model and per-project breakdowns, monthly trend chart,
unconverted-spend view) and the 1200×1350 AI ROI share card export.

Buy Pro:

- [$49 per year](https://buy.stripe.com/4gMeVd3PA3Oc3Ut0eQ6c000)
- [$99 early lifetime](https://buy.stripe.com/7sY7sLeue70o9eNe5G6c001)

Your license key is emailed after purchase. Then:

```bash
coding-ledger license install <file-or-string>
coding-ledger license status
```

The license is an Ed25519-signed blob verified against a key embedded in the
script. Gating is honor-based and rendering-only.

## Sources

| Source | Receipt | Hours |
|---|---|---:|
| Git | Author-filtered commits, SHA, timestamp, numstat, co-author trailers | Daily density proxy |
| Claude Code | `~/.claude/projects/**/*.jsonl` metadata | Sessionized active time |
| Codex | `~/.codex/sessions/**/*.jsonl` metadata | Sessionized and attributed time |
| Gemini | `~/.gemini/tmp/*/chats/session-*.json[l]` metadata | Sessionized and attributed time |
| Antigravity | Local edit history plus opaque trajectory counts | Capped edit proxy |
| Grok Build | `$GROK_HOME/sessions/**/events.jsonl` metadata | Sessionized and attributed time |
| Cursor | Agent transcripts, chat timestamps, local history | Sessionized active time |
| Aider | `.aider.chat.history.md` timestamps | Sessionized active time |
| VS Code | Local History edit timestamps | Capped edit proxy |
| GitHub | Contributor-week commits and LOC for remote-only repositories | Zero hours |
| Screen Time | macOS per-app foreground intervals (bundle ids and durations only) | Envelope, never additive |

Git commits are deduplicated by SHA. Growing agent sessions are replaced by stable,
path-based event IDs, making rescans idempotent.

Do not include iCloud-backed Desktop repositories in scan roots. Explicit roots are
enforced even when the database contains older cached Desktop paths.

## Lightweight GitHub history

Working trees are unnecessary for exact Git history. Create or update no-checkout
repositories on non-iCloud storage:

```bash
python3 coding_ledger.py sync-github \
  --owners "BMC-INC" \
  --destination "/Volumes/MacBook Extended Storage/Coding-Ledger-GitHub"
```

These repositories contain Git objects and refs but omit working-tree build artifacts
such as `node_modules` and Rust `target`. Add the destination to `--roots`; the normal
Git scanner then records exact commit SHAs and numstat.

The GitHub aggregate source remains a fallback for repositories not represented by
a local or no-checkout repository:

```bash
python3 coding_ledger.py scan \
  --sources github \
  --gh-owners "BMC-INC" \
  --gh-login "YOUR_GITHUB_LOGIN"
```

GitHub aggregates receive zero hours and are skipped for projects already represented
by exact local Git receipts.

## Hours and attribution

Coding Ledger reports two totals:

- **Raw source sum** preserves every source's independent hours.
- **Attributed total** discounts only timestamp-qualified shared agent activity
  against human Git/editor proxies. Independently running AI time remains additive.

The attributed total has two scorecard categories:

- **Your Coding:** measured human-only base hours plus your proportional share of
  shared work.
- **AI Coding:** measured AI-only base hours plus AI's proportional share of shared
  work.

Shared work is agent activity within ten minutes of an explicit human steering turn.
It is split using the ratio of human-only to AI-only base hours. For example, if the
base evidence is 100 human hours and 50 AI hours, two-thirds of shared hours go to
Your Coding and one-third goes to AI Coding. Explicit Git `Co-authored-by` trailers
remain supporting evidence for badges, not a third scorecard category.

For each day, credited time is:

```text
max(human Git/editor evidence, timestamp-qualified shared AI time)
+ independent AI time
```

Agent sources without sufficient steering metadata default their full duration to
shared work. This preserves a conservative fallback without treating all AI work on
the same calendar day as concurrent.

These are evidence-based estimates, not claims about who typed each line. The JSON
report exposes the raw totals, attributed totals, source breakdown, and underlying
badge metrics.

Current time heuristics:

- Agent sources: timestamps split at 30-minute idle gaps with a one-minute floor.
- Git: `0.35h + 0.10h × commits` per active day, capped at six hours.
- VS Code: two minutes per history edit, capped at 90 minutes per day.
- GitHub: commits and LOC only; zero hours.
- Screen Time: measured foreground intervals, capped at 18 hours per day.

## Total involved time (screen-verified)

Receipts alone miss the reading, reviewing, and debugging time that never
produces a commit or an agent session. The `screen` source reads macOS Screen
Time foreground intervals for an allowlist of coding apps (terminals, editors,
IDEs, agent desktop apps; browsers excluded by default) and persists them into
the ledger before Apple's roughly four-week retention prunes them. Override the
allowlist at `~/.coding-ledger/screen_apps.json` with `include`/`exclude`
fnmatch pattern lists; edits re-filter all persisted history.

Screen time overlaps git, editor, and steering evidence, so it is an envelope,
never an additive source. The explicit per-day formula:

```text
screen_hours   = allowlisted foreground seconds / 3600 (18h/day cap)
uncaptured     = max(0, screen_hours - max(human_evidence, shared_ai))
total_involved = max(human_evidence, shared_ai, screen_hours) + independent_ai
               = attributed_total + uncaptured
```

`uncaptured` is coding-app time with no receipt. It credits to Your Coding,
never to AI Coding, and is always reported as its own labeled line. The raw
source sum and the attributed total are unchanged; total involved time is a
third explicit total. A day needs at least 15 minutes of coding-app screen
time to count as an active day on its own. If the store is unreadable (Full
Disk Access not granted to the scanning context), the scan records a warning
and totals fall back to attributed-only; the gap is labeled, never inferred.

## Workflow analytics

Coding Ledger exposes reproducible analytics instead of an opaque productivity score:

- AI leverage as a share of attributed coding time
- project focus and neutral portfolio-diversity measurement
- multi-project versus single-project commit and active-hour comparisons
- alternating building/off-day runs, all-time totals, and longest break
- verification calls per AI session
- parallel-agent dispatches
- session-to-commit conversion within a visible seven-day window
- median session-to-commit lag for project-matchable receipts

Activity is measured. Performance is evidenced through outcomes such as commits,
tests, and sustained delivery. The tool does not claim that hours alone establish
quality or business impact. Project diversity is not scored as inherently good or
bad; the accompanying cohort comparison shows whether broader workdays coincide
with stronger or weaker momentum for that builder. Cohorts are assigned from
session and editor receipts, while commits are measured separately as the outcome.

## Builder profile and badges

The dashboard is an offline builder field report with five reproducible dimensions:

- Steering
- Planning
- Engineering
- Execution
- Autonomy

The highest dimension selects an archetype such as The Architect, The Director,
The Quality Guardian, The Shipping Engine, or The Agent Orchestrator.

Badges have visible Bronze, Silver, Gold, and Platinum thresholds:

- Commit Cadence
- Quality Loop
- Steering Hand
- Toolsmith
- Parallel Commander
- Night Shift
- AI Pairing

Every badge shows its measured value and next threshold. No model-generated personality
judgment is stored or required.

## Privacy

For agent sessions, Coding Ledger reads only:

- timestamps and record types
- session identifier and working directory
- role counts
- tool-call counts
- locally derived test, planning, and parallel-agent counts

It does **not** store:

- prompts or assistant responses
- reasoning text
- tool arguments or output
- source code
- environment variables, credentials, or API keys

The database stores minimal provenance: source path, project identifier, day buckets,
active seconds, attribution seconds, and aggregate counts.

For Screen Time, Coding Ledger reads only app bundle identifiers and interval
durations. It never reads window titles, document names, or URLs.

## Public exports

Generate a public-safe scorecard, one-page PDF, and LinkedIn image locally:

```bash
python3 coding_ledger.py export --name "Your Name"
```

Exports are written to `~/.coding-ledger/share/` by default. The PDF contains
selectable text and the social image is 1200×1350 pixels. Both omit prompts,
responses, source code, secrets, tool output, project names, and repository names.
They report only aggregate evidence, including the number of repositories with
matched commits. Chrome, Chromium, or Edge is required for rendering.

## Scan durability

A scan row is written before processing starts. It is updated after every source and
ends as `running`, `complete`, or `interrupted`.

`status` explicitly labels the ledger provisional when no completed scan exists.
Per-repository and per-session commits preserve already imported events after an
interruption. Git timeouts are recorded with exact repository paths.

Use `scan --sources claude,codex,gemini,grok --reprocess-sessions` after changing attribution
rules; it invalidates only the selected source caches and upserts the same stable events.

## License and direction

Coding Ledger is source-available, not open source. The code is licensed under
the [Elastic License 2.0](LICENSE), copyright ExecLayer Inc.: use it, read it,
and modify it freely; you may not offer it as a hosted service, circumvent or
remove the Pro license gating, or strip the licensing notices.

The scanner, SQLite ledger, reports, analytics, and generated local site are free
and unlocked; the Pro license gates only the dashboard ROI deep-dive and the ROI share
card (see Free versus Pro above). The product thesis is the individual builder's
work record in the AI era: prove how you build, and what your AI returns, without
exposing what you build. Hosted verification and team features are intentionally
deferred until real usage establishes which workflows users value.

## Commands

```text
init              Initialize metadata and author identities
scan              Scan selected sources and explicit roots (--gh-prs for PRs)
status            Show terminal totals, attribution, spend, and scan state
roi               AI spend tied to shipped outcomes (--set-subscription USD)
today             Today and this week at a glance
report            Produce Markdown or JSON
dashboard         Generate the offline landing page and HTML field report
export            Generate public-safe HTML, PDF, LinkedIn image, ROI card
license           Install or inspect the Pro license
doctor            Show discoverable sources, including Codex
sync-github       Maintain lightweight no-checkout GitHub history
install-daemon    Install the macOS daily scan
uninstall-daemon  Remove the daily scan
```

Run tests with:

```bash
python3 -m unittest discover -s tests -v
```
