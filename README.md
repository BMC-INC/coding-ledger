# Coding Ledger

Coding Ledger is a local-first, evidence-backed record of coding work. It combines
Git history, coding-agent sessions, editor receipts, and optional GitHub statistics
without storing prompt bodies, source code, secrets, or tool output in its database.

It is a single Python 3.10+ standard-library application. The generated dashboard is
self-contained and works offline.

## Sources

| Source | Receipt | Hours |
|---|---|---:|
| Git | Author-filtered commits, SHA, timestamp, numstat, co-author trailers | Daily density proxy |
| Claude Code | `~/.claude/projects/**/*.jsonl` metadata | Sessionized active time |
| Codex | `~/.codex/sessions/**/*.jsonl` metadata | Sessionized and attributed time |
| Cursor | Agent transcripts, chat timestamps, local history | Sessionized active time |
| Aider | `.aider.chat.history.md` timestamps | Sessionized active time |
| VS Code | Local History edit timestamps | Capped edit proxy |
| GitHub | Contributor-week commits and LOC for remote-only repositories | Zero hours |

Git commits are deduplicated by SHA. Growing agent sessions are replaced by stable,
path-based event IDs, making rescans idempotent.

## Quick start

```bash
python3 coding_ledger.py init \
  --author "James Benton,kjscusoms831@gmail.com,jamesbenton@ymail.com"

python3 coding_ledger.py scan \
  --roots "$HOME/Projects,$HOME/dev,$HOME/Documents/Codex,/Volumes/MacBook Extended Storage/Coding-Ledger-GitHub"

python3 coding_ledger.py status
python3 coding_ledger.py report --format markdown
python3 coding_ledger.py dashboard --open
```

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
- **Attributed total** conservatively discounts overlap between agent sessions and
  human Git/editor proxies.

The attributed total is divided into:

- **Own:** Git and VS Code activity outside measured agent overlap.
- **Co-authored:** agent activity within ten minutes of an explicit human steering
  turn. Explicit Git `Co-authored-by` trailers are retained as supporting evidence.
- **AI-only:** assistant and tool activity outside the steering window, or automated
  sessions with no human turn.

These are evidence-based estimates, not claims about who typed each line. The JSON
report exposes the raw totals, attributed totals, source breakdown, and underlying
badge metrics.

Current time heuristics:

- Agent sources: timestamps split at 30-minute idle gaps with a one-minute floor.
- Git: `0.35h + 0.10h × commits` per active day, capped at six hours.
- VS Code: two minutes per history edit, capped at 90 minutes per day.
- GitHub: commits and LOC only; zero hours.

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

## Scan durability

A scan row is written before processing starts. It is updated after every source and
ends as `running`, `complete`, or `interrupted`.

`status` explicitly labels the ledger provisional when no completed scan exists.
Per-repository and per-session commits preserve already imported events after an
interruption. Git timeouts are recorded with exact repository paths.

Use `scan --sources claude,codex --reprocess-sessions` after changing attribution
rules; it invalidates only the selected source caches and upserts the same stable events.

## Commands

```text
init              Initialize metadata and author identities
scan              Scan selected sources and explicit roots
status            Show terminal totals, attribution, and scan state
report            Produce Markdown or JSON
dashboard         Generate the offline HTML field report
doctor            Show discoverable sources, including Codex
sync-github       Maintain lightweight no-checkout GitHub history
install-daemon    Install the macOS daily scan
uninstall-daemon  Remove the daily scan
```

Run tests with:

```bash
python3 -m unittest discover -s tests -v
```
