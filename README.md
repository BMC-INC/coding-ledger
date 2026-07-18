# coding-ledger

**Local forensic scanner for your entire coding history. Zero dependencies.**

One Python file, stdlib only (3.10+). No pip installs, no SaaS, no 30-day API
windows. It walks the filesystem, materializes every receipt into a permanent
SQLite ledger, and renders a fully offline HTML dashboard.

| Source | What it pulls | Path / method |
|--------|---------------|---------------|
| **Git** | Every commit: LOC + timestamps, author-filtered, deduped by SHA across clones/worktrees | `git log --all --numstat` across local repos under `~/Projects`, `~/Desktop`, `~/dev` |
| **Claude Code** | Sessions: wall time (idle-gap sessionized), messages, tool calls | `~/.claude/projects/**/*.jsonl` |
| **Cursor** | Agent transcripts, chat store.db, local history | `~/.cursor/projects/*/agent-transcripts/*.jsonl`, `~/.cursor/chats/**/store.db`, `~/Library/Application Support/Cursor/User/History` |
| **Aider** | Chat history timestamps | `**/.aider.chat.history.md` |
| **VS Code Local History** | File edit entries (activity proxy, capped) | `~/Library/Application Support/Code/User/History` |
| **GitHub** | Weekly LOC + commits for repos NOT cloned locally (via `gh`) | `repos/{owner}/{repo}/stats/contributors` |

Everything lands in `~/.coding-ledger/ledger.db`. Raw events are kept forever;
hours are recomputed from raw data on every report, so you can retune the
heuristics anytime without rescanning.

Perfect for:

- Proving **10,000 hours** (journeyman badge)
- AI-vs-human attribution
- Sovereign, offline stats no SaaS can revoke

Built for the ExecLayer / SovereignClaw mindset: *receipts over assurances*.

## Quick start

```bash
python3 coding_ledger.py init --author "Your Name,you@email.com"

# full multi-source backfill (idempotent — rerun anytime)
python3 coding_ledger.py scan

# or selective
python3 coding_ledger.py scan --sources git,claude
python3 coding_ledger.py scan --sources github --gh-owners you,YourOrg

python3 coding_ledger.py status
python3 coding_ledger.py report --format markdown
python3 coding_ledger.py report --format json
python3 coding_ledger.py dashboard --open
python3 coding_ledger.py doctor            # which sources exist on this box
```

Default DB: `~/.coding-ledger/ledger.db` (`--db` or `$CODING_LEDGER_DB` to
override). Default dashboard: `~/.coding-ledger/dashboard.html`.

## Dashboard

Self-contained dark HTML. Chart.js is **vendored and inlined** (see
`vendor/`), so the dashboard works fully offline with no CDN calls (falls back
to an SRI-pinned CDN tag only if the vendored file is missing).

- Progress to 10k hours + remaining
- Stacked daily hours by source (last 180 days) + all-time monthly
- Doughnut source breakdown
- Cumulative hours curve toward 10k
- Daily LOC added (log scale)
- Top projects table (hours, +LOC, -LOC)

## Hours heuristics (yours to tune, constants at top of file)

- **Claude / Cursor / Aider**: real wall-clock from timestamps, sessionized at
  30-minute idle gaps, split across midnights per local day
- **Git**: density credit per active day: `0.35h + 0.10h x commits`, capped at
  6h/day, distributed to projects by commit share
- **VS Code Local History**: 2 min per edit, capped at 90 min/day
- **GitHub**: LOC/commits only, **zero hours** (no double counting), and repos
  already scanned locally are skipped entirely

All raw data is retained forever; recompute anytime.

## Scan design

- **Idempotent**: every event has a dedup `uid` (`git:<sha>`,
  `claude:<session-path>`, ...). Rescans only add what's new.
- **Incremental**: unchanged files (mtime+size cache) are skipped; growing
  session files are re-parsed and upserted.
- **Clone-proof**: commits dedup by SHA, so clones, worktrees, and
  `-main-merge` copies never double count.
- **Hang-proof**: per-repo `git log` gets a 60s timeout (iCloud dataless
  placeholder folders on `~/Desktop` love to hang git — those repos get
  skipped with a note instead of stalling the scan).

## Background daemon (macOS)

```bash
python3 coding_ledger.py install-daemon --hour 21   # daily scan at 21:00
python3 coding_ledger.py uninstall-daemon
```

Caveat: launchd calendar jobs don't fire while the Mac sleeps.

## Why this works for full history

Git, Claude Code, Cursor, Aider, and VS Code Local History all leave permanent
local receipts. The GitHub source backfills repos that only exist remotely.
Your scanner just walks the filesystem and materializes the truth into one
queryable SQLite file.

## Future

- Deeper Cursor `state.vscdb` / `bubbleId` token extraction
- Wakatime / other importers
- Rust port for single-binary ultra-light daemon

## License

MIT. Your data never leaves the box.

---

*Built for King / ExecLayer — the only hours that count are the ones you can prove yourself.*
