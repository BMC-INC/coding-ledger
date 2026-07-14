# coding-ledger

**Local forensic scanner for your entire coding history.**

Tracks every line and every hour from:

| Source | What it pulls | Path / method |
|--------|---------------|---------------|
| **Git** | Full career LOC + timestamps | `git log --numstat --author=…` across local repos |
| **Claude Code** | Sessions, wall time, tool/write calls | `~/.claude/projects/**/*.jsonl` |
| **Cursor** | Agent transcripts, store.db, ai-tracking | `~/.cursor/projects/*/agent-transcripts/*.jsonl`, `~/Library/Application Support/Cursor/…`, `~/.cursor/chats/**/store.db` |
| **Aider** | Chat history files | `**/.aider.chat.history.md` |
| **VS Code / Cursor Local History** | File edit entries (activity proxy) | `~/Library/Application Support/Code/User/History/` (and Cursor equivalent) |
| **Antigravity / Artifacts** | TaskLists, Plans, Walkthroughs, diffs | User-supplied paths or keyword scan |

Everything lands in a permanent **SQLite receipt ledger** (`~/.coding-ledger/ledger.db`).

Perfect for:

- Proving **10 000 hours** (journeyman badge)
- AI-vs-human attribution
- Sovereign, offline stats no SaaS can revoke

Built for the Execlayer / SovereignClaw mindset: *receipts over assurances*.

## Quick start

```bash
# deps (usually already present)
python3 -m pip install --user click rich

python3 coding_ledger.py init

# full multi-source backfill
python3 coding_ledger.py scan --author "Your Name,you@email.com"

# or selective
python3 coding_ledger.py scan --sources git,claude,cursor,aider

python3 coding_ledger.py status
python3 coding_ledger.py report --format markdown
python3 coding_ledger.py dashboard --open     # pretty HTML with charts
```

Default DB: `~/.coding-ledger/ledger.db`  
Default dashboard: `~/.coding-ledger/dashboard.html`

## Dashboard

Self-contained dark HTML (Chart.js via CDN):

- Progress to 10k hours + remaining
- Stacked daily hours by source (Claude / Cursor / Aider / Git density)
- Doughnut source breakdown
- Daily LOC added line chart
- First/last activity, net LOC, session counts

Open with `--open` or just double-click the file. No server, no data leaves the machine.

## Hours heuristic (yours to tune)

- Claude + Cursor + Aider: real wall-clock session durations from timestamps
- Git: density credit (0.35 h base + 0.10 h × commits that day)
- VS Code Local History: light activity signal (capped)
- Artifacts: small fixed credit

All raw data is retained forever; recompute anytime.

## Why this works for full history

Git, Claude Code, Cursor agent-transcripts, Aider history files, and VS Code Local History all leave permanent local receipts. No 30-day API windows. Your scanner just walks the filesystem and materializes the truth into one queryable SQLite file.

## Future

- Background daemon / launchd agent
- Deeper Cursor `state.vscdb` / `bubbleId` token extraction
- Wakatime / other importers
- Rust port for single-binary ultra-light daemon

## License

MIT. Your data never leaves the box.

---

*Built for King / Execlayer — the only hours that count are the ones you can prove yourself.*
