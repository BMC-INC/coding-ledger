#!/usr/bin/env python3
"""
coding-ledger — Local forensic scanner for your entire coding history.

Zero dependencies: Python 3.10+ stdlib only. No pip install, no SaaS, no
30-day API windows. Walks the filesystem (plus optional GitHub API via `gh`)
and materializes every receipt into one queryable SQLite file.

Sources:
  git      local repos: every commit (LOC + timestamps), author-filtered
  claude   Claude Code session logs (~/.claude/projects/**/*.jsonl)
  cursor   Cursor agent transcripts / chat DBs / local history
  aider    .aider.chat.history.md files
  vscode   VS Code Local History (edit-level activity proxy)
  codex    Codex sessions (~/.codex/sessions/**/*.jsonl), metadata only
  gemini   Gemini CLI sessions (~/.gemini/tmp/*/chats/session-*.json[l])
  antigravity Antigravity IDE agent and edit receipts
  grok     Grok Build sessions (~/.grok/sessions/**/events.jsonl)
  github   remote repos via `gh` (weekly LOC for repos not cloned locally)

Usage:
  python3 coding_ledger.py init
  python3 coding_ledger.py scan --author "james benton,kjscustoms831@gmail.com"
  python3 coding_ledger.py scan --sources git,claude
  python3 coding_ledger.py status
  python3 coding_ledger.py report --format markdown
  python3 coding_ledger.py dashboard --open
  python3 coding_ledger.py export
  python3 coding_ledger.py doctor
  python3 coding_ledger.py install-daemon   # daily launchd scan (macOS)

Ledger: ~/.coding-ledger/ledger.db (override: --db or $CODING_LEDGER_DB)
"""

from __future__ import annotations

import argparse
import base64
import bisect
import fnmatch
import html
import json
import os
import re
import signal
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------- constants

HOME = Path.home()
LEDGER_DIR = Path(os.environ.get("CODING_LEDGER_DIR", HOME / ".coding-ledger"))
DEFAULT_DB = Path(os.environ.get("CODING_LEDGER_DB", LEDGER_DIR / "ledger.db"))
DASHBOARD_PATH = LEDGER_DIR / "dashboard.html"
LANDING_PATH = LEDGER_DIR / "index.html"

ALL_SOURCES = [
    "git", "claude", "codex", "gemini", "antigravity", "grok",
    "cursor", "aider", "vscode", "github",
]
AGENT_SOURCES = ("claude", "codex", "gemini", "grok", "cursor", "aider")
EDITOR_SOURCES = ("vscode", "antigravity")
LOVABLE_BOT_LOGINS = ("lovable-dev[bot]",)
LOVABLE_COMMIT_AUTHOR_NAMES = ("gpt-engineer-app[bot]",)
DEFAULT_ROOTS = [HOME / "Projects", HOME / "dev", HOME / "Documents" / "Codex"]

IDLE_GAP_S = 30 * 60          # gap that splits a session
STEERING_WINDOW_S = 10 * 60   # agent work within this window is human/AI co-authored
MIN_SESSION_S = 60            # floor credit per sub-session
GIT_BASE_H = 0.35             # density credit: base hours per active git day
GIT_PER_COMMIT_H = 0.10       # + per commit that day
GIT_DAY_CAP_H = 6.0           # cap on git density credit per day
VSCODE_PER_EDIT_S = 120       # activity credit per local-history edit
VSCODE_DAY_CAP_S = 90 * 60    # cap per day
TARGET_HOURS = 10_000

GIT_TIMEOUT_S = 60            # per-repo git subprocess timeout (iCloud hangs)
SKIP_DIR_NAMES = {
    "node_modules", "target", ".build", "DerivedData", "Pods", ".venv",
    "venv", "__pycache__", ".git", "dist", "build", ".next", ".terraform",
    "Library",
}

C_RESET, C_BOLD, C_DIM = "\033[0m", "\033[1m", "\033[2m"
C_GREEN, C_YELLOW, C_CYAN, C_RED = "\033[32m", "\033[33m", "\033[36m", "\033[31m"


def say(msg: str = "") -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    print(f"{C_YELLOW}! {msg}{C_RESET}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY,
    uid      TEXT UNIQUE NOT NULL,   -- dedup key, e.g. git:<sha>
    source   TEXT NOT NULL,          -- git|claude|cursor|aider|vscode|github
    kind     TEXT NOT NULL,          -- commit|session|edit|gh_week|...
    ts_start TEXT NOT NULL,          -- ISO8601 UTC
    ts_end   TEXT,
    project  TEXT,
    loc_add  INTEGER DEFAULT 0,
    loc_del  INTEGER DEFAULT 0,
    items    INTEGER DEFAULT 0,      -- commits/messages/edits in this event
    meta     TEXT                    -- JSON: active_s, days{}, tools, ...
);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_start);
CREATE INDEX IF NOT EXISTS idx_events_project ON events(project);

CREATE TABLE IF NOT EXISTS file_cache (
    path  TEXT PRIMARY KEY,
    mtime REAL,
    size  INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT,
    finished_at TEXT,
    sources     TEXT,
    added       INTEGER,
    notes       TEXT,
    status      TEXT DEFAULT 'complete'
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS repos (
    path      TEXT PRIMARY KEY,
    last_seen TEXT
);
"""


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    scan_cols = {r[1] for r in db.execute("PRAGMA table_info(scans)")}
    if "status" not in scan_cols:
        db.execute("ALTER TABLE scans ADD COLUMN status TEXT DEFAULT 'complete'")
    db.execute("UPDATE scans SET status='complete' WHERE status IS NULL")
    db.commit()
    return db


def meta_get(db: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def insert_event(db: sqlite3.Connection, uid: str, source: str, kind: str,
                 ts_start: datetime, ts_end: datetime | None, project: str | None,
                 loc_add: int = 0, loc_del: int = 0, items: int = 0,
                 meta: dict | None = None) -> bool:
    cur = db.execute(
        "INSERT OR IGNORE INTO events(uid,source,kind,ts_start,ts_end,project,"
        "loc_add,loc_del,items,meta) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (uid, source, kind, ts_start.astimezone(timezone.utc).isoformat(),
         ts_end.astimezone(timezone.utc).isoformat() if ts_end else None,
         project, loc_add, loc_del, items,
         json.dumps(meta, separators=(",", ":")) if meta else None))
    return cur.rowcount > 0


def replace_event(db: sqlite3.Connection, uid: str, **kw) -> bool:
    """Upsert for events whose payload can grow (e.g. live session files)."""
    db.execute("DELETE FROM events WHERE uid=?", (uid,))
    return insert_event(db, uid, **kw)


def file_unchanged(db: sqlite3.Connection, p: Path) -> bool:
    try:
        st = p.stat()
    except OSError:
        return True  # unreadable => nothing to do
    row = db.execute("SELECT mtime,size FROM file_cache WHERE path=?", (str(p),)).fetchone()
    return bool(row and row[0] == st.st_mtime and row[1] == st.st_size)


def file_mark(db: sqlite3.Connection, p: Path) -> None:
    try:
        st = p.stat()
    except OSError:
        return
    db.execute("INSERT INTO file_cache(path,mtime,size) VALUES(?,?,?) "
               "ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime,size=excluded.size",
               (str(p), st.st_mtime, st.st_size))


# ---------------------------------------------------------------- time utils

def parse_iso(s: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def local_day(dt: datetime) -> str:
    return dt.astimezone().strftime("%Y-%m-%d")


def sessions_from_timestamps(stamps: list[datetime]) -> tuple[int, dict[str, int]]:
    """Split sorted timestamps at idle gaps; return (active_seconds, {day: seconds}).
    Each sub-session's duration is allocated to local days, split at midnight."""
    if not stamps:
        return 0, {}
    stamps = sorted(stamps)
    total = 0
    days: dict[str, int] = {}
    start = prev = stamps[0]

    def flush(a: datetime, b: datetime) -> None:
        nonlocal total
        dur = max(int((b - a).total_seconds()), MIN_SESSION_S)
        total += dur
        # allocate across local midnights
        a_l, b_l = a.astimezone(), a.astimezone() + timedelta(seconds=dur)
        cur = a_l
        while cur < b_l:
            midnight = (cur + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            seg_end = min(b_l, midnight)
            days[cur.strftime("%Y-%m-%d")] = days.get(cur.strftime("%Y-%m-%d"), 0) + \
                int((seg_end - cur).total_seconds())
            cur = seg_end

    for ts in stamps[1:]:
        if (ts - prev).total_seconds() > IDLE_GAP_S:
            flush(start, prev)
            start = ts
        prev = ts
    flush(start, prev)
    return total, days


def sessions_from_activity(
        activity: list[tuple[datetime, str]]) -> tuple[int, dict[str, int], dict[str, int]]:
    """Sessionize timestamped activity and conservatively attribute active seconds.

    `user` activity opens a steering window. Assistant/tool activity inside that
    window is co-authored; later autonomous activity is AI-only. Human-only
    activity is accounted for separately from Git and editor receipts.
    """
    if not activity:
        return 0, {}, {"coauthored_s": 0, "ai_only_s": 0}
    ordered = sorted(activity, key=lambda item: item[0])
    active_s, days = sessions_from_timestamps([ts for ts, _ in ordered])
    coauthored = ai_only = 0
    last_user: datetime | None = None
    previous: datetime | None = None
    for ts, kind in ordered:
        if previous is None or (ts - previous).total_seconds() > IDLE_GAP_S:
            previous = ts
            last_user = ts if kind == "user" else None
            continue
        segment = max(0, int((ts - previous).total_seconds()))
        if last_user:
            window_end = last_user + timedelta(seconds=STEERING_WINDOW_S)
            steered_end = min(ts, window_end)
            steered = max(0, int((steered_end - previous).total_seconds()))
            coauthored += min(steered, segment)
            ai_only += max(segment - steered, 0)
        else:
            ai_only += segment
        if kind == "user":
            last_user = ts
        previous = ts
    credited = coauthored + ai_only
    if credited < active_s:
        # The minimum per-session credit follows the strongest available signal.
        if any(kind == "user" for _, kind in ordered):
            coauthored += active_s - credited
        else:
            ai_only += active_s - credited
    return active_s, days, {"coauthored_s": coauthored, "ai_only_s": ai_only}


# ---------------------------------------------------------------- git scanner

def find_git_repos(roots: list[Path]) -> list[Path]:
    repos: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            name = os.path.basename(dirpath)
            if name in SKIP_DIR_NAMES or name.startswith("~$"):
                dirnames[:] = []
                continue
            if ".git" in dirnames or ".git" in filenames:
                real = os.path.realpath(dirpath)
                if real not in seen:
                    seen.add(real)
                    repos.append(Path(dirpath))
                dirnames[:] = []  # don't descend into repos (submodules counted via parent)
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and "DerivedData" not in d]
            # keep walk shallow-ish: don't dig more than 4 levels below root
            depth = len(Path(dirpath).relative_to(root).parts)
            if depth >= 4:
                dirnames[:] = []
    return repos


def path_under_roots(path: Path, roots: list[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def author_matches(name: str, email: str, needles: list[str]) -> bool:
    hay = f"{name} <{email}>".lower()
    return any(n in hay for n in needles)


def cached_repos(db: sqlite3.Connection, roots: list[Path],
                 rediscover: bool = False) -> list[Path]:
    """Repo discovery with a persistent cache — walking iCloud-backed trees
    (~/Desktop) is minutes-slow, so rescans reuse the last discovered list.
    Pass --rediscover (or empty cache) to walk again."""
    if not rediscover:
        cached = [Path(r[0]) for r in db.execute("SELECT path FROM repos")]
        cached = [p for p in cached if path_under_roots(p, roots) and (p / ".git").exists()]
        if cached:
            return cached
    repos = find_git_repos(roots)
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    # Cache entries outside the current roots remain as forensic history but can
    # never leak back into a scan that explicitly excludes those roots.
    for r in repos:
        db.execute("INSERT INTO repos(path,last_seen) VALUES(?,?) "
                   "ON CONFLICT(path) DO UPDATE SET last_seen=excluded.last_seen",
                   (str(r), now))
    db.commit()
    return repos


def scan_git(db: sqlite3.Connection, roots: list[Path], authors: list[str],
             rediscover: bool = False, timeout: int = GIT_TIMEOUT_S) -> tuple[int, list[str]]:
    needles = [a.strip().lower() for a in authors if a.strip()]
    repos = cached_repos(db, roots, rediscover)
    say(f"  git: {len(repos)} repos under {', '.join(str(r) for r in roots if r.is_dir())}")
    added, notes = 0, []
    fmt = ("%x1e%H%x1f%an%x1f%ae%x1f%aI%x1f"
           "%(trailers:key=Co-authored-by,valueonly,separator=%x1d)")
    for repo in repos:
        try:
            out = subprocess.run(
                ["git", "-C", str(repo), "log", "--all", "--no-merges",
                 "--numstat", f"--pretty=format:{fmt}"],
                capture_output=True, text=True, timeout=timeout, errors="replace")
        except subprocess.TimeoutExpired:
            notes.append(f"timeout: {repo}")
            warn(f"git timeout (iCloud?): {repo}")
            continue
        if out.returncode != 0:
            notes.append(f"git-error: {repo}")
            continue
        repo_name = repo.name
        for record in out.stdout.split("\x1e"):
            record = record.strip("\n")
            if not record:
                continue
            head, _, body = record.partition("\n")
            parts = head.split("\x1f")
            if len(parts) != 5:
                continue
            sha, an, ae, aiso, coauthor_text = parts
            if needles and not author_matches(an, ae, needles):
                continue
            ts = parse_iso(aiso)
            if not ts:
                continue
            add = dele = files = 0
            for line in body.splitlines():
                cols = line.split("\t")
                if len(cols) == 3:
                    a, d = cols[0], cols[1]
                    if a.isdigit():
                        add += int(a)
                    if d.isdigit():
                        dele += int(d)
                    files += 1
            coauthors = [value.strip() for value in coauthor_text.split("\x1d")
                         if value.strip()]
            ai_coauthor = any(any(token in value.lower() for token in (
                "claude", "codex", "cursor", "copilot", "bot@", "[bot]"))
                              for value in coauthors)
            if insert_event(db, f"git:{sha}", "git", "commit", ts, None, repo_name,
                            loc_add=add, loc_del=dele, items=1,
                            meta={"files": files, "email": ae,
                                  "coauthor_count": len(coauthors),
                                  "ai_coauthor": ai_coauthor}):
                added += 1
        db.commit()  # per-repo durability: interrupted scans lose nothing
    return added, notes


# ------------------------------------------------------- jsonl session scanner
# shared by claude + cursor agent transcripts

TS_RE = re.compile(r'"timestamp"\s*:\s*"([^"]+)"')


def scan_session_jsonl(db: sqlite3.Connection, path: Path, source: str,
                       project: str, uid: str | None = None) -> bool:
    """One .jsonl transcript = one session event (upserted as the file grows)."""
    uid = uid or f"{source}:{path.stem}"
    if file_unchanged(db, path):
        return False
    activity: list[tuple[datetime, str]] = []
    msgs = tools = users = tests = parallel = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = TS_RE.search(line[:2000])
                ts = None
                if m:
                    ts = parse_iso(m.group(1))
                prefix = line[:4000]
                kind = "assistant"
                if ('"role":"user"' in prefix or '"role": "user"' in prefix or
                        '"type":"user"' in prefix or '"type": "user"' in prefix):
                    kind = "user"
                    users += 1
                elif ('"tool_use"' in prefix or '"function_call"' in prefix):
                    kind = "tool"
                if ts:
                    activity.append((ts, kind))
                if '"type":"assistant"' in prefix or '"type": "assistant"' in prefix:
                    msgs += 1
                tools += prefix.count('"type":"tool_use"') + prefix.count('"function_call"')
                lowered = prefix.lower()
                if any(token in lowered for token in ("cargo test", "pytest", "npm test",
                                                       "pnpm test", "unittest", "go test")):
                    tests += 1
                if "spawn_agent" in lowered or "create_thread" in lowered:
                    parallel += 1
    except OSError:
        return False
    file_mark(db, path)
    if not activity:
        return False
    active_s, days, attribution = sessions_from_activity(activity)
    stamps = sorted(ts for ts, _ in activity)
    replace_event(db, uid, source=source, kind="session",
                  ts_start=stamps[0], ts_end=stamps[-1], project=project,
                  items=msgs, meta={"active_s": active_s, "days": days,
                                    **attribution, "tools": tools,
                                    "user_messages": users, "test_calls": tests,
                                    "parallel_calls": parallel, "file": str(path)})
    db.commit()  # per-file durability: interrupted scans lose nothing
    return True


def project_from_claude_dir(dirname: str) -> str:
    # "-Users-kingjames-Desktop-Agent-Clawbrary" -> "Agent-Clawbrary"
    parts = [p for p in dirname.split("-") if p]
    known_prefix = ["Users", "kingjames", "Desktop", "Projects", "dev", "claude",
                    "worktrees", "Documents", "private", "tmp"]
    tail = [p for p in parts if p not in known_prefix]
    return "-".join(tail) if tail else dirname


def scan_claude(db: sqlite3.Connection) -> tuple[int, list[str]]:
    root = HOME / ".claude" / "projects"
    if not root.is_dir():
        return 0, ["no ~/.claude/projects"]
    added = 0
    files = sorted(root.rglob("*.jsonl"))
    say(f"  claude: {len(files)} session files")
    for f in files:
        rel = f.relative_to(root)
        if scan_session_jsonl(db, f, "claude", project_from_claude_dir(rel.parts[0]),
                              uid=f"claude:{rel}"):
            added += 1
    return added, []


def project_from_path(cwd: str | None, fallback: str = "misc") -> str:
    if not cwd:
        return fallback
    path = Path(cwd)
    ignored = {"worktrees", ".git", "tmp", "private", "var"}
    parts = [part for part in path.parts if part not in ignored]
    for anchor in ("Projects", "Desktop", "dev", "Codex"):
        if anchor in parts:
            idx = parts.index(anchor)
            if idx + 1 < len(parts):
                candidate_idx = idx + 1
                if (anchor == "Codex" and
                        re.fullmatch(r"\d{4}-\d{2}-\d{2}", parts[candidate_idx]) and
                        candidate_idx + 1 < len(parts)):
                    candidate_idx += 1
                return parts[candidate_idx]
    return path.name or fallback


def parse_codex_session(path: Path) -> dict | None:
    """Read only timing/type metadata from a Codex JSONL session."""
    activity: list[tuple[datetime, str]] = []
    project = path.stem
    session_id = path.stem
    tools = users = assistants = tests = parallel = plan_turns = turns = 0
    try:
        with path.open("r", errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = parse_iso(row.get("timestamp", ""))
                payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
                row_type = row.get("type")
                payload_type = payload.get("type")
                kind: str | None = None
                if row_type == "session_meta":
                    project = project_from_path(payload.get("cwd"), project)
                    session_id = str(payload.get("id") or session_id)
                elif row_type == "turn_context":
                    turns += 1
                    mode = payload.get("collaboration_mode")
                    mode_text = json.dumps(mode, separators=(",", ":")).lower()
                    if "plan" in mode_text:
                        plan_turns += 1
                elif row_type == "event_msg" and payload_type == "user_message":
                    kind = "user"
                    users += 1
                elif row_type == "response_item":
                    if payload_type == "function_call":
                        kind = "tool"
                        tools += 1
                        name = str(payload.get("name") or "").lower()
                        arguments = str(payload.get("arguments") or "").lower()
                        if any(token in arguments for token in (
                                "cargo test", "pytest", "npm test", "pnpm test",
                                "unittest", "go test", "swift test")):
                            tests += 1
                        if "spawn_agent" in name or "create_thread" in name:
                            parallel += 1
                    elif payload_type == "message" and payload.get("role") == "user":
                        # System/developer context is represented as user-role messages;
                        # the explicit event_msg is the reliable human-turn receipt.
                        continue
                    elif payload_type in {"message", "reasoning"}:
                        kind = "assistant"
                        assistants += 1
                elif row_type == "event_msg" and payload_type == "agent_message":
                    # response_item carries the same message; avoid double counting.
                    continue
                if ts and kind:
                    activity.append((ts, kind))
    except OSError:
        return None
    if not activity:
        return None
    active_s, days, attribution = sessions_from_activity(activity)
    stamps = [ts for ts, _ in activity]
    return {
        "session_id": session_id, "project": project, "ts_start": min(stamps),
        "ts_end": max(stamps), "active_s": active_s, "days": days,
        **attribution, "items": assistants, "tools": tools,
        "user_messages": users, "test_calls": tests, "parallel_calls": parallel,
        "plan_turns": plan_turns, "turns": turns,
    }


def scan_codex(db: sqlite3.Connection) -> tuple[int, list[str]]:
    root = HOME / ".codex" / "sessions"
    if not root.is_dir():
        return 0, ["no ~/.codex/sessions"]
    files = sorted(root.rglob("*.jsonl"))
    say(f"  codex: {len(files)} session files")
    added = 0
    for path in files:
        if file_unchanged(db, path):
            continue
        parsed = parse_codex_session(path)
        file_mark(db, path)
        if not parsed:
            continue
        rel = path.relative_to(root)
        replace_event(
            db, f"codex:{rel}", source="codex", kind="session",
            ts_start=parsed["ts_start"], ts_end=parsed["ts_end"],
            project=parsed["project"], items=parsed["items"],
            meta={k: v for k, v in parsed.items()
                  if k not in {"session_id", "project", "ts_start", "ts_end", "items"}}
                  | {"session_id": parsed["session_id"], "file": str(path)})
        db.commit()
        added += 1
    return added, []


def _gemini_tool_count(content: object) -> int:
    """Count tool-call envelopes by key without retaining their arguments."""
    if isinstance(content, list):
        return sum(_gemini_tool_count(item) for item in content)
    if not isinstance(content, dict):
        return 0
    count = sum(1 for key in content
                if key.lower() in {"toolcall", "tool_call", "functioncall",
                                   "function_call"})
    return count + sum(_gemini_tool_count(value) for value in content.values()
                       if isinstance(value, (dict, list)))


def parse_gemini_session(path: Path, project: str) -> dict | None:
    """Extract only timing, role, and tool-count metadata from a Gemini session."""
    try:
        if path.suffix == ".jsonl":
            records = []
            with path.open("r", errors="replace") as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict):
                        records.append(row)
        else:
            root = json.loads(path.read_text(errors="replace"))
            records = [root] if isinstance(root, dict) else []
    except (OSError, json.JSONDecodeError):
        return None
    if not records:
        return None

    header = records[0]
    session_id = str(header.get("sessionId") or path.stem)
    message_rows: list[dict] = []
    for row in records:
        messages = row.get("messages")
        if isinstance(messages, list):
            message_rows.extend(item for item in messages if isinstance(item, dict))
        elif row.get("type") in {"user", "gemini", "assistant", "model", "tool"}:
            message_rows.append(row)

    activity: list[tuple[datetime, str]] = []
    users = assistants = tools = 0
    for message in message_rows:
        ts = parse_iso(message.get("timestamp", ""))
        role = str(message.get("type") or message.get("role") or "").lower()
        if role == "user":
            kind = "user"
            users += 1
        elif role == "tool":
            kind = "tool"
        else:
            kind = "assistant"
            assistants += 1
        tools += _gemini_tool_count(message.get("content"))
        if ts:
            activity.append((ts, kind))

    if not activity:
        start = parse_iso(header.get("startTime", ""))
        end = parse_iso(header.get("lastUpdated", ""))
        if start:
            activity.append((start, "assistant"))
        if end and end != start:
            activity.append((end, "assistant"))
    if not activity:
        return None

    active_s, days, attribution = sessions_from_activity(activity)
    stamps = [ts for ts, _ in activity]
    return {
        "session_id": session_id, "project": project,
        "ts_start": min(stamps), "ts_end": max(stamps),
        "active_s": active_s, "days": days, **attribution,
        "items": assistants, "tools": tools, "user_messages": users,
        "test_calls": 0, "parallel_calls": 0,
    }


def scan_gemini(db: sqlite3.Connection) -> tuple[int, list[str]]:
    root = HOME / ".gemini" / "tmp"
    if not root.is_dir():
        return 0, ["no ~/.gemini/tmp"]
    files = sorted(
        path for path in root.glob("*/chats/session-*")
        if path.is_file() and path.suffix in {".json", ".jsonl"})
    say(f"  gemini: {len(files)} session files")
    added = 0
    for path in files:
        if file_unchanged(db, path):
            continue
        project = path.parent.parent.name
        parsed = parse_gemini_session(path, project)
        file_mark(db, path)
        if not parsed:
            continue
        rel = path.relative_to(root)
        replace_event(
            db, f"gemini:{rel}", source="gemini", kind="session",
            ts_start=parsed["ts_start"], ts_end=parsed["ts_end"],
            project=parsed["project"], items=parsed["items"],
            meta={key: value for key, value in parsed.items()
                  if key not in {"session_id", "project", "ts_start", "ts_end", "items"}}
                 | {"session_id": parsed["session_id"], "file": str(path)})
        db.commit()
        added += 1
    return added, []


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    return None


def _count_top_level_protobuf_messages(data: bytes, field_number: int = 1) -> int:
    """Count top-level length-delimited fields without decoding private payloads."""
    offset = count = 0
    while offset < len(data):
        key_result = _read_varint(data, offset)
        if not key_result:
            break
        key, offset = key_result
        wire_type = key & 7
        current_field = key >> 3
        if wire_type == 0:
            value_result = _read_varint(data, offset)
            if not value_result:
                break
            _, offset = value_result
        elif wire_type == 1:
            offset += 8
        elif wire_type == 2:
            length_result = _read_varint(data, offset)
            if not length_result:
                break
            length, offset = length_result
            if current_field == field_number:
                count += 1
            offset += length
        elif wire_type == 5:
            offset += 4
        else:
            break
    return count


def antigravity_trajectory_count(state_db: Path) -> int:
    """Count opaque trajectory summaries; never deserialize their private content."""
    try:
        con = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
        row = con.execute(
            "SELECT value FROM ItemTable WHERE key=?",
            ("antigravityUnifiedStateSync.trajectorySummaries",)).fetchone()
        con.close()
        if not row or not row[0]:
            return 0
        encoded = row[0].encode() if isinstance(row[0], str) else row[0]
        return _count_top_level_protobuf_messages(
            base64.b64decode(encoded, validate=True))
    except (OSError, sqlite3.Error, ValueError):
        return 0


def scan_antigravity(db: sqlite3.Connection) -> tuple[int, list[str]]:
    roots = [
        HOME / "Library" / "Application Support" / "Antigravity",
        HOME / "Library" / "Application Support" / "Antigravity IDE",
    ]
    available = [root for root in roots if root.is_dir()]
    if not available:
        return 0, ["no Antigravity application data"]
    added = 0
    for root in available:
        history = root / "User" / "History"
        if history.is_dir():
            history_added, _ = _scan_vscode_history(db, history, "antigravity")
            added += history_added
        state_db = root / "User" / "globalStorage" / "state.vscdb"
        if not state_db.is_file() or file_unchanged(db, state_db):
            continue
        count = antigravity_trajectory_count(state_db)
        file_mark(db, state_db)
        if count:
            modified = datetime.fromtimestamp(state_db.stat().st_mtime, timezone.utc)
            product = root.name
            replace_event(
                db, f"antigravity:trajectories:{product}",
                source="antigravity", kind="agent_receipts",
                ts_start=modified, ts_end=modified, project=product, items=count,
                meta={"trajectory_receipts": count, "file": str(state_db)})
            db.commit()
            added += 1
    say(f"  antigravity: {len(available)} product stores")
    return added, []


def grok_project_from_session_path(path: Path, sessions_root: Path) -> str:
    try:
        cwd_dir = path.relative_to(sessions_root).parts[0]
    except (ValueError, IndexError):
        return path.parent.name
    cwd_file = sessions_root / cwd_dir / ".cwd"
    try:
        cwd = cwd_file.read_text(errors="replace").strip()
    except OSError:
        cwd = urllib.parse.unquote(cwd_dir)
    return project_from_path(cwd, path.parent.name)


def parse_grok_session(path: Path, project: str) -> dict | None:
    """Read Grok Build's documented event log without transcript content."""
    activity: list[tuple[datetime, str]] = []
    session_id = path.parent.name
    users = assistants = tools = parallel = plan_turns = turns = 0
    models: set[str] = set()
    try:
        with path.open("r", errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = parse_iso(row.get("ts", ""))
                event_type = str(row.get("type") or "")
                kind: str | None = None
                if event_type == "turn_started":
                    session_id = str(row.get("session_id") or session_id)
                    model = row.get("model_id")
                    if isinstance(model, str) and model:
                        models.add(model)
                    kind = "user"
                    users += 1
                    turns += 1
                elif event_type == "interjected":
                    kind = "user"
                    users += 1
                elif event_type == "tool_started":
                    kind = "tool"
                    tools += 1
                elif event_type in {"first_token", "turn_ended"}:
                    kind = "assistant"
                    assistants += event_type == "turn_ended"
                if event_type.startswith("goal_planner_"):
                    plan_turns += event_type == "goal_planner_fired"
                if (event_type.endswith("_fired") and
                        event_type.startswith(("goal_planner", "goal_strategist",
                                               "goal_summarizer", "goal_classifier"))):
                    parallel += 1
                relationship = str(row.get("session_relationship") or "").lower()
                if relationship and relationship != "primary":
                    parallel += event_type == "turn_started"
                if ts and kind:
                    activity.append((ts, kind))
    except OSError:
        return None
    if not activity:
        return None
    active_s, days, attribution = sessions_from_activity(activity)
    stamps = [ts for ts, _ in activity]
    return {
        "session_id": session_id, "project": project,
        "ts_start": min(stamps), "ts_end": max(stamps),
        "active_s": active_s, "days": days, **attribution,
        "items": assistants, "tools": tools, "user_messages": users,
        "test_calls": 0, "parallel_calls": parallel,
        "plan_turns": plan_turns, "turns": turns, "models": sorted(models),
    }


def scan_grok(db: sqlite3.Connection) -> tuple[int, list[str]]:
    grok_home = Path(os.environ.get("GROK_HOME") or HOME / ".grok").expanduser()
    sessions_root = grok_home / "sessions"
    if not sessions_root.is_dir():
        return 0, [f"no Grok Build sessions at {sessions_root}"]
    files = sorted(sessions_root.rglob("events.jsonl"))
    say(f"  grok: {len(files)} session files")
    added = 0
    for path in files:
        if file_unchanged(db, path):
            continue
        parsed = parse_grok_session(
            path, grok_project_from_session_path(path, sessions_root))
        file_mark(db, path)
        if not parsed:
            continue
        rel = path.relative_to(sessions_root)
        replace_event(
            db, f"grok:{rel}", source="grok", kind="session",
            ts_start=parsed["ts_start"], ts_end=parsed["ts_end"],
            project=parsed["project"], items=parsed["items"],
            meta={key: value for key, value in parsed.items()
                  if key not in {"session_id", "project", "ts_start", "ts_end", "items"}}
                 | {"session_id": parsed["session_id"], "file": str(path)})
        db.commit()
        added += 1
    return added, []


def scan_cursor(db: sqlite3.Connection) -> tuple[int, list[str]]:
    added, notes = 0, []
    # 1. agent transcripts (same format family as claude jsonl)
    troot = HOME / ".cursor" / "projects"
    tfiles = list(troot.glob("*/agent-transcripts/*.jsonl")) if troot.is_dir() else []
    for f in tfiles:
        if scan_session_jsonl(db, f, "cursor", f.parent.parent.name):
            added += 1
    # 2. chat store.db files — extract any epoch-ish timestamps best-effort
    for dbf in (HOME / ".cursor").glob("chats/**/store.db"):
        if file_unchanged(db, dbf):
            continue
        stamps = _sqlite_harvest_timestamps(dbf)
        file_mark(db, dbf)
        if stamps:
            active_s, days = sessions_from_timestamps(stamps)
            replace_event(db, f"cursor:store:{dbf.parent.name}", source="cursor",
                          kind="session", ts_start=min(stamps), ts_end=max(stamps),
                          project=dbf.parent.name, items=len(stamps),
                          meta={"active_s": active_s, "days": days, "file": str(dbf)})
            added += 1
    # 3. Cursor local history (VS Code format)
    ch = HOME / "Library" / "Application Support" / "Cursor" / "User" / "History"
    if ch.is_dir():
        a, _ = _scan_vscode_history(db, ch, "cursor")
        added += a
    if not tfiles and not (HOME / ".cursor" / "chats").is_dir() and not ch.is_dir():
        notes.append("no cursor data found")
    return added, notes


def _sqlite_harvest_timestamps(dbf: Path) -> list[datetime]:
    stamps: list[datetime] = []
    try:
        con = sqlite3.connect(f"file:{dbf}?mode=ro", uri=True)
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
            for c in cols:
                if any(k in c.lower() for k in ("time", "created", "updated", "date")):
                    try:
                        for (v,) in con.execute(f'SELECT "{c}" FROM "{t}" LIMIT 5000'):
                            ts = _coerce_epoch(v)
                            if ts:
                                stamps.append(ts)
                    except sqlite3.Error:
                        pass
        con.close()
    except sqlite3.Error:
        pass
    return stamps


def _coerce_epoch(v) -> datetime | None:
    if isinstance(v, (int, float)):
        if 1_000_000_000_000 < v < 3_000_000_000_000:      # ms
            return datetime.fromtimestamp(v / 1000, tz=timezone.utc)
        if 1_000_000_000 < v < 3_000_000_000:              # s
            return datetime.fromtimestamp(v, tz=timezone.utc)
    elif isinstance(v, str) and len(v) >= 19:
        return parse_iso(v)
    return None


# ---------------------------------------------------------------- aider

AIDER_TS_RE = re.compile(r"^#### (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def scan_aider(db: sqlite3.Connection, roots: list[Path]) -> tuple[int, list[str]]:
    added = 0
    files: list[Path] = []
    # aider writes its history at the repo root — check known repos (fast),
    # only fall back to a pruned walk when no repo cache exists yet
    known = [Path(r[0]) for r in db.execute("SELECT path FROM repos")
             if path_under_roots(Path(r[0]), roots)]
    if known:
        files = [p / ".aider.chat.history.md" for p in known
                 if (p / ".aider.chat.history.md").is_file()]
    else:
        for root in roots:
            if not root.is_dir():
                continue
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                dirnames[:] = [d for d in dirnames
                               if d not in SKIP_DIR_NAMES and not d.startswith("~$")]
                if len(Path(dirpath).relative_to(root).parts) >= 4:
                    dirnames[:] = []
                if ".aider.chat.history.md" in filenames:
                    files.append(Path(dirpath) / ".aider.chat.history.md")
    say(f"  aider: {len(files)} history files")
    for f in files:
        if file_unchanged(db, f):
            continue
        stamps = []
        try:
            for line in open(f, errors="replace"):
                m = AIDER_TS_RE.match(line)
                if m:
                    ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").astimezone()
                    stamps.append(ts)
        except OSError:
            continue
        file_mark(db, f)
        if not stamps:
            continue
        active_s, days = sessions_from_timestamps(stamps)
        replace_event(db, f"aider:{f.parent}", source="aider", kind="session",
                      ts_start=min(stamps), ts_end=max(stamps), project=f.parent.name,
                      items=len(stamps), meta={"active_s": active_s, "days": days})
        added += 1
    return added, []


# ---------------------------------------------------------------- vscode

def _project_from_resource(uri: str) -> str:
    m = re.search(r"/Users/[^/]+/(?:Projects|Desktop|dev)/([^/]+)/", uri)
    return m.group(1) if m else "misc"


def _scan_vscode_history(db: sqlite3.Connection, hist: Path, source: str) -> tuple[int, list[str]]:
    added = 0
    for d in hist.iterdir():
        ej = d / "entries.json"
        if not ej.is_file() or file_unchanged(db, ej):
            continue
        try:
            data = json.loads(ej.read_text(errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        file_mark(db, ej)
        project = _project_from_resource(data.get("resource", ""))
        for e in data.get("entries", []):
            ts = _coerce_epoch(e.get("timestamp"))
            if not ts:
                continue
            if insert_event(db, f"{source}:hist:{d.name}:{e.get('id')}", source,
                            "edit", ts, None, project, items=1):
                added += 1
    return added, []


def scan_vscode(db: sqlite3.Connection) -> tuple[int, list[str]]:
    hist = HOME / "Library" / "Application Support" / "Code" / "User" / "History"
    if not hist.is_dir():
        return 0, ["no VS Code Local History"]
    n = len(list(hist.iterdir()))
    say(f"  vscode: {n} history dirs")
    return _scan_vscode_history(db, hist, "vscode")


# ---------------------------------------------------------------- github

def _gh(args: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        out = subprocess.run(["gh"] + args, capture_output=True, text=True, timeout=timeout)
        return out.returncode, out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 1, ""


def scan_github(db: sqlite3.Connection, owners: list[str], login: str,
                local_repo_names: set[str]) -> tuple[int, list[str]]:
    added, notes = 0, []
    for owner in owners:
        rc, out = _gh(["repo", "list", owner, "--limit", "400",
                       "--json", "name,nameWithOwner,isFork"])
        if rc != 0:
            notes.append(f"gh repo list failed for {owner}")
            continue
        repos = [r for r in json.loads(out or "[]") if not r["isFork"]]
        say(f"  github: {owner}: {len(repos)} repos")
        for r in repos:
            is_local = r["name"].lower() in local_repo_names
            full = r["nameWithOwner"]
            stats = None
            for attempt in range(3):
                rc, out = _gh(["api", f"repos/{full}/stats/contributors"], timeout=90)
                if rc == 0 and out.strip() and out.strip() != "[]":
                    try:
                        stats = json.loads(out)
                        break
                    except json.JSONDecodeError:
                        pass
                time.sleep(2)  # 202 Accepted: GitHub is computing stats
            if not isinstance(stats, list):
                if stats is None:
                    notes.append(f"no stats: {full}")
                continue
            mine = next((s for s in stats
                         if (s.get("author") or {}).get("login", "").lower() == login.lower()), None)
            if mine and not is_local:
                for w in mine.get("weeks", []):
                    if not (w.get("c") or w.get("a") or w.get("d")):
                        continue
                    ts = datetime.fromtimestamp(w["w"], tz=timezone.utc)
                    if insert_event(db, f"github:{full}:{w['w']}", "github", "gh_week",
                                    ts, ts + timedelta(days=7), r["name"],
                                    loc_add=w.get("a", 0), loc_del=w.get("d", 0),
                                    items=w.get("c", 0)):
                        added += 1

            contributor_logins = {
                str((entry.get("author") or {}).get("login") or "").lower()
                for entry in stats}
            # Human activity in a local repository is already represented by
            # exact Git commits. Platform-authored history is independent
            # evidence and must still be imported (for example, a project that
            # began in Lovable and was cloned locally later).
            actors = [login] if mine and not is_local else []
            actors.extend(
                bot for bot in LOVABLE_BOT_LOGINS
                if bot.lower() in contributor_logins)
            for actor in actors:
                encoded_actor = urllib.parse.quote(actor, safe="")
                is_lovable = actor in LOVABLE_BOT_LOGINS
                commit_path = (
                    f"repos/{full}/commits?per_page=100" if is_lovable
                    else f"repos/{full}/commits?author={encoded_actor}&per_page=100")
                jq_filter = ".[]"
                if is_lovable:
                    login_json = json.dumps(actor)
                    name_checks = " or ".join(
                        f"(.commit.author.name // \"\") == {json.dumps(name)}"
                        for name in LOVABLE_COMMIT_AUTHOR_NAMES)
                    jq_filter += (
                        f" | select((.author.login // \"\") == {login_json} or "
                        f"({name_checks}))")
                rc, out = _gh([
                    "api", "--paginate",
                    commit_path,
                    "--jq", f"{jq_filter} | [.sha,.commit.author.date] | @tsv",
                ], timeout=90)
                if rc:
                    notes.append(f"commit activity unavailable: {full} ({actor})")
                    continue
                for line in out.splitlines():
                    parts = line.split("\t", 1)
                    ts = parse_iso(parts[1]) if len(parts) == 2 else None
                    if not ts:
                        continue
                    if insert_event(
                            db, f"github-activity:{full}:{parts[0]}", "github",
                            "remote_activity", ts, ts, r["name"], meta={
                                "actor": actor,
                                "platform_bot": actor.lower() != login.lower(),
                                "platform": (
                                    "lovable" if is_lovable
                                    else "github"),
                                "repository": full,
                            }):
                        added += 1
    return added, notes


def cmd_sync_github(args) -> None:
    """Create/update lightweight no-checkout repositories for exact Git history."""
    destination = Path(args.destination).expanduser().resolve()
    owners = [owner.strip() for owner in args.owners.split(",") if owner.strip()]
    if not owners:
        raise SystemExit("--owners must contain at least one GitHub owner")
    destination.mkdir(parents=True, exist_ok=True)
    failures = []
    synced = 0
    for owner in owners:
        rc, out = _gh(["repo", "list", owner, "--limit", str(args.limit),
                       "--json", "name,nameWithOwner,isFork,isArchived"])
        if rc:
            failures.append(f"unable to list {owner}")
            continue
        repos = [r for r in json.loads(out or "[]")
                 if not r.get("isFork") and (args.include_archived or not r.get("isArchived"))]
        say(f"  {owner}: {len(repos)} repositories")
        for repo in repos:
            full = repo["nameWithOwner"]
            target = destination / owner / repo["name"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if (target / ".git").is_dir():
                run = subprocess.run(["git", "-C", str(target), "fetch", "--all", "--prune"],
                                     capture_output=True, text=True)
            elif target.exists():
                failures.append(f"destination exists but is not a Git repo: {target}")
                continue
            else:
                run = subprocess.run(
                    ["gh", "repo", "clone", full, str(target), "--", "--no-checkout"],
                    capture_output=True, text=True)
            if run.returncode:
                failures.append(f"sync failed: {full}")
                continue
            synced += 1
    say(f"{C_GREEN}✓ GitHub history sync complete{C_RESET}: {synced} repositories")
    if failures:
        for failure in failures:
            warn(failure)
        raise SystemExit(1)


# ---------------------------------------------------------------- aggregation

def compute_daily(db: sqlite3.Connection) -> dict:
    """Build per-day aggregates from raw events. Recomputable forever."""
    hours: dict[str, dict[str, float]] = {}   # day -> source -> hours
    loc: dict[str, int] = {}                  # day -> net LOC added (local git)
    loc_add: dict[str, int] = {}
    commits_per_day: dict[str, int] = {}
    commits_day_proj: dict[tuple[str, str], int] = {}
    edits_per_day: dict[tuple[str, str], int] = {}
    evidence_days: set[str] = set()
    attributed: dict[str, dict[str, float]] = {}
    proj: dict[str, dict[str, float]] = {}    # project -> {hours, loc_add, loc_del}

    def bump_proj(p: str | None, h: float = 0, a: int = 0, d: int = 0):
        p = p or "misc"
        if p in {"-Users-kingjames", "Users-kingjames"}:
            p = "Unattributed workspace"
        e = proj.setdefault(p, {"hours": 0.0, "loc_add": 0, "loc_del": 0})
        e["hours"] += h
        e["loc_add"] += a
        e["loc_del"] += d

    for source, kind, ts_start, project, la, ld, items, meta_s in db.execute(
            "SELECT source,kind,ts_start,project,loc_add,loc_del,items,meta FROM events"):
        meta = json.loads(meta_s) if meta_s else {}
        ts = parse_iso(ts_start)
        day = local_day(ts) if ts else None
        if kind == "session":
            active_s = int(meta.get("active_s", 0))
            coauthored_s = int(meta.get("coauthored_s", active_s))
            ai_only_s = int(meta.get("ai_only_s", max(active_s - coauthored_s, 0)))
            for d, secs in (meta.get("days") or {}).items():
                evidence_days.add(d)
                hours.setdefault(d, {}).setdefault(source, 0.0)
                hours[d][source] += secs / 3600
                share = secs / active_s if active_s else 0
                bucket = attributed.setdefault(d, {"coauthored": 0.0, "ai_only": 0.0})
                bucket["coauthored"] += coauthored_s * share / 3600
                bucket["ai_only"] += ai_only_s * share / 3600
            bump_proj(project, h=active_s / 3600)
        elif kind == "commit" and day:
            evidence_days.add(day)
            commits_per_day[day] = commits_per_day.get(day, 0) + 1
            commits_day_proj[(day, project or "misc")] = \
                commits_day_proj.get((day, project or "misc"), 0) + 1
            loc[day] = loc.get(day, 0) + la - ld
            loc_add[day] = loc_add.get(day, 0) + la
            bump_proj(project, a=la, d=ld)
        elif kind == "edit" and day:
            evidence_days.add(day)
            key = (day, source)
            edits_per_day[key] = edits_per_day.get(key, 0) + items
        elif kind == "gh_week" and day:
            bump_proj(project, a=la, d=ld)
        elif kind == "remote_activity" and day:
            evidence_days.add(day)

    day_proj: dict[str, dict[str, int]] = {}
    for (d, p), cnt in commits_day_proj.items():
        day_proj.setdefault(d, {})[p] = cnt
    for day, n in commits_per_day.items():
        h = min(GIT_BASE_H + GIT_PER_COMMIT_H * n, GIT_DAY_CAP_H)
        hours.setdefault(day, {}).setdefault("git", 0.0)
        hours[day]["git"] += h
        # distribute the day's density credit to projects by commit share
        for p, cnt in day_proj.get(day, {}).items():
            bump_proj(p, h=h * cnt / n)
    for (day, source), n in edits_per_day.items():
        h = min(n * VSCODE_PER_EDIT_S, VSCODE_DAY_CAP_S) / 3600
        hours.setdefault(day, {}).setdefault(source, 0.0)
        hours[day][source] += h

    for day, per_source in hours.items():
        human_h = per_source.get("git", 0.0) + sum(
            per_source.get(source, 0.0) for source in EDITOR_SOURCES)
        bucket = attributed.setdefault(day, {"coauthored": 0.0, "ai_only": 0.0})
        # Only agent time classified from interaction timestamps as co-authored
        # can overlap human evidence. Independently running AI time is additive.
        # Parsers without steering detail default their full duration to
        # co-authored, preserving the conservative fallback.
        bucket["own"] = max(human_h - bucket["coauthored"], 0.0)

    evidence_days.update(hours)
    return {"hours": hours, "loc": loc, "loc_add": loc_add,
            "commits": commits_per_day, "projects": proj, "attributed": attributed,
            "evidence_days": sorted(evidence_days)}


def allocate_coding_hours(own: float, coauthored: float, ai_only: float) -> dict[str, float]:
    """Allocate shared work into the two visible coding categories.

    The human and AI base hours determine the proportional split. If neither
    side has base evidence, shared time is split evenly rather than assigned
    arbitrarily to one side.
    """
    own = max(float(own), 0.0)
    coauthored = max(float(coauthored), 0.0)
    ai_only = max(float(ai_only), 0.0)
    base_total = own + ai_only
    your_share = own / base_total if base_total else 0.5
    ai_share = 1.0 - your_share
    return {
        "your_coding": own + coauthored * your_share,
        "ai_coding": ai_only + coauthored * ai_share,
        "your_share": your_share,
        "ai_share": ai_share,
    }


def activity_rhythm(active_day_strings: list[str], report_day: str,
                    start_day: str | None = None) -> dict:
    """Return alternating building/off calendar runs through the report day."""
    end = datetime.strptime(report_day, "%Y-%m-%d").date()
    active = {
        datetime.strptime(day, "%Y-%m-%d").date() for day in active_day_strings}
    active = {day for day in active if day <= end}
    if start_day:
        requested_start = datetime.strptime(start_day, "%Y-%m-%d").date()
        active = {day for day in active if day >= requested_start}
    if not active:
        return {
            "calendar_days": 0, "active_days": 0, "off_days": 0,
            "longest_break_days": 0, "streak_count": 0, "runs": [],
            "start_day": None, "end_day": end.isoformat()}
    start = requested_start if start_day else min(active)
    runs: list[dict] = []
    cursor = start
    run_start = start
    building = cursor in active
    while cursor <= end:
        state = cursor in active
        if state != building:
            runs.append({
                "state": "building" if building else "off",
                "start": run_start.isoformat(),
                "end": (cursor - timedelta(days=1)).isoformat(),
                "days": (cursor - run_start).days,
            })
            run_start = cursor
            building = state
        cursor += timedelta(days=1)
    runs.append({
        "state": "building" if building else "off",
        "start": run_start.isoformat(),
        "end": end.isoformat(),
        "days": (end - run_start).days + 1,
    })
    span = (end - start).days + 1
    return {
        "calendar_days": span,
        "active_days": len(active),
        "off_days": span - len(active),
        "longest_break_days": max(
            (run["days"] for run in runs if run["state"] == "off"), default=0),
        "streak_count": sum(run["state"] == "building" for run in runs),
        "start_day": start.isoformat(),
        "end_day": end.isoformat(),
        "runs": runs,
    }


def tier_for(value: float, thresholds: tuple[float, float, float, float]) -> str | None:
    tier = None
    for name, threshold in zip(("bronze", "silver", "gold", "platinum"), thresholds):
        if value >= threshold:
            tier = name
    return tier


def builder_profile(db: sqlite3.Connection, agg: dict, evidence_hours: dict[str, float]) -> dict:
    metrics = {
        "sessions": 0, "tools": 0, "user_messages": 0, "test_calls": 0,
        "parallel_calls": 0, "plan_turns": 0, "turns": 0, "ai_coauthored_commits": 0,
    }
    late = timed = 0
    for source, kind, ts_start, meta_s in db.execute(
            "SELECT source,kind,ts_start,meta FROM events"):
        meta = json.loads(meta_s) if meta_s else {}
        if kind == "session":
            metrics["sessions"] += 1
            for key in ("tools", "user_messages", "test_calls", "parallel_calls",
                        "plan_turns", "turns"):
                metrics[key] += int(meta.get(key, 0) or 0)
        elif kind == "commit" and meta.get("ai_coauthor"):
            metrics["ai_coauthored_commits"] += 1
        ts = parse_iso(ts_start)
        if ts:
            timed += 1
            hour = ts.astimezone().hour
            if hour >= 22 or hour < 2:
                late += 1
    active_days = max(len(agg["hours"]), 1)
    commits = sum(agg["commits"].values())
    sessions = max(metrics["sessions"], 1)
    user_per_session = metrics["user_messages"] / sessions
    tools_per_session = metrics["tools"] / sessions
    plan_rate = metrics["plan_turns"] / max(metrics["turns"], 1)
    tests_per_session = metrics["test_calls"] / sessions
    commits_per_day = commits / active_days
    ai_total = evidence_hours.get("coauthored", 0) + evidence_hours.get("ai_only", 0)
    autonomy_rate = evidence_hours.get("ai_only", 0) / max(ai_total, 0.001)
    night_rate = late / max(timed, 1)
    dimensions = {
        "steering": min(100, round(user_per_session * 18 + min(tools_per_session, 10) * 3)),
        "planning": min(100, round(plan_rate * 100)),
        "engineering": min(100, round(tests_per_session * 28 + min(commits_per_day, 3) * 12)),
        "execution": min(100, round(min(commits_per_day, 5) * 16 +
                                    min(metrics["sessions"] / active_days, 1) * 20)),
        "autonomy": min(100, round(autonomy_rate * 100 +
                                   min(metrics["parallel_calls"], 10) * 2)),
    }
    archetypes = {
        "steering": ("The Director", "You actively redirect agents and keep decisions explicit."),
        "planning": ("The Architect", "You plan, structure, and codify before execution."),
        "engineering": ("The Quality Guardian", "Tests and durable engineering receipts lead your work."),
        "execution": ("The Shipping Engine", "You turn active days into commits consistently."),
        "autonomy": ("The Agent Orchestrator", "You delegate long runs and parallel tool work."),
    }
    dominant = max(dimensions, key=dimensions.get)
    badge_defs = [
        ("Commit Cadence", commits_per_day, (0.5, 1.0, 2.0, 4.0), "commits per active day"),
        ("Quality Loop", tests_per_session, (0.10, 0.25, 0.50, 1.0), "test calls per AI session"),
        ("Steering Hand", user_per_session, (1.0, 2.0, 4.0, 8.0), "human turns per AI session"),
        ("Toolsmith", tools_per_session, (2.0, 5.0, 10.0, 20.0), "tool calls per AI session"),
        ("Parallel Commander", float(metrics["parallel_calls"]), (1, 5, 15, 40),
         "parallel-agent dispatches"),
        ("Night Shift", night_rate * 100, (15, 30, 50, 70), "percent of receipts from 10 PM–2 AM"),
        ("AI Pairing", float(metrics["ai_coauthored_commits"]), (1, 5, 20, 50),
         "commits with explicit AI co-author trailers"),
    ]
    badges = []
    for name, value, thresholds, unit in badge_defs:
        tier = tier_for(value, thresholds)
        badges.append({"name": name, "tier": tier or "locked", "value": round(value, 2),
                       "unit": unit, "next": next((t for t in thresholds if value < t), None)})
    return {
        "archetype": archetypes[dominant][0],
        "archetype_reason": archetypes[dominant][1],
        "dimensions": dimensions, "badges": badges,
        "metrics": {**metrics, "commits_per_day": round(commits_per_day, 2),
                    "tools_per_session": round(tools_per_session, 2),
                    "user_turns_per_session": round(user_per_session, 2),
                    "plan_rate": round(plan_rate, 3), "night_rate": round(night_rate, 3)},
        "growth_edge": min(dimensions, key=dimensions.get),
    }


def workflow_analytics(db: sqlite3.Connection, agg: dict, total_hours: float,
                       ai_hours: float, profile: dict) -> dict:
    project_hours = sorted(
        (entry["hours"] for project, entry in agg["projects"].items()
         if entry["hours"] > 0 and project not in {"misc", "Unattributed workspace"}),
        reverse=True)
    project_total = sum(project_hours)
    focus_pct = 100 * project_hours[0] / project_total if project_total else 0.0
    project_diversity = 0.0
    if project_total:
        project_diversity = 100 * (1 - sum((hours / project_total) ** 2
                                           for hours in project_hours))

    projects_by_day: dict[str, set[str]] = {}
    for ts_start, project in db.execute(
            "SELECT ts_start,project FROM events "
            "WHERE kind IN ('session','edit')"):
        ts = parse_iso(ts_start)
        normalized_project = project or "misc"
        if not ts or normalized_project in {
                "misc", "Unattributed workspace", "-Users-kingjames",
                "Users-kingjames"}:
            continue
        projects_by_day.setdefault(local_day(ts), set()).add(normalized_project)
    single_project_days = [
        day for day, projects in projects_by_day.items() if len(projects) == 1]
    multi_project_days = [
        day for day, projects in projects_by_day.items() if len(projects) >= 2]

    def cohort_average(days: list[str], daily_values: dict[str, float | int]) -> float:
        return statistics.mean(float(daily_values.get(day, 0)) for day in days) \
            if days else 0.0

    single_commits = cohort_average(single_project_days, agg["commits"])
    multi_commits = cohort_average(multi_project_days, agg["commits"])
    single_hours = cohort_average(
        single_project_days,
        {day: sum(per_source.values()) for day, per_source in agg["hours"].items()})
    multi_hours = cohort_average(
        multi_project_days,
        {day: sum(per_source.values()) for day, per_source in agg["hours"].items()})

    def percent_change(comparison: float, baseline: float) -> float | None:
        if not baseline:
            return None
        return round(100 * (comparison - baseline) / baseline, 1)

    commits_by_project: dict[str, list[datetime]] = {}
    for project, ts_start in db.execute(
            "SELECT project,ts_start FROM events WHERE kind='commit'"):
        ts = parse_iso(ts_start)
        if ts:
            commits_by_project.setdefault(project or "misc", []).append(ts)
    for timestamps in commits_by_project.values():
        timestamps.sort()

    eligible = matched_24h = matched_7d = 0
    lags: list[float] = []
    for project, ts_end, ts_start in db.execute(
            "SELECT project,ts_end,ts_start FROM events WHERE kind='session'"):
        end = parse_iso(ts_end or ts_start)
        commits = commits_by_project.get(project or "misc", [])
        if not end or not commits:
            continue
        eligible += 1
        index = bisect.bisect_left(commits, end)
        if index < len(commits):
            lag_h = (commits[index] - end).total_seconds() / 3600
            if 0 <= lag_h <= 7 * 24:
                matched_7d += 1
                if lag_h <= 24:
                    matched_24h += 1
                lags.append(lag_h)

    metrics = profile["metrics"]
    sessions = metrics["sessions"]
    return {
        "ai_leverage_pct": round(100 * ai_hours / total_hours, 1) if total_hours else 0.0,
        "active_projects": len(project_hours),
        "top_project_focus_pct": round(focus_pct, 1),
        "project_diversity_pct": round(project_diversity, 1),
        "single_project_days": len(single_project_days),
        "multi_project_days": len(multi_project_days),
        "single_project_commits_per_day": round(single_commits, 2),
        "multi_project_commits_per_day": round(multi_commits, 2),
        "multi_project_commit_change_pct": percent_change(multi_commits, single_commits),
        "single_project_hours_per_day": round(single_hours, 2),
        "multi_project_hours_per_day": round(multi_hours, 2),
        "multi_project_hours_change_pct": percent_change(multi_hours, single_hours),
        "verification_calls": metrics["test_calls"],
        "verification_per_session": round(
            metrics["test_calls"] / sessions, 2) if sessions else 0.0,
        "parallel_dispatches": metrics["parallel_calls"],
        "session_commit_eligible": eligible,
        "session_commit_24h_matches": matched_24h,
        "session_commit_24h_conversion_pct": round(
            100 * matched_24h / eligible, 1) if eligible else 0.0,
        "session_commit_matches": matched_7d,
        "session_commit_conversion_pct": round(100 * matched_7d / eligible, 1)
        if eligible else 0.0,
        "median_session_to_commit_hours": round(statistics.median(lags), 1)
        if lags else None,
        "session_commit_window_days": 7,
    }


def summarize(db: sqlite3.Connection) -> dict:
    agg = compute_daily(db)
    hours = agg["hours"]
    total_by_source: dict[str, float] = {}
    for day, per in hours.items():
        for s, h in per.items():
            total_by_source[s] = total_by_source.get(s, 0.0) + h
    raw_total_hours = sum(total_by_source.values())
    evidence_hours = {"own": 0.0, "coauthored": 0.0, "ai_only": 0.0}
    for per in agg["attributed"].values():
        for key in evidence_hours:
            evidence_hours[key] += per.get(key, 0.0)
    allocation = allocate_coding_hours(
        evidence_hours["own"], evidence_hours["coauthored"], evidence_hours["ai_only"])
    total_hours = allocation["your_coding"] + allocation["ai_coding"]
    overlap_discount_hours = max(raw_total_hours - total_hours, 0.0)
    rounded_total = round(total_hours, 1)
    rounded_your = round(allocation["your_coding"], 1)
    attributed_hours = {
        "your_coding": rounded_your,
        "ai_coding": round(rounded_total - rounded_your, 1),
    }

    rows = db.execute("SELECT source, COUNT(*), SUM(loc_add), SUM(loc_del), SUM(items) "
                      "FROM events GROUP BY source").fetchall()
    per_source = {r[0]: {"events": r[1], "loc_add": r[2] or 0,
                         "loc_del": r[3] or 0, "items": r[4] or 0} for r in rows}

    first = db.execute("SELECT MIN(ts_start), MAX(COALESCE(ts_end, ts_start)) FROM events").fetchone()
    days_active = agg["evidence_days"]
    streak = best_streak = 0
    prev = None
    for d in days_active:
        dt = datetime.strptime(d, "%Y-%m-%d").date()
        streak = streak + 1 if prev and (dt - prev).days == 1 else 1
        best_streak = max(best_streak, streak)
        prev = dt
    cur_streak = 0
    today = datetime.now().date()
    dset = {datetime.strptime(d, "%Y-%m-%d").date() for d in days_active}
    probe = today if today in dset else today - timedelta(days=1)
    while probe in dset:
        cur_streak += 1
        probe -= timedelta(days=1)

    yearly: dict[str, float] = {}
    for day, per in hours.items():
        yearly[day[:4]] = yearly.get(day[:4], 0.0) + sum(per.values())

    profile = builder_profile(db, agg, evidence_hours)
    analytics = workflow_analytics(
        db, agg, total_hours, allocation["ai_coding"], profile)
    session_count = db.execute(
        "SELECT COUNT(*) FROM events WHERE kind='session'").fetchone()[0]
    trajectory_receipts = sum(
        int((json.loads(row[0]) if row[0] else {}).get("trajectory_receipts", 0))
        for row in db.execute("SELECT meta FROM events WHERE kind='agent_receipts'"))
    generated_at = datetime.now().astimezone()
    first_attributable = db.execute(
        "SELECT ts_start FROM events "
        "WHERE kind IN ('session','commit','edit','remote_activity') "
        "AND project IS NOT NULL AND project NOT IN "
        "('misc','Unattributed workspace','-Users-kingjames','Users-kingjames') "
        "ORDER BY ts_start LIMIT 1").fetchone()
    first_attributable_day = None
    if first_attributable:
        first_ts = parse_iso(first_attributable[0])
        first_attributable_day = local_day(first_ts) if first_ts else None
    rhythm = activity_rhythm(
        days_active, generated_at.date().isoformat(), first_attributable_day)
    building_runs = [
        run["days"] for run in rhythm["runs"] if run["state"] == "building"]
    best_streak = max(building_runs, default=0)
    cur_streak = (
        rhythm["runs"][-1]["days"]
        if rhythm["runs"] and rhythm["runs"][-1]["state"] == "building" else 0)
    return {
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "total_hours": rounded_total,
        "raw_total_hours": round(raw_total_hours, 1),
        "overlap_discount_hours": round(overlap_discount_hours, 1),
        "overlap_discount_pct": round(
            100 * overlap_discount_hours / raw_total_hours, 1)
        if raw_total_hours else 0.0,
        "attributed_hours": attributed_hours,
        "coauthor_allocation": {
            "shared_hours": round(evidence_hours["coauthored"], 1),
            "your_base_hours": round(evidence_hours["own"], 1),
            "ai_base_hours": round(evidence_hours["ai_only"], 1),
            "your_share_pct": round(allocation["your_share"] * 100, 2),
            "ai_share_pct": round(allocation["ai_share"] * 100, 2),
        },
        "target_hours": TARGET_HOURS,
        "pct_to_target": round(100 * total_hours / TARGET_HOURS, 2),
        "remaining_hours": round(max(TARGET_HOURS - total_hours, 0), 1),
        "hours_by_source": {k: round(v, 1) for k, v in
                            sorted(total_by_source.items(), key=lambda x: -x[1])},
        "per_source": per_source,
        "net_loc": sum(agg["loc"].values()),
        "loc_added": sum(agg["loc_add"].values()),
        "github_loc_added": per_source.get("github", {}).get("loc_add", 0),
        "total_commits": per_source.get("git", {}).get("items", 0),
        "repositories_with_commits": db.execute(
            "SELECT COUNT(DISTINCT project) FROM events "
            "WHERE kind IN ('commit','remote_activity') AND project IS NOT NULL"
        ).fetchone()[0],
        "remote_commits": per_source.get("github", {}).get("items", 0),
        "sessions": session_count,
        "trajectory_receipts": trajectory_receipts,
        "active_days": rhythm["active_days"],
        "first_activity": first[0], "last_activity": first[1],
        "best_streak": best_streak, "current_streak": cur_streak,
        "activity_rhythm": rhythm,
        "yearly_hours": {k: round(v, 1) for k, v in sorted(yearly.items())},
        "top_projects": sorted(
            ({"project": p, **{k: round(v, 1) if isinstance(v, float) else v
                               for k, v in e.items()}}
             for p, e in agg["projects"].items()),
            key=lambda e: -(e["hours"] * 50 + e["loc_add"] / 1000))[:15],
        "profile": profile,
        "analytics": analytics,
        "_daily": agg,
    }


# ---------------------------------------------------------------- commands

def resolve_authors(db: sqlite3.Connection, cli_authors: str | None) -> list[str]:
    if cli_authors:
        meta_set(db, "authors", cli_authors)
        return cli_authors.split(",")
    saved = meta_get(db, "authors")
    if saved:
        return saved.split(",")
    guesses = []
    for key in ("user.name", "user.email"):
        rc = subprocess.run(["git", "config", "--global", key],
                            capture_output=True, text=True)
        if rc.returncode == 0 and rc.stdout.strip():
            guesses.append(rc.stdout.strip())
    if guesses:
        meta_set(db, "authors", ",".join(guesses))
    return guesses


def invalidate_source_cache(db: sqlite3.Connection, sources: list[str]) -> int:
    prefixes = {
        "claude": [HOME / ".claude" / "projects"],
        "codex": [HOME / ".codex" / "sessions"],
        "gemini": [HOME / ".gemini" / "tmp"],
        "antigravity": [
            HOME / "Library" / "Application Support" / "Antigravity",
            HOME / "Library" / "Application Support" / "Antigravity IDE",
        ],
        "grok": [Path(os.environ.get("GROK_HOME") or HOME / ".grok")],
        "cursor": [HOME / ".cursor",
                   HOME / "Library" / "Application Support" / "Cursor"],
        "vscode": [HOME / "Library" / "Application Support" / "Code"],
    }
    removed = 0
    for source in sources:
        for prefix in prefixes.get(source, []):
            cur = db.execute("DELETE FROM file_cache WHERE path LIKE ?",
                             (str(prefix) + "%",))
            removed += cur.rowcount
        if source == "aider":
            cur = db.execute(
                "DELETE FROM file_cache WHERE path LIKE '%/.aider.chat.history.md'")
            removed += cur.rowcount
    db.commit()
    return removed


def cmd_init(args) -> None:
    db = open_db(args.db)
    authors = resolve_authors(db, args.author)
    db.commit()
    say(f"{C_GREEN}✓ ledger initialized{C_RESET} at {args.db}")
    say(f"  authors: {', '.join(authors) or '(none — pass --author)'}")
    say(f"  next: python3 coding_ledger.py scan")


def cmd_scan(args) -> None:
    db = open_db(args.db)
    authors = resolve_authors(db, args.author)
    if not authors:
        warn("no author filter — pass --author \"Name,email\" (matching ALL commits otherwise)")
    sources = args.sources.split(",") if args.sources else ALL_SOURCES
    roots = [Path(r) for r in args.roots.split(",")] if args.roots else DEFAULT_ROOTS
    if args.reprocess_sessions:
        removed = invalidate_source_cache(db, sources)
        say(f"  reprocess: invalidated {removed} source cache entries")
    t0 = datetime.now().astimezone()
    cur = db.execute(
        "INSERT INTO scans(started_at,finished_at,sources,added,notes,status) "
        "VALUES(?,?,?,?,?,?)",
        (t0.isoformat(timespec="seconds"), None, ",".join(sources), 0, "", "running"))
    scan_id = cur.lastrowid
    db.commit()
    say(f"{C_BOLD}scan{C_RESET} sources={','.join(sources)}")
    total_added = 0
    all_notes: list[str] = []
    local_repo_names: set[str] = set()

    try:
        for s in sources:
            if s not in ALL_SOURCES:
                warn(f"unknown source: {s}")
                continue
            t = time.time()
            if s == "git":
                added, notes = scan_git(db, roots, authors, rediscover=args.rediscover,
                                        timeout=args.git_timeout)
                local_repo_names = {r[0].lower() for r in db.execute(
                    "SELECT DISTINCT project FROM events WHERE source='git'") if r[0]}
            elif s == "claude":
                added, notes = scan_claude(db)
            elif s == "codex":
                added, notes = scan_codex(db)
            elif s == "gemini":
                added, notes = scan_gemini(db)
            elif s == "antigravity":
                added, notes = scan_antigravity(db)
            elif s == "grok":
                added, notes = scan_grok(db)
            elif s == "cursor":
                added, notes = scan_cursor(db)
            elif s == "aider":
                added, notes = scan_aider(db, roots)
            elif s == "vscode":
                added, notes = scan_vscode(db)
            elif s == "github":
                if not local_repo_names:
                    local_repo_names = {r[0].lower() for r in db.execute(
                        "SELECT DISTINCT project FROM events WHERE source='git'") if r[0]}
                owners = (args.gh_owners or meta_get(db, "gh_owners") or "").split(",")
                owners = [o for o in owners if o]
                login = args.gh_login or meta_get(db, "gh_login") or ""
                if not owners or not login:
                    rc, out = _gh(["api", "user", "--jq", ".login"])
                    if rc == 0 and out.strip():
                        login = login or out.strip()
                        owners = owners or [login]
                if not owners:
                    warn("github: no owners resolved; skip (pass --gh-owners)")
                    continue
                meta_set(db, "gh_owners", ",".join(owners))
                meta_set(db, "gh_login", login)
                added, notes = scan_github(db, owners, login, local_repo_names)
            db.commit()
            total_added += added
            all_notes += notes
            db.execute("UPDATE scans SET added=?,notes=? WHERE id=?",
                       (total_added, "; ".join(all_notes)[-8000:], scan_id))
            db.commit()
            say(f"  {C_CYAN}{s}{C_RESET}: +{added} events ({time.time()-t:.1f}s)")
    except BaseException as exc:
        note = f"interrupted: {type(exc).__name__}"
        all_notes.append(note)
        db.execute("UPDATE scans SET finished_at=?,added=?,notes=?,status='interrupted' "
                   "WHERE id=?",
                   (datetime.now().astimezone().isoformat(timespec="seconds"),
                    total_added, "; ".join(all_notes)[-8000:], scan_id))
        db.commit()
        raise
    db.execute("UPDATE scans SET finished_at=?,added=?,notes=?,status='complete' WHERE id=?",
               (datetime.now().astimezone().isoformat(timespec="seconds"),
                total_added, "; ".join(all_notes)[-8000:], scan_id))
    db.commit()
    say(f"{C_GREEN}✓ scan complete{C_RESET}: +{total_added} events" +
        (f"  ({len(all_notes)} notes — see `status`)" if all_notes else ""))


def fmt_h(h: float) -> str:
    return f"{h:,.1f}h"


def has_complete_baseline(db: sqlite3.Connection) -> bool:
    required = set(ALL_SOURCES)
    for (sources,) in db.execute(
            "SELECT sources FROM scans WHERE status='complete' ORDER BY id DESC"):
        if required.issubset({source.strip() for source in (sources or "").split(",")}):
            return True
    return False


def cmd_status(args) -> None:
    db = open_db(args.db)
    s = summarize(db)
    bar_w = 40
    filled = min(int(bar_w * s["total_hours"] / s["target_hours"]), bar_w)
    bar = "█" * filled + "░" * (bar_w - filled)
    say(f"{C_BOLD}coding-ledger{C_RESET}  {args.db}")
    provisional = not has_complete_baseline(db)
    say(f"  {C_GREEN}{bar}{C_RESET} {fmt_h(s['total_hours'])} / {s['target_hours']:,}h "
        f"({s['pct_to_target']}%)")
    if provisional:
        say(f"  {C_YELLOW}PROVISIONAL — no complete all-source baseline is recorded{C_RESET}")
    say(f"  coding: yours {fmt_h(s['attributed_hours']['your_coding'])} · "
        f"AI {fmt_h(s['attributed_hours']['ai_coding'])}")
    allocation = s["coauthor_allocation"]
    say(f"  shared evidence: {fmt_h(allocation['shared_hours'])} allocated "
        f"{allocation['your_share_pct']}% yours / {allocation['ai_share_pct']}% AI")
    say(f"  raw source sum before overlap discount: {fmt_h(s['raw_total_hours'])}")
    say(f"  remaining to journeyman: {fmt_h(s['remaining_hours'])}")
    say("")
    for src, h in s["hours_by_source"].items():
        ev = s["per_source"].get(src, {})
        extra = f"  +{ev.get('loc_add', 0):,}/-{ev.get('loc_del', 0):,} LOC" \
            if ev.get("loc_add") else ""
        say(f"  {src:<8} {fmt_h(h):>10}   {ev.get('events', 0):>6} events{extra}")
    gh = s["per_source"].get("github")
    if gh and "github" not in s["hours_by_source"]:
        say(f"  {'github':<8} {'(LOC only)':>10}   {gh['events']:>6} events  "
            f"+{gh['loc_add']:,}/-{gh['loc_del']:,} LOC, {gh['items']:,} commits")
    say("")
    say(f"  local commits: {s['total_commits']:,}   net LOC: {s['net_loc']:,}   "
        f"sessions: {s['sessions']:,}")
    analytics = s["analytics"]
    say(f"  AI leverage: {analytics['ai_leverage_pct']}%   "
        f"top-project focus: {analytics['top_project_focus_pct']}%   "
        f"session→commit: {analytics['session_commit_conversion_pct']}%")
    say(f"  active days: {s['active_days']:,}   streak: {s['current_streak']}d "
        f"(best {s['best_streak']}d)")
    rhythm = s["activity_rhythm"]
    say(f"  building span: {rhythm['start_day'] or '?'} → "
        f"{rhythm['end_day'] or '?'}")
    last = db.execute("SELECT finished_at, sources, added, notes, status FROM scans "
                      "ORDER BY id DESC LIMIT 1").fetchone()
    if last:
        finished = (last[0] or "in progress")[:19]
        say(f"  last scan: {finished} [{last[1]}] +{last[2]} ({last[4]})")
        if last[3]:
            say(f"  {C_DIM}notes: {last[3][:300]}{C_RESET}")


def cmd_report(args) -> None:
    db = open_db(args.db)
    s = summarize(db)
    s.pop("_daily")
    if args.format == "json":
        say(json.dumps(s, indent=2))
        return
    L = []
    L.append(f"# Coding Ledger Report\n")
    L.append(f"*Generated {s['generated_at']}*\n")
    L.append(f"## Headline\n")
    L.append(f"- **Total proven hours: {s['total_hours']:,}** "
             f"({s['pct_to_target']}% of the {s['target_hours']:,}h journeyman target, "
             f"{s['remaining_hours']:,}h remaining)")
    L.append(f"- Coding score: **{s['attributed_hours']['your_coding']:,}h yours**, "
             f"**{s['attributed_hours']['ai_coding']:,}h AI**")
    allocation = s["coauthor_allocation"]
    L.append(f"- Shared-work allocation: **{allocation['shared_hours']:,}h** split "
             f"**{allocation['your_share_pct']}% yours / "
             f"{allocation['ai_share_pct']}% AI** from the base-hour ratio")
    L.append(f"- Raw per-source sum before overlap discount: **{s['raw_total_hours']:,}h**")
    L.append(f"- Timestamp-qualified concurrency discount: "
             f"**−{s['overlap_discount_hours']:,}h "
             f"({s['overlap_discount_pct']}%)**")
    L.append(f"- Local commits: **{s['total_commits']:,}** "
             f"(+{s['loc_added']:,} LOC added, net {s['net_loc']:,})")
    if s["remote_commits"]:
        L.append(f"- Remote-only GitHub commits: **{s['remote_commits']:,}** "
                 f"(+{s['github_loc_added']:,} LOC)")
    L.append(f"- AI-assisted sessions: **{s['sessions']:,}**")
    L.append(f"- AI leverage: **{s['analytics']['ai_leverage_pct']}%** of attributed time")
    L.append(f"- Active days: **{s['active_days']:,}** — current streak "
             f"{s['current_streak']}d, best {s['best_streak']}d")
    rhythm = s["activity_rhythm"]
    L.append(f"- Activity rhythm: **{rhythm['active_days']:,} building / "
             f"{rhythm['off_days']:,} off days** across "
             f"{rhythm['calendar_days']:,} calendar days "
             f"({rhythm['start_day']} → {rhythm['end_day']}); "
             f"{rhythm['streak_count']:,} building streaks, "
             f"{rhythm['longest_break_days']:,}d longest break")
    L.append("")
    L.append("## Hours by source\n")
    L.append("| Source | Hours | Events |")
    L.append("|--------|------:|-------:|")
    for src, h in s["hours_by_source"].items():
        L.append(f"| {src} | {h:,} | {s['per_source'].get(src, {}).get('events', 0):,} |")
    L.append("\n## Hours by year\n")
    L.append("| Year | Hours |")
    L.append("|------|------:|")
    for y, h in s["yearly_hours"].items():
        L.append(f"| {y} | {h:,} |")
    L.append("\n## Top projects\n")
    L.append("| Project | Hours | +LOC | -LOC |")
    L.append("|---------|------:|-----:|-----:|")
    for p in s["top_projects"]:
        L.append(f"| {p['project']} | {p['hours']:,} | {p['loc_add']:,} | {p['loc_del']:,} |")
    a = s["analytics"]
    L.append("\n## Workflow analytics\n")
    L.append(f"- Top-project focus: **{a['top_project_focus_pct']}%** across "
             f"**{a['active_projects']:,}** projects")
    L.append(f"- Project diversity index: **{a['project_diversity_pct']}%**")
    if a["multi_project_commit_change_pct"] is not None:
        direction = "more" if a["multi_project_commit_change_pct"] >= 0 else "fewer"
        L.append(f"- Multi-project days average **{abs(a['multi_project_commit_change_pct']):.1f}% "
                 f"{direction} commits** than single-project days "
                 f"({a['multi_project_days']} vs {a['single_project_days']} days)")
    L.append(f"- Verification density: **{a['verification_per_session']}** detected "
             f"test calls per AI session")
    L.append(f"- Parallel-agent dispatches: **{a['parallel_dispatches']:,}**")
    L.append(f"- Session-to-commit conversion: **{a['session_commit_conversion_pct']}%** "
             f"within {a['session_commit_window_days']} days "
             f"({a['session_commit_matches']:,}/{a['session_commit_eligible']:,} "
             "project-matchable sessions)")
    if a["median_session_to_commit_hours"] is not None:
        L.append(f"- Median session-to-commit lag: "
                 f"**{a['median_session_to_commit_hours']:,}h**")
    out = "\n".join(L) + "\n"
    if args.out:
        Path(args.out).write_text(out)
        say(f"{C_GREEN}✓ report written{C_RESET} to {args.out}")
    else:
        say(out)


def cmd_dashboard(args) -> None:
    db = open_db(args.db)
    s = summarize(db)
    s["scan_state"] = (db.execute(
        "SELECT status FROM scans ORDER BY id DESC LIMIT 1").fetchone() or ["provisional"])[0]
    s["completed_scans"] = 1 if has_complete_baseline(db) else 0
    daily = s.pop("_daily")
    html = render_dashboard(s, daily)
    out = Path(args.out) if args.out else DASHBOARD_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    say(f"{C_GREEN}✓ dashboard written{C_RESET} to {out}")
    landing_out = out.parent / "index.html"
    landing_out.write_text(render_landing(s))
    say(f"{C_GREEN}✓ landing page written{C_RESET} to {landing_out}")
    if args.open:
        subprocess.run(["open", str(landing_out)], check=False)


def chromium_executable() -> Path | None:
    candidates = [
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    ]
    installed = next((path for path in candidates if path.is_file()), None)
    if installed:
        return installed
    for name in ("google-chrome", "chromium", "chromium-browser", "msedge"):
        command = shutil.which(name)
        if command:
            return Path(command)
    return None


def default_builder_name() -> str:
    result = subprocess.run(
        ["git", "config", "--global", "user.name"],
        capture_output=True, text=True)
    return result.stdout.strip() or "Independent Builder"


def run_chromium_export(command: list[str], output: Path,
                        timeout_s: float = 20) -> bool:
    """Run headless Chromium until its artifact is complete, then stop its group."""
    output.unlink(missing_ok=True)
    process = subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    deadline = time.monotonic() + timeout_s
    last_size = -1
    stable_checks = 0
    try:
        while time.monotonic() < deadline:
            if output.is_file() and output.stat().st_size > 0:
                size = output.stat().st_size
                stable_checks = stable_checks + 1 if size == last_size else 0
                if stable_checks >= 2:
                    return True
                last_size = size
            if process.poll() is not None and not output.is_file():
                return False
            time.sleep(0.2)
        return False
    finally:
        # Chromium may let the parent exit while profile-writing children keep
        # the temporary user-data directory busy. Terminate the whole process
        # group even when the parent has already reported completion.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)


def cmd_export(args) -> None:
    """Generate public-safe HTML, PDF, and social-image scorecards locally."""
    db = open_db(args.db)
    summary = summarize(db)
    summary.pop("_daily")
    output_dir = Path(args.out_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    builder_name = (args.name or default_builder_name()).strip() or "Independent Builder"
    html_path = output_dir / "coding-ledger-scorecard.html"
    pdf_path = output_dir / "coding-ledger-scorecard.pdf"
    image_path = output_dir / "coding-ledger-linkedin.png"
    html_path.write_text(render_public_scorecard(summary, builder_name))

    browser = chromium_executable()
    if not browser:
        raise SystemExit("Chrome, Chromium, or Edge is required to render PDF and PNG exports")
    # Chrome profile helpers can briefly recreate lock files during shutdown.
    # The profile contains only disposable export state, so cleanup contention
    # must not turn successfully rendered artifacts into a failed command.
    with tempfile.TemporaryDirectory(
            prefix="coding-ledger-export-", ignore_cleanup_errors=True) as temp_root:
        common = [
            str(browser), "--headless=new", "--disable-gpu", "--hide-scrollbars",
            "--disable-background-networking", "--disable-component-update",
            "--no-first-run", "--disable-default-apps",
            "--run-all-compositor-stages-before-draw", "--virtual-time-budget=1500",
        ]
        pdf_ok = run_chromium_export(
            common + [f"--user-data-dir={temp_root}/pdf", "--no-pdf-header-footer",
                      f"--print-to-pdf={pdf_path}", html_path.as_uri()],
            pdf_path)
        image_ok = run_chromium_export(
            common + [f"--user-data-dir={temp_root}/image",
                      "--window-size=1200,1350", "--force-device-scale-factor=1",
                      f"--screenshot={image_path}", html_path.as_uri()],
            image_path)
    failures = [
        label for label, ok in (("PDF", pdf_ok), ("LinkedIn image", image_ok))
        if not ok]
    if failures:
        raise SystemExit(f"Export failed: {', '.join(failures)}")
    say(f"{C_GREEN}✓ public scorecard HTML{C_RESET}: {html_path}")
    say(f"{C_GREEN}✓ shareable PDF{C_RESET}: {pdf_path}")
    say(f"{C_GREEN}✓ LinkedIn image{C_RESET}: {image_path}")


def cmd_doctor(args) -> None:
    checks = [
        ("git repos", any(r.is_dir() for r in DEFAULT_ROOTS),
         ", ".join(str(r) for r in DEFAULT_ROOTS if r.is_dir())),
        ("claude", (HOME / ".claude" / "projects").is_dir(),
         f"{len(list((HOME / '.claude' / 'projects').rglob('*.jsonl')))} jsonl"
         if (HOME / ".claude" / "projects").is_dir() else "—"),
        ("codex", (HOME / ".codex" / "sessions").is_dir(),
         f"{len(list((HOME / '.codex' / 'sessions').rglob('*.jsonl')))} jsonl"
         if (HOME / ".codex" / "sessions").is_dir() else "—"),
        ("gemini", (HOME / ".gemini" / "tmp").is_dir(),
         f"{len(list((HOME / '.gemini' / 'tmp').glob('*/chats/session-*')))} sessions"
         if (HOME / ".gemini" / "tmp").is_dir() else "—"),
        ("antigravity", any((HOME / "Library" / "Application Support" / name).is_dir()
                            for name in ("Antigravity", "Antigravity IDE")),
         "editor history + opaque trajectory receipts"),
        ("grok build", (Path(os.environ.get("GROK_HOME") or HOME / ".grok")
                        / "sessions").is_dir(),
         f"{len(list((Path(os.environ.get('GROK_HOME') or HOME / '.grok') / 'sessions').rglob('events.jsonl')))} sessions"
         if (Path(os.environ.get("GROK_HOME") or HOME / ".grok") / "sessions").is_dir()
         else "—"),
        ("cursor transcripts", (HOME / ".cursor" / "projects").is_dir(), str(HOME / ".cursor")),
        ("cursor chats db", bool(list((HOME / ".cursor").glob("chats/**/store.db")))
         if (HOME / ".cursor").is_dir() else False, ""),
        ("aider", True, "scanned under roots at scan time"),
        ("vscode history", (HOME / "Library/Application Support/Code/User/History").is_dir(),
         ""),
        ("gh CLI", _gh(["auth", "status"])[0] == 0, "github source available"),
    ]
    say(f"{C_BOLD}coding-ledger doctor{C_RESET}")
    for name, ok, detail in checks:
        mark = f"{C_GREEN}✓{C_RESET}" if ok else f"{C_DIM}–{C_RESET}"
        say(f"  {mark} {name:<20} {detail}")
    say(f"  db: {args.db} ({'exists' if Path(args.db).exists() else 'not created yet'})")


PLIST_LABEL = "com.bmc-inc.coding-ledger"


def cmd_install_daemon(args) -> None:
    plist_path = HOME / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"
    script = Path(__file__).resolve()
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{PLIST_LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>{sys.executable}</string>
    <string>{script}</string>
    <string>scan</string>
  </array>
  <key>StartCalendarInterval</key><dict>
    <key>Hour</key><integer>{args.hour}</integer><key>Minute</key><integer>0</integer>
  </dict>
  <key>StandardOutPath</key><string>{LEDGER_DIR}/daemon.log</string>
  <key>StandardErrorPath</key><string>{LEDGER_DIR}/daemon.log</string>
</dict></plist>
"""
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(plist)
    subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
    rc = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
    if rc.returncode == 0:
        say(f"{C_GREEN}✓ daemon installed{C_RESET}: daily scan at {args.hour:02d}:00 "
            f"({plist_path})")
        say(f"  note: launchd calendar jobs skip while the Mac sleeps")
    else:
        warn(f"launchctl load failed: {rc.stderr.strip()}")


def cmd_uninstall_daemon(args) -> None:
    plist_path = HOME / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"
    subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
    if plist_path.exists():
        plist_path.unlink()
        say(f"{C_GREEN}✓ daemon removed{C_RESET}")
    else:
        say("no daemon installed")


# ---------------------------------------------------------------- dashboard

CHARTJS_VERSION = "4.5.1"
CHARTJS_SRI = "sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+6DChMTBJemed7ZnvJ"


def chartjs_tag() -> str:
    """Inline the vendored Chart.js (fully offline dashboard); SRI-pinned CDN fallback."""
    vendored = Path(__file__).resolve().parent / "vendor" / "chart.umd.min.js"
    if vendored.is_file():
        return f"<script>{vendored.read_text(errors='replace')}</script>"
    warn("vendor/chart.umd.min.js missing — dashboard will use the CDN (SRI-pinned)")
    return (f'<script src="https://cdn.jsdelivr.net/npm/chart.js@{CHARTJS_VERSION}'
            f'/dist/chart.umd.min.js" integrity="{CHARTJS_SRI}" '
            f'crossorigin="anonymous"></script>')


def _render_dashboard_legacy(s: dict, daily: dict) -> str:
    days = sorted(daily["hours"].keys())
    sources = list(s["hours_by_source"].keys())
    palette = {"claude": "#e07a5f", "git": "#81b29a", "cursor": "#f2cc8f",
               "aider": "#9b8ac4", "vscode": "#6a8caf", "github": "#b5838d"}
    stacked = {src: [round(daily["hours"][d].get(src, 0.0), 2) for d in days]
               for src in sources}
    loc_days = sorted(daily["loc_add"].keys())
    loc_series = [daily["loc_add"][d] for d in loc_days]
    cum, acc = [], 0.0
    for d in days:
        acc += sum(daily["hours"][d].values())
        cum.append(round(acc, 1))
    # monthly rollup for the all-time chart
    monthly: dict[str, float] = {}
    for d in days:
        monthly[d[:7]] = monthly.get(d[:7], 0.0) + sum(daily["hours"][d].values())
    months = sorted(monthly.keys())
    payload = json.dumps({
        "days": days, "stacked": stacked, "sources": sources, "palette": palette,
        "locDays": loc_days, "loc": loc_series, "cum": cum,
        "months": months, "monthly": [round(monthly[m], 1) for m in months],
        "bySource": s["hours_by_source"],
    }, separators=(",", ":"))
    cards = f"""
      <div class="card big"><div class="label">Total proven hours</div>
        <div class="value">{s['total_hours']:,}</div>
        <div class="sub">{s['pct_to_target']}% of {s['target_hours']:,}h · {s['remaining_hours']:,}h remaining</div>
        <div class="bar"><div class="fill" style="width:{min(s['pct_to_target'], 100)}%"></div></div></div>
      <div class="card"><div class="label">Local commits</div><div class="value">{s['total_commits']:,}</div>
        <div class="sub">+{s['loc_added']:,} LOC · net {s['net_loc']:,}</div></div>
      <div class="card"><div class="label">AI sessions</div><div class="value">{s['sessions']:,}</div>
        <div class="sub">Claude · Cursor · Aider</div></div>
      <div class="card"><div class="label">Active days</div><div class="value">{s['active_days']:,}</div>
        <div class="sub">streak {s['current_streak']}d · best {s['best_streak']}d</div></div>
      <div class="card"><div class="label">Span</div>
        <div class="value" style="font-size:1.3rem">{(s['first_activity'] or '?')[:10]}<br>→ {(s['last_activity'] or '?')[:10]}</div>
        <div class="sub">remote commits {s['remote_commits']:,}</div></div>"""
    proj_rows = "".join(
        f"<tr><td>{p['project']}</td><td>{p['hours']:,}</td>"
        f"<td>+{p['loc_add']:,}</td><td>-{p['loc_del']:,}</td></tr>"
        for p in s["top_projects"])
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>coding-ledger — {s['total_hours']:,}h proven</title>
{chartjs_tag()}
<style>
  :root {{ --bg:#12141a; --panel:#1a1d26; --ink:#e8e6e3; --dim:#8a8f9c; --accent:#81b29a; }}
  * {{ box-sizing:border-box; margin:0 }}
  body {{ background:var(--bg); color:var(--ink); font:15px/1.5 -apple-system,system-ui,sans-serif; padding:2rem }}
  h1 {{ font-size:1.5rem; margin-bottom:.25rem }}
  .gen {{ color:var(--dim); margin-bottom:1.5rem }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-bottom:1.5rem }}
  .card {{ background:var(--panel); border-radius:12px; padding:1.1rem }}
  .card.big {{ grid-column:span 2 }}
  .label {{ color:var(--dim); font-size:.8rem; text-transform:uppercase; letter-spacing:.06em }}
  .value {{ font-size:2rem; font-weight:700; margin:.2rem 0 }}
  .sub {{ color:var(--dim); font-size:.85rem }}
  .bar {{ height:8px; background:#2a2e3a; border-radius:4px; margin-top:.6rem; overflow:hidden }}
  .fill {{ height:100%; background:var(--accent) }}
  .panel {{ background:var(--panel); border-radius:12px; padding:1.2rem; margin-bottom:1.2rem }}
  .panel h2 {{ font-size:1rem; color:var(--dim); margin-bottom:.8rem }}
  .row {{ display:grid; grid-template-columns:2fr 1fr; gap:1.2rem }}
  table {{ width:100%; border-collapse:collapse; font-size:.9rem }}
  td,th {{ padding:.35rem .6rem; text-align:right; border-bottom:1px solid #262a35 }}
  td:first-child,th:first-child {{ text-align:left }}
  @media (max-width:900px) {{ .row {{ grid-template-columns:1fr }} .card.big {{ grid-column:span 1 }} }}
</style></head><body>
<h1>coding-ledger</h1>
<div class="gen">receipts over assurances · generated {s['generated_at']} · all data local</div>
<div class="cards">{cards}</div>
<div class="panel"><h2>Daily hours by source (last 180 days)</h2><canvas id="daily" height="90"></canvas></div>
<div class="row">
  <div class="panel"><h2>All-time monthly hours</h2><canvas id="monthly" height="110"></canvas></div>
  <div class="panel"><h2>Hours by source</h2><canvas id="doughnut" height="110"></canvas></div>
</div>
<div class="row">
  <div class="panel"><h2>Cumulative hours → {TARGET_HOURS:,}</h2><canvas id="cum" height="110"></canvas></div>
  <div class="panel"><h2>Daily LOC added (last 180 days)</h2><canvas id="loc" height="110"></canvas></div>
</div>
<div class="panel"><h2>Top projects</h2>
<table><tr><th>Project</th><th>Hours</th><th>+LOC</th><th>-LOC</th></tr>{proj_rows}</table></div>
<script>
const D = {payload};
Chart.defaults.color = "#8a8f9c"; Chart.defaults.borderColor = "#262a35";
const tail = (a, n) => a.slice(-n);
const cut = D.days.length > 180 ? D.days.length - 180 : 0;
new Chart(document.getElementById("daily"), {{ type:"bar",
  data: {{ labels: tail(D.days,180), datasets: D.sources.map(s => ({{
    label:s, data: D.stacked[s].slice(cut), backgroundColor: D.palette[s]||"#888", stack:"h" }})) }},
  options: {{ scales: {{ x:{{stacked:true,ticks:{{maxTicksLimit:12}}}}, y:{{stacked:true,title:{{display:true,text:"hours"}}}} }} }} }});
new Chart(document.getElementById("monthly"), {{ type:"bar",
  data: {{ labels: D.months, datasets: [{{ label:"hours", data:D.monthly, backgroundColor:"#81b29a" }}] }},
  options: {{ plugins:{{legend:{{display:false}}}}, scales:{{x:{{ticks:{{maxTicksLimit:14}}}}}} }} }});
new Chart(document.getElementById("doughnut"), {{ type:"doughnut",
  data: {{ labels: Object.keys(D.bySource), datasets:[{{ data:Object.values(D.bySource),
    backgroundColor: Object.keys(D.bySource).map(s=>D.palette[s]||"#888"), borderWidth:0 }}] }} }});
new Chart(document.getElementById("cum"), {{ type:"line",
  data: {{ labels: D.days, datasets: [{{ label:"cumulative h", data:D.cum, borderColor:"#e07a5f",
    pointRadius:0, tension:.2, fill:false }}] }},
  options: {{ plugins:{{legend:{{display:false}}}}, scales:{{x:{{ticks:{{maxTicksLimit:10}}}}}} }} }});
new Chart(document.getElementById("loc"), {{ type:"line",
  data: {{ labels: tail(D.locDays,180), datasets: [{{ label:"LOC added", data:tail(D.loc,180),
    borderColor:"#6a8caf", pointRadius:0, tension:.2 }}] }},
  options: {{ plugins:{{legend:{{display:false}}}}, scales:{{x:{{ticks:{{maxTicksLimit:12}}}}, y:{{type:"logarithmic"}}}} }} }});
</script></body></html>
"""


def render_landing(s: dict) -> str:
    """Render the local product landing page without exposing project details."""
    analytics = s["analytics"]
    source_names = {
        "git": "Git", "claude": "Claude Code", "codex": "Codex",
        "gemini": "Gemini", "antigravity": "Antigravity", "grok": "Grok Build",
        "cursor": "Cursor", "aider": "Aider", "vscode": "VS Code",
        "github": "GitHub",
    }
    source_chips = "".join(
        f"<span>{html.escape(source_names[source])}</span>" for source in ALL_SOURCES)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coding Ledger — Prove how you build</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='12' fill='%23d7ff52'/%3E%3Cpath d='M18 18h28v7H25v14h21v7H18z' fill='%23131c18'/%3E%3C/svg%3E">
<style>
:root{{--ink:#131c18;--paper:#f4f0e5;--acid:#d7ff52;--orange:#ff6b3d;--blue:#18344c;--muted:#68716b}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--paper);color:var(--ink);
font:15px/1.6 "SFMono-Regular","Cascadia Mono","Liberation Mono",monospace}}
a{{color:inherit}}.wrap{{max-width:1240px;margin:auto;padding:0 28px}}nav{{height:78px;display:flex;align-items:center;
justify-content:space-between;border-bottom:1px solid var(--ink)}}.brand{{font-weight:900;letter-spacing:-.05em;font-size:1.2rem}}
.navlinks{{display:flex;gap:24px;align-items:center}}.navlinks a{{text-decoration:none}}.button{{display:inline-block;background:var(--acid);
border:1px solid var(--ink);box-shadow:4px 4px 0 var(--ink);padding:11px 16px;text-decoration:none;font-weight:800}}
.button.dark{{background:var(--ink);color:white}}.hero{{min-height:720px;display:grid;grid-template-columns:1.45fr .8fr;
gap:70px;align-items:center;padding:90px 0}}.kicker{{text-transform:uppercase;letter-spacing:.17em;font-size:11px}}
h1,h2,h3,p{{margin-top:0}}h1,h2,h3{{font-family:"Iowan Old Style","Palatino Linotype",serif}}h1{{font-size:clamp(4rem,8vw,8rem);
line-height:.82;letter-spacing:-.07em;margin:28px 0}}h1 em{{font-style:normal;color:var(--orange)}}.lede{{font-size:1.1rem;
max-width:660px;color:#44504a}}.actions{{display:flex;gap:14px;margin-top:32px;flex-wrap:wrap}}.proof{{background:var(--blue);
color:white;padding:28px;border:1px solid var(--ink);box-shadow:10px 10px 0 var(--acid);transform:rotate(1deg)}}
.proof .big{{font:900 5.5rem/.9 "Iowan Old Style","Palatino Linotype",serif;letter-spacing:-.06em;margin:22px 0}}
.proof dl{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:26px 0 0}}.proof dt{{color:#aebdc5;font-size:11px;
text-transform:uppercase;letter-spacing:.1em}}.proof dd{{margin:3px 0;font-size:1.25rem;font-weight:800}}section.block{{padding:90px 0;
border-top:2px solid var(--ink)}}.section-head{{display:grid;grid-template-columns:1fr 1fr;gap:60px;margin-bottom:40px}}
h2{{font-size:clamp(2.5rem,5vw,5rem);line-height:.92;letter-spacing:-.05em}}.grid3{{display:grid;grid-template-columns:repeat(3,1fr);
gap:16px}}.card{{border:1px solid var(--ink);padding:24px;min-height:250px;background:#faf7ef;box-shadow:5px 5px 0 var(--ink)}}
.card b{{display:block;font:800 2rem/1 "Iowan Old Style","Palatino Linotype",serif;margin:20px 0}}.card p,.section-copy{{color:var(--muted)}}
.sources{{display:flex;flex-wrap:wrap;gap:9px}}.sources span{{border:1px solid var(--ink);padding:8px 11px;background:#fff}}
.privacy{{background:var(--ink);color:white}}.privacy .section-copy{{color:#b9c4bf}}.rule-list{{list-style:none;padding:0;margin:0;
display:grid;grid-template-columns:1fr 1fr;gap:10px}}.rule-list li{{border-top:1px solid #607068;padding:14px 0}}
.rule-list li::before{{content:"✓";color:var(--acid);margin-right:10px}}.closing{{text-align:center;padding:110px 0}}.closing h2{{max-width:900px;
margin:0 auto 30px}}footer{{border-top:1px solid var(--ink);padding:24px 0;display:flex;justify-content:space-between;color:var(--muted)}}
@media(max-width:800px){{.wrap{{padding:0 17px}}.navlinks a:not(.button){{display:none}}.hero,.section-head{{grid-template-columns:1fr}}
.hero{{padding:65px 0;gap:45px}}.grid3{{grid-template-columns:1fr}}.rule-list{{grid-template-columns:1fr}}h1{{font-size:4rem}}
.proof .big{{font-size:4rem}}footer{{gap:20px;flex-direction:column}}}}
</style></head><body>
<div class="wrap"><nav><div class="brand">CODING LEDGER</div><div class="navlinks">
<a href="#use-cases">Use cases</a><a href="#evidence">Evidence</a><a href="#privacy">Privacy</a>
<a class="button" href="dashboard.html">Open report →</a></div></nav>
<main><section class="hero"><div><div class="kicker">Local-first development intelligence</div>
<h1>Prove how<br>you <em>build.</em></h1>
<p class="lede">Turn Git history, coding-agent sessions, and editor activity into a transparent,
auditable account of your work—without uploading prompts, source code, secrets, or tool output.</p>
<div class="actions"><a class="button" href="dashboard.html">Open the field report →</a>
<a class="button dark" href="#evidence">See how it works</a></div></div>
<aside class="proof"><div class="kicker">Live local ledger</div><div class="big">{s['total_hours']:,}h</div>
<p>Deduplicated evidence after a {s['overlap_discount_pct']}% timestamp-qualified concurrency discount.</p><dl>
<div><dt>Commits</dt><dd>{s['total_commits']:,}</dd></div>
<div><dt>AI sessions</dt><dd>{s['sessions']:,}</dd></div>
<div><dt>AI leverage</dt><dd>{analytics['ai_leverage_pct']}%</dd></div>
<div><dt>Active days</dt><dd>{s['active_days']:,}</dd></div></dl></aside></section>

<section class="block" id="use-cases"><div class="section-head"><h2>Receipts over assurances.</h2>
<p class="section-copy">Coding Ledger is built for people and teams that want evidence of sustained
building, effective AI adoption, verification habits, and delivery—not a hidden productivity score.</p></div>
<div class="grid3"><article class="card"><div class="kicker">01 / Builders</div><b>A verified portfolio</b>
<p>Show how you work across projects, tools, and time without publishing private repositories.</p></article>
<article class="card"><div class="kicker">02 / Applicants</div><b>Evidence for diligence</b>
<p>Give accelerators, investors, and clients a transparent view of cadence, focus, and shipping behavior.</p></article>
<article class="card"><div class="kicker">03 / Teams</div><b>AI adoption that is measurable</b>
<p>Understand tool usage, agent leverage, testing loops, and delivery conversion with explicit formulas.</p></article></div></section>

<section class="block" id="evidence"><div class="section-head"><h2>One ledger.<br>Every workflow.</h2>
<div><p class="section-copy">Adapters normalize local metadata into reproducible events. Growing sessions
are replaced idempotently and interrupted scans remain explicitly labeled.</p><div class="sources">{source_chips}</div></div></div>
<div class="grid3"><article class="card"><div class="kicker">Attribution</div><b>Your Coding / AI Coding</b>
<p>Shared work is allocated using the measured ratio of human-only and AI-only base evidence.</p></article>
<article class="card"><div class="kicker">Performance evidence</div><b>{analytics['session_commit_conversion_pct']}% conversion</b>
<p>Project-matchable agent sessions followed by a commit within seven days. Correlation, not a quality claim.</p></article>
<article class="card"><div class="kicker">Portfolio signal</div><b>{analytics['top_project_focus_pct']}% top focus</b>
<p>See project diversity, concentration, active projects, streaks, and sustained delivery over time.</p></article></div></section>

<section class="block privacy" id="privacy"><div class="section-head"><h2>Private by architecture.</h2>
<p class="section-copy">The free core runs locally with Python and SQLite. Raw work stays on the machine;
the generated report works offline.</p></div><ul class="rule-list"><li>No prompt bodies</li><li>No assistant responses</li>
<li>No source-code storage</li><li>No tool arguments or output</li><li>No credentials or environment values</li>
<li>No model-generated personality judgment</li></ul></section>

<section class="closing"><div class="kicker">The builder field report</div>
<h2>Activity is measured.<br>Performance is evidenced through outcomes.</h2>
<a class="button" href="dashboard.html">Open the field report →</a></section></main>
<footer><span>CODING LEDGER / OPEN CORE</span><span>ALL DATA LOCAL · GENERATED {html.escape(s['generated_at'][:10])}</span></footer>
</div></body></html>"""


def render_dashboard(s: dict, daily: dict) -> str:
    """Render an offline, evidence-first builder field report."""
    days = sorted(daily["hours"])
    sources = list(s["hours_by_source"])
    palette = {
        "claude": "#f4a261", "codex": "#e76f51", "git": "#2a9d8f",
        "cursor": "#e9c46a", "aider": "#9b5de5", "vscode": "#4cc9f0",
        "gemini": "#4285f4", "antigravity": "#7b61ff", "grok": "#111111",
        "github": "#8d99ae",
    }
    stacked = {source: [round(daily["hours"][day].get(source, 0), 2) for day in days]
               for source in sources}
    evidence_totals = {
        key: sum(daily["attributed"].get(day, {}).get(key, 0) for day in days)
        for key in ("own", "coauthored", "ai_only")
    }
    allocation = allocate_coding_hours(
        evidence_totals["own"], evidence_totals["coauthored"], evidence_totals["ai_only"])
    attributed = {"your_coding": [], "ai_coding": []}
    for day in days:
        evidence = daily["attributed"].get(day, {})
        shared = evidence.get("coauthored", 0)
        attributed["your_coding"].append(round(
            evidence.get("own", 0) + shared * allocation["your_share"], 2))
        attributed["ai_coding"].append(round(
            evidence.get("ai_only", 0) + shared * allocation["ai_share"], 2))
    profile = s["profile"]
    payload = json.dumps({
        "days": days, "sources": sources, "stacked": stacked, "palette": palette,
        "attributed": attributed, "bySource": s["hours_by_source"],
        "dimensions": profile["dimensions"],
        "attributionTotals": s["attributed_hours"],
    }, separators=(",", ":"))
    tier_icons = {"bronze": "I", "silver": "II", "gold": "III",
                  "platinum": "IV", "locked": "—"}
    badge_cards = "".join(
        f"""<article class="badge {b['tier']}">
          <div class="badge-mark">{tier_icons[b['tier']]}</div>
          <div><div class="eyebrow">{html.escape(b['tier'])}</div>
          <h3>{html.escape(b['name'])}</h3>
          <p>{b['value']:,} {html.escape(b['unit'])}</p>
          <small>{'earned' if b['next'] is None else f"next at {b['next']:,}"}</small></div>
        </article>""" for b in profile["badges"])
    project_rows = "".join(
        f"<tr><td>{html.escape(p['project'])}</td><td>{p['hours']:,}</td>"
        f"<td>+{p['loc_add']:,}</td><td>-{p['loc_del']:,}</td></tr>"
        for p in s["top_projects"])
    scan_label = "verified" if s.get("completed_scans", 0) else "provisional"
    analytics = s["analytics"]
    lag = (f"{analytics['median_session_to_commit_hours']:,}h median lag"
           if analytics["median_session_to_commit_hours"] is not None
           else "lag unavailable")
    commit_change = analytics["multi_project_commit_change_pct"]
    if commit_change is None:
        diversity_momentum = "Not enough single-project history for a comparison."
    else:
        direction = "more" if commit_change >= 0 else "fewer"
        diversity_momentum = (
            f"Multi-project workflow days average {analytics['multi_project_commits_per_day']:.2f} "
            f"commits versus {analytics['single_project_commits_per_day']:.2f} on single-project "
            f"days—{abs(commit_change):.1f}% {direction} "
            f"({analytics['multi_project_days']:,} vs "
            f"{analytics['single_project_days']:,} days).")
    analytics_cards = f"""
      <article class="insight"><div class="eyebrow">AI leverage</div>
        <strong>{analytics['ai_leverage_pct']}%</strong>
        <p>AI Coding as a share of attributed time.</p></article>
      <article class="insight"><div class="eyebrow">Project focus</div>
        <strong>{analytics['top_project_focus_pct']}%</strong>
        <p>Time concentrated in the leading project; {analytics['active_projects']:,} active projects.</p></article>
      <article class="insight"><div class="eyebrow">Verification loop</div>
        <strong>{analytics['verification_per_session']}</strong>
        <p>Detected test calls per AI session.</p></article>
      <article class="insight"><div class="eyebrow">Session → commit</div>
        <strong>{analytics['session_commit_conversion_pct']}%</strong>
        <p>Converted within {analytics['session_commit_window_days']} days · {lag}.</p></article>
      <article class="insight"><div class="eyebrow">Parallel work</div>
        <strong>{analytics['parallel_dispatches']:,}</strong>
        <p>Evidence-backed agent and subagent dispatches.</p></article>
      <article class="insight"><div class="eyebrow">Project diversity</div>
        <strong>{analytics['project_diversity_pct']}%</strong>
        <p>Expansive portfolio breadth using an inverse concentration index. Neutral by design.</p></article>
      <article class="insight"><div class="eyebrow">Diversity momentum</div>
        <strong>{'+' if commit_change is not None and commit_change >= 0 else ''}{commit_change if commit_change is not None else 'N/A'}{'%' if commit_change is not None else ''}</strong>
        <p>{html.escape(diversity_momentum)}</p></article>"""
    rhythm = s["activity_rhythm"]
    rhythm_segments = "".join(
        f'<span class="run {run["state"]}" style="flex-grow:{run["days"]}" '
        f'title="{run["start"]} to {run["end"]}: {run["days"]} '
        f'{"building" if run["state"] == "building" else "off"} days"></span>'
        for run in rhythm["runs"])
    recent_runs = rhythm["runs"][-9:]
    recent_rhythm = " → ".join(
        f'{run["days"]} {"on" if run["state"] == "building" else "off"}'
        for run in recent_runs)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coding Ledger — Builder Field Report</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%23d8ff4f'/%3E%3Ctext x='13' y='45' font-size='40'%3EC%3C/text%3E%3C/svg%3E">
{chartjs_tag()}
<style>
:root{{--paper:#f0eadb;--ink:#17211d;--muted:#6d7167;--rule:#b9b39f;--acid:#d8ff4f;
--red:#e76f51;--green:#2a9d8f;--navy:#16324f;--panel:#e6dfce}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--paper);color:var(--ink);
font:14px/1.55 "SFMono-Regular","Cascadia Mono","Liberation Mono",monospace;background-image:linear-gradient(rgba(23,33,29,.045) 1px,transparent 1px);
background-size:100% 28px}} main{{max-width:1480px;margin:auto;padding:28px;overflow:hidden}}
h1,h2,h3,p{{margin:0}} h1,h2{{font-family:"Iowan Old Style","Palatino Linotype",Palatino,serif}} h1{{font-size:clamp(3.4rem,9vw,9rem);
line-height:.79;letter-spacing:-.06em;max-width:1050px}} .topline{{display:flex;justify-content:space-between;
border-top:2px solid var(--ink);border-bottom:1px solid var(--ink);padding:8px 0;margin-bottom:34px}}
.eyebrow{{text-transform:uppercase;letter-spacing:.14em;font-size:10px;font-weight:500}} .status{{background:var(--acid);
padding:2px 8px;border:1px solid var(--ink)}} .hero{{display:grid;grid-template-columns:2.2fr 1fr;gap:40px;
align-items:end;border-bottom:3px solid var(--ink);padding-bottom:30px}} .archetype{{border-left:1px solid var(--ink);padding-left:24px}}
.archetype strong{{font:800 2.2rem/1 "Iowan Old Style","Palatino Linotype",serif;display:block;margin:8px 0 12px}}
.ledger-grid{{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin:18px 0}}
.metric,.panel,.badge{{border:1px solid var(--ink);background:rgba(240,234,219,.9);box-shadow:4px 4px 0 var(--ink);min-width:0}}
.metric{{grid-column:span 3;padding:18px;min-height:145px;position:relative;overflow:hidden}}
.metric.wide{{grid-column:span 6;background:var(--navy);color:#fff}} .metric .number{{font:800 clamp(2.2rem,5vw,5rem)/1 "Iowan Old Style","Palatino Linotype",serif;
letter-spacing:-.05em;margin:12px 0}} .metric small{{color:var(--muted)}} .metric.wide small{{color:#b9c4c8}}
.duo{{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:18px}} .duo div{{border-top:1px solid #80909a;padding-top:9px}}
.duo b{{font-size:1.3rem;display:block}} .panel{{padding:20px;margin-bottom:16px}} .panel h2{{font-size:1.6rem;margin-bottom:16px}}
.two{{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:16px}} .chartbox{{height:320px;min-width:0;max-width:100%}}
.chartbox canvas{{max-width:100%!important}} .chart-note{{border-top:1px solid var(--rule);margin-top:14px;padding-top:12px;
color:var(--muted);font-size:11px;line-height:1.6}} .chart-note b{{color:var(--ink);font-weight:600}} .badges{{display:grid;
grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}} .badge{{display:flex;gap:15px;padding:15px;min-height:130px}}
.insights{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}} .insight{{border-top:2px solid var(--ink);padding:15px 2px}}
.insight strong{{font:800 2.4rem/1 "Iowan Old Style","Palatino Linotype",serif;display:block;margin:10px 0}}
.insight p{{color:var(--muted);max-width:34ch}}
.rhythm-stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}}
.rhythm-stat{{border-top:2px solid;padding-top:10px}} .rhythm-stat b{{display:block;font:700 1.8rem "Iowan Old Style",serif}}
.rhythm-stat span,.rhythm-copy{{font-size:11px;color:var(--muted)}} .rhythm-bar{{display:flex;height:28px;border:1px solid var(--ink);
background:repeating-linear-gradient(135deg,transparent,transparent 4px,rgba(23,33,29,.08) 4px,rgba(23,33,29,.08) 8px)}}
.run{{min-width:1px}} .run.building{{background:var(--navy)}} .run.off{{background:transparent}}
.rhythm-legend{{display:flex;gap:18px;margin:10px 0}} .rhythm-legend span::before{{content:"";display:inline-block;width:11px;height:11px;
border:1px solid;margin-right:6px;vertical-align:-1px}} .rhythm-legend .on::before{{background:var(--navy)}}
.rhythm-legend .off::before{{background:repeating-linear-gradient(135deg,transparent,transparent 2px,rgba(23,33,29,.18) 2px,rgba(23,33,29,.18) 4px)}}
.badge-mark{{width:48px;height:48px;display:grid;place-items:center;border:1px solid var(--ink);border-radius:50%;font-weight:500}}
.badge h3{{font:600 1.2rem "Iowan Old Style","Palatino Linotype",serif;margin:3px 0 8px}} .badge p,.badge small{{color:var(--muted)}}
.badge.locked{{opacity:.46;box-shadow:none}} .badge.gold .badge-mark{{background:#e9c46a}} .badge.platinum .badge-mark{{background:var(--acid)}}
.badge.silver .badge-mark{{background:#d4d8d5}} .badge.bronze .badge-mark{{background:#c88b62}}
table{{width:100%;border-collapse:collapse;table-layout:fixed}} th,td{{padding:8px;border-bottom:1px solid var(--rule);text-align:right;overflow-wrap:anywhere}}
th:first-child,td:first-child{{text-align:left}} .method{{font-size:12px;color:var(--muted);max-width:900px}}
footer{{display:flex;justify-content:space-between;border-top:2px solid var(--ink);padding-top:10px;margin-top:30px}}
@media(max-width:900px){{main{{padding:16px}}.hero,.two{{grid-template-columns:1fr}}.archetype{{border-left:0;border-top:1px solid;padding:18px 0 0}}
.metric,.metric.wide{{grid-column:span 12}}.insights{{grid-template-columns:1fr}}.rhythm-stats{{grid-template-columns:repeat(2,1fr)}}
h1{{font-size:4rem}}.topline{{gap:10px;flex-wrap:wrap}}}}
</style></head><body><main>
<div class="topline"><span>CODING LEDGER / BUILDER FIELD REPORT</span>
<span>{html.escape(s['generated_at'])}</span><span class="status">{scan_label.upper()}</span></div>
<section class="hero"><div><div class="eyebrow">Receipts over assurances</div>
<h1>HOW YOU<br>ACTUALLY BUILD.</h1></div>
<div class="archetype"><div class="eyebrow">Dominant archetype</div>
<strong>{html.escape(profile['archetype'])}</strong>
<p>{html.escape(profile['archetype_reason'])}</p>
<p class="method">Growth edge: {html.escape(profile['growth_edge'])}</p></div></section>
<section class="ledger-grid">
<article class="metric wide"><div class="eyebrow">Deduplicated attributed time</div>
<div class="number">{s['total_hours']:,}h</div>
<small>Raw source sum {s['raw_total_hours']:,}h · −{s['overlap_discount_hours']:,}h ({s['overlap_discount_pct']}%) timestamp-qualified concurrency discount</small>
<div class="duo"><div><span>Your Coding</span><b>{s['attributed_hours']['your_coding']:,}h</b></div>
<div><span>AI Coding</span><b>{s['attributed_hours']['ai_coding']:,}h</b></div></div></article>
<article class="metric"><div class="eyebrow">Commits</div><div class="number">{s['total_commits']:,}</div>
<small>+{s['loc_added']:,} LOC · net {s['net_loc']:,}</small></article>
<article class="metric"><div class="eyebrow">AI sessions</div><div class="number">{s['sessions']:,}</div>
<small>Claude · Codex · Gemini · Grok · Cursor · Aider</small></article>
</section>
<article class="panel"><h2>Workflow analytics</h2><div class="insights">{analytics_cards}</div></article>
<article class="panel"><h2>Building rhythm</h2><div class="rhythm-stats">
<div class="rhythm-stat"><b>{rhythm['calendar_days']:,}</b><span>calendar days</span></div>
<div class="rhythm-stat"><b>{rhythm['active_days']:,}</b><span>building days</span></div>
<div class="rhythm-stat"><b>{rhythm['off_days']:,}</b><span>off days</span></div>
<div class="rhythm-stat"><b>{rhythm['streak_count']:,}</b><span>building streaks</span></div>
<div class="rhythm-stat"><b>{rhythm['longest_break_days']:,}d</b><span>longest break</span></div></div>
<div class="rhythm-bar" role="img" aria-label="{rhythm['active_days']} building days and {rhythm['off_days']} off days from first attributable project activity on {rhythm['start_day']} through report day {rhythm['end_day']}">{rhythm_segments}</div>
<div class="rhythm-legend"><span class="on">Building</span><span class="off">Off</span></div>
<p class="rhythm-copy"><b>{rhythm['start_day']} → {rhythm['end_day']}:</b> first attributable project activity through report day. <b>Recent sequence:</b> {html.escape(recent_rhythm)}</p></article>
<section class="two"><article class="panel"><h2>Attributed work, over time</h2><div class="chartbox"><canvas id="attr"></canvas></div></article>
<article class="panel"><h2>Builder dimensions</h2><div class="chartbox"><canvas id="radar"></canvas></div></article></section>
<article class="panel"><h2>Earned field badges</h2><div class="badges">{badge_cards}</div></article>
<section class="two"><article class="panel"><h2>Raw hours by source</h2><div class="chartbox"><canvas id="source"></canvas></div>
<p class="chart-note"><b>How to read this:</b> these are independent evidence streams before concurrency removal, so they do not add up to the attributed headline. Agent time uses timestamped sessions with a 30-minute idle break and one-minute floor. Git uses a daily commit-density proxy capped at six hours; editor history uses two minutes per edit capped at 90 minutes. GitHub aggregates add commits and LOC, never hours.</p></article>
<article class="panel"><h2>Top projects</h2><table><thead><tr><th>Project</th><th>Hours</th><th>+LOC</th><th>-LOC</th></tr></thead>
<tbody>{project_rows}</tbody></table></article></section>
<article class="panel method"><h2>How attribution works</h2><p>The scorecard has two categories: Your Coding and AI Coding.
Shared work is allocated between them using the ratio of measured human-only to AI-only base hours ({s['coauthor_allocation']['your_share_pct']}% yours / {s['coauthor_allocation']['ai_share_pct']}% AI).
Only AI activity inside the ten-minute window after an explicit human steering turn is eligible to overlap human Git/editor evidence. Independently running AI time remains additive; sources without steering detail default conservatively to shared work. GitHub aggregates add commits and LOC but never synthetic hours. Badge thresholds are visible and reproducible.
Transcript bodies, prompts, secrets, and tool output are not stored.</p></article>
<footer><span>ALL DATA LOCAL</span><span>{s['active_days']} ACTIVE DAYS / BEST STREAK {s['best_streak']}D</span></footer>
</main><script>
const D={payload}; Chart.defaults.color="#4f574f"; Chart.defaults.font.family='"SFMono-Regular",monospace';
Chart.defaults.borderColor="#b9b39f";
new Chart(document.getElementById("attr"),{{type:"bar",data:{{labels:D.days,datasets:[
{{label:"Your Coding",data:D.attributed.your_coding,backgroundColor:"#2a9d8f",stack:"a"}},
{{label:"AI Coding",data:D.attributed.ai_coding,backgroundColor:"#e76f51",stack:"a"}}]}},
options:{{maintainAspectRatio:false,scales:{{x:{{stacked:true,ticks:{{maxTicksLimit:12}}}},y:{{stacked:true}}}}}}}});
new Chart(document.getElementById("radar"),{{type:"radar",data:{{labels:Object.keys(D.dimensions),
datasets:[{{data:Object.values(D.dimensions),backgroundColor:"rgba(216,255,79,.38)",borderColor:"#17211d",pointBackgroundColor:"#17211d"}}]}},
options:{{maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{r:{{min:0,max:100,ticks:{{display:false}}}}}}}}}});
new Chart(document.getElementById("source"),{{type:"doughnut",data:{{labels:Object.keys(D.bySource),
datasets:[{{data:Object.values(D.bySource),backgroundColor:Object.keys(D.bySource).map(s=>D.palette[s]||"#8d99ae"),borderColor:"#f0eadb"}}]}},
options:{{maintainAspectRatio:false,cutout:"62%"}}}});
</script></body></html>"""


def render_public_scorecard(s: dict, builder_name: str) -> str:
    """Render a public-safe scorecard without project or repository names."""
    a = s["analytics"]
    rhythm = s["activity_rhythm"]
    profile = s["profile"]
    earned = [badge for badge in profile["badges"] if badge["tier"] != "locked"]
    badge_names = " · ".join(badge["name"] for badge in earned[:6]) or "Evidence building"
    generated = s["generated_at"][:10]
    momentum = a["multi_project_commit_change_pct"]
    momentum_text = (
        f"{'+' if momentum >= 0 else ''}{momentum}%"
        if momentum is not None else "N/A")
    recent_rhythm = " → ".join(
        f'{run["days"]} {"on" if run["state"] == "building" else "off"}'
        for run in rhythm["runs"][-7:])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(builder_name)} — Coding Ledger Scorecard</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%23d8ff4f'/%3E%3Ctext x='13' y='45' font-size='40'%3EC%3C/text%3E%3C/svg%3E">
<style>
@page{{size:letter portrait;margin:0}} *{{box-sizing:border-box}}
:root{{--paper:#f0eadb;--ink:#17211d;--muted:#17211d;--acid:#d8ff4f;--navy:#16324f;--rule:#62685f}}
html,body{{margin:0;background:#d5d0c2;color:var(--ink);font-family:"SFMono-Regular","Cascadia Mono",monospace}}
.sheet{{width:100%;min-height:100vh;background:var(--paper);padding:4.5%;display:flex;flex-direction:column;
background-image:linear-gradient(rgba(23,33,29,.045) 1px,transparent 1px);background-size:100% 28px}}
.top{{display:flex;justify-content:space-between;border-top:3px solid var(--ink);border-bottom:1px solid var(--ink);
padding:10px 0;font-size:11px;letter-spacing:.12em;text-transform:uppercase}} .status{{background:var(--acid);padding:2px 8px;border:1px solid}}
.hero{{display:grid;grid-template-columns:1.6fr 1fr;gap:5%;align-items:end;padding:5% 0;border-bottom:3px solid}}
.kicker,.label{{font-size:10px;text-transform:uppercase;letter-spacing:.14em}} h1{{font:800 clamp(48px,7vw,94px)/.84 "Iowan Old Style",serif;
letter-spacing:-.055em;margin:12px 0 0;text-transform:uppercase}} .identity{{border-left:1px solid;padding-left:8%}}
.identity strong{{display:block;font:700 clamp(25px,3vw,42px)/1 "Iowan Old Style",serif;margin:10px 0}}
.identity p,.method p{{font-size:11px;line-height:1.55;color:var(--muted);margin:0}}
.score{{display:grid;grid-template-columns:1.25fr 1fr 1fr;background:var(--navy);color:white;margin:2.5% 0}}
.score>div{{padding:4%;border-right:1px solid #657984;min-width:0}} .score>div:last-child{{border:0}}
.score b{{display:block;font:800 clamp(34px,5vw,68px)/1 "Iowan Old Style",serif;margin:9px 0}}
.score small{{color:#fff;font-size:10px}} .correction{{display:flex;align-items:center;gap:9px;border-top:1px solid #8fa2aa;
padding-top:9px;margin-top:9px}} .correction strong{{font:700 18px/1 "Iowan Old Style",serif;color:var(--acid)}}
.correction span{{font-size:8px;line-height:1.35;text-transform:uppercase;letter-spacing:.08em;color:#fff}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:1.4%;margin-bottom:2.5%}}
.metric{{border-top:2px solid;padding:2.5% 1%;min-width:0}} .metric b{{font:700 clamp(25px,3vw,42px)/1 "Iowan Old Style",serif;display:block;margin:8px 0}}
.metric span{{font-size:9px;color:var(--muted);line-height:1.35;display:block}} .metric-pair{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
.metric-pair>div{{min-width:0}} .metric-pair div+div{{border-left:1px solid var(--rule);padding-left:8px}} .metric-pair b{{font-size:clamp(22px,2.6vw,36px)}}
.public-rhythm{{display:grid;grid-template-columns:auto 1fr;gap:4%;
align-items:center;border:1px solid;padding:2%;margin-bottom:2.5%}} .public-rhythm b{{font:700 clamp(20px,2.4vw,32px) "Iowan Old Style",serif;white-space:nowrap}}
.public-rhythm p{{font-size:10px;line-height:1.5;color:var(--muted);margin:0}} .band{{display:grid;grid-template-columns:1fr 1fr;gap:2%;margin-bottom:2.5%}}
.panel{{border:1px solid;padding:3%;background:rgba(240,234,219,.88)}} .panel h2{{font:700 clamp(22px,2.5vw,34px)/1 "Iowan Old Style",serif;margin:8px 0 12px}}
.panel p{{font-size:11px;line-height:1.55;margin:0;color:var(--muted)}} .badges{{border-top:1px solid var(--rule);padding-top:2%;font-size:10px}}
.method{{margin-top:auto;border-top:2px solid;padding-top:2%;display:grid;grid-template-columns:1fr 2.2fr;gap:4%}}
.method strong{{font:700 17px "Iowan Old Style",serif}} footer{{display:flex;justify-content:space-between;margin-top:2%;font-size:9px;color:var(--muted)}}
@media screen and (max-width:600px){{.sheet{{padding:4%}}.label{{font-size:8px;letter-spacing:.08em}}
.score b{{font-size:clamp(22px,7vw,34px)}}.correction{{gap:5px}}.correction strong{{font-size:14px}}
.metric-pair{{gap:4px}}.metric-pair div+div{{padding-left:4px}}.metric-pair b{{font-size:clamp(11px,3vw,20px)}}
.metric span{{font-size:7px;overflow-wrap:anywhere}}}}
@media print{{html,body{{background:white}}.sheet{{width:8.5in;height:11in;min-height:0;padding:.34in;break-after:avoid}}
.hero{{padding:3.5% 0}}.score{{margin:1.8% 0}}.score>div{{padding:3%}}.correction{{padding-top:6px;margin-top:6px}}
.metrics,.public-rhythm,.band{{margin-bottom:1.8%}}.metric{{padding:1.8% 1%}}.panel{{padding:2.2%}}
.panel h2{{margin:6px 0 8px}}.badges{{padding-top:1.4%}}.method{{padding-top:1.4%}}footer{{margin-top:1.4%}}}}
</style></head><body><main class="sheet">
<div class="top"><span>Coding Ledger / Public Builder Scorecard</span><span class="status">Evidence-based</span></div>
<section class="hero"><div><div class="kicker">Prove how you build</div><h1>Builder<br>field report.</h1></div>
<div class="identity"><div class="label">Builder</div><strong>{html.escape(builder_name)}</strong>
<p>{html.escape(profile['archetype'])} · {rhythm['active_days']:,} attributable building days · best streak {s['best_streak']} days</p></div></section>
<section class="score"><div><div class="label">Receipt-backed execution time</div><b>{s['total_hours']:,}h</b>
<small>Evidence floor—not total time worked<br>{s['raw_total_hours']:,}h raw evidence before correction</small>
<div class="correction"><strong>−{s['overlap_discount_hours']:,}h</strong><span>overlap removed<br>{s['overlap_discount_pct']}% concurrency correction</span></div></div>
<div><div class="label">Your Coding</div><b>{s['attributed_hours']['your_coding']:,}h</b><small>human-side attribution</small></div>
<div><div class="label">AI Coding</div><b>{s['attributed_hours']['ai_coding']:,}h</b><small>{a['ai_leverage_pct']}% leverage</small></div></section>
<section class="metrics">
<div class="metric"><div class="label">Commits</div><b>{s['total_commits']:,}</b><span>matched local receipts</span></div>
<div class="metric"><div class="label">Evidence scope</div><div class="metric-pair">
<div><b>{s['repositories_with_commits']:,}</b><span>commit-bearing repositories</span></div>
<div><b>{a['active_projects']:,}</b><span>observed workspace identities</span></div></div></div>
<div class="metric"><div class="label">AI sessions</div><b>{s['sessions']:,}</b><span>metadata-only evidence</span></div>
<div class="metric"><div class="label">Session → commit</div><div class="metric-pair">
<div><b>{a['session_commit_24h_conversion_pct']}%</b><span>within 24 hours</span></div>
<div><b>{a['session_commit_conversion_pct']}%</b><span>within 7 days</span></div></div></div></section>
<section class="public-rhythm"><b>{rhythm['active_days']:,} on / {rhythm['off_days']:,} off</b>
<p><span class="label">Building rhythm across {rhythm['calendar_days']:,} calendar days · {rhythm['start_day']} → {rhythm['end_day']}</span><br>
{rhythm['streak_count']:,} building streaks · {rhythm['longest_break_days']:,}d longest break · recent: {html.escape(recent_rhythm)}</p></section>
<section class="band"><article class="panel"><div class="label">Portfolio breadth</div><h2>{a['project_diversity_pct']}% project diversity</h2>
<p>Neutral inverse-concentration measure across {a['active_projects']:,} active project identities. Diversity momentum: {momentum_text} commits on multi-project workflow days.</p></article>
<article class="panel"><div class="label">Direction and orchestration</div><h2>{a['parallel_dispatches']:,} parallel dispatches</h2>
<p>Evidence-backed profile: {html.escape(profile['archetype'])}. Hours measure attributable activity, not code quality, productivity, or business impact.</p></article></section>
<div class="badges"><span class="label">Earned evidence badges</span><br>{html.escape(badge_names)}</div>
<section class="method"><strong>How the score is evaluated</strong><p>Git uses a capped daily commit-density proxy; editor history uses capped edit receipts; agents use timestamped activity with a 30-minute idle break. The ledger does not count keystrokes or infer how long work took before a commit. Unobserved research, architecture, debugging, review, planning, and other work remain uncounted. Only AI work within ten minutes of an explicit human steering turn can overlap human evidence. Independent AI runtime remains additive. GitHub aggregates contribute commits and LOC, never synthetic hours. Prompts, responses, source code, secrets, tool output, and repository names are excluded from this export.</p></section>
<footer><span>GENERATED LOCALLY · {generated}</span><span>CODING LEDGER · METHODOLOGY V2</span></footer>
</main></body></html>"""


# ---------------------------------------------------------------- entrypoint

def main() -> None:
    ap = argparse.ArgumentParser(prog="coding_ledger",
                                 description="Local forensic scanner for your coding history")
    ap.add_argument("--db", type=Path, default=DEFAULT_DB, help="ledger DB path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create the ledger DB")
    p.add_argument("--author", help="comma-separated author names/emails to match")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("scan", help="scan sources into the ledger (idempotent)")
    p.add_argument("--author", help="comma-separated author names/emails")
    p.add_argument("--sources", help=f"comma list of {','.join(ALL_SOURCES)} (default all)")
    p.add_argument("--roots", help="comma list of dirs to search for repos")
    p.add_argument("--gh-owners", help="github owners/orgs for the github source")
    p.add_argument("--gh-login", help="your github login for attribution")
    p.add_argument("--rediscover", action="store_true",
                   help="re-walk roots for repos instead of using the cached list")
    p.add_argument("--reprocess-sessions", action="store_true",
                   help="reparse selected agent/editor sources even when files are unchanged")
    p.add_argument("--git-timeout", type=int, default=GIT_TIMEOUT_S,
                   help="per-repo git log timeout in seconds (bump for cold iCloud repos)")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("status", help="quick terminal summary")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("report", help="full report")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--out", help="write to file instead of stdout")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("dashboard", help="generate the HTML dashboard")
    p.add_argument("--open", action="store_true", help="open in browser")
    p.add_argument("--out", help="output path (default ~/.coding-ledger/dashboard.html)")
    p.set_defaults(fn=cmd_dashboard)

    p = sub.add_parser("export", help="generate public-safe PDF and social image")
    p.add_argument("--name", help="builder name shown on the public scorecard")
    p.add_argument("--out-dir", default=str(LEDGER_DIR / "share"),
                   help="export directory (default ~/.coding-ledger/share)")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("doctor", help="show which sources are available")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("sync-github", help="sync lightweight no-checkout GitHub history")
    p.add_argument("--owners", required=True, help="comma-separated GitHub users/orgs")
    p.add_argument("--destination", required=True, help="non-iCloud history root")
    p.add_argument("--limit", type=int, default=400, help="repositories per owner")
    p.add_argument("--include-archived", action="store_true")
    p.set_defaults(fn=cmd_sync_github)

    p = sub.add_parser("install-daemon", help="install daily launchd scan (macOS)")
    p.add_argument("--hour", type=int, default=21)
    p.set_defaults(fn=cmd_install_daemon)

    p = sub.add_parser("uninstall-daemon", help="remove the launchd scan")
    p.set_defaults(fn=cmd_uninstall_daemon)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
