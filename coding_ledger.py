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
  python3 coding_ledger.py doctor
  python3 coding_ledger.py install-daemon   # daily launchd scan (macOS)

Ledger: ~/.coding-ledger/ledger.db (override: --db or $CODING_LEDGER_DB)
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------- constants

HOME = Path.home()
LEDGER_DIR = Path(os.environ.get("CODING_LEDGER_DIR", HOME / ".coding-ledger"))
DEFAULT_DB = Path(os.environ.get("CODING_LEDGER_DB", LEDGER_DIR / "ledger.db"))
DASHBOARD_PATH = LEDGER_DIR / "dashboard.html"

ALL_SOURCES = [
    "git", "claude", "codex", "gemini", "antigravity", "grok",
    "cursor", "aider", "vscode", "github",
]
AGENT_SOURCES = ("claude", "codex", "gemini", "grok", "cursor", "aider")
EDITOR_SOURCES = ("vscode", "antigravity")
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
            if r["name"].lower() in local_repo_names:
                continue  # counted precisely by the local git scan
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
            if not mine:
                continue
            for w in mine.get("weeks", []):
                if not (w.get("c") or w.get("a") or w.get("d")):
                    continue
                ts = datetime.fromtimestamp(w["w"], tz=timezone.utc)
                if insert_event(db, f"github:{full}:{w['w']}", "github", "gh_week",
                                ts, ts + timedelta(days=7), r["name"],
                                loc_add=w.get("a", 0), loc_del=w.get("d", 0),
                                items=w.get("c", 0)):
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
    attributed: dict[str, dict[str, float]] = {}
    proj: dict[str, dict[str, float]] = {}    # project -> {hours, loc_add, loc_del}

    def bump_proj(p: str | None, h: float = 0, a: int = 0, d: int = 0):
        p = p or "misc"
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
                hours.setdefault(d, {}).setdefault(source, 0.0)
                hours[d][source] += secs / 3600
                share = secs / active_s if active_s else 0
                bucket = attributed.setdefault(d, {"coauthored": 0.0, "ai_only": 0.0})
                bucket["coauthored"] += coauthored_s * share / 3600
                bucket["ai_only"] += ai_only_s * share / 3600
            bump_proj(project, h=active_s / 3600)
        elif kind == "commit" and day:
            commits_per_day[day] = commits_per_day.get(day, 0) + 1
            commits_day_proj[(day, project or "misc")] = \
                commits_day_proj.get((day, project or "misc"), 0) + 1
            loc[day] = loc.get(day, 0) + la - ld
            loc_add[day] = loc_add.get(day, 0) + la
            bump_proj(project, a=la, d=ld)
        elif kind == "edit" and day:
            key = (day, source)
            edits_per_day[key] = edits_per_day.get(key, 0) + items
        elif kind == "gh_week" and day:
            bump_proj(project, a=la, d=ld)

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
        agent_h = sum(per_source.get(source, 0.0) for source in AGENT_SOURCES)
        human_h = per_source.get("git", 0.0) + sum(
            per_source.get(source, 0.0) for source in EDITOR_SOURCES)
        bucket = attributed.setdefault(day, {"coauthored": 0.0, "ai_only": 0.0})
        bucket["own"] = max(human_h - agent_h, 0.0)

    return {"hours": hours, "loc": loc, "loc_add": loc_add,
            "commits": commits_per_day, "projects": proj, "attributed": attributed}


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
    days_active = sorted(hours.keys())
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
    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "total_hours": rounded_total,
        "raw_total_hours": round(raw_total_hours, 1),
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
        "remote_commits": per_source.get("github", {}).get("items", 0),
        "sessions": per_source.get("claude", {}).get("events", 0) +
                    per_source.get("codex", {}).get("events", 0) +
                    per_source.get("cursor", {}).get("events", 0) +
                    per_source.get("aider", {}).get("events", 0),
        "active_days": len(days_active),
        "first_activity": first[0], "last_activity": first[1],
        "best_streak": best_streak, "current_streak": cur_streak,
        "yearly_hours": {k: round(v, 1) for k, v in sorted(yearly.items())},
        "top_projects": sorted(
            ({"project": p, **{k: round(v, 1) if isinstance(v, float) else v
                               for k, v in e.items()}}
             for p, e in agg["projects"].items()),
            key=lambda e: -(e["hours"] * 50 + e["loc_add"] / 1000))[:15],
        "profile": profile,
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
    say(f"  active days: {s['active_days']:,}   streak: {s['current_streak']}d "
        f"(best {s['best_streak']}d)")
    say(f"  span: {(s['first_activity'] or '?')[:10]} → {(s['last_activity'] or '?')[:10]}")
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
    L.append(f"- Local commits: **{s['total_commits']:,}** "
             f"(+{s['loc_added']:,} LOC added, net {s['net_loc']:,})")
    if s["remote_commits"]:
        L.append(f"- Remote-only GitHub commits: **{s['remote_commits']:,}** "
                 f"(+{s['github_loc_added']:,} LOC)")
    L.append(f"- AI-assisted sessions: **{s['sessions']:,}**")
    L.append(f"- Active days: **{s['active_days']:,}** — current streak "
             f"{s['current_streak']}d, best {s['best_streak']}d")
    L.append(f"- Span: {(s['first_activity'] or '?')[:10]} → {(s['last_activity'] or '?')[:10]}\n")
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
    if args.open:
        subprocess.run(["open", str(out)], check=False)


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


def render_dashboard(s: dict, daily: dict) -> str:
    """Render an offline, evidence-first builder field report."""
    days = sorted(daily["hours"])
    sources = list(s["hours_by_source"])
    palette = {
        "claude": "#f4a261", "codex": "#e76f51", "git": "#2a9d8f",
        "cursor": "#e9c46a", "aider": "#9b5de5", "vscode": "#4cc9f0",
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
background-size:100% 28px}} main{{max-width:1480px;margin:auto;padding:28px}}
h1,h2,h3,p{{margin:0}} h1,h2{{font-family:"Iowan Old Style","Palatino Linotype",Palatino,serif}} h1{{font-size:clamp(3.4rem,9vw,9rem);
line-height:.79;letter-spacing:-.06em;max-width:1050px}} .topline{{display:flex;justify-content:space-between;
border-top:2px solid var(--ink);border-bottom:1px solid var(--ink);padding:8px 0;margin-bottom:34px}}
.eyebrow{{text-transform:uppercase;letter-spacing:.14em;font-size:10px;font-weight:500}} .status{{background:var(--acid);
padding:2px 8px;border:1px solid var(--ink)}} .hero{{display:grid;grid-template-columns:2.2fr 1fr;gap:40px;
align-items:end;border-bottom:3px solid var(--ink);padding-bottom:30px}} .archetype{{border-left:1px solid var(--ink);padding-left:24px}}
.archetype strong{{font:800 2.2rem/1 "Iowan Old Style","Palatino Linotype",serif;display:block;margin:8px 0 12px}}
.ledger-grid{{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin:18px 0}}
.metric,.panel,.badge{{border:1px solid var(--ink);background:rgba(240,234,219,.9);box-shadow:4px 4px 0 var(--ink)}}
.metric{{grid-column:span 3;padding:18px;min-height:145px;position:relative;overflow:hidden}}
.metric.wide{{grid-column:span 6;background:var(--navy);color:#fff}} .metric .number{{font:800 clamp(2.2rem,5vw,5rem)/1 "Iowan Old Style","Palatino Linotype",serif;
letter-spacing:-.05em;margin:12px 0}} .metric small{{color:var(--muted)}} .metric.wide small{{color:#b9c4c8}}
.duo{{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:18px}} .duo div{{border-top:1px solid #80909a;padding-top:9px}}
.duo b{{font-size:1.3rem;display:block}} .panel{{padding:20px;margin-bottom:16px}} .panel h2{{font-size:1.6rem;margin-bottom:16px}}
.two{{display:grid;grid-template-columns:1.35fr 1fr;gap:16px}} .chartbox{{height:320px}} .badges{{display:grid;
grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}} .badge{{display:flex;gap:15px;padding:15px;min-height:130px}}
.badge-mark{{width:48px;height:48px;display:grid;place-items:center;border:1px solid var(--ink);border-radius:50%;font-weight:500}}
.badge h3{{font:600 1.2rem "Iowan Old Style","Palatino Linotype",serif;margin:3px 0 8px}} .badge p,.badge small{{color:var(--muted)}}
.badge.locked{{opacity:.46;box-shadow:none}} .badge.gold .badge-mark{{background:#e9c46a}} .badge.platinum .badge-mark{{background:var(--acid)}}
.badge.silver .badge-mark{{background:#d4d8d5}} .badge.bronze .badge-mark{{background:#c88b62}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:8px;border-bottom:1px solid var(--rule);text-align:right}}
th:first-child,td:first-child{{text-align:left}} .method{{font-size:12px;color:var(--muted);max-width:900px}}
footer{{display:flex;justify-content:space-between;border-top:2px solid var(--ink);padding-top:10px;margin-top:30px}}
@media(max-width:900px){{main{{padding:16px}}.hero,.two{{grid-template-columns:1fr}}.archetype{{border-left:0;border-top:1px solid;padding:18px 0 0}}
.metric,.metric.wide{{grid-column:span 12}}h1{{font-size:4rem}}.topline{{gap:10px;flex-wrap:wrap}}}}
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
<small>Raw source sum {s['raw_total_hours']:,}h · overlap discounted conservatively</small>
<div class="duo"><div><span>Your Coding</span><b>{s['attributed_hours']['your_coding']:,}h</b></div>
<div><span>AI Coding</span><b>{s['attributed_hours']['ai_coding']:,}h</b></div></div></article>
<article class="metric"><div class="eyebrow">Commits</div><div class="number">{s['total_commits']:,}</div>
<small>+{s['loc_added']:,} LOC · net {s['net_loc']:,}</small></article>
<article class="metric"><div class="eyebrow">AI sessions</div><div class="number">{s['sessions']:,}</div>
<small>Claude · Codex · Cursor · Aider</small></article>
</section>
<section class="two"><article class="panel"><h2>Attributed work, over time</h2><div class="chartbox"><canvas id="attr"></canvas></div></article>
<article class="panel"><h2>Builder dimensions</h2><div class="chartbox"><canvas id="radar"></canvas></div></article></section>
<article class="panel"><h2>Earned field badges</h2><div class="badges">{badge_cards}</div></article>
<section class="two"><article class="panel"><h2>Raw hours by source</h2><div class="chartbox"><canvas id="source"></canvas></div></article>
<article class="panel"><h2>Top projects</h2><table><thead><tr><th>Project</th><th>Hours</th><th>+LOC</th><th>-LOC</th></tr></thead>
<tbody>{project_rows}</tbody></table></article></section>
<article class="panel method"><h2>How attribution works</h2><p>The scorecard has two categories: Your Coding and AI Coding.
Shared work is allocated between them using the ratio of measured human-only to AI-only base hours ({s['coauthor_allocation']['your_share_pct']}% yours / {s['coauthor_allocation']['ai_share_pct']}% AI).
Daily human and agent proxies are overlap-discounted; GitHub aggregates add commits and LOC but never synthetic hours. Badge thresholds are visible and reproducible.
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
