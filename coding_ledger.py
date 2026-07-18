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
import fnmatch
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

ALL_SOURCES = ["git", "claude", "cursor", "aider", "vscode", "github"]
DEFAULT_ROOTS = [HOME / "Projects", HOME / "Desktop", HOME / "dev"]

IDLE_GAP_S = 30 * 60          # gap that splits a session
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
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
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


def author_matches(name: str, email: str, needles: list[str]) -> bool:
    hay = f"{name} <{email}>".lower()
    return any(n in hay for n in needles)


def scan_git(db: sqlite3.Connection, roots: list[Path], authors: list[str]) -> tuple[int, list[str]]:
    needles = [a.strip().lower() for a in authors if a.strip()]
    repos = find_git_repos(roots)
    say(f"  git: {len(repos)} repos under {', '.join(str(r) for r in roots if r.is_dir())}")
    added, notes = 0, []
    fmt = "%x1e%H%x1f%an%x1f%ae%x1f%aI"
    for repo in repos:
        try:
            out = subprocess.run(
                ["git", "-C", str(repo), "log", "--all", "--no-merges",
                 "--numstat", f"--pretty=format:{fmt}"],
                capture_output=True, text=True, timeout=GIT_TIMEOUT_S, errors="replace")
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
            if len(parts) != 4:
                continue
            sha, an, ae, aiso = parts
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
            if insert_event(db, f"git:{sha}", "git", "commit", ts, None, repo_name,
                            loc_add=add, loc_del=dele, items=1,
                            meta={"files": files, "email": ae}):
                added += 1
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
    stamps: list[datetime] = []
    msgs = tools = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = TS_RE.search(line[:2000])
                if m:
                    ts = parse_iso(m.group(1))
                    if ts:
                        stamps.append(ts)
                if '"type":"assistant"' in line[:200] or '"type": "assistant"' in line[:200]:
                    msgs += 1
                tools += line.count('"type":"tool_use"')
    except OSError:
        return False
    file_mark(db, path)
    if not stamps:
        return False
    active_s, days = sessions_from_timestamps(stamps)
    stamps.sort()
    replace_event(db, uid, source=source, kind="session",
                  ts_start=stamps[0], ts_end=stamps[-1], project=project,
                  items=msgs, meta={"active_s": active_s, "days": days,
                                    "tools": tools, "file": str(path)})
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
    for root in roots:
        if root.is_dir():
            files.extend(root.rglob(".aider.chat.history.md"))
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


# ---------------------------------------------------------------- aggregation

def compute_daily(db: sqlite3.Connection) -> dict:
    """Build per-day aggregates from raw events. Recomputable forever."""
    hours: dict[str, dict[str, float]] = {}   # day -> source -> hours
    loc: dict[str, int] = {}                  # day -> net LOC added (local git)
    loc_add: dict[str, int] = {}
    commits_per_day: dict[str, int] = {}
    commits_day_proj: dict[tuple[str, str], int] = {}
    edits_per_day: dict[str, int] = {}
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
            for d, secs in (meta.get("days") or {}).items():
                hours.setdefault(d, {}).setdefault(source, 0.0)
                hours[d][source] += secs / 3600
            bump_proj(project, h=(meta.get("active_s", 0)) / 3600)
        elif kind == "commit" and day:
            commits_per_day[day] = commits_per_day.get(day, 0) + 1
            commits_day_proj[(day, project or "misc")] = \
                commits_day_proj.get((day, project or "misc"), 0) + 1
            loc[day] = loc.get(day, 0) + la - ld
            loc_add[day] = loc_add.get(day, 0) + la
            bump_proj(project, a=la, d=ld)
        elif kind == "edit" and day:
            edits_per_day[day] = edits_per_day.get(day, 0) + items
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
    for day, n in edits_per_day.items():
        h = min(n * VSCODE_PER_EDIT_S, VSCODE_DAY_CAP_S) / 3600
        hours.setdefault(day, {}).setdefault("vscode", 0.0)
        hours[day]["vscode"] += h

    return {"hours": hours, "loc": loc, "loc_add": loc_add,
            "commits": commits_per_day, "projects": proj}


def summarize(db: sqlite3.Connection) -> dict:
    agg = compute_daily(db)
    hours = agg["hours"]
    total_by_source: dict[str, float] = {}
    for day, per in hours.items():
        for s, h in per.items():
            total_by_source[s] = total_by_source.get(s, 0.0) + h
    total_hours = sum(total_by_source.values())

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

    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "total_hours": round(total_hours, 1),
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
    t0 = datetime.now().astimezone()
    say(f"{C_BOLD}scan{C_RESET} sources={','.join(sources)}")
    total_added = 0
    all_notes: list[str] = []
    local_repo_names: set[str] = set()

    for s in sources:
        if s not in ALL_SOURCES:
            warn(f"unknown source: {s}")
            continue
        t = time.time()
        if s == "git":
            added, notes = scan_git(db, roots, authors)
            local_repo_names = {r[0].lower() for r in db.execute(
                "SELECT DISTINCT project FROM events WHERE source='git'") if r[0]}
        elif s == "claude":
            added, notes = scan_claude(db)
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
        say(f"  {C_CYAN}{s}{C_RESET}: +{added} events ({time.time()-t:.1f}s)")

    db.execute("INSERT INTO scans(started_at,finished_at,sources,added,notes) VALUES(?,?,?,?,?)",
               (t0.isoformat(timespec="seconds"),
                datetime.now().astimezone().isoformat(timespec="seconds"),
                ",".join(sources), total_added, "; ".join(all_notes)[:2000]))
    db.commit()
    say(f"{C_GREEN}✓ scan complete{C_RESET}: +{total_added} events" +
        (f"  ({len(all_notes)} notes — see `status`)" if all_notes else ""))


def fmt_h(h: float) -> str:
    return f"{h:,.1f}h"


def cmd_status(args) -> None:
    db = open_db(args.db)
    s = summarize(db)
    bar_w = 40
    filled = min(int(bar_w * s["total_hours"] / s["target_hours"]), bar_w)
    bar = "█" * filled + "░" * (bar_w - filled)
    say(f"{C_BOLD}coding-ledger{C_RESET}  {args.db}")
    say(f"  {C_GREEN}{bar}{C_RESET} {fmt_h(s['total_hours'])} / {s['target_hours']:,}h "
        f"({s['pct_to_target']}%)")
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
    last = db.execute("SELECT finished_at, sources, added, notes FROM scans "
                      "ORDER BY id DESC LIMIT 1").fetchone()
    if last:
        say(f"  last scan: {last[0][:19]} [{last[1]}] +{last[2]}")
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


def render_dashboard(s: dict, daily: dict) -> str:
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

    p = sub.add_parser("install-daemon", help="install daily launchd scan (macOS)")
    p.add_argument("--hour", type=int, default=21)
    p.set_defaults(fn=cmd_install_daemon)

    p = sub.add_parser("uninstall-daemon", help="remove the launchd scan")
    p.set_defaults(fn=cmd_uninstall_daemon)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
