"""Exercise an installed release against a temporary, synthetic Git repository."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

executable = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="coding-ledger-smoke-") as directory:
    root = Path(directory)
    project = root / "synthetic-project"
    project.mkdir()
    env = dict(os.environ, CODING_LEDGER_DIR=str(root / "ledger"),
               CODING_LEDGER_DB=str(root / "ledger" / "ledger.db"),
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def run(*args, cwd=root):
        return subprocess.run(args, cwd=cwd, env=env, check=True,
                              text=True, capture_output=True).stdout

    run("git", "init", "-q", str(project))
    (project / "example.txt").write_text("synthetic integration fixture\n")
    run("git", "add", "example.txt", cwd=project)
    run("git", "-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic fixture", cwd=project)
    run(executable, "init", "--author", "release@example.invalid")
    for _ in range(2):
        run(executable, "scan", "--sources", "git", "--roots", str(project))
    with sqlite3.connect(env["CODING_LEDGER_DB"]) as db:
        assert db.execute("SELECT count(*) FROM events WHERE source='git'").fetchone()[0] == 1
    for command in ["status", "roi", "today"]:
        assert run(executable, command).strip()
    report = run(executable, "report", "--format", "json")
    assert isinstance(json.loads(report), dict)
    dashboard = root / "dashboard.html"
    run(executable, "dashboard", "--out", str(dashboard))
    html = dashboard.read_text()
    assert "Chart.js" in html, "Installed release must bundle the offline chart library"
    assert "<script src=" not in html, "Dashboard must not require remote JavaScript"
    assert "synthetic-project" in html
    print("Installed CLI: synthetic scan, deduplication, reports and offline dashboard passed")
