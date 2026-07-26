import argparse
import contextlib
import importlib.util
import io
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "coding_ledger.py"
SPEC = importlib.util.spec_from_file_location("coding_ledger", MODULE_PATH)
ledger = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(ledger)


class LedgerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "ledger.db"
        self.db = ledger.open_db(self.db_path)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_schema_migrates_scan_status(self):
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(scans)")}
        self.assertIn("status", columns)

    def test_activity_attribution_splits_after_steering_window(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        activity = [
            (start, "user"),
            (start + timedelta(minutes=2), "assistant"),
            (start + timedelta(minutes=8), "tool"),
            (start + timedelta(minutes=22), "tool"),
        ]
        active, _, attribution = ledger.sessions_from_activity(activity)
        self.assertEqual(active, 22 * 60)
        self.assertGreater(attribution["coauthored_s"], 0)
        self.assertGreater(attribution["ai_only_s"], 0)
        self.assertEqual(sum(attribution.values()), active)

    def test_long_first_agent_interval_splits_at_steering_window(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        active, _, attribution = ledger.sessions_from_activity([
            (start, "user"), (start + timedelta(minutes=20), "assistant")])
        self.assertEqual(active, 20 * 60)
        self.assertEqual(attribution["coauthored_s"], 10 * 60)
        self.assertEqual(attribution["ai_only_s"], 10 * 60)

    def test_coauthored_hours_are_allocated_by_base_share(self):
        allocation = ledger.allocate_coding_hours(100, 90, 50)
        self.assertAlmostEqual(allocation["your_share"], 2 / 3)
        self.assertAlmostEqual(allocation["ai_share"], 1 / 3)
        self.assertAlmostEqual(allocation["your_coding"], 160)
        self.assertAlmostEqual(allocation["ai_coding"], 80)
        self.assertAlmostEqual(
            allocation["your_coding"] + allocation["ai_coding"], 240)

    def test_coauthored_hours_split_evenly_without_base_evidence(self):
        allocation = ledger.allocate_coding_hours(0, 10, 0)
        self.assertEqual(allocation["your_coding"], 5)
        self.assertEqual(allocation["ai_coding"], 5)
        self.assertEqual(allocation["your_share"], 0.5)

    def test_codex_parser_extracts_metadata_without_transcript_text(self):
        session = self.root / "rollout.jsonl"
        rows = [
            {"timestamp": "2026-01-01T12:00:00Z", "type": "session_meta",
             "payload": {"id": "session-1", "cwd": "/Users/test/Projects/widget"}},
            {"timestamp": "2026-01-01T12:00:01Z", "type": "event_msg",
             "payload": {"type": "user_message", "message": "SECRET PROMPT"}},
            {"timestamp": "2026-01-01T12:00:10Z", "type": "response_item",
             "payload": {"type": "function_call", "name": "exec_command",
                         "arguments": "pytest -q SECRET_TOKEN"}},
            {"timestamp": "2026-01-01T12:00:30Z", "type": "response_item",
             "payload": {"type": "message", "role": "assistant",
                         "content": "SECRET RESPONSE"}},
        ]
        session.write_text("\n".join(json.dumps(row) for row in rows))
        parsed = ledger.parse_codex_session(session)
        self.assertEqual(parsed["project"], "widget")
        self.assertEqual(parsed["session_id"], "session-1")
        self.assertEqual(parsed["user_messages"], 1)
        self.assertEqual(parsed["tools"], 1)
        self.assertEqual(parsed["test_calls"], 1)
        serialized = json.dumps(parsed, default=str)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("pytest", serialized)

    def test_codex_project_skips_dated_task_container(self):
        project = ledger.project_from_path(
            "/Users/test/Documents/Codex/2026-07-25/verify-production")
        self.assertEqual(project, "verify-production")

    def test_sessionization_splits_credit_across_midnight(self):
        start = datetime(2026, 1, 1, 23, 59, 30).astimezone()
        end = start + timedelta(minutes=2)
        active, days = ledger.sessions_from_timestamps([start, end])
        self.assertEqual(active, 120)
        self.assertEqual(len(days), 2)
        self.assertEqual(sum(days.values()), 120)

    def test_codex_rescan_replaces_growing_session(self):
        session = self.root / "rollout.jsonl"
        first = [
            {"timestamp": "2026-01-01T12:00:00Z", "type": "session_meta",
             "payload": {"id": "one", "cwd": "/tmp/widget"}},
            {"timestamp": "2026-01-01T12:00:01Z", "type": "event_msg",
             "payload": {"type": "user_message"}},
        ]
        session.write_text("\n".join(json.dumps(row) for row in first))
        with mock.patch.object(ledger, "HOME", self.root):
            target = self.root / ".codex" / "sessions" / "2026" / "01" / "01"
            target.mkdir(parents=True)
            target_file = target / "rollout.jsonl"
            target_file.write_text(session.read_text())
            added, _ = ledger.scan_codex(self.db)
            self.assertEqual(added, 1)
            first_count = self.db.execute(
                "SELECT COUNT(*) FROM events WHERE source='codex'").fetchone()[0]
            with target_file.open("a") as fh:
                fh.write("\n" + json.dumps({
                    "timestamp": "2026-01-01T12:01:00Z", "type": "response_item",
                    "payload": {"type": "function_call", "name": "exec_command"}}))
            added, _ = ledger.scan_codex(self.db)
            second_count = self.db.execute(
                "SELECT COUNT(*) FROM events WHERE source='codex'").fetchone()[0]
        self.assertEqual(added, 1)
        self.assertEqual(first_count, 1)
        self.assertEqual(second_count, 1)

    def test_multiple_author_emails_match(self):
        authors = ["James Benton", "kjscusoms831@gmail.com", "jamesbenton@ymail.com"]
        self.assertTrue(ledger.author_matches("James Benton", "jamesbenton@ymail.com", authors))
        self.assertTrue(ledger.author_matches("James Benton", "kjscusoms831@gmail.com", authors))
        self.assertFalse(ledger.author_matches("Other", "other@example.com", authors))

    def test_cached_repos_are_scoped_to_explicit_roots(self):
        projects = self.root / "Projects"
        desktop = self.root / "Desktop"
        for path in (projects / "kept", desktop / "excluded"):
            (path / ".git").mkdir(parents=True)
            self.db.execute("INSERT INTO repos(path,last_seen) VALUES(?,?)", (str(path), "now"))
        self.db.commit()
        repos = ledger.cached_repos(self.db, [projects])
        self.assertEqual(repos, [projects / "kept"])

    def test_source_cache_invalidation_is_scoped(self):
        codex = ledger.HOME / ".codex" / "sessions" / "one.jsonl"
        claude = ledger.HOME / ".claude" / "projects" / "two.jsonl"
        self.db.executemany(
            "INSERT INTO file_cache(path,mtime,size) VALUES(?,?,?)",
            [(str(codex), 1, 1), (str(claude), 1, 1)])
        self.db.commit()
        removed = ledger.invalidate_source_cache(self.db, ["codex"])
        remaining = [row[0] for row in self.db.execute("SELECT path FROM file_cache")]
        self.assertEqual(removed, 1)
        self.assertEqual(remaining, [str(claude)])

    def test_interrupted_scan_is_durable(self):
        args = argparse.Namespace(
            db=self.db_path, author="James Benton", sources="git",
            roots=str(self.root / "Projects"), rediscover=False, git_timeout=1,
            reprocess_sessions=False, gh_owners=None, gh_login=None)
        self.db.close()
        with mock.patch.object(ledger, "scan_git", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                ledger.cmd_scan(args)
        con = sqlite3.connect(self.db_path)
        status = con.execute("SELECT status FROM scans ORDER BY id DESC LIMIT 1").fetchone()[0]
        con.close()
        self.db = ledger.open_db(self.db_path)
        self.assertEqual(status, "interrupted")

    def test_status_is_provisional_without_complete_scan(self):
        args = argparse.Namespace(db=self.db_path)
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            ledger.cmd_status(args)
        self.assertIn("PROVISIONAL", capture.getvalue())

    def test_focused_scan_does_not_claim_complete_baseline(self):
        self.db.execute(
            "INSERT INTO scans(started_at,finished_at,sources,added,notes,status) "
            "VALUES('a','b','codex',1,'','complete')")
        self.db.commit()
        self.assertFalse(ledger.has_complete_baseline(self.db))
        all_sources = ",".join(ledger.ALL_SOURCES)
        self.db.execute(
            "INSERT INTO scans(started_at,finished_at,sources,added,notes,status) "
            "VALUES('a','b',?,1,'','complete')", (all_sources,))
        self.db.commit()
        self.assertTrue(ledger.has_complete_baseline(self.db))

    def test_dashboard_contains_attribution_and_badges(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, "codex:test", "codex", "session", start,
            start + timedelta(minutes=10), "widget", items=2,
            meta={"active_s": 600, "days": {"2026-01-01": 600},
                  "coauthored_s": 480, "ai_only_s": 120,
                  "user_messages": 2, "tools": 4})
        self.db.commit()
        summary = ledger.summarize(self.db)
        summary["scan_state"] = "complete"
        summary["completed_scans"] = 1
        daily = summary.pop("_daily")
        rendered = ledger.render_dashboard(summary, daily)
        self.assertIn("Co-authored", rendered)
        self.assertIn("Earned field badges", rendered)
        self.assertIn("Builder dimensions", rendered)
        self.assertNotIn("SECRET", rendered)


if __name__ == "__main__":
    unittest.main()
