import argparse
import base64
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
        for attr, filename in (("SCREEN_APPS_CONFIG", "screen_apps.json"),
                               ("PRICING_CONFIG", "pricing.json")):
            patcher = mock.patch.object(ledger, attr, self.root / filename)
            patcher.start()
            self.addCleanup(patcher.stop)

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

    def test_independent_ai_time_is_not_removed_as_daily_overlap(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, "codex:independent", "codex", "session", start,
            start + timedelta(hours=3), "widget",
            meta={"active_s": 10800, "days": {"2026-01-01": 10800},
                  "coauthored_s": 7200, "ai_only_s": 3600})
        for offset in range(37):
            ts = start + timedelta(minutes=offset)
            ledger.insert_event(
                self.db, f"git:{offset}", "git", "commit", ts, ts,
                "widget", items=1)
        self.db.commit()
        summary = ledger.summarize(self.db)
        # Git's capped daily proxy contributes 4h. Only the 2h co-authored
        # portion overlaps it; the 1h independent AI portion remains additive.
        self.assertEqual(summary["raw_total_hours"], 7)
        self.assertEqual(summary["total_hours"], 5)
        self.assertEqual(summary["overlap_discount_hours"], 2)
        self.assertEqual(summary["overlap_discount_pct"], 28.4)

    def test_agent_time_without_steering_detail_uses_conservative_fallback(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, "agent:legacy", "codex", "session", start,
            start + timedelta(hours=3), "widget",
            meta={"active_s": 10800, "days": {"2026-01-01": 10800}})
        for offset in range(37):
            ts = start + timedelta(minutes=offset)
            ledger.insert_event(
                self.db, f"git:legacy:{offset}", "git", "commit", ts, ts,
                "widget", items=1)
        self.db.commit()
        summary = ledger.summarize(self.db)
        self.assertEqual(summary["raw_total_hours"], 7)
        self.assertEqual(summary["total_hours"], 4)
        self.assertEqual(summary["overlap_discount_hours"], 3)

    def test_repository_count_uses_commit_bearing_projects(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        for offset, project in enumerate(("alpha", "beta", "alpha")):
            ts = start + timedelta(minutes=offset)
            ledger.insert_event(
                self.db, f"repo-count:{offset}", "git", "commit", ts, ts,
                project, items=1)
        self.db.commit()
        self.assertEqual(ledger.summarize(self.db)["repositories_with_commits"], 2)

    def test_session_commit_conversion_reports_24h_and_7d_windows(self):
        sessions = [
            ("one", "2026-01-01T12:00:00+00:00"),
            ("two", "2026-01-02T12:00:00+00:00"),
            ("three", "2026-01-05T12:00:00+00:00"),
        ]
        commits = [
            ("one", "2026-01-01T14:00:00+00:00"),
            ("two", "2026-01-04T12:00:00+00:00"),
            ("three", "2026-01-13T12:00:00+00:00"),
        ]
        for uid, timestamp in sessions:
            ts = datetime.fromisoformat(timestamp)
            ledger.insert_event(
                self.db, f"session:{uid}", "codex", "session", ts, ts,
                "widget", meta={"active_s": 60, "days": {ts.date().isoformat(): 60}})
        for uid, timestamp in commits:
            ts = datetime.fromisoformat(timestamp)
            ledger.insert_event(
                self.db, f"commit:{uid}", "git", "commit", ts, ts,
                "widget", items=1)
        self.db.commit()
        analytics = ledger.summarize(self.db)["analytics"]
        self.assertEqual(analytics["session_commit_eligible"], 3)
        self.assertEqual(analytics["session_commit_24h_matches"], 1)
        self.assertEqual(analytics["session_commit_matches"], 2)
        self.assertEqual(analytics["session_commit_24h_conversion_pct"], 33.3)
        self.assertEqual(analytics["session_commit_conversion_pct"], 66.7)
        scorecard = ledger.render_public_scorecard(
            ledger.summarize(self.db), "Test Builder")
        self.assertIn("within 24 hours", scorecard)
        self.assertIn("within 7 days", scorecard)
        self.assertIn("commit-bearing repositories", scorecard)
        self.assertIn("observed workspace identities", scorecard)
        self.assertIn("overlap removed", scorecard)
        self.assertIn("Receipt-backed execution time", scorecard)
        self.assertIn("Evidence floor—not total time worked", scorecard)
        self.assertIn("does not count keystrokes", scorecard)
        self.assertIn("Unobserved research, architecture, debugging", scorecard)
        self.assertIn("--muted:#17211d", scorecard)
        self.assertIn(".score small{color:#fff", scorecard)
        self.assertNotIn("test calls / session", scorecard)

    def test_activity_rhythm_alternates_building_and_off_runs(self):
        rhythm = ledger.activity_rhythm(
            ["2026-01-01", "2026-01-02", "2026-01-04",
             "2026-01-05", "2026-01-06", "2026-01-10"],
            "2026-01-08", "2026-01-02")
        self.assertEqual(rhythm["calendar_days"], 7)
        self.assertEqual(rhythm["active_days"], 4)
        self.assertEqual(rhythm["off_days"], 3)
        self.assertEqual(rhythm["longest_break_days"], 2)
        self.assertEqual(rhythm["streak_count"], 2)
        self.assertEqual(
            [(run["state"], run["days"]) for run in rhythm["runs"]],
            [("building", 1), ("off", 1), ("building", 3), ("off", 2)])
        self.assertEqual(rhythm["start_day"], "2026-01-02")
        self.assertEqual(rhythm["end_day"], "2026-01-08")

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
        self.assertNotIn("shell", serialized)
        self.assertNotIn("pytest", serialized)

    def test_codex_project_skips_dated_task_container(self):
        project = ledger.project_from_path(
            "/Users/test/Documents/Codex/2026-07-25/verify-production")
        self.assertEqual(project, "verify-production")

    def test_gemini_parser_extracts_metadata_without_content(self):
        session = self.root / "session.json"
        session.write_text(json.dumps({
            "sessionId": "gemini-1",
            "startTime": "2026-01-01T12:00:00Z",
            "lastUpdated": "2026-01-01T12:04:00Z",
            "messages": [
                {"type": "user", "timestamp": "2026-01-01T12:00:00Z",
                 "content": [{"text": "SECRET PROMPT"}]},
                {"type": "gemini", "timestamp": "2026-01-01T12:00:30Z",
                 "content": [{"toolCall": {"name": "run_shell_command",
                                            "args": "SECRET COMMAND"}}]},
                {"type": "gemini", "timestamp": "2026-01-01T12:04:00Z",
                 "content": [{"text": "SECRET RESPONSE"}]},
            ],
        }))
        parsed = ledger.parse_gemini_session(session, "widget")
        self.assertEqual(parsed["session_id"], "gemini-1")
        self.assertEqual(parsed["project"], "widget")
        self.assertEqual(parsed["user_messages"], 1)
        self.assertEqual(parsed["items"], 2)
        self.assertEqual(parsed["tools"], 1)
        serialized = json.dumps(parsed, default=str)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("run_shell_command", serialized)

    def test_gemini_jsonl_parser_handles_incremental_records(self):
        session = self.root / "session.jsonl"
        rows = [
            {"sessionId": "gemini-2", "startTime": "2026-01-01T12:00:00Z",
             "lastUpdated": "2026-01-01T12:02:00Z"},
            {"type": "user", "timestamp": "2026-01-01T12:00:00Z",
             "content": "SECRET"},
            {"type": "gemini", "timestamp": "2026-01-01T12:02:00Z",
             "content": "SECRET"},
        ]
        session.write_text("\n".join(json.dumps(row) for row in rows))
        parsed = ledger.parse_gemini_session(session, "widget")
        self.assertEqual(parsed["session_id"], "gemini-2")
        self.assertEqual(parsed["user_messages"], 1)
        self.assertEqual(parsed["items"], 1)
        self.assertEqual(parsed["active_s"], 120)

    def test_antigravity_counts_opaque_trajectory_receipts(self):
        state = self.root / "state.vscdb"
        con = sqlite3.connect(state)
        con.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
        # Two top-level field-1 length-delimited protobuf messages.
        payload = b"\x0a\x03one\x0a\x03two"
        con.execute(
            "INSERT INTO ItemTable(key,value) VALUES(?,?)",
            ("antigravityUnifiedStateSync.trajectorySummaries",
             base64.b64encode(payload).decode()))
        con.commit()
        con.close()
        self.assertEqual(ledger.antigravity_trajectory_count(state), 2)

    def test_grok_parser_extracts_event_metadata_without_content(self):
        session = self.root / "events.jsonl"
        rows = [
            {"ts": "2026-01-01T12:00:00Z", "type": "turn_started",
             "session_id": "grok-1", "model_id": "grok-4.5",
             "session_relationship": "primary", "prompt": "SECRET PROMPT"},
            {"ts": "2026-01-01T12:00:10Z", "type": "tool_started",
             "tool_name": "shell", "arguments": "SECRET COMMAND"},
            {"ts": "2026-01-01T12:03:00Z", "type": "turn_ended",
             "outcome": "completed", "response": "SECRET RESPONSE"},
        ]
        session.write_text("\n".join(json.dumps(row) for row in rows))
        parsed = ledger.parse_grok_session(session, "widget")
        self.assertEqual(parsed["session_id"], "grok-1")
        self.assertEqual(parsed["models"], ["grok-4.5"])
        self.assertEqual(parsed["user_messages"], 1)
        self.assertEqual(parsed["tools"], 1)
        self.assertEqual(parsed["active_s"], 180)
        serialized = json.dumps(parsed, default=str)
        self.assertNotIn("SECRET", serialized)

    def test_github_platform_bot_commits_become_zero_hour_activity(self):
        repo_list = json.dumps([{
            "name": "partsgenie-ai",
            "nameWithOwner": "BMC-INC/partsgenie-ai",
            "isFork": False,
        }])
        stats = json.dumps([{
            "author": {"login": "lovable-dev[bot]"},
            "weeks": [{"w": 1760832000, "c": 3, "a": 100, "d": 10}],
        }])

        def fake_gh(args, timeout=60):
            joined = " ".join(args)
            if "repo list" in joined:
                return 0, repo_list
            if "stats/contributors" in joined:
                return 0, stats
            if "repos/BMC-INC/partsgenie-ai/commits?per_page=100" in joined:
                return 0, "abc123\t2025-10-21T03:50:32Z\n"
            return 1, ""

        with mock.patch.object(ledger, "_gh", side_effect=fake_gh):
            added, notes = ledger.scan_github(
                self.db, ["BMC-INC"], "james", {"partsgenie-ai"})
        self.assertEqual(notes, [])
        self.assertEqual(added, 1)
        row = self.db.execute(
            "SELECT kind,items,meta FROM events WHERE uid LIKE "
            "'github-activity:%'").fetchone()
        self.assertEqual(row[0], "remote_activity")
        self.assertEqual(row[1], 0)
        self.assertTrue(json.loads(row[2])["platform_bot"])
        self.assertEqual(json.loads(row[2])["platform"], "lovable")
        summary = ledger.summarize(self.db)
        self.assertEqual(summary["raw_total_hours"], 0)
        self.assertEqual(summary["activity_rhythm"]["active_days"], 1)

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
        self.assertEqual(
            set(summary["attributed_hours"]), {"your_coding", "ai_coding"})
        self.assertAlmostEqual(
            sum(summary["attributed_hours"].values()), summary["total_hours"])
        summary["scan_state"] = "complete"
        summary["completed_scans"] = 1
        daily = summary.pop("_daily")
        rendered = ledger.render_dashboard(summary, daily)
        self.assertIn("Your Coding", rendered)
        self.assertIn("AI Coding", rendered)
        self.assertNotIn('label:"Co-authored"', rendered)
        self.assertIn('rel="icon"', rendered)
        self.assertIn("Earned field badges", rendered)
        self.assertIn("Builder dimensions", rendered)
        self.assertIn("Workflow analytics", rendered)
        self.assertIn("Session → commit", rendered)
        self.assertIn("Project diversity", rendered)
        self.assertIn("Diversity momentum", rendered)
        self.assertNotIn("Fragmentation", rendered)
        self.assertIn("timestamp-qualified concurrency discount", rendered)
        self.assertIn("Independently running AI time remains additive", rendered)
        self.assertIn("How to read this:", rendered)
        self.assertIn("before concurrency removal", rendered)
        self.assertIn("GitHub aggregates add commits and LOC, never hours", rendered)
        self.assertNotIn("SECRET", rendered)
        landing = ledger.render_landing(summary)
        self.assertIn("Prove how you build", landing)
        self.assertIn("Open the field report", landing)
        self.assertIn("Gemini", landing)
        self.assertIn("Grok Build", landing)
        self.assertNotIn("SECRET", landing)
        public = ledger.render_public_scorecard(summary, "Test Builder")
        self.assertIn("Test Builder", public)
        self.assertIn("Public Builder Scorecard", public)
        self.assertIn("commit-bearing repositories", public)
        self.assertIn("observed workspace identities", public)
        self.assertIn("How the score is evaluated", public)
        self.assertIn("Building rhythm", public)
        self.assertIn("on /", public)
        self.assertNotIn("widget", public)
        self.assertNotIn("SECRET", public)

    def _write_screen_store(self, rows):
        store = self.root / "knowledgeC.db"
        con = sqlite3.connect(store)
        con.execute(
            "CREATE TABLE IF NOT EXISTS ZOBJECT "
            "(ZSTREAMNAME TEXT, ZVALUESTRING TEXT, ZSTARTDATE REAL, ZENDDATE REAL)")
        con.executemany(
            "INSERT INTO ZOBJECT VALUES ('/app/usage',?,?,?)", rows)
        con.commit()
        con.close()
        return store

    @staticmethod
    def _apple(ts):
        return ts.timestamp() - ledger.APPLE_EPOCH_S

    def test_screen_interval_helpers_merge_and_split_at_midnight(self):
        base = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
        merged = ledger.merge_intervals([
            (base, base + timedelta(hours=1)),
            (base + timedelta(minutes=30), base + timedelta(hours=2)),
            (base + timedelta(hours=3), base + timedelta(hours=4)),
        ])
        self.assertEqual(merged, [
            (base, base + timedelta(hours=2)),
            (base + timedelta(hours=3), base + timedelta(hours=4)),
        ])
        start = datetime(2026, 1, 1, 23, 59, 0).astimezone()
        split = ledger.seconds_by_local_day(start, start + timedelta(minutes=2))
        self.assertEqual(len(split), 2)
        self.assertEqual(sum(split.values()), 120)

    def test_screen_scan_persists_all_apps_and_is_idempotent(self):
        start = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        rows = [
            ("com.apple.Terminal", self._apple(start),
             self._apple(start + timedelta(hours=2))),
            # overlaps the first interval — must merge, not double count
            ("com.apple.Terminal", self._apple(start + timedelta(hours=1)),
             self._apple(start + timedelta(hours=1, minutes=30))),
            ("com.apple.Safari", self._apple(start + timedelta(hours=3)),
             self._apple(start + timedelta(hours=6))),
        ]
        store = self._write_screen_store(rows)
        added, notes = ledger.scan_screen(self.db, store=store)
        self.assertEqual(notes, [])
        self.assertEqual(added, 2)
        day = ledger.local_day(start)
        meta = json.loads(self.db.execute(
            "SELECT meta FROM events WHERE uid=?",
            (f"screen:{day}:com.apple.Terminal",)).fetchone()[0])
        self.assertEqual(meta["seconds"], 7200)
        # Safari is persisted (allowlist filtering happens at aggregation)
        self.assertIsNotNone(self.db.execute(
            "SELECT 1 FROM events WHERE uid=?",
            (f"screen:{day}:com.apple.Safari",)).fetchone())
        added, _ = ledger.scan_screen(self.db, store=store)
        self.assertEqual(added, 0)

    def test_screen_missing_store_reports_note(self):
        added, notes = ledger.scan_screen(self.db, store=self.root / "missing.db")
        self.assertEqual(added, 0)
        self.assertEqual(len(notes), 1)

    def test_screen_envelope_adds_only_uncaptured_time(self):
        start = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        day = ledger.local_day(start)
        ledger.insert_event(
            self.db, "codex:screen-test", "codex", "session", start,
            start + timedelta(hours=3), "widget",
            meta={"active_s": 10800, "days": {day: 10800},
                  "coauthored_s": 7200, "ai_only_s": 3600})
        ledger.insert_event(
            self.db, f"screen:{day}:com.apple.Terminal", "screen", "screen",
            start, start + timedelta(hours=6), None, items=3,
            meta={"seconds": 6 * 3600, "day": day, "app": "com.apple.Terminal"})
        # Safari never counts toward the envelope under the default allowlist
        ledger.insert_event(
            self.db, f"screen:{day}:com.apple.Safari", "screen", "screen",
            start, start + timedelta(hours=8), None, items=1,
            meta={"seconds": 8 * 3600, "day": day, "app": "com.apple.Safari"})
        self.db.commit()
        summary = ledger.summarize(self.db)
        # attributed/day = max(0 human, 2h shared) + 1h independent = 3h;
        # screen 6h - foreground 2h = 4h uncaptured; involved = 3 + 4 = 7
        self.assertEqual(summary["total_hours"], 3)
        st = summary["screen_time"]
        self.assertTrue(st["available"])
        self.assertEqual(st["hours"], 6)
        self.assertEqual(st["uncaptured_hours"], 4)
        self.assertEqual(summary["total_involved_hours"], 7)
        self.assertEqual(st["your_coding_involved"], 4)
        self.assertEqual(st["per_app_hours"], {"com.apple.Terminal": 6})
        self.assertIn("screen_coding", summary["involved_formula"])
        summary["scan_state"] = "complete"
        summary["completed_scans"] = 1
        daily = summary.pop("_daily")
        rendered = ledger.render_dashboard(summary, daily)
        self.assertIn("Total involved time", rendered)
        self.assertIn("screen-verified uncaptured", rendered)
        self.assertIn("envelope over", rendered)

    def test_screen_smaller_than_receipts_adds_nothing(self):
        start = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        day = ledger.local_day(start)
        ledger.insert_event(
            self.db, "codex:covered", "codex", "session", start,
            start + timedelta(hours=3), "widget",
            meta={"active_s": 10800, "days": {day: 10800},
                  "coauthored_s": 10800, "ai_only_s": 0})
        ledger.insert_event(
            self.db, f"screen:{day}:com.apple.Terminal", "screen", "screen",
            start, start + timedelta(hours=1), None, items=1,
            meta={"seconds": 3600, "day": day, "app": "com.apple.Terminal"})
        self.db.commit()
        summary = ledger.summarize(self.db)
        self.assertEqual(summary["screen_time"]["uncaptured_hours"], 0)
        self.assertEqual(
            summary["total_involved_hours"], summary["total_hours"])

    def test_screen_day_cap_and_evidence_floor(self):
        day_a = "2026-01-05"
        start_a = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, f"screen:{day_a}:com.apple.Terminal", "screen", "screen",
            start_a, start_a + timedelta(hours=20), None, items=1,
            meta={"seconds": 20 * 3600, "day": day_a, "app": "com.apple.Terminal"})
        self.db.commit()
        summary = ledger.summarize(self.db)
        self.assertEqual(summary["screen_time"]["hours"], 18)
        self.assertEqual(summary["total_involved_hours"], 18)
        self.assertEqual(summary["active_days"], 1)
        # a sub-15-minute day contributes hours but never an active day
        self.db.execute("DELETE FROM events")
        start_b = datetime(2026, 1, 6, 12, tzinfo=timezone.utc)
        day_b = "2026-01-06"
        ledger.insert_event(
            self.db, f"screen:{day_b}:com.apple.Terminal", "screen", "screen",
            start_b, start_b + timedelta(minutes=12), None, items=1,
            meta={"seconds": 720, "day": day_b, "app": "com.apple.Terminal"})
        self.db.commit()
        summary = ledger.summarize(self.db)
        self.assertEqual(summary["active_days"], 0)
        self.assertEqual(summary["total_involved_hours"], 0.2)

    def test_screen_config_overrides_allowlist(self):
        (self.root / "screen_apps.json").write_text(json.dumps({
            "include": ["com.apple.Safari"], "exclude": []}))
        start = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        day = ledger.local_day(start)
        for bundle in ("com.apple.Terminal", "com.apple.Safari"):
            ledger.insert_event(
                self.db, f"screen:{day}:{bundle}", "screen", "screen",
                start, start + timedelta(hours=1), None, items=1,
                meta={"seconds": 3600, "day": day, "app": bundle})
        self.db.commit()
        summary = ledger.summarize(self.db)
        self.assertEqual(
            summary["screen_time"]["per_app_hours"], {"com.apple.Safari": 1})

    def test_report_states_involved_formula_explicitly(self):
        start = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
        day = ledger.local_day(start)
        ledger.insert_event(
            self.db, f"screen:{day}:com.apple.Terminal", "screen", "screen",
            start, start + timedelta(hours=2), None, items=1,
            meta={"seconds": 7200, "day": day, "app": "com.apple.Terminal"})
        self.db.commit()
        out = self.root / "report.md"
        args = argparse.Namespace(db=self.db_path, format="markdown", out=str(out))
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            ledger.cmd_report(args)
        report = out.read_text()
        self.assertIn("Total involved time", report)
        self.assertIn(
            "total_involved(day) = max(human_evidence, shared_ai, "
            "screen_coding) + independent_ai", report)
        self.assertIn("uncaptured", report)

    def test_claude_usage_sums_once_per_message_id(self):
        session = self.root / "claude.jsonl"
        usage = {"input_tokens": 10, "output_tokens": 100,
                 "cache_read_input_tokens": 1000,
                 "cache_creation_input_tokens": 50}
        rows = [
            {"timestamp": "2026-01-01T12:00:00Z", "type": "user",
             "message": {"role": "user", "content": "SECRET"}},
            # same API message logged twice (one line per content block)
            {"timestamp": "2026-01-01T12:00:10Z", "type": "assistant",
             "message": {"id": "msg_a", "model": "claude-fable-5",
                         "usage": usage}},
            {"timestamp": "2026-01-01T12:00:11Z", "type": "assistant",
             "message": {"id": "msg_a", "model": "claude-fable-5",
                         "usage": usage}},
            {"timestamp": "2026-01-01T12:00:30Z", "type": "assistant",
             "message": {"id": "msg_b", "model": "claude-opus-5",
                         "usage": {"input_tokens": 5, "output_tokens": 7}}},
            {"timestamp": "2026-01-01T12:00:40Z", "type": "assistant",
             "message": {"id": "msg_c", "model": "<synthetic>",
                         "usage": {"input_tokens": 9, "output_tokens": 9}}},
        ]
        session.write_text("\n".join(json.dumps(row) for row in rows))
        self.assertTrue(ledger.scan_session_jsonl(
            self.db, session, "claude", "widget", uid="claude:test"))
        meta = json.loads(self.db.execute(
            "SELECT meta FROM events WHERE uid='claude:test'").fetchone()[0])
        self.assertEqual(meta["token_models"]["claude-fable-5"], {
            "input": 10, "output": 100, "cache_read": 1000, "cache_write": 50})
        self.assertEqual(meta["token_models"]["claude-opus-5"], {
            "input": 5, "output": 7, "cache_read": 0, "cache_write": 0})
        self.assertNotIn("<synthetic>", meta["token_models"])
        self.assertEqual(meta["tokens"]["input"], 15)
        self.assertEqual(meta["tokens"]["output"], 107)

    def test_codex_cumulative_token_count_uses_last_event(self):
        session = self.root / "rollout.jsonl"
        rows = [
            {"timestamp": "2026-01-01T12:00:00Z", "type": "session_meta",
             "payload": {"id": "s1", "cwd": "/tmp/widget"}},
            {"timestamp": "2026-01-01T12:00:00Z", "type": "turn_context",
             "payload": {"model": "gpt-5.6-sol"}},
            {"timestamp": "2026-01-01T12:00:01Z", "type": "event_msg",
             "payload": {"type": "user_message"}},
            {"timestamp": "2026-01-01T12:00:10Z", "type": "event_msg",
             "payload": {"type": "token_count", "info": {"total_token_usage": {
                 "input_tokens": 1000, "cached_input_tokens": 600,
                 "cache_write_input_tokens": 0, "output_tokens": 50,
                 "reasoning_output_tokens": 10, "total_tokens": 1050}}}},
            {"timestamp": "2026-01-01T12:01:00Z", "type": "event_msg",
             "payload": {"type": "token_count", "info": {"total_token_usage": {
                 "input_tokens": 5000, "cached_input_tokens": 4000,
                 "cache_write_input_tokens": 0, "output_tokens": 300,
                 "reasoning_output_tokens": 80, "total_tokens": 5300}}}},
        ]
        session.write_text("\n".join(json.dumps(row) for row in rows))
        parsed = ledger.parse_codex_session(session)
        # last cumulative event wins; cached tokens split out of input
        self.assertEqual(parsed["tokens"], {
            "input": 1000, "output": 300, "cache_read": 4000, "cache_write": 0})
        self.assertEqual(list(parsed["token_models"]), ["gpt-5.6-sol"])

    def test_pricing_math_and_user_override(self):
        rates = ledger.load_pricing()
        usd = ledger.price_tokens("claude-fable-5", {
            "input": 1_000_000, "output": 100_000,
            "cache_read": 2_000_000, "cache_write": 400_000}, rates)
        # 1M*$10 + 0.1M*$50 + 2M*$1 + 0.4M*$12.50 = 10 + 5 + 2 + 5 = 22
        self.assertAlmostEqual(usd, 22.0)
        self.assertIsNone(ledger.price_tokens("mystery-model-9", {
            "input": 1000}, rates))
        (self.root / "pricing.json").write_text(json.dumps({
            "claude-fable-5*": {"input": 1, "output": 1,
                                "cache_read": 1, "cache_write": 1}}))
        rates = ledger.load_pricing()
        self.assertAlmostEqual(ledger.price_tokens(
            "claude-fable-5", {"input": 1_000_000}, rates), 1.0)

    def test_spend_is_allocated_across_days_and_summarized(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, "claude:spend", "claude", "session", start,
            start + timedelta(days=1), "widget",
            meta={"active_s": 7200,
                  "days": {"2026-01-01": 5400, "2026-01-02": 1800},
                  "coauthored_s": 7200, "ai_only_s": 0,
                  "token_models": {"claude-opus-5": {
                      "input": 1_000_000, "output": 200_000,
                      "cache_read": 0, "cache_write": 0}}})
        ledger.insert_event(
            self.db, "codex:no-tokens", "codex", "session", start,
            start + timedelta(hours=1), "widget",
            meta={"active_s": 3600, "days": {"2026-01-01": 3600}})
        self.db.commit()
        summary = ledger.summarize(self.db)
        spend = summary["ai_spend"]
        # 1M*$5 + 0.2M*$25 = $10 total, split 75/25 across the two days
        self.assertTrue(spend["available"])
        self.assertEqual(spend["total_usd"], 10.0)
        self.assertEqual(spend["by_source"], {"claude": 10.0})
        self.assertEqual(spend["by_model"], {"claude-opus-5": 10.0})
        self.assertEqual(spend["by_month"], {"2026-01": 10.0})
        self.assertEqual(spend["top_projects"], {"widget": 10.0})
        self.assertEqual(spend["coverage"]["claude"],
                         {"sessions": 1, "with_tokens": 1})
        self.assertEqual(spend["coverage"]["codex"],
                         {"sessions": 1, "with_tokens": 0})
        daily = summary["_daily"]
        self.assertAlmostEqual(daily["spend"]["by_day"]["2026-01-01"], 7.5)
        self.assertAlmostEqual(daily["spend"]["by_day"]["2026-01-02"], 2.5)
        self.assertIn("not what you paid", spend["label"])

    def test_unpriced_models_are_labeled_never_inferred(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, "claude:unpriced", "claude", "session", start,
            start + timedelta(hours=1), "widget",
            meta={"active_s": 3600, "days": {"2026-01-01": 3600},
                  "token_models": {"mystery-model-9": {
                      "input": 500, "output": 100,
                      "cache_read": 0, "cache_write": 0}}})
        self.db.commit()
        spend = ledger.summarize(self.db)["ai_spend"]
        self.assertEqual(spend["total_usd"], 0.0)
        self.assertEqual(spend["unpriced_models"], {"mystery-model-9": 600})

    def test_subscription_roi_multiple_from_meta(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        ledger.insert_event(
            self.db, "claude:roi", "claude", "session", start,
            start + timedelta(hours=1), "widget",
            meta={"active_s": 3600, "days": {"2026-01-01": 3600},
                  "token_models": {"claude-opus-5": {
                      "input": 40_000_000, "output": 0,
                      "cache_read": 0, "cache_write": 0}}})
        ledger.meta_set(self.db, "subscription_usd_month", "100")
        self.db.commit()
        spend = ledger.summarize(self.db)["ai_spend"]
        self.assertEqual(spend["monthly_value_usd"], 200.0)
        self.assertEqual(spend["subscription_roi_multiple"], 2.0)

    def test_project_diversity_compares_multi_project_momentum(self):
        start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        for offset, project in ((0, "alpha"), (24, "alpha"), (25, "beta")):
            ts = start + timedelta(hours=offset)
            ledger.insert_event(
                self.db, f"session:{offset}", "codex", "session", ts,
                ts + timedelta(minutes=1), project,
                meta={"active_s": 60, "days": {ledger.local_day(ts): 60}})
        for offset, project in ((0, "alpha"), (1, "alpha"), (24, "alpha"),
                                (25, "beta"), (26, "beta")):
            ts = start + timedelta(hours=offset)
            ledger.insert_event(
                self.db, f"commit:{offset}", "git", "commit", ts, ts,
                project, items=1)
        self.db.commit()
        summary = ledger.summarize(self.db)
        analytics = summary["analytics"]
        self.assertEqual(analytics["single_project_days"], 1)
        self.assertEqual(analytics["multi_project_days"], 1)
        self.assertEqual(analytics["single_project_commits_per_day"], 2)
        self.assertEqual(analytics["multi_project_commits_per_day"], 3)
        self.assertEqual(analytics["multi_project_commit_change_pct"], 50)
        self.assertGreater(analytics["project_diversity_pct"], 0)


if __name__ == "__main__":
    unittest.main()
