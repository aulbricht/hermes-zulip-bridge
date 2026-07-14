from __future__ import annotations

import argparse
import copy
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from hermes_zulip_bridge import smoke


def zulip_success(**payload: object) -> dict:
    return {"result": "success", "msg": "", **payload}


def narrow_match(content: str = "", subject: str = "Smoke") -> dict[str, str]:
    return {"match_content": content, "match_subject": subject}


def stream_message(
    message_id: int,
    content: str,
    *,
    topic: str = "Smoke",
    sender_id: int = 17,
    sender_email: str = "user@example.com",
    sender_is_bot: bool = False,
) -> dict:
    return {
        "id": message_id,
        "type": "stream",
        "stream_id": 7,
        "display_recipient": "hermes",
        "topic": topic,
        "sender_id": sender_id,
        "sender_email": sender_email,
        "sender_full_name": "Test User",
        "sender_is_bot": sender_is_bot,
        "content": content,
    }


class SmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        policy = mock.patch.multiple(
            smoke.bridge,
            ALLOWED_SENDERS={"id:17"},
            TOPIC_POLICY="any",
            REQUIRE_MENTION=False,
            HERMES_EXTRA_ARGS=["--toolsets", "coding"],
        )
        policy.start()
        self.addCleanup(policy.stop)
        self.state_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_dir.cleanup)
        state_patch = mock.patch.object(smoke.bridge, "STATE_PATH", Path(self.state_dir.name) / "state.json")
        aliases_patch = mock.patch.object(smoke.bridge, "ALIASES_PATH", Path(self.state_dir.name) / "aliases.json")
        state_patch.start()
        aliases_patch.start()
        self.addCleanup(state_patch.stop)
        self.addCleanup(aliases_patch.stop)
        self.venv = Path(self.state_dir.name) / "venv"
        (self.venv / "bin").mkdir(parents=True, mode=0o700)
        python_home = Path(sys.executable).resolve().parent
        (self.venv / "pyvenv.cfg").write_text(f"home = {python_home}\n", encoding="utf-8")
        (self.venv / "pyvenv.cfg").chmod(0o600)
        self.venv_python = self.venv / "bin" / "python"
        self.venv_python.symlink_to(Path(sys.executable).resolve())

    def write_python_console(self, path: Path) -> None:
        path.write_text(f"#!{self.venv_python}\n", encoding="utf-8")
        path.chmod(0o700)

    def run_durable_smoke(
        self,
        state: dict,
        save_json: object,
        hermes_reply: object,
        *,
        post_reply: bool = False,
        reply: object | None = None,
        reconcile: object | None = None,
    ) -> dict:
        def fake_api(_rc: dict[str, str], method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com", user_id=99)
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if method == "POST" and path == "/api/v1/messages":
                return zulip_success(id=123)
            if path == "/api/v1/messages/123":
                return zulip_success(
                    message=stream_message(
                        123, "probe", sender_id=99, sender_email="bot@example.com", sender_is_bot=True
                    )
                )
            if path == "/api/v1/messages/456":
                return zulip_success(message=stream_message(456, "human smoke request"))
            raise AssertionError((method, path))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            replacements = {
                "load_rc": lambda: {
                    "site": "https://zulip.example.com",
                    "email": "bot@example.com",
                    "key": "test-api-key",
                },
                "load_json": lambda *_args: state,
                "save_json": save_json,
                "load_alias_entries": lambda: [],
                "load_state_signing_key": lambda *_args, **_kwargs: b"k" * 32,
                "api": fake_api,
                "append_steering_message": lambda *_args, **_kwargs: {
                    "formatted": smoke.bridge.OUT_OF_BAND_USER_MESSAGE_OPEN
                },
                "HERMES": hermes,
                "STEERING_PATH": Path(tmpdir) / "steering.jsonl",
                "ALLOW_STREAMS": {"hermes"},
                "ALLOW_STREAM_IDS": {"7"},
                "ALLOW_TOPICS": {"Smoke"},
                "hermes_reply": hermes_reply,
            }
            if reply is not None:
                replacements["reply"] = reply
            if reconcile is not None:
                replacements["reconcile_pending_replies"] = reconcile
            with mock.patch.multiple(smoke.bridge, **replacements):
                return smoke.run(
                    argparse.Namespace(
                        stream="hermes",
                        topic="Smoke",
                        message="probe",
                        post_probe=True,
                        run_hermes=True,
                        human_origin_message_id=456,
                        post_reply=post_reply,
                    )
                )

    def test_no_post_smoke_persists_admission_start_seen_then_retirement(self) -> None:
        state: dict = {"seen_ids": [], "topic_sessions": {}}
        snapshots: list[dict] = []
        runs = 0

        def save_json(_path: Path, candidate: dict) -> None:
            snapshots.append(copy.deepcopy(candidate))

        def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
            nonlocal runs
            runs += 1
            message["_zulip_before_hermes_start"]()
            message["_zulip_execution"]["hermes_started"] = True
            return "ok", "s1"

        result = self.run_durable_smoke(state, save_json, run_hermes)

        stages = [
            (
                list(item.get("seen_ids", [])),
                [origin["stage"] for origin in item.get("origin_in_flight", [])],
            )
            for item in snapshots
        ]
        self.assertTrue(result["ok"])
        self.assertEqual(runs, 1)
        self.assertEqual(
            stages,
            [([], ["admitted"]), ([], ["hermes_may_start"]), ([456], ["hermes_may_start"]), ([456], [])],
        )

    def test_smoke_completion_retries_only_transient_state_saves(self) -> None:
        state: dict = {"seen_ids": [], "topic_sessions": {}}
        attempts = 0
        hermes_runs = 0

        def save_json(_path: Path, _candidate: dict) -> None:
            nonlocal attempts
            attempts += 1
            if attempts in {3, 4}:
                raise smoke.bridge.StatePersistenceError("transient")

        def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
            nonlocal hermes_runs
            hermes_runs += 1
            message["_zulip_before_hermes_start"]()
            message["_zulip_execution"]["hermes_started"] = True
            return "ok", "s1"

        result = self.run_durable_smoke(state, save_json, run_hermes)

        self.assertTrue(result["ok"])
        self.assertEqual((hermes_runs, attempts), (1, 6))
        self.assertEqual(state["seen_ids"], [456])
        self.assertEqual(state["origin_in_flight"], [])

    def test_admission_save_failure_rolls_back_before_hermes_and_allows_later_run(self) -> None:
        state: dict = {"seen_ids": [], "topic_sessions": {}}
        hermes_runs = 0

        def rejected_save(_path: Path, _candidate: dict) -> None:
            raise smoke.bridge.StatePersistenceError("transient admission failure")

        def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
            nonlocal hermes_runs
            hermes_runs += 1
            message["_zulip_before_hermes_start"]()
            message["_zulip_execution"]["hermes_started"] = True
            return "ok", "s1"

        with self.assertRaisesRegex(SystemExit, "StatePersistenceError"):
            self.run_durable_smoke(state, rejected_save, run_hermes)
        self.assertEqual(hermes_runs, 0)
        self.assertEqual(state.get("origin_in_flight", []), [])
        self.assertEqual(state.get("zulip_threads", {}), {})

        result = self.run_durable_smoke(state, lambda *_args: None, run_hermes)
        self.assertTrue(result["ok"])
        self.assertEqual(hermes_runs, 1)

    def test_confirmed_post_persists_proof_seen_reconciliation_and_retirement(self) -> None:
        state: dict = {"seen_ids": [], "topic_sessions": {}}
        snapshots: list[dict] = []
        calls = {"hermes": 0, "reply": 0, "reconcile": 0}

        def save_json(_path: Path, candidate: dict) -> None:
            snapshots.append(copy.deepcopy(candidate))

        def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
            calls["hermes"] += 1
            message["_zulip_before_hermes_start"]()
            message["_zulip_execution"]["hermes_started"] = True
            return "ok", "s1"

        def post_reply(_rc: dict, message: dict, _content: str) -> None:
            calls["reply"] += 1
            state["reply_reconciliations"] = [{"origin_message_id": 456, "sent_message_id": 124}]
            message["_zulip_persist"]()

        def reconcile(_rc: dict, candidate: dict, _key: bytes, **_kwargs: object) -> None:
            calls["reconcile"] += 1
            self.assertIn(456, candidate["seen_ids"])
            self.assertEqual(candidate["origin_in_flight"][0]["stage"], "hermes_may_start")
            self.assertEqual(candidate["reply_reconciliations"][0]["sent_message_id"], 124)
            candidate["reply_reconciliations"].clear()

        result = self.run_durable_smoke(
            state, save_json, run_hermes, post_reply=True, reply=post_reply, reconcile=reconcile
        )

        proof = [
            (
                456 in item.get("seen_ids", []),
                bool(item.get("origin_in_flight")),
                bool(item.get("reply_reconciliations")),
            )
            for item in snapshots
        ]
        self.assertTrue(result["ok"])
        self.assertEqual(calls, {"hermes": 1, "reply": 1, "reconcile": 1})
        self.assertEqual(
            proof,
            [
                (False, True, False),
                (False, True, False),
                (False, True, True),
                (True, True, True),
                (True, True, False),
                (True, False, False),
            ],
        )

    def test_confirmed_post_transient_proof_failures_never_repeat_hermes_or_post(self) -> None:
        state: dict = {"seen_ids": [], "topic_sessions": {}}
        attempts = 0
        calls = {"hermes": 0, "reply": 0}

        def save_json(_path: Path, _candidate: dict) -> None:
            nonlocal attempts
            attempts += 1
            if attempts in {3, 4}:
                raise smoke.bridge.StatePersistenceError("transient")

        def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
            calls["hermes"] += 1
            message["_zulip_before_hermes_start"]()
            message["_zulip_execution"]["hermes_started"] = True
            return "ok", "s1"

        def post_reply(_rc: dict, _message: dict, _content: str) -> None:
            calls["reply"] += 1
            state["reply_reconciliations"] = [{"origin_message_id": 456, "sent_message_id": 124}]
            raise smoke.bridge.ConfirmedReplyPersistencePending(124, "s1")

        def reconcile(_rc: dict, candidate: dict, _key: bytes, **_kwargs: object) -> None:
            candidate["reply_reconciliations"].clear()

        result = self.run_durable_smoke(
            state, save_json, run_hermes, post_reply=True, reply=post_reply, reconcile=reconcile
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls, {"hermes": 1, "reply": 1})
        self.assertEqual(attempts, 8)
        self.assertEqual(state["seen_ids"], [456])
        self.assertEqual(state["origin_in_flight"], [])

    def test_pending_reconciliation_fails_closed_with_seen_and_post_proof_durable(self) -> None:
        state: dict = {"seen_ids": [], "topic_sessions": {}}
        calls = {"hermes": 0, "reply": 0}

        def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
            calls["hermes"] += 1
            message["_zulip_before_hermes_start"]()
            message["_zulip_execution"]["hermes_started"] = True
            return "ok", "s1"

        def post_reply(_rc: dict, message: dict, _content: str) -> None:
            calls["reply"] += 1
            state["reply_reconciliations"] = [{"origin_message_id": 456, "sent_message_id": 124}]
            message["_zulip_persist"]()

        with self.assertRaisesRegex(SystemExit, "StatePersistenceError"):
            self.run_durable_smoke(
                state,
                lambda *_args: None,
                run_hermes,
                post_reply=True,
                reply=post_reply,
                reconcile=lambda *_args, **_kwargs: None,
            )

        self.assertEqual(calls, {"hermes": 1, "reply": 1})
        self.assertEqual(state["seen_ids"], [456])
        self.assertEqual(state["origin_in_flight"][0]["stage"], "hermes_may_start")
        self.assertEqual(state["reply_reconciliations"], [{"origin_message_id": 456, "sent_message_id": 124}])

    def test_post_hermes_persistence_exhaustion_is_bounded_and_leaves_restart_proof(self) -> None:
        attempts = 0

        def fail(_path: Path, _state: dict) -> None:
            nonlocal attempts
            attempts += 1
            raise smoke.bridge.StatePersistenceError("permanent")

        with (
            mock.patch.object(smoke.bridge, "save_json", side_effect=fail),
            mock.patch.object(smoke.bridge, "MAX_DURABLE_ATTEMPTS", 1),
            self.assertRaisesRegex(smoke.bridge.StatePersistenceError, "persistence exhausted"),
        ):
            smoke._persist_after_hermes(Path(self.state_dir.name) / "state.json", {"seen_ids": [456]})
        self.assertEqual(attempts, 1)

    def test_post_hermes_failure_and_uncertain_post_restart_terminalize_without_replay(self) -> None:
        failures = {
            "hermes": RuntimeError("failed after start"),
            "post": smoke.bridge.ReplyPostUncertain("unknown POST outcome"),
        }
        for stage, failure in failures.items():
            with self.subTest(stage=stage):
                state: dict = {"seen_ids": [], "topic_sessions": {}}
                persisted: list[dict] = []
                calls = {"hermes": 0, "reply": 0}

                def save_json(_path: Path, candidate: dict) -> None:
                    persisted.append(copy.deepcopy(candidate))

                def run_hermes(_rc: dict, message: dict, _session_id: str | None) -> tuple[str, str]:
                    calls["hermes"] += 1
                    message["_zulip_before_hermes_start"]()
                    message["_zulip_execution"]["hermes_started"] = True
                    if stage == "hermes":
                        raise failure
                    return "ok", "s1"

                def post_reply(_rc: dict, _message: dict, _content: str) -> None:
                    calls["reply"] += 1
                    raise failure

                with self.assertRaisesRegex(SystemExit, "Smoke test failed"):
                    self.run_durable_smoke(
                        state,
                        save_json,
                        run_hermes,
                        post_reply=stage == "post",
                        reply=post_reply,
                    )

                recovered = copy.deepcopy(persisted[-1])
                with self.assertRaisesRegex(SystemExit, "durable processing evidence"):
                    smoke._recover_and_refuse_durable_origin(
                        recovered, Path(self.state_dir.name) / "state.json", 456
                    )
                self.assertEqual(calls, {"hermes": 1, "reply": 1 if stage == "post" else 0})
                self.assertEqual(recovered["origin_in_flight"], [])
                self.assertIn(456, recovered["seen_ids"])
                self.assertEqual(recovered["dead_letters"][0]["reason"], "smoke_restart_after_hermes_may_start")

    def test_smoke_refuses_all_existing_durable_origin_states(self) -> None:
        in_flight = {"origin_message_id": 456, "stage": "admitted", "attempts": 0, "created_at": 1.0}
        retry = {"origin_message_id": 456, "attempts": 1, "created_at": 1.0, "next_attempt_at": 1.0}
        dead = {"origin_message_id": 456}
        cases = {
            "seen": {"seen_ids": [456]},
            "in-flight": {"origin_in_flight": [in_flight]},
            "retry": {"origin_retries": [retry]},
            "terminal": {"dead_letters": [dead]},
            "reconciliation": {"reply_reconciliations": [{"origin_message_id": 456}]},
        }
        for label, state in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(SystemExit, "durable processing evidence"):
                smoke._recover_and_refuse_durable_origin(
                    state, Path(self.state_dir.name) / "state.json", 456
                )

    def test_restart_with_confirmed_reply_keeps_reconciliation_proof_and_refuses_replay(self) -> None:
        state = {
            "origin_in_flight": [
                {
                    "origin_message_id": 456,
                    "stage": "hermes_may_start",
                    "attempts": 0,
                    "created_at": 1.0,
                }
            ],
            "reply_reconciliations": [{"origin_message_id": 456, "sent_message_id": 124}],
        }
        persisted: list[dict] = []
        with (
            mock.patch.object(
                smoke.bridge,
                "save_json",
                side_effect=lambda _path, candidate: persisted.append(copy.deepcopy(candidate)),
            ),
            self.assertRaisesRegex(SystemExit, "durable processing evidence"),
        ):
            smoke._recover_and_refuse_durable_origin(
                state, Path(self.state_dir.name) / "state.json", 456
            )

        self.assertEqual(state["origin_in_flight"], [])
        self.assertEqual(state["seen_ids"], [456])
        self.assertEqual(state["reply_reconciliations"], [{"origin_message_id": 456, "sent_message_id": 124}])
        self.assertEqual(state.get("dead_letters", []), [])
        self.assertEqual(persisted, [state])

    def test_post_reply_requires_posted_probe_origin(self) -> None:
        with self.assertRaisesRegex(SystemExit, "--post-probe"):
            smoke.run(
                argparse.Namespace(
                    stream="hermes",
                    topic="Smoke",
                    message="probe",
                    post_probe=False,
                    run_hermes=True,
                    human_origin_message_id=456,
                    post_reply=True,
                )
            )

    def test_run_hermes_requires_post_probe_before_lock_or_state_side_effects(self) -> None:
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=False,
            run_hermes=True,
            human_origin_message_id=456,
            post_reply=False,
        )
        with (
            mock.patch.object(smoke.bridge, "process_lock") as lock,
            mock.patch.object(smoke.bridge, "load_json") as load_state,
            mock.patch.object(smoke.bridge, "load_rc") as load_rc,
            mock.patch.object(smoke.bridge, "api") as api,
            mock.patch.object(smoke.bridge, "hermes_reply") as hermes,
            self.assertRaisesRegex(SystemExit, "--run-hermes requires --post-probe"),
        ):
            smoke.run(args)

        lock.assert_not_called()
        load_state.assert_not_called()
        load_rc.assert_not_called()
        api.assert_not_called()
        hermes.assert_not_called()

    def test_run_hermes_requires_explicit_human_origin_before_side_effects(self) -> None:
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=True,
            run_hermes=True,
            post_reply=False,
        )
        with mock.patch.object(smoke.bridge, "process_lock") as lock, self.assertRaisesRegex(
            SystemExit, "--human-origin-message-id"
        ):
            smoke.run(args)
        lock.assert_not_called()

    def test_required_bot_identity_fails_before_smoke_state_is_loaded_or_saved(self) -> None:
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=False,
            run_hermes=False,
            human_origin_message_id=None,
            post_reply=False,
        )
        load_state = mock.Mock()
        save_state = mock.Mock()
        api = mock.Mock(return_value=zulip_success(email="bot@example.com"))
        with smoke.bridge.process_lock() as held_lock, mock.patch.multiple(
            smoke.bridge,
            REQUIRE_MENTION=True,
            load_json=load_state,
            save_json=save_state,
            api=api,
        ), self.assertRaisesRegex(SystemExit, "identity preflight failed"):
            smoke.run(
                args,
                lock=held_lock,
                hermes_launcher=mock.sentinel.launcher,
                rc={"site": "https://example", "email": "bot@example.com", "key": "key"},
            )

        api.assert_called_once_with(
            {"site": "https://example", "email": "bot@example.com", "key": "key"},
            "GET",
            "/api/v1/users/me",
        )
        load_state.assert_not_called()
        save_state.assert_not_called()

    def test_smoke_process_lock_blocks_all_side_effects_then_releases(self) -> None:
        holder_code = """
import sys
from pathlib import Path
from hermes_zulip_bridge import bridge

with bridge.process_lock(Path(sys.argv[1])):
    print("locked", flush=True)
    sys.stdin.read(1)
"""
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
        holder = subprocess.Popen(
            [sys.executable, "-c", holder_code, str(smoke.bridge.STATE_PATH)],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        load_rc = mock.Mock()
        load_state = mock.Mock()
        api = mock.Mock()
        hermes_reply = mock.Mock()
        post_reply = mock.Mock()
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=True,
            run_hermes=True,
            human_origin_message_id=456,
            post_reply=True,
        )
        try:
            self.assertEqual(holder.stdout.readline(), "locked\n")
            with (
                mock.patch.multiple(
                    smoke.bridge,
                    load_rc=load_rc,
                    load_json=load_state,
                    api=api,
                    hermes_reply=hermes_reply,
                    reply=post_reply,
                ),
                mock.patch.object(
                    smoke.bridge,
                    "_python_console_script",
                    return_value=(str(Path(sys.executable)), str(Path(sys.executable))),
                ),
                self.assertRaisesRegex(SystemExit, re.escape(smoke.bridge.PROCESS_LOCK_UNAVAILABLE)),
            ):
                smoke.run(args, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})
        finally:
            _stdout, stderr = holder.communicate(input="\n", timeout=5)
            holder.stdin.close()
            holder.stdout.close()
            holder.stderr.close()

        self.assertEqual(holder.returncode, 0, stderr)
        load_rc.assert_not_called()
        load_state.assert_not_called()
        api.assert_not_called()
        hermes_reply.assert_not_called()
        post_reply.assert_not_called()
        launcher = (str(Path(sys.executable)), str(Path(sys.executable)))
        with mock.patch.object(smoke.bridge, "_python_console_script", return_value=launcher), mock.patch.object(
            smoke, "_run", return_value={"ok": True, "checks": {}}
        ) as run_unlocked:
            self.assertTrue(smoke.run(args, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})["ok"])
        run_unlocked.assert_called_once_with(args, smoke.bridge.STATE_PATH.resolve(), launcher, {"site": "https://example", "email": "bot@example.com", "key": "key"})

        with smoke.bridge.process_lock(smoke.bridge.STATE_PATH) as held_lock:
            with (
                mock.patch.object(smoke.bridge, "process_lock") as reacquire,
                mock.patch.object(smoke.bridge, "_python_console_script", return_value=launcher),
                mock.patch.object(smoke, "_run", return_value={"ok": True, "checks": {}}),
            ):
                self.assertTrue(smoke.run(args, lock=held_lock, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})["ok"])
        reacquire.assert_not_called()

    def test_smoke_public_errors_escape_terminal_controls(self) -> None:
        hostile = "bad\nstream\t\x1b]2;title\x07" + chr(0x202E)
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=False,
            run_hermes=False,
            post_reply=False,
        )
        with mock.patch.object(
            smoke.bridge,
            "_python_console_script",
            return_value=(str(Path(sys.executable)), str(Path(sys.executable))),
        ), mock.patch.object(
            smoke.bridge, "process_lock", side_effect=smoke.bridge.ProcessLockError(hostile)
        ), self.assertRaises(SystemExit) as raised:
            smoke.run(args, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})
        rendered = str(raised.exception)
        self.assertNotIn("\n", rendered)
        self.assertNotIn("\t", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("\\u000a", rendered)
        self.assertIn("\\u202e", rendered)

        with mock.patch.object(smoke.bridge, "api", return_value=zulip_success(streams=[])), self.assertRaises(
            SystemExit
        ) as stream_error:
            smoke._stream_id({}, hostile)
        self.assertNotIn("\n", str(stream_error.exception))
        self.assertEqual(str(stream_error.exception), "Unable to resolve requested Zulip stream")

    def test_smoke_uses_handed_off_lock_canonical_state_path(self) -> None:
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=False,
            run_hermes=False,
            post_reply=False,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            launcher = (str(Path(sys.executable)), str(Path(sys.executable)))
            with smoke.bridge.process_lock(Path(tmpdir) / "other-state") as wrong_lock, mock.patch.object(
                smoke.bridge, "_python_console_script", return_value=launcher
            ), mock.patch.object(smoke, "_run", return_value={"ok": True, "checks": {}}) as run:
                self.assertTrue(smoke.run(args, lock=wrong_lock, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})["ok"])
        run.assert_called_once_with(args, wrong_lock.state_path, launcher, {"site": "https://example", "email": "bot@example.com", "key": "key"})

    def test_smoke_default_mode_rejects_corrupt_persistence_before_side_effects(self) -> None:
        state_path = smoke.bridge.STATE_PATH
        aliases_path = smoke.bridge.ALIASES_PATH
        steering_path = Path(str(state_path.parent / "steering.jsonl") + ".smoke")
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=False,
            run_hermes=False,
            post_reply=False,
        )
        cases = [
            ("state", b"[]", b'{"aliases": []}', "ValueError"),
            (
                "alias manifest",
                b'{"seen_ids": [], "topic_sessions": {}}',
                b'{"aliases": [',
                "JSONDecodeError",
            ),
        ]
        for label, state_bytes, alias_bytes, error_type in cases:
            side_effects = {
                name: mock.Mock(side_effect=AssertionError(name))
                for name in (
                    "load_rc",
                    "api",
                    "hermes_reply",
                    "reply",
                    "append_steering_message",
                    "save_json",
                    "bind_state_realm",
                    "load_aliases",
                    "apply_alias_repairs",
                    "resolve_session",
                    "allowed_stream_topic",
                    "stream_id",
                )
            }
            with self.subTest(label=label):
                hermes_launcher = mock.Mock(
                    return_value=(str(Path(sys.executable)), str(Path(sys.executable)))
                )
                state_path.write_bytes(state_bytes)
                aliases_path.write_bytes(alias_bytes)
                aliases_path.chmod(0o600)
                steering_path.unlink(missing_ok=True)
                with (
                    mock.patch.multiple(
                        smoke.bridge,
                        load_rc=side_effects["load_rc"],
                        api=side_effects["api"],
                        hermes_reply=side_effects["hermes_reply"],
                        reply=side_effects["reply"],
                        append_steering_message=side_effects["append_steering_message"],
                        save_json=side_effects["save_json"],
                        bind_state_realm=side_effects["bind_state_realm"],
                        load_aliases=side_effects["load_aliases"],
                        apply_alias_repairs=side_effects["apply_alias_repairs"],
                        resolve_session=side_effects["resolve_session"],
                        allowed_stream_topic=side_effects["allowed_stream_topic"],
                        STEERING_PATH=state_path.parent / "steering.jsonl",
                    ),
                    mock.patch.object(smoke.bridge, "_python_console_script", hermes_launcher),
                    mock.patch.object(smoke, "_stream_id", side_effects["stream_id"]),
                    self.assertRaisesRegex(SystemExit, rf"^Smoke test failed \({error_type}\)$"),
                ):
                    smoke.run(args, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})

                for side_effect in side_effects.values():
                    side_effect.assert_not_called()
                hermes_launcher.assert_called_once_with(str(smoke.bridge.HERMES))
                self.assertFalse(steering_path.exists())
                self.assertEqual(state_path.read_bytes(), state_bytes)
                self.assertEqual(aliases_path.read_bytes(), alias_bytes)

    def test_smoke_auth_and_hermes_preflights_fail_before_route_or_side_effects(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        cases = [
            ("auth", {}, True, "authentication preflight failed"),
            ("Hermes", {"email": "bot@example.com"}, False, "Hermes executable preflight failed"),
        ]
        for label, me, hermes_exists, error in cases:
            api = mock.Mock(return_value=me)
            hermes_reply = mock.Mock()
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmpdir:
                hermes = Path(tmpdir) / "hermes"
                if hermes_exists:
                    self.write_python_console(hermes)
                with mock.patch.multiple(
                    smoke.bridge,
                    load_rc=lambda: rc,
                    api=api,
                    HERMES=hermes,
                    hermes_reply=hermes_reply,
                ):
                    with self.assertRaisesRegex(SystemExit, error):
                        smoke.run(
                            argparse.Namespace(
                                stream="hermes",
                                topic="Smoke",
                                message="probe",
                                post_probe=True,
                                run_hermes=True,
                                human_origin_message_id=456,
                                post_reply=True,
                            )
                        )

            if hermes_exists:
                api.assert_called_once_with(rc, "GET", "/api/v1/users/me")
            else:
                api.assert_not_called()
            hermes_reply.assert_not_called()

    def test_secure_hermes_preflight_rejects_hostile_commands_before_every_side_effect(self) -> None:
        args = argparse.Namespace(
            stream="hermes",
            topic="Smoke",
            message="probe",
            post_probe=False,
            run_hermes=False,
            post_reply=False,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            valid = root / "valid.py"
            self.write_python_console(valid)
            directory = root / "directory"
            directory.mkdir()
            symlink = root / "symlink.py"
            symlink.symlink_to(valid)
            wrong_interpreter = root / "wrong-interpreter.py"
            wrong_interpreter.write_text("#!/bin/sh\n", encoding="utf-8")
            wrong_interpreter.chmod(0o700)
            relative_interpreter = root / "relative-interpreter.py"
            relative_interpreter.write_text("#!python3\n", encoding="utf-8")
            relative_interpreter.chmod(0o700)
            env_interpreter = root / "env-interpreter.py"
            env_interpreter.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            env_interpreter.chmod(0o700)
            nonexec = root / "nonexec.py"
            nonexec.write_text(f"#!{sys.executable}\n", encoding="utf-8")
            nonexec.chmod(0o600)

            cases = {
                "missing": root / "missing.py",
                "directory": directory,
                "symlink": symlink,
                "wrong interpreter": wrong_interpreter,
                "relative interpreter": relative_interpreter,
                "env interpreter": env_interpreter,
                "non-executable": nonexec,
            }
            for label, command in cases.items():
                process_lock = mock.Mock()
                load_state = mock.Mock()
                save_state = mock.Mock()
                api = mock.Mock()
                run = mock.Mock()
                with (
                    self.subTest(label=label),
                    mock.patch.object(smoke.bridge, "HERMES", command),
                    mock.patch.object(smoke.bridge, "process_lock", process_lock),
                    mock.patch.object(smoke.bridge, "load_json", load_state),
                    mock.patch.object(smoke.bridge, "save_json", save_state),
                    mock.patch.object(smoke.bridge, "api", api),
                    mock.patch.object(smoke, "_run", run),
                    self.assertRaisesRegex(SystemExit, "Hermes executable preflight failed"),
                ):
                    smoke.run(args, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})
                for side_effect in (process_lock, load_state, save_state, api, run):
                    side_effect.assert_not_called()

            held = mock.Mock(state_path=root / "state.json")
            result = {"ok": True, "checks": {}}
            with (
                mock.patch.object(smoke.bridge, "HERMES", valid),
                mock.patch.object(smoke.bridge, "freeze_auxiliary_paths") as freeze,
                mock.patch.object(smoke, "_run", return_value=result) as run,
            ):
                self.assertEqual(smoke.run(args, lock=held, rc={"site": "https://example", "email": "bot@example.com", "key": "key"}), result)
            held.validate.assert_called_once_with(held.state_path)
            freeze.assert_called_once_with(held.state_path)
            proof = run.call_args.args[2]
            self.assertIsInstance(proof, smoke.LauncherProof)
            self.assertEqual(tuple(proof), (str(valid.resolve()), str(Path(sys.executable).resolve())))

            launcher = (str(valid.resolve()), str(Path(sys.executable).resolve()))
            with (
                mock.patch.object(smoke.bridge, "_python_console_script") as validate,
                mock.patch.object(smoke, "_run", return_value=result) as handed_off,
            ):
                self.assertEqual(smoke.run(args, lock=held, hermes_launcher=launcher, rc={"site": "https://example", "email": "bot@example.com", "key": "key"}), result)
            validate.assert_not_called()
            handed_off.assert_called_once_with(args, held.state_path, launcher, {"site": "https://example", "email": "bot@example.com", "key": "key"})

    def test_smoke_unexpected_stage_failures_expose_only_generic_type_reference(self) -> None:
        secret = "SECRET-CANARY-smoke-boundary"
        stages = ("auth", "stream", "post", "unexpected")
        for stage in stages:
            logs: list[tuple[object, ...]] = []

            def fake_api(_rc: dict[str, str], method: str, path: str, **_kwargs: object) -> dict:
                if path == "/api/v1/users/me":
                    if stage == "auth":
                        raise RuntimeError(secret)
                    return zulip_success(email="bot@example.com")
                if path == "/api/v1/streams":
                    if stage == "stream":
                        raise RuntimeError(secret)
                    return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
                if method == "POST" and path == "/api/v1/messages":
                    if stage == "post":
                        raise RuntimeError(secret)
                    return zulip_success(id=123)
                if path == "/api/v1/messages/123":
                    return zulip_success(
                        message={
                            "id": 123,
                            "type": "stream",
                            "stream_id": 7,
                            "display_recipient": "hermes",
                            "topic": "Smoke",
                            "content": "probe",
                        }
                    )
                raise AssertionError((method, path))

            def append_steering(*_args: object, **_kwargs: object) -> dict:
                if stage == "unexpected":
                    raise RuntimeError(secret)
                return {"formatted": smoke.bridge.OUT_OF_BAND_USER_MESSAGE_OPEN}

            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmpdir:
                hermes = Path(tmpdir) / "hermes"
                self.write_python_console(hermes)
                with mock.patch.multiple(
                    smoke.bridge,
                    load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    load_json=lambda *_args: {"seen_ids": [], "topic_sessions": {}},
                    load_alias_entries=lambda: [],
                    api=fake_api,
                    log=lambda *parts: logs.append(parts),
                    append_steering_message=append_steering,
                    HERMES=hermes,
                    STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                    ALLOW_STREAMS={"hermes"},
                    ALLOW_STREAM_IDS=set(),
                    ALLOW_TOPICS=set(),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        smoke.run(
                            argparse.Namespace(
                                stream="hermes",
                                topic="Smoke",
                                message="probe",
                                post_probe=True,
                                run_hermes=False,
                                post_reply=False,
                            )
                        )

            self.assertEqual(str(raised.exception), "Smoke test failed (RuntimeError)")
            self.assertEqual(logs, [("smoke_failed", "RuntimeError")])
            self.assertNotIn(secret, str(raised.exception))
            self.assertNotIn(secret, repr(logs))

    def test_smoke_run_posts_probe_and_checks_steering_without_hermes(self) -> None:
        calls: list[tuple[str, str]] = []
        probe_posts: list[dict] = []

        def fake_api(_rc: dict[str, str], method: str, path: str, **_kwargs: object) -> dict:
            calls.append((method, path))
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com")
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if method == "POST" and path == "/api/v1/messages":
                probe_posts.append(dict(_kwargs.get("data") or {}))
                return zulip_success(id=123)
            if path == "/api/v1/messages/123":
                return zulip_success(
                    message={
                        "id": 123,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_full_name": "Hermes bot",
                        "sender_email": "bot@example.com",
                        "content": "probe",
                    }
                )
            if path == "/api/v1/messages/124":
                return zulip_success(
                    message={
                        "id": 124,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_email": "bot@example.com",
                    }
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"123": narrow_match()})
            raise AssertionError(path)

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            with mock.patch.multiple(
                smoke.bridge,
                load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                load_json=lambda *_args: {"seen_ids": [], "topic_sessions": {}},
                load_alias_entries=lambda: [],
                api=fake_api,
                HERMES=hermes,
                STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                ALLOW_STREAMS={"hermes"},
                ALLOW_STREAM_IDS=set(),
                ALLOW_TOPICS=set(),
            ):
                result = smoke.run(argparse.Namespace(stream="", topic="Smoke", message="probe", post_probe=True, run_hermes=False, post_reply=False))

        self.assertTrue(result["ok"])
        self.assertEqual(
            calls[:4],
            [
                ("GET", "/api/v1/users/me"),
                ("GET", "/api/v1/streams"),
                ("POST", "/api/v1/messages"),
                ("GET", "/api/v1/messages/123"),
            ],
        )
        self.assertEqual(probe_posts, [{"type": "stream", "to": 7, "topic": "Smoke", "content": "probe"}])
        self.assertTrue(result["checks"]["steering_marker_ok"])

    def test_smoke_fetches_raw_probe_when_default_message_content_is_html(self) -> None:
        probe = "**probe**"
        fetch_params: list[dict] = []

        def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com")
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if method == "POST" and path == "/api/v1/messages":
                return zulip_success(id=123)
            if path == "/api/v1/messages/123":
                params = dict(kwargs.get("params") or {})
                fetch_params.append(params)
                content = probe if params.get("apply_markdown") == "false" else "<p><strong>probe</strong></p>"
                return zulip_success(
                    message={
                        "id": 123,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "content": content,
                    }
                )
            raise AssertionError((method, path))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            with mock.patch.multiple(
                smoke.bridge,
                load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                load_json=lambda *_args: {"seen_ids": [], "topic_sessions": {}},
                load_alias_entries=lambda: [],
                api=fake_api,
                HERMES=hermes,
                STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                ALLOW_STREAMS={"hermes"},
                ALLOW_STREAM_IDS=set(),
                ALLOW_TOPICS=set(),
            ):
                result = smoke.run(
                    argparse.Namespace(
                        stream="hermes",
                        topic="Smoke",
                        message=probe,
                        post_probe=True,
                        run_hermes=False,
                        post_reply=False,
                    )
                )

        self.assertTrue(result["ok"])
        self.assertEqual(fetch_params, [{"apply_markdown": "false"}])

    def test_unfetchable_or_mismatched_probe_blocks_hermes_reply_and_success(self) -> None:
        secret = "SECRET-CANARY-smoke-probe"
        valid = {
            "id": 123,
            "type": "stream",
            "stream_id": 7,
            "display_recipient": "hermes",
            "topic": "Smoke",
            "content": "probe",
        }
        cases = [
            ("unfetchable response", None),
            ("fetch failure", RuntimeError(secret)),
            ("message id", {**valid, "id": 124}),
            ("message type", {**valid, "type": "private"}),
            ("stream id", {**valid, "stream_id": 8}),
            ("topic", {**valid, "topic": "Other"}),
            ("content", {**valid, "content": "altered"}),
        ]
        for label, fetched in cases:
            probe_posts: list[dict] = []
            logs: list[tuple[object, ...]] = []
            hermes_reply = mock.Mock()
            reply = mock.Mock()
            append_steering = mock.Mock()

            def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
                if path == "/api/v1/users/me":
                    return zulip_success(email="bot@example.com")
                if path == "/api/v1/streams":
                    return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
                if method == "POST" and path == "/api/v1/messages":
                    probe_posts.append(dict(kwargs.get("data") or {}))
                    return zulip_success(id=123)
                if path == "/api/v1/messages/123":
                    if isinstance(fetched, Exception):
                        raise fetched
                    return zulip_success(message=fetched)
                raise AssertionError((method, path))

            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmpdir:
                hermes = Path(tmpdir) / "hermes"
                self.write_python_console(hermes)
                with mock.patch.multiple(
                    smoke.bridge,
                    load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    load_json=lambda *_args: {"seen_ids": [], "topic_sessions": {}},
                    load_alias_entries=lambda: [],
                    api=fake_api,
                    log=lambda *parts: logs.append(parts),
                    HERMES=hermes,
                    STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                    ALLOW_STREAMS={"hermes"},
                    ALLOW_STREAM_IDS={"7"},
                    ALLOW_TOPICS={"Smoke"},
                    append_steering_message=append_steering,
                    hermes_reply=hermes_reply,
                    reply=reply,
                ):
                    with self.assertRaisesRegex(SystemExit, "could not be fetched exactly") as raised:
                        smoke.run(
                            argparse.Namespace(
                                stream="hermes",
                                topic="Smoke",
                                message="probe",
                                post_probe=True,
                                run_hermes=True,
                                human_origin_message_id=456,
                                post_reply=True,
                            )
                        )

            self.assertEqual(probe_posts, [{"type": "stream", "to": 7, "topic": "Smoke", "content": "probe"}])
            hermes_reply.assert_not_called()
            reply.assert_not_called()
            append_steering.assert_not_called()
            self.assertNotIn(secret, str(raised.exception))
            self.assertNotIn(secret, repr(logs))

    def test_smoke_run_can_run_hermes_and_post_reply(self) -> None:
        replies: list[dict] = []
        origin_gets = 0

        def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
            nonlocal origin_gets
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com")
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if path == "/api/v1/messages/123":
                origin_gets += 1
                return zulip_success(
                    message={
                        "id": 123,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_id": 99,
                        "sender_email": "bot@example.com",
                        "sender_is_bot": True,
                        "content": "probe",
                    }
                )
            if path == "/api/v1/messages/456":
                origin_gets += 1
                return zulip_success(
                    message={
                        "id": 456,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_full_name": "Test User",
                        "sender_is_bot": False,
                        "content": "human smoke request",
                    }
                )
            if path == "/api/v1/messages/124":
                return zulip_success(
                    message={
                        "id": 124,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_email": "bot@example.com",
                        "content": "Smoke test response from packaged bridge:\n\nok",
                    }
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"456": narrow_match()})
            if method == "POST" and path == "/api/v1/messages":
                data = dict(kwargs.get("data") or {})
                if data.get("content") == "probe":
                    return zulip_success(id=123)
                replies.append(data)
                return zulip_success(id=124)
            raise AssertionError((method, path))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            with mock.patch.multiple(
                smoke.bridge,
                load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                load_json=lambda *_args: {"seen_ids": [], "topic_sessions": {}},
                load_alias_entries=lambda: [],
                api=fake_api,
                HERMES=hermes,
                STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                ALLOW_STREAMS={"hermes"},
                ALLOW_STREAM_IDS={"7"},
                ALLOW_TOPICS={"Smoke"},
                hermes_reply=lambda _rc, _message, _session_id: ("ok", "s1"),
            ):
                result = smoke.run(
                    argparse.Namespace(
                        stream="",
                        topic="Smoke",
                        message="probe",
                        post_probe=True,
                        run_hermes=True,
                        human_origin_message_id=456,
                        post_reply=True,
                    )
                )

        self.assertTrue(result["ok"])
        self.assertTrue(result["checks"]["hermes_session_present"])
        self.assertEqual(
            replies,
            [{"type": "stream", "to": 7, "topic": "Smoke", "content": "Smoke test response from packaged bridge:\n\nok"}],
        )
        self.assertGreaterEqual(origin_gets, 3)

    def test_smoke_real_hermes_uses_authorized_human_origin_and_posts_output(self) -> None:
        probe = "CONNECTIVITY_PROBE_CANARY_29a4"
        human_content = "HUMAN_ORIGIN_CANARY_8d31"
        answer_content = "authorized human reply"
        answer_posts: list[dict] = []

        def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com", user_id=99)
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if method == "POST" and path == "/api/v1/messages":
                data = dict(kwargs.get("data") or {})
                if data.get("content") == probe:
                    return zulip_success(id=123)
                answer_posts.append(data)
                return zulip_success(id=124)
            if path == "/api/v1/messages/123":
                return zulip_success(
                    message=stream_message(
                        123,
                        probe,
                        sender_id=99,
                        sender_email="bot@example.com",
                        sender_is_bot=True,
                    )
                )
            if path == "/api/v1/messages/456":
                return zulip_success(message=stream_message(456, human_content))
            if path == "/api/v1/messages/124":
                return zulip_success(
                    message=stream_message(
                        124,
                        "Smoke test response from packaged bridge:\n\n" + answer_content,
                        sender_id=99,
                        sender_email="bot@example.com",
                        sender_is_bot=True,
                    )
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"456": narrow_match()})
            if method == "GET" and path == "/api/v1/messages":
                return zulip_success(ignored_parameters_unsupported=[], messages=[])
            raise AssertionError((method, path, kwargs))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes.py"
            hermes.write_text(
                f"#!{self.venv_python}\n"
                "import sys\n"
                "prompt=sys.argv[sys.argv.index('-z')+1]\n"
                f"assert {human_content!r} in prompt\n"
                f"assert {probe!r} not in prompt\n"
                f"print({answer_content!r})\n",
                encoding="utf-8",
            )
            hermes.chmod(0o700)
            state: dict = {"seen_ids": [], "topic_sessions": {}}
            validate = smoke.bridge._python_console_script
            with mock.patch.multiple(
                smoke.bridge,
                load_rc=lambda: {
                    "site": "https://zulip.example.com",
                    "email": "bot@example.com",
                    "key": "test-api-key",
                },
                load_json=lambda *_args: state,
                load_alias_entries=lambda: [],
                api=fake_api,
                HERMES=hermes,
                HERMES_EXTRA_ARGS=["--toolsets", "coding"],
                STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                ALLOW_STREAMS={"hermes"},
                ALLOW_STREAM_IDS={"7"},
                ALLOW_TOPICS={"Smoke"},
                typing_status=lambda *_args, **_kwargs: None,
                find_session_by_marker=lambda _marker: "s1",
                clean_session_record=lambda *_args, **_kwargs: None,
                set_session_archived=lambda *_args, **_kwargs: None,
            ), mock.patch.object(smoke.bridge, "_python_console_script", wraps=validate) as validated:
                result = smoke.run(
                    argparse.Namespace(
                        stream="hermes",
                        topic="Smoke",
                        message=probe,
                        post_probe=True,
                        run_hermes=True,
                        human_origin_message_id=456,
                        post_reply=True,
                    )
                )
            validated.assert_called_once_with(str(hermes))

        self.assertTrue(result["ok"])
        self.assertEqual(result["checks"]["human_origin_message_id"], 456)
        self.assertEqual(state.get("seen_ids"), [456])
        self.assertEqual(state.get("origin_in_flight"), [])
        self.assertEqual(state.get("reply_reconciliations"), [])
        self.assertEqual(
            answer_posts,
            [
                {
                    "type": "stream",
                    "to": 7,
                    "topic": "Smoke",
                    "content": "Smoke test response from packaged bridge:\n\n" + answer_content,
                }
            ],
        )

    def test_smoke_rejects_bot_self_incomplete_or_moved_human_origins_before_hermes(self) -> None:
        cases = {
            "bot-probe": (123, stream_message(123, "probe", sender_id=99, sender_email="bot@example.com", sender_is_bot=True), "incomplete sender identity"),
            "self": (456, stream_message(456, "human", sender_email="bot@example.com"), "authorized human"),
            "missing-id": (
                456,
                {key: value for key, value in stream_message(456, "human").items() if key != "sender_id"},
                "incomplete sender identity",
            ),
            "moved-route": (456, stream_message(456, "human", topic="Moved"), "requested stream/topic"),
            "unmentioned": (456, stream_message(456, "human"), "does not directly mention"),
        }
        for label, (human_id, human, error) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmpdir:
                marker = Path(tmpdir) / "hermes-ran"
                hermes = Path(tmpdir) / "hermes.py"
                hermes.write_text(
                    f"#!{self.venv_python}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n",
                    encoding="utf-8",
                )
                hermes.chmod(0o700)

                def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
                    if path == "/api/v1/users/me":
                        return zulip_success(email="bot@example.com", user_id=99, full_name="Hermes")
                    if path == "/api/v1/streams":
                        return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
                    if method == "POST" and path == "/api/v1/messages":
                        return zulip_success(id=123)
                    if path == "/api/v1/messages/123":
                        return zulip_success(
                            message=stream_message(
                                123,
                                "probe",
                                sender_id=99,
                                sender_email="bot@example.com",
                                sender_is_bot=True,
                            )
                        )
                    if path == f"/api/v1/messages/{human_id}":
                        return zulip_success(message=human)
                    raise AssertionError((method, path, kwargs))

                with mock.patch.multiple(
                    smoke.bridge,
                    load_rc=lambda: {
                        "site": "https://zulip.example.com",
                        "email": "bot@example.com",
                        "key": "test-api-key",
                    },
                    load_json=lambda *_args: {"seen_ids": [], "topic_sessions": {}},
                    load_alias_entries=lambda: [],
                    api=fake_api,
                    HERMES=hermes,
                    STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                    ALLOW_STREAMS={"hermes"},
                    ALLOW_STREAM_IDS={"7"},
                    ALLOW_TOPICS={"Smoke"},
                    REQUIRE_MENTION=label == "unmentioned",
                ), self.assertRaisesRegex(SystemExit, error):
                    smoke.run(
                        argparse.Namespace(
                            stream="hermes",
                            topic="Smoke",
                            message="probe",
                            post_probe=True,
                            run_hermes=True,
                            human_origin_message_id=human_id,
                            post_reply=False,
                        )
                    )
                self.assertFalse(marker.exists())

    def test_smoke_reply_reservation_uses_resolved_session_during_post_race(self) -> None:
        state = {"seen_ids": [], "topic_sessions": {}}
        reply_post_started = threading.Event()
        release_reply_post = threading.Event()
        results: list[dict] = []
        errors: list[BaseException] = []

        def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com")
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if path == "/api/v1/messages/123":
                return zulip_success(
                    message={
                        "id": 123,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "content": "probe",
                    }
                )
            if path == "/api/v1/messages/456":
                return zulip_success(
                    message={
                        "id": 456,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_full_name": "Test User",
                        "sender_is_bot": False,
                        "content": "human smoke request",
                    }
                )
            if method == "GET" and path == "/api/v1/messages/124":
                return zulip_success(
                    message={
                        "id": 124,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_email": "bot@example.com",
                        "content": "Smoke test response from packaged bridge:\n\nok",
                    }
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"456": narrow_match()})
            if method == "POST" and path == "/api/v1/messages":
                if (kwargs.get("data") or {}).get("content") == "probe":
                    return zulip_success(id=123)
                reply_post_started.set()
                if not release_reply_post.wait(2):
                    raise TimeoutError("test reply POST was not released")
                return zulip_success(id=124)
            raise AssertionError((method, path))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            with mock.patch.multiple(
                smoke.bridge,
                load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                load_json=lambda *_args: state,
                load_alias_entries=lambda: [],
                api=fake_api,
                HERMES=hermes,
                STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                ALLOW_STREAMS={"hermes"},
                ALLOW_STREAM_IDS={"7"},
                ALLOW_TOPICS={"Smoke"},
                hermes_reply=lambda _rc, _message, _session_id: ("ok", "s1"),
            ):
                def run_smoke() -> None:
                    try:
                        results.append(
                            smoke.run(
                                argparse.Namespace(
                                    stream="hermes",
                                    topic="Smoke",
                                    message="probe",
                                    post_probe=True,
                                    run_hermes=True,
                                    human_origin_message_id=456,
                                    post_reply=True,
                                )
                            )
                        )
                    except BaseException as exc:
                        errors.append(exc)

                worker = threading.Thread(target=run_smoke)
                worker.start()
                try:
                    self.assertTrue(reply_post_started.wait(2))
                    foreign = smoke.bridge.resolve_zulip_conversation_key(
                        {"id": 200, "stream_id": 7, "display_recipient": "hermes", "topic": "Smoke"},
                        "zulip.example.com",
                    )
                    self.assertFalse(smoke.bridge.note_bridge_thread(state, foreign, session_id="s2"))
                finally:
                    release_reply_post.set()
                    worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(results[0]["ok"])
        self.assertEqual({thread["session_id"] for thread in state.get("zulip_threads", {}).values()}, {"s1"})
        self.assertEqual(state.get("reply_reconciliations"), [])
        self.assertNotIn(id(state), smoke.bridge.STATE_RESERVATIONS)

    def test_smoke_rejects_disallowed_stream_id_name_and_topic_without_side_effects(self) -> None:
        cases = [
            ("stream name", {"ALLOW_STREAMS": {"allowed"}}, "blocked", "Smoke"),
            ("stream id", {"ALLOW_STREAM_IDS": {"8"}}, "hermes", "Smoke"),
            ("topic", {"ALLOW_TOPICS": {"Allowed"}}, "hermes", "Blocked"),
        ]
        for label, configured, stream, topic in cases:
            posts: list[dict] = []
            hermes_reply = mock.Mock()

            def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
                if path == "/api/v1/users/me":
                    return zulip_success(email="bot@example.com")
                if path == "/api/v1/streams":
                    return zulip_success(streams=[{"stream_id": 7, "name": stream}])
                if method == "POST":
                    posts.append(dict(kwargs.get("data") or {}))
                    return zulip_success(id=123)
                raise AssertionError((method, path))

            defaults = {"ALLOW_STREAMS": set(), "ALLOW_STREAM_IDS": set(), "ALLOW_TOPICS": set()}
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmpdir:
                hermes = Path(tmpdir) / "hermes"
                self.write_python_console(hermes)
                with mock.patch.multiple(
                    smoke.bridge,
                    load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    api=fake_api,
                    HERMES=hermes,
                    STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                    hermes_reply=hermes_reply,
                    **{**defaults, **configured},
                ):
                    with self.assertRaisesRegex(SystemExit, "allowlist"):
                        smoke.run(
                            argparse.Namespace(
                                stream=stream,
                                topic=topic,
                                message="probe",
                                post_probe=True,
                                run_hermes=True,
                                human_origin_message_id=456,
                                post_reply=True,
                            )
                        )

            self.assertEqual(posts, [])
            hermes_reply.assert_not_called()

    def test_smoke_owner_collision_stops_before_probe_or_hermes(self) -> None:
        state = {
            "realm": "zulip.example.com",
            "topic_sessions": {},
            "zulip_topic_aliases": {},
            "zulip_threads": {
                "thread-one": {"stream_id": "7", "session_id": "s1", "last_seen_message_id": 10},
                "thread-two": {"stream_id": "7", "session_id": "s2", "last_seen_message_id": 20},
            },
        }
        posts: list[dict] = []
        hermes_reply = mock.Mock()
        matches = 0

        def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
            nonlocal matches
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com")
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if path == "/api/v1/messages/matches_narrow":
                matches += 1
                return {"result": "success", "msg": "", "messages": {"10": narrow_match(), "20": narrow_match()}}
            if method == "POST":
                posts.append(dict(kwargs.get("data") or {}))
                return zulip_success(id=123)
            raise AssertionError((method, path))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            with mock.patch.multiple(
                smoke.bridge,
                load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                load_json=lambda *_args: state,
                load_alias_entries=lambda: [],
                api=fake_api,
                HERMES=hermes,
                STEERING_PATH=Path(tmpdir) / "steering.jsonl",
                ALLOW_STREAMS={"hermes"},
                ALLOW_STREAM_IDS={"7"},
                ALLOW_TOPICS={"Smoke"},
                hermes_reply=hermes_reply,
            ):
                with self.assertRaisesRegex(SystemExit, "route admission failed"):
                    smoke.run(
                        argparse.Namespace(
                            stream="hermes",
                            topic="Smoke",
                            message="probe",
                            post_probe=True,
                            run_hermes=True,
                            human_origin_message_id=456,
                            post_reply=True,
                        )
                    )

        self.assertEqual(matches, 1)
        self.assertEqual(posts, [])
        hermes_reply.assert_not_called()

    def test_smoke_realm_mismatch_stops_before_post_hermes_steering_or_mutation(self) -> None:
        state = {"realm": "other.example", "topic_sessions": {"legacy": "s1"}}
        before = {"realm": "other.example", "topic_sessions": {"legacy": "s1"}}
        posts: list[dict] = []
        hermes_reply = mock.Mock()
        steering = mock.Mock()

        def fake_api(_rc: dict[str, str], method: str, path: str, **kwargs: object) -> dict:
            if path == "/api/v1/users/me":
                return zulip_success(email="bot@example.com")
            if path == "/api/v1/streams":
                return zulip_success(streams=[{"stream_id": 7, "name": "hermes"}])
            if method == "POST":
                posts.append(dict(kwargs.get("data") or {}))
                return zulip_success(id=123)
            raise AssertionError((method, path))

        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = Path(tmpdir) / "hermes"
            self.write_python_console(hermes)
            with (
                mock.patch.multiple(
                    smoke.bridge,
                    load_rc=lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    load_json=lambda *_args: state,
                    load_alias_entries=lambda: [],
                    api=fake_api,
                    HERMES=hermes,
                    ALLOW_STREAMS={"hermes"},
                    ALLOW_STREAM_IDS={"7"},
                    ALLOW_TOPICS={"Smoke"},
                    append_steering_message=steering,
                    hermes_reply=hermes_reply,
                ),
                self.assertRaisesRegex(SystemExit, smoke.bridge.STATE_REALM_MIGRATION_REQUIRED),
            ):
                smoke.run(
                    argparse.Namespace(
                        stream="hermes",
                        topic="Smoke",
                        message="probe",
                        post_probe=True,
                        run_hermes=True,
                        human_origin_message_id=456,
                        post_reply=True,
                    )
                )

        self.assertEqual(state, before)
        self.assertEqual(posts, [])
        hermes_reply.assert_not_called()
        steering.assert_not_called()


if __name__ == "__main__":
    unittest.main()
