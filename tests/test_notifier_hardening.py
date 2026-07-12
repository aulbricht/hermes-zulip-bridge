from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hermes_zulip_bridge import notifier


RC = {"site": "https://example.invalid", "email": "bot@example.invalid", "key": "key"}


def empty_state() -> dict:
    return {"version": notifier.STATE_VERSION, "notified": {}, "revisions": {}, "outbox": [], "dead_letters": []}


def task(
    *,
    task_id: str = "task-1",
    topic: str = "Original",
    stream_id: object = 7,
    message_id: object = 41,
    revision: object = 1,
    status: str = "done",
) -> dict:
    return {
        "id": task_id,
        "title": "private task",
        "status": status,
        "updated_at": revision,
        "metadata": {
            "notification_target": {
                "platform": "zulip",
                "stream": "private stream",
                "stream_id": stream_id,
                "topic": topic,
                "message_id": message_id,
            }
        },
    }


def origin(*, topic: str = "Renamed", stream_id: object = 7, message_id: object = 41) -> dict:
    return {
        "id": message_id,
        "type": "stream",
        "stream_id": stream_id,
        "display_recipient": "private stream",
        "topic": topic,
        "sender_id": 9,
        "sender_email": "human@example.invalid",
        "sender_is_bot": False,
        "content": "private origin",
    }


class NotifierHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"k" * notifier.SIGNING_KEY_BYTES
        self.state = empty_state()
        policy = mock.patch.dict(
            os.environ,
            {
                "HERMES_ZULIP_STREAM_IDS": "7",
                "HERMES_ZULIP_TOPIC_POLICY": "any",
                "HERMES_ZULIP_TOPICS": "",
                "HERMES_ZULIP_ALLOWED_SENDERS": "id:9,email:human@example.invalid",
                "HERMES_ZULIP_ALLOW_DMS": "true",
                "HERMES_ZULIP_ALLOWED_DM_RECIPIENTS": "id:9,email:human@example.invalid",
            },
        )
        policy.start()
        self.addCleanup(policy.stop)

    def reserve_notified(self, count: int) -> None:
        for index in range(count):
            task_id = f"reserved-{index}"
            signature = f"{index:064x}"
            self.state["notified"][task_id] = signature
            self.state["revisions"][task_id] = {"revision": f"v:{index:020d}", "signature": signature}

    def add_job(self, candidate: dict | None = None) -> dict:
        candidate = candidate or task()
        job = notifier._job_for_task(candidate, notifier.zulip_target_for_task(candidate), self.key, 10)
        self.state["revisions"][job["task_id"]] = {"revision": job["revision"], "signature": job["signature"]}
        self.state["outbox"].append(job)
        return job

    def write_state(self, root: str, state: dict | None = None) -> Path:
        path = Path(root) / "state.json"
        notifier._atomic_write(notifier.signing_key_path(path), self.key)
        notifier.save_state(path, state or self.state, self.key)
        return path

    def persist_and_reload(self, path: Path, state: dict) -> dict:
        notifier.save_state(path, state, self.key)
        loaded, loaded_key = notifier.load_state(path)
        self.assertEqual(loaded_key, self.key)
        self.assertEqual(notifier._state_payload(loaded), notifier._state_payload(state))
        return loaded

    def test_full_notified_prime_batch_fails_before_mutation(self) -> None:
        self.reserve_notified(notifier.MAX_NOTIFIED)
        before = copy.deepcopy(self.state)
        persist = mock.Mock()
        post = mock.Mock()
        board = {"tasks": [task(task_id="overflow-a"), task(task_id="overflow-b")]}
        with mock.patch.object(notifier, "fetch_kanban_board", return_value=board), mock.patch.object(
            notifier, "post_zulip_message", post
        ), self.assertRaisesRegex(notifier.StateError, "^notifier notified capacity is exhausted$"):
            notifier.scan_once(self.state, RC, send=False, prime=True, key=self.key, persist=persist, now=10)
        self.assertEqual(self.state, before)
        self.assertEqual(len(self.state["notified"]), notifier.MAX_NOTIFIED)
        persist.assert_not_called()
        post.assert_not_called()

    def test_two_admissions_cannot_over_reserve_last_slot(self) -> None:
        self.reserve_notified(notifier.MAX_NOTIFIED - 1)
        before = copy.deepcopy(self.state)
        persist = mock.Mock()
        post = mock.Mock()
        board = {"tasks": [task(task_id="last-a"), task(task_id="last-b")]}
        with mock.patch.object(notifier, "fetch_kanban_board", return_value=board), mock.patch.object(
            notifier, "post_zulip_message", post
        ), self.assertRaisesRegex(notifier.StateError, "capacity is exhausted"):
            notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
        self.assertEqual(self.state, before)
        self.assertLessEqual(len(notifier._reserved_task_ids(self.state)), notifier.MAX_NOTIFIED)
        persist.assert_not_called()
        post.assert_not_called()

    def test_existing_identity_update_is_allowed_at_capacity(self) -> None:
        self.reserve_notified(notifier.MAX_NOTIFIED - 1)
        old_signature = "f" * 64
        self.state["notified"]["task-1"] = old_signature
        self.state["revisions"]["task-1"] = {"revision": "t:00000000000000000000", "signature": old_signature}
        persist = mock.Mock()
        post = mock.Mock()
        candidate = task()
        with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [candidate]}), mock.patch.object(
            notifier, "post_zulip_message", post
        ):
            counts = notifier.scan_once(
                self.state, RC, send=False, prime=True, key=self.key, persist=persist, now=10
            )
        self.assertEqual(counts["primed"], 1)
        self.assertEqual(self.state["notified"]["task-1"], notifier.task_signature(candidate))
        self.assertEqual(len(self.state["notified"]), notifier.MAX_NOTIFIED)
        persist.assert_called_once_with()
        post.assert_not_called()

    def test_outbox_reservation_counts_and_survives_restart_validation(self) -> None:
        self.reserve_notified(notifier.MAX_NOTIFIED - 1)
        job = self.add_job()
        self.assertEqual(len(notifier._reserved_task_ids(self.state)), notifier.MAX_NOTIFIED)
        notifier._validate_state(self.state)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            notifier._atomic_write(notifier.signing_key_path(path), self.key)
            notifier.save_state(path, self.state, self.key)
            loaded, _key = notifier.load_state(path)
        self.assertEqual(len(notifier._reserved_task_ids(loaded)), notifier.MAX_NOTIFIED)

        overflow = copy.deepcopy(loaded)
        overflow["notified"]["overflow"] = "f" * 64
        overflow["revisions"]["overflow"] = {"revision": "v:00000000000000010001", "signature": "f" * 64}
        with self.assertRaises(notifier.StateError):
            notifier._validate_state(overflow)

    def test_reserved_delivery_publishes_without_capacity_failure_after_post(self) -> None:
        self.reserve_notified(notifier.MAX_NOTIFIED - 1)
        job = self.add_job()
        persist = mock.Mock()
        post = mock.Mock(return_value={"id": 99})
        with mock.patch.object(
            notifier,
            "current_zulip_target",
            return_value={"message_id": 41, "stream_id": 7, "topic": "Renamed"},
        ), mock.patch.object(notifier, "post_zulip_message", post), mock.patch.object(
            notifier, "_reconcile", return_value=True
        ):
            self.assertEqual(notifier._deliver_job(self.state, job, RC, persist, 10), "delivered")
        post.assert_called_once()
        self.assertEqual(len(self.state["notified"]), notifier.MAX_NOTIFIED)
        self.assertEqual(self.state["notified"]["task-1"], job["signature"])
        self.assertEqual(self.state["outbox"], [])
        notifier._validate_state(self.state)

    def test_exact_origin_current_topic_and_numeric_stream_route(self) -> None:
        posts: list[dict] = []
        sent: dict = {}

        def fetch(_rc: dict, message_id: object) -> dict:
            if message_id == 41:
                return origin()
            return {**sent, "id": 99, "type": "stream", "stream_id": 7, "topic": "Renamed", "sender_email": RC["email"]}

        def post(_rc: dict, stream_id: int, topic: str, content: str) -> dict:
            posts.append({"stream_id": stream_id, "topic": topic})
            sent["content"] = content
            return {"id": 99}

        with mock.patch.dict(
            os.environ,
            {"HERMES_ZULIP_TOPIC_POLICY": "allowlist", "HERMES_ZULIP_TOPICS": "Renamed"},
        ), mock.patch.object(
            notifier, "fetch_kanban_board", return_value={"tasks": [task()]}
        ), mock.patch.object(notifier, "fetch_zulip_message", side_effect=fetch), mock.patch.object(
            notifier, "post_zulip_message", side_effect=post
        ):
            counts = notifier.scan_once(self.state, RC, send=True, key=self.key, persist=lambda: None, now=10)

        self.assertEqual(posts, [{"stream_id": 7, "topic": "Renamed"}])
        self.assertEqual(counts["delivered"], 1)
        self.assertEqual(self.state["outbox"], [])

    def test_stream_sender_and_topic_policy_denials_never_post(self) -> None:
        cases = (
            ({"HERMES_ZULIP_STREAM_IDS": "8"}, origin(), False),
            ({"HERMES_ZULIP_ALLOWED_SENDERS": "id:10,email:other@example.invalid"}, origin(), True),
            (
                {"HERMES_ZULIP_TOPIC_POLICY": "allowlist", "HERMES_ZULIP_TOPICS": "Allowed"},
                origin(topic="Denied"),
                True,
            ),
        )
        for environment, fetched_origin, admitted in cases:
            with self.subTest(environment=environment):
                state = empty_state()
                post = mock.Mock()
                with mock.patch.dict(os.environ, environment), mock.patch.object(
                    notifier, "fetch_kanban_board", return_value={"tasks": [task()]}
                ), mock.patch.object(notifier, "fetch_zulip_message", return_value=fetched_origin), mock.patch.object(
                    notifier, "post_zulip_message", post
                ):
                    notifier.scan_once(state, RC, send=True, key=self.key, persist=lambda: None, now=10)
                post.assert_not_called()
                self.assertEqual(bool(state["outbox"]), admitted)

    def test_empty_or_malformed_stream_sender_and_topic_policies_fail_closed(self) -> None:
        cases = (
            {"HERMES_ZULIP_STREAM_IDS": ""},
            {"HERMES_ZULIP_STREAM_IDS": "7,not-an-id"},
            {"HERMES_ZULIP_ALLOWED_SENDERS": ""},
            {"HERMES_ZULIP_ALLOWED_SENDERS": "human@example.invalid"},
            {"HERMES_ZULIP_TOPIC_POLICY": ""},
            {"HERMES_ZULIP_TOPIC_POLICY": "sometimes"},
            {"HERMES_ZULIP_TOPIC_POLICY": "allowlist", "HERMES_ZULIP_TOPICS": ""},
        )
        for environment in cases:
            with self.subTest(environment=environment):
                state = empty_state()
                post = mock.Mock()
                with mock.patch.dict(os.environ, environment), mock.patch.object(
                    notifier, "fetch_kanban_board", return_value={"tasks": [task()]}
                ), mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                    notifier, "post_zulip_message", post
                ):
                    notifier.scan_once(state, RC, send=True, key=self.key, persist=lambda: None, now=10)
                post.assert_not_called()

    def test_direct_messages_default_deny_and_require_exact_allowlist_entry(self) -> None:
        direct = {
            "metadata": {
                "notification_target": {
                    "platform": "zulip",
                    "type": "direct",
                    "to": "human@example.invalid",
                }
            }
        }
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(notifier.zulip_target_for_task(direct))
        with mock.patch.dict(
            os.environ,
            {
                "HERMES_ZULIP_ALLOW_DMS": "true",
                "HERMES_ZULIP_ALLOWED_DM_RECIPIENTS": "email:other@example.invalid",
            },
        ):
            self.assertIsNone(notifier.zulip_target_for_task(direct))
        with mock.patch.dict(
            os.environ,
            {
                "HERMES_ZULIP_ALLOW_DMS": "true",
                "HERMES_ZULIP_ALLOWED_DM_RECIPIENTS": "email:human@example.invalid",
            },
        ):
            self.assertEqual(notifier.zulip_target_for_task(direct)["to"], "human@example.invalid")
        direct["metadata"]["notification_target"]["to"] = 9
        with mock.patch.dict(
            os.environ,
            {
                "HERMES_ZULIP_ALLOW_DMS": "true",
                "HERMES_ZULIP_ALLOWED_DM_RECIPIENTS": "id:9",
            },
        ):
            self.assertEqual(notifier.zulip_target_for_task(direct)["to"], "9")

    def test_queued_direct_message_rechecks_policy_before_posting(self) -> None:
        candidate = {
            "id": "task-dm-policy",
            "status": "done",
            "updated_at": 1,
            "metadata": {
                "notification_target": {
                    "platform": "zulip",
                    "type": "direct",
                    "to": "human@example.invalid",
                }
            },
        }
        job = self.add_job(candidate)
        persist = mock.Mock()
        post = mock.Mock()
        with mock.patch.dict(os.environ, {"HERMES_ZULIP_ALLOW_DMS": "false"}), mock.patch.object(
            notifier, "post_zulip_direct_message", post
        ):
            self.assertEqual(notifier._deliver_job(self.state, job, RC, persist, 10), "pending")
        post.assert_not_called()
        persist.assert_called_once_with()
        self.assertEqual(job["stage"], "admitted")

    def test_missing_malformed_or_moved_origin_never_posts(self) -> None:
        cases = [
            RuntimeError("lookup"),
            {**origin(), "id": 42},
            {**origin(), "type": "private"},
            {**origin(), "stream_id": 8},
            {**origin(), "topic": ""},
            {**origin(), "sender_is_bot": True},
        ]
        for candidate in cases:
            with self.subTest(candidate=type(candidate).__name__):
                state = empty_state()
                post = mock.Mock()
                fetch = mock.Mock(side_effect=candidate) if isinstance(candidate, Exception) else mock.Mock(return_value=candidate)
                with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), mock.patch.object(
                    notifier, "fetch_zulip_message", fetch
                ), mock.patch.object(notifier, "post_zulip_message", post):
                    notifier.scan_once(state, RC, send=True, key=self.key, persist=lambda: None, now=10)
                post.assert_not_called()
                self.assertEqual(state["outbox"][0]["stage"], "admitted")

    def test_origin_accepts_absent_optional_bot_flag_but_rejects_true_or_malformed_values(self) -> None:
        with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()):
            self.assertEqual(notifier._verified_origin(RC, 41, 7)["id"], 41)

        missing = origin()
        missing.pop("sender_is_bot")
        for candidate in (missing, {**origin(), "sender_is_bot": None}):
            with self.subTest(sender_is_bot=candidate.get("sender_is_bot", "missing")), mock.patch.object(
                notifier, "fetch_zulip_message", return_value=candidate
            ):
                self.assertEqual(notifier._verified_origin(RC, 41, 7)["id"], 41)
        cases = (
            {**origin(), "sender_is_bot": 0},
            {**origin(), "sender_is_bot": 1},
            {**origin(), "sender_is_bot": ""},
            {**origin(), "sender_is_bot": "false"},
            {**origin(), "sender_is_bot": True},
        )
        for candidate in cases:
            with self.subTest(sender_is_bot=candidate.get("sender_is_bot", "missing")):
                state = empty_state()
                persist = mock.Mock()
                post = mock.Mock()
                with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), mock.patch.object(
                    notifier, "fetch_zulip_message", return_value=candidate
                ), mock.patch.object(notifier, "post_zulip_message", post):
                    notifier.scan_once(state, RC, send=True, key=self.key, persist=persist, now=10)
                post.assert_not_called()
                self.assertEqual(persist.call_count, 2)
                self.assertEqual(state["outbox"][0]["stage"], "admitted")

    def test_route_failures_back_off_then_terminalize_without_posting(self) -> None:
        persist = mock.Mock()
        post = mock.Mock()
        fetch = mock.Mock(side_effect=notifier.RouteError("deleted"))
        with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), mock.patch.object(
            notifier, "fetch_zulip_message", fetch
        ), mock.patch.object(notifier, "post_zulip_message", post):
            notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
            job = self.state["outbox"][0]
            self.assertEqual((job["attempts"], job["next_attempt_at"]), (1, 15))
            calls = (fetch.call_count, persist.call_count)
            notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
            self.assertEqual((fetch.call_count, persist.call_count), calls)
            while self.state["outbox"]:
                notifier.scan_once(
                    self.state,
                    RC,
                    send=True,
                    key=self.key,
                    persist=persist,
                    now=self.state["outbox"][0]["next_attempt_at"],
                )
        post.assert_not_called()
        self.assertEqual(fetch.call_count, notifier.MAX_ATTEMPTS)
        self.assertEqual(self.state["outbox"], [])
        self.assertEqual(self.state["dead_letters"][0]["attempts"], notifier.MAX_ATTEMPTS)
        self.assertEqual(self.state["dead_letters"][0]["reason"], "operator_review_origin_unavailable")
        self.assertEqual(notifier._retry_delay(100), notifier.RETRY_MAX_SECONDS)

    def test_route_attempt_accounting_persists_before_retry(self) -> None:
        job = self.add_job()
        persist = mock.Mock(side_effect=notifier.StateError("crash"))
        post = mock.Mock()
        with mock.patch.object(notifier, "fetch_zulip_message", side_effect=notifier.RouteError("deleted")), mock.patch.object(
            notifier, "post_zulip_message", post
        ), self.assertRaises(notifier.StateError):
            notifier._deliver_job(self.state, job, RC, persist, 10)
        persist.assert_called_once_with()
        post.assert_not_called()
        self.assertEqual((job["stage"], job["attempts"], job["next_attempt_at"]), ("admitted", 1, 15))

    def test_full_dead_letter_queue_terminalizes_route_failure_in_outbox(self) -> None:
        job = self.add_job()
        job["attempts"] = notifier.MAX_ATTEMPTS - 1
        self.state["dead_letters"] = [
            {"ref": f"full-{index}", "reason": "operator_review", "attempts": 1, "terminal_at": 1}
            for index in range(notifier.MAX_DEAD_LETTERS)
        ]
        persist = mock.Mock()
        post = mock.Mock()
        with mock.patch.object(notifier, "fetch_zulip_message", side_effect=notifier.RouteError("deleted")), mock.patch.object(
            notifier, "post_zulip_message", post
        ):
            self.assertEqual(notifier._deliver_job(self.state, job, RC, persist, 10), "operator_review")
        post.assert_not_called()
        persist.assert_called_once_with()
        self.assertEqual((job["stage"], job["attempts"], job["next_attempt_at"]), ("operator_review", notifier.MAX_ATTEMPTS, 10**11))
        notifier._validate_state(self.state)

    def test_invalid_target_scope_is_not_admitted(self) -> None:
        for stream_id, message_id in ((None, 41), (7, None), (False, 41), (7, "01")):
            with self.subTest(stream_id=stream_id, message_id=message_id), mock.patch.object(
                notifier, "fetch_kanban_board", return_value={"tasks": [task(stream_id=stream_id, message_id=message_id)]}
            ):
                state = empty_state()
                notifier.scan_once(state, RC, send=True, key=self.key, persist=lambda: None, now=10)
                self.assertEqual(state["outbox"], [])

    def test_dry_run_counts_without_mutating_or_persisting(self) -> None:
        before = copy.deepcopy(self.state)
        persist = mock.Mock()
        with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}):
            counts = notifier.scan_once(self.state, RC, send=False, key=self.key, persist=persist, now=10)
        self.assertEqual(counts["admitted"], 1)
        self.assertEqual(self.state, before)
        persist.assert_not_called()

    def test_save_state_preserves_live_job_reference_and_reloads_each_stage(self) -> None:
        job = self.add_job()
        outbox = self.state["outbox"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)
            self.persist_and_reload(path, self.state)
            self.assertIs(self.state["outbox"], outbox)
            self.assertIs(self.state["outbox"][0], job)

            job["stage"] = "post_started"
            job["attempts"] = 1
            loaded = self.persist_and_reload(path, self.state)
        self.assertEqual((loaded["outbox"][0]["stage"], loaded["outbox"][0]["attempts"]), ("post_started", 1))

    def test_real_restart_from_admitted_delivers_once(self) -> None:
        posts: list[str] = []
        sent_content = ""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)
            saves = 0

            def crash_after_admission() -> None:
                nonlocal saves
                saves += 1
                self.persist_and_reload(path, self.state)
                if saves == 1:
                    raise notifier.StateError("crash")

            with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), self.assertRaises(
                notifier.StateError
            ):
                notifier.scan_once(self.state, RC, send=True, key=self.key, persist=crash_after_admission, now=10)
            restarted, _ = notifier.load_state(path)
            self.assertEqual(restarted["outbox"][0]["stage"], "admitted")

            def post(_rc: dict, _stream_id: int, _topic: str, content: str) -> dict:
                nonlocal sent_content
                posts.append(content)
                sent_content = content
                return {"id": 99}

            def fetch(_rc: dict, message_id: object) -> dict:
                if message_id == 41:
                    return origin()
                return {
                    "id": 99,
                    "type": "stream",
                    "stream_id": 7,
                    "topic": "Renamed",
                    "sender_email": RC["email"],
                    "content": sent_content,
                }

            persist = lambda: self.persist_and_reload(path, restarted)
            with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), mock.patch.object(
                notifier, "fetch_zulip_message", side_effect=fetch
            ), mock.patch.object(notifier, "post_zulip_message", side_effect=post):
                notifier.scan_once(restarted, RC, send=True, key=self.key, persist=persist, now=20)
            final, _ = notifier.load_state(path)
        self.assertEqual(len(posts), 1)
        self.assertEqual(final["outbox"], [])
        self.assertIn("task-1", final["notified"])

    def test_real_restart_from_post_started_never_blindly_posts(self) -> None:
        job = self.add_job()
        post = mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)

            def crash_after_post_started() -> None:
                self.persist_and_reload(path, self.state)
                raise notifier.StateError("crash")

            with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                notifier, "post_zulip_message", post
            ), self.assertRaises(notifier.StateError):
                notifier._deliver_job(self.state, job, RC, crash_after_post_started, 10)
            restarted, _ = notifier.load_state(path)
            self.assertEqual(restarted["outbox"][0]["stage"], "post_started")

            persist = lambda: self.persist_and_reload(path, restarted)
            with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                notifier, "zulip_api", return_value={"messages": []}
            ), mock.patch.object(notifier, "post_zulip_message", post):
                self.assertEqual(notifier._deliver_job(restarted, restarted["outbox"][0], RC, persist, 20), "pending")
            final, _ = notifier.load_state(path)
        post.assert_not_called()
        self.assertEqual(final["outbox"][0]["stage"], "post_started")

    def test_real_restart_reconciles_lost_post_response(self) -> None:
        job = self.add_job()
        posts = 0
        sent_content = ""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)
            persist = lambda: self.persist_and_reload(path, self.state)

            def lost_response(_rc: dict, _stream_id: int, _topic: str, content: str) -> dict:
                nonlocal posts, sent_content
                posts += 1
                sent_content = content
                raise TimeoutError("lost response")

            with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                notifier, "post_zulip_message", side_effect=lost_response
            ), self.assertRaises(TimeoutError):
                notifier._deliver_job(self.state, job, RC, persist, 10)
            restarted, _ = notifier.load_state(path)
            self.assertEqual(restarted["outbox"][0]["stage"], "post_started")

            sent = {
                "id": 99,
                "type": "stream",
                "stream_id": 7,
                "topic": "Renamed",
                "sender_email": RC["email"],
                "content": sent_content,
            }
            persist = lambda: self.persist_and_reload(path, restarted)
            with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                notifier, "zulip_api", return_value={"messages": [sent]}
            ), mock.patch.object(notifier, "post_zulip_message") as retry_post:
                self.assertEqual(notifier._deliver_job(restarted, restarted["outbox"][0], RC, persist, 20), "delivered")
            final, _ = notifier.load_state(path)
        self.assertEqual(posts, 1)
        retry_post.assert_not_called()
        self.assertEqual(final["outbox"], [])

    def test_real_restart_reconciles_save_failure_after_post(self) -> None:
        job = self.add_job()
        sent_content = ""
        saves = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)

            def fail_after_post() -> None:
                nonlocal saves
                saves += 1
                if saves == 2:
                    raise notifier.StateError("crash")
                self.persist_and_reload(path, self.state)

            def post(_rc: dict, _stream_id: int, _topic: str, content: str) -> dict:
                nonlocal sent_content
                sent_content = content
                return {"id": 99}

            with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                notifier, "post_zulip_message", side_effect=post
            ), self.assertRaises(notifier.StateError):
                notifier._deliver_job(self.state, job, RC, fail_after_post, 10)
            restarted, _ = notifier.load_state(path)
            self.assertEqual((restarted["outbox"][0]["stage"], restarted["outbox"][0]["sent_message_id"]), ("post_started", None))

            sent = {
                "id": 99,
                "type": "stream",
                "stream_id": 7,
                "topic": "Renamed",
                "sender_email": RC["email"],
                "content": sent_content,
            }
            persist = lambda: self.persist_and_reload(path, restarted)
            with mock.patch.object(notifier, "fetch_zulip_message", return_value=origin()), mock.patch.object(
                notifier, "zulip_api", return_value={"messages": [sent]}
            ), mock.patch.object(notifier, "post_zulip_message") as retry_post:
                self.assertEqual(notifier._deliver_job(restarted, restarted["outbox"][0], RC, persist, 20), "delivered")
            final, _ = notifier.load_state(path)
        retry_post.assert_not_called()
        self.assertEqual(final["outbox"], [])

    def test_strict_revision_schema_and_duplicate_rows_fail_closed(self) -> None:
        invalid = (None, -1, True, "1", "2026-01-01", " bad ", {}, float("inf"))
        for revision in invalid:
            with self.subTest(revision=revision):
                before = copy.deepcopy(self.state)
                persist = mock.Mock()
                post = mock.Mock()
                with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task(revision=revision)]}), mock.patch.object(
                    notifier, "post_zulip_message", post
                ), self.assertRaises(notifier.StateError):
                    notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
                self.assertEqual(self.state, before)
                persist.assert_not_called()
                post.assert_not_called()

        equal_but_different = [task(revision=2), task(revision=2, status="blocked")]
        timestamp = task(revision=2)
        versioned = {**task(revision=1), "version": 2}
        for rows in (equal_but_different, [timestamp, versioned]):
            with self.subTest(rows=len(rows)), mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": rows}), self.assertRaises(
                notifier.StateError
            ):
                notifier.scan_once(self.state, RC, send=True, key=self.key, persist=mock.Mock(), now=10)

    def test_real_revision_ordering_never_coexists_or_replays_stale(self) -> None:
        current = task(revision=3)
        stale = task(revision=1)
        current_signature = notifier.task_signature(current)
        self.state["notified"]["task-1"] = current_signature
        self.state["revisions"]["task-1"] = {"revision": notifier.task_revision(current), "signature": current_signature}
        post = mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)
            persist = mock.Mock(side_effect=lambda: self.persist_and_reload(path, self.state))
            with mock.patch.object(notifier, "post_zulip_message", post):
                for candidate in (stale, current):
                    with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [candidate]}):
                        notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
            unchanged, _ = notifier.load_state(path)
        post.assert_not_called()
        persist.assert_not_called()
        self.assertEqual(unchanged["notified"]["task-1"], current_signature)

        self.state = empty_state()
        stale_job = self.add_job(stale)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)
            persist = lambda: self.persist_and_reload(path, self.state)
            with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [stale, current]}), mock.patch.object(
                notifier, "fetch_zulip_message", side_effect=notifier.RouteError("unavailable")
            ), mock.patch.object(notifier, "post_zulip_message", post):
                notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
            replaced, _ = notifier.load_state(path)
        self.assertEqual(len(replaced["outbox"]), 1)
        self.assertEqual(replaced["outbox"][0]["revision"], notifier.task_revision(current))
        self.assertNotEqual(replaced["outbox"][0]["signature"], stale_job["signature"])

    def test_real_newer_revision_waits_for_uncertain_older_job(self) -> None:
        stale = task(revision=1)
        current = task(revision=2)
        old_job = self.add_job(stale)
        old_job["stage"] = "post_started"
        old_job["attempts"] = 1
        post = mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)
            persist = lambda: self.persist_and_reload(path, self.state)
            with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [current]}), mock.patch.object(
                notifier, "fetch_zulip_message", return_value=origin()
            ), mock.patch.object(notifier, "zulip_api", return_value={"messages": []}), mock.patch.object(
                notifier, "post_zulip_message", post
            ):
                notifier.scan_once(self.state, RC, send=True, key=self.key, persist=persist, now=10)
            waiting, _ = notifier.load_state(path)
            self.assertEqual(len(waiting["outbox"]), 1)
            self.assertEqual(waiting["outbox"][0]["revision"], notifier.task_revision(stale))
            self.assertEqual(waiting["revisions"]["task-1"]["revision"], notifier.task_revision(current))

            sent = {
                "id": 99,
                "type": "stream",
                "stream_id": 7,
                "topic": "Renamed",
                "sender_email": RC["email"],
                "content": waiting["outbox"][0]["content"],
            }
            persist_waiting = lambda: self.persist_and_reload(path, waiting)
            with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [current]}), mock.patch.object(
                notifier, "fetch_zulip_message", return_value=origin()
            ), mock.patch.object(notifier, "zulip_api", return_value={"messages": [sent]}), mock.patch.object(
                notifier, "post_zulip_message", post
            ):
                notifier.scan_once(waiting, RC, send=True, key=self.key, persist=persist_waiting, now=100)
            reconciled, _ = notifier.load_state(path)
            self.assertEqual(reconciled["outbox"], [])

            persist_reconciled = lambda: self.persist_and_reload(path, reconciled)
            with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [current]}), mock.patch.object(
                notifier, "fetch_zulip_message", side_effect=notifier.RouteError("unavailable")
            ), mock.patch.object(notifier, "post_zulip_message", post):
                notifier.scan_once(reconciled, RC, send=True, key=self.key, persist=persist_reconciled, now=200)
            final, _ = notifier.load_state(path)
        post.assert_not_called()
        self.assertEqual(len(final["outbox"]), 1)
        self.assertEqual(final["outbox"][0]["revision"], notifier.task_revision(current))

    def test_crash_boundaries_never_repeat_post_before_reconciliation(self) -> None:
        for fail_at in (1, 2, 3, 4):
            with self.subTest(fail_at=fail_at):
                state = empty_state()
                saves = 0
                posts = 0
                sent_content = ""

                def persist() -> None:
                    nonlocal saves
                    saves += 1
                    if saves == fail_at:
                        raise notifier.StateError("crash")

                def post(_rc: dict, _stream_id: int, _topic: str, content: str) -> dict:
                    nonlocal posts, sent_content
                    posts += 1
                    sent_content = content
                    return {"id": 99}

                def fetch(_rc: dict, message_id: object) -> dict:
                    if message_id == 41:
                        return origin()
                    return {"id": 99, "type": "stream", "stream_id": 7, "topic": "Renamed", "sender_email": RC["email"], "content": sent_content}

                with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), mock.patch.object(
                    notifier, "fetch_zulip_message", side_effect=fetch
                ), mock.patch.object(notifier, "post_zulip_message", side_effect=post):
                    try:
                        notifier.scan_once(state, RC, send=True, key=self.key, persist=persist, now=10)
                    except notifier.StateError:
                        pass
                    first_posts = posts
                    notifier.scan_once(state, RC, send=True, key=self.key, persist=lambda: None, now=1000)
                self.assertLessEqual(first_posts, 1)
                self.assertLessEqual(posts, 1)

    def test_uncertain_post_searches_exact_marker_then_bounds_operator_review(self) -> None:
        posts = mock.Mock(side_effect=TimeoutError("lost response"))
        with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": [task()]}), mock.patch.object(
            notifier, "fetch_zulip_message", return_value=origin()
        ), mock.patch.object(notifier, "post_zulip_message", posts):
            notifier.scan_once(self.state, RC, send=True, key=self.key, persist=lambda: None, now=10)
        self.assertEqual(posts.call_count, 1)
        job = self.state["outbox"][0]
        job["attempts"] = notifier.MAX_ATTEMPTS - 1
        with mock.patch.object(notifier, "fetch_kanban_board", return_value={"tasks": []}), mock.patch.object(
            notifier, "fetch_zulip_message", return_value=origin()
        ), mock.patch.object(notifier, "zulip_api", return_value={"messages": []}), mock.patch.object(
            notifier, "post_zulip_message", posts
        ):
            notifier.scan_once(self.state, RC, send=True, key=self.key, persist=lambda: None, now=1000)
        self.assertEqual(posts.call_count, 1)
        self.assertEqual(self.state["outbox"], [])
        self.assertEqual(self.state["dead_letters"][0]["reason"], "operator_review_uncertain_post")

    def test_direct_reconciliation_requires_exact_recipient_route(self) -> None:
        content = "private\n<!-- hermes-notifier:marker -->"
        job = {
            "type": "direct",
            "recipient": "human@example.invalid",
            "content_digest": notifier.hashlib.sha256(content.encode()).hexdigest(),
        }
        rc = {**RC, "user_id": 10}
        intended = {"id": 9, "email": "human@example.invalid"}
        bot = {"id": 10, "email": RC["email"]}
        message = {
            "id": 99,
            "type": "private",
            "sender_email": RC["email"],
            "content": content,
            "display_recipient": [intended, bot],
        }
        self.assertTrue(notifier._exact_sent_message(rc, job, message, None))
        self.assertTrue(
            notifier._exact_sent_message(
                rc,
                {**job, "recipient": "9"},
                {**message, "display_recipient": [{"id": 9}, {"id": 10}]},
                None,
            )
        )
        self.assertTrue(
            notifier._exact_sent_message(
                rc,
                job,
                {
                    **message,
                    "display_recipient": [
                        {"email": "HUMAN@example.invalid"},
                        {"email": RC["email"].upper()},
                    ],
                },
                None,
            )
        )
        self.assertFalse(
            notifier._exact_sent_message(
                rc,
                job,
                {**message, "display_recipient": [intended, bot, {"id": 11, "email": "other@example.invalid"}]},
                None,
            )
        )
        self.assertFalse(notifier._exact_sent_message(rc, job, {**message, "display_recipient": [bot]}, None))

        malformed_actual = (None, {}, ["human@example.invalid"], [{}], [{"id": 0}], [{"email": None}])
        for recipients in malformed_actual:
            with self.subTest(actual=recipients):
                self.assertFalse(
                    notifier._exact_sent_message(rc, job, {**message, "display_recipient": recipients}, None)
                )
        for recipient in ("[]", "{}", '[""]', "not-an-identity"):
            with self.subTest(expected=recipient):
                self.assertFalse(notifier._exact_sent_message(rc, {**job, "recipient": recipient}, message, None))

    def test_direct_terminal_notification_persists_posts_reconciles_and_completes(self) -> None:
        candidate = {
            "id": "task-dm",
            "title": "failed workflow",
            "updated_at": 1,
            "metadata": {
                "notification_target": {
                    "platform": "zulip",
                    "type": "direct",
                    "to": "human@example.invalid",
                }
            },
        }
        terminal = {**candidate, "status": "blocked"}
        board = {"columns": [{"name": "Blocked", "tasks": [candidate]}]}
        rc = {**RC, "user_id": 10}
        posts: list[tuple[str, str]] = []
        lookups: list[object] = []
        snapshots: list[dict] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_state(tmpdir)

            def persist() -> None:
                notifier.save_state(path, self.state, self.key)
                loaded, loaded_key = notifier.load_state(path)
                self.assertEqual(loaded_key, self.key)
                self.assertEqual(notifier._state_payload(loaded), notifier._state_payload(self.state))
                snapshots.append(loaded)

            def post(_rc: dict, recipient: str, content: str) -> dict:
                posts.append((recipient, content))
                return {"id": 99}

            def fetch(_rc: dict, message_id: object) -> dict:
                lookups.append(message_id)
                self.assertEqual(message_id, 99)
                return {
                    "id": 99,
                    "type": "private",
                    "sender_email": RC["email"],
                    "display_recipient": [
                        {"id": 9, "email": "human@example.invalid"},
                        {"id": 10, "email": RC["email"]},
                    ],
                    "content": posts[0][1],
                }

            with mock.patch.object(notifier, "fetch_kanban_board", return_value=board), mock.patch.object(
                notifier, "post_zulip_direct_message", side_effect=post
            ), mock.patch.object(notifier, "post_zulip_message") as stream_post, mock.patch.object(
                notifier, "fetch_zulip_message", side_effect=fetch
            ):
                counts = notifier.scan_once(
                    self.state,
                    rc,
                    send=True,
                    key=self.key,
                    persist=persist,
                    now=10,
                )
            final, final_key = notifier.load_state(path)

        signature = notifier.task_signature(terminal)
        marker = notifier._marker(self.key, "task-dm", signature)
        self.assertEqual(
            counts,
            {"admitted": 1, "delivered": 1, "pending": 0, "primed": 0, "operator_review": 0},
        )
        self.assertEqual(lookups, [99])
        stream_post.assert_not_called()
        expected_content = (
            notifier.notification_body(terminal, candidate["metadata"]["notification_target"])
            + "\n\n"
            + marker
        )
        self.assertEqual(posts, [("human@example.invalid", expected_content)])
        stages = [
            snapshot["outbox"][0]["stage"] if snapshot["outbox"] else "complete"
            for snapshot in snapshots
        ]
        self.assertEqual(stages, ["admitted", "post_started", "posted", "complete"])
        self.assertEqual(final_key, self.key)
        self.assertEqual(final["outbox"], [])
        self.assertEqual(final["notified"], {"task-dm": signature})
        self.assertEqual(
            final["revisions"]["task-dm"],
            {"revision": notifier.task_revision(terminal), "signature": signature},
        )

    def test_legacy_0644_migrates_to_private_signed_state_without_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            signature = "a" * 64
            path.write_text(json.dumps({"notified": {"old": signature}}), encoding="utf-8")
            path.chmod(0o644)
            with notifier.process_lock(path) as held:
                state, key = notifier.load_state(held.state_path)
            self.assertEqual(state["notified"], {"old": signature})
            self.assertEqual(state["revisions"], {"old": {"revision": None, "signature": signature}})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(notifier.signing_key_path(path).stat().st_mode), 0o600)
            self.assertEqual(len(key), notifier.SIGNING_KEY_BYTES)
            loaded, _ = notifier.load_state(path)
            self.assertEqual(loaded["notified"], {"old": signature})

    def test_signed_state_tamper_and_key_loss_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            path.parent.chmod(0o700)
            notifier._atomic_write(path, b'{"notified": {}}')
            state, key = notifier.load_state(path)
            notifier.save_state(path, state, key)
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["notified"]["tampered"] = "yes"
            notifier._atomic_write(path, json.dumps(raw).encode())
            with self.assertRaisesRegex(notifier.StateError, "authentication"):
                notifier.load_state(path)
            notifier.save_state(path, state, key)
            notifier.signing_key_path(path).unlink()
            with self.assertRaises(notifier.StateError):
                notifier.load_state(path)

    def test_oversize_malformed_symlink_and_corrupt_key_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            malformed.chmod(0o600)
            with self.assertRaisesRegex(notifier.StateError, "corrupt"):
                notifier.load_state(malformed)

            oversize = root / "oversize.json"
            oversize.write_bytes(b"x" * (notifier.MAX_STATE_BYTES + 1))
            oversize.chmod(0o600)
            with self.assertRaisesRegex(notifier.StateError, "exceeds"):
                notifier.load_state(oversize)

            target = root / "target.json"
            target.write_text('{"notified": {}}', encoding="utf-8")
            target.chmod(0o600)
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaises(notifier.StateError):
                notifier.load_state(linked)

            state, key = notifier.load_state(target)
            notifier.save_state(target, state, key)
            key_path = notifier.signing_key_path(target)
            key_path.write_bytes(b"short")
            key_path.chmod(0o600)
            with self.assertRaisesRegex(notifier.StateError, "corrupt"):
                notifier.load_state(target)

    def test_unsafe_legacy_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for mode in (0o666, 0o640):
                path = root / f"state-{mode:o}.json"
                path.write_text('{"notified": {}}', encoding="utf-8")
                path.chmod(mode)
                with self.assertRaises(notifier.StateError):
                    notifier.load_state(path)
            source = root / "source.json"
            source.write_text('{"notified": {}}', encoding="utf-8")
            source.chmod(0o600)
            os.link(source, root / "hardlink.json")
            with self.assertRaises(notifier.StateError):
                notifier.load_state(source)


if __name__ == "__main__":
    unittest.main()
