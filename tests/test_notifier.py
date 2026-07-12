from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import os
import tempfile
import traceback
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from hermes_zulip_bridge import kanban_task as creator
from hermes_zulip_bridge import notifier


class ZulipKanbanNotifierTests(unittest.TestCase):
    def setUp(self) -> None:
        policy = mock.patch.dict(
            os.environ,
            {
                "HERMES_ZULIP_STREAM_IDS": "7",
                "HERMES_ZULIP_TOPIC_POLICY": "any",
                "HERMES_ZULIP_TOPICS": "",
                "HERMES_ZULIP_ALLOWED_SENDERS": "id:9,email:human@example.invalid",
                "HERMES_ZULIP_ALLOW_DMS": "true",
                "HERMES_ZULIP_ALLOWED_DM_RECIPIENTS": "id:123,id:456,email:user@example.com",
            },
        )
        policy.start()
        self.addCleanup(policy.stop)

    def test_flatten_tasks_propagates_column_status(self) -> None:
        board = {"columns": [{"name": "Done", "tasks": [{"id": "task-1", "updated_at": 1}]}]}

        self.assertEqual(notifier.flatten_tasks(board), [{"id": "task-1", "updated_at": 1, "status": "done"}])

    def test_target_is_not_parsed_from_free_text_or_top_level_fields(self) -> None:
        target = {"platform": "zulip", "stream_id": 7, "message_id": 41}
        block = "request\nnotification_target:\n" + json.dumps(target) + "\n\nworkflow:\n{}"

        for field in ("description", "body", "details", "content", "notes"):
            with self.subTest(field=field):
                self.assertIsNone(notifier.zulip_target_for_task({field: block}))
        self.assertIsNone(notifier.zulip_target_for_task({"notification_target": target}))

    def test_target_is_parsed_from_source_detail(self) -> None:
        target = {"platform": "zulip", "stream_id": 7, "message_id": 41}

        self.assertEqual(notifier.zulip_target_for_task({"source_detail": {"notification_target": target}}), target)
        self.assertEqual(notifier.zulip_target_for_task({"source_detail": target}), target)

    def test_direct_target_is_parsed_with_canonical_recipient(self) -> None:
        task = {
            "metadata": {
                "notification_target": {"platform": "zulip", "delivery": "dm", "user_ids": [123, "456"]}
            }
        }

        self.assertEqual(
            notifier.zulip_target_for_task(task),
            {
                "platform": "zulip",
                "delivery": "dm",
                "user_ids": [123, "456"],
                "type": "direct",
                "to": '["123", "456"]',
            },
        )

    def test_zuliprc_is_parsed_only_from_verified_private_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "zuliprc"
            path.write_text("[api]\nemail=bot@example.com\nkey=fixture-key\nsite=https://example/\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(notifier.load_rc(path), {"email": "bot@example.com", "key": "fixture-key", "site": "https://example"})
            path.chmod(0o666)
            with self.assertRaisesRegex(SystemExit, "unsafe"):
                notifier.load_rc(path)
            path.chmod(0o600)
            link = root / "linked-zuliprc"
            link.symlink_to(path)
            with self.assertRaisesRegex(SystemExit, "unsafe"):
                notifier.load_rc(link)
            path.write_text("[wrong]\nvalue=1\n", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(SystemExit, "malformed"):
                notifier.load_rc(path)

    def test_notifier_log_hashes_private_values(self) -> None:
        canaries = ("Private Stream", "Private Topic", "session-secret", "bot@example.com", "/private/path")
        output = io.StringIO()
        with mock.patch("sys.stdout", output), mock.patch.object(notifier.time, "strftime", return_value="timestamp"):
            notifier.log("notified", *canaries)
        rendered = output.getvalue()
        self.assertTrue(rendered.startswith("timestamp notified ref:"))
        for canary in canaries:
            self.assertNotIn(canary, rendered)

    def test_target_requires_numeric_origin_scope(self) -> None:
        scoped = {
            "metadata": {
                "notification_target": {
                    "platform": "zulip",
                    "stream": "s",
                    "stream_id": 7,
                    "topic": "t",
                    "message_id": 41,
                }
            }
        }
        self.assertEqual(notifier.zulip_target_for_task(scoped)["stream_id"], 7)
        scoped["metadata"]["notification_target"].pop("stream_id")
        self.assertIsNone(notifier.zulip_target_for_task(scoped))

    def test_direct_recipient_lists_are_canonical_json(self) -> None:
        self.assertEqual(notifier.direct_recipient_for_target({"type": "direct", "user_ids": [123, "456"]}), '["123", "456"]')

    def test_notification_body_has_workflow_result(self) -> None:
        body = notifier.notification_body(
            {"id": "task-1", "title": "workflow", "status": "done"},
            {"message_id": 41, "bridge_marker": "bridge-marker"},
        )
        self.assertIn("Origin Zulip message: `41`", body)
        self.assertIn("Coding workflow result", body)


class CodingWorkflowCreatorTests(unittest.TestCase):
    def args(self, *, dm_to: str = "") -> argparse.Namespace:
        return argparse.Namespace(
            title="Fix bridge",
            request="Implement the repair.",
            repo="/repo",
            acceptance=["Tests pass."],
            stream="hermes",
            stream_id=7,
            topic="Zulip bridge",
            dm_to=dm_to,
            message_id="41",
            bridge_marker="bridge-41",
            assignee="coder",
            reviewer="reviewer",
            status="ready",
            priority="p2",
        )

    def test_payload_persists_numeric_stream_and_origin_ids(self) -> None:
        payload = creator.build_payload(self.args())
        target = payload["metadata"]["notification_target"]
        self.assertEqual(target["stream_id"], 7)
        self.assertEqual(target["message_id"], "41")
        self.assertEqual(payload["source_detail"]["notification_target"], target)
        self.assertIn("adversarial review", payload["body"])
        self.assertNotIn("notification_target", payload["body"])

    def test_payload_can_target_direct_message(self) -> None:
        target = creator.build_payload(self.args(dm_to="user@example.com"))["metadata"]["notification_target"]
        self.assertEqual(target["type"], "direct")
        self.assertNotIn("stream", target)

    def test_request_failures_do_not_render_private_inputs(self) -> None:
        secret_url = "https://user:credential@example.invalid/private-path?token=query-secret"
        payload = {"request": "private-request", "repo": "/private/repo", "body": "private-body"}
        response_secret = b"echoed-response-secret\x00\x1b[31m"
        reason_secret = "hostile-reason-secret\r\nforged-log\x1b[31m"
        canaries = (
            secret_url,
            "credential",
            "private-path",
            "query-secret",
            "private-request",
            "/private/repo",
            "private-body",
            "echoed-response-secret",
            "hostile-reason-secret",
            "forged-log",
            "\x1b",
            "\x00",
        )
        failures = (
            urllib.error.HTTPError(secret_url, 503, "secret status", None, io.BytesIO(response_secret)),
            urllib.error.URLError(reason_secret),
        )

        for failure in failures:
            with self.subTest(failure=type(failure).__name__), mock.patch.object(
                creator.urllib.request, "urlopen", side_effect=failure
            ), self.assertRaises(creator.KanbanRequestError) as raised:
                creator.request_json("POST", secret_url, operation="task creation", payload=payload)

            error = raised.exception
            log_output = io.StringIO()
            logger = logging.getLogger(f"kanban-privacy-{type(failure).__name__}")
            logger.handlers = [logging.StreamHandler(log_output)]
            logger.propagate = False
            logger.error("failure", exc_info=(type(error), error, error.__traceback__))
            rendered = "\n".join((str(error), repr(error), "".join(traceback.format_exception(error)), log_output.getvalue()))
            expected_status = "HTTP 503" if isinstance(failure, urllib.error.HTTPError) else "request error"
            self.assertEqual(str(error), str(creator._request_error("task creation", expected_status)))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            for canary in canaries:
                self.assertNotIn(canary, rendered)

    def test_invalid_response_and_cli_output_are_stably_sanitized(self) -> None:
        secret_body = b'{"echo":"echoed-response-secret"'
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = secret_body
        with mock.patch.object(creator.urllib.request, "urlopen", return_value=response), self.assertRaises(
            creator.KanbanRequestError
        ) as raised:
            creator.request_json("POST", "https://example.invalid/private?secret=query", operation="task dispatch")
        self.assertEqual(str(raised.exception), str(creator._request_error("task dispatch", "invalid response")))
        self.assertNotIn("echoed-response-secret", repr(raised.exception))

        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "kanban-task",
            "--title",
            "private-title",
            "--request",
            "private-request",
            "--repo",
            "/private/repo",
            "--agentos-url",
            "https://user:credential@example.invalid/private?secret=query",
        ]
        with mock.patch("sys.argv", argv), mock.patch.object(
            creator, "create_task", side_effect=creator._request_error("task creation", "request error")
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(creator.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), f'{creator._request_error("task creation", "request error")}\n')
        for canary in ("private-title", "private-request", "/private/repo", "credential", "secret", "\x1b", "\r"):
            self.assertNotIn(canary, stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
