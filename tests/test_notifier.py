from __future__ import annotations

import argparse
import unittest
from pathlib import Path

from hermes_zulip_bridge import notifier
from hermes_zulip_bridge import kanban_task as creator


class ZulipKanbanNotifierTests(unittest.TestCase):
    def test_flatten_tasks_adds_column_status(self) -> None:
        payload = {"columns": [{"name": "Done", "tasks": [{"id": "task-1", "title": "Example Task"}]}]}
        self.assertEqual(notifier.flatten_tasks(payload)[0]["status"], "done")

    def test_zulip_target_for_task_reads_description_block(self) -> None:
        task = {
            "description": "hello\nnotification_target:\n{\"platform\": \"zulip\", \"stream\": \"hermes\", \"topic\": \"Example Topic\"}\n\nworkflow:\n{}"
        }
        target = notifier.zulip_target_for_task(task)
        self.assertEqual(target["stream"], "hermes")
        self.assertEqual(target["topic"], "Example Topic")

    def test_zulip_target_for_task_reads_metadata(self) -> None:
        task = {"metadata": {"notification_target": {"platform": "zulip", "stream": "s", "topic": "t"}}}
        self.assertEqual(notifier.zulip_target_for_task(task), {"platform": "zulip", "stream": "s", "topic": "t"})

    def test_zulip_target_for_task_accepts_direct_message_target(self) -> None:
        task = {"metadata": {"notification_target": {"platform": "zulip", "type": "direct", "to": "user@example.com"}}}
        self.assertEqual(
            notifier.zulip_target_for_task(task),
            {"platform": "zulip", "type": "direct", "to": "user@example.com"},
        )

    def test_direct_recipient_for_target_serializes_recipient_lists(self) -> None:
        self.assertEqual(notifier.direct_recipient_for_target({"type": "direct", "user_ids": [123, "456"]}), '["123", "456"]')

    def test_zulip_target_for_task_reads_source_detail(self) -> None:
        task = {"source_detail": {"notification_target": {"platform": "zulip", "stream": "s", "topic": "renamed"}}}
        self.assertEqual(notifier.zulip_target_for_task(task), {"platform": "zulip", "stream": "s", "topic": "renamed"})

    def test_notification_body_includes_origin_message_and_bridge_marker(self) -> None:
        task = {
            "id": "task-1",
            "title": "Example Task",
            "status": "done",
            "summary": "Tests passed and adversarial review passed.",
        }
        target = {
            "platform": "zulip",
            "stream": "hermes",
            "topic": "Example Topic",
            "message_id": "101",
            "bridge_marker": "test-marker-101",
        }

        body = notifier.notification_body(task, target)

        self.assertIn("Origin Zulip message: `101`", body)
        self.assertIn("Bridge marker: `test-marker-101`", body)
        self.assertIn("Coding workflow result: implementation and required review cycle are complete.", body)

    def test_current_zulip_target_uses_origin_message_current_topic(self) -> None:
        original_fetch = notifier.fetch_zulip_message

        def fake_fetch(_rc: dict[str, str], message_id: str) -> dict:
            self.assertEqual(message_id, "101")
            return {"display_recipient": "hermes", "subject": "Renamed Example Topic"}

        try:
            notifier.fetch_zulip_message = fake_fetch
            target = notifier.current_zulip_target(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {
                    "platform": "zulip",
                    "stream": "hermes",
                    "topic": "Example Topic",
                    "message_id": "101",
                },
            )
        finally:
            notifier.fetch_zulip_message = original_fetch

        self.assertEqual(target["stream"], "hermes")
        self.assertEqual(target["topic"], "Renamed Example Topic")
        self.assertEqual(target["original_topic"], "Example Topic")

    def test_scan_once_sends_to_current_topic_from_origin_message(self) -> None:
        original_fetch_board = notifier.fetch_kanban_board
        original_fetch_message = notifier.fetch_zulip_message
        original_post = notifier.post_zulip_message
        original_state_path = notifier.STATE_PATH
        sent: list[tuple[str, str, str]] = []

        def fake_fetch_board() -> dict:
            return {
                "columns": [
                    {
                        "name": "Done",
                        "tasks": [
                            {
                                "id": "task-2",
                                "title": "Example Task",
                                "status": "done",
                                "updated_at": 456,
                                "metadata": {
                                    "notification_target": {
                                        "platform": "zulip",
                                        "stream": "hermes",
                                        "topic": "Example Topic",
                                        "message_id": "101",
                                    }
                                },
                            }
                        ],
                    }
                ]
            }

        def fake_fetch_message(_rc: dict[str, str], _message_id: str) -> dict:
            return {"display_recipient": "hermes", "subject": "Renamed Example Topic"}

        def fake_post(_rc: dict, stream: str, topic: str, content: str) -> dict:
            sent.append((stream, topic, content))
            return {"ok": True, "stream": stream, "topic": topic}

        try:
            notifier.fetch_kanban_board = fake_fetch_board
            notifier.fetch_zulip_message = fake_fetch_message
            notifier.post_zulip_message = fake_post
            notifier.STATE_PATH = Path("/tmp/hermes-zulip-bridge-test-notifier-rename-state.json")
            events = notifier.scan_once({"notified": {}}, {"site": "", "email": "", "key": ""}, send=True)
        finally:
            notifier.fetch_kanban_board = original_fetch_board
            notifier.fetch_zulip_message = original_fetch_message
            notifier.post_zulip_message = original_post
            notifier.STATE_PATH = original_state_path

        self.assertEqual(sent[0][0], "hermes")
        self.assertEqual(sent[0][1], "Renamed Example Topic")
        self.assertEqual(events[0]["topic"], "Renamed Example Topic")
        self.assertEqual(events[0]["original_topic"], "Example Topic")

    def test_scan_once_sends_and_deduplicates_terminal_status(self) -> None:
        original_fetch = notifier.fetch_kanban_board
        original_post = notifier.post_zulip_message
        original_state_path = notifier.STATE_PATH
        sent: list[str] = []

        def fake_fetch() -> dict:
            return {
                "columns": [
                    {
                        "name": "Done",
                        "tasks": [
                            {
                                "id": "task-1",
                                "title": "Example Task",
                                "status": "done",
                                "updated_at": 123,
                                "metadata": {"notification_target": {"platform": "zulip", "stream": "s", "topic": "t"}},
                            }
                        ],
                    }
                ]
            }

        def fake_post(_rc: dict, stream: str, topic: str, content: str) -> dict:
            sent.append(content)
            return {"ok": True, "stream": stream, "topic": topic}

        try:
            notifier.fetch_kanban_board = fake_fetch
            notifier.post_zulip_message = fake_post
            notifier.STATE_PATH = Path("/tmp/hermes-zulip-bridge-test-notifier-state.json")
            state = {"notified": {}}
            events = notifier.scan_once(state, {"site": "", "email": "", "key": ""}, send=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(len(sent), 1)
            events = notifier.scan_once(state, {"site": "", "email": "", "key": ""}, send=True)
            self.assertEqual(events, [])
            self.assertEqual(len(sent), 1)
        finally:
            notifier.fetch_kanban_board = original_fetch
            notifier.post_zulip_message = original_post
            notifier.STATE_PATH = original_state_path

    def test_scan_once_sends_direct_message_target(self) -> None:
        original_fetch = notifier.fetch_kanban_board
        original_post_direct = notifier.post_zulip_direct_message
        original_state_path = notifier.STATE_PATH
        sent: list[tuple[str, str]] = []

        def fake_fetch() -> dict:
            return {
                "columns": [
                    {
                        "name": "Blocked",
                        "tasks": [
                            {
                                "id": "task-dm",
                                "title": "Example Blocked Task",
                                "status": "blocked",
                                "updated_at": 789,
                                "metadata": {"notification_target": {"platform": "zulip", "type": "direct", "to": "user@example.com"}},
                            }
                        ],
                    }
                ]
            }

        def fake_post_direct(_rc: dict, to: str, content: str) -> dict:
            sent.append((to, content))
            return {"ok": True, "to": to}

        try:
            notifier.fetch_kanban_board = fake_fetch
            notifier.post_zulip_direct_message = fake_post_direct
            notifier.STATE_PATH = Path("/tmp/hermes-zulip-bridge-test-notifier-dm-state.json")
            events = notifier.scan_once({"notified": {}}, {"site": "", "email": "", "key": ""}, send=True)
        finally:
            notifier.fetch_kanban_board = original_fetch
            notifier.post_zulip_direct_message = original_post_direct
            notifier.STATE_PATH = original_state_path

        self.assertEqual(sent[0][0], "user@example.com")
        self.assertEqual(events[0]["type"], "direct")
        self.assertEqual(events[0]["to"], "user@example.com")
        self.assertNotIn("stream", events[0])


class CodingWorkflowCreatorTests(unittest.TestCase):
    def test_payload_contains_review_contract_and_notification_metadata(self) -> None:
        args = argparse.Namespace(
            title="Example Task",
            request="Example request.",
            repo="/repo",
            acceptance=["Example acceptance criterion."],
            stream="hermes",
            topic="Example Topic",
            dm_to="",
            message_id="102",
            bridge_marker="test-marker-102",
            assignee="coder",
            reviewer="reviewer",
            status="ready",
            priority="p2",
        )
        payload = creator.build_payload(args)
        self.assertEqual(payload["assignee"], "coder")
        self.assertEqual(payload["metadata"]["workflow"], "coding_with_adversarial_review")
        self.assertEqual(payload["source_detail"]["workflow"], "coding_with_adversarial_review")
        self.assertEqual(payload["metadata"]["notification_target"]["topic"], "Example Topic")
        self.assertEqual(payload["source_detail"]["notification_target"]["message_id"], "102")
        self.assertIn("adversarial review", payload["body"])
        self.assertIn("notification_target:", payload["body"])
        self.assertEqual(payload["description"], payload["body"])
        self.assertIn("Example acceptance criterion.", payload["body"])

    def test_payload_can_target_zulip_direct_message(self) -> None:
        args = argparse.Namespace(
            title="Example Direct Task",
            request="Example direct request.",
            repo="/repo",
            acceptance=None,
            stream="hermes",
            topic="Example Topic",
            dm_to="user@example.com",
            message_id="102",
            bridge_marker="test-marker-102",
            assignee="integration-manager",
            reviewer="reviewer",
            status="ready",
            priority="p1",
        )
        payload = creator.build_payload(args)

        target = payload["metadata"]["notification_target"]
        self.assertEqual(target["type"], "direct")
        self.assertEqual(target["to"], "user@example.com")
        self.assertNotIn("stream", target)
        self.assertIn('"type": "direct"', payload["body"])


if __name__ == "__main__":
    unittest.main()
