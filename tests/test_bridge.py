from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


from hermes_zulip_bridge import bridge


class ZulipAttachmentTests(unittest.TestCase):
    def test_find_zulip_upload_links_normalizes_and_deduplicates(self) -> None:
        links = bridge.find_zulip_upload_links(
            "see [note](/user_uploads/1/ab/note.md), "
            "same https://zulip.example.com/user_uploads/1/ab/note.md "
            "img ![](/user_uploads/1/ab/image.png) "
            "ignore https://evil.example/user_uploads/1/ab/ignored.txt "
            "ignore /api/v1/messages "
            "ignore /user_uploads/../api/v1/users",
            "https://zulip.example.com",
        )

        self.assertEqual(
            links,
            [
                {"path": "/user_uploads/1/ab/note.md", "source": "/user_uploads/1/ab/note.md", "filename": "note.md"},
                {"path": "/user_uploads/1/ab/image.png", "source": "/user_uploads/1/ab/image.png", "filename": "image.png"},
            ],
        )

    def test_text_like_attachment_detection(self) -> None:
        self.assertTrue(bridge.is_text_like_attachment("/user_uploads/1/a/file.txt", "application/octet-stream"))
        self.assertTrue(bridge.is_text_like_attachment("/user_uploads/1/a/file", "application/json"))
        self.assertTrue(bridge.is_text_like_attachment("/user_uploads/1/a/file", "application/vnd.test+xml"))
        self.assertFalse(bridge.is_text_like_attachment("/user_uploads/1/a/file.bin", "application/octet-stream"))

    def test_safe_decode_attachment_uses_declared_charset(self) -> None:
        self.assertEqual(bridge.safe_decode_attachment("hello".encode("utf-16"), "text/plain; charset=utf-16"), "hello")

    def test_build_attachment_context_handles_text_image_error_and_limits(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_fetch = bridge.fetch_zulip_attachment
        original_max_chars = bridge.ATTACHMENT_MAX_CHARS
        original_total_chars = bridge.ATTACHMENT_TOTAL_CHARS
        original_max_files = bridge.ATTACHMENT_MAX_FILES

        def fake_fetch(_rc: dict[str, str], path: str) -> dict:
            if path.endswith("note.md"):
                return {
                    "path": path,
                    "filename": "note.md",
                    "content_type": "text/markdown",
                    "content_length": 12,
                    "data": b"abcdef",
                    "truncated_bytes": True,
                    "error": "",
                }
            if path.endswith("screen.png"):
                return {
                    "path": path,
                    "filename": "screen.png",
                    "content_type": "image/png",
                    "content_length": 12345,
                    "data": b"\x89PNG",
                    "truncated_bytes": False,
                    "error": "",
                }
            return {
                "path": path,
                "filename": "missing.txt",
                "content_type": "",
                "content_length": None,
                "data": b"",
                "truncated_bytes": False,
                "error": "HTTP 404 Not Found",
            }

        try:
            bridge.fetch_zulip_attachment = fake_fetch
            bridge.ATTACHMENT_MAX_CHARS = 4
            bridge.ATTACHMENT_TOTAL_CHARS = 4
            bridge.ATTACHMENT_MAX_FILES = 10
            context = bridge.build_attachment_context(
                rc,
                "[note](/user_uploads/1/ab/note.md) "
                "![screen](/user_uploads/1/ab/screen.png) "
                "/user_uploads/1/ab/missing.txt",
            )
        finally:
            bridge.fetch_zulip_attachment = original_fetch
            bridge.ATTACHMENT_MAX_CHARS = original_max_chars
            bridge.ATTACHMENT_TOTAL_CHARS = original_total_chars
            bridge.ATTACHMENT_MAX_FILES = original_max_files

        self.assertIn("----- BEGIN ZULIP ATTACHMENT: note.md -----", context)
        self.assertIn("Attachment access instructions for the agent: Zulip uploads are private.", context)
        self.assertIn("Source path: /user_uploads/1/ab/screen.png", context)
        self.assertIn("Source URL: https://zulip.example.com/user_uploads/1/ab/screen.png", context)
        self.assertIn("HTTP Basic auth with the Zulip bot credentials", context)
        self.assertIn("abcd", context)
        self.assertIn("[Truncated: read limit", context)
        self.assertIn("[Truncated: per-file character limit", context)
        self.assertIn("Image attachment not inlined", context)
        self.assertIn("save the image locally", context)
        self.assertIn("Fetch error: HTTP 404 Not Found. Original link preserved: /user_uploads/1/ab/missing.txt", context)

    def test_non_text_attachment_guidance_includes_authenticated_source_url(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_fetch = bridge.fetch_zulip_attachment

        def fake_fetch(_rc: dict[str, str], path: str) -> dict:
            return {
                "path": path,
                "filename": "archive.zip",
                "content_type": "application/zip",
                "content_length": 100,
                "data": b"PK",
                "truncated_bytes": False,
                "error": "",
            }

        try:
            bridge.fetch_zulip_attachment = fake_fetch
            context = bridge.build_attachment_context(rc, "[archive](/user_uploads/1/ab/archive.zip)")
        finally:
            bridge.fetch_zulip_attachment = original_fetch

        self.assertIn("Source URL: https://zulip.example.com/user_uploads/1/ab/archive.zip", context)
        self.assertIn("Attachment not inlined: non-text file type.", context)
        self.assertIn("save it locally before inspecting", context)

    def test_api_uses_official_zulip_client_facade(self) -> None:
        calls: list[dict[str, object]] = []
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_cache = dict(bridge.ZULIP_CLIENT_CACHE)

        class FakeClient:
            def call_endpoint(self, **kwargs: object) -> dict:
                calls.append(kwargs)
                return {"result": "success", "messages": []}

        try:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE[("https://zulip.example.com", "bot@example.com", "test-api-key")] = FakeClient()
            payload = bridge.api(
                rc,
                "GET",
                "/api/v1/messages",
                params={"anchor": "newest", "num_before": 100},
            )
        finally:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE.update(original_cache)

        self.assertEqual(payload["result"], "success")
        self.assertEqual(
            calls,
            [
                {
                    "url": "messages",
                    "method": "GET",
                    "request": {"anchor": "newest", "num_before": 100},
                    "timeout": 30,
                }
            ],
        )

    def test_api_surfaces_zulip_library_error_payloads(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_cache = dict(bridge.ZULIP_CLIENT_CACHE)

        class FakeClient:
            def call_endpoint(self, **_kwargs: object) -> dict:
                return {"result": "error", "code": "BAD_REQUEST", "msg": "nope"}

        try:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE[("https://zulip.example.com", "bot@example.com", "test-api-key")] = FakeClient()
            with self.assertRaisesRegex(RuntimeError, "BAD_REQUEST"):
                bridge.api(rc, "POST", "/api/v1/messages", data={"content": "hello"})
        finally:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE.update(original_cache)

    def test_format_out_of_band_user_message_uses_exact_marker(self) -> None:
        formatted = bridge.format_out_of_band_user_message(
            {
                "id": 123,
                "sender_full_name": "Test User",
                "content": "please stop and use the new requirement",
            }
        )

        self.assertTrue(formatted.startswith(bridge.OUT_OF_BAND_USER_MESSAGE_OPEN + "\n"))
        self.assertTrue(formatted.endswith("\n" + bridge.OUT_OF_BAND_USER_MESSAGE_CLOSE))
        self.assertIn("User: Test User", formatted)
        self.assertIn("Zulip message ID: 123", formatted)
        self.assertIn("please stop and use the new requirement", formatted)

    def test_store_steering_message_appends_jsonl_and_reacts(self) -> None:
        conversation = {
            "conversation_key": "zulip:example:1:thread",
            "thread_id": "thread",
            "stream": "hermes",
            "stream_id": "1",
            "topic": "Zulip bridge",
        }
        message = {
            "id": 456,
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Zulip bridge",
            "sender_full_name": "Test User",
            "content": "actually, make this interrupting",
        }
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_path = bridge.STEERING_PATH
        original_add_reaction = bridge.add_reaction
        reactions: list[tuple[int, str]] = []

        def fake_add_reaction(_rc: dict[str, str], msg: dict, emoji: str) -> None:
            reactions.append((int(msg["id"]), emoji))

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                bridge.STEERING_PATH = Path(tmpdir) / "steering.jsonl"
                bridge.add_reaction = fake_add_reaction

                record = bridge.store_steering_message(rc, message, conversation, active_message_id=111)
                lines = bridge.STEERING_PATH.read_text().splitlines()
        finally:
            bridge.STEERING_PATH = original_path
            bridge.add_reaction = original_add_reaction

        self.assertEqual(record["message_id"], 456)
        self.assertEqual(record["active_message_id"], 111)
        self.assertEqual(record["conversation_key"], "zulip:example:1:thread")
        self.assertEqual(reactions, [(456, "eyes")])
        self.assertEqual(len(lines), 1)
        stored = json.loads(lines[0])
        self.assertEqual(stored["message_id"], 456)
        self.assertIn(bridge.OUT_OF_BAND_USER_MESSAGE_OPEN, stored["formatted"])
        self.assertIn("actually, make this interrupting", stored["formatted"])

    def test_should_process_can_filter_topics(self) -> None:
        original_streams = bridge.ALLOW_STREAMS
        original_topics = bridge.ALLOW_TOPICS
        original_patterns = bridge.IGNORE_CONTENT_PATTERNS
        try:
            bridge.ALLOW_STREAMS = set()
            bridge.ALLOW_TOPICS = {"Allowed"}
            bridge.IGNORE_CONTENT_PATTERNS = []
            self.assertTrue(
                bridge.should_process(
                    {
                        "type": "stream",
                        "display_recipient": "hermes",
                        "topic": "Allowed",
                        "sender_email": "user@example.com",
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
            self.assertFalse(
                bridge.should_process(
                    {
                        "type": "stream",
                        "display_recipient": "hermes",
                        "topic": "Blocked",
                        "sender_email": "user@example.com",
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
        finally:
            bridge.ALLOW_STREAMS = original_streams
            bridge.ALLOW_TOPICS = original_topics
            bridge.IGNORE_CONTENT_PATTERNS = original_patterns

    def test_should_process_prefers_stream_id_over_stream_name(self) -> None:
        original_streams = bridge.ALLOW_STREAMS
        original_stream_ids = bridge.ALLOW_STREAM_IDS
        try:
            bridge.ALLOW_STREAMS = {"old-name"}
            bridge.ALLOW_STREAM_IDS = {"123"}
            self.assertTrue(
                bridge.should_process(
                    {
                        "type": "stream",
                        "stream_id": 123,
                        "display_recipient": "new-name",
                        "topic": "Allowed",
                        "sender_email": "user@example.com",
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
            self.assertFalse(
                bridge.should_process(
                    {
                        "type": "stream",
                        "stream_id": 456,
                        "display_recipient": "old-name",
                        "topic": "Allowed",
                        "sender_email": "user@example.com",
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
        finally:
            bridge.ALLOW_STREAMS = original_streams
            bridge.ALLOW_STREAM_IDS = original_stream_ids

    def test_reply_resolves_current_stream_name_from_id(self) -> None:
        original_api = bridge.api
        posts: list[dict] = []

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            if method == "GET" and path == "/api/v1/streams":
                return {"streams": [{"stream_id": 123, "name": "new-name"}]}
            if method == "POST" and path == "/api/v1/messages":
                posts.append(data or {})
                return {"ok": True}
            raise AssertionError((method, path, params, data))

        try:
            bridge.api = fake_api
            bridge.reply(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"type": "stream", "stream_id": 123, "display_recipient": "old-name", "topic": "t"},
                "hello",
            )
        finally:
            bridge.api = original_api

        self.assertEqual(posts[0]["to"], "new-name")

    def test_should_process_uses_configurable_ignore_patterns(self) -> None:
        original_streams = bridge.ALLOW_STREAMS
        original_topics = bridge.ALLOW_TOPICS
        original_patterns = bridge.IGNORE_CONTENT_PATTERNS
        message = {
            "type": "stream",
            "display_recipient": "hermes",
            "topic": "Allowed",
            "sender_email": "user@example.com",
            "content": "archive-import: archived note",
        }
        try:
            bridge.ALLOW_STREAMS = set()
            bridge.ALLOW_TOPICS = set()
            bridge.IGNORE_CONTENT_PATTERNS = []
            self.assertTrue(bridge.should_process(message, "bot@example.com"))
            bridge.IGNORE_CONTENT_PATTERNS = ["archive-import:"]
            self.assertFalse(bridge.should_process(message, "bot@example.com"))
        finally:
            bridge.ALLOW_STREAMS = original_streams
            bridge.ALLOW_TOPICS = original_topics
            bridge.IGNORE_CONTENT_PATTERNS = original_patterns

    def test_active_steering_is_seen_only_after_success(self) -> None:
        seen: set[int] = set()
        active = {"key": {2, 3}}

        bridge.finish_active_message(seen, active, "key", 1, ok=False)
        self.assertEqual(seen, {1})
        self.assertEqual(active, {})

        active = {}
        self.assertTrue(bridge.remember_active_steering(active, "key", 4))
        self.assertFalse(bridge.remember_active_steering(active, "key", 4))
        bridge.finish_active_message(seen, active, "key", 5, ok=True)
        self.assertEqual(seen, {1, 4, 5})
        self.assertEqual(active, {})

    def test_goal_status_is_readonly_during_active_turn(self) -> None:
        self.assertTrue(bridge.is_readonly_goal_slash({"content": "/goal"}))
        self.assertTrue(bridge.is_readonly_goal_slash({"content": "/goal status"}))
        self.assertTrue(bridge.is_readonly_goal_slash({"content": "/goal show"}))
        self.assertFalse(bridge.is_readonly_goal_slash({"content": "/goal pause"}))
        self.assertFalse(bridge.is_readonly_goal_slash({"content": "/goal ship it"}))
        self.assertFalse(bridge.is_readonly_goal_slash({"content": "please stop now"}))

    def test_active_goal_status_replies_without_steering_or_interrupt(self) -> None:
        original_handle_message = bridge.handle_message
        original_store = bridge.store_steering_message
        original_interrupt = bridge.interrupt_active_message
        calls: list[tuple[str, object, object]] = []
        seen: set[int] = set()
        active_steering: dict[str, set[int]] = {}
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        message = {"id": 222, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "/goal status"}
        conversation = {"conversation_key": "zulip:example:1:t"}

        try:
            bridge.handle_message = lambda _rc, msg, session_id: calls.append(("handle", msg["content"], session_id)) or session_id
            bridge.store_steering_message = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("read-only goal status should not be stored as steering")
            )
            bridge.interrupt_active_message = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("read-only goal status should not interrupt")
            )

            bridge.handle_active_topic_message(rc, message, "s1", conversation, 111, active_steering, seen)
        finally:
            bridge.handle_message = original_handle_message
            bridge.store_steering_message = original_store
            bridge.interrupt_active_message = original_interrupt

        self.assertEqual(calls, [("handle", "/goal status", "s1")])
        self.assertEqual(seen, {222})
        self.assertEqual(active_steering, {})

    def test_active_normal_message_still_steers_and_interrupts(self) -> None:
        original_store = bridge.store_steering_message
        original_interrupt = bridge.interrupt_active_message
        original_hard_interrupt = bridge.HARD_INTERRUPT_ON_STEERING
        calls: list[tuple[str, object]] = []
        seen: set[int] = set()
        active_steering: dict[str, set[int]] = {}
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        message = {"id": 222, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "stop now"}
        conversation = {"conversation_key": "zulip:example:1:t"}

        try:
            bridge.HARD_INTERRUPT_ON_STEERING = True
            bridge.store_steering_message = lambda _rc, _msg, _conversation, active_id: calls.append(("store", active_id))
            bridge.interrupt_active_message = lambda active_id: calls.append(("interrupt", active_id)) or True

            bridge.handle_active_topic_message(rc, message, "s1", conversation, 111, active_steering, seen)
        finally:
            bridge.store_steering_message = original_store
            bridge.interrupt_active_message = original_interrupt
            bridge.HARD_INTERRUPT_ON_STEERING = original_hard_interrupt

        self.assertEqual(calls, [("store", 111), ("interrupt", 111)])
        self.assertEqual(seen, set())
        self.assertEqual(active_steering, {"zulip:example:1:t": {222}})

    def test_interrupt_active_message_marks_and_terminates_process_group(self) -> None:
        calls: list[tuple[int, int]] = []
        original_killpg = bridge.os.killpg
        original_processes = dict(bridge.ACTIVE_PROCESSES)
        original_interrupts = set(bridge.ACTIVE_INTERRUPTS)

        class FakeProc:
            pid = 12345

            def poll(self) -> None:
                return None

        try:
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_INTERRUPTS.clear()
            bridge.ACTIVE_PROCESSES[777] = FakeProc()
            bridge.os.killpg = lambda pid, sig: calls.append((pid, sig))

            self.assertTrue(bridge.interrupt_active_message(777))
            self.assertTrue(bridge.pop_active_interrupt(777))
        finally:
            bridge.os.killpg = original_killpg
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_PROCESSES.update(original_processes)
            bridge.ACTIVE_INTERRUPTS.clear()
            bridge.ACTIVE_INTERRUPTS.update(original_interrupts)

        self.assertEqual(calls, [(12345, bridge.signal.SIGTERM)])

    def test_register_active_process_honors_pending_interrupt(self) -> None:
        calls: list[tuple[int, int]] = []
        original_killpg = bridge.os.killpg
        original_processes = dict(bridge.ACTIVE_PROCESSES)
        original_interrupts = set(bridge.ACTIVE_INTERRUPTS)

        class FakeProc:
            pid = 22222

            def poll(self) -> None:
                return None

        try:
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_INTERRUPTS.clear()
            bridge.ACTIVE_INTERRUPTS.add(888)
            bridge.os.killpg = lambda pid, sig: calls.append((pid, sig))

            self.assertTrue(bridge.register_active_process(888, FakeProc()))
            self.assertTrue(bridge.pop_active_interrupt(888))
        finally:
            bridge.os.killpg = original_killpg
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_PROCESSES.update(original_processes)
            bridge.ACTIVE_INTERRUPTS.clear()
            bridge.ACTIVE_INTERRUPTS.update(original_interrupts)

        self.assertEqual(calls, [(22222, bridge.signal.SIGTERM)])

    def test_handle_message_interruption_does_not_post_error_reply(self) -> None:
        original_hermes_reply = bridge.hermes_reply
        original_reply = bridge.reply
        original_add_reaction = bridge.add_reaction
        original_remove_reaction = bridge.remove_reaction
        replies: list[str] = []

        try:
            bridge.hermes_reply = lambda *_args, **_kwargs: (_ for _ in ()).throw(bridge.HermesInterrupted("stopped"))
            bridge.reply = lambda _rc, _message, content: replies.append(content)
            bridge.add_reaction = lambda *_args, **_kwargs: None
            bridge.remove_reaction = lambda *_args, **_kwargs: None

            with self.assertRaises(bridge.HermesInterrupted):
                bridge.handle_message(
                    {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    {"id": 1, "display_recipient": "hermes", "topic": "t"},
                    None,
                )
        finally:
            bridge.hermes_reply = original_hermes_reply
            bridge.reply = original_reply
            bridge.add_reaction = original_add_reaction
            bridge.remove_reaction = original_remove_reaction

        self.assertEqual(replies, [])

    def test_parse_known_slash_command_uses_fallback_registry(self) -> None:
        self.assertEqual(bridge.parse_known_slash_command("/goal build it"), ("goal", "goal", "build it"))
        self.assertEqual(bridge.parse_known_slash_command("/reload_mcp"), ("reload_mcp", "reload-mcp", ""))
        self.assertEqual(bridge.parse_known_slash_command("`/goal status`"), ("goal", "goal", "status"))
        self.assertEqual(bridge.parse_known_slash_command("<p>/goal status</p>"), ("goal", "goal", "status"))
        self.assertEqual(bridge.parse_known_slash_command("Let's test... /goal status"), ("goal", "goal", "status"))
        self.assertIsNone(bridge.parse_known_slash_command("Can I use /goal status?"))
        self.assertIsNone(bridge.parse_known_slash_command("/definitely-not-real"))

    def test_handle_message_routes_known_slash_command_to_worker(self) -> None:
        original_hermes_reply = bridge.hermes_reply
        original_run_slash_worker = bridge.run_slash_worker
        original_reply = bridge.reply
        original_add_reaction = bridge.add_reaction
        original_remove_reaction = bridge.remove_reaction
        replies: list[str] = []

        try:
            bridge.hermes_reply = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slash leaked to prompt"))
            bridge.run_slash_worker = lambda command, session_id: f"ran {command} in {session_id}"
            bridge.reply = lambda _rc, _message, content: replies.append(content)
            bridge.add_reaction = lambda *_args, **_kwargs: None
            bridge.remove_reaction = lambda *_args, **_kwargs: None

            bridge.handle_message(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 1, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "/status"},
                "s1",
            )
        finally:
            bridge.hermes_reply = original_hermes_reply
            bridge.run_slash_worker = original_run_slash_worker
            bridge.reply = original_reply
            bridge.add_reaction = original_add_reaction
            bridge.remove_reaction = original_remove_reaction

        self.assertEqual(replies, ["ran /status in s1"])

    def test_handle_message_posts_goal_status_and_continuation_turn(self) -> None:
        original_hermes_reply = bridge.hermes_reply
        original_goal_manager = bridge.goal_manager
        original_goal_background_processes = bridge.goal_background_processes
        original_reply = bridge.reply
        original_add_reaction = bridge.add_reaction
        original_remove_reaction = bridge.remove_reaction
        replies: list[str] = []
        prompts: list[str] = []
        decisions = [
            {"message": "continuing toward goal", "should_continue": True, "continuation_prompt": "next step"},
            {"message": "goal achieved", "should_continue": False},
        ]

        class Manager:
            def is_active(self) -> bool:
                return True

            def evaluate_after_turn(self, last_response: str, **_kwargs: object) -> dict:
                prompts.append(f"evaluated:{last_response}")
                return decisions.pop(0)

        def fake_hermes_reply(_rc: dict, msg: dict, session_id: str | None) -> tuple[str, str]:
            prompts.append(str(msg["content"]))
            return ("first answer" if session_id is None else "second answer"), "s1"

        try:
            bridge.hermes_reply = fake_hermes_reply
            bridge.goal_manager = lambda _session_id: Manager()
            bridge.goal_background_processes = lambda: []
            bridge.reply = lambda _rc, _message, content: replies.append(content)
            bridge.add_reaction = lambda *_args, **_kwargs: None
            bridge.remove_reaction = lambda *_args, **_kwargs: None

            session_id = bridge.handle_message(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 1, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "start"},
                None,
            )
        finally:
            bridge.hermes_reply = original_hermes_reply
            bridge.goal_manager = original_goal_manager
            bridge.goal_background_processes = original_goal_background_processes
            bridge.reply = original_reply
            bridge.add_reaction = original_add_reaction
            bridge.remove_reaction = original_remove_reaction

        self.assertEqual(session_id, "s1")
        self.assertEqual(replies, ["first answer", "continuing toward goal", "second answer", "goal achieved"])
        self.assertEqual(prompts, ["start", "evaluated:first answer", "next step", "evaluated:second answer"])

    def test_goal_slash_sets_goal_and_kicks_off_prompt(self) -> None:
        original_hermes_reply = bridge.hermes_reply
        original_goal_manager = bridge.goal_manager
        calls: list[tuple[str, str]] = []

        class State:
            max_turns = 20
            goal = "ship it"

        class Manager:
            def __init__(self, session_id: str) -> None:
                self.session_id = session_id

            def set(self, goal: str, *, contract: object | None = None) -> State:
                calls.append((self.session_id, goal))
                return State()

            def status_line(self) -> str:
                return "Goal (active, 0/20 turns): ship it"

            def render_contract(self) -> str:
                return "(no completion contract)"

        try:
            bridge.hermes_reply = lambda _rc, message, _session_id: (f"started {message['content']}", "s-new")
            bridge.goal_manager = lambda session_id: Manager(session_id)
            answer, session_id = bridge.handle_goal_slash(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 1, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "/goal ship it"},
                None,
                "ship it",
            )
        finally:
            bridge.hermes_reply = original_hermes_reply
            bridge.goal_manager = original_goal_manager

        self.assertEqual(session_id, "s-new")
        self.assertEqual(calls, [("s-new", "ship it")])
        self.assertIn("Goal set (20-turn budget): ship it", answer)
        self.assertIn("Goal (active", answer)
        self.assertIn("started ship it", answer)

    def test_goal_status_includes_goal_details(self) -> None:
        original_goal_manager = bridge.goal_manager

        class State:
            last_verdict = "continue"
            last_reason = "more work remains"
            paused_reason = ""
            subgoals = ["prove it"]

        class Manager:
            state = State()

            def status_line(self) -> str:
                return "Goal (active, 1/20 turns): ship it"

            def render_contract(self) -> str:
                return "Verification: tests pass"

        try:
            bridge.goal_manager = lambda _session_id: Manager()
            answer, session_id = bridge.handle_goal_slash(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 1, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "/goal status"},
                "s1",
                "status",
            )
        finally:
            bridge.goal_manager = original_goal_manager

        self.assertEqual(session_id, "s1")
        self.assertIn("Goal (active, 1/20 turns): ship it", answer)
        self.assertIn("Last verdict: continue - more work remains", answer)
        self.assertIn("- prove it", answer)
        self.assertIn("Verification: tests pass", answer)

    def test_hermes_reply_uses_extra_args_before_prompt(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        message = {
            "id": 999,
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Bridge",
            "sender_full_name": "User",
            "content": "ping",
        }
        captured: dict[str, list[str]] = {}
        originals = {
            "HERMES": bridge.HERMES,
            "HERMES_EXTRA_ARGS": bridge.HERMES_EXTRA_ARGS,
            "Popen": bridge.subprocess.Popen,
            "topic_history": bridge.topic_history,
            "build_attachment_context": bridge.build_attachment_context,
            "typing_status": bridge.typing_status,
            "find_session_by_marker": bridge.find_session_by_marker,
            "clean_session_record": bridge.clean_session_record,
            "set_session_archived": bridge.set_session_archived,
        }

        class FakeProc:
            returncode = 0

            def poll(self) -> int:
                return 0

            def communicate(self) -> tuple[str, str]:
                return "pong\n", ""

        def fake_popen(cmd: list[str], **_kwargs: object) -> FakeProc:
            captured["cmd"] = cmd
            return FakeProc()

        try:
            bridge.HERMES = Path("/opt/hermes/bin/hermes")
            bridge.HERMES_EXTRA_ARGS = ["--profile", "hermes"]
            bridge.subprocess.Popen = fake_popen
            bridge.topic_history = lambda _rc, _message: ""
            bridge.build_attachment_context = lambda _rc, _content: ""
            bridge.typing_status = lambda *_args, **_kwargs: None
            bridge.find_session_by_marker = lambda _marker: None
            bridge.clean_session_record = lambda *_args, **_kwargs: None
            bridge.set_session_archived = lambda *_args, **_kwargs: None
            answer, session_id = bridge.hermes_reply(rc, message, None)
        finally:
            bridge.HERMES = originals["HERMES"]
            bridge.HERMES_EXTRA_ARGS = originals["HERMES_EXTRA_ARGS"]
            bridge.subprocess.Popen = originals["Popen"]
            bridge.topic_history = originals["topic_history"]
            bridge.build_attachment_context = originals["build_attachment_context"]
            bridge.typing_status = originals["typing_status"]
            bridge.find_session_by_marker = originals["find_session_by_marker"]
            bridge.clean_session_record = originals["clean_session_record"]
            bridge.set_session_archived = originals["set_session_archived"]

        self.assertEqual(answer, "pong")
        self.assertIsNone(session_id)
        self.assertEqual(captured["cmd"][:4], ["/opt/hermes/bin/hermes", "--profile", "hermes", "-z"])
        prompt = captured["cmd"][4]
        self.assertIn("Only act on records with conversation_key", prompt)
        self.assertIn("active_message_id 999", prompt)
        self.assertIn("stop that wait immediately", prompt)


if __name__ == "__main__":
    unittest.main()
