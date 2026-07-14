from __future__ import annotations

import json
import http.server
import io
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


from hermes_zulip_bridge import bridge, cli


def zulip_success(**payload: object) -> dict:
    return {"result": "success", "msg": "", **payload}


def narrow_match(content: str = "", subject: str = "Topic") -> dict[str, str]:
    return {"match_content": content, "match_subject": subject}


BOT_KEY = "generic-fixture-bot-key"
SIGNING_KEY = b"generic-fixture-state-key-000001"


def bot_message(message_id: int, stream_id: int, topic: str, *, stream: str = "hermes", content: str = "answer") -> dict:
    return {
        "id": message_id,
        "type": "stream",
        "stream_id": stream_id,
        "display_recipient": stream,
        "topic": topic,
        "sender_email": "bot@example.com",
        "sender_id": 99,
        "sender_is_bot": True,
        "content": content,
    }


def user_message(
    message_id: int,
    stream_id: int,
    topic: str,
    *,
    stream: str | None = None,
    content: str = "hello",
) -> dict:
    return {
        "id": message_id,
        "type": "stream",
        "stream_id": stream_id,
        "display_recipient": stream or f"stream-{stream_id}",
        "topic": topic,
        "sender_id": 17,
        "sender_email": "user@example.com",
        "sender_full_name": "Test User",
        "sender_is_bot": False,
        "content": content,
    }


class SequenceZulipClient:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def call_endpoint(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.responses.pop(0)


class ZulipAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        routes = mock.patch.multiple(
            bridge,
            ALLOW_STREAMS=set(),
            ALLOW_STREAM_IDS={str(value) for value in range(1, 1001)},
            ALLOW_TOPICS=set(),
            TOPIC_POLICY="any",
            ALLOWED_SENDERS={"id:17"},
            PRIVILEGED_SENDERS=set(),
            PRIVILEGED_SLASH_COMMANDS=set(),
            REQUIRE_MENTION=False,
            HERMES_EXTRA_ARGS=["--toolsets", "coding"],
        )
        routes.start()
        self.addCleanup(routes.stop)
        self.state_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_dir.cleanup)
        state_path = mock.patch.object(bridge, "STATE_PATH", Path(self.state_dir.name) / "state.json")
        state_path.start()
        self.addCleanup(state_path.stop)
        bridge.SHUTTING_DOWN = False
        bridge.ACTIVE_INTERRUPTS.clear()
        self.venv = Path(self.state_dir.name) / "venv"
        (self.venv / "bin").mkdir(parents=True, mode=0o700)
        python_home = Path(sys.executable).resolve().parent
        (self.venv / "pyvenv.cfg").write_text(f"home = {python_home}\n", encoding="utf-8")
        (self.venv / "pyvenv.cfg").chmod(0o600)
        self.venv_python = self.venv / "bin" / "python"
        self.venv_python.symlink_to(Path(sys.executable).resolve())

    def python_console_script(self, body: str) -> Path:
        path = Path(self.state_dir.name) / f"hermes-{time.time_ns()}.py"
        path.write_text(f"#!{self.venv_python}\n{body}\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def launcher_proof(self, body: str = "raise SystemExit(0)") -> bridge.LauncherProof:
        return bridge._python_console_script(str(self.python_console_script(body)))

    def admitted_message(self, message: dict) -> tuple[dict, dict]:
        state: dict = {}
        bridge._admit_origin(state, message["id"], now=1.0)
        message.update(_zulip_state=state, _zulip_persist=lambda: None)
        return message, state

    def seed_topic(self, state: dict, *, message_id: int, stream_id: int, topic: str, session_id: str) -> dict:
        message = {
            "id": message_id,
            "type": "stream",
            "stream_id": stream_id,
            "display_recipient": f"stream-{stream_id}",
            "topic": topic,
        }
        _session_id, conversation = bridge.resolve_session(message, {}, state, "example")
        bridge.note_bridge_thread(state, conversation, session_id=session_id)
        bridge.note_topic_session(state, conversation, session_id)
        return conversation

    def first_turn_reply(self) -> tuple[dict, dict, dict]:
        state: dict = {"topic_sessions": {}}
        message = user_message(44, 1, "Before")
        session_id, conversation = bridge.resolve_session(message, {}, state, "example")
        self.assertIsNone(session_id)
        self.assertEqual(state["zulip_threads"][conversation["thread_id"]]["session_id"], "")
        conversation["session_id"] = "new-session"
        message.update(
            _zulip_state=state,
            _zulip_bridge=conversation,
            _zulip_signing_key=SIGNING_KEY,
            _zulip_generation_route={
                "realm": "example",
                "thread_id": conversation["thread_id"],
                "session_id": "",
                "stream_id": 1,
                "topic": "Before",
                "native_id": "",
                "sender_id": 17,
                "sender_email": "user@example.com",
                "sender_is_bot": False,
            },
        )
        return state, message, conversation

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
            with tempfile.TemporaryDirectory() as tmpdir:
                context = bridge.build_attachment_context(
                    rc,
                    "[note](/user_uploads/1/ab/note.md) "
                    "![screen](/user_uploads/1/ab/screen.png) "
                    "/user_uploads/1/ab/missing.txt",
                    Path(tmpdir),
                )
                materialized = {path.name: path.read_bytes() for path in Path(tmpdir).iterdir()}
        finally:
            bridge.fetch_zulip_attachment = original_fetch
            bridge.ATTACHMENT_MAX_CHARS = original_max_chars
            bridge.ATTACHMENT_TOTAL_CHARS = original_total_chars
            bridge.ATTACHMENT_MAX_FILES = original_max_files

        self.assertIn("----- BEGIN ZULIP ATTACHMENT: note.md -----", context)
        self.assertIn("Private Zulip uploads were downloaded by the bridge.", context)
        self.assertNotIn("Source URL", context)
        self.assertNotIn("HTTP Basic auth", context)
        self.assertNotIn(str(bridge.RC_PATH), context)
        self.assertIn("abcd", context)
        self.assertIn("[Truncated: read limit", context)
        self.assertIn("[Truncated: per-file character limit", context)
        self.assertIn("Image local path:", context)
        self.assertEqual(materialized, {"2-screen.png": b"\x89PNG"})
        self.assertIn("Fetch error: HTTP 404 Not Found.", context)

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
            with tempfile.TemporaryDirectory() as tmpdir:
                context = bridge.build_attachment_context(
                    rc,
                    "[archive](/user_uploads/1/ab/archive.zip)",
                    Path(tmpdir),
                )
                materialized = {path.name: path.read_bytes() for path in Path(tmpdir).iterdir()}
        finally:
            bridge.fetch_zulip_attachment = original_fetch

        self.assertNotIn("Source URL", context)
        self.assertIn("Binary attachment local path:", context)
        self.assertEqual(materialized, {"1-archive.zip": b"PK"})

    def test_api_uses_official_zulip_client_facade(self) -> None:
        calls: list[dict[str, object]] = []
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_cache = dict(bridge.ZULIP_CLIENT_CACHE)

        class FakeClient:
            def call_endpoint(self, **kwargs: object) -> dict:
                calls.append(kwargs)
                return {"result": "success", "msg": "", "messages": []}

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

    def test_matches_narrow_request_is_json_encoded_for_official_client(self) -> None:
        calls: list[dict[str, object]] = []
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_cache = dict(bridge.ZULIP_CLIENT_CACHE)

        class FakeClient:
            def call_endpoint(self, **kwargs: object) -> dict:
                calls.append(kwargs)
                return {"result": "success", "msg": "", "messages": {}}

        try:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE[("https://zulip.example.com", "bot@example.com", "test-api-key")] = FakeClient()
            bridge.api(
                rc,
                "GET",
                "/api/v1/messages/matches_narrow",
                params={
                    "msg_ids": [1, 2],
                    "narrow": [
                        {"operator": "channel", "operand": 616350},
                        {"operator": "topic", "operand": "Initial setup"},
                    ],
                },
            )
        finally:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE.update(original_cache)

        request = calls[0]["request"]
        self.assertEqual(
            request,
            {
                "msg_ids": "[1, 2]",
                "narrow": '[{"operator": "channel", "operand": 616350}, {"operator": "topic", "operand": "Initial setup"}]',
            },
        )

    def test_official_client_disables_transport_retries_for_inline_and_zuliprc_credentials(self) -> None:
        constructed: list[dict[str, object]] = []
        clients: list[Client] = []

        class Client:
            def __init__(self, **kwargs: object) -> None:
                constructed.append(dict(kwargs))
                self.retry_on_errors = kwargs.get("retry_on_errors")
                self.calls: list[dict[str, object]] = []
                self.session = mock.Mock(hooks={})
                clients.append(self)

            def ensure_session(self) -> None:
                pass

            def call_endpoint(self, **kwargs: object) -> dict:
                self.calls.append(dict(kwargs))
                return {"result": "error", "msg": "unavailable", "status_code": 503}

        def assert_one_call_per_method(rc: dict[str, str], client: object) -> None:
            calls = client._client.calls
            for method in ("GET", "POST", "PATCH"):
                before = len(calls)
                with self.assertRaises(RuntimeError):
                    bridge.api(rc, method, "/api/v1/messages", data={})
                self.assertEqual(len(calls), before + 1)

        module = mock.Mock(Client=Client)
        inline = {
            "HERMES_ZULIP_SITE": "https://zulip.example.com",
            "HERMES_ZULIP_EMAIL": "bot@example.com",
            "HERMES_ZULIP_API_KEY": "test-api-key",
        }
        with mock.patch.dict(os.environ, inline, clear=True), mock.patch.dict(
            sys.modules, {"zulip": module}
        ), mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {}, clear=True):
            rc = bridge.load_rc()
            client = bridge.zulip_client(rc)
            assert_one_call_per_method(rc, client)
            self.assertIs(bridge.zulip_client(rc), client)
        self.assertFalse(client.retry_on_errors)

        rc_path = Path(self.state_dir.name) / "zuliprc"
        rc_path.write_text(
            "[api]\nemail=bot@example.com\nkey=test-api-key\nsite=https://zulip.example.com\n",
            encoding="utf-8",
        )
        rc_path.chmod(0o600)
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            bridge, "RC_PATH", rc_path
        ), mock.patch.dict(sys.modules, {"zulip": module}), mock.patch.dict(
            bridge.ZULIP_CLIENT_CACHE, {}, clear=True
        ):
            rc = bridge.load_rc()
            client = bridge.zulip_client(rc)
            assert_one_call_per_method(rc, client)
            self.assertIs(bridge.zulip_client(rc), client)
        self.assertFalse(client.retry_on_errors)
        self.assertEqual(len(constructed), 2)
        self.assertEqual([len(client.calls) for client in clients], [3, 3])
        for kwargs in constructed:
            self.assertIs(kwargs["retry_on_errors"], False)
            self.assertEqual(kwargs["client"], "Hermes-Zulip-Bridge")

    def test_official_client_real_http_status_is_thread_local_and_classified(self) -> None:
        try:
            import requests
            import zulip
        except ImportError:
            self.skipTest("official Zulip client is unavailable")

        barrier = threading.Barrier(2)
        calls: list[int] = []

        class Adapter(requests.adapters.BaseAdapter):
            def send(self, request, **_kwargs):
                status = int(request.url.rsplit("/", 1)[-1])
                calls.append(status)
                barrier.wait(timeout=2)
                response = requests.Response()
                response.status_code = status
                response.url = request.url
                response.request = request
                response.headers["Content-Type"] = "application/json"
                response._content = json.dumps(
                    {"result": "error", "code": "BAD_REQUEST", "msg": "private server detail"}
                ).encode()
                return response

            def close(self) -> None:
                pass

        rc = {
            "site": "https://zulip.example.com",
            "email": "bot@example.com",
            "key": "test-api-key",
        }
        with mock.patch.object(
            zulip.Client,
            "get_server_settings",
            return_value={"zulip_version": "test", "zulip_feature_level": 1},
        ), mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {}, clear=True):
            client = bridge.zulip_client(rc)
            client._client.session.mount("https://", Adapter())

            def request(status: int) -> bridge.ZulipResponseError:
                try:
                    bridge.api(rc, "POST", f"/api/v1/messages/{status}", data={"content": "private"})
                except RuntimeError as exc:
                    return next(
                        item
                        for item in bridge._exception_chain(exc)
                        if isinstance(item, bridge.ZulipResponseError)
                    )
                raise AssertionError("request unexpectedly succeeded")

            with bridge.concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = dict(zip((400, 503), pool.map(request, (400, 503))))

        self.assertEqual(sorted(calls), [400, 503])
        self.assertEqual(results[400].status_code, 400)
        self.assertFalse(results[400].retryable)
        self.assertFalse(results[400].uncertain)
        self.assertEqual(results[503].status_code, 503)
        self.assertTrue(results[503].retryable)
        self.assertTrue(results[503].uncertain)
        self.assertNotIn("private server detail", str(results))

    def test_official_status_holder_resets_when_a_request_has_no_status(self) -> None:
        barrier = threading.Barrier(2)

        class Client:
            retry_on_errors = False

            def __init__(self) -> None:
                self.session = mock.Mock(hooks={})

            def ensure_session(self) -> None:
                pass

            def call_endpoint(self, **kwargs: object) -> dict:
                status = kwargs.get("status")
                if status is not None:
                    barrier.wait(timeout=2)
                    response = mock.Mock(status_code=status)
                    for hook in self.session.hooks["response"]:
                        hook(response)
                    barrier.wait(timeout=2)
                return {"result": "error", "code": "BAD_REQUEST", "msg": "private detail"}

        client = bridge._OfficialZulipClient(Client())
        with bridge.concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda status: client.call_endpoint(status=status), (400, 503)))
        self.assertEqual([result["status_code"] for result in results], [400, 503])
        self.assertNotIn("status_code", client.call_endpoint())

    def test_official_client_fails_if_retry_control_is_rejected_or_ignored(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}

        class UnsupportedClient:
            def __init__(self, email: str, api_key: str, site: str, client: str) -> None:
                pass

        class IgnoringClient:
            def __init__(self, **_kwargs: object) -> None:
                self.retry_on_errors = True

        class SilentClient:
            def __init__(self, **_kwargs: object) -> None:
                pass

        class MissingClient:
            __slots__ = ()

            def __init__(self, **_kwargs: object) -> None:
                pass

        class RaisingClient:
            def __init__(self, **_kwargs: object) -> None:
                pass

            @property
            def retry_on_errors(self) -> bool:
                raise OSError("property unavailable")

        class AmbiguousClient:
            def __init__(self, **_kwargs: object) -> None:
                self.retry_on_errors = 0

        for client_class, error in (
            (UnsupportedClient, "0.9.1-compatible semantics"),
            (IgnoringClient, "did not honor retry_on_errors=False"),
            (SilentClient, "cannot verify retry_on_errors=False"),
            (MissingClient, "cannot verify retry_on_errors=False"),
            (RaisingClient, "cannot verify retry_on_errors=False"),
            (AmbiguousClient, "did not honor retry_on_errors=False"),
        ):
            with self.subTest(client=client_class.__name__), mock.patch.dict(
                sys.modules, {"zulip": mock.Mock(Client=client_class)}
            ), mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {}, clear=True), self.assertRaisesRegex(
                RuntimeError, error
            ):
                bridge.zulip_client(rc)
            self.assertEqual(bridge.ZULIP_CLIENT_CACHE, {})

    def test_api_surfaces_zulip_library_error_payloads(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        original_cache = dict(bridge.ZULIP_CLIENT_CACHE)

        class FakeClient:
            def call_endpoint(self, **_kwargs: object) -> dict:
                return {"result": "error", "code": "BAD_REQUEST", "msg": "nope"}

        try:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE[("https://zulip.example.com", "bot@example.com", "test-api-key")] = FakeClient()
            with self.assertRaisesRegex(RuntimeError, "invalid response") as raised:
                bridge.api(rc, "POST", "/api/v1/messages", data={"content": "hello"})
            self.assertTrue(bridge.post_may_have_committed(raised.exception))
        finally:
            bridge.ZULIP_CLIENT_CACHE.clear()
            bridge.ZULIP_CLIENT_CACHE.update(original_cache)

    def test_zulip_envelope_rejects_missing_nonempty_and_nondict_fields(self) -> None:
        malformed = [
            None,
            [],
            {},
            {"result": "success"},
            {"result": "success", "msg": None},
            {"result": "success", "msg": "unexpected"},
        ]
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaisesRegex(RuntimeError, "invalid response"):
                bridge._check_zulip_result("GET", "/api/v1/messages", payload, safe_read=True)

    def test_official_http_error_envelopes_preserve_status_and_read_retryability(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        for status_code, retryable in ((503, True), (429, True), (408, True), (425, True), (400, False), (401, False), (404, False)):
            client = SequenceZulipClient(
                [{"result": "error", "msg": "request failed", "code": "HTTP_ERROR", "status_code": status_code}]
            )
            with self.subTest(status_code=status_code), mock.patch.dict(
                bridge.ZULIP_CLIENT_CACHE,
                {(rc["site"], rc["email"], rc["key"]): client},
                clear=True,
            ), self.assertRaises(RuntimeError) as raised:
                bridge.api(rc, "GET", "/api/v1/messages")
            response = next(
                item for item in bridge._exception_chain(raised.exception) if isinstance(item, bridge.ZulipResponseError)
            )
            self.assertEqual(response.status_code, status_code)
            self.assertEqual(bridge.retryable_zulip_failure(raised.exception), retryable)

    def test_malformed_reads_retry_but_malformed_or_transient_writes_stay_uncertain(self) -> None:
        for payload in (None, {}, {"result": "maybe", "msg": ""}):
            with self.subTest(payload=payload), self.assertRaises(bridge.ZulipResponseError) as raised:
                bridge._check_zulip_result("GET", "/api/v1/messages", payload, safe_read=True)
            self.assertTrue(raised.exception.retryable)
            self.assertFalse(raised.exception.uncertain)

        for status_code in (None, "503", 200):
            payload = {"result": "error", "msg": "untrusted", "code": "HTTP_ERROR"}
            if status_code is not None:
                payload["status_code"] = status_code
            with self.subTest(status_code=status_code), self.assertRaises(bridge.ZulipResponseError) as raised:
                bridge._check_zulip_result("GET", "/api/v1/messages", payload, safe_read=True)
            self.assertTrue(raised.exception.retryable)

        for payload in (
            {},
            {"result": "error", "msg": "unavailable", "code": "HTTP_ERROR", "status_code": 503},
        ):
            with self.subTest(payload=payload), self.assertRaises(bridge.ZulipResponseError) as raised:
                bridge._check_zulip_result("POST", "/api/v1/messages", payload, safe_read=False)
            self.assertTrue(raised.exception.uncertain)
            self.assertTrue(bridge.post_may_have_committed(raised.exception))

        with self.assertRaises(bridge.ZulipResponseError) as permanent:
            bridge._check_zulip_result(
                "POST",
                "/api/v1/messages",
                {"result": "error", "msg": "forbidden", "code": "HTTP_ERROR", "status_code": 400},
                safe_read=False,
            )
        self.assertFalse(permanent.exception.retryable)
        self.assertFalse(bridge.post_may_have_committed(permanent.exception))

    def test_official_transient_write_is_called_once_and_exception_remains_uncertain(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        client = SequenceZulipClient(
            [{"result": "error", "msg": "unavailable", "code": "HTTP_ERROR", "status_code": 503}]
        )
        with mock.patch.dict(
            bridge.ZULIP_CLIENT_CACHE,
            {(rc["site"], rc["email"], rc["key"]): client},
            clear=True,
        ), self.assertRaises(RuntimeError) as raised:
            bridge.api(rc, "POST", "/api/v1/messages", data={"content": "answer"})
        self.assertEqual(len(client.calls), 1)
        self.assertTrue(bridge.post_may_have_committed(raised.exception))

    def test_official_transport_envelopes_make_exactly_one_call_per_bridge_attempt(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        envelopes = [
            {"result": "error", "msg": "unavailable", "code": "HTTP_ERROR", "status_code": 503},
            {"result": "http-error", "msg": "Unexpected error from the server", "status_code": 503},
            {"result": "error", "msg": "status unavailable", "code": "BAD_REQUEST"},
        ]
        for method in ("GET", "POST", "PATCH"):
            client = SequenceZulipClient(envelopes)
            with self.subTest(method=method), mock.patch.dict(
                bridge.ZULIP_CLIENT_CACHE,
                {(rc["site"], rc["email"], rc["key"]): client},
                clear=True,
            ):
                for _envelope in envelopes:
                    with self.assertRaises(RuntimeError) as raised:
                        bridge.api(rc, method, "/api/v1/messages", params={} if method == "GET" else None, data={})
                    if method == "GET":
                        self.assertTrue(bridge.retryable_zulip_failure(raised.exception))
                        self.assertFalse(bridge.post_may_have_committed(raised.exception))
                    else:
                        self.assertTrue(bridge.post_may_have_committed(raised.exception))
            self.assertEqual(len(client.calls), len(envelopes))
            self.assertEqual([call["method"] for call in client.calls], [method] * len(envelopes))

    def test_json_and_alias_manifest_loaders_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            missing = root / "missing.json"
            self.assertEqual(bridge.load_json(missing, {"default": True}), {"default": True})

            malformed = root / "state.json"
            original = b'{"seen_ids": [1]'
            malformed.write_bytes(original)
            with self.assertRaises(json.JSONDecodeError):
                bridge.load_json(malformed, {})
            self.assertEqual(malformed.read_bytes(), original)

            with mock.patch.object(Path, "open", side_effect=PermissionError("denied")), self.assertRaises(
                PermissionError
            ):
                bridge.load_json(malformed, {})

            manifest = root / "aliases.json"
            invalid = [[], {}, {"aliases": {}}, {"aliases": [None]}, {"aliases": [{}]}]
            for payload in invalid:
                manifest.write_text(json.dumps(payload), encoding="utf-8")
                manifest.chmod(0o600)
                with self.subTest(payload=payload), mock.patch.object(bridge, "ALIASES_PATH", manifest), self.assertRaises(
                    ValueError
                ):
                    bridge.load_alias_entries()

            with mock.patch.object(bridge, "ALIASES_PATH", root / "absent.json"):
                self.assertEqual(bridge.load_alias_entries(), [])

    def test_non_object_state_and_corrupt_manifest_stop_startup_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            manifest_path = Path(tmpdir) / "aliases.json"
            api = mock.Mock()
            worker = mock.Mock()
            save = mock.Mock()
            common = (
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://zulip.example.com", "email": "bot@example.com", "key": "secret"},
                ),
                mock.patch.object(bridge, "STATE_PATH", state_path),
                mock.patch.object(bridge, "ALIASES_PATH", manifest_path),
                mock.patch.object(bridge, "latest_messages", api),
                mock.patch.object(bridge, "handle_message", worker),
                mock.patch.object(bridge, "save_json", save),
            )

            state_path.write_text("[]", encoding="utf-8")
            with common[0], common[1], common[2], common[3], common[4], common[5], self.assertRaisesRegex(
                ValueError, "state root"
            ):
                bridge._main()
            self.assertEqual(state_path.read_text(encoding="utf-8"), "[]")

            state_path.unlink()
            original_manifest = b'{"aliases": ['
            manifest_path.write_bytes(original_manifest)
            manifest_path.chmod(0o600)
            with common[0], common[1], common[2], common[3], common[4], common[5], self.assertRaises(
                json.JSONDecodeError
            ):
                bridge._main()
            self.assertEqual(manifest_path.read_bytes(), original_manifest)
            api.assert_not_called()
            worker.assert_not_called()
            save.assert_not_called()

    def test_malformed_current_origin_envelope_blocks_send_and_mutation(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        client = SequenceZulipClient([{"result": "success", "message": {"id": 44}}])
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Before",
            "_zulip_bridge": {"realm": "zulip.example.com", "topic_aliases": ["Before"]},
        }
        before = json.loads(json.dumps(message))
        cache_key = (rc["site"], rc["email"], rc["key"])

        with mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {cache_key: client}, clear=True), self.assertRaises(
            bridge.ReplyRoutingError
        ):
            bridge.reply(rc, message, "answer")

        self.assertEqual(message, before)
        self.assertEqual([call["method"] for call in client.calls], ["GET"])

    def test_malformed_send_envelope_blocks_route_mutation(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        origin = {"id": 44, "type": "stream", "stream_id": 2, "display_recipient": "ops", "topic": "Moved"}
        client = SequenceZulipClient([zulip_success(message=origin), {"result": "success", "id": 900}])
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Before",
            "_zulip_bridge": {"realm": "zulip.example.com", "topic_aliases": ["Before"]},
        }
        before = json.loads(json.dumps(message))
        cache_key = (rc["site"], rc["email"], rc["key"])

        with mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {cache_key: client}, clear=True), self.assertRaises(
            bridge.ReplyPostUncertain
        ):
            bridge.reply(rc, message, "answer")

        self.assertEqual(message, before)
        self.assertEqual([call["method"] for call in client.calls], ["GET", "POST"])

    def test_unknown_answer_post_envelopes_are_seen_without_retry_or_reconciliation(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        origin = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        cache_key = (rc["site"], rc["email"], rc["key"])

        for malformed in (
            {},
            {"result": "maybe", "msg": "not a Zulip error"},
            {"result": "error", "msg": "unavailable", "code": "HTTP_ERROR", "status_code": 503},
            {"result": "http-error", "msg": "Unexpected error from the server", "status_code": 503},
            {"result": "error", "msg": "status unavailable", "code": "BAD_REQUEST"},
        ):
            with self.subTest(malformed=malformed):
                state = {"seen_ids": [], "topic_sessions": {}}
                message = dict(origin)
                client = SequenceZulipClient([zulip_success(message=origin), malformed])
                hermes = mock.Mock(return_value=("answer", "s1"))
                reconcile = mock.Mock()
                errors: list[BaseException] = []
                handled = threading.Event()
                sleeps = 0
                original_handle_message = bridge.handle_message

                def capture_handle_message(*args: object) -> str | None:
                    try:
                        return original_handle_message(*args)
                    except BaseException as exc:
                        errors.append(exc)
                        raise
                    finally:
                        handled.set()

                def resolve(current: dict, *_args: object, **_kwargs: object) -> tuple[None, dict]:
                    return None, {
                        "conversation_key": "zulip:example:1:thread",
                        "thread_id": "thread",
                        "realm": "zulip.example.com",
                        "stream": "hermes",
                        "stream_id": "1",
                        "topic": "Topic",
                        "topic_aliases": ["Topic"],
                        "message_id": "44",
                        "session_id": "",
                    }

                def stop_after_seen(_seconds: float) -> None:
                    nonlocal sleeps
                    sleeps += 1
                    if sleeps == 1:
                        self.assertTrue(handled.wait(2))
                        return
                    raise StopIteration

                with (
                    mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {cache_key: client}, clear=True),
                    mock.patch.object(bridge, "load_json", return_value=state),
                    mock.patch.object(bridge, "load_rc", return_value=rc),
                    mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                    mock.patch.object(bridge, "latest_messages", return_value=[message]),
                    mock.patch.object(bridge, "resolve_session", side_effect=resolve) as resolve_mock,
                    mock.patch.object(bridge, "handle_message", side_effect=capture_handle_message),
                    mock.patch.object(bridge, "hermes_slash_reply", return_value=None),
                    mock.patch.object(bridge, "hermes_reply", hermes),
                    mock.patch.object(bridge, "add_reaction"),
                    mock.patch.object(bridge, "remove_reaction"),
                    mock.patch.object(bridge, "_reconcile_reply_job", reconcile),
                    mock.patch.object(bridge, "save_json"),
                    mock.patch.object(bridge.time, "sleep", side_effect=stop_after_seen),
                    self.assertRaises(StopIteration),
                ):
                    bridge._main()

                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], bridge.ReplyPostUncertain)
                self.assertEqual([call["method"] for call in client.calls], ["GET", "POST"])
                hermes.assert_called_once()
                resolve_mock.assert_called_once()
                reconcile.assert_not_called()
                self.assertEqual(state["seen_ids"], [44])
                self.assertEqual(state["dead_letters"][0]["origin_message_id"], 44)
                self.assertIn("uncertain_post", state["dead_letters"][0]["reason"])

    def test_malformed_patch_envelope_does_not_publish_unconfirmed_route(self) -> None:
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        first = {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Before"}
        moved = {"id": 44, "type": "stream", "stream_id": 2, "display_recipient": "ops", "topic": "After"}
        client = SequenceZulipClient(
            [
                zulip_success(message=first),
                zulip_success(id=900),
                zulip_success(message=moved),
                zulip_success(message=bot_message(900, 1, "Before")),
                {"result": "success"},
            ]
        )
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Before",
            "_zulip_bridge": {"realm": "zulip.example.com", "topic_aliases": ["Before"]},
        }
        cache_key = (rc["site"], rc["email"], rc["key"])

        with mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {cache_key: client}, clear=True):
            bridge.reply(rc, message, "answer")

        self.assertEqual(message["stream_id"], 1)
        self.assertEqual(message["topic"], "Before")
        self.assertEqual(message["_zulip_bridge"]["topic_aliases"], ["Before"])
        self.assertEqual([call["method"] for call in client.calls], ["GET", "POST", "GET"])

    def test_strict_positive_int_accepts_only_positive_ints_and_canonical_digits(self) -> None:
        self.assertEqual(bridge.strict_positive_int(1), 1)
        self.assertEqual(bridge.strict_positive_int("987654321"), 987654321)
        maximum = int("9" * 64)
        self.assertEqual(bridge.strict_positive_int(maximum), maximum)
        self.assertEqual(bridge.strict_positive_int("9" * 64), maximum)
        self.assertIsNone(bridge.strict_positive_int(10**64))
        self.assertIsNone(bridge.strict_positive_int("1" + "0" * 64))
        self.assertIsNone(bridge.strict_positive_int(10**10000))
        for value in (
            True,
            False,
            0,
            -1,
            1.0,
            1.5,
            float("inf"),
            float("-inf"),
            float("nan"),
            [],
            {},
            (),
            {1},
            None,
            "",
            "0",
            "-1",
            "+1",
            "01",
            "1.0",
            " 1",
            "one",
            "١",
        ):
            with self.subTest(value=value):
                self.assertIsNone(bridge.strict_positive_int(value))

    def test_process_lock_rejects_second_bridge_process_and_releases_on_exit(self) -> None:
        holder_code = """
import sys
from pathlib import Path
from hermes_zulip_bridge import bridge

with bridge.process_lock(Path(sys.argv[1])):
    print("locked", flush=True)
    sys.stdin.read(1)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "shared-state.json"
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
            holder = subprocess.Popen(
                [sys.executable, "-c", holder_code, str(state_path)],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(holder.stdout.readline(), "locked\n")
                with self.assertRaisesRegex(bridge.ProcessLockError, re.escape(bridge.PROCESS_LOCK_UNAVAILABLE)):
                    with bridge.process_lock(state_path):
                        self.fail("second bridge acquired the process lock")
                self.assertEqual(stat.S_IMODE(bridge.process_lock_path(state_path).stat().st_mode), 0o600)
            finally:
                _stdout, stderr = holder.communicate(input="\n", timeout=5)
                holder.stdin.close()
                holder.stdout.close()
                holder.stderr.close()
            self.assertEqual(holder.returncode, 0, stderr)
            with bridge.process_lock(state_path):
                pass

    def test_bridge_main_fails_clearly_before_startup_when_lock_is_held(self) -> None:
        proof = self.launcher_proof()
        with (
            mock.patch.object(bridge, "process_lock", side_effect=bridge.ProcessLockError),
            mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}) as load_rc,
            self.assertRaisesRegex(SystemExit, re.escape(bridge.PROCESS_LOCK_UNAVAILABLE)),
        ):
            bridge.main(launcher_proof=proof)

        load_rc.assert_called_once_with()

    def test_bridge_main_uses_cli_held_lock_without_reacquiring(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(bridge, "STATE_PATH", Path(tmpdir) / "state"):
            with bridge.process_lock() as held_lock, mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}) as load_rc, mock.patch.object(bridge, "process_lock") as acquire, mock.patch.object(
                bridge, "_main", return_value=7
            ), mock.patch.object(bridge, "refresh_zulip_bot_identity") as refresh, mock.patch.object(
                bridge, "REQUIRE_MENTION", True
            ):
                self.assertEqual(bridge.main(lock=held_lock), 7)

            acquire.assert_not_called()
            refresh.assert_called_once_with(load_rc.return_value)

    def test_bridge_main_restores_startup_signal_handlers_and_releases_lock(self) -> None:
        for shutdown_signal in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=shutdown_signal), tempfile.TemporaryDirectory() as tmpdir:
                state_path = Path(tmpdir) / "state.json"
                original_sigterm = signal.getsignal(signal.SIGTERM)
                original_sigint = signal.getsignal(signal.SIGINT)
                worker = mock.Mock()

                def interrupt(_rc: dict[str, str]) -> None:
                    signal.raise_signal(shutdown_signal)

                with mock.patch.multiple(
                    bridge,
                    STATE_PATH=state_path,
                    REQUIRE_MENTION=True,
                    load_rc=lambda: {"site": "https://example", "email": "bot@example.com", "key": "key"},
                    freeze_auxiliary_paths=lambda _path: None,
                    refresh_zulip_bot_identity=interrupt,
                    _main=worker,
                ):
                    self.assertEqual(bridge.main(launcher_proof=mock.sentinel.launcher), 0)

                self.assertIs(signal.getsignal(signal.SIGTERM), original_sigterm)
                self.assertIs(signal.getsignal(signal.SIGINT), original_sigint)
                worker.assert_not_called()
                with bridge.process_lock(state_path):
                    pass

    def test_bridge_main_uses_handed_off_lock_canonical_state_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with bridge.process_lock(Path(tmpdir) / "other-state") as wrong_lock, mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}), mock.patch.object(
                bridge, "_main", return_value=0
            ) as run:
                self.assertEqual(bridge.main(lock=wrong_lock), 0)
        run.assert_called_once_with(wrong_lock.state_path, rc={"site": "https://example", "email": "bot@example.com", "key": "key"})

    def test_huge_integer_and_string_message_ids_fail_closed_and_anchors_stay_bounded(self) -> None:
        too_large = 10**64
        api = mock.Mock()
        for message_id in (too_large, str(too_large)):
            with self.subTest(kind=type(message_id).__name__), mock.patch.object(bridge, "api", api), self.assertRaises(
                bridge.ReplyRoutingError
            ):
                bridge.resolve_session(
                    {"id": message_id, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "New"},
                    {},
                    {"topic_sessions": {}},
                    "example",
                    {"site": "https://zulip.example.com"},
                )
        api.assert_not_called()

        state = {
            "topic_sessions": {},
            "zulip_topic_aliases": {},
            "zulip_threads": {
                "valid": {"realm": "example", "stream_id": "1", "session_id": "s1", "last_seen_message_id": 7},
                "huge-int": {"realm": "example", "stream_id": "1", "session_id": "s2", "last_seen_message_id": 10**10000},
                "huge-string": {"realm": "example", "stream_id": "1", "session_id": "s3", "last_seen_message_id": str(too_large)},
            },
        }
        batches: list[list[int]] = []

        def fake_api(_rc: dict, _method: str, _path: str, **kwargs: object) -> dict:
            batches.append(list((kwargs.get("params") or {}).get("msg_ids") or []))
            return {"result": "success", "msg": "", "messages": {}}

        with mock.patch.object(bridge, "api", fake_api), self.assertRaisesRegex(ValueError, "last_seen_message_id"):
            bridge.resolve_session(
                {"id": 8, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "New"},
                {},
                state,
                "example",
                {"site": "https://zulip.example.com"},
            )

        self.assertEqual(batches, [])

    def test_latest_messages_rejects_page_with_any_invalid_id(self) -> None:
        invalid = [True, 0, -1, 1.0, 1.5, float("inf"), float("nan"), [], {}, "nope"]
        payload_messages = [
            {"id": value, "stream_id": 1, "type": "stream", "topic": "T"}
            for value in invalid
        ]
        payload_messages.extend(
            [
                {"id": 2, "stream_id": "1", "type": "stream", "topic": "T"},
                {"id": "1", "stream_id": 1, "type": "stream", "topic": "T"},
                {"id": 3, "stream_id": False, "type": "stream", "topic": "T"},
            ]
        )

        with mock.patch.object(bridge, "api", return_value={"messages": payload_messages}), self.assertRaises(
            bridge.ZulipResponseError
        ):
            bridge.latest_messages({"site": "https://zulip.example.com"})

    def test_latest_messages_rejects_digit_limit_id_and_valid_neighbor_together(self) -> None:
        payload = {
            "messages": [
                {"id": "9" * 5000, "stream_id": 1, "type": "stream", "topic": "T"},
                {"id": "7", "stream_id": "3", "type": "stream", "topic": "T"},
            ]
        }

        with mock.patch.object(bridge, "api", return_value=payload), self.assertRaises(bridge.ZulipResponseError):
            bridge.latest_messages({"site": "https://zulip.example.com"})

    def test_invalid_message_or_stream_ids_stop_before_hermes_or_outward_calls(self) -> None:
        invalid = [True, 0, -1, 1.0, 1.5, float("inf"), float("nan"), [], {}, "nope"]
        for field in ("id", "stream_id"):
            for value in invalid:
                api = mock.Mock()
                hermes_reply = mock.Mock()
                message = {"id": 1, "stream_id": 1, "type": "stream", "topic": "T", "content": "hello"}
                message[field] = value
                with (
                    self.subTest(field=field, value=value),
                    mock.patch.object(bridge, "api", api),
                    mock.patch.object(bridge, "hermes_reply", hermes_reply),
                    self.assertRaises(bridge.ReplyRoutingError),
                ):
                    bridge.handle_message({"site": "https://zulip.example.com"}, message, None)
                api.assert_not_called()
                hermes_reply.assert_not_called()

    def test_invalid_ids_do_not_cross_fetch_or_reaction_boundaries(self) -> None:
        for value in (True, 0, -1, 1.0, 1.5, float("inf"), float("nan"), [], {}, "nope"):
            api = mock.Mock()
            with self.subTest(value=value), mock.patch.object(bridge, "api", api):
                with self.assertRaises(bridge.ReplyRoutingError):
                    bridge.live_origin_message({}, {"id": value})
                bridge.add_reaction({}, {"id": value}, "eyes")
                bridge.remove_reaction({}, {"id": value}, "eyes")
            api.assert_not_called()

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
                lines = bridge.active_steering_path(111).read_text().splitlines()
        finally:
            bridge.STEERING_PATH = original_path
            bridge.add_reaction = original_add_reaction

        self.assertEqual(record["message_id"], 456)
        self.assertEqual(record["active_message_id"], 111)
        self.assertEqual(record["conversation_key"], "zulip:example:1:thread")
        self.assertEqual(reactions, [])
        self.assertEqual(len(lines), 1)
        stored = json.loads(lines[0])
        self.assertEqual(stored["message_id"], 456)
        self.assertIn(bridge.OUT_OF_BAND_USER_MESSAGE_OPEN, stored["formatted"])
        self.assertIn("actually, make this interrupting", stored["formatted"])

    def test_should_process_can_filter_topics(self) -> None:
        original_streams = bridge.ALLOW_STREAMS
        original_stream_ids = bridge.ALLOW_STREAM_IDS
        original_topics = bridge.ALLOW_TOPICS
        original_patterns = bridge.IGNORE_CONTENT_PATTERNS
        try:
            bridge.ALLOW_STREAMS = set()
            bridge.ALLOW_STREAM_IDS = {"1"}
            bridge.ALLOW_TOPICS = {"Allowed"}
            bridge.IGNORE_CONTENT_PATTERNS = []
            self.assertTrue(
                bridge.should_process(
                    {
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes",
                        "topic": "Allowed",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
            self.assertFalse(
                bridge.should_process(
                    {
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes",
                        "topic": "Blocked",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
        finally:
            bridge.ALLOW_STREAMS = original_streams
            bridge.ALLOW_STREAM_IDS = original_stream_ids
            bridge.ALLOW_TOPICS = original_topics
            bridge.IGNORE_CONTENT_PATTERNS = original_patterns

    def test_canonical_topic_treats_only_leading_resolved_marker_as_status(self) -> None:
        self.assertEqual(bridge.canonical_topic("✔ Project"), "Project")
        self.assertEqual(bridge.canonical_topic("Project ✔ status"), "Project ✔ status")
        self.assertEqual(bridge.alias_topic_variants("✔ Project"), ["✔ Project", "Project"])

    def test_should_process_allows_resolved_topic_from_unresolved_allowlist(self) -> None:
        message = {
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "✔ Allowed",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "hello",
        }
        with (
            mock.patch.object(bridge, "ALLOW_STREAMS", set()),
            mock.patch.object(bridge, "ALLOW_STREAM_IDS", {"1"}),
            mock.patch.object(bridge, "ALLOW_TOPICS", {"Allowed"}),
            mock.patch.object(bridge, "IGNORE_CONTENT_PATTERNS", []),
        ):
            self.assertTrue(bridge.should_process(message, "bot@example.com"))

    def test_should_process_allows_unresolved_topic_from_resolved_allowlist(self) -> None:
        message = {
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Allowed",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "hello",
        }
        with (
            mock.patch.object(bridge, "ALLOW_STREAMS", set()),
            mock.patch.object(bridge, "ALLOW_STREAM_IDS", {"1"}),
            mock.patch.object(bridge, "ALLOW_TOPICS", {"✔ Allowed"}),
            mock.patch.object(bridge, "IGNORE_CONTENT_PATTERNS", []),
        ):
            self.assertTrue(bridge.should_process(message, "bot@example.com"))

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
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
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
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                        "content": "hello",
                    },
                    "bot@example.com",
                )
            )
        finally:
            bridge.ALLOW_STREAMS = original_streams
            bridge.ALLOW_STREAM_IDS = original_stream_ids

    def test_admission_policy_fails_closed_and_requires_allowed_sender(self) -> None:
        message = user_message(1, 7, "Topic")
        with mock.patch.multiple(
            bridge,
            ALLOW_STREAMS=set(),
            ALLOW_STREAM_IDS=set(),
            ALLOW_TOPICS=set(),
            TOPIC_POLICY="",
            ALLOWED_SENDERS=set(),
        ):
            self.assertFalse(bridge.should_process(message, "bot@example.com"))
        with mock.patch.multiple(
            bridge,
            ALLOW_STREAM_IDS={"7"},
            ALLOW_TOPICS=set(),
            TOPIC_POLICY="any",
            ALLOWED_SENDERS={"id:18"},
        ):
            self.assertFalse(bridge.should_process(message, "bot@example.com"))
        with mock.patch.multiple(
            bridge,
            ALLOW_STREAM_IDS={"7"},
            ALLOW_TOPICS=set(),
            TOPIC_POLICY="any",
            ALLOWED_SENDERS={"id:17"},
        ):
            self.assertTrue(bridge.should_process(message, "bot@example.com"))
            without_optional_bot_flag = {key: value for key, value in message.items() if key != "sender_is_bot"}
            self.assertTrue(bridge.should_process(without_optional_bot_flag, "bot@example.com"))

    def test_direct_bot_mention_is_server_flagged_and_removed_from_payload(self) -> None:
        direct = user_message(1, 7, "Topic", content="@**Hermes** /goal status")
        direct["flags"] = ["mentioned"]
        direct["_zulip_bot_name"] = "Hermes"
        group = {**direct, "content": "@*operators* /goal status"}
        unflagged = {**direct, "flags": []}

        self.assertTrue(bridge.message_directly_mentions_bot(direct, "Hermes"))
        self.assertEqual(bridge.effective_message_content(direct), "/goal status")
        self.assertFalse(bridge.message_directly_mentions_bot(group, "Hermes"))
        self.assertFalse(bridge.message_directly_mentions_bot(unflagged, "Hermes"))
        with mock.patch.object(bridge, "REQUIRE_MENTION", True):
            self.assertTrue(bridge.message_can_activate(direct))
            self.assertFalse(bridge.message_can_activate(unflagged))
            self.assertTrue(bridge.message_can_activate(unflagged, user_message(2, 7, "Topic")))
            self.assertFalse(
                bridge.message_can_activate(
                    {**unflagged, "sender_id": 18, "sender_email": "other@example.com"},
                    user_message(2, 7, "Topic"),
                )
            )

    def test_authenticated_bot_identity_drives_mentions_without_configured_name(self) -> None:
        direct = user_message(1, 7, "Topic", content="@**Ops Bot** /status")
        direct["flags"] = ["mentioned"]
        direct["_zulip_rendered_content"] = (
            '<p><span class="user-mention" data-user-id="99">@Ops Bot</span> /status</p>'
        )
        renamed = {
            **direct,
            "content": "@**Renamed Ops Bot** /status",
            "_zulip_rendered_content": (
                '<p><span class="user-mention" data-user-id="99">@Renamed Ops Bot</span> /status</p>'
            ),
        }
        wrong_duplicate = {
            **direct,
            "content": "@**Ops Bot|100** /status",
            "_zulip_rendered_content": (
                '<p><span class="user-mention" data-user-id="100">@Ops Bot</span> /status</p>'
            ),
        }
        group_and_wrong_duplicate = {
            **direct,
            "content": "@*operators* `@**Ops Bot**` /status",
            "_zulip_rendered_content": (
                '<p><span class="user-group-mention" data-user-group-id="5">@operators</span> '
                '<code>@**Ops Bot**</code> /status</p>'
            ),
        }
        quoted = {
            **direct,
            "_zulip_rendered_content": (
                '<blockquote><span class="user-mention" data-user-id="99">@Ops Bot</span></blockquote>'
            ),
        }
        silent = {
            **direct,
            "_zulip_rendered_content": (
                '<p><span class="user-mention silent" data-user-id="99">Ops Bot</span> /status</p>'
            ),
        }

        with mock.patch.multiple(
            bridge,
            ZULIP_BOT_NAME="Hermes",
            ZULIP_BOT_USER_ID=None,
            REQUIRE_MENTION=True,
        ):
            bridge.configure_zulip_bot_identity({"full_name": "Ops Bot", "user_id": 99})
            self.assertTrue(bridge.message_can_activate(direct))
            self.assertTrue(bridge.message_can_activate(renamed))
            self.assertFalse(bridge.message_can_activate(wrong_duplicate))
            self.assertFalse(bridge.message_can_activate(group_and_wrong_duplicate))
            self.assertFalse(bridge.message_can_activate(quoted))
            self.assertFalse(bridge.message_can_activate(silent))
            self.assertEqual(bridge.effective_message_content(direct), "/status")
            self.assertEqual(bridge.effective_message_content(renamed), "/status")

    def test_live_mention_verification_uses_id_and_rejects_revision_mismatch(self) -> None:
        raw = user_message(1, 7, "Topic", content="@**New Name** /status")
        raw["flags"] = ["mentioned"]
        rendered = {
            **raw,
            "content": '<p><span class="user-mention" data-user-id="99">@New Name</span> /status</p>',
        }
        with mock.patch.object(
            bridge,
            "api",
            side_effect=[zulip_success(message=rendered), zulip_success(message=raw)],
        ):
            self.assertTrue(bridge.verify_live_direct_mention({}, raw, 99))
        self.assertEqual(bridge.effective_message_content({**raw, "_zulip_bot_user_id": 99}), "/status")

        edited = {**rendered, "last_edit_timestamp": 2}
        api = mock.Mock(return_value=zulip_success(message=edited))
        with mock.patch.object(bridge, "api", api), self.assertRaisesRegex(
            bridge.ReplyRoutingError, "metadata is ambiguous"
        ):
            bridge.verify_live_direct_mention({}, {**raw, "last_edit_timestamp": 1}, 99)

        changed_raw = {**raw, "content": "same timestamp, different body"}
        with mock.patch.object(
            bridge,
            "api",
            side_effect=[zulip_success(message=rendered), zulip_success(message=changed_raw)],
        ), self.assertRaisesRegex(bridge.ReplyRoutingError, "mention revision changed"):
            bridge.verify_live_direct_mention({}, raw, 99)


    def test_incomplete_authenticated_bot_identity_fails_without_mutating_identity(self) -> None:
        with mock.patch.multiple(
            bridge,
            ZULIP_BOT_NAME="Existing",
            ZULIP_BOT_USER_ID=99,
        ):
            with self.assertRaisesRegex(RuntimeError, "identity is incomplete"):
                bridge.configure_zulip_bot_identity({"full_name": "", "user_id": 100})
            self.assertEqual((bridge.ZULIP_BOT_NAME, bridge.ZULIP_BOT_USER_ID), ("Existing", 99))

    def test_slash_policy_denies_unauthorized_and_state_changing_commands_before_worker(self) -> None:
        worker = mock.Mock(return_value="ok")
        allowed = user_message(1, 7, "Topic", content="/status")
        dangerous = user_message(2, 7, "Topic", content="/reset")
        unauthorized = {**allowed, "sender_id": 18, "sender_email": "other@example.com"}
        with mock.patch.object(bridge, "run_slash_worker", worker):
            self.assertEqual(bridge.hermes_slash_reply({}, allowed, "s1"), ("ok", "s1"))
            self.assertEqual(
                bridge.hermes_slash_reply({}, dangerous, "s1"),
                ("That slash command is not allowed from Zulip.", "s1"),
            )
            self.assertEqual(
                bridge.hermes_slash_reply({}, unauthorized, "s1"),
                ("That slash command is not allowed from Zulip.", "s1"),
            )
        worker.assert_called_once()

        with (
            mock.patch.object(bridge, "PRIVILEGED_SENDERS", {"id:17"}),
            mock.patch.object(bridge, "PRIVILEGED_SLASH_COMMANDS", {"reset"}),
            mock.patch.object(bridge, "run_slash_worker", return_value="reset") as privileged,
        ):
            self.assertEqual(bridge.hermes_slash_reply({}, dangerous, "s1"), ("reset", "s1"))
        privileged.assert_called_once()

    def test_reply_uses_numeric_stream_id_across_stream_rename(self) -> None:
        posts: list[dict] = []
        gets = 0

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            nonlocal gets
            if method == "GET" and path == "/api/v1/messages/44":
                gets += 1
                return zulip_success(
                    message={
                        "id": 44,
                        "type": "stream",
                        "stream_id": 123,
                        "display_recipient": "before-send" if gets == 1 else "renamed-after-lookup",
                        "topic": "new-topic",
                    }
                )
            if method == "POST" and path == "/api/v1/messages":
                posts.append(data or {})
                return zulip_success(id=900)
            raise AssertionError((method, path, params, data))

        with mock.patch.object(bridge, "api", fake_api):
            bridge.reply(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 44, "type": "stream", "stream_id": 123, "display_recipient": "old-name", "topic": "old-topic"},
                "hello",
            )

        self.assertEqual(posts[0]["to"], 123)
        self.assertEqual(posts[0]["topic"], "new-topic")
        self.assertEqual(gets, 2)

    def test_reply_reconciles_only_the_just_sent_message_after_origin_moves(self) -> None:
        origins = [
            {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Old"},
            {"id": 44, "type": "stream", "stream_id": 2, "display_recipient": "ops", "topic": "New"},
        ]
        calls: list[tuple[str, str, dict]] = []

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            calls.append((method, path, data or {}))
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "Old", content="hello"))
            if method == "GET":
                return zulip_success(message=origins.pop(0))
            if method == "POST":
                return zulip_success(id=900)
            if method == "PATCH":
                return zulip_success()
            raise AssertionError((method, path, params, data))

        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Old",
            "_zulip_bridge": {"topic_aliases": ["Old"]},
        }
        with mock.patch.object(bridge, "api", fake_api):
            bridge.reply(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                message,
                "hello",
            )

        patches = [call for call in calls if call[0] == "PATCH"]
        self.assertEqual(patches, [])
        self.assertEqual((message["stream_id"], message["topic"]), (1, "Old"))
        self.assertEqual(message["_zulip_bridge"]["topic_aliases"], ["Old"])

    def test_reconciliation_failures_retain_first_confirmed_live_route(self) -> None:
        cases = ("second-get", "patch")
        for failure in cases:
            calls: list[str] = []
            first = {"id": 44, "type": "stream", "stream_id": 2, "display_recipient": "ops", "topic": "First"}
            second = {"id": 44, "type": "stream", "stream_id": 3, "display_recipient": "later", "topic": "Second"}

            def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                calls.append(method)
                if method == "GET" and calls.count("GET") == 1:
                    return zulip_success(message=first)
                if method == "POST":
                    return zulip_success(id=900)
                if method == "GET":
                    if failure == "second-get":
                        raise RuntimeError("lookup failed")
                    if path == "/api/v1/messages/900":
                        return zulip_success(message=bot_message(900, 2, "First", stream="ops"))
                    return zulip_success(message=second)
                if method == "PATCH":
                    raise RuntimeError("patch failed")
                raise AssertionError(method)

            message = {
                "id": 44,
                "type": "stream",
                "stream_id": 1,
                "display_recipient": "stale",
                "topic": "Stale",
                "_zulip_bridge": {"topic_aliases": ["Stale"]},
            }
            with self.subTest(failure=failure), mock.patch.object(bridge, "api", fake_api):
                bridge.reply({"site": "https://zulip.example.com", "email": "bot@example.com", "key": BOT_KEY}, message, "answer")

            self.assertEqual((message["stream_id"], message["topic"]), (2, "First"))
            self.assertEqual(message["_zulip_bridge"]["topic_aliases"], ["Stale", "First"])
            self.assertEqual(calls, ["GET", "POST", "GET"])

    def test_reply_reconciliation_is_bounded_to_one_recheck_and_patch(self) -> None:
        gets = 0
        patches = 0

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            nonlocal gets, patches
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "Before", content="hello"))
            if method == "GET":
                gets += 1
                if gets > 2:
                    raise AssertionError("unbounded origin lookup")
                topic = "Before" if gets == 1 else "After"
                return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": topic})
            if method == "POST":
                return zulip_success(id=900)
            if method == "PATCH":
                patches += 1
                return zulip_success()
            raise AssertionError((method, path, params, data))

        with mock.patch.object(bridge, "api", fake_api):
            bridge.reply(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Before"},
                "hello",
            )

        self.assertEqual((gets, patches), (2, 1))

    def test_invalid_sent_message_id_never_reaches_patch_boundary(self) -> None:
        for sent_id in (True, 0, -1, 1.0, 1.5, float("inf"), float("nan"), [], {}, "nope"):
            calls: list[tuple[str, str]] = []

            def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                calls.append((method, path))
                if method == "GET":
                    return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "T"})
                if method == "POST":
                    return zulip_success(id=sent_id)
                raise AssertionError("invalid sent ID must not reach PATCH")

            with self.subTest(sent_id=sent_id), mock.patch.object(bridge, "api", fake_api), self.assertRaises(bridge.ReplyPostUncertain):
                bridge.reply(
                    {"site": "https://zulip.example.com"},
                    {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "T"},
                    "hello",
                )

            self.assertEqual([method for method, _path in calls], ["GET", "POST"])

    def test_patch_denial_after_send_is_logged_without_duplicate_error_post(self) -> None:
        gets = 0
        posts = 0

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            nonlocal gets, posts
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "Before"))
            if method == "GET":
                gets += 1
                topic = "Before" if gets == 1 else "After"
                return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": topic})
            if method == "POST":
                posts += 1
                return zulip_success(id=900)
            if method == "PATCH":
                raise RuntimeError("move permission denied")
            raise AssertionError((method, path, params, data))

        with (
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "hermes_reply", lambda *_args, **_kwargs: ("answer", "s1")),
            mock.patch.object(bridge, "should_run_goal_after_turn", lambda _message: False),
            mock.patch.object(bridge, "add_reaction", lambda *_args, **_kwargs: None),
            mock.patch.object(bridge, "remove_reaction", lambda *_args, **_kwargs: None),
        ):
            self.assertEqual(
                bridge.handle_message(
                    {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Before", "content": "hi"},
                    "s1",
                ),
                "s1",
            )

        self.assertEqual((gets, posts), (2, 1))

    def test_post_send_origin_failure_does_not_reconcile_or_mutate_aliases(self) -> None:
        failures = [RuntimeError("origin deleted"), {"id": 44, "type": "stream", "stream_id": 2, "display_recipient": "ops", "topic": "Moved"}]
        for failure in failures:
            calls: list[str] = []
            conversation = {"topic_aliases": ["Before"]}

            def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
                calls.append(method)
                if method == "GET" and calls.count("GET") == 1:
                    return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Before"})
                if method == "GET":
                    if isinstance(failure, Exception):
                        raise failure
                    return zulip_success(message=failure)
                if method == "POST":
                    return zulip_success(id=900)
                raise AssertionError((method, path, params, data))

            with (
                self.subTest(failure=failure),
                mock.patch.object(bridge, "api", fake_api),
                mock.patch.object(bridge, "ALLOW_STREAM_IDS", {"1"}),
            ):
                bridge.reply(
                    {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    {
                        "id": 44,
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes",
                        "topic": "Before",
                        "_zulip_bridge": conversation,
                    },
                    "hello",
                )

            self.assertEqual(calls, ["GET", "POST", "GET"])
            self.assertEqual(conversation["topic_aliases"], ["Before"])

    def test_reply_rejects_each_disallowed_live_location_without_posting(self) -> None:
        cases = [
            ({"ALLOW_STREAM_IDS": {"1"}}, {"stream_id": 2, "display_recipient": "hermes", "topic": "Allowed"}),
            ({"ALLOW_STREAMS": {"hermes"}}, {"stream_id": 1, "display_recipient": "ops", "topic": "Allowed"}),
            ({"ALLOW_TOPICS": {"Allowed"}}, {"stream_id": 1, "display_recipient": "hermes", "topic": "Blocked"}),
        ]
        for config, location in cases:
            posts: list[dict] = []

            def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
                if method == "GET":
                    return zulip_success(message={"id": 44, "type": "stream", **location})
                posts.append(data or {})
                return zulip_success(id=900)

            defaults = {"ALLOW_STREAM_IDS": set(), "ALLOW_STREAMS": set(), "ALLOW_TOPICS": set()}
            with self.subTest(config=config), mock.patch.object(bridge, "api", fake_api), mock.patch.multiple(
                bridge, **{**defaults, **config}
            ):
                with self.assertRaises(bridge.ReplyRoutingError):
                    bridge.reply(
                        {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                        {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Allowed"},
                        "hello",
                    )
            self.assertEqual(posts, [])

    def test_reply_rejects_deleted_or_inaccessible_origin_without_posting(self) -> None:
        calls: list[str] = []

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            calls.append(method)
            raise RuntimeError("404 not found")

        with mock.patch.object(bridge, "api", fake_api):
            with self.assertRaises(bridge.ReplyRoutingError):
                bridge.reply(
                    {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Allowed"},
                    "hello",
                )
        self.assertEqual(calls, ["GET"])

    def test_reply_rejects_non_stream_origin_without_posting(self) -> None:
        methods: list[str] = []

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            methods.append(method)
            return zulip_success(message={"id": 44, "type": "private", "display_recipient": []})

        with mock.patch.object(bridge, "api", fake_api):
            with self.assertRaises(bridge.ReplyRoutingError):
                bridge.reply(
                    {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Allowed"},
                    "hello",
                )
        self.assertEqual(methods, ["GET"])

    def test_handle_message_does_not_attempt_error_post_when_routing_fails(self) -> None:
        gets = 0

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            nonlocal gets
            if method == "GET":
                gets += 1
                raise RuntimeError("origin deleted")
            raise AssertionError("routing failure must not trigger a post")

        with (
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "hermes_reply", lambda *_args, **_kwargs: ("answer", "s1")),
            mock.patch.object(bridge, "add_reaction", lambda *_args, **_kwargs: None),
            mock.patch.object(bridge, "remove_reaction", lambda *_args, **_kwargs: None),
        ):
            with self.assertRaises(bridge.ReplyRoutingError):
                bridge.handle_message(
                    {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                    {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Allowed", "content": "hi"},
                    None,
                )
        self.assertEqual(gets, 1)

    def test_handle_message_does_not_post_internal_error_for_malformed_origin_payload(self) -> None:
        gets = 0
        posts: list[dict] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            nonlocal gets
            if method == "GET" and path == "/api/v1/messages/44":
                gets += 1
                if gets == 1:
                    return zulip_success(message={"id": "not-a-number", "type": "stream", "stream_id": 1, "topic": "Allowed"})
                return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Allowed"})
            if method == "POST":
                posts.append(dict(kwargs.get("data") or {}))
                return zulip_success(id=900)
            raise AssertionError((method, path))

        with (
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "hermes_reply", lambda *_args, **_kwargs: ("answer", "s1")),
            mock.patch.object(bridge, "add_reaction", lambda *_args, **_kwargs: None),
            mock.patch.object(bridge, "remove_reaction", lambda *_args, **_kwargs: None),
            self.assertRaises(bridge.ReplyRoutingError),
        ):
            bridge.handle_message(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Allowed", "content": "hi"},
                None,
            )

        self.assertEqual(gets, 1)
        self.assertEqual(posts, [])

    def test_handle_message_normalizes_nonnumeric_origin_id_to_routing_error(self) -> None:
        api = mock.Mock()
        hermes_reply = mock.Mock()

        with (
            mock.patch.object(bridge, "api", api),
            mock.patch.object(bridge, "hermes_reply", hermes_reply),
            self.assertRaises(bridge.ReplyRoutingError),
        ):
            bridge.handle_message(
                {"site": "https://zulip.example.com"},
                {"id": "not-a-number", "type": "stream", "stream_id": 1, "topic": "Allowed", "content": "hi"},
                None,
            )

        api.assert_not_called()
        hermes_reply.assert_not_called()

    def test_goal_multi_post_reresolves_origin_before_every_output(self) -> None:
        topics = iter(["One", "One", "Two", "Two", "Three", "Three", "Four", "Four"])
        gets = 0
        posts: list[str] = []
        decisions = [
            {"message": "progress", "should_continue": True, "continuation_prompt": "next"},
            {"message": "done", "should_continue": False},
        ]

        class Manager:
            def is_active(self) -> bool:
                return True

            def evaluate_after_turn(self, _last_response: str, **_kwargs: object) -> dict:
                return decisions.pop(0)

        def fake_api(_rc: dict, method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
            nonlocal gets
            if method == "GET" and path == "/api/v1/messages/44":
                gets += 1
                return zulip_success(
                    message={
                        "id": 44,
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes",
                        "topic": next(topics),
                    }
                )
            if method == "POST" and path == "/api/v1/messages":
                posts.append(str((data or {}).get("topic")))
                return zulip_success(id=900 + len(posts))
            raise AssertionError((method, path, params, data))

        def fake_hermes_reply(_rc: dict, _message: dict, session_id: str | None) -> tuple[str, str]:
            return ("first" if session_id is None else "second"), "s1"

        with (
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "hermes_reply", fake_hermes_reply),
            mock.patch.object(bridge, "goal_manager", lambda _session_id: Manager()),
            mock.patch.object(bridge, "goal_background_processes", lambda: []),
            mock.patch.object(bridge, "add_reaction", lambda *_args, **_kwargs: None),
            mock.patch.object(bridge, "remove_reaction", lambda *_args, **_kwargs: None),
            mock.patch.multiple(bridge, ALLOW_STREAMS=set(), ALLOW_STREAM_IDS=set(), ALLOW_TOPICS=set()),
        ):
            bridge.handle_message(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Start", "content": "start"},
                None,
            )

        self.assertEqual(posts, ["One", "Two", "Three", "Four"])
        self.assertEqual(gets, 8)

    def test_resolved_and_unresolved_topics_share_conversation_and_session(self) -> None:
        state = {"topic_sessions": {}}
        first = {"id": 10, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Project"}
        _session_id, conversation = bridge.resolve_session(first, {}, state, "example")
        state["zulip_threads"][conversation["thread_id"]]["session_id"] = "s1"
        bridge.note_topic_session(state, conversation, "s1")

        session_id, resolved = bridge.resolve_session({**first, "id": 11, "topic": "✔ Project"}, {}, state, "example")
        session_id_again, unresolved = bridge.resolve_session({**first, "id": 12}, {}, state, "example")

        self.assertEqual((session_id, session_id_again), ("s1", "s1"))
        self.assertEqual(resolved["conversation_key"], conversation["conversation_key"])
        self.assertEqual(unresolved["conversation_key"], conversation["conversation_key"])

    def test_native_thread_ids_are_scoped_by_realm_and_stream(self) -> None:
        for native_field in ("topic_id", "thread_id", "conversation_id"):
            with self.subTest(native_field=native_field):
                state = {"topic_sessions": {}}
                first = {
                    "id": 10,
                    "type": "stream",
                    "stream_id": 1,
                    "display_recipient": "one",
                    "topic": "Topic",
                    native_field: "native-42",
                }
                second = {**first, "id": 11, "stream_id": 2, "display_recipient": "two"}

                _first_session, first_conversation = bridge.resolve_session(first, {}, state, "example")
                _second_session, second_conversation = bridge.resolve_session(second, {}, state, "example")

                self.assertNotEqual(first_conversation["thread_id"], second_conversation["thread_id"])
                self.assertNotEqual(first_conversation["conversation_key"], second_conversation["conversation_key"])
                self.assertNotEqual(
                    bridge.stable_zulip_thread_id("example", 1, "Topic", first),
                    bridge.stable_zulip_thread_id("other.example", 1, "Topic", first),
                )
                self.assertEqual(len(state["zulip_threads"]), 2)

    def test_native_thread_rename_adopts_its_stored_session_after_alias_and_anchor_miss(self) -> None:
        state = {"topic_sessions": {}}
        first = {
            "id": 10,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "one",
            "topic": "Before",
            "topic_id": 42,
        }
        _session_id, original = bridge.resolve_session(first, {}, state, "example")
        bridge.note_bridge_thread(state, original, session_id="s1")
        bridge.note_topic_session(state, original, "s1")

        renamed = {**first, "id": 11, "topic": "After"}
        with mock.patch.object(bridge, "_thread_for_matching_anchors", return_value=""):
            session_id, resolved = bridge.resolve_session(renamed, {}, state, "example", {})

        self.assertEqual(session_id, "s1")
        self.assertEqual(resolved["thread_id"], original["thread_id"])
        self.assertEqual(resolved["conversation_key"], original["conversation_key"])

        state["zulip_threads"]["conflict"] = {
            **state["zulip_threads"][original["thread_id"]],
            "thread_id": "conflict",
            "conversation_key": bridge.conversation_key("example", 1, "conflict"),
        }
        with mock.patch.object(bridge, "_thread_for_matching_anchors", return_value=""), self.assertRaises(
            bridge.ReplyRoutingError
        ):
            bridge.resolve_session({**renamed, "id": 12}, {}, state, "example", {})

    def test_native_owner_conflicts_with_different_topic_owner_before_selection(self) -> None:
        state = {"topic_sessions": {}}
        native_a = {
            "id": 10,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "one",
            "topic": "Before",
            "topic_id": "A",
        }
        _session_id, owner_a = bridge.resolve_session(native_a, {}, state, "example")
        bridge.note_bridge_thread(state, owner_a, session_id="s1")
        bridge.note_topic_session(state, owner_a, "s1")
        native_b = {**native_a, "id": 20, "topic": "Target", "topic_id": "B"}
        _session_id, owner_b = bridge.resolve_session(native_b, {}, state, "example")
        bridge.note_bridge_thread(state, owner_b, session_id="s2")
        bridge.note_topic_session(state, owner_b, "s2")
        before = json.loads(json.dumps(state))

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "conflicting native Hermes owner"):
            bridge.resolve_session({**native_a, "id": 30, "topic": "Target"}, {}, state, "example")

        self.assertEqual(state, before)

    def test_native_owner_continues_onto_topic_owned_by_the_same_session(self) -> None:
        state = {"topic_sessions": {}}
        first = {
            "id": 10,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "one",
            "topic": "Before",
            "topic_id": "A",
        }
        _session_id, original = bridge.resolve_session(first, {}, state, "example")
        bridge.note_bridge_thread(state, original, session_id="s1")
        bridge.note_topic_session(state, original, "s1")
        moved = {**first, "id": 20, "topic": "Target"}
        target = bridge.resolve_zulip_conversation_key(moved, "example", thread_id=original["thread_id"])
        bridge.note_bridge_thread(state, target, session_id="s1")
        bridge.note_topic_session(state, target, "s1")

        session_id, resolved = bridge.resolve_session(moved, {}, state, "example")

        self.assertEqual(session_id, "s1")
        self.assertEqual(resolved["thread_id"], original["thread_id"])

    def test_sessionless_native_record_accepts_consistent_topic_session_owner(self) -> None:
        state = {"topic_sessions": {}}
        first = {
            "id": 10,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "one",
            "topic": "Before",
            "topic_id": "A",
        }
        _session_id, original = bridge.resolve_session(first, {}, state, "example")
        moved = {**first, "id": 20, "topic": "Target"}
        target = bridge.resolve_zulip_conversation_key(moved, "example", thread_id=original["thread_id"])
        bridge.note_bridge_thread(state, target)
        bridge.note_topic_session(state, target, "s1")
        self.assertEqual(state["zulip_threads"][original["thread_id"]]["session_id"], "")

        session_id, resolved = bridge.resolve_session(moved, {}, state, "example")

        self.assertEqual(session_id, "s1")
        self.assertEqual(resolved["thread_id"], original["thread_id"])

    def test_topic_continuity_is_unchanged_without_authoritative_native_record(self) -> None:
        state = {"topic_sessions": {}}
        original = self.seed_topic(state, message_id=10, stream_id=1, topic="Topic", session_id="s1")
        messages = [
            {
                "id": 20,
                "type": "stream",
                "stream_id": 1,
                "display_recipient": "stream-1",
                "topic": "Topic",
            },
            {
                "id": 21,
                "type": "stream",
                "stream_id": 1,
                "display_recipient": "stream-1",
                "topic": "Topic",
                "topic_id": "not-yet-stored",
            },
        ]

        for message in messages:
            with self.subTest(message_id=message["id"]):
                session_id, resolved = bridge.resolve_session(message, {}, state, "example")
                self.assertEqual(session_id, "s1")
                self.assertEqual(resolved["thread_id"], original["thread_id"])

    def test_persisted_thread_stream_or_conversation_collision_fails_closed(self) -> None:
        message = {
            "id": 10,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "one",
            "topic": "Topic",
            "topic_id": 42,
        }
        for corruption in ("stream", "key", "duplicate-key"):
            with self.subTest(corruption=corruption):
                state = {"topic_sessions": {}}
                _session_id, conversation = bridge.resolve_session(message.copy(), {}, state, "example")
                thread = state["zulip_threads"][conversation["thread_id"]]
                if corruption == "stream":
                    thread["stream_id"] = "2"
                elif corruption == "key":
                    thread["conversation_key"] = "zulip:example:2:foreign"
                else:
                    state["zulip_threads"]["foreign"] = {
                        "realm": "example",
                        "stream_id": "1",
                        "conversation_key": conversation["conversation_key"],
                    }
                before = json.loads(json.dumps(state))

                if corruption == "duplicate-key":
                    with self.assertRaises(ValueError):
                        bridge.require_state_object(json.loads(json.dumps(state)))
                else:
                    bridge.require_state_object(json.loads(json.dumps(state)))
                with self.assertRaises((ValueError, bridge.ReplyRoutingError)):
                    bridge.resolve_session({**message, "id": 11}, {}, state, "example")

                self.assertEqual(state, before)

    def test_steering_after_resolve_maps_to_and_interrupts_same_active_turn(self) -> None:
        state = {"topic_sessions": {}}
        active_message = {"id": 111, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Project"}
        _session_id, active_conversation = bridge.resolve_session(active_message, {}, state, "example")
        state["zulip_threads"][active_conversation["thread_id"]]["session_id"] = "s1"
        bridge.note_topic_session(state, active_conversation, "s1")
        steering = {**active_message, "id": 222, "topic": "✔ Project", "content": "stop now"}
        session_id, steering_conversation = bridge.resolve_session(steering, {}, state, "example")
        bridge._admit_origin(state, 222, now=1.0)
        steering.update(_zulip_state=state, _zulip_persist=lambda: None)
        calls: list[tuple[str, int]] = []

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True),
            mock.patch.object(
                bridge,
                "store_steering_message",
                lambda _rc, _message, _conversation, active_id: calls.append(("store", active_id)),
            ),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, message: message),
            mock.patch.object(bridge, "interrupt_active_message", lambda active_id: calls.append(("interrupt", active_id)) or True),
            mock.patch.object(bridge, "HARD_INTERRUPT_ON_STEERING", True),
        ):
            bridge.handle_active_topic_message(
                {}, steering, session_id, steering_conversation, 111, {}, set()
            )

        self.assertEqual(steering_conversation["conversation_key"], active_conversation["conversation_key"])
        self.assertEqual(calls, [("store", 111), ("interrupt", 111)])

    def test_first_turn_same_stream_rename_reuses_sessionless_active_anchor(self) -> None:
        state = {"topic_sessions": {}}
        first = {"id": 50, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Original"}
        session_id, original = bridge.resolve_session(first, {}, state, "example")
        lookups: list[dict] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            lookups.append(dict(kwargs.get("params") or {}))
            return {"result": "success", "msg": "", "messages": {"50": narrow_match()}}

        message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}
        with mock.patch.object(bridge, "api", fake_api):
            renamed_session, renamed = bridge.resolve_session(
                message,
                {},
                state,
                "example",
                {"site": "https://zulip.example.com"},
            )

        self.assertIsNone(session_id)
        self.assertIsNone(renamed_session)
        self.assertEqual(renamed["thread_id"], original["thread_id"])
        self.assertEqual(renamed["conversation_key"], original["conversation_key"])
        active_keys = {original["conversation_key"]: 50}
        self.assertEqual(active_keys.get(renamed["conversation_key"]), 50)
        self.assertEqual(len(lookups), 1)

    def test_renamed_topic_stale_original_alias_cannot_capture_new_sibling(self) -> None:
        state: dict = {"topic_sessions": {}}
        original = self.seed_topic(
            state, message_id=40, stream_id=1, topic="Original", session_id="session-one"
        )
        renamed_message = user_message(50, 1, "Renamed")
        with mock.patch.object(
            bridge, "api", return_value=zulip_success(messages={"40": narrow_match()})
        ):
            renamed_session, renamed = bridge.resolve_session(
                renamed_message, {}, state, "example", {"site": "https://example"}
            )
        self.assertEqual(renamed_session, "session-one")
        self.assertEqual(renamed["thread_id"], original["thread_id"])

        sibling = user_message(60, 1, "Original")
        with mock.patch.object(
            bridge, "api", return_value=zulip_success(messages={})
        ):
            sibling_session, sibling_conversation = bridge.resolve_session(
                sibling, {}, state, "example", {"site": "https://example"}
            )

        self.assertIsNone(sibling_session)
        self.assertNotEqual(sibling_conversation["thread_id"], original["thread_id"])
        self.assertEqual(
            state["zulip_topic_aliases"][bridge.topic_alias_lookup_key("example", 1, "Original")],
            sibling_conversation["thread_id"],
        )
        self.assertEqual(
            state["zulip_threads"][original["thread_id"]]["current_display_topic"], "Renamed"
        )
        self.assertNotIn(
            "Original", state["zulip_threads"][original["thread_id"]]["topic_aliases"]
        )

    def test_live_anchor_and_resolved_variants_preserve_topic_continuity(self) -> None:
        for topic, matches in (("Renamed", {"40": narrow_match()}), ("✔ Original", {})):
            with self.subTest(topic=topic):
                state: dict = {"topic_sessions": {}}
                original = self.seed_topic(
                    state, message_id=40, stream_id=1, topic="Original", session_id="session-one"
                )
                with mock.patch.object(
                    bridge, "api", return_value=zulip_success(messages=matches)
                ):
                    session_id, conversation = bridge.resolve_session(
                        user_message(50, 1, topic),
                        {},
                        state,
                        "example",
                        {"site": "https://example"},
                    )
                self.assertEqual(session_id, "session-one")
                self.assertEqual(conversation["thread_id"], original["thread_id"])

    def test_mixed_realm_session_and_anchor_candidates_fail_before_api_or_mutation(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        state["topic_sessions"][f"1:{bridge.topic_key('1', 'Renamed')}"] = "s1"
        state["zulip_threads"]["foreign-thread"] = {
            "realm": "other.example",
            "stream_id": "1",
            "session_id": "s1",
            "last_seen_message_id": 50,
        }
        before = json.loads(json.dumps(state))
        api = mock.Mock(return_value={"result": "success", "msg": "", "messages": {"50": narrow_match()}})

        with mock.patch.object(bridge, "api", api), self.assertRaisesRegex(bridge.ReplyRoutingError, "mixed Zulip realms"):
            bridge.resolve_session(
                {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Renamed"},
                {},
                state,
                "example",
                {"site": "https://zulip.example.com"},
            )

        self.assertEqual(state, before)
        api.assert_not_called()

    def test_foreign_realm_message_id_collision_cannot_reuse_thread_or_session(self) -> None:
        state = {
            "topic_sessions": {},
            "zulip_topic_aliases": {},
            "zulip_threads": {
                "foreign-thread": {
                    "realm": "other.example",
                    "stream_id": "1",
                    "session_id": "foreign-session",
                    "last_seen_message_id": 50,
                }
            },
        }
        api = mock.Mock(return_value={"result": "success", "msg": "", "messages": {"50": narrow_match()}})

        before = json.loads(json.dumps(state))
        with mock.patch.object(bridge, "api", api), self.assertRaisesRegex(bridge.ReplyRoutingError, "different Zulip realm"):
            bridge.resolve_session(
                {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Renamed"},
                {},
                state,
                "example",
                {"site": "https://zulip.example.com"},
            )

        self.assertEqual(state, before)
        api.assert_not_called()

    def test_foreign_realm_stored_session_claim_fails_closed(self) -> None:
        topic = "Renamed"
        state = {
            "topic_sessions": {f"1:{bridge.topic_key('1', topic)}": "foreign-session"},
            "zulip_topic_aliases": {},
            "zulip_threads": {
                "foreign-thread": {
                    "realm": "other.example",
                    "stream_id": "1",
                    "session_id": "foreign-session",
                    "last_seen_message_id": 50,
                }
            },
        }
        before = json.loads(json.dumps(state))

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "different Zulip realm"):
            bridge.resolve_session(
                {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": topic},
                {},
                state,
                "example",
            )

        self.assertEqual(state, before)

    def test_base_format_state_infers_one_realm_and_annotates_missing_threads(self) -> None:
        state = {
            "topic_sessions": {"legacy": "s1"},
            "zulip_topic_aliases": {bridge.topic_alias_lookup_key("example", "1", "Topic"): "thread-one"},
            "zulip_threads": {
                "thread-one": {"realm": "example", "stream_id": "1", "session_id": "s1"},
                "thread-two": {"stream_id": "2", "session_id": "s2"},
            },
        }

        bridge.bind_state_realm(state, "example")

        self.assertEqual(state["realm"], "example")
        self.assertEqual({thread["realm"] for thread in state["zulip_threads"].values()}, {"example"})

    def test_realm_binding_matrix_and_persistence(self) -> None:
        cases = {
            "empty": ({"seen_ids": []}, True),
            "alias-only": (
                {"zulip_topic_aliases": {bridge.topic_alias_lookup_key("example", "1", "Topic"): "thread"}},
                True,
            ),
            "thread-only": ({"zulip_threads": {"thread": {"realm": "example", "stream_id": "1"}}}, True),
            "foreign": ({"zulip_threads": {"thread": {"realm": "foreign", "stream_id": "1"}}}, False),
            "mixed": (
                {
                    "zulip_threads": {
                        "one": {"realm": "example", "stream_id": "1"},
                        "two": {"realm": "foreign", "stream_id": "1"},
                    }
                },
                False,
            ),
            "evidence-free": ({"topic_sessions": {"legacy": "s1"}}, False),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            for name, (state, allowed) in cases.items():
                before = json.loads(json.dumps(state))
                if not allowed:
                    with self.subTest(name=name), self.assertRaises(bridge.ReplyRoutingError):
                        bridge.bind_state_realm(state, "example")
                    self.assertEqual(state, before)
                    continue
                bridge.bind_state_realm(state, "example")
                path = Path(tmpdir) / f"{name}.json"
                bridge.save_json(path, state)
                reloaded = bridge.require_state_object(bridge.load_json(path, {}))
                bridge.bind_state_realm(reloaded, "example")
                self.assertEqual(reloaded["realm"], "example")

    def test_external_alias_manifest_is_not_legacy_realm_evidence(self) -> None:
        state = {"topic_sessions": {"legacy": "s1"}}
        entries = [{"stream_id": "1", "topic": "Topic", "session_id": "s1"}]
        before = json.loads(json.dumps(state))

        with self.assertRaises(bridge.ReplyRoutingError):
            bridge.bind_state_realm(state, "example")

        self.assertEqual(state, before)
        self.assertEqual(
            bridge.load_aliases(entries),
            {("1", "topic"): "s1", ("1", "✔ topic"): "s1"},
        )

    def test_current_bound_state_accepts_legacy_owners_without_new_evidence(self) -> None:
        state = {
            "realm": "example",
            "topic_sessions": {"legacy": "s1"},
            "zulip_threads": {"thread": {"stream_id": "1", "session_id": "s1"}},
        }

        bridge.bind_state_realm(state, "example")

        self.assertEqual(state["zulip_threads"]["thread"]["realm"], "example")

    def test_legacy_ownership_without_realm_evidence_fails_without_mutation(self) -> None:
        state = {"topic_sessions": {"legacy": "s1"}}
        before = json.loads(json.dumps(state))

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "legacy ownership has no trustworthy"):
            bridge.bind_state_realm(state, "example")

        self.assertEqual(state, before)

    def test_owner_and_anchor_helpers_require_bound_active_realm(self) -> None:
        state = {"topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        api = mock.Mock()

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "not bound"):
            bridge._thread_for_session(state, "example", "1", "s1")
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "not bound"):
            bridge._stored_topic_owner(state, "example", "1", "Topic")
        with mock.patch.object(bridge, "api", api), self.assertRaisesRegex(bridge.ReplyRoutingError, "not bound"):
            bridge._thread_for_matching_anchors({}, state, {"stream_id": 1, "topic": "Topic"}, "example")
        api.assert_not_called()

    def test_main_realm_mismatch_stops_before_aliases_api_worker_or_state_write(self) -> None:
        state = {"realm": "other.example", "topic_sessions": {"legacy": "s1"}}
        before = json.loads(json.dumps(state))
        load_aliases = mock.Mock()
        latest = mock.Mock()
        worker = mock.Mock()
        save = mock.Mock()

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(bridge, "STATE_PATH", Path(tmpdir) / "state"):
            with bridge.process_lock() as held_lock, (
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test"},
                )
            ):
                with (
                    mock.patch.object(bridge, "load_json", return_value=state),
                    mock.patch.object(bridge, "load_alias_entries", load_aliases),
                    mock.patch.object(bridge, "latest_messages", latest),
                    mock.patch.object(bridge, "handle_message", worker),
                    mock.patch.object(bridge, "save_json", save),
                    self.assertRaisesRegex(SystemExit, bridge.STATE_REALM_MIGRATION_REQUIRED),
                ):
                    bridge.main(lock=held_lock)

        self.assertEqual(state, before)
        load_aliases.assert_not_called()
        latest.assert_not_called()
        worker.assert_not_called()
        save.assert_not_called()

    def test_cross_stream_anchor_starts_separate_session_without_lookup(self) -> None:
        state = {"topic_sessions": {}}
        first = {"id": 50, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Original"}
        session_id, active = bridge.resolve_session(first, {}, state, "example")
        lookups = 0

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            nonlocal lookups
            lookups += 1
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            self.assertEqual(
                (kwargs.get("params") or {}).get("narrow"),
                [
                    {"operator": "channel", "operand": 2},
                    {"operator": "topic", "operand": "Renamed"},
                ],
            )
            return {"result": "success", "msg": "", "messages": {"50": narrow_match()}}

        steering = {"id": 51, "type": "stream", "stream_id": 2, "display_recipient": "stream-2", "topic": "Renamed", "content": "stop"}
        with mock.patch.object(bridge, "api", fake_api), mock.patch.object(bridge, "ALLOW_STREAM_IDS", {"1", "2"}):
            moved_session, moved = bridge.resolve_session(
                steering,
                {},
                state,
                "example",
                {"site": "https://zulip.example.com"},
            )

        self.assertIsNone(session_id)
        self.assertIsNone(moved_session)
        self.assertNotEqual(moved["conversation_key"], active["conversation_key"])
        self.assertEqual(lookups, 0)

    def test_batch_anchor_lookup_includes_more_than_twenty_anchors_once(self) -> None:
        state = {"topic_sessions": {}}
        conversations = [
            self.seed_topic(state, message_id=message_id, stream_id=1, topic=f"Old {message_id}", session_id=f"s{message_id}")
            for message_id in range(1, 22)
        ]
        lookups: list[dict] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            lookups.append(dict(kwargs.get("params") or {}))
            return {"result": "success", "msg": "", "messages": {"1": narrow_match()}}

        message = {"id": 100, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}
        with mock.patch.object(bridge, "api", fake_api):
            session_id, renamed = bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

        self.assertEqual(session_id, "s1")
        self.assertEqual(renamed["thread_id"], conversations[0]["thread_id"])
        self.assertEqual(len(lookups), 1)
        self.assertEqual(lookups[0]["msg_ids"], list(range(1, 22)))
        self.assertEqual(
            lookups[0]["narrow"],
            [
                {"operator": "channel", "operand": 1},
                {"operator": "topic", "operand": "Renamed"},
            ],
        )

    def test_anchor_lookup_accepts_current_zulip_match_details(self) -> None:
        state = {"topic_sessions": {}}
        original = self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            self.assertEqual((kwargs.get("params") or {}).get("msg_ids"), [50])
            return zulip_success(messages={"50": {"match_content": "hello", "match_subject": "Renamed"}})

        message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}
        with mock.patch.object(bridge, "api", fake_api):
            session_id, renamed = bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

        self.assertEqual(session_id, "s1")
        self.assertEqual(renamed["thread_id"], original["thread_id"])

    def test_anchor_batches_are_bounded_and_second_batch_match_prevents_false_fork(self) -> None:
        state = {
            "realm": "example",
            "topic_sessions": {},
            "zulip_topic_aliases": {},
            "zulip_threads": {
                f"thread-{message_id}": {
                    "thread_id": f"thread-{message_id}",
                    "conversation_key": f"zulip:example:1:thread-{message_id}",
                    "stream_id": "1",
                    "session_id": f"session-{message_id}",
                    "last_seen_message_id": message_id,
                }
                for message_id in range(1, 1002)
            },
        }
        batches: list[list[int]] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            batch = list((kwargs.get("params") or {}).get("msg_ids") or [])
            batches.append(batch)
            matches = {"1001": narrow_match()} if 1001 in batch else {}
            return {"result": "success", "msg": "", "messages": matches}

        message = {"id": 2000, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}
        with mock.patch.object(bridge, "api", fake_api):
            session_id, conversation = bridge.resolve_session(
                message,
                {},
                state,
                "example",
                {"site": "https://zulip.example.com"},
            )

        self.assertEqual([len(batch) for batch in batches], [1000, 1])
        self.assertTrue(all(len(batch) <= bridge.ANCHOR_BATCH_SIZE for batch in batches))
        self.assertEqual(session_id, "session-1001")
        self.assertEqual(conversation["thread_id"], "thread-1001")

    def test_zero_batch_anchor_matches_starts_new_session_with_one_lookup(self) -> None:
        state = {"topic_sessions": {}}
        original = self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        lookups = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal lookups
            lookups += 1
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            return {"result": "success", "msg": "", "messages": {}}

        message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Unrelated"}
        with mock.patch.object(bridge, "api", fake_api):
            session_id, unrelated = bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

        self.assertIsNone(session_id)
        self.assertNotEqual(unrelated["thread_id"], original["thread_id"])
        self.assertEqual(lookups, 1)

    def test_multiple_batch_anchor_threads_fail_with_one_lookup_and_no_mutation(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="One", session_id="s1")
        self.seed_topic(state, message_id=60, stream_id=1, topic="Two", session_id="s2")
        before = json.loads(json.dumps(state))
        lookups = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal lookups
            lookups += 1
            self.assertEqual((method, path), ("GET", "/api/v1/messages/matches_narrow"))
            return {"result": "success", "msg": "", "messages": {"50": narrow_match(), "60": narrow_match()}}

        message = {"id": 70, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Collision"}
        with mock.patch.object(bridge, "api", fake_api), self.assertRaises(bridge.ReplyRoutingError):
            bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

        self.assertEqual(state, before)
        self.assertEqual(lookups, 1)

    def test_batch_anchor_api_failure_fails_closed_with_one_lookup(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        before = json.loads(json.dumps(state))
        api = mock.Mock(side_effect=RuntimeError("unavailable"))
        message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}

        with mock.patch.object(bridge, "api", api), self.assertRaises(bridge.ReplyRoutingError) as raised:
            bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

        self.assertEqual(state, before)
        self.assertTrue(raised.exception.retryable)
        api.assert_called_once()

    def test_ambiguous_batch_anchor_response_fails_closed_with_one_lookup(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        before = json.loads(json.dumps(state))
        api = mock.Mock(return_value={"result": "success", "msg": "", "messages": []})
        message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}

        with mock.patch.object(bridge, "api", api), self.assertRaises(bridge.ReplyRoutingError) as raised:
            bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

        self.assertEqual(state, before)
        self.assertFalse(raised.exception.retryable)
        api.assert_called_once()

    def test_retryable_anchor_failure_is_retried_on_next_poll_without_premature_seen_write(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        message = {
            "id": 51,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Renamed",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        anchor_api = mock.Mock(
            side_effect=[RuntimeError("temporary"), zulip_success(message=message), zulip_success(messages={})]
        )
        worker = mock.Mock(return_value="new-session")
        saved: list[dict] = []
        sleeps = 0
        clock = [100.0]

        def stop_after_completion_poll(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            clock[0] += 1000
            if sleeps == 3:
                raise StopIteration("completion poll complete")

        with (
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"},
            ),
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "api", anchor_api),
            mock.patch.object(bridge, "handle_message", worker),
            mock.patch.object(bridge, "save_json", side_effect=lambda _path, value: saved.append(json.loads(json.dumps(value)))),
            mock.patch.object(bridge.time, "time", side_effect=lambda: clock[0]),
            mock.patch.object(bridge.time, "sleep", side_effect=stop_after_completion_poll),
            self.assertRaisesRegex(StopIteration, "completion poll complete"),
        ):
            bridge._main()

        self.assertEqual(anchor_api.call_count, 3)
        worker.assert_called_once()
        self.assertTrue(any(item["origin_message_id"] == 51 for snapshot in saved for item in snapshot["origin_retries"]))
        self.assertIn(51, saved[-1]["seen_ids"])

    def test_batch_anchor_response_requires_explicit_success_result(self) -> None:
        for payload in ({"msg": "", "messages": {}}, {"result": {"status": "success"}, "msg": "", "messages": {}}):
            state = {"topic_sessions": {}}
            self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
            before = json.loads(json.dumps(state))
            api = mock.Mock(return_value=payload)
            message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}

            with self.subTest(payload=payload), mock.patch.object(bridge, "api", api), self.assertRaises(bridge.ReplyRoutingError):
                bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

            self.assertEqual(state, before)
            api.assert_called_once()

    def test_batch_anchor_response_requires_exact_empty_msg(self) -> None:
        for payload in (
            {"result": "success", "messages": {}},
            {"result": "success", "msg": "not empty", "messages": {}},
            {"result": "success", "msg": None, "messages": {}},
        ):
            state = {"topic_sessions": {}}
            self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
            before = json.loads(json.dumps(state))
            api = mock.Mock(return_value=payload)
            message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}

            with self.subTest(payload=payload), mock.patch.object(bridge, "api", api), self.assertRaises(bridge.ReplyRoutingError):
                bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

            self.assertEqual(state, before)
            api.assert_called_once()

    def test_batch_anchor_response_rejects_ignored_route_parameters(self) -> None:
        for ignored in (["narrow"], ["msg_ids"], "narrow"):
            state = {"topic_sessions": {}}
            self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
            before = json.loads(json.dumps(state))
            api = mock.Mock(
                return_value={
                    "result": "success",
                    "msg": "",
                    "messages": {"50": narrow_match()},
                    "ignored_parameters_unsupported": ignored,
                }
            )
            message = {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"}

            with self.subTest(ignored=ignored), mock.patch.object(bridge, "api", api), self.assertRaises(bridge.ReplyRoutingError):
                bridge.resolve_session(message, {}, state, "example", {"site": "https://zulip.example.com"})

            self.assertEqual(state, before)
            api.assert_called_once()

    def test_duplicate_manifest_canonical_route_conflict_does_not_mutate_state(self) -> None:
        entries = [
            {"stream_id": "1", "topic": "Topic", "session_id": "s1"},
            {"stream_id": "1", "topic": "✔ Topic", "session_id": "s2"},
        ]
        state = {"topic_sessions": {"untouched": "session"}}
        before = json.loads(json.dumps(state))

        with self.assertRaises(bridge.ReplyRoutingError):
            bridge.load_aliases(entries)
        with self.assertRaises(bridge.ReplyRoutingError):
            bridge.apply_alias_repairs(state, entries, "example")

        self.assertEqual(state, before)

    def test_duplicate_manifest_variants_for_same_session_are_valid(self) -> None:
        entries = [
            {"stream_id": "1", "stream": "hermes", "topic": "Topic", "session_id": "s1"},
            {"stream_id": "1", "stream": "hermes", "topic": "✔ Topic", "session_id": "s1"},
        ]
        aliases = bridge.load_aliases(entries)
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=1, stream_id=1, topic="Existing", session_id="s1")

        bridge.apply_alias_repairs(state, entries, "example")

        self.assertEqual(aliases[("1", "topic")], "s1")
        self.assertEqual(aliases[("1", "✔ topic")], "s1")
        self.assertEqual(len(state["zulip_threads"]), 1)
        self.assertEqual(
            set(state["topic_sessions"].values()),
            {"s1"},
        )

    def test_alias_repair_preserves_job_inserted_after_ownership_snapshot(self) -> None:
        state = {"topic_sessions": {}, "reply_reconciliations": []}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Source", session_id="s1")
        job = {
            "origin_message_id": 44,
            "sent_message_id": 900,
            "realm": "example",
            "source_thread_id": source["thread_id"],
            "session_id": "s1",
            "confirmed_stream_id": 1,
            "confirmed_stream": "hermes",
            "confirmed_topic": "Source",
            "attempts": 0,
            "created_at": 1.0,
            "next_attempt_at": 1.0,
        }
        original_note = bridge.note_topic_session

        def insert_job(candidate: dict, conversation: dict, session_id: str) -> bool:
            state["reply_reconciliations"].append(job)
            return original_note(candidate, conversation, session_id)

        with mock.patch.object(bridge, "note_topic_session", side_effect=insert_job):
            bridge.apply_alias_repairs(
                state,
                [{"stream_id": "1", "stream": "hermes", "topic": "Target", "session_id": "s1"}],
                "example",
            )

        self.assertEqual(state["reply_reconciliations"], [job])

    def test_alias_repair_preserves_job_removal_after_ownership_snapshot(self) -> None:
        state = {"topic_sessions": {}, "reply_reconciliations": []}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Source", session_id="s1")
        state["reply_reconciliations"].append(
            {
                "origin_message_id": 44,
                "sent_message_id": 900,
                "realm": "example",
                "source_thread_id": source["thread_id"],
                "session_id": "s1",
                "confirmed_stream_id": 1,
                "confirmed_stream": "hermes",
                "confirmed_topic": "Source",
                "attempts": 0,
                "created_at": 1.0,
                "next_attempt_at": 1.0,
            }
        )
        original_note = bridge.note_topic_session

        def remove_job(candidate: dict, conversation: dict, session_id: str) -> bool:
            state["reply_reconciliations"].clear()
            return original_note(candidate, conversation, session_id)

        with mock.patch.object(bridge, "note_topic_session", side_effect=remove_job):
            bridge.apply_alias_repairs(
                state,
                [{"stream_id": "1", "stream": "hermes", "topic": "Target", "session_id": "s1"}],
                "example",
            )

        self.assertEqual(state["reply_reconciliations"], [])

    def test_alias_repair_cas_detects_newer_same_owner_route_metadata(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Source", session_id="s1")
        newer = bridge.resolve_zulip_conversation_key(
            {"id": 99, "stream_id": 1, "display_recipient": "renamed-stream", "topic": "Source"},
            "example",
            thread_id=source["thread_id"],
        )
        original_note = bridge.note_topic_session

        def publish_newer_route(candidate: dict, conversation: dict, session_id: str) -> bool:
            self.assertTrue(bridge.note_bridge_thread(state, newer, session_id="s1"))
            return original_note(candidate, conversation, session_id)

        with mock.patch.object(bridge, "note_topic_session", side_effect=publish_newer_route), self.assertRaisesRegex(
            bridge.ReplyRoutingError, "ownership changed"
        ):
            bridge.apply_alias_repairs(
                state,
                [{"stream_id": "1", "stream": "stream-1", "topic": "Target", "session_id": "s1"}],
                "example",
            )

        thread = state["zulip_threads"][source["thread_id"]]
        self.assertEqual((thread["stream"], thread["last_seen_message_id"]), ("renamed-stream", 99))
        self.assertNotIn(bridge.topic_alias_lookup_key("example", "1", "Target"), state["zulip_topic_aliases"])

    def test_manifest_vs_stored_owner_conflict_stops_routing_without_mutation(self) -> None:
        topic_alias = bridge.topic_alias_lookup_key("example", "1", "Topic")
        legacy_alias = f"1:{bridge.topic_key('1', 'Topic')}"
        state = {
            "realm": "example",
            "topic_sessions": {legacy_alias: "stored-session"},
            "zulip_topic_aliases": {topic_alias: "stored-thread"},
            "zulip_threads": {
                "stored-thread": {
                    "thread_id": "stored-thread",
                    "conversation_key": "opaque-stored-key",
                    "realm": "example",
                    "stream_id": "1",
                    "session_id": "stored-session",
                }
            },
        }
        entries = [{"stream_id": "1", "topic": "Topic", "session_id": "manifest-session"}]
        aliases = bridge.load_aliases(entries)
        message = {"id": 10, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Topic"}
        before = json.loads(json.dumps(state))

        with self.assertRaises(bridge.ReplyRoutingError):
            bridge.resolve_session(message, aliases, state, "example")
        self.assertEqual(state, before)
        with self.assertRaises(bridge.ReplyRoutingError):
            bridge.apply_alias_repairs(state, entries, "example")
        self.assertEqual(state, before)

    def test_conflicting_manifest_stops_main_before_any_hermes_worker(self) -> None:
        entries = [
            {"stream_id": "1", "topic": "Topic", "session_id": "s1"},
            {"stream_id": "1", "topic": "✔ Topic", "session_id": "s2"},
        ]
        worker = mock.Mock()

        with (
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test"},
            ),
            mock.patch.object(bridge, "load_json", return_value={"seen_ids": [], "topic_sessions": {}}),
            mock.patch.object(bridge, "load_alias_entries", return_value=entries),
            mock.patch.object(bridge, "handle_message", worker),
            self.assertRaises(bridge.ReplyRoutingError),
        ):
            bridge._main()

        worker.assert_not_called()

    def test_conflicting_legacy_resolved_topics_remain_distinct_and_unchanged(self) -> None:
        topic_key = f"1:{bridge.topic_key('1', 'Topic')}"
        resolved_key = f"1:{bridge.topic_key('1', '✔ Topic')}"
        state = {"realm": "example", "topic_sessions": {topic_key: "s1", resolved_key: "s2"}}
        before = json.loads(json.dumps(state))

        session_id, topic = bridge.resolve_session(
            {"id": 10, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Topic"},
            {},
            state,
            "example",
        )
        resolved_session_id, resolved = bridge.resolve_session(
            {"id": 11, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "✔ Topic"},
            {},
            state,
            "example",
        )

        self.assertEqual((session_id, resolved_session_id), ("s1", "s2"))
        self.assertNotEqual(topic["conversation_key"], resolved["conversation_key"])
        self.assertEqual(state, before)

    def test_reply_refuses_topic_owned_by_another_session_without_mutation(self) -> None:
        source_key = bridge.topic_alias_lookup_key("example", "1", "Source")
        target_key = bridge.topic_alias_lookup_key("example", "1", "Target")
        target_legacy_key = f"1:{bridge.topic_key('1', 'Target')}"
        state = {
            "realm": "example",
            "topic_sessions": {target_legacy_key: "s2"},
            "zulip_topic_aliases": {source_key: "source-thread", target_key: "target-thread"},
            "zulip_threads": {
                "source-thread": {"realm": "example", "session_id": "s1", "conversation_key": "opaque-source-key"},
                "target-thread": {"realm": "example", "session_id": "s2", "conversation_key": "opaque-target-key"},
            },
        }
        before = json.loads(json.dumps(state))
        posts: list[dict] = []
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Source",
            "_zulip_state": state,
            "_zulip_signing_key": SIGNING_KEY,
            "_zulip_bridge": {
                "realm": "example",
                "thread_id": "source-thread",
                "conversation_key": "opaque-source-key",
                "session_id": "s1",
                "topic_aliases": ["Source"],
            },
        }

        def fake_api(_rc: dict, method: str, _path: str, **kwargs: object) -> dict:
            if method == "GET":
                return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "✔ Target"})
            posts.append(dict(kwargs.get("data") or {}))
            return zulip_success(id=900)

        with mock.patch.object(bridge, "api", fake_api), self.assertRaises(bridge.ReplyRoutingError):
            bridge.reply({"site": "https://zulip.example.com"}, message, "source-session output")

        self.assertEqual(posts, [])
        self.assertEqual(message["topic"], "Source")
        self.assertEqual(message["_zulip_bridge"]["topic_aliases"], ["Source"])
        self.assertEqual(state, before)

    def test_reply_refuses_stale_same_owner_alias_with_foreign_renamed_live_anchor(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Source", session_id="s1")
        self.seed_topic(state, message_id=60, stream_id=1, topic="Other", session_id="s2")
        state["zulip_topic_aliases"][
            bridge.topic_alias_lookup_key("example", "1", "Renamed out of band")
        ] = source["thread_id"]
        state["topic_sessions"][
            f"1:{bridge.topic_key('1', 'Renamed out of band')}"
        ] = "s1"
        before = json.loads(json.dumps(state))
        calls: list[tuple[str, str]] = []
        posts: list[dict] = []
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Source",
            "_zulip_state": state,
            "_zulip_signing_key": SIGNING_KEY,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            calls.append((method, path))
            if method == "GET" and path == "/api/v1/messages/44":
                return zulip_success(
                    message={
                        "id": 44,
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes",
                        "topic": "Renamed out of band",
                    }
                )
            if method == "GET" and path == "/api/v1/messages/matches_narrow":
                params = dict(kwargs.get("params") or {})
                self.assertEqual(params["msg_ids"], [44, 60])
                return {"result": "success", "msg": "", "messages": {"60": narrow_match()}}
            if method == "POST":
                posts.append(dict(kwargs.get("data") or {}))
                return zulip_success(id=900)
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", fake_api), self.assertRaises(bridge.ReplyRoutingError):
            bridge.reply({"site": "https://zulip.example.com"}, message, "source-session output")

        self.assertEqual(
            calls,
            [
                ("GET", "/api/v1/messages/44"),
                ("GET", "/api/v1/messages/matches_narrow"),
            ],
        )
        self.assertEqual(posts, [])
        self.assertEqual(state, before)

    def test_reply_refuses_same_live_thread_when_worker_and_stored_sessions_differ(self) -> None:
        source_key = bridge.topic_alias_lookup_key("example", "1", "Source")
        state = {
            "realm": "example",
            "topic_sessions": {},
            "zulip_topic_aliases": {source_key: "source-thread"},
            "zulip_threads": {
                "source-thread": {
                    "realm": "example",
                    "stream_id": "1",
                    "session_id": "s2",
                    "last_seen_message_id": 44,
                }
            },
        }
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Source",
            "_zulip_state": state,
            "_zulip_signing_key": SIGNING_KEY,
            "_zulip_bridge": {
                "realm": "example",
                "thread_id": "source-thread",
                "session_id": "s1",
                "topic_aliases": ["Source"],
            },
        }
        calls: list[tuple[str, str]] = []

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            calls.append((method, path))
            if method == "GET" and path == "/api/v1/messages/44":
                return zulip_success(
                    message={
                        "id": 44,
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes-renamed",
                        "topic": "Renamed",
                    }
                )
            if method == "GET" and path == "/api/v1/messages/matches_narrow":
                return {"result": "success", "msg": "", "messages": {"44": narrow_match()}}
            raise AssertionError("session mismatch must fail before POST")

        with mock.patch.object(bridge, "api", fake_api), self.assertRaises(bridge.ReplyRoutingError):
            bridge.reply({"site": "https://zulip.example.com"}, message, "unsafe")

        self.assertEqual(calls, [("GET", "/api/v1/messages/44")])

    def test_reply_fails_closed_when_owner_publishes_during_anchor_io(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Source", session_id="s1")
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Source",
            "_zulip_state": state,
            "_zulip_signing_key": SIGNING_KEY,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }
        anchor_started = threading.Event()
        release_anchor = threading.Event()
        posts: list[dict] = []
        errors: list[Exception] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            if method == "GET" and path == "/api/v1/messages/44":
                return zulip_success(
                    message={
                        "id": 44,
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "hermes",
                        "topic": "Renamed",
                    }
                )
            if method == "GET" and path == "/api/v1/messages/matches_narrow":
                anchor_started.set()
                self.assertTrue(release_anchor.wait(1))
                return {"result": "success", "msg": "", "messages": {"44": narrow_match()}}
            if method == "POST":
                posts.append(dict(kwargs.get("data") or {}))
                return zulip_success(id=900)
            raise AssertionError((method, path))

        def send_reply() -> None:
            try:
                bridge.reply({"site": "https://zulip.example.com"}, message, "unsafe")
            except Exception as exc:
                errors.append(exc)

        with mock.patch.object(bridge, "api", fake_api):
            worker = threading.Thread(target=send_reply)
            worker.start()
            self.assertTrue(anchor_started.wait(1))
            foreign = bridge.resolve_zulip_conversation_key(
                {"id": 60, "stream_id": 1, "display_recipient": "hermes", "topic": "Renamed"},
                "example",
                thread_id="foreign-thread",
            )
            self.assertTrue(bridge.note_bridge_thread(state, foreign, session_id="s2"))
            self.assertTrue(bridge.note_topic_session(state, foreign, "s2"))
            release_anchor.set()
            worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(posts, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], bridge.ReplyRoutingError)

    def test_reconciliation_reservation_blocks_publication_during_patch_and_releases(self) -> None:
        for patch_fails in (False, True):
            with self.subTest(patch_fails=patch_fails):
                state = {"topic_sessions": {}}
                source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
                message = {
                    "id": 44,
                    "type": "stream",
                    "stream_id": 1,
                    "display_recipient": "hermes",
                    "topic": "Before",
                    "_zulip_state": state,
                    "_zulip_bridge": {**source, "session_id": "s1"},
                    "_zulip_signing_key": SIGNING_KEY,
                }
                foreign = bridge.resolve_zulip_conversation_key(
                    {"id": 60, "stream_id": 1, "display_recipient": "hermes", "topic": "After"},
                    "example",
                    thread_id="foreign-thread",
                )
                origin_gets = 0
                patch_started = threading.Event()
                release_patch = threading.Event()
                publication_done = threading.Event()
                publication_results: list[bool] = []
                reply_errors: list[Exception] = []
                patch_attempts = 0

                def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                    nonlocal origin_gets, patch_attempts
                    if method == "GET" and path == "/api/v1/messages/44":
                        origin_gets += 1
                        topic = "Before" if origin_gets == 1 else "After"
                        return zulip_success(
                            message={
                                "id": 44,
                                "type": "stream",
                                "stream_id": 1,
                                "display_recipient": "hermes",
                                "topic": topic,
                            }
                        )
                    if method == "GET" and path == "/api/v1/messages/900":
                        return zulip_success(message=bot_message(900, 1, "Before"))
                    if method == "GET" and path == "/api/v1/messages/matches_narrow":
                        return {"result": "success", "msg": "", "messages": {"44": narrow_match()}}
                    if method == "POST" and path == "/api/v1/messages":
                        return zulip_success(id=900)
                    if method == "PATCH" and path == "/api/v1/messages/900":
                        patch_attempts += 1
                        patch_started.set()
                        if not release_patch.wait(2):
                            raise AssertionError("test did not release PATCH")
                        if patch_fails:
                            raise RuntimeError("move denied")
                        return zulip_success()
                    raise AssertionError((method, path))

                def reconcile_reply() -> None:
                    try:
                        bridge.reconcile_pending_replies(
                            {"site": "https://zulip.example.com", "email": "bot@example.com", "key": BOT_KEY},
                            state,
                            SIGNING_KEY,
                            persist=lambda: None,
                        )
                    except Exception as exc:
                        reply_errors.append(exc)

                def publish_foreign_owner() -> None:
                    try:
                        publication_results.append(bridge.note_bridge_thread(state, foreign, session_id="s2"))
                        publication_results.append(bridge.note_topic_session(state, foreign, "s2"))
                    finally:
                        publication_done.set()

                reply_worker = threading.Thread(target=reconcile_reply)
                publisher = threading.Thread(target=publish_foreign_owner)
                with mock.patch.object(bridge, "api", fake_api):
                    bridge.reply({"site": "https://zulip.example.com", "key": BOT_KEY}, message, "answer")
                    reply_worker.start()
                    patch_was_started = patch_started.wait(1)
                    publication_completed_during_patch = False
                    try:
                        if patch_was_started:
                            publisher.start()
                            publication_completed_during_patch = publication_done.wait(1)
                    finally:
                        release_patch.set()
                        reply_worker.join(1)
                        if publisher.ident is not None:
                            publisher.join(1)

                self.assertTrue(patch_was_started)
                self.assertTrue(publication_completed_during_patch)
                self.assertFalse(reply_worker.is_alive())
                self.assertFalse(publisher.is_alive())
                self.assertEqual(publication_results, [False, False])
                self.assertEqual(reply_errors, [])
                self.assertEqual(patch_attempts, 1)
                self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)
                self.assertEqual(bridge.note_bridge_thread(state, foreign, session_id="s2"), patch_fails)
                self.assertEqual(bridge.note_topic_session(state, foreign, "s2"), patch_fails)

    def test_thread_location_and_last_seen_do_not_rewind_on_older_completion(self) -> None:
        state = {"topic_sessions": {}}
        newer = bridge.resolve_zulip_conversation_key(
            {"id": 20, "stream_id": 2, "display_recipient": "new-stream", "topic": "New"},
            "example",
            thread_id="thread",
        )
        older = bridge.resolve_zulip_conversation_key(
            {"id": 10, "stream_id": 1, "display_recipient": "old-stream", "topic": "Old"},
            "example",
            thread_id="thread",
        )
        bridge.note_bridge_thread(state, newer, session_id="new-session")
        bridge.note_bridge_thread(state, older, session_id="old-session")

        thread = state["zulip_threads"]["thread"]
        self.assertEqual(thread["current_display_topic"], "New")
        self.assertEqual(thread["stream"], "new-stream")
        self.assertEqual(thread["stream_id"], "2")
        self.assertEqual(thread["last_seen_message_id"], 20)
        self.assertEqual(thread["session_id"], "new-session")

    def test_legacy_exact_resolved_topic_state_remains_readable_and_adds_canonical_aliases(self) -> None:
        exact = "✔ Legacy"
        state = {"realm": "example", "topic_sessions": {f"1:{bridge.topic_key('1', exact)}": "s1"}}
        message = {"id": 10, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Legacy"}

        session_id, conversation = bridge.resolve_session(message, {}, state, "example")
        resolved_session, resolved = bridge.resolve_session({**message, "id": 11, "topic": exact}, {}, state, "example")

        self.assertEqual((session_id, resolved_session), ("s1", "s1"))
        self.assertEqual(resolved["conversation_key"], conversation["conversation_key"])
        self.assertEqual(state["topic_sessions"][f"1:{bridge.topic_key('1', 'Legacy')}"], "s1")
        self.assertEqual(
            state["zulip_topic_aliases"][bridge.topic_alias_lookup_key("example", "1", "Legacy")],
            conversation["thread_id"],
        )

    def test_should_process_uses_configurable_ignore_patterns(self) -> None:
        original_streams = bridge.ALLOW_STREAMS
        original_stream_ids = bridge.ALLOW_STREAM_IDS
        original_topics = bridge.ALLOW_TOPICS
        original_patterns = bridge.IGNORE_CONTENT_PATTERNS
        message = {
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Allowed",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "archive-import: archived note",
        }
        try:
            bridge.ALLOW_STREAMS = set()
            bridge.ALLOW_STREAM_IDS = {"1"}
            bridge.ALLOW_TOPICS = set()
            bridge.IGNORE_CONTENT_PATTERNS = []
            self.assertTrue(bridge.should_process(message, "bot@example.com"))
            bridge.IGNORE_CONTENT_PATTERNS = ["archive-import:"]
            self.assertFalse(bridge.should_process(message, "bot@example.com"))
        finally:
            bridge.ALLOW_STREAMS = original_streams
            bridge.ALLOW_STREAM_IDS = original_stream_ids
            bridge.ALLOW_TOPICS = original_topics
            bridge.IGNORE_CONTENT_PATTERNS = original_patterns

    def test_active_steering_is_seen_only_after_success(self) -> None:
        seen: set[int] = set()
        active = {"key": {2: (10, "thread"), 3: (10, "thread")}}

        bridge.finish_active_message(seen, active, "key", 1, ok=False)
        self.assertEqual(seen, {1})
        self.assertEqual(active, {})

        active = {}
        self.assertTrue(bridge.remember_active_steering(active, "key", 4, 10, "thread"))
        self.assertFalse(bridge.remember_active_steering(active, "key", 4, 10, "thread"))
        with self.assertRaises(bridge.StatePersistenceError):
            bridge.remember_active_steering(active, "key", 4, 11, "thread")
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
        state: dict = {}
        bridge._admit_origin(state, 222, now=1.0)
        message = {
            "id": 222,
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "t",
            "content": "/goal status",
            "_zulip_state": state,
            "_zulip_persist": lambda: None,
        }
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
        original_validate = bridge.validated_active_steering_message
        original_hard_interrupt = bridge.HARD_INTERRUPT_ON_STEERING
        calls: list[tuple[str, object]] = []
        seen: set[int] = set()
        active_steering: dict[str, set[int]] = {}
        rc = {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
        message, _state = self.admitted_message(
            {"id": 222, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "stop now"}
        )
        conversation = {"conversation_key": "zulip:example:1:t", "thread_id": "thread"}

        try:
            bridge.HARD_INTERRUPT_ON_STEERING = True
            bridge.ACTIVE_PROCESSES[111] = mock.Mock(poll=mock.Mock(return_value=None))
            bridge.store_steering_message = lambda _rc, _msg, _conversation, active_id: calls.append(("store", active_id))
            bridge.validated_active_steering_message = lambda _rc, current: current
            bridge.interrupt_active_message = lambda active_id: calls.append(("interrupt", active_id)) or True

            bridge.handle_active_topic_message(rc, message, "s1", conversation, 111, active_steering, seen)
        finally:
            bridge.store_steering_message = original_store
            bridge.interrupt_active_message = original_interrupt
            bridge.validated_active_steering_message = original_validate
            bridge.HARD_INTERRUPT_ON_STEERING = original_hard_interrupt
            bridge.ACTIVE_PROCESSES.pop(111, None)

        self.assertEqual(calls, [("store", 111), ("interrupt", 111)])
        self.assertEqual(seen, set())
        self.assertEqual(active_steering, {"zulip:example:1:t": {222: (111, "thread")}})

    def test_interrupt_active_message_marks_and_terminates_process_group(self) -> None:
        calls: list[tuple[int, int]] = []
        original_killpg = bridge.os.killpg
        original_processes = dict(bridge.ACTIVE_PROCESSES)
        original_interrupts = dict(bridge.ACTIVE_INTERRUPTS)
        original_descendants = dict(bridge.ACTIVE_DESCENDANTS)
        original_identities = dict(bridge.ACTIVE_PROCESS_IDENTITIES)

        class FakeProc:
            pid = 12345

            def poll(self) -> None:
                return None

        try:
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_INTERRUPTS.clear()
            proc = FakeProc()
            bridge.ACTIVE_PROCESSES[777] = proc
            bridge.ACTIVE_DESCENDANTS[12345] = set()
            bridge.ACTIVE_PROCESS_IDENTITIES[12345] = "birth"
            bridge.os.killpg = lambda pid, sig: calls.append((pid, sig))

            with mock.patch.object(
                bridge, "_local_process_table", return_value={12345: (1, 12345, "birth")}
            ):
                self.assertTrue(bridge.interrupt_active_message(777))
            self.assertTrue(bridge.pop_active_interrupt(777))
        finally:
            bridge.os.killpg = original_killpg
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_PROCESSES.update(original_processes)
            bridge.ACTIVE_INTERRUPTS.clear()
            bridge.ACTIVE_INTERRUPTS.update(original_interrupts)
            bridge.ACTIVE_DESCENDANTS.clear()
            bridge.ACTIVE_DESCENDANTS.update(original_descendants)
            bridge.ACTIVE_PROCESS_IDENTITIES.clear()
            bridge.ACTIVE_PROCESS_IDENTITIES.update(original_identities)

        self.assertEqual(calls, [(12345, bridge.signal.SIGTERM)])

    def test_register_active_process_honors_pending_interrupt(self) -> None:
        calls: list[tuple[int, int]] = []
        original_killpg = bridge.os.killpg
        original_processes = dict(bridge.ACTIVE_PROCESSES)
        original_interrupts = dict(bridge.ACTIVE_INTERRUPTS)

        class FakeProc:
            pid = 22222

            def poll(self) -> None:
                return None

        try:
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_INTERRUPTS.clear()
            proc = FakeProc()
            bridge.ACTIVE_INTERRUPTS[888] = proc
            bridge.os.killpg = lambda pid, sig: calls.append((pid, sig))

            with mock.patch.object(bridge, "_process_birth_identity", return_value="birth"), mock.patch.object(
                bridge, "_local_process_table", return_value={22222: (1, 22222, "birth")}
            ):
                self.assertTrue(bridge.register_active_process(888, proc))
            self.assertTrue(bridge.pop_active_interrupt(888))
        finally:
            bridge.os.killpg = original_killpg
            bridge.ACTIVE_PROCESSES.clear()
            bridge.ACTIVE_PROCESSES.update(original_processes)
            bridge.ACTIVE_INTERRUPTS.clear()
            bridge.ACTIVE_INTERRUPTS.update(original_interrupts)

        self.assertEqual(calls, [(22222, bridge.signal.SIGTERM)])

    def test_interrupt_generation_replacement_and_stale_unregister_are_isolated(self) -> None:
        old = mock.Mock(pid=1001)
        new = mock.Mock(pid=1002)
        old.poll.return_value = None
        new.poll.return_value = None
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_INTERRUPTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_process_birth_identity", side_effect=lambda pid: f"birth-{pid}"),
            mock.patch.object(bridge, "terminate_process", return_value=True),
        ):
            bridge.register_active_process(77, old)
            self.assertTrue(bridge.interrupt_active_message(77))
            self.assertIs(bridge.ACTIVE_INTERRUPTS[77], old)

            bridge.register_active_process(77, new)
            self.assertNotIn(77, bridge.ACTIVE_INTERRUPTS)
            self.assertTrue(bridge.interrupt_active_message(77))
            self.assertIs(bridge.ACTIVE_INTERRUPTS[77], new)

            self.assertTrue(bridge.unregister_active_process(77, old))
            self.assertIs(bridge.ACTIVE_PROCESSES[77], new)
            self.assertIs(bridge.ACTIVE_INTERRUPTS[77], new)
            self.assertTrue(bridge.unregister_active_process(77, new))
            self.assertFalse(bridge.unregister_active_process(77, new))
            self.assertEqual(
                (bridge.ACTIVE_PROCESSES, bridge.ACTIVE_INTERRUPTS, bridge.ACTIVE_DESCENDANTS),
                ({}, {}, {}),
            )

    def test_hard_replacement_rejects_stale_slash_output_without_consuming_new_interrupt(self) -> None:
        events: list[tuple[str, object]] = []

        class Replacement:
            pid = 2002
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

        replacement = Replacement()

        class OldProcess:
            pid = 2001
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def communicate(self, *_args: object, **_kwargs: object) -> tuple[str, str]:
                bridge.register_active_process(88, replacement)
                self_interrupted = bridge.interrupt_active_message(88)
                events.append(("replacement_interrupted", self_interrupted))
                self.returncode = 0
                return json.dumps({"ok": True, "output": "stale output"}) + "\n", ""

        old = OldProcess()

        def terminate(proc: object) -> bool:
            self.assertIs(proc, replacement)
            replacement.returncode = -bridge.signal.SIGTERM
            events.append(("signal", bridge.signal.SIGTERM))
            return True

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_INTERRUPTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge.subprocess, "Popen", return_value=old),
            mock.patch.object(bridge, "_process_birth_identity", side_effect=lambda pid: f"birth-{pid}"),
            mock.patch.object(bridge, "terminate_process", side_effect=terminate),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
        ):
            with self.assertRaises(bridge.HermesInterrupted):
                bridge.run_slash_worker("/status", "s1", 88)
            self.assertIs(bridge.ACTIVE_PROCESSES[88], replacement)
            self.assertIs(bridge.ACTIVE_INTERRUPTS[88], replacement)
            self.assertTrue(bridge.unregister_active_process(88, replacement))
            self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_INTERRUPTS), ({}, {}))
        self.assertEqual(events, [("signal", bridge.signal.SIGTERM), ("replacement_interrupted", True)])

    def test_concurrent_stale_unregister_never_consumes_replacement_interrupt(self) -> None:
        with mock.patch.object(bridge, "_process_birth_identity", return_value="birth"), mock.patch.object(
            bridge, "terminate_process", return_value=True
        ):
            for iteration in range(100):
                old = mock.Mock(pid=3000 + iteration * 2)
                new = mock.Mock(pid=3001 + iteration * 2)
                old.poll.return_value = None
                new.poll.return_value = None
                with mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True), mock.patch.dict(
                    bridge.ACTIVE_INTERRUPTS, {}, clear=True
                ), mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True):
                    bridge.register_active_process(99, old)
                    bridge.register_active_process(99, new)
                    barrier = threading.Barrier(3)
                    stale_results: list[bool] = []
                    interrupt_results: list[bool] = []

                    def stale_unregister() -> None:
                        barrier.wait()
                        stale_results.append(bridge.unregister_active_process(99, old))

                    def interrupt_new() -> None:
                        barrier.wait()
                        interrupt_results.append(bridge.interrupt_active_message(99))

                    threads = [threading.Thread(target=stale_unregister), threading.Thread(target=interrupt_new)]
                    for thread in threads:
                        thread.start()
                    barrier.wait()
                    for thread in threads:
                        thread.join(1)
                        self.assertFalse(thread.is_alive())
                    self.assertEqual(stale_results, [True])
                    self.assertEqual(interrupt_results, [True])
                    self.assertIs(bridge.ACTIVE_INTERRUPTS[99], new)
                    self.assertTrue(bridge.unregister_active_process(99, new))
                    self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_INTERRUPTS), ({}, {}))

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
                    {"id": 1, "stream_id": 1, "display_recipient": "hermes", "topic": "t"},
                    None,
                )
        finally:
            bridge.hermes_reply = original_hermes_reply
            bridge.reply = original_reply
            bridge.add_reaction = original_add_reaction
            bridge.remove_reaction = original_remove_reaction

        self.assertEqual(replies, [])

    def test_handle_message_posts_generic_error_and_redacts_secret_canary_from_logs(self) -> None:
        secret = "SECRET-CANARY-hermes-failure"
        replies: list[str] = []
        logs: list[tuple[object, ...]] = []

        with (
            mock.patch.object(bridge, "hermes_reply", side_effect=RuntimeError(secret)),
            mock.patch.object(bridge, "reply", side_effect=lambda _rc, _message, content: replies.append(content)),
            mock.patch.object(bridge, "add_reaction"),
            mock.patch.object(bridge, "remove_reaction"),
            mock.patch.object(bridge, "log", side_effect=lambda *parts: logs.append(parts)),
            self.assertRaises(RuntimeError),
        ):
            bridge.handle_message(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                {"id": 1, "stream_id": 1, "display_recipient": "hermes", "topic": "t", "content": "hello"},
                None,
            )

        self.assertEqual(replies, [f"{bridge.BOT_NAME} bridge error. Please try again."])
        self.assertNotIn(secret, repr(replies))
        self.assertNotIn(secret, repr(logs))
        self.assertIn(("reply_failed", 1, "RuntimeError"), logs)

    @mock.patch.dict(sys.modules, {"hermes_cli.commands": None})
    def test_parse_known_slash_command_uses_fallback_registry(self) -> None:
        self.assertEqual(bridge.parse_known_slash_command("/goal build it"), ("goal", "goal", "build it"))
        self.assertEqual(bridge.parse_known_slash_command("/reload_mcp"), ("reload_mcp", "reload-mcp", ""))
        self.assertEqual(bridge.parse_known_slash_command("  /goal status  "), ("goal", "goal", "status"))
        self.assertEqual(bridge.parse_known_slash_command("\t/reset now\t"), ("reset", "reset", "now"))
        for content in (
            "`/goal status`",
            "<p>/goal status</p>",
            "Let's test... /goal status",
            "Can I use /goal status?",
            "before\n/reset",
            "/status\nafter",
            "> /status",
            "```\n/reset\n```",
            "output:\n/status complete",
        ):
            with self.subTest(content=content):
                self.assertIsNone(bridge.parse_known_slash_command(content))
        self.assertIsNone(bridge.parse_known_slash_command("/definitely-not-real"))

    def test_parse_known_slash_command_keeps_package_names_stable_and_discovers_new_aliases(self) -> None:
        command = mock.Mock()
        command.name = "new"
        registry = mock.Mock(resolve_command=mock.Mock(return_value=command))
        with mock.patch.dict(sys.modules, {"hermes_cli.commands": registry}):
            self.assertEqual(bridge.parse_known_slash_command("/reset now"), ("reset", "reset", "now"))
            self.assertEqual(bridge.parse_known_slash_command("/fresh now"), ("fresh", "new", "now"))

    def test_multiline_or_quoted_slash_text_stays_on_the_ordinary_prompt_path(self) -> None:
        for content in ("prose /reset", "quoted:\n> /status", "```text\n/reset\n```", "/goal status\nmore"):
            message = {"content": content}
            with self.subTest(content=content), mock.patch.object(bridge, "run_slash_worker") as worker:
                self.assertIsNone(bridge.hermes_slash_reply({}, message, "s1"))
                worker.assert_not_called()

    def test_handle_message_routes_known_slash_command_to_worker(self) -> None:
        original_hermes_reply = bridge.hermes_reply
        original_run_slash_worker = bridge.run_slash_worker
        original_reply = bridge.reply
        original_add_reaction = bridge.add_reaction
        original_remove_reaction = bridge.remove_reaction
        replies: list[str] = []

        try:
            bridge.hermes_reply = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slash leaked to prompt"))
            bridge.run_slash_worker = (
                lambda command, session_id, _active_message_id, _message=None: f"ran {command} in {session_id}"
            )
            bridge.reply = lambda _rc, _message, content: replies.append(content)
            bridge.add_reaction = lambda *_args, **_kwargs: None
            bridge.remove_reaction = lambda *_args, **_kwargs: None

            bridge.handle_message(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"},
                user_message(1, 1, "t", stream="hermes", content="/status"),
                "s1",
            )
        finally:
            bridge.hermes_reply = original_hermes_reply
            bridge.run_slash_worker = original_run_slash_worker
            bridge.reply = original_reply
            bridge.add_reaction = original_add_reaction
            bridge.remove_reaction = original_remove_reaction

        self.assertEqual(replies, ["ran /status in s1"])

    def test_owned_slash_rejects_cross_stream_move_before_worker_start(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")
        message = {
            "id": 44,
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "/status",
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }
        moved = {"id": 44, "type": "stream", "stream_id": 2, "display_recipient": "stream-2", "topic": "Topic"}

        with (
            mock.patch.object(bridge, "live_origin_message", return_value=moved),
            mock.patch.object(bridge, "run_slash_worker") as worker,
            self.assertRaises(bridge.ReplyRoutingError),
        ):
            bridge.hermes_slash_reply({}, message, "s1")

        worker.assert_not_called()

    def test_slash_worker_registers_session_process_and_always_reaps(self) -> None:
        captured: dict[str, object] = {}

        class FakeProcess:
            pid = 123456
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def communicate(self, payload: str, timeout: float) -> tuple[str, str]:
                self.assert_registered = bridge.ACTIVE_PROCESSES.get(77) is self
                captured.update(payload=payload, timeout=timeout, registered=self.assert_registered)
                self.returncode = 0
                return json.dumps({"ok": True, "output": "done"}) + "\n", ""

        proc = FakeProcess()

        def popen(_cmd: list[str], **kwargs: object) -> FakeProcess:
            captured["kwargs"] = kwargs
            return proc

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.object(bridge.subprocess, "Popen", side_effect=popen),
        ):
            self.assertEqual(bridge.run_slash_worker("/status", "s1", 77), "done")
            self.assertEqual(bridge.ACTIVE_PROCESSES, {})
        self.assertTrue(captured["registered"])
        self.assertTrue(captured["kwargs"]["start_new_session"])
        self.assertEqual(json.loads(str(captured["payload"])), {"id": 1, "command": "/status"})

    def test_slash_worker_rejects_shutdown_before_start(self) -> None:
        before_start = mock.Mock()
        with (
            mock.patch.object(bridge, "SHUTTING_DOWN", True),
            mock.patch.object(bridge.subprocess, "Popen") as popen,
            self.assertRaises(bridge.HermesInterrupted),
        ):
            bridge.run_slash_worker("/status", None, 77, {"_zulip_before_hermes_start": before_start})
        popen.assert_not_called()
        before_start.assert_not_called()

    def test_live_slash_worker_can_be_hard_interrupted(self) -> None:
        signals: list[tuple[int, int]] = []

        class FakeProcess:
            pid = 234567
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def communicate(self, *_args: object, **_kwargs: object) -> tuple[str, str]:
                self.assert_registered = bridge.ACTIVE_PROCESSES.get(88) is self
                self.assertTrue = bridge.interrupt_active_message(88)
                self.returncode = -bridge.signal.SIGTERM
                return "", ""

        proc = FakeProcess()

        def killpg(pid: int, sig: int) -> None:
            if sig == 0 and proc.returncode is not None:
                raise ProcessLookupError
            if sig != 0:
                signals.append((pid, sig))

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.object(bridge.subprocess, "Popen", return_value=proc),
            mock.patch.object(bridge.os, "killpg", side_effect=killpg),
            mock.patch.object(bridge, "_process_birth_identity", return_value="birth"),
            mock.patch.object(
                bridge, "_local_process_table", return_value={proc.pid: (1, proc.pid, "birth")}
            ),
            self.assertRaises(bridge.HermesInterrupted),
        ):
            bridge.run_slash_worker("/status", "s1", 88)
        self.assertTrue(proc.assert_registered)
        self.assertTrue(proc.assertTrue)
        self.assertEqual(signals, [(proc.pid, bridge.signal.SIGTERM)])
        self.assertNotIn(88, bridge.ACTIVE_PROCESSES)
        self.assertNotIn(88, bridge.ACTIVE_INTERRUPTS)

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

    def test_goal_continuation_updates_reply_owner_when_hermes_resolves_new_session(self) -> None:
        message = {
            "id": 1,
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "t",
            "content": "start",
            "_zulip_bridge": {"session_id": "s1"},
        }
        decisions = iter(
            [
                {"message": "continuing", "should_continue": True, "continuation_prompt": "next"},
                {"message": "done", "should_continue": False},
            ]
        )
        replies: list[tuple[str, str]] = []

        with (
            mock.patch.object(bridge, "goal_decision_after_turn", lambda *_args: next(decisions)),
            mock.patch.object(bridge, "hermes_reply", return_value=("continued", "s2")) as hermes_reply,
            mock.patch.object(
                bridge,
                "reply",
                lambda _rc, routed_message, content: replies.append(
                    (content, str(routed_message["_zulip_bridge"].get("session_id") or ""))
                ),
            ),
        ):
            session_id = bridge.post_goal_turns({}, message, "s1", "first")

        self.assertEqual(session_id, "s2")
        self.assertEqual(replies, [("continuing", "s1"), ("continued", "s2"), ("done", "s2")])
        hermes_reply.assert_called_once()

    def test_missing_goal_manager_does_not_block_normal_turn(self) -> None:
        error = ModuleNotFoundError("No module named 'hermes_cli'", name="hermes_cli")

        with mock.patch.object(bridge, "goal_manager", side_effect=error):
            self.assertIsNone(bridge.goal_decision_after_turn("s1", "answered"))

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
        content_canary = "ARGV_CONTENT_CANARY_7f31d95a"
        topic_canary = "ARGV_TOPIC_CANARY_a84962c1"
        sender_canary = "ARGV_SENDER_CANARY_19ce478b"
        message = {
            "id": 999,
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": topic_canary,
            "sender_full_name": sender_canary,
            "content": content_canary,
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
            "refresh_generation_origin": bridge.refresh_generation_origin,
        }

        class FakeProc:
            pid = 999001
            returncode = 0

            def poll(self) -> int:
                return 0

            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                return "pong\n", ""

        def fake_popen(cmd: list[str], **_kwargs: object) -> FakeProc:
            captured["cmd"] = cmd
            return FakeProc()

        hermes_script = self.python_console_script("raise SystemExit(0)")
        try:
            bridge.HERMES = hermes_script
            bridge.HERMES_EXTRA_ARGS = ["--profile", "hermes", "--toolsets", "coding"]
            bridge.subprocess.Popen = fake_popen
            bridge.topic_history = lambda _rc, _message: ""
            bridge.build_attachment_context = lambda _rc, _content, _directory=None: ""
            bridge.typing_status = lambda *_args, **_kwargs: None
            bridge.find_session_by_marker = lambda _marker: None
            bridge.clean_session_record = lambda *_args, **_kwargs: None
            bridge.set_session_archived = lambda *_args, **_kwargs: None
            bridge.refresh_generation_origin = lambda _rc, _message: {}
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
            bridge.refresh_generation_origin = originals["refresh_generation_origin"]

        self.assertEqual(answer, "pong")
        self.assertIsNone(session_id)
        command = captured["cmd"]
        resolved_script = str(hermes_script.resolve())
        script_index = command.index(resolved_script)
        self.assertEqual(
            command[script_index:],
            [resolved_script, "--profile", "hermes", "--toolsets", "coding", "-z"],
        )
        self.assertEqual(command[1:3], ["-c", bridge._PROCESS_START_GATE])
        for argument in command:
            for private in (content_canary, topic_canary, sender_canary, "active_message_id 999"):
                self.assertNotIn(private, argument)

    def test_direct_runtime_rejects_abbreviated_or_unrestricted_hermes_arguments(self) -> None:
        values = {
            "message": {"id": 1},
            "session_id": None,
            "active_message_id": 1,
            "user_text": "hello",
            "attachment_context": "",
            "history": "",
            "stream": "stream",
            "topic": "topic",
            "sender": "user",
        }
        for args in (
            [],
            ["--toolsets", "all"],
            ["--toolsets", "hermes-cli"],
            ["--toolsets", "coding", "--tools=all"],
            ["--toolsets", "coding", "--yo"],
        ):
            with self.subTest(args=args), mock.patch.object(bridge, "HERMES_EXTRA_ARGS", args), self.assertRaises(
                ValueError
            ):
                bridge._hermes_command(**values)

    def test_terminal_safe_log_fields_escape_controls_and_bound_length(self) -> None:
        hostile = (
            "safe Unicode café\n\r\t\x1b[31m\x1b]2;title\x07\x85"
            + chr(0x202E)
            + chr(0x2028)
            + "x" * 500
        )
        cleaned = bridge.terminal_safe(hostile)
        self.assertTrue(
            cleaned.startswith(
                "safe Unicode café\\u000a\\u000d\\u0009\\u001b[31m"
                "\\u001b]2;title\\u0007\\u0085\\u202e\\u2028"
            )
        )
        self.assertTrue(cleaned.endswith("..."))
        self.assertLessEqual(len(cleaned), bridge.LOG_FIELD_MAX_CHARS)
        self.assertEqual(bridge.terminal_safe("stream-1 / Normal Topic"), "stream-1 / Normal Topic")
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\x1b", cleaned)

        output = io.StringIO()
        with mock.patch("sys.stdout", output), mock.patch.object(bridge.time, "strftime", return_value="timestamp"):
            bridge.log("event", hostile, "normal")
        line = output.getvalue()
        self.assertEqual(line.count("\n"), 1)
        self.assertNotIn("\x1b", line)
        self.assertNotIn("safe Unicode", line)
        self.assertNotIn("normal", line)
        self.assertRegex(line, r"^timestamp event ref:[0-9a-f]{16} ref:[0-9a-f]{16}\n$")

    def test_log_canary_redacts_all_private_operational_values(self) -> None:
        canaries = (
            "Private Stream",
            "Private Topic",
            "session-private-id",
            "goal status private content",
            "https://private.example",
            "bot@private.example",
            "PRIVATE_ENV_ALLOWLIST",
            "/private/runtime/cwd",
            "private prompt text",
            "attachment-private-name.txt",
            "/private/attachment/path",
            "private-api-credential",
        )
        output = io.StringIO()
        with mock.patch("sys.stdout", output), mock.patch.object(
            bridge.time, "strftime", return_value="timestamp"
        ):
            bridge.log("privacy_canary", *canaries)
        rendered = output.getvalue()
        self.assertRegex(rendered, r"^timestamp privacy_canary(?: ref:[0-9a-f]{16}){12}\n$")
        for canary in canaries:
            self.assertNotIn(canary, rendered)
            self.assertNotIn(repr(canary), rendered)

    def test_hermes_timeout_kills_group_reaps_and_unregisters_in_finally(self) -> None:
        message = {
            "id": 77,
            "stream_id": 1,
            "display_recipient": "hermes",
            "topic": "Bridge",
            "content": "wait",
        }
        signals: list[tuple[int, int]] = []

        class FakeProcess:
            pid = 345678
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                if self.returncode is None:
                    raise subprocess.TimeoutExpired("fake", timeout)
                return self.returncode

            def communicate(self, *_args: object, **_kwargs: object) -> tuple[str, str]:
                return "", ""

        proc = FakeProcess()
        launcher_proof = self.launcher_proof()
        clock = iter((0.0, 2.0))

        def monotonic() -> float:
            value = next(clock)
            if value == 2.0:
                bridge.ACTIVE_INTERRUPTS[77] = proc
            return value

        def killpg(pid: int, sig: int) -> None:
            if sig == 0:
                if proc.returncode is not None:
                    raise ProcessLookupError
                return
            signals.append((pid, sig))
            if sig == bridge.signal.SIGKILL:
                proc.returncode = -sig

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.object(bridge.subprocess, "Popen", return_value=proc),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "typing_status"),
            mock.patch.object(bridge, "HERMES_TIMEOUT_SECONDS", 1),
            mock.patch.object(bridge.time, "monotonic", side_effect=monotonic),
            mock.patch.object(bridge.os, "killpg", side_effect=killpg),
            mock.patch.object(bridge, "_process_birth_identity", return_value="birth"),
            mock.patch.object(
                bridge, "_local_process_table", return_value={proc.pid: (1, proc.pid, "birth")}
            ),
            mock.patch.object(bridge, "refresh_generation_origin"),
            self.assertRaisesRegex(RuntimeError, "Hermes timed out"),
        ):
            bridge.hermes_reply({}, {**message, "_zulip_launcher_proof": launcher_proof}, None)
        self.assertEqual(
            signals,
            [(proc.pid, bridge.signal.SIGTERM), (proc.pid, bridge.signal.SIGKILL)],
        )
        self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))
        self.assertNotIn(77, bridge.ACTIVE_INTERRUPTS)

    def test_registered_process_group_cleanup_kills_child_after_leader_exits(self) -> None:
        child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        parent_code = (
            "import subprocess,sys,time; "
            f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "print(child.pid, flush=True); time.sleep(60)"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", parent_code],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        bridge.register_active_process(990, proc)
        child_pid = int(proc.stdout.readline().strip())
        child_birth = bridge._process_birth_identity(child_pid)
        self.addCleanup(
            lambda: bridge._signal_pid_if_current(
                child_pid, proc.pid, child_birth, bridge.signal.SIGKILL
            )
        )
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and not bridge._has_registered_descendants(proc):
            time.sleep(0.02)

        bridge.terminate_and_reap_process_group(proc, grace_seconds=0.05)

        self.assertIsNotNone(proc.poll())
        self.assertNotIn(proc.pid, bridge.ACTIVE_DESCENDANTS)
        self.assertNotIn(990, bridge.ACTIVE_PROCESSES)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(child_pid)], capture_output=True, text=True, check=False
            ).stdout.strip()
            if not status or status.startswith("Z"):
                break
            time.sleep(0.02)
        self.assertTrue(not status or status.startswith("Z"), f"descendant {child_pid} survived with status {status}")

    def test_unregistered_cleanup_never_adopts_current_pid_or_descendants(self) -> None:
        proc = mock.Mock(pid=41000, returncode=None)
        proc.poll.return_value = None
        proc.wait.side_effect = subprocess.TimeoutExpired("stale", 0)
        proc.communicate.side_effect = subprocess.TimeoutExpired("stale", 0)
        table = {
            41000: (1, 41000, "replacement"),
            41001: (41000, 41000, "replacement-child"),
        }
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_local_process_table", return_value=table),
            mock.patch.object(bridge.os, "killpg") as killpg,
            mock.patch.object(bridge, "_signal_pid_if_current") as signal_pid,
        ):
            bridge._terminate_and_reap_process_group(proc, grace_seconds=0)
        killpg.assert_not_called()
        signal_pid.assert_not_called()
        proc.terminate.assert_called_once_with()
        proc.kill.assert_called_once_with()

    def test_stale_unregistered_cleanup_cannot_borrow_replacement_registration(self) -> None:
        replacement = mock.Mock(pid=41000, returncode=None)
        replacement.poll.return_value = None
        table = {41000: (1, 41000, "replacement")}

        def stale_process() -> mock.Mock:
            stale = mock.Mock(pid=41000, returncode=None)
            stale.poll.return_value = None
            stale.wait.side_effect = subprocess.TimeoutExpired("stale", 0)
            stale.communicate.side_effect = subprocess.TimeoutExpired("stale", 0)
            return stale

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {77: replacement}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {41000: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {41000: "replacement"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {41000: "replacement"}, clear=True),
            mock.patch.object(bridge, "_local_process_table", return_value=table),
            mock.patch.object(bridge.os, "killpg") as killpg,
        ):
            term_stale = stale_process()
            self.assertTrue(bridge.terminate_process(term_stale))
            term_stale.terminate.assert_called_once_with()
            kill_stale = stale_process()
            bridge._terminate_and_reap_process_group(kill_stale, grace_seconds=0)
            kill_stale.kill.assert_called_once_with()
        killpg.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin kqueue regression")
    def test_no_waitid_late_child_created_at_leader_exit_is_cleaned(self) -> None:
        child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        parent_code = (
            "import subprocess,sys; "
            f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "print(child.pid, flush=True)"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", parent_code],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        bridge.register_active_process(992, proc)
        with mock.patch.object(bridge.os, "waitid", None, create=True):
            stdout, _stderr = bridge._communicate_registered(proc, None, 5)
        child_pid = int(stdout.strip())
        self.assertIsNotNone(proc.returncode)
        self.assertNotIn(proc.pid, bridge.ACTIVE_DESCENDANTS)
        deadline = time.monotonic() + 3
        status = ""
        while time.monotonic() < deadline:
            status = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(child_pid)],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if not status or status.startswith("Z"):
                break
            time.sleep(0.02)
        self.assertTrue(not status or status.startswith("Z"), f"late child {child_pid} survived: {status}")

    def test_registered_cleanup_kills_real_detached_descendant(self) -> None:
        child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        parent_code = (
            "import signal,subprocess,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}], start_new_session=True); "
            "print(child.pid, flush=True); time.sleep(0.3)"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", parent_code],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        bridge.register_active_process(991, proc)
        child_pid = int(proc.stdout.readline().strip())
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and not bridge._has_registered_descendants(proc):
            time.sleep(0.02)

        bridge.terminate_and_reap_process_group(proc, grace_seconds=0.05)
        self.assertNotIn(proc.pid, bridge.ACTIVE_DESCENDANTS)
        self.assertNotIn(991, bridge.ACTIVE_PROCESSES)
        bridge.unregister_active_process(991, proc)

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(child_pid)], capture_output=True, text=True, check=False
            ).stdout.strip()
            if not status or status.startswith("Z"):
                break
            time.sleep(0.02)
        self.assertTrue(not status or status.startswith("Z"), f"detached descendant {child_pid} survived: {status}")

    def test_registered_cleanup_prunes_reused_pid_and_pgid_birth_identity(self) -> None:
        proc = mock.Mock(pid=41000)
        proc.poll.return_value = 0
        killed = mock.Mock()
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {99: proc}, clear=True),
            mock.patch.dict(
                bridge.ACTIVE_DESCENDANTS, {41000: {(42000, 43000, "old-birth")}}, clear=True
            ),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {41000: "root-birth"}, clear=True),
            mock.patch.object(bridge, "_local_process_table", return_value={42000: (1, 43000, "new-birth")}),
            mock.patch.object(bridge.os, "kill", killed),
            mock.patch.object(bridge.os, "killpg", killed),
        ):
            bridge._signal_registered_descendants(proc, bridge.signal.SIGKILL)
            self.assertEqual(bridge.ACTIVE_DESCENDANTS[41000], set())

        killed.assert_not_called()

    def test_unregistered_descendant_snapshots_are_ephemeral(self) -> None:
        proc = mock.Mock(pid=41000)
        proc.poll.return_value = None
        child = (42000, 41000, "child-birth")
        table = {41000: (1, 41000, "root-birth"), child[0]: (41000, child[1], child[2])}
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_local_process_table", return_value=table),
        ):
            self.assertEqual(bridge._snapshot_registered_descendants(proc), {child})
            self.assertEqual(bridge.ACTIVE_DESCENDANTS, {})
            self.assertEqual(bridge._snapshot_registered_descendants(proc, require_registered=True), set())
            self.assertEqual(bridge.ACTIVE_DESCENDANTS, {})

    def test_required_snapshot_rechecks_registration_during_and_after_process_table_collection(self) -> None:
        root_pid = 41000
        child = (42000, root_pid, "child-birth")
        table = {root_pid: (1, root_pid, "root-birth"), child[0]: (root_pid, child[1], child[2])}

        owner = mock.Mock(pid=root_pid)
        owner.poll.return_value = None
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: owner}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {root_pid: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "root-birth"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_local_process_table", return_value=table),
        ):
            registration = bridge.ACTIVE_DESCENDANTS[root_pid]
            self.assertEqual(
                bridge._snapshot_registered_descendants(owner, require_registered=True), {child}
            )
            self.assertIs(bridge.ACTIVE_DESCENDANTS[root_pid], registration)
            self.assertEqual(registration, {child})

        owner = mock.Mock(pid=root_pid)
        owner.poll.return_value = None
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: owner}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {root_pid: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "root-birth"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True),
            mock.patch.object(
                bridge,
                "_local_process_table",
                side_effect=lambda: (bridge.unregister_active_process(1, owner), table)[1],
            ),
        ):
            self.assertEqual(bridge._snapshot_registered_descendants(owner, require_registered=True), set())
            self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))

        owner = mock.Mock(pid=root_pid)
        replacement = mock.Mock(pid=root_pid)
        owner.poll.return_value = None
        replacement.poll.return_value = None

        def replace_during_table() -> dict[int, tuple[int, int, str]]:
            bridge.register_active_process(2, replacement)
            return table

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: owner}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {root_pid: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "root-birth"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_process_birth_identity", return_value="replacement-birth"),
            mock.patch.object(bridge, "_local_process_table", side_effect=replace_during_table),
        ):
            self.assertEqual(bridge._snapshot_registered_descendants(owner, require_registered=True), set())
            self.assertIs(bridge.ACTIVE_PROCESSES[2], replacement)
            self.assertEqual(bridge.ACTIVE_DESCENDANTS[root_pid], set())

        owner = mock.Mock(pid=root_pid)
        replacement = mock.Mock(pid=root_pid)
        replacement.poll.return_value = None
        replaced = False

        def replace_before_merge() -> None:
            nonlocal replaced
            if not replaced:
                replaced = True
                bridge.register_active_process(2, replacement)
            return None

        owner.poll.side_effect = replace_before_merge
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: owner}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {root_pid: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "root-birth"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_process_birth_identity", return_value="replacement-birth"),
            mock.patch.object(bridge, "_local_process_table", return_value=table),
        ):
            self.assertEqual(bridge._snapshot_registered_descendants(owner, require_registered=True), set())
            self.assertIs(bridge.ACTIVE_PROCESSES[2], replacement)
            self.assertEqual(bridge.ACTIVE_DESCENDANTS[root_pid], set())

    def test_process_cleanup_removes_only_its_exact_registration(self) -> None:
        old = mock.Mock(pid=41000, returncode=0)
        new = mock.Mock(pid=41000, returncode=0)
        other = mock.Mock(pid=43000, returncode=0)
        for proc in (old, new, other):
            proc.poll.return_value = 0
            proc.wait.return_value = 0
            proc.communicate.return_value = ("", "")
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_INTERRUPTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_process_birth_identity", side_effect=lambda pid: f"birth-{pid}"),
            mock.patch.object(bridge, "_terminate_and_reap_process_group"),
        ):
            bridge.register_active_process(1, old)
            bridge.ACTIVE_DESCENDANTS[41000] = {(42000, 41000, "old-child")}
            bridge.register_active_process(2, new)
            bridge.ACTIVE_DESCENDANTS[41000] = {(42001, 41000, "new-child")}
            bridge.register_active_process(3, other)
            bridge.ACTIVE_DESCENDANTS[43000] = {(43001, 43000, "other-child")}

            bridge.terminate_and_reap_process_group(old, grace_seconds=0)
            self.assertIs(bridge.ACTIVE_PROCESSES[2], new)
            self.assertEqual(bridge.ACTIVE_DESCENDANTS[41000], {(42001, 41000, "new-child")})
            self.assertEqual(bridge.ACTIVE_DESCENDANTS[43000], {(43001, 43000, "other-child")})

            bridge.terminate_and_reap_process_group(new, grace_seconds=0)
            self.assertNotIn(41000, bridge.ACTIVE_DESCENDANTS)
            self.assertIs(bridge.ACTIVE_PROCESSES[3], other)
            bridge.terminate_and_reap_process_group(other, grace_seconds=0)
            self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))

    def test_process_cleanup_forgets_registration_on_exception_and_missing_pid(self) -> None:
        failed = mock.Mock(pid=41000)
        missing = mock.Mock(pid=None)
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_process_birth_identity", return_value="birth"),
        ):
            bridge.register_active_process(1, failed)
            with mock.patch.object(
                bridge, "_terminate_and_reap_process_group", side_effect=RuntimeError("cleanup failed")
            ), self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                bridge.terminate_and_reap_process_group(failed, grace_seconds=0)
            self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))

            bridge.register_active_process(2, missing)
            with mock.patch.object(bridge, "_terminate_and_reap_process_group"):
                bridge.terminate_and_reap_process_group(missing, grace_seconds=0)
            self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))

    def test_normal_hermes_drains_two_megabytes_from_both_streams_concurrently(self) -> None:
        size = 2_000_000
        hermes_script = self.python_console_script(
            "import sys,threading\n"
            f"chunks=[(sys.stdout,'o'*{size}),(sys.stderr,'e'*{size})]\n"
            "threads=[threading.Thread(target=lambda item: (item[0].write(item[1]),item[0].flush()),args=(item,)) for item in chunks]\n"
            "[thread.start() for thread in threads]\n"
            "[thread.join() for thread in threads]"
        )
        message = {
            "id": 77,
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "content": "go",
        }
        with (
            mock.patch.object(
                bridge,
                "_hermes_command",
                return_value=("marker", [str(hermes_script), "--toolsets", "coding", "-z", "private"]),
            ),
            mock.patch.object(bridge, "HERMES_OUTPUT_MAX_BYTES", size + 1024),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge, "typing_status"),
            mock.patch.object(bridge, "find_session_by_marker", return_value=None),
            mock.patch.object(bridge, "clean_session_record"),
            mock.patch.object(bridge, "set_session_archived"),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
        ):
            answer, session_id = bridge.hermes_reply({}, message, None)
        self.assertEqual((len(answer), set(answer), session_id), (size, {"o"}, None))
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_output_limit_startup_parser_accepts_default_and_boundaries_in_isolated_processes(self) -> None:
        source = str(Path(__file__).parents[1] / "src")
        for label, configured, expected in (
            ("default", None, 4 * 1024 * 1024),
            ("minimum", "1", 1),
            ("explicit default", str(4 * 1024 * 1024), 4 * 1024 * 1024),
            ("maximum", str(64 * 1024 * 1024), 64 * 1024 * 1024),
        ):
            env = {"PYTHONPATH": source, "PYTHONPYCACHEPREFIX": str(Path(self.state_dir.name) / label.replace(" ", "-"))}
            if configured is not None:
                env["HERMES_ZULIP_OUTPUT_MAX_BYTES"] = configured
            completed = subprocess.run(
                [sys.executable, "-c", "from hermes_zulip_bridge.bridge import HERMES_OUTPUT_MAX_BYTES; print(HERMES_OUTPUT_MAX_BYTES)"],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            with self.subTest(label=label):
                self.assertEqual((completed.returncode, completed.stdout.strip()), (0, str(expected)), completed.stderr)

    def test_output_limit_startup_parser_rejects_ambiguous_invalid_and_oversized_values(self) -> None:
        source = str(Path(__file__).parents[1] / "src")
        error = "HERMES_ZULIP_OUTPUT_MAX_BYTES must be a canonical decimal integer from 1 to 67108864 bytes"
        invalid = ("", "0", "-1", "+1", "01", " 1", "1 ", "1\n", "1.0", "0x10", "ten", "67108865", "9" * 1000)
        for value in invalid:
            completed = subprocess.run(
                [sys.executable, "-c", "import hermes_zulip_bridge.bridge; print('bridge-work-started')"],
                text=True,
                capture_output=True,
                env={
                    "PYTHONPATH": source,
                    "PYTHONPYCACHEPREFIX": str(Path(self.state_dir.name) / "invalid"),
                    "HERMES_ZULIP_OUTPUT_MAX_BYTES": value,
                },
                check=False,
            )
            with self.subTest(value=value[:20]):
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("bridge-work-started", completed.stdout)
                self.assertIn(error, completed.stderr)

        startup = subprocess.run(
            [sys.executable, "-m", "hermes_zulip_bridge.bridge", "--demo"],
            text=True,
            capture_output=True,
            env={
                "PYTHONPATH": source,
                "PYTHONPYCACHEPREFIX": str(Path(self.state_dir.name) / "startup"),
                "HERMES_ZULIP_OUTPUT_MAX_BYTES": "0",
            },
            check=False,
        )
        self.assertNotEqual(startup.returncode, 0)
        self.assertIn(error, startup.stderr)
        self.assertNotIn("zulip_bridge_thread_created", startup.stdout)

    def test_slash_worker_drains_large_simultaneous_and_slow_output(self) -> None:
        size = 2_000_000
        code = (
            "import json,sys,threading,time\n"
            f"output='s'*{size}\n"
            "def stdout():\n"
            " data=json.dumps({'ok':True,'output':output})+'\\n'\n"
            " for start in range(0,len(data),8192): sys.stdout.write(data[start:start+8192]); sys.stdout.flush(); time.sleep(.0001)\n"
            "def stderr():\n"
            f" data='e'*{size}\n"
            " for start in range(0,len(data),8192): sys.stderr.write(data[start:start+8192]); sys.stderr.flush(); time.sleep(.0001)\n"
            "threads=[threading.Thread(target=stdout),threading.Thread(target=stderr)]\n"
            "[thread.start() for thread in threads]\n"
            "[thread.join() for thread in threads]"
        )
        with (
            mock.patch.object(bridge, "_slash_worker_command", return_value=[sys.executable, "-c", code]),
            mock.patch.object(bridge, "HERMES_OUTPUT_MAX_BYTES", size + 1024),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
        ):
            output = bridge.run_slash_worker("/status", "s1", 88)
        self.assertEqual((len(output), set(output)), (size, {"s"}))
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_over_limit_normal_and_slash_output_fail_without_deadlock_or_reader_leak(self) -> None:
        limit = 64 * 1024
        hermes_script = self.python_console_script(
            "import sys\nsys.stdout.write('x'*2000000)\nsys.stdout.flush()"
        )
        message = {
            "id": 77,
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "content": "go",
        }
        with (
            mock.patch.object(bridge, "HERMES_OUTPUT_MAX_BYTES", limit),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
            mock.patch.object(bridge, "_hermes_command", return_value=("marker", [str(hermes_script), "--toolsets", "coding", "-z", "private"])),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge, "typing_status"),
            self.assertRaisesRegex(RuntimeError, rf"stdout exceeded the {limit}-byte output limit"),
        ):
            bridge.hermes_reply({}, message, None)

        slash_code = "import sys; sys.stderr.write('e'*2000000); sys.stderr.flush()"
        with (
            mock.patch.object(bridge, "HERMES_OUTPUT_MAX_BYTES", limit),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
            mock.patch.object(bridge, "_slash_worker_command", return_value=[sys.executable, "-c", slash_code]),
            self.assertRaisesRegex(RuntimeError, rf"stderr exceeded the {limit}-byte output limit"),
        ):
            bridge.run_slash_worker("/status", "s1", 88)
        self.assertEqual(bridge.ACTIVE_PROCESSES, {})
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_registered_output_handles_broken_stdin_and_reader_error_without_leaks(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('done', flush=True)"],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = bridge._communicate_registered(proc, "x" * 2_000_000, 5)
        self.assertEqual((stdout, stderr, proc.returncode), ("done\n", "", 0))

        binary = subprocess.Popen(
            [sys.executable, "-c", "import os; os.write(1, b'binary\\xffoutput')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = bridge._communicate_registered(binary, None, 5)
        self.assertEqual((stdout, stderr, binary.returncode), ("binary\ufffdoutput", "", 0))

        class BadStream:
            def read(self, _size: int) -> str:
                raise OSError("read failed")

            def close(self) -> None:
                pass

        reader = bridge._BoundedOutputReader(BadStream(), "stdout", 100)
        reader.start()
        reader.join(1, force=True)
        self.assertIsNotNone(reader.failure("Hermes"))
        self.assertFalse(reader.thread.is_alive())

        class EmptyStream:
            def __init__(self) -> None:
                self.closed = False

            def read(self, _size: int) -> str:
                return ""

            def close(self) -> None:
                self.closed = True

        fake_proc = mock.Mock(stdout=EmptyStream(), stderr=EmptyStream())
        partial = bridge._BoundedProcessOutput(fake_proc)
        partial.readers[1].thread.start = mock.Mock(side_effect=RuntimeError("thread unavailable"))
        with self.assertRaisesRegex(RuntimeError, "thread unavailable"):
            partial.start()
        partial.close(1)
        self.assertFalse(partial.readers[0].thread.is_alive())
        self.assertTrue(fake_proc.stderr.closed)

        unopened = mock.Mock()
        writer = bridge._ProcessInputWriter(unopened, "payload")
        writer.close(1)
        unopened.close.assert_called_once_with()
        failed_close = mock.Mock()
        failed_close.close.side_effect = OSError("close failed")
        bridge._ProcessInputWriter(failed_close, "payload").close(1)

        blocked = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            bridge._communicate_registered(blocked, "x" * 2_000_000, 0.2)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNotNone(blocked.poll())
        self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_shutdown_joins_active_bounded_readers_without_competing_communicate(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import sys,time; sys.stdout.write('x'*2000000); sys.stdout.flush(); time.sleep(5)"],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        bridge.register_active_process(901, proc)
        result: list[BaseException | tuple[str, str]] = []

        def supervise() -> None:
            try:
                result.append(bridge._communicate_registered(proc, None, 10))
            except BaseException as exc:
                result.append(exc)

        worker = threading.Thread(target=supervise)
        worker.start()
        deadline = time.monotonic() + 2
        while not hasattr(proc, "_hermes_bounded_output") and time.monotonic() < deadline:
            time.sleep(0.01)
        try:
            bridge.shutdown_active_processes(grace_seconds=0.1)
            worker.join(2)
        finally:
            bridge.SHUTTING_DOWN = False
            bridge.unregister_active_process(901, proc)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result)
        self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_five_hundred_mixed_cleanup_output_runs_leave_no_registry_or_threads(self) -> None:
        class Process:
            returncode = 0
            stdin = None

            def __init__(self, pid: int, output: str) -> None:
                self.pid = pid
                self.stdout = io.StringIO(output)
                self.stderr = io.StringIO("")

            def poll(self) -> int:
                return 0

            def wait(self, **_kwargs: object) -> int:
                return 0

            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                return "", ""

            def terminate(self) -> None:
                pass

            def kill(self) -> None:
                pass

        class BrokenInput:
            def write(self, _data: str) -> None:
                raise BrokenPipeError

            def close(self) -> None:
                pass

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True),
            mock.patch.object(bridge, "_local_process_table", return_value={}),
            mock.patch.object(bridge, "_process_birth_identity", side_effect=lambda pid: f"birth-{pid}"),
        ):
            for index in range(500):
                proc = Process(45000 + index % 7, f"output-{index}")
                bridge.register_active_process(index + 1, proc)
                if index % 7 == 0:
                    bridge.ACTIVE_INTERRUPTS[index + 1] = proc
                if index % 11 == 0:
                    replacement = Process(46000 + index % 7, f"output-{index}")
                    bridge.register_active_process(index + 1, replacement)
                    proc = replacement
                if index % 2 == 0:
                    output = bridge._BoundedProcessOutput(proc)
                    proc._hermes_bounded_output = output
                    output.start()
                    self.assertEqual(output.finish("Hermes", 1), (f"output-{index}", ""))
                if index % 3 == 0:
                    writer = bridge._ProcessInputWriter(BrokenInput(), "payload")
                    writer.start()
                    writer.close(1)
                    self.assertFalse(writer.thread.is_alive())
                if index % 5 == 0:
                    bridge.unregister_active_process(index + 1, proc)
                elif index % 5 < 4:
                    bridge.terminate_and_reap_process_group(proc, grace_seconds=0)
                if index % 25 == 24:
                    bridge.shutdown_active_processes(grace_seconds=0)
                    bridge.SHUTTING_DOWN = False
            bridge.shutdown_active_processes(grace_seconds=0)
            bridge.SHUTTING_DOWN = False
            self.assertEqual(
                (bridge.ACTIVE_PROCESSES, bridge.ACTIVE_INTERRUPTS, bridge.ACTIVE_DESCENDANTS),
                ({}, {}, {}),
            )
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_process_identity_monitor_failures_fail_closed(self) -> None:
        with mock.patch.object(bridge.ctypes, "CDLL", side_effect=OSError("libproc unavailable")):
            self.assertIsNone(bridge._darwin_process_info(123))
        with mock.patch.object(bridge.Path, "is_file", side_effect=OSError("stat failed")), mock.patch.object(
            bridge, "SYSTEM_PS_PATHS", (Path("/trusted/ps"),)
        ):
            self.assertEqual(bridge._system_ps_path(), "")

        class BrokenPs:
            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                raise OSError("ps read failed")

            def kill(self) -> None:
                raise OSError("ps kill failed")

        with (
            mock.patch.object(bridge.sys, "platform", "generic"),
            mock.patch.object(bridge.Path, "read_text", side_effect=OSError("proc unavailable")),
            mock.patch.object(bridge, "_system_ps_path", return_value="/usr/bin/ps"),
            mock.patch.object(bridge, "SYSTEM_POPEN", return_value=BrokenPs()),
        ):
            self.assertEqual(bridge._process_birth_identity(123), "")
            self.assertEqual(bridge._local_process_table(), {})

    def test_process_signal_failures_never_signal_unverified_instances(self) -> None:
        sender = mock.Mock()
        with mock.patch.object(bridge.os, "pidfd_open", side_effect=OSError("gone"), create=True), mock.patch.object(
            bridge.signal, "pidfd_send_signal", sender, create=True
        ):
            self.assertFalse(bridge._signal_pid_if_current(10, 10, "birth", bridge.signal.SIGTERM))
        sender.assert_not_called()

        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(bridge.os, "pidfd_open", return_value=read_fd, create=True), mock.patch.object(
                bridge.signal, "pidfd_send_signal", sender, create=True
            ), mock.patch.object(bridge, "_local_process_table", return_value={}):
                self.assertFalse(bridge._signal_pid_if_current(10, 10, "birth", bridge.signal.SIGTERM))
        finally:
            os.close(write_fd)
        sender.assert_not_called()

        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(bridge.os, "pidfd_open", return_value=read_fd, create=True), mock.patch.object(
                bridge.signal, "pidfd_send_signal", side_effect=OSError("signal failed"), create=True
            ), mock.patch.object(
                bridge, "_local_process_table", return_value={10: (1, 10, "birth")}
            ):
                self.assertFalse(bridge._signal_pid_if_current(10, 10, "birth", bridge.signal.SIGTERM))
        finally:
            os.close(write_fd)

        proc = mock.Mock(pid=10)
        proc.poll.side_effect = OSError("poll failed")
        with mock.patch.object(bridge.os, "killpg") as killpg:
            self.assertFalse(bridge._signal_group_if_current(proc, 10, "birth", bridge.signal.SIGTERM))
        killpg.assert_not_called()

        proc.poll.side_effect = None
        proc.poll.return_value = None
        with mock.patch.object(
            bridge, "_local_process_table", return_value={10: (1, 10, "birth")}
        ), mock.patch.object(bridge.os, "killpg", side_effect=OSError("signal failed")):
            self.assertFalse(bridge._signal_group_if_current(proc, 10, "birth", bridge.signal.SIGTERM))

        with mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {10: "birth"}, clear=True), mock.patch.dict(
            bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {10: "birth"}, clear=True
        ), mock.patch.object(bridge, "_process_instance_held_unreaped", return_value=True), mock.patch.object(
            bridge.os, "killpg", side_effect=OSError("signal failed")
        ):
            self.assertFalse(bridge._signal_held_registered_group(proc, bridge.signal.SIGKILL))
        bridge._signal_registered_descendants(mock.Mock(pid=None), bridge.signal.SIGKILL)

    def test_forced_output_and_input_cleanup_propagates_errors_without_thread_leaks(self) -> None:
        class BlockingReader:
            def __init__(self) -> None:
                self.entered = threading.Event()
                self.release = threading.Event()

            def read(self, _size: int) -> str:
                self.entered.set()
                self.release.wait()
                return ""

            def fileno(self) -> int:
                self.release.set()
                raise OSError("no descriptor")

            def close(self) -> None:
                raise OSError("close failed")

        stream = BlockingReader()
        reader = bridge._BoundedOutputReader(stream, "stdout", 100)
        reader.start()
        self.assertTrue(stream.entered.wait(1))
        reader.join(0.001, force=True)
        self.assertTrue(reader.forced)
        self.assertFalse(reader.thread.is_alive())
        unstarted = bridge._BoundedOutputReader(stream, "stdout", 100)
        unstarted.join(0, force=True)

        class BlockingWriter:
            def __init__(self) -> None:
                self.entered = threading.Event()
                self.release = threading.Event()

            def write(self, _data: str) -> None:
                self.entered.set()
                self.release.wait()

            def fileno(self) -> int:
                self.release.set()
                raise OSError("no descriptor")

            def close(self) -> None:
                raise BrokenPipeError

        destination = BlockingWriter()
        writer = bridge._ProcessInputWriter(destination, "payload")
        writer.start()
        self.assertTrue(destination.entered.wait(1))
        writer.close(0.001)
        self.assertFalse(writer.thread.is_alive())

        output = bridge._BoundedProcessOutput(mock.Mock(stdout=io.StringIO(""), stderr=io.StringIO("")))
        stuck = mock.Mock()
        stuck.thread.is_alive.return_value = True
        output.readers = [stuck]
        with self.assertRaisesRegex(RuntimeError, "reader did not terminate"):
            output.finish("Hermes", 0)

        class FailedReader:
            def read(self, _size: int) -> str:
                raise OSError("read failed")

            def close(self) -> None:
                pass

        output = bridge._BoundedProcessOutput(
            mock.Mock(stdout=FailedReader(), stderr=io.StringIO(""))
        )
        output.start()
        with self.assertRaisesRegex(RuntimeError, "stdout could not be read"):
            output.finish("Hermes", 1)
        self.assertFalse(any(thread.is_alive() and thread.name.startswith("hermes-") for thread in threading.enumerate()))

    def test_terminate_shutdown_and_retry_failure_branches_remain_fail_closed(self) -> None:
        proc = mock.Mock(pid=None)
        proc.poll.side_effect = OSError("poll failed")
        proc.terminate.side_effect = OSError("terminate failed")
        self.assertFalse(bridge.terminate_process(proc))

        proc = mock.Mock(pid=None)
        proc.poll.side_effect = OSError("poll failed")
        proc.wait.side_effect = [OSError("wait failed"), 0]
        proc.kill.side_effect = OSError("kill failed")
        proc.communicate.side_effect = TypeError("unsupported")
        with mock.patch.object(bridge, "terminate_process", return_value=False):
            bridge._terminate_and_reap_process_group(proc, grace_seconds=0)

        active = mock.Mock(pid=10)
        with mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: active}, clear=True), mock.patch.dict(
            bridge.ACTIVE_DESCENDANTS, {10: set()}, clear=True
        ), mock.patch.object(
            bridge, "terminate_and_reap_process_group", side_effect=RuntimeError("cleanup failed")
        ):
            bridge.shutdown_active_processes(grace_seconds=0)
            self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))
        bridge.SHUTTING_DOWN = False

        interrupted = mock.Mock(pid=10)
        with mock.patch.object(bridge, "SHUTTING_DOWN", True), mock.patch.object(
            bridge, "terminate_process", return_value=False
        ):
            self.assertFalse(bridge.register_active_process(99, interrupted))
            self.assertIn(99, bridge.ACTIVE_INTERRUPTS)
        bridge.ACTIVE_INTERRUPTS.pop(99, None)

        bridge._reschedule_reconciliation_job({"reply_reconciliations": []}, {"attempts": 1}, now=1.0)
        retryable = bridge.ZulipResponseError("temporary", retryable=True)
        with mock.patch.object(bridge, "api", side_effect=retryable), self.assertRaises(
            bridge.RetryableBeforeHermes
        ):
            bridge.add_reaction({}, {"id": 1}, "eyes", raise_retryable=True)
        with mock.patch.object(bridge, "api", side_effect=retryable):
            self.assertEqual(
                bridge.current_stream_name({}, {"stream_id": 1, "display_recipient": "fallback"}),
                "fallback",
            )

    def test_normal_hermes_exit_cleans_descendant_holding_output_pipes(self) -> None:
        child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        parent_code = (
            "import subprocess,sys; "
            f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "print(child.pid, flush=True)"
        )
        hermes_script = self.python_console_script(parent_code)
        with (
            mock.patch.object(bridge, "_hermes_command", return_value=("marker", [str(hermes_script), "--toolsets", "coding", "-z", "private"])),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge, "typing_status"),
            mock.patch.object(bridge, "find_session_by_marker", return_value=None),
            mock.patch.object(bridge, "clean_session_record"),
            mock.patch.object(bridge, "set_session_archived"),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
        ):
            answer, _session_id = bridge.hermes_reply(
                {},
                {"id": 77, "stream_id": 1, "display_recipient": "stream-1", "topic": "Topic", "content": "go"},
                None,
            )

        child_pid = int(answer)
        self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))
        status = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(child_pid)], capture_output=True, text=True, check=False
        ).stdout.strip()
        self.assertTrue(not status or status.startswith("Z"), f"descendant {child_pid} survived with status {status}")

    def test_normal_slash_exit_cleans_descendant_holding_output_pipes(self) -> None:
        child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        parent_code = (
            "import json,subprocess,sys; "
            f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "print(json.dumps({'ok': True, 'output': str(child.pid)}), flush=True)"
        )
        with (
            mock.patch.object(bridge, "_slash_worker_command", return_value=[sys.executable, "-c", parent_code]),
            mock.patch.object(bridge, "SLASH_COMMAND_TIMEOUT_SECONDS", 0.2),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
        ):
            child_pid = int(bridge.run_slash_worker("/status", "s1", 88))

        self.assertEqual((bridge.ACTIVE_PROCESSES, bridge.ACTIVE_DESCENDANTS), ({}, {}))
        status = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(child_pid)], capture_output=True, text=True, check=False
        ).stdout.strip()
        self.assertTrue(not status or status.startswith("Z"), f"descendant {child_pid} survived with status {status}")

    def test_alias_manifest_accepts_legacy_entry_only_for_owned_current_realm_session(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=1, stream_id=1, topic="Original", session_id="s1")
        entries = [
            {"stream_id": "1", "topic": "Renamed", "session_id": "s1"},
            {"realm": "example", "stream_id": "1", "topic": "Realm match", "session_id": "s1"},
        ]

        bridge.apply_alias_repairs(state, entries, "example")
        session_id, _conversation = bridge.resolve_session(
            {"id": 2, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"},
            bridge.load_aliases(entries),
            state,
            "example",
        )

        self.assertEqual(session_id, "s1")
        matched_session, _conversation = bridge.resolve_session(
            {"id": 3, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Realm match"},
            bridge.load_aliases(entries),
            state,
            "example",
        )
        self.assertEqual(matched_session, "s1")

    def test_alias_manifest_rejects_unowned_session_without_mutating_empty_state(self) -> None:
        state = {"topic_sessions": {}}
        entries = [{"stream_id": "1", "topic": "Topic", "session_id": "foreign-session"}]

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "not owned"):
            bridge.apply_alias_repairs(state, entries, "example")

        self.assertEqual(state, {"topic_sessions": {}, "realm": "example"})
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "not owned"):
            bridge.resolve_session(
                {"id": 1, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Topic"},
                bridge.load_aliases(entries),
                state,
                "example",
            )

    def test_alias_manifest_rejects_explicit_cross_realm_claim_for_owned_session(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=1, stream_id=1, topic="Original", session_id="s1")
        before = json.loads(json.dumps(state))

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "another Zulip realm"):
            bridge.apply_alias_repairs(
                state,
                [{"realm": "other.example", "stream_id": "1", "topic": "Renamed", "session_id": "s1"}],
                "example",
            )

        self.assertEqual(state, before)

    def test_alias_manifest_cannot_continue_session_in_different_stream(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=1, stream_id=1, topic="Original", session_id="s1")
        before = json.loads(json.dumps(state))
        entries = [{"stream_id": "2", "topic": "Moved", "session_id": "s1"}]

        with self.assertRaisesRegex(bridge.ReplyRoutingError, "active Zulip stream"):
            bridge.apply_alias_repairs(state, entries, "example")
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "active Zulip stream"):
            bridge.resolve_session(
                {"id": 2, "type": "stream", "stream_id": 2, "display_recipient": "stream-2", "topic": "Moved"},
                bridge.load_aliases(entries),
                state,
                "example",
            )

        self.assertEqual(state, before)

    def test_first_destination_reservation_survives_post_until_owner_publication(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Before",
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
            "_zulip_signing_key": SIGNING_KEY,
        }
        post_started = threading.Event()
        release_post = threading.Event()
        errors: list[BaseException] = []

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(
                    message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "After"}
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                post_started.set()
                self.assertTrue(release_post.wait(2))
                return zulip_success(id=900)
            raise AssertionError((method, path))

        worker = threading.Thread(
            target=lambda: self._capture_exception(
                errors, bridge.reply, {"site": "https://example", "key": BOT_KEY}, message, "answer"
            )
        )
        with mock.patch.object(bridge, "api", fake_api):
            worker.start()
            self.assertTrue(post_started.wait(1))
            foreign = bridge.resolve_zulip_conversation_key(
                {"id": 50, "stream_id": 1, "display_recipient": "stream-1", "topic": "After"},
                "example",
                thread_id="foreign-thread",
            )
            self.assertFalse(bridge.note_bridge_thread(state, foreign, session_id="s2"))
            release_post.set()
            worker.join(2)

        self.assertEqual(errors, [])
        self.assertEqual(
            state["zulip_topic_aliases"][bridge.topic_alias_lookup_key("example", "1", "After")],
            source["thread_id"],
        )
        self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)

    def test_generation_reservation_covers_attachment_and_history_context(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        attachment_started = threading.Event()
        release_attachment = threading.Event()
        history_started = threading.Event()
        release_history = threading.Event()
        launch_checked = threading.Event()
        errors: list[BaseException] = []
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Before",
            "content": "hello",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }
        foreign = bridge.resolve_zulip_conversation_key(
            {"id": 50, "stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
            "example",
            thread_id="foreign-thread",
        )

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(
                    message={**message, "stream_id": 1, "display_recipient": "stream-1", "topic": "Before"}
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            raise AssertionError(path)

        def attachments(*_args: object) -> str:
            attachment_started.set()
            self.assertTrue(release_attachment.wait(2))
            return ""

        def history(*_args: object) -> str:
            history_started.set()
            self.assertTrue(release_history.wait(2))
            return ""

        def before_start() -> None:
            self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)
            launch_checked.set()
            raise RuntimeError("stop before launch")

        message["_zulip_before_hermes_start"] = before_start
        message["_zulip_launcher_proof"] = self.launcher_proof()
        with (
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.object(bridge, "build_attachment_context", side_effect=attachments),
            mock.patch.object(bridge, "topic_history", side_effect=history),
        ):
            worker = threading.Thread(
                target=lambda: self._capture_exception(errors, bridge.hermes_reply, {}, message, "s1")
            )
            worker.start()
            self.assertTrue(attachment_started.wait(1))
            self.assertFalse(bridge.note_bridge_thread(state, foreign, session_id="s2"))
            release_attachment.set()
            self.assertTrue(history_started.wait(1))
            self.assertFalse(bridge.note_bridge_thread(state, foreign, session_id="s2"))
            release_history.set()
            worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertTrue(launch_checked.is_set())
        self.assertEqual(len(errors), 1)
        self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)

    def test_generation_rejects_same_origin_moved_to_different_stream(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Before",
            "content": "hello",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }
        moved = {**user_message(44, 2, "After"), "sender_email": "user@example.com"}

        with mock.patch.object(bridge, "live_origin_message", return_value=moved), self.assertRaises(
            bridge.ReplyRoutingError
        ) as raised:
            bridge.refresh_generation_origin({}, message)

        self.assertFalse(raised.exception.retryable)
        self.assertEqual(message["stream_id"], 1)
        self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)

    def test_prompt_construction_failure_releases_generation_reservation(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "content": "hello",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }
        origin = user_message(44, 1, "Topic")

        with (
            mock.patch.object(bridge, "live_origin_message", return_value=origin),
            mock.patch.object(bridge, "api", return_value=zulip_success(messages={"44": narrow_match()})),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge, "_hermes_command", side_effect=MemoryError("prompt")),
            mock.patch.object(bridge.subprocess, "Popen") as popen,
            self.assertRaises(MemoryError),
        ):
            bridge.hermes_reply({}, message, "s1")

        popen.assert_not_called()
        self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)

    def test_reconciliation_job_survives_restart_and_never_reposts_answer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = {"topic_sessions": {}}
            source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
            message = {
                "id": 44,
                "type": "stream",
                "stream_id": 1,
                "display_recipient": "stream-1",
                "topic": "Before",
                "_zulip_state": state,
                "_zulip_bridge": {**source, "session_id": "s1"},
                "_zulip_persist": lambda: bridge.save_json(state_path, state),
                "_zulip_signing_key": SIGNING_KEY,
            }
            calls: list[tuple[str, str]] = []
            origin_gets = 0

            def first_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                nonlocal origin_gets
                calls.append((method, path))
                if path == "/api/v1/messages/44":
                    origin_gets += 1
                    if origin_gets == 2:
                        raise TimeoutError("temporary second GET failure")
                    return zulip_success(
                        message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Before"}
                    )
                if path == "/api/v1/messages/matches_narrow":
                    return zulip_success(messages={"44": narrow_match()})
                if method == "POST":
                    return zulip_success(id=900)
                raise AssertionError((method, path))

            with mock.patch.object(bridge, "api", first_api):
                bridge.reply({"site": "https://example", "key": BOT_KEY}, message, "answer")

            reloaded = bridge.require_state_object(bridge.load_json(state_path, {}))
            self.assertEqual(len(reloaded["reply_reconciliations"]), 1)

            def restart_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                calls.append((method, path))
                if path == "/api/v1/messages/44":
                    return zulip_success(
                        message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "After"}
                    )
                if method == "GET" and path == "/api/v1/messages/900":
                    return zulip_success(message=bot_message(900, 1, "Before", stream="stream-1"))
                if path == "/api/v1/messages/matches_narrow":
                    return zulip_success(messages={"44": narrow_match()})
                if method == "PATCH":
                    return zulip_success()
                raise AssertionError((method, path))

            with mock.patch.object(bridge, "api", restart_api):
                bridge.reconcile_pending_replies(
                    {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                    reloaded,
                    SIGNING_KEY,
                    persist=lambda: None,
                )

        self.assertEqual(sum(method == "POST" for method, _path in calls), 1)
        self.assertEqual(sum(method == "PATCH" for method, _path in calls), 1)
        self.assertEqual(reloaded["reply_reconciliations"], [])
        self.assertEqual(
            reloaded["zulip_topic_aliases"][bridge.topic_alias_lookup_key("example", "1", "After")],
            source["thread_id"],
        )

    def test_transient_patch_reconciliation_retries_without_reposting(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Before",
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
            "_zulip_signing_key": SIGNING_KEY,
        }
        posts = 0
        patches = 0
        origin_gets = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posts, patches, origin_gets
            if path == "/api/v1/messages/44":
                origin_gets += 1
                topic = "Before" if origin_gets == 1 else "After"
                return zulip_success(
                    message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": topic}
                )
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "Before", stream="stream-1"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                posts += 1
                return zulip_success(id=900)
            if method == "PATCH":
                patches += 1
                if patches == 1:
                    raise TimeoutError("temporary patch transport failure")
                return zulip_success()
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", fake_api):
            rc = {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            bridge.reply(rc, message, "answer")
            self.assertEqual(len(state["reply_reconciliations"]), 1)
            bridge.reconcile_pending_replies(rc, state, SIGNING_KEY, persist=lambda: None)
            retry_at = state["reply_reconciliations"][0]["next_attempt_at"]
            bridge.reconcile_pending_replies(rc, state, SIGNING_KEY, now=retry_at, persist=lambda: None)

        self.assertEqual((posts, patches), (1, 2))
        self.assertEqual(state["reply_reconciliations"], [])
        self.assertEqual(
            state["zulip_topic_aliases"][bridge.topic_alias_lookup_key("example", "1", "After")],
            source["thread_id"],
        )

    def test_retry_queue_fetches_origin_after_newest_hundred_window_moves_past_it(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        origin = {
            "id": 51,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Renamed",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        newer = [
            {**origin, "id": message_id, "sender_is_bot": True}
            for message_id in range(52, 152)
        ]
        latest = mock.Mock(side_effect=[[origin], newer])
        worker = mock.Mock(return_value="new-session")
        anchor_calls = 0
        direct_fetches = 0
        snapshots: list[dict] = []
        sleeps = 0
        clock = [100.0]

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            nonlocal anchor_calls, direct_fetches
            if path == "/api/v1/messages/51":
                direct_fetches += 1
                return zulip_success(message=origin)
            if path == "/api/v1/messages/matches_narrow":
                anchor_calls += 1
                if anchor_calls == 1:
                    raise RuntimeError("temporary route lookup failure")
                return zulip_success(messages={})
            raise AssertionError(path)

        def stop_after_two_loops(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            clock[0] += 1000
            if sleeps == 3:
                raise StopIteration

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "handle_message", worker),
            mock.patch.object(bridge, "save_json", side_effect=lambda _path, value: snapshots.append(json.loads(json.dumps(value)))),
            mock.patch.object(bridge.time, "time", side_effect=lambda: clock[0]),
            mock.patch.object(bridge.time, "sleep", side_effect=stop_after_two_loops),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        worker.assert_called_once()
        self.assertEqual(direct_fetches, 1)
        self.assertTrue(any(item["origin_message_id"] == 51 for snapshot in snapshots for item in snapshot["origin_retries"]))
        self.assertEqual(snapshots[-1]["origin_retries"], [])
        self.assertIn(51, snapshots[-1]["seen_ids"])

    def test_rate_limit_during_route_discovery_is_retryable(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        client = SequenceZulipClient([{"result": "error", "msg": "rate limited", "code": "RATE_LIMIT_HIT"}])
        rc = {"site": "https://example", "email": "bot@example.com", "key": "secret"}

        with mock.patch.dict(bridge.ZULIP_CLIENT_CACHE, {(rc["site"], rc["email"], rc["key"]): client}, clear=True):
            with self.assertRaises(bridge.ReplyRoutingError) as raised:
                bridge.resolve_session(
                    {"id": 51, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Renamed"},
                    {},
                    state,
                    "example",
                    rc,
                )

        self.assertTrue(raised.exception.retryable)

    def test_official_transient_route_discovery_recovers_and_exhaustion_dead_letters(self) -> None:
        state = {"topic_sessions": {}}
        self.seed_topic(state, message_id=50, stream_id=1, topic="Original", session_id="s1")
        rc = {"site": "https://example", "email": "bot@example.com", "key": "secret"}
        client = SequenceZulipClient(
            [
                {"result": "error", "msg": "unavailable", "code": "HTTP_ERROR", "status_code": 503},
                zulip_success(messages={"50": narrow_match()}),
            ]
        )
        renamed = {
            "id": 51,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Renamed",
        }
        with mock.patch.dict(
            bridge.ZULIP_CLIENT_CACHE,
            {(rc["site"], rc["email"], rc["key"]): client},
            clear=True,
        ):
            with self.assertRaises(bridge.ReplyRoutingError) as raised:
                bridge.resolve_session(renamed, {}, state, "example", rc)
            self.assertTrue(raised.exception.retryable)
            session_id, _conversation = bridge.resolve_session(renamed, {}, state, "example", rc)
        self.assertEqual(session_id, "s1")

        exhausted = {
            "origin_retries": [
                {
                    "origin_message_id": 51,
                    "attempts": bridge.MAX_DURABLE_ATTEMPTS - 1,
                    "created_at": 1.0,
                    "next_attempt_at": 2.0,
                }
            ]
        }
        self.assertIsNone(
            bridge._upsert_origin_retry(
                exhausted,
                51,
                previous_attempts=bridge.MAX_DURABLE_ATTEMPTS - 1,
                now=3.0,
                reason="official_transient_read_exhausted",
            )
        )
        self.assertEqual(exhausted["origin_retries"], [])
        self.assertEqual(exhausted["dead_letters"][0]["reason"], "official_transient_read_exhausted")

    def test_lost_answer_post_response_posts_once_and_suppresses_generic_error(self) -> None:
        posts = 0
        hermes_runs = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posts
            if method == "GET":
                return zulip_success(
                    message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Topic"}
                )
            posts += 1
            raise TimeoutError("response lost after commit")

        def fake_hermes(*_args: object) -> tuple[str, str]:
            nonlocal hermes_runs
            hermes_runs += 1
            return "answer", "s1"

        with (
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "hermes_reply", fake_hermes),
            mock.patch.object(bridge, "add_reaction"),
            mock.patch.object(bridge, "remove_reaction"),
            self.assertRaises(bridge.ReplyPostUncertain),
        ):
            bridge.handle_message(
                {"site": "https://example"},
                {"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Topic", "content": "hello"},
                None,
            )

        self.assertEqual((hermes_runs, posts), (1, 1))

    def test_uncertain_answer_post_without_hermes_is_not_reclassified_retryable(self) -> None:
        def uncertain_reply(*_args: object) -> None:
            try:
                raise TimeoutError("response lost")
            except TimeoutError as exc:
                raise bridge.ReplyPostUncertain("answer POST uncertain") from exc

        message = {
            "id": 44,
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "content": "/status",
            "_zulip_execution": {"hermes_started": False},
        }
        with (
            mock.patch.object(bridge, "hermes_slash_reply", return_value=("status", None)),
            mock.patch.object(bridge, "reply", side_effect=uncertain_reply),
            mock.patch.object(bridge, "add_reaction"),
            mock.patch.object(bridge, "remove_reaction"),
            self.assertRaises(bridge.ReplyPostUncertain),
        ):
            bridge.handle_message({"site": "https://example"}, message, None)

    def test_nested_state_corruption_stops_before_credentials_api_worker_or_write(self) -> None:
        corrupt_states = [
            {"realm": "example", "topic_sessions": []},
            {"topic_sessions": {}, "zulip_threads": {"thread": []}},
            {"topic_sessions": {}, "zulip_topic_aliases": []},
            {"topic_sessions": {}, "zulip_topic_aliases": {"route": 1}},
            {"topic_sessions": {"topic": 1}},
            {"topic_sessions": {}, "zulip_threads": {"thread": {"topic_aliases": "Topic"}}},
            {"topic_sessions": {}, "retry_origin_ids": {}},
            {"topic_sessions": {}, "origin_in_flight": [{}]},
            {"topic_sessions": {}, "dead_letters": [{}]},
            {"topic_sessions": {}, "reply_reconciliations": [{}]},
            {"seen_ids": {}, "topic_sessions": {}},
        ]
        for state in corrupt_states:
            load_rc = mock.Mock()
            load_aliases = mock.Mock()
            latest = mock.Mock()
            worker = mock.Mock()
            save = mock.Mock()
            with (
                self.subTest(state=state),
                mock.patch.object(bridge, "load_json", return_value=state),
                mock.patch.object(bridge, "load_rc", load_rc),
                mock.patch.object(bridge, "load_alias_entries", load_aliases),
                mock.patch.object(bridge, "latest_messages", latest),
                mock.patch.object(bridge, "handle_message", worker),
                mock.patch.object(bridge, "save_json", save),
                self.assertRaises(ValueError),
            ):
                bridge._main()
            load_rc.assert_not_called()
            load_aliases.assert_not_called()
            latest.assert_not_called()
            worker.assert_not_called()
            save.assert_not_called()

    def test_hermes_child_environment_is_allowlisted_and_excludes_all_zulip_credentials(self) -> None:
        captured: dict[str, str] = {}

        class FakeProc:
            pid = 999002
            returncode = 0

            def poll(self) -> int:
                return 0

            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                return "ok", ""

        def fake_popen(_cmd: list[str], **kwargs: object) -> FakeProc:
            captured.update(kwargs["env"])
            return FakeProc()

        child_vars = {
            "HOME": "/tmp/home",
            "PATH": "/bin",
            "REQUIRED_RUNTIME": "works",
            "ARBITRARY_CANARY": "must-not-leak",
            "CUSTOM_ZULIP_SECRET": "secret-1",
            "CUSTOM_SECRET": "secret-2",
            "HERMES_ZULIP_API_KEY": "secret-3",
            "HERMES_ZULIP_RC": "/secret/zuliprc",
            "ZULIPRC": "/secret/legacy-zuliprc",
            "REALM_URL": "https://secret.example",
            "BOT_LOGIN": "bot@example.com",
            "BOT_TOKEN": "secret-4",
        }
        launcher_proof = self.launcher_proof("print('ok')")
        with (
            mock.patch.dict(os.environ, child_vars, clear=True),
            mock.patch.object(
                bridge,
                "HERMES_ENV_ALLOWLIST",
                {"REQUIRED_RUNTIME", "CUSTOM_ZULIP_SECRET", "CUSTOM_SECRET", "REALM_URL", "BOT_LOGIN", "BOT_TOKEN"},
            ),
            mock.patch.object(bridge, "ZULIP_SECRET_ENV_NAMES", {"CUSTOM_SECRET", "REALM_URL", "BOT_LOGIN", "BOT_TOKEN"}),
            mock.patch.object(bridge.subprocess, "Popen", fake_popen),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "typing_status"),
            mock.patch.object(bridge, "find_session_by_marker", return_value=None),
            mock.patch.object(bridge, "clean_session_record"),
            mock.patch.object(bridge, "set_session_archived"),
            mock.patch.object(bridge, "refresh_generation_origin"),
        ):
            bridge.hermes_reply(
                {"site": "https://example", "email": "bot@example.com", "key": "secret"},
                {
                    "id": 1,
                    "stream_id": 1,
                    "display_recipient": "stream-1",
                    "topic": "Topic",
                    "content": "hello",
                    "_zulip_launcher_proof": launcher_proof,
                },
                None,
            )

        self.assertEqual(captured["REQUIRED_RUNTIME"], "works")
        for name in (
            "ARBITRARY_CANARY",
            "CUSTOM_ZULIP_SECRET",
            "CUSTOM_SECRET",
            "HERMES_ZULIP_API_KEY",
            "HERMES_ZULIP_RC",
            "ZULIPRC",
            "REALM_URL",
            "BOT_LOGIN",
            "BOT_TOKEN",
        ):
            self.assertNotIn(name, captured)

    def test_authenticated_attachment_redirect_does_not_reach_second_origin(self) -> None:
        received_authorization: list[str | None] = []

        class Destination(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received_authorization.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"leaked")

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        destination = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Destination)
        destination_thread = threading.Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()
        redirect_url = f"http://127.0.0.1:{destination.server_port}/stolen"

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        source = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        source_thread = threading.Thread(target=source.serve_forever, daemon=True)
        source_thread.start()
        try:
            result = bridge.fetch_zulip_attachment(
                {"site": f"http://127.0.0.1:{source.server_port}", "email": "bot@example.com", "key": "secret"},
                "/user_uploads/1/ab/file.txt",
            )
        finally:
            source.shutdown()
            destination.shutdown()
            source.server_close()
            destination.server_close()
            source_thread.join(2)
            destination_thread.join(2)

        self.assertIn("HTTP 302", result["error"])
        self.assertEqual(received_authorization, [])

    def test_rejected_authenticated_redirect_response_is_closed(self) -> None:
        error = urllib.error.HTTPError(
            "https://zulip.example.com/user_uploads/1/a/file.txt",
            302,
            "Found",
            {},
            io.BytesIO(b"redirect"),
        )
        original_close = error.close
        error.close = mock.Mock(wraps=original_close)
        opener = mock.Mock()
        opener.open.side_effect = error

        with mock.patch.object(bridge.urllib.request, "build_opener", return_value=opener):
            result = bridge.fetch_zulip_attachment(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "secret"},
                "/user_uploads/1/a/file.txt",
            )

        self.assertIn("HTTP 302", result["error"])
        error.close.assert_called_once_with()

    def test_live_origin_requires_complete_reconciliation_route_before_post(self) -> None:
        state = {"realm": "example", "seen_ids": [44], "topic_sessions": {}, "origin_retries": []}
        before = json.loads(json.dumps(state))
        posts = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posts
            if method == "GET" and path == "/api/v1/messages/44":
                return zulip_success(message={"id": 44, "type": "stream", "stream_id": 1, "topic": "Topic"})
            if method == "POST":
                posts += 1
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", fake_api), self.assertRaisesRegex(bridge.ReplyRoutingError, "stream name"):
            bridge.reply(
                {"site": "https://example"},
                {"id": 44, "_zulip_state": state, "_zulip_signing_key": SIGNING_KEY},
                "answer",
            )

        self.assertEqual(posts, 0)
        self.assertEqual(state, before)
        reloaded = json.loads(json.dumps(state))
        self.assertEqual(bridge.require_state_object(reloaded), before)

    def test_topic_history_rate_limit_is_retryable_only_before_hermes_start(self) -> None:
        popen = mock.Mock()
        rate_limit = RuntimeError("GET failed")
        rate_limit.__cause__ = bridge.ZulipResponseError("rate limited", retryable=True)

        with (
            mock.patch.object(bridge, "topic_history", side_effect=rate_limit),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge.subprocess, "Popen", popen),
            mock.patch.object(bridge, "refresh_generation_origin"),
            self.assertRaises(bridge.RetryableBeforeHermes),
        ):
            bridge.hermes_reply(
                {"site": "https://example"},
                {"id": 44, "stream_id": 1, "display_recipient": "stream-1", "topic": "Topic", "content": "hello"},
                None,
            )

        popen.assert_not_called()

    def test_attachment_transport_failure_is_retryable_before_hermes_start(self) -> None:
        popen = mock.Mock()
        message = {
            "id": 44,
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "content": "see /user_uploads/1/a/file.txt",
        }
        failed = {
            "path": "/user_uploads/1/a/file.txt",
            "filename": "file.txt",
            "content_type": "",
            "content_length": None,
            "data": b"",
            "truncated_bytes": False,
            "error": "URL error: timed out",
            "retryable": True,
        }

        with (
            mock.patch.object(bridge, "fetch_zulip_attachment", return_value=failed),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge.subprocess, "Popen", popen),
            self.assertRaises(bridge.RetryableBeforeHermes),
        ):
            bridge.hermes_reply({"site": "https://example"}, message, None)

        popen.assert_not_called()

    def test_pre_hermes_future_releases_seen_into_backed_off_retry_then_runs_once(self) -> None:
        state = {"topic_sessions": {}}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        clock = [100.0]
        calls = 0
        snapshots: list[dict] = []

        class ImmediateFuture:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error:
                    raise self.error
                return self.value

        class ImmediateExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def submit(self, function, *args: object) -> ImmediateFuture:
                return ImmediateFuture(function, *args)

        def worker(*_args: object) -> str:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise bridge.RetryableBeforeHermes("rate limited")
            return "s1"

        def run_loops(limit: int) -> None:
            sleeps = 0

            def advance(_seconds: float) -> None:
                nonlocal sleeps
                sleeps += 1
                clock[0] += 1000
                if sleeps == limit:
                    raise StopIteration

            with (
                mock.patch.object(bridge, "load_json", return_value=state),
                mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "latest_messages", return_value=[message]),
                mock.patch.object(bridge, "live_origin_message", side_effect=lambda _rc, _message: dict(message)),
                mock.patch.object(bridge, "api", return_value=zulip_success(messages={"44": narrow_match()})),
                mock.patch.object(bridge, "handle_message", side_effect=worker),
                mock.patch.object(bridge, "save_json", side_effect=lambda _path, value: snapshots.append(json.loads(json.dumps(value)))),
                mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor),
                mock.patch.object(bridge.time, "time", side_effect=lambda: clock[0]),
                mock.patch.object(bridge.time, "sleep", side_effect=advance),
                self.assertRaises(StopIteration),
            ):
                bridge._main()

        run_loops(2)
        self.assertNotIn(44, state["seen_ids"])
        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [44])
        run_loops(2)
        self.assertEqual(calls, 2)
        self.assertIn(44, state["seen_ids"])
        self.assertEqual(state["origin_retries"], [])

    def test_posted_answer_restart_reconciles_without_rerunning_origin(self) -> None:
        state = {"topic_sessions": {}, "seen_ids": list(range(1000, 1500))}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Before",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        posted = False
        posts = 0
        patches = 0
        hermes_runs = 0

        class ImmediateFuture:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error:
                    raise self.error
                return self.value

        class ImmediateExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def submit(self, function, *args: object) -> ImmediateFuture:
                return ImmediateFuture(function, *args)

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posted, posts, patches
            if method == "GET" and path == "/api/v1/messages/44":
                topic = "After" if posted else "Before"
                return zulip_success(message={**message, "subject": topic, "topic": topic})
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "Before", stream="stream-1"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                posts += 1
                posted = True
                return zulip_success(id=900)
            if method == "PATCH":
                patches += 1
                return zulip_success()
            raise AssertionError((method, path))

        def worker(rc: dict, worker_message: dict, _session_id: str | None) -> str:
            nonlocal hermes_runs
            hermes_runs += 1
            bridge.reply(rc, worker_message, "answer")
            return "s1"

        def run_once(handler) -> None:
            with (
                mock.patch.object(bridge, "load_json", return_value=state),
                mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "latest_messages", return_value=[message]),
                mock.patch.object(bridge, "api", fake_api),
                mock.patch.object(bridge, "handle_message", side_effect=handler),
                mock.patch.object(bridge, "save_json"),
                mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor),
                mock.patch.object(bridge.time, "time", return_value=100.0),
                mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
                self.assertRaises(StopIteration),
            ):
                bridge._main()

        run_once(worker)
        self.assertIn(44, state["seen_ids"])
        self.assertEqual(len(state["reply_reconciliations"]), 1)
        never_run = mock.Mock(side_effect=AssertionError("origin reran"))
        run_once(never_run)
        run_once(never_run)

        self.assertEqual((hermes_runs, posts, patches), (1, 1, 1))
        self.assertEqual(state["reply_reconciliations"], [])
        never_run.assert_not_called()

    def test_stale_older_reconciliation_cannot_rewind_newer_route_or_remove_newer_job(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=10, stream_id=1, topic="Initial", session_id="s1")

        def job(origin_id: int, sent_id: int) -> dict:
            return bridge._reply_reconciliation_job(
                {"id": origin_id, "_zulip_bridge": {**source, "session_id": "s1"}},
                {"id": origin_id, "stream_id": 1, "display_recipient": "stream-1", "topic": "Initial"},
                sent_id,
                SIGNING_KEY,
                "answer",
            )

        older = job(44, 900)
        newer = job(45, 901)
        state["reply_reconciliations"] = [older, newer]
        patch_topics: list[str] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            if method == "GET":
                origin_id = int(path.rsplit("/", 1)[-1])
                if origin_id in {900, 901}:
                    return zulip_success(message=bot_message(origin_id, 1, "Initial", stream="stream-1"))
                topic = "Newest" if origin_id == 45 else "Older"
                return zulip_success(
                    message={"id": origin_id, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": topic}
                )
            if method == "PATCH":
                patch_topics.append(str((kwargs.get("data") or {})["topic"]))
                return zulip_success()
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", fake_api), mock.patch.object(
            bridge, "_thread_for_matching_anchors", return_value=source["thread_id"]
        ):
            rc = {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            bridge._reconcile_reply_job(rc, state, newer, SIGNING_KEY, persist=lambda: None)
            bridge._remove_reconciliation_job(state, newer)
            replacement = {**older, "attempts": 1, "next_attempt_at": older["next_attempt_at"] + 5}
            state["reply_reconciliations"][0] = replacement
            with self.assertRaises(bridge.StatePersistenceError):
                bridge._reconcile_reply_job(rc, state, older, SIGNING_KEY, persist=lambda: None)

        thread = state["zulip_threads"][source["thread_id"]]
        self.assertEqual(patch_topics, ["Newest"])
        self.assertEqual((thread["current_display_topic"], thread["last_seen_message_id"]), ("Newest", 45))
        self.assertEqual(state["reply_reconciliations"], [replacement])

    def test_durable_work_schema_capacity_backoff_and_poll_budget_are_strict(self) -> None:
        invalid = [
            {"origin_message_id": 1, "attempts": True, "created_at": 0.0, "next_attempt_at": 0.0},
            {"origin_message_id": 1, "attempts": 1, "created_at": -1.0, "next_attempt_at": 0.0},
            {"origin_message_id": 1, "attempts": 1, "created_at": 2.0, "next_attempt_at": 1.0},
        ]
        for retry in invalid:
            with self.subTest(retry=retry), self.assertRaises(ValueError):
                bridge.require_state_object({"topic_sessions": {}, "origin_retries": [retry]})

        reconciliation = {
            "origin_message_id": 1,
            "sent_message_id": 2,
            "realm": "example",
            "source_thread_id": "thread",
            "session_id": "",
            "confirmed_stream_id": 1,
            "confirmed_stream": "stream-1",
            "confirmed_topic": "Topic",
            "attempts": 0,
            "created_at": 0.0,
            "next_attempt_at": float("inf"),
        }
        with self.assertRaises(ValueError):
            bridge.require_state_object({"topic_sessions": {}, "reply_reconciliations": [reconciliation]})

        state = {"origin_retries": []}
        with mock.patch.object(bridge, "MAX_ORIGIN_RETRIES", 1):
            first = bridge._upsert_origin_retry(state, 1, now=100.0)
            with self.assertRaises(bridge.DurableQueueFull):
                bridge._upsert_origin_retry(state, 2, now=100.0)
        self.assertEqual(first["next_attempt_at"], 100.0 + bridge.DURABLE_RETRY_BASE_SECONDS)
        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [1])

        reconciliation["next_attempt_at"] = 0.0
        reconciliation_state = {"reply_reconciliations": [reconciliation]}
        with mock.patch.object(bridge, "MAX_REPLY_RECONCILIATIONS", 1), self.assertRaises(bridge.DurableQueueFull):
            bridge._reserve_reconciliation_capacity(reconciliation_state)
        self.assertEqual(reconciliation_state["reply_reconciliations"], [reconciliation])

        state["origin_retries"].append(
            {"origin_message_id": 2, "attempts": 1, "created_at": 100.0, "next_attempt_at": 105.0}
        )
        calls = 0

        def fetch(_rc: dict, message: dict) -> dict:
            nonlocal calls
            calls += 1
            return {"id": message["id"]}

        with mock.patch.object(bridge, "live_origin_message", side_effect=fetch), mock.patch.object(
            bridge, "MAX_DURABLE_WORK_PER_POLL", 1
        ):
            queued, permanent, retryable = bridge.queued_origin_messages({}, state["origin_retries"], now=105.0)
        self.assertEqual((len(queued), permanent, retryable, calls), (1, set(), set(), 1))

    def test_in_flight_restart_recovery_retries_only_the_safe_prestart_stage(self) -> None:
        state = {
            "origin_in_flight": [
                {"origin_message_id": 1, "stage": "admitted", "attempts": 0, "created_at": 10.0},
                {"origin_message_id": 2, "stage": "hermes_may_start", "attempts": 1, "created_at": 11.0},
                {"origin_message_id": 3, "stage": "hermes_may_start", "attempts": 2, "created_at": 12.0},
            ],
            "reply_reconciliations": [
                {
                    "origin_message_id": 3,
                    "sent_message_id": 30,
                    "realm": "example",
                    "source_thread_id": "thread",
                    "session_id": "s1",
                    "confirmed_stream_id": 1,
                    "confirmed_stream": "stream-1",
                    "confirmed_topic": "Topic",
                    "attempts": 0,
                    "created_at": 12.0,
                    "next_attempt_at": 12.0,
                }
            ],
        }
        seen: set[int] = set()

        bridge._recover_in_flight_origins(state, seen, now=20.0)

        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [1])
        self.assertEqual(state["origin_in_flight"], [])
        self.assertEqual(seen, {2, 3})
        self.assertEqual([item["origin_message_id"] for item in state["dead_letters"]], [2])
        self.assertEqual([job["sent_message_id"] for job in state["reply_reconciliations"]], [30])
        reloaded = bridge.require_state_object(json.loads(json.dumps(state)))
        self.assertEqual(reloaded, state)

    def test_restart_after_hermes_may_start_never_runs_origin_again(self) -> None:
        state = {
            "origin_in_flight": [
                {"origin_message_id": 44, "stage": "hermes_may_start", "attempts": 0, "created_at": 10.0}
            ]
        }
        worker = mock.Mock(side_effect=AssertionError("Hermes duplicated"))
        latest = mock.Mock(return_value=[{
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }])
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "handle_message", worker),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "time", return_value=20.0),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        worker.assert_not_called()
        self.assertIn(44, state["seen_ids"])
        self.assertEqual(state["origin_in_flight"], [])
        self.assertEqual(state["dead_letters"][0]["reason"], "restart_after_hermes_may_start")

    def test_full_reconciliation_capacity_releases_destination_reservation(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")
        state["reply_reconciliations"] = [{}]
        message = {
            "id": 44,
            "_zulip_state": state,
            "_zulip_signing_key": SIGNING_KEY,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(message={**bot_message(44, 1, "Topic", stream="stream-1"), "sender_email": "user@example.com"})
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            raise AssertionError((method, path))

        with (
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "MAX_REPLY_RECONCILIATIONS", 1),
            self.assertRaises(bridge.DurableQueueFull),
        ):
            bridge.reply({"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}, message, "answer")

        self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)
        self.assertNotIn(id(state), bridge.STATE_RECONCILIATION_RESERVATIONS)

    def test_initial_reaction_rate_limit_completes_into_durable_retry(self) -> None:
        state = {"topic_sessions": {}}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }

        class ImmediateFuture:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error:
                    raise self.error
                return self.value

        class ImmediateExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def submit(self, function, *args: object) -> ImmediateFuture:
                return ImmediateFuture(function, *args)

        hermes = mock.Mock(side_effect=AssertionError("Hermes started after rate limit"))

        def reaction(_rc: dict, _message: dict, _emoji: str, *, raise_retryable: bool = False) -> None:
            if raise_retryable:
                raise bridge.RetryableBeforeHermes("rate limited")

        sleeps = 0

        def stop(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            if sleeps == 2:
                raise StopIteration

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "api", return_value=zulip_success(messages={})),
            mock.patch.object(bridge, "add_reaction", side_effect=reaction),
            mock.patch.object(bridge, "remove_reaction"),
            mock.patch.object(bridge, "hermes_reply", hermes),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=stop),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        hermes.assert_not_called()
        self.assertNotIn(44, state["seen_ids"])
        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [44])
        self.assertEqual(state["origin_in_flight"], [])

    def test_full_origin_queue_stops_before_poll_and_is_not_swallowed(self) -> None:
        retry = {"origin_message_id": 1, "attempts": 1, "created_at": 10.0, "next_attempt_at": 20.0}
        state = {"origin_retries": [retry]}
        latest = mock.Mock(return_value=[{"id": 2}])
        sleep = mock.Mock()

        with (
            mock.patch.object(bridge, "MAX_ORIGIN_RETRIES", 1),
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "time", return_value=10.0),
            mock.patch.object(bridge.time, "sleep", sleep),
            self.assertRaises(bridge.DurableQueueFull),
        ):
            bridge._main()

        latest.assert_called_once()
        sleep.assert_not_called()
        self.assertEqual(state["origin_retries"], [retry])

    def test_terminal_work_is_not_called_again_and_round_trips(self) -> None:
        state = {
            "origin_retries": [
                {"origin_message_id": 1, "attempts": 15, "created_at": 10.0, "next_attempt_at": 20.0}
            ]
        }
        self.assertIsNone(bridge._upsert_origin_retry(state, 1, previous_attempts=15, now=30.0))
        fetch = mock.Mock(side_effect=AssertionError("terminal origin retried"))
        with mock.patch.object(bridge, "live_origin_message", fetch):
            self.assertEqual(bridge.queued_origin_messages({}, state["origin_retries"], now=1000.0), ([], set(), set()))
        fetch.assert_not_called()

        state["origin_retries"] = [
            {"origin_message_id": 2, "attempts": 15, "created_at": 10.0, "next_attempt_at": 20.0}
        ]
        with mock.patch.object(bridge, "MAX_DEAD_LETTERS", 1), self.assertRaises(bridge.DurableQueueFull):
            bridge._upsert_origin_retry(state, 2, previous_attempts=15, now=30.0)
        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [2])

        source_state = {"topic_sessions": {}}
        source = self.seed_topic(source_state, message_id=2, stream_id=1, topic="Topic", session_id="s1")
        job = bridge._reply_reconciliation_job(
            {"id": 2, "_zulip_bridge": {**source, "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "Topic"},
            20,
            SIGNING_KEY,
            "answer",
        )
        job.update(attempts=15, created_at=10.0, next_attempt_at=20.0)
        source_state["reply_reconciliations"] = [job]
        bridge._reschedule_reconciliation_job(source_state, job, now=30.0)
        api = mock.Mock(side_effect=AssertionError("terminal reconciliation retried"))
        with mock.patch.object(bridge, "api", api):
            bridge.reconcile_pending_replies(
                {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                source_state,
                SIGNING_KEY,
                now=1000.0,
            )
        api.assert_not_called()
        reloaded = bridge.require_state_object(json.loads(json.dumps(source_state)))
        self.assertEqual(reloaded, source_state)
        self.assertEqual({item["kind"] for item in state["dead_letters"] + source_state["dead_letters"]}, {"origin", "reconciliation"})

    def test_failed_steering_store_is_terminal_after_durable_consumption_stage(self) -> None:
        active: dict = {}
        seen: set[int] = set()
        conversation = {"conversation_key": "zulip:example:1:thread", "thread_id": "thread"}
        message, state = self.admitted_message({"id": 222, "content": "steer"})
        store = mock.Mock(side_effect=OSError("disk full"))

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True),
            mock.patch.object(bridge, "store_steering_message", store),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current),
            mock.patch.object(bridge, "interrupt_active_message", return_value=False),
            self.assertRaises(OSError),
        ):
            bridge.handle_active_topic_message({}, message, "s1", conversation, 111, active, seen)
        self.assertEqual(active, {})
        self.assertEqual(seen, set())
        self.assertEqual(state["origin_in_flight"][0]["stage"], "hermes_may_start")
        bridge._recover_in_flight_origins(state, seen, now=2.0)
        self.assertEqual(seen, {222})
        self.assertEqual(state.get("origin_retries", []), [])
        self.assertEqual([item["origin_message_id"] for item in state["dead_letters"]], [222])
        store.assert_called_once()

    def test_late_steering_without_live_process_remains_unseen(self) -> None:
        active: dict[str, set[int]] = {}
        seen: set[int] = set()
        conversation = {"conversation_key": "zulip:example:1:thread"}
        store = mock.Mock()
        with mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True), mock.patch.object(
            bridge, "store_steering_message", store
        ):
            outcome = bridge.handle_active_topic_message(
                {}, {"id": 222, "content": "late"}, "s1", conversation, 111, active, seen
            )
        bridge.finish_active_message(seen, active, conversation["conversation_key"], 111, True)
        self.assertEqual(outcome, "deferred")
        self.assertEqual(seen, {111})
        store.assert_not_called()

    def test_steering_exit_race_appends_but_does_not_acknowledge_or_react(self) -> None:
        proc = mock.Mock()
        proc.poll.side_effect = [None, 0]
        active: dict = {}
        seen: set[int] = set()
        store = mock.Mock(return_value={"message_id": 222})
        reaction = mock.Mock()
        message, state = self.admitted_message({"id": 222, "content": "stop"})
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: proc}, clear=True),
            mock.patch.object(bridge, "store_steering_message", store),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current),
            mock.patch.object(bridge, "add_reaction", reaction),
        ):
            outcome = bridge.handle_active_topic_message(
                {}, message, "s1", {"conversation_key": "key", "thread_id": "thread"}, 111, active, seen
            )
        self.assertEqual(outcome, "retired")
        self.assertEqual(active, {})
        self.assertEqual(seen, set())
        self.assertEqual(state["origin_in_flight"], [])
        self.assertEqual(state["origin_retries"], [])
        review = state["dead_letters"][0]
        self.assertEqual(review["origin_message_id"], 222)
        self.assertIn("message=222 parent=111 route=", review["reason"])
        bridge.finish_active_message(seen, active, "key", 111, True)
        self.assertEqual(seen, {111})
        self.assertNotIn(222, seen)
        store.assert_called_once()
        reaction.assert_not_called()

    def test_unacknowledged_steering_retirement_retries_only_persistence_and_survives_restart(self) -> None:
        state: dict = {"topic_sessions": {}}
        parent = user_message(44, 1, "Topic", content="start")
        steering = user_message(45, 1, "Topic", content="stop")
        appends: list[int] = []
        review_saves = 0

        class Future:
            def done(self) -> bool:
                return False

        class Executor:
            submissions: list[int] = []

            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, _function, _rc: dict, message: dict, _session_id: str | None) -> Future:
                self.submissions.append(message["id"])
                return Future()

            def shutdown(self, **_kwargs: object) -> None:
                pass

        def store(
            _rc: dict, message: dict, _conversation: dict, _active: int, before: object
        ) -> tuple[bool, bool]:
            before()
            appends.append(message["id"])
            return True, False

        def save(_path: Path, candidate: dict) -> None:
            nonlocal review_saves
            if bridge._uncertain_steering_origin_ids(candidate):
                review_saves += 1
                if review_saves <= 2:
                    raise bridge.StatePersistenceError("transient review save")

        sleeps = 0

        def advance(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            if sleeps == 1:
                return
            raise StopIteration

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[parent, steering]),
            mock.patch.object(
                bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current
            ),
            mock.patch.object(bridge, "store_active_steering_if_live", side_effect=store),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge, "save_json", side_effect=save),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=advance),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        self.assertEqual(Executor.submissions, [44])
        self.assertEqual(appends, [45])
        self.assertEqual(review_saves, 4)
        self.assertEqual(state["origin_in_flight"], [mock.ANY])
        self.assertEqual(state["origin_in_flight"][0]["origin_message_id"], 44)
        self.assertNotIn(45, state["seen_ids"])
        self.assertEqual(bridge._uncertain_steering_origin_ids(state), {45})

        reloaded = bridge.require_state_object(json.loads(json.dumps(state)))
        Executor.submissions.clear()
        with (
            mock.patch.object(bridge, "load_json", return_value=reloaded),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[steering]),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        self.assertEqual(Executor.submissions, [])
        self.assertNotIn(45, reloaded["seen_ids"])
        self.assertEqual(bridge._uncertain_steering_origin_ids(reloaded), {45})

    def test_unacknowledged_steering_reviews_are_bounded_and_never_reappended(self) -> None:
        state: dict = {}
        conversation = {"conversation_key": "key", "thread_id": "thread"}
        store = mock.Mock(return_value={"message_id": 1})
        proc = mock.Mock(poll=mock.Mock(return_value=None))
        with (
            mock.patch.object(bridge, "MAX_DEAD_LETTERS", 2),
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: proc}, clear=True),
            mock.patch.object(bridge, "store_steering_message", store),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current),
            mock.patch.object(bridge, "interrupt_active_message", return_value=False),
        ):
            for message_id in (1, 2):
                bridge._admit_origin(state, message_id, now=1.0)
                message = {
                    "id": message_id,
                    "content": "stop",
                    "_zulip_state": state,
                    "_zulip_persist": lambda: None,
                }
                self.assertEqual(
                    bridge.handle_active_topic_message({}, message, "s1", conversation, 111, {}, set()),
                    "retired",
                )
                self.assertEqual(
                    bridge.handle_active_topic_message({}, message, "s1", conversation, 111, {}, set()),
                    "retired",
                )
            bridge._admit_origin(state, 3, now=1.0)
            third = {"id": 3, "content": "stop", "_zulip_state": state, "_zulip_persist": lambda: None}
            with self.assertRaisesRegex(bridge.DurableQueueFull, "review queue"):
                bridge.handle_active_topic_message({}, third, "s1", conversation, 111, {}, set())

        self.assertEqual(store.call_count, 2)
        self.assertEqual(len(state["dead_letters"]), 2)
        self.assertEqual([item["origin_message_id"] for item in state["origin_in_flight"]], [3])
        self.assertEqual(state["origin_in_flight"][0]["stage"], "admitted")

    def test_active_slash_without_registered_process_remains_unseen(self) -> None:
        store = mock.Mock()
        active: dict[str, set[int]] = {}
        with mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True), mock.patch.object(
            bridge, "store_steering_message", store
        ):
            outcome = bridge.handle_active_topic_message(
                {}, {"id": 222, "content": "/status"}, "s1", {"conversation_key": "key"}, 111, active, set()
            )
        self.assertEqual(outcome, "deferred")
        self.assertEqual(active, {})
        store.assert_not_called()

    def test_successful_hard_interrupt_does_not_repeat_admission_ack(self) -> None:
        store = mock.Mock(return_value={"message_id": 222})
        reaction = mock.Mock()
        active: dict = {}
        proc = mock.Mock(poll=mock.Mock(return_value=None))
        message, _state = self.admitted_message({"id": 222, "content": "stop"})
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: proc}, clear=True),
            mock.patch.object(bridge, "store_steering_message", store),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current),
            mock.patch.object(bridge, "interrupt_active_message", return_value=True) as interrupt,
            mock.patch.object(bridge, "add_reaction", reaction),
        ):
            outcome = bridge.handle_active_topic_message(
                {}, message, "s1", {"conversation_key": "key", "thread_id": "thread"}, 111, active, set()
            )
        self.assertEqual(outcome, "delivered")
        self.assertEqual(active, {"key": {222: (111, "thread")}})
        interrupt.assert_called_once_with(111)
        reaction.assert_not_called()

    def test_active_steering_refetches_and_revalidates_before_each_side_effect(self) -> None:
        state: dict = {"topic_sessions": {}}
        origin = {
            "id": 111,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "start",
        }
        _session_id, active = bridge.resolve_session(origin.copy(), {}, state, "example")
        bridge.note_bridge_thread(state, active, session_id="s1")
        bridge.note_topic_session(state, active, "s1")
        steering = {**origin, "id": 222, "content": "change course"}
        session_id, conversation = bridge.resolve_session(steering, {}, state, "example")
        bridge._admit_origin(state, 222, now=1.0)
        steering.update(_zulip_state=state, _zulip_persist=lambda: None)
        events: list[str] = []

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/222":
                events.append("fetch")
                return zulip_success(message=steering.copy())
            if path == "/api/v1/messages/matches_narrow":
                events.append("owner")
                return zulip_success(messages={"222": narrow_match()})
            raise AssertionError(path)

        with (
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True),
            mock.patch.object(bridge, "store_steering_message", side_effect=lambda *_args: events.append("append")),
            mock.patch.object(
                bridge, "interrupt_active_message", side_effect=lambda _mid: events.append("interrupt") or True
            ),
            mock.patch.object(bridge, "add_reaction", side_effect=lambda *_args: events.append("reaction")),
            mock.patch.object(bridge, "HARD_INTERRUPT_ON_STEERING", True),
        ):
            outcome = bridge.handle_active_topic_message(
                {"email": "bot@example.com"}, steering, session_id, conversation, 111, {}, set()
            )

        self.assertEqual(outcome, "delivered")
        self.assertEqual(
            events,
            [
                "fetch", "owner", "fetch", "owner", "append",
                "fetch", "owner", "interrupt",
                "fetch", "owner",
            ],
        )

    def test_active_steering_changed_route_owner_or_sender_is_rejected_unseen(self) -> None:
        for change in ("disallowed-route", "different-owner", "bot-sender"):
            with self.subTest(change=change):
                state: dict = {"topic_sessions": {}}
                polled = {
                    "id": 222,
                    "type": "stream",
                    "stream_id": 1,
                    "display_recipient": "stream-1",
                    "topic": "Topic",
                    "sender_id": 17,
                    "sender_email": "user@example.com",
                    "sender_is_bot": False,
                    "content": "change course",
                }
                _session_id, conversation = bridge.resolve_session(polled, {}, state, "example")
                bridge.note_bridge_thread(state, conversation, session_id="s1")
                bridge.note_topic_session(state, conversation, "s1")
                live = polled.copy()
                if change in {"disallowed-route", "different-owner"}:
                    live["topic"] = "Other"
                if change == "different-owner":
                    self.seed_topic(state, message_id=300, stream_id=1, topic="Other", session_id="s2")
                if change == "bot-sender":
                    live["sender_is_bot"] = True
                seen: set[int] = set()
                side_effect = mock.Mock()

                def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
                    if path == "/api/v1/messages/222":
                        return zulip_success(message=live)
                    if path == "/api/v1/messages/matches_narrow":
                        return zulip_success(messages={})
                    raise AssertionError(path)

                allowed_topics = {"Topic"} if change == "disallowed-route" else set()
                with (
                    mock.patch.object(bridge, "api", side_effect=fake_api),
                    mock.patch.object(bridge, "ALLOW_TOPICS", allowed_topics),
                    mock.patch.dict(
                        bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True
                    ),
                    mock.patch.object(bridge, "store_steering_message", side_effect),
                    mock.patch.object(bridge, "interrupt_active_message", side_effect),
                    mock.patch.object(bridge, "add_reaction", side_effect),
                ):
                    outcome = bridge.handle_active_topic_message(
                        {"email": "bot@example.com"}, polled, "s1", conversation, 111, {}, seen
                    )

                self.assertEqual(outcome, "deferred")
                self.assertEqual(seen, set())
                side_effect.assert_not_called()

    def test_active_steering_sender_identity_failures_have_no_side_effects(self) -> None:
        base = user_message(222, 1, "Topic", content="change course")
        variants = {
            "missing-id": {key: value for key, value in base.items() if key != "sender_id"},
            "missing-email": {key: value for key, value in base.items() if key != "sender_email"},
            "changed-id": {**base, "sender_id": 18},
            "changed-email": {**base, "sender_email": "other@example.com"},
            "bot": {**base, "sender_is_bot": True},
            "self": {**base, "sender_email": "bot@example.com"},
        }
        for hard in (False, True):
            for label, live in variants.items():
                state: dict = {"topic_sessions": {}}
                _session_id, conversation = bridge.resolve_session(base.copy(), {}, state, "example")
                bridge.note_bridge_thread(state, conversation, session_id="s1")
                bridge.note_topic_session(state, conversation, "s1")
                bridge._admit_origin(state, 222, now=1.0)
                message = {**base, "_zulip_state": state, "_zulip_persist": lambda: None}
                seen: set[int] = set()
                outward = mock.Mock()

                def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
                    if path == "/api/v1/messages/222":
                        return zulip_success(message=live)
                    if path == "/api/v1/messages/matches_narrow":
                        return zulip_success(messages={"222": narrow_match()})
                    raise AssertionError(path)

                with (
                    self.subTest(hard=hard, case=label),
                    mock.patch.object(bridge, "api", side_effect=fake_api),
                    mock.patch.object(bridge, "HARD_INTERRUPT_ON_STEERING", hard),
                    mock.patch.dict(
                        bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True
                    ),
                    mock.patch.object(bridge, "store_steering_message", outward),
                    mock.patch.object(bridge, "interrupt_active_message", outward),
                    mock.patch.object(bridge, "add_reaction", outward),
                ):
                    try:
                        outcome = bridge.handle_active_topic_message(
                            {"email": "bot@example.com"}, message, "s1", conversation, 111, {}, seen
                        )
                    except bridge.ReplyRoutingError:
                        outcome = "retryable"

                self.assertIn(outcome, {"deferred", "retryable"})
                self.assertEqual(seen, set())
                self.assertEqual(state["origin_in_flight"][0]["stage"], "admitted")
                outward.assert_not_called()

    def test_active_steering_sender_race_rolls_back_before_append(self) -> None:
        state: dict = {"topic_sessions": {}}
        message = user_message(222, 1, "Topic", content="change course")
        _session_id, conversation = bridge.resolve_session(message.copy(), {}, state, "example")
        bridge.note_bridge_thread(state, conversation, session_id="s1")
        bridge.note_topic_session(state, conversation, "s1")
        bridge._admit_origin(state, 222, now=1.0)
        persist = mock.Mock()
        message.update(_zulip_state=state, _zulip_persist=persist)
        live_reads = 0
        outward = mock.Mock()

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            nonlocal live_reads
            if path == "/api/v1/messages/222":
                live_reads += 1
                return zulip_success(
                    message=message if live_reads == 1 else {**message, "sender_id": 18}
                )
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"222": narrow_match()})
            raise AssertionError(path)

        with (
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.dict(
                bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True
            ),
            mock.patch.object(bridge, "store_steering_message", outward),
            mock.patch.object(bridge, "interrupt_active_message", outward),
            mock.patch.object(bridge, "add_reaction", outward),
        ):
            outcome = bridge.handle_active_topic_message(
                {"email": "bot@example.com"}, message, "s1", conversation, 111, {}, set()
            )

        self.assertEqual(outcome, "deferred")
        self.assertEqual(state["origin_in_flight"][0]["stage"], "admitted")
        self.assertEqual(persist.call_count, 2)
        outward.assert_not_called()

    def test_valid_soft_steering_appends_without_repeating_admission_ack(self) -> None:
        state: dict = {"topic_sessions": {}}
        self.seed_topic(state, message_id=111, stream_id=1, topic="Topic", session_id="s1")
        message = user_message(222, 1, "Topic", content="change course")
        session_id, conversation = bridge.resolve_session(message, {}, state, "example")
        bridge._admit_origin(state, 222, now=1.0)
        message.update(_zulip_state=state, _zulip_persist=lambda: None)
        store = mock.Mock(return_value={"message_id": 222})
        reaction = mock.Mock()
        interrupt = mock.Mock()

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/222":
                return zulip_success(message=message.copy())
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"222": narrow_match()})
            raise AssertionError(path)

        with (
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.object(bridge, "HARD_INTERRUPT_ON_STEERING", False),
            mock.patch.dict(
                bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True
            ),
            mock.patch.object(bridge, "store_steering_message", store),
            mock.patch.object(bridge, "interrupt_active_message", interrupt),
            mock.patch.object(bridge, "add_reaction", reaction),
        ):
            outcome = bridge.handle_active_topic_message(
                {"email": "bot@example.com"}, message, session_id, conversation, 111, {}, set()
            )

        self.assertEqual(outcome, "delivered")
        store.assert_called_once()
        reaction.assert_not_called()
        interrupt.assert_not_called()

    def test_failed_active_readonly_goal_enters_durable_retry_unseen(self) -> None:
        state = {"origin_retries": []}
        bridge._admit_origin(state, 222, now=1.0)
        message = {
            "id": 222,
            "content": "/goal status",
            "_zulip_state": state,
            "_zulip_persist": lambda: None,
            "_zulip_execution": {"hermes_started": False},
        }
        error = bridge.ReplyRoutingError("temporary", retryable=True)
        with mock.patch.object(bridge, "is_readonly_goal_slash", return_value=True), mock.patch.object(
            bridge, "handle_message", side_effect=error
        ), mock.patch.object(bridge.time, "time", return_value=100.0):
            outcome = bridge.handle_active_topic_message(
                {}, message, "s1", {"conversation_key": "key"}, 111, {}, set()
            )
        self.assertEqual(outcome, "handled")
        self.assertEqual(state["origin_retries"][0]["origin_message_id"], 222)

    def test_active_goal_save_failure_recovers_without_duplicate_status_post(self) -> None:
        state: dict = {}
        bridge._admit_origin(state, 222, now=1.0)
        state_path = Path(self.state_dir.name) / "goal-state.json"
        saves = 0

        def persist() -> None:
            nonlocal saves
            saves += 1
            if saves == 1:
                bridge.save_json(state_path, state)
                return
            raise bridge.StatePersistenceError("injected save failure after status POST")

        message = {
            "id": 222,
            "content": "/goal status",
            "_zulip_state": state,
            "_zulip_persist": persist,
            "_zulip_execution": {"hermes_started": False},
        }

        def posted_status(_rc: dict, posted: dict, _session_id: str | None) -> str:
            bridge.persist_message_state(posted)
            return "s1"

        with mock.patch.object(bridge, "handle_message", side_effect=posted_status), self.assertRaises(
            bridge.StatePersistenceError
        ):
            bridge.handle_active_topic_message({}, message, "s1", {"conversation_key": "key"}, 111, {}, set())

        recovered = bridge.require_state_object(bridge.load_json(state_path, {}))
        self.assertEqual(recovered["origin_in_flight"][0]["stage"], "hermes_may_start")
        seen: set[int] = set()
        bridge._recover_in_flight_origins(recovered, seen, now=2.0)
        self.assertEqual(seen, {222})
        self.assertEqual(recovered.get("origin_retries", []), [])

    def test_active_goal_uncertain_post_is_not_returned_to_retry(self) -> None:
        state: dict = {}
        bridge._admit_origin(state, 222, now=1.0)
        message = {
            "id": 222,
            "content": "/goal show",
            "_zulip_state": state,
            "_zulip_persist": lambda: None,
            "_zulip_execution": {"hermes_started": False},
        }
        seen: set[int] = set()
        with mock.patch.object(
            bridge, "handle_message", side_effect=bridge.ReplyPostUncertain("unknown POST outcome")
        ):
            outcome = bridge.handle_active_topic_message(
                {}, message, "s1", {"conversation_key": "key"}, 111, {}, seen
            )
        self.assertEqual(outcome, "handled")
        self.assertEqual(seen, {222})
        self.assertEqual(state.get("origin_retries", []), [])

    def test_save_json_fsyncs_private_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state" / "bridge.json"
            actual_fsync = os.fsync
            fsync_kinds: list[str] = []

            def checked_fsync(fd: int) -> None:
                fsync_kinds.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
                actual_fsync(fd)

            old_umask = os.umask(0)
            try:
                with mock.patch.object(bridge.os, "fsync", side_effect=checked_fsync):
                    bridge.save_json(path, {"ok": True})
            finally:
                os.umask(old_umask)
            self.assertEqual(fsync_kinds, ["file", "directory"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_uid, os.geteuid())

    def test_save_json_fsyncs_through_parent_path_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            bridge.save_json(alias / "state.json", {"ok": True})
            self.assertEqual(json.loads((real / "state.json").read_text(encoding="utf-8")), {"ok": True})
            self.assertEqual(stat.S_IMODE((real / "state.json").stat().st_mode), 0o600)

    def test_state_signing_key_is_private_stable_and_has_no_malformed_state_side_effect(self) -> None:
        state_path = Path(self.state_dir.name) / "signing" / "state.json"
        state_path.parent.mkdir(mode=0o700)
        old_umask = os.umask(0)
        try:
            key = bridge.load_state_signing_key(state_path, {})
        finally:
            os.umask(old_umask)
        key_path = bridge.state_signing_key_path(state_path)
        self.assertEqual(len(key or b""), 32)
        self.assertEqual(bridge.load_state_signing_key(state_path, {}), key)
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        self.assertEqual(key_path.stat().st_nlink, 1)

        malformed_path = Path(self.state_dir.name) / "malformed" / "state.json"
        with self.assertRaises(ValueError):
            bridge.load_state_signing_key(malformed_path, {"topic_sessions": []})
        self.assertFalse(bridge.state_signing_key_path(malformed_path).exists())
        self.assertFalse(malformed_path.parent.exists())

    def test_state_signing_key_rejects_missing_pending_mode_symlink_and_hardlink(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        state["reply_reconciliations"] = [
            bridge._reply_reconciliation_job(
                {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
                {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
                900,
                SIGNING_KEY,
                "answer",
            )
        ]
        missing_state = Path(self.state_dir.name) / "missing" / "state.json"
        missing_state.parent.mkdir(mode=0o700)
        before = json.loads(json.dumps(state))
        with self.assertRaises(bridge.StatePersistenceError):
            bridge.load_state_signing_key(missing_state, state)
        self.assertEqual(state, before)

        for kind in ("mode", "symlink", "hardlink"):
            with self.subTest(kind=kind):
                directory = Path(self.state_dir.name) / kind
                directory.mkdir(mode=0o700)
                state_path = directory / "state.json"
                key_path = bridge.state_signing_key_path(state_path)
                target = directory / "target"
                target.write_bytes(SIGNING_KEY)
                target.chmod(0o600)
                if kind == "mode":
                    target.chmod(0o644)
                    target.rename(key_path)
                elif kind == "symlink":
                    key_path.symlink_to(target)
                else:
                    os.link(target, key_path)
                with self.assertRaises(bridge.StatePersistenceError):
                    bridge.load_state_signing_key(state_path, {})

    def test_missing_or_corrupt_key_with_pending_job_stops_before_dead_letter_or_api(self) -> None:
        for kind in ("missing", "corrupt"):
            with self.subTest(kind=kind):
                state = {"topic_sessions": {}}
                source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
                state["reply_reconciliations"] = [
                    bridge._reply_reconciliation_job(
                        {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
                        {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
                        900,
                        SIGNING_KEY,
                        "answer",
                    )
                ]
                state_path = Path(self.state_dir.name) / f"{kind}.json"
                key_path = bridge.state_signing_key_path(state_path)
                if kind == "corrupt":
                    key_path.write_bytes(b"short")
                    key_path.chmod(0o600)
                before = json.loads(json.dumps(state))
                api = mock.Mock(side_effect=AssertionError("pending job reached Zulip"))
                with (
                    mock.patch.object(bridge, "load_json", return_value=state),
                    mock.patch.object(
                        bridge,
                        "load_rc",
                        return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                    ),
                    mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                    mock.patch.object(bridge, "api", api),
                    self.assertRaises(bridge.StatePersistenceError),
                ):
                    bridge._main(state_path)
                api.assert_not_called()
                self.assertEqual(state, before)

    def test_reconciliation_survives_zulip_api_key_rotation(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        job = bridge._reply_reconciliation_job(
            {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
            900,
            SIGNING_KEY,
            "answer",
        )
        state["reply_reconciliations"] = [job]

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(
                    message={"id": 44, "type": "stream", "stream_id": 1, "display_recipient": "stream-1", "topic": "Before"}
                )
            if path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "Before", stream="stream-1"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", fake_api):
            bridge.reconcile_pending_replies(
                {"site": "https://example", "email": "bot@example.com", "key": "rotated-api-key"},
                state,
                SIGNING_KEY,
            )
        self.assertEqual(state["reply_reconciliations"], [])

    def test_bridge_main_keeps_reads_and_writes_on_held_path_after_parent_retarget(self) -> None:
        root = Path(self.state_dir.name) / "retarget"
        first = root / "first"
        second = root / "second"
        first.mkdir(parents=True)
        second.mkdir()
        alias = root / "current"
        alias.symlink_to(first, target_is_directory=True)
        lexical_state = alias / "state.json"
        (first / "state.json").write_text('{"seen_ids":[1]}', encoding="utf-8")

        with bridge.process_lock(lexical_state) as held:
            alias.unlink()
            alias.symlink_to(second, target_is_directory=True)

            def run(canonical: Path, *, rc: dict[str, str]) -> int:
                loaded = bridge.load_json(canonical, {})
                bridge.save_json(canonical, {**loaded, "canonical": True})
                return 0

            with mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}), mock.patch.object(bridge, "_main", side_effect=run), mock.patch.object(
                bridge, "STATE_PATH", lexical_state
            ):
                self.assertEqual(bridge.main(lock=held), 0)

        self.assertTrue(json.loads((first / "state.json").read_text(encoding="utf-8"))["canonical"])
        self.assertFalse((second / "state.json").exists())

    def test_auxiliary_bundle_freezes_to_held_parent_after_retarget(self) -> None:
        root = Path(self.state_dir.name) / "bundle-retarget"
        first = root / "first"
        second = root / "second"
        first.mkdir(parents=True)
        second.mkdir()
        alias = root / "current"
        alias.symlink_to(first, target_is_directory=True)
        lexical_state = alias / "state.json"

        with bridge.process_lock(lexical_state) as held:
            alias.unlink()
            alias.symlink_to(second, target_is_directory=True)
            with mock.patch.multiple(
                bridge,
                STATE_PATH=lexical_state,
                STEERING_PATH=alias / "steering.jsonl",
                ALIASES_PATH=alias / "aliases.json",
                STEERING_STATE_ASSOCIATED=True,
                ALIASES_STATE_ASSOCIATED=True,
            ):
                bridge.freeze_auxiliary_paths(held.state_path)
                self.assertEqual(bridge.STATE_PATH, (first / "state.json").resolve())
                self.assertEqual(bridge.STEERING_PATH, first.resolve() / "steering.jsonl")
                self.assertEqual(bridge.ALIASES_PATH, first.resolve() / "aliases.json")

    def test_explicit_auxiliary_paths_canonicalize_independently(self) -> None:
        root = Path(self.state_dir.name) / "explicit-bundle"
        state_dir = root / "state"
        custom_dir = root / "custom"
        state_dir.mkdir(parents=True)
        custom_dir.mkdir()
        custom_alias = root / "custom-current"
        custom_alias.symlink_to(custom_dir, target_is_directory=True)

        with mock.patch.multiple(
            bridge,
            STEERING_PATH=custom_alias / "steering.jsonl",
            ALIASES_PATH=custom_alias / "aliases.json",
            STEERING_STATE_ASSOCIATED=False,
            ALIASES_STATE_ASSOCIATED=False,
        ):
            bridge.freeze_auxiliary_paths(state_dir / "state.json")
            self.assertEqual(bridge.STEERING_PATH, custom_dir.resolve() / "steering.jsonl")
            self.assertEqual(bridge.ALIASES_PATH, custom_dir.resolve() / "aliases.json")

    def test_runtime_bundle_rejects_credentials_and_database_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state.json"
            for name, steering, aliases in (
                ("credentials", root / "zuliprc", root / "aliases.json"),
                ("database", root / "steering.jsonl", root / "state.db"),
            ):
                with self.subTest(name=name), mock.patch.multiple(
                    bridge,
                    RC_PATH=root / "zuliprc",
                    STATE_DB=root / "state.db",
                    STEERING_PATH=steering,
                    ALIASES_PATH=aliases,
                    STEERING_STATE_ASSOCIATED=False,
                    ALIASES_STATE_ASSOCIATED=False,
                ), self.assertRaisesRegex(ValueError, "must be disjoint"):
                    bridge.freeze_auxiliary_paths(state)

    def test_runtime_bundle_rejects_derived_smoke_steering_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            with mock.patch.multiple(
                bridge,
                RC_PATH=root / "zuliprc",
                STATE_DB=root / "state.db",
                STEERING_PATH=root / "sidecar",
                ALIASES_PATH=root / "aliases.json",
                STEERING_STATE_ASSOCIATED=False,
                ALIASES_STATE_ASSOCIATED=False,
            ), self.assertRaisesRegex(ValueError, "state = smoke steering"):
                bridge.freeze_auxiliary_paths(root / "sidecar.smoke")

    def test_direct_environment_custom_auxiliary_paths_are_inferred_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = dict(os.environ)
            env.update(
                PYTHONPATH=str(Path(__file__).parents[1] / "src"),
                HERMES_ZULIP_STEERING=str(Path(tmpdir) / "steering.jsonl"),
                HERMES_ZULIP_ALIAS_MANIFEST=str(Path(tmpdir) / "aliases.json"),
            )
            env.pop("HERMES_ZULIP_STEERING_STATE_ASSOCIATED", None)
            env.pop("HERMES_ZULIP_ALIASES_STATE_ASSOCIATED", None)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from hermes_zulip_bridge import bridge; "
                    "print(bridge.STEERING_STATE_ASSOCIATED, bridge.ALIASES_STATE_ASSOCIATED)",
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
        self.assertEqual(completed.stdout.strip(), "False False")

    def test_latest_messages_requires_endpoint_message_list(self) -> None:
        for payload in (zulip_success(), zulip_success(messages={}), zulip_success(messages="bad")):
            with self.subTest(payload=payload), mock.patch.object(bridge, "api", return_value=payload), self.assertRaises(
                bridge.ZulipResponseError
            ):
                bridge.latest_messages({})

    def test_reconciliation_hmac_forgery_terminalizes_before_api_or_owner_mutation(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        job = bridge._reply_reconciliation_job(
            {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
            900,
            SIGNING_KEY,
            "answer",
        )
        forged = {**job, "confirmed_topic": "Forged"}
        state["reply_reconciliations"] = [forged]
        ownership = json.loads(json.dumps(state["zulip_threads"]))
        api = mock.Mock(side_effect=AssertionError("forged state reached Zulip"))
        with mock.patch.object(bridge, "api", api):
            bridge.reconcile_pending_replies(
                {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}, state, SIGNING_KEY
            )
        api.assert_not_called()
        self.assertEqual(state["zulip_threads"], ownership)
        self.assertEqual(state["reply_reconciliations"], [])
        self.assertIn("provenance", state["dead_letters"][0]["reason"])

    def test_reconciliation_verifies_sent_author_route_id_and_content_before_patch(self) -> None:
        variants = {
            "author": {"sender_email": "other@example.com"},
            "route": {"topic": "Elsewhere"},
            "id": {"id": 901},
            "content": {"content": "different"},
        }
        for name, change in variants.items():
            with self.subTest(name=name):
                state = {"topic_sessions": {}}
                source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
                job = bridge._reply_reconciliation_job(
                    {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
                    {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
                    900,
                    SIGNING_KEY,
                    "answer",
                )
                state["reply_reconciliations"] = [job]
                patches = 0

                def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                    nonlocal patches
                    if path == "/api/v1/messages/44":
                        return zulip_success(
                            message={
                                "id": 44,
                                "type": "stream",
                                "stream_id": 1,
                                "display_recipient": "stream-1",
                                "topic": "After",
                            }
                        )
                    if path == "/api/v1/messages/900":
                        return zulip_success(message={**bot_message(900, 1, "Before", stream="stream-1"), **change})
                    if method == "PATCH":
                        patches += 1
                    raise AssertionError((method, path))

                with mock.patch.object(bridge, "api", fake_api):
                    bridge.reconcile_pending_replies(
                        {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                        state,
                        SIGNING_KEY,
                    )
                self.assertEqual(patches, 0)
                self.assertEqual(state["reply_reconciliations"], [])
                self.assertNotIn(bridge.topic_alias_lookup_key("example", "1", "After"), state["zulip_topic_aliases"])

    def test_valid_hmac_with_missing_source_terminalizes_before_get(self) -> None:
        message = {
            "id": 44,
            "_zulip_bridge": {"realm": "example", "thread_id": "missing", "session_id": "s1"},
        }
        job = bridge._reply_reconciliation_job(
            message,
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
            900,
            SIGNING_KEY,
            "answer",
        )
        state = {"realm": "example", "topic_sessions": {}, "reply_reconciliations": [job]}
        api = mock.Mock(side_effect=AssertionError("missing source reached Zulip"))
        with mock.patch.object(bridge, "api", api):
            bridge.reconcile_pending_replies(
                {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}, state, SIGNING_KEY
            )
        api.assert_not_called()
        self.assertEqual(state.get("zulip_threads", {}), {})

    def test_capacity_one_rejects_two_message_page_without_partial_admission(self) -> None:
        state = {"topic_sessions": {}}
        messages = [
            {
                "id": mid,
                "type": "stream",
                "stream_id": 1,
                "display_recipient": "stream-1",
                "topic": topic,
                "sender_id": 17,
                "sender_email": "user@example.com",
                "content": "hello",
            }
            for mid, topic in ((44, "One"), (45, "Two"))
        ]
        worker = mock.Mock()
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=messages),
            mock.patch.object(bridge, "handle_message", worker),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge, "MAX_ORIGIN_RETRIES", 1),
            self.assertRaises(bridge.DurableQueueFull),
        ):
            bridge._main()
        worker.assert_not_called()
        self.assertEqual(state.get("origin_in_flight", []), [])
        self.assertEqual(state.get("origin_retries", []), [])
        self.assertEqual(state.get("zulip_threads", {}), {})

    def test_admission_persistence_failure_rolls_back_and_terminates(self) -> None:
        state = {"topic_sessions": {}}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        worker = mock.Mock()
        save = mock.Mock(side_effect=[None, OSError("disk full")])
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "handle_message", worker),
            mock.patch.object(bridge, "save_json", save),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1),
            self.assertRaisesRegex(SystemExit, "1 consecutive iteration"),
        ):
            bridge._main()
        worker.assert_not_called()
        self.assertEqual(state.get("origin_in_flight", []), [])
        self.assertEqual(state.get("zulip_threads", {}), {})

    def test_wrapped_steering_persistence_error_preserves_consumption_stage(self) -> None:
        state = {"topic_sessions": {}}
        parent = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "start",
        }
        steering = {**parent, "id": 45, "content": "change course"}
        proc = mock.Mock(poll=mock.Mock(return_value=None))

        class PendingFuture:
            def done(self) -> bool:
                return False

        class Executor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, _function, _rc: dict, message: dict, _session_id: str | None) -> PendingFuture:
                self.assert_parent(message)
                bridge.ACTIVE_PROCESSES[message["id"]] = proc
                return PendingFuture()

            @staticmethod
            def assert_parent(message: dict) -> None:
                if message["id"] != 44:
                    raise AssertionError("steering message reached the executor")

            def shutdown(self, **_kwargs: object) -> None:
                pass

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            steering_path = root / "steering.jsonl"
            steering_path.write_bytes(b"")
            steering_path.chmod(0o660)
            with (
                mock.patch.object(bridge, "load_json", return_value=state),
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                ),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "latest_messages", return_value=[parent, steering]),
                mock.patch.object(bridge, "STEERING_PATH", steering_path),
                mock.patch.object(bridge, "STEERING_STATE_ASSOCIATED", False),
                mock.patch.object(bridge, "retire_stale_steering_paths"),
                mock.patch.object(
                    bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current
                ),
                mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
                mock.patch.object(bridge, "save_json"),
                mock.patch.object(bridge, "shutdown_active_processes"),
                mock.patch.dict(bridge.ACTIVE_PROCESSES, {}, clear=True),
                mock.patch.object(bridge.time, "time", return_value=100.0),
                mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
                self.assertRaises(StopIteration),
            ):
                bridge._main()

            self.assertEqual(steering_path.read_bytes(), b"")
            self.assertEqual(stat.S_IMODE(steering_path.stat().st_mode), 0o660)
        self.assertNotIn(45, {item["origin_message_id"] for item in state.get("origin_retries", [])})
        self.assertEqual(
            [(item["origin_message_id"], item["stage"]) for item in state["origin_in_flight"] if item["origin_message_id"] == 45],
            [(45, "hermes_may_start")],
        )
        recovered_seen: set[int] = set()
        bridge._recover_in_flight_origins(state, recovered_seen, now=200.0)
        self.assertIn(45, recovered_seen)
        self.assertNotIn(45, {item["origin_message_id"] for item in state.get("origin_retries", [])})

    def test_full_queue_dispatches_due_retry_before_capacity_check(self) -> None:
        state = {
            "topic_sessions": {},
            "origin_retries": [{"origin_message_id": 44, "attempts": 1, "created_at": 10.0, "next_attempt_at": 20.0}],
        }
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }

        class ImmediateFuture:
            def __init__(self, function, args: tuple[object, ...]) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error:
                    raise self.error
                return self.value

        class ImmediateExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def submit(self, function, *args: object) -> ImmediateFuture:
                return ImmediateFuture(function, args)

        latest = mock.Mock(return_value=[])
        worker = mock.Mock(return_value="s1")

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(message=message)
            raise AssertionError(path)

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "handle_message", worker),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor),
            mock.patch.object(bridge, "MAX_ORIGIN_RETRIES", 1),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        worker.assert_called_once()
        latest.assert_called_once()
        self.assertEqual(state["origin_retries"], [])
        self.assertEqual(state["origin_in_flight"], [])
        self.assertIn(44, state["seen_ids"])

    def test_executor_submission_failure_backs_off_then_terminalizes(self) -> None:
        state = {
            "topic_sessions": {},
            "origin_retries": [{"origin_message_id": 44, "attempts": 15, "created_at": 10.0, "next_attempt_at": 20.0}],
        }
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }

        class FailingExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def submit(self, *_args: object):
                raise OSError("temporary executor submission failure")

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(message=message)
            raise AssertionError(path)

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge, "api", fake_api),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", FailingExecutor),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        self.assertEqual(state["origin_retries"], [])
        self.assertEqual(state["origin_in_flight"], [])
        self.assertIn("executor_submission", state["dead_letters"][0]["reason"])

    def test_broken_executor_terminates_without_retrying_or_dead_lettering_origin(self) -> None:
        state = {"topic_sessions": {}}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }

        class BrokenExecutor:
            submissions = 0

            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, *_args: object):
                BrokenExecutor.submissions += 1
                raise bridge.concurrent.futures.BrokenExecutor("poisoned pool")

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", BrokenExecutor),
            self.assertRaises(bridge.concurrent.futures.BrokenExecutor),
        ):
            bridge._main()
        self.assertEqual(BrokenExecutor.submissions, 1)
        self.assertEqual(state.get("dead_letters", []), [])
        self.assertEqual(state["origin_in_flight"][0]["stage"], "admitted")

    def test_initial_poll_failure_terminates_startup(self) -> None:
        latest = mock.Mock(side_effect=RuntimeError("auth failed"))
        with (
            mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "sleep") as sleep,
            self.assertRaisesRegex(SystemExit, "Initial Zulip message poll failed"),
        ):
            bridge._main()
        sleep.assert_not_called()

    def test_later_poll_failure_counter_resets_then_exits_public_daemon_at_threshold(self) -> None:
        latest = mock.Mock(
            side_effect=[[], RuntimeError("one"), [], RuntimeError("two"), RuntimeError("three")]
        )
        with bridge.process_lock(bridge.STATE_PATH) as held:
            with (
                mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                ),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "latest_messages", latest),
                mock.patch.object(bridge, "save_json"),
                mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 2),
                mock.patch.object(bridge.time, "sleep"),
                self.assertRaisesRegex(SystemExit, "2 consecutive"),
            ):
                bridge.main(lock=held)
        self.assertEqual(latest.call_count, 5)
        with bridge.process_lock(bridge.STATE_PATH):
            pass

    def test_runtime_alias_reload_failures_exit_at_whole_iteration_threshold(self) -> None:
        aliases = mock.Mock(side_effect=[[], ValueError("malformed"), ValueError("malformed")])
        latest = mock.Mock(return_value=[])
        with (
            mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", aliases),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 2),
            mock.patch.object(bridge.time, "sleep"),
            self.assertRaisesRegex(SystemExit, "2 consecutive iterations"),
        ):
            bridge._main()
        self.assertEqual(aliases.call_count, 3)
        latest.assert_called_once()

    def test_successful_complete_iteration_resets_pre_poll_failure_counter(self) -> None:
        aliases = mock.Mock(
            side_effect=[[], ValueError("one"), [], ValueError("two"), ValueError("three")]
        )
        latest = mock.Mock(return_value=[])
        with (
            mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", aliases),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 2),
            mock.patch.object(bridge.time, "sleep"),
            self.assertRaisesRegex(SystemExit, "2 consecutive iterations"),
        ):
            bridge._main()
        latest.assert_called_once()
        self.assertEqual(aliases.call_count, 5)

    def test_repeated_loop_state_save_failures_use_runtime_health_threshold(self) -> None:
        save = mock.Mock(side_effect=[None, OSError("disk"), OSError("disk")])
        latest = mock.Mock(return_value=[])
        with (
            mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json", save),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 2),
            mock.patch.object(bridge.time, "sleep"),
            self.assertRaisesRegex(SystemExit, "2 consecutive iterations"),
        ):
            bridge._main()
        self.assertEqual(save.call_count, 3)
        latest.assert_called_once()

    def test_keyboard_interrupt_cleans_children_then_waits_for_executor(self) -> None:
        shutdown_calls: list[tuple[bool, bool]] = []
        children_stopped = False

        class Executor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
                self.assert_children_stopped = children_stopped
                shutdown_calls.append((wait, cancel_futures))

        def cleanup(**_kwargs: object) -> None:
            nonlocal children_stopped
            children_stopped = True

        with (
            mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge, "shutdown_active_processes", side_effect=cleanup),
            mock.patch.object(bridge.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(bridge._main(), 0)
        self.assertTrue(children_stopped)
        self.assertEqual(shutdown_calls, [(True, True)])

    def test_executor_shutdown_deadline_is_bounded_and_runtime_fatal_stops_polling(self) -> None:
        release = threading.Event()
        shutdown_started = threading.Event()

        class StuckExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
                self.options = (wait, cancel_futures)
                shutdown_started.set()
                release.wait(2)

        executor = StuckExecutor()
        started = time.monotonic()
        self.assertFalse(bridge._shutdown_executor(executor, time.perf_counter() + 0.02))
        self.assertLess(time.monotonic() - started, 0.25)
        self.assertTrue(shutdown_started.is_set())
        release.set()

        release.clear()
        aliases = mock.Mock(side_effect=[[], RuntimeError("fatal")])
        latest = mock.Mock(return_value=[])
        started = time.monotonic()
        try:
            with (
                mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                ),
                mock.patch.object(bridge, "load_alias_entries", aliases),
                mock.patch.object(bridge, "latest_messages", latest),
                mock.patch.object(bridge, "save_json"),
                mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", StuckExecutor),
                mock.patch.object(bridge, "shutdown_active_processes", return_value=True),
                mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1),
                mock.patch.object(bridge, "SHUTDOWN_DEADLINE_SECONDS", 0.02),
                mock.patch.object(bridge.time, "sleep", return_value=None),
                self.assertRaisesRegex(bridge.FatalBridgeExit, "consecutive iterations"),
            ):
                bridge._main()
        finally:
            release.set()
        self.assertLess(time.monotonic() - started, 0.25)
        self.assertEqual(aliases.call_count, 2)
        latest.assert_called_once()

    def test_sigterm_and_sigint_shutdown_gracefully_when_cleanup_finishes(self) -> None:
        for signum in (bridge.signal.SIGTERM, bridge.signal.SIGINT):
            with self.subTest(signum=signum):
                previous = bridge.signal.getsignal(signum)

                def request_signal(_seconds: float) -> None:
                    bridge.signal.getsignal(signum)(signum, None)

                with (
                    mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
                    mock.patch.object(
                        bridge,
                        "load_rc",
                        return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                    ),
                    mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                    mock.patch.object(bridge, "latest_messages", return_value=[]),
                    mock.patch.object(bridge, "save_json"),
                    mock.patch.object(bridge, "shutdown_active_processes", return_value=True),
                    mock.patch.object(bridge.time, "sleep", side_effect=request_signal),
                ):
                    self.assertEqual(bridge._main(), 0)
                self.assertIs(bridge.signal.getsignal(signum), previous)

    def test_process_lock_remains_held_until_executor_join_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_path = root / "state.json"
            shutdown_started = threading.Event()
            release_join = threading.Event()
            errors: list[BaseException] = []

            class Executor:
                def __init__(self, **_kwargs: object) -> None:
                    pass

                def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
                    self.assert_wait = (wait, cancel_futures)
                    shutdown_started.set()
                    self.assertTrue = release_join.wait(3)

            code = (
                "import sys; from pathlib import Path; "
                "from hermes_zulip_bridge.locking import ProcessLockError, process_lock; "
                "\ntry:\n"
                " with process_lock(Path(sys.argv[1])): print('acquired')\n"
                "except ProcessLockError: print('blocked')\n"
            )
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
            launcher_proof = self.launcher_proof()

            with (
                mock.patch.multiple(
                    bridge,
                    STATE_PATH=state_path,
                    STEERING_PATH=root / "steering.jsonl",
                    ALIASES_PATH=root / "aliases.json",
                    RC_PATH=root / "zuliprc",
                    STATE_DB=root / "hermes.db",
                    STEERING_STATE_ASSOCIATED=True,
                    ALIASES_STATE_ASSOCIATED=True,
                ),
                mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                ),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
                mock.patch.object(bridge, "latest_messages", return_value=[]),
                mock.patch.object(bridge, "save_json"),
                mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
                mock.patch.object(bridge.time, "sleep", side_effect=KeyboardInterrupt),
            ):
                worker = threading.Thread(
                    target=lambda: self._capture_exception(
                        errors, lambda: bridge.main(launcher_proof=launcher_proof)
                    )
                )
                worker.start()
                self.assertTrue(shutdown_started.wait(2))
                held = subprocess.run(
                    [sys.executable, "-c", code, str(state_path)],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(held.stdout.strip(), "blocked")
                release_join.set()
                worker.join(3)
                released = subprocess.run(
                    [sys.executable, "-c", code, str(state_path)],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True,
                )

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(released.stdout.strip(), "acquired")

    def test_cleanup_ignores_repeated_term_and_interrupt_then_restores_handlers(self) -> None:
        previous_term = bridge.signal.getsignal(bridge.signal.SIGTERM)
        previous_int = bridge.signal.getsignal(bridge.signal.SIGINT)
        cleanup_observations: list[tuple[object, object]] = []

        def request_term(_seconds: float) -> None:
            handler = bridge.signal.getsignal(bridge.signal.SIGTERM)
            handler(bridge.signal.SIGTERM, None)

        def cleanup(**_kwargs: object) -> bool:
            cleanup_observations.append(
                (
                    bridge.signal.getsignal(bridge.signal.SIGTERM),
                    bridge.signal.getsignal(bridge.signal.SIGINT),
                )
            )
            bridge.signal.getsignal(bridge.signal.SIGTERM)(bridge.signal.SIGTERM, None)
            bridge.signal.getsignal(bridge.signal.SIGINT)(bridge.signal.SIGINT, None)
            return True

        with (
            mock.patch.object(bridge, "load_json", return_value={"topic_sessions": {}}),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge, "shutdown_active_processes", side_effect=cleanup),
            mock.patch.object(bridge.time, "sleep", side_effect=request_term),
        ):
            self.assertEqual(bridge._main(), 0)
        self.assertEqual(len(cleanup_observations), 1)
        self.assertTrue(all(callable(handler) for handler in cleanup_observations[0]))
        self.assertIs(bridge.signal.getsignal(bridge.signal.SIGTERM), previous_term)
        self.assertIs(bridge.signal.getsignal(bridge.signal.SIGINT), previous_int)

    def test_shutdown_terms_kills_reaps_and_clears_only_registered_process_groups(self) -> None:
        class FakeProcess:
            pid = 424242

            def __init__(self) -> None:
                self.killed = False
                self.waits = 0

            def poll(self) -> int | None:
                return -9 if self.killed else None

            def wait(self, timeout: float) -> int:
                self.waits += 1
                if not self.killed:
                    raise subprocess.TimeoutExpired("fake", timeout)
                return -9

            def kill(self) -> None:
                self.killed = True

            def terminate(self) -> None:
                pass

        proc = FakeProcess()
        signals: list[tuple[int, int]] = []

        def fake_killpg(pid: int, sig: int) -> None:
            signals.append((pid, sig))
            if sig == bridge.signal.SIGKILL:
                proc.killed = True

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: proc}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {proc.pid: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {proc.pid: "birth"}, clear=True),
            mock.patch.object(bridge.os, "killpg", side_effect=fake_killpg),
            mock.patch.object(
                bridge, "_local_process_table", return_value={proc.pid: (1, proc.pid, "birth")}
            ),
        ):
            bridge.shutdown_active_processes(grace_seconds=0)
            self.assertEqual(bridge.ACTIVE_PROCESSES, {})
            self.assertEqual(bridge.ACTIVE_INTERRUPTS, {})
        self.assertEqual(signals, [(424242, bridge.signal.SIGTERM), (424242, bridge.signal.SIGKILL)])
        self.assertEqual(proc.waits, 2)
        bridge.SHUTTING_DOWN = False

    def test_shutdown_continues_after_repeated_keyboard_interrupts_mid_reap(self) -> None:
        signals: list[tuple[int, int]] = []

        class InterruptingProcess:
            def __init__(self, pid: int) -> None:
                self.pid = pid
                self.returncode: int | None = None
                self.waits = 0

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                self.waits += 1
                if self.waits < 3:
                    raise KeyboardInterrupt
                return self.returncode or -bridge.signal.SIGKILL

            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                raise KeyboardInterrupt

        processes = [InterruptingProcess(501001), InterruptingProcess(501002)]

        def killpg(pid: int, sig: int) -> None:
            signals.append((pid, sig))
            if sig == bridge.signal.SIGKILL:
                next(proc for proc in processes if proc.pid == pid).returncode = -sig

        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: processes[0], 2: processes[1]}, clear=True),
            mock.patch.dict(
                bridge.ACTIVE_DESCENDANTS,
                {processes[0].pid: set(), processes[1].pid: set()},
                clear=True,
            ),
            mock.patch.dict(
                bridge.ACTIVE_PROCESS_IDENTITIES,
                {processes[0].pid: "birth-1", processes[1].pid: "birth-2"},
                clear=True,
            ),
            mock.patch.object(bridge.os, "killpg", side_effect=killpg),
            mock.patch.object(
                bridge,
                "_local_process_table",
                return_value={
                    processes[0].pid: (1, processes[0].pid, "birth-1"),
                    processes[1].pid: (1, processes[1].pid, "birth-2"),
                },
            ),
        ):
            bridge.shutdown_active_processes(grace_seconds=0)
            self.assertEqual(bridge.ACTIVE_PROCESSES, {})
            self.assertEqual(bridge.ACTIVE_INTERRUPTS, {})
        for proc in processes:
            self.assertIn((proc.pid, bridge.signal.SIGTERM), signals)
            self.assertIn((proc.pid, bridge.signal.SIGKILL), signals)
            self.assertGreaterEqual(proc.waits, 3)
        bridge.SHUTTING_DOWN = False

    def test_first_attempt_permanent_route_failure_dead_letters_before_seen(self) -> None:
        state = {"topic_sessions": {}}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "resolve_session", side_effect=bridge.ReplyRoutingError("permanent route")),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        self.assertEqual(state["origin_in_flight"], [])
        self.assertEqual(state["origin_retries"], [])
        self.assertEqual(state["dead_letters"][0]["origin_message_id"], 44)
        self.assertIn("route:", state["dead_letters"][0]["reason"])
        self.assertIn(44, state["seen_ids"])

    def test_post_hermes_worker_failure_dead_letters_before_inflight_removal(self) -> None:
        state = {"topic_sessions": {}}
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "content": "hello",
        }
        failed = threading.Event()
        sleeps = 0

        def worker(_rc: dict, current: dict, _session_id: str | None) -> None:
            current["_zulip_before_hermes_start"]()
            current["_zulip_execution"]["hermes_started"] = True
            failed.set()
            raise RuntimeError("Hermes failed")

        def stop_after_failure(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            if sleeps == 1:
                self.assertTrue(failed.wait(2))
                return
            raise StopIteration

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "handle_message", side_effect=worker),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "sleep", side_effect=stop_after_failure),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        self.assertEqual(state["origin_in_flight"], [])
        self.assertEqual(state["dead_letters"][0]["origin_message_id"], 44)
        self.assertIn("post_hermes", state["dead_letters"][0]["reason"])

    def test_missing_reconciliation_source_terminalizes_without_api_or_owner_creation(self) -> None:
        state = {
            "realm": "example",
            "topic_sessions": {},
            "reply_reconciliations": [
                {
                    "origin_message_id": 44,
                    "sent_message_id": 999,
                    "realm": "example",
                    "source_thread_id": "missing-thread",
                    "session_id": "s1",
                    "confirmed_stream_id": 1,
                    "confirmed_stream": "stream-1",
                    "confirmed_topic": "Topic",
                    "attempts": 0,
                    "created_at": 10.0,
                    "next_attempt_at": 10.0,
                }
            ],
        }
        api = mock.Mock(side_effect=AssertionError("invalid provenance reached Zulip"))
        bridge.state_signing_key_path(bridge.STATE_PATH).write_bytes(SIGNING_KEY)
        bridge.state_signing_key_path(bridge.STATE_PATH).chmod(0o600)
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(bridge, "load_rc", return_value={"site": "https://example", "email": "bot@example.com", "key": "secret"}),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge, "api", api),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "time", return_value=20.0),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        api.assert_not_called()
        self.assertEqual(state.get("zulip_threads", {}), {})
        self.assertEqual(state["reply_reconciliations"], [])
        self.assertEqual(state["dead_letters"][0]["sent_message_id"], 999)

    def test_unrelated_sent_message_never_reaches_patch(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        job = bridge._reply_reconciliation_job(
            {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
            999,
            SIGNING_KEY,
            "answer",
        )
        state["reply_reconciliations"] = [job]
        patches = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal patches
            if path == "/api/v1/messages/44":
                return zulip_success(message={**bot_message(44, 1, "After", stream="stream-1"), "sender_email": "user@example.com"})
            if path == "/api/v1/messages/999":
                return zulip_success(message={**bot_message(999, 1, "Before", stream="stream-1"), "sender_email": "other@example.com"})
            if method == "PATCH":
                patches += 1
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", fake_api):
            bridge.reconcile_pending_replies(
                {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}, state, SIGNING_KEY
            )
        self.assertEqual(patches, 0)
        self.assertEqual(state["reply_reconciliations"], [])
        self.assertEqual(len(state["zulip_threads"]), 1)
        self.assertEqual(state["dead_letters"][0]["sent_message_id"], 999)

    def test_malformed_patch_is_retained_then_already_moved_verifies_without_second_patch(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
        job = bridge._reply_reconciliation_job(
            {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "Before"},
            900,
            SIGNING_KEY,
            "answer",
        )
        state["reply_reconciliations"] = [job]
        moved = False
        patches = 0

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal moved, patches
            if path == "/api/v1/messages/44":
                return zulip_success(message={**bot_message(44, 1, "After", stream="stream-1"), "sender_email": "user@example.com"})
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, "After" if moved else "Before", stream="stream-1"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "PATCH":
                patches += 1
                moved = True
                return bridge._check_zulip_result(
                    "PATCH",
                    path,
                    {"result": "error", "msg": "status unavailable", "code": "BAD_REQUEST"},
                    safe_read=False,
                )
            raise AssertionError((method, path))

        rc = {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
        with mock.patch.object(bridge, "api", fake_api):
            bridge.reconcile_pending_replies(
                rc, state, SIGNING_KEY, now=job["next_attempt_at"], persist=lambda: None
            )
            self.assertEqual(len(state["reply_reconciliations"]), 1)
            self.assertEqual(state["reply_reconciliations"][0]["attempted_routes"][0]["topic"], "After")
            retry_at = state["reply_reconciliations"][0]["next_attempt_at"]
            bridge.reconcile_pending_replies(rc, state, SIGNING_KEY, now=retry_at, persist=lambda: None)

        self.assertEqual(patches, 1)
        self.assertEqual(state["reply_reconciliations"], [])
        self.assertEqual(state.get("dead_letters", []), [])

    def test_initial_health_gate_has_no_durable_worker_or_reconciliation_side_effects(self) -> None:
        state = {
            "topic_sessions": {},
            "origin_in_flight": [
                {"origin_message_id": 44, "stage": "admitted", "attempts": 0, "created_at": 1.0}
            ],
        }
        before = json.loads(json.dumps(state))
        recover = mock.Mock(side_effect=AssertionError("recovery ran before health gate"))
        reconcile = mock.Mock(side_effect=AssertionError("reconciliation ran before health gate"))
        queued = mock.Mock(side_effect=AssertionError("queued GET ran before health gate"))
        save = mock.Mock(side_effect=AssertionError("state persisted before health gate"))
        executor = mock.Mock(side_effect=AssertionError("worker pool created before health gate"))
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=None),
            mock.patch.object(bridge, "latest_messages", side_effect=bridge.ZulipResponseError("malformed")),
            mock.patch.object(bridge, "_recover_in_flight_origins", recover),
            mock.patch.object(bridge, "reconcile_pending_replies", reconcile),
            mock.patch.object(bridge, "queued_origin_messages", queued),
            mock.patch.object(bridge, "save_json", save),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", executor),
            self.assertRaisesRegex(SystemExit, "Initial Zulip message poll failed"),
        ):
            bridge._main()
        self.assertEqual(state, before)
        recover.assert_not_called()
        reconcile.assert_not_called()
        queued.assert_not_called()
        save.assert_not_called()
        executor.assert_not_called()

    def test_initial_health_page_is_reused_as_the_first_loop_input(self) -> None:
        state = {"topic_sessions": {}}
        page = [
            {
                "id": 44,
                "type": "stream",
                "stream_id": 1,
                "display_recipient": "stream-1",
                "topic": "Topic",
                "sender_email": "other-bot@example.com",
                "sender_is_bot": True,
                "content": "ignore",
            }
        ]
        latest = mock.Mock(return_value=page)
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()
        latest.assert_called_once()
        self.assertEqual(state["seen_ids"], [44])

    def test_generation_refresh_precedes_attachment_history_and_records_live_scope(self) -> None:
        message = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Old",
            "content": "stale",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "_zulip_bridge": {
                "realm": "example",
                "thread_id": "thread",
                "session_id": "s1",
                "conversation_key": "zulip:example:1:thread",
            },
        }

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            self.assertEqual((method, path), ("GET", "/api/v1/messages/44"))
            return zulip_success(
                message={
                    "id": 44,
                    "type": "stream",
                    "stream_id": 1,
                    "display_recipient": "stream-1",
                    "topic": "Old",
                    "sender_id": 17,
                    "sender_email": "user@example.com",
                    "sender_is_bot": False,
                    "content": "live /user_uploads/1/a/file.txt",
                }
            )

        def stop_at_attachments(_rc: dict, content: str, _directory: Path) -> str:
            self.assertEqual(content, "live /user_uploads/1/a/file.txt")
            self.assertEqual(message["_zulip_generation_route"]["stream_id"], 1)
            self.assertEqual(message["_zulip_generation_route"]["thread_id"], "thread")
            self.assertEqual(message["_zulip_generation_route"]["topic"], "Old")
            raise bridge.ReplyRoutingError("attachments reached after refresh")

        with (
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.object(bridge, "ensure_reply_destination_owner", return_value=None),
            mock.patch.object(bridge, "build_attachment_context", side_effect=stop_at_attachments),
            self.assertRaisesRegex(bridge.ReplyRoutingError, "after refresh"),
        ):
            bridge.hermes_reply(
                {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}, message, "s1"
            )
        self.assertEqual((message["stream_id"], message["topic"]), (1, "Old"))

    def test_generated_reply_follows_current_same_stream_topic_but_not_cross_scope_moves(self) -> None:
        for destination, should_post in (
            ((1, "Before", "s1"), True),
            ((1, "✔ Before", "s1"), True),
            ((1, "Renamed", "s1"), True),
            ((2, "Moved", "s1"), False),
            ((1, "Other", "s2"), False),
        ):
            stream_id, topic, owner = destination
            with self.subTest(stream_id=stream_id, topic=topic, owner=owner):
                state = {"topic_sessions": {}}
                source = self.seed_topic(state, message_id=44, stream_id=1, topic="Before", session_id="s1")
                if owner == "s2":
                    self.seed_topic(state, message_id=60, stream_id=1, topic=topic, session_id="s2")
                message = {
                    "id": 44,
                    "type": "stream",
                    "stream_id": 1,
                    "display_recipient": "stream-1",
                    "topic": "Before",
                    "_zulip_state": state,
                    "_zulip_signing_key": SIGNING_KEY,
                    "_zulip_persist": lambda: None,
                    "_zulip_bridge": {**source, "session_id": "s1"},
                    "_zulip_generation_route": {
                        "realm": "example",
                        "thread_id": source["thread_id"],
                        "session_id": "s1",
                        "stream_id": 1,
                        "topic": "Before",
                        "native_id": "",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                    },
                }
                posts: list[dict] = []

                def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
                    if path == "/api/v1/messages/44":
                        return zulip_success(
                            message=user_message(44, stream_id, topic)
                        )
                    if path == "/api/v1/messages/matches_narrow":
                        return zulip_success(messages={"44": narrow_match()})
                    if method == "POST":
                        posts.append(kwargs.get("data") or {})
                        return zulip_success(id=900)
                    raise AssertionError((method, path))

                with mock.patch.object(bridge, "api", side_effect=fake_api):
                    if should_post:
                        bridge.reply({}, message, "answer")
                    else:
                        with self.assertRaises(bridge.ReplyRoutingError):
                            bridge.reply({}, message, "answer")
                self.assertEqual(len(posts), int(should_post))

    def test_active_generation_posts_once_to_renamed_resolved_or_unresolved_topic(self) -> None:
        for started, current in (
            ("Before", "Renamed"),
            ("Before", "✔ Before"),
            ("✔ Before", "Before"),
        ):
            with self.subTest(started=started, current=current):
                state: dict = {"topic_sessions": {}}
                source = self.seed_topic(
                    state, message_id=44, stream_id=1, topic=started, session_id="s1"
                )
                message = user_message(44, 1, started)
                message.update(
                    _zulip_state=state,
                    _zulip_signing_key=SIGNING_KEY,
                    _zulip_persist=lambda: None,
                    _zulip_bridge={**source, "session_id": "s1"},
                    _zulip_generation_route={
                        "realm": "example",
                        "thread_id": source["thread_id"],
                        "session_id": "s1",
                        "stream_id": 1,
                        "topic": started,
                        "native_id": "",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                    },
                )
                posts: list[dict] = []

                def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
                    if path == "/api/v1/messages/44":
                        return zulip_success(message=user_message(44, 1, current))
                    if path == "/api/v1/messages/matches_narrow":
                        return zulip_success(messages={"44": narrow_match()})
                    if method == "POST":
                        posts.append(kwargs["data"])
                        return zulip_success(id=900)
                    raise AssertionError((method, path))

                with mock.patch.object(bridge, "api", side_effect=fake_api):
                    bridge.reply({}, message, "answer")
                self.assertEqual([post["topic"] for post in posts], [current])

    def test_first_turn_reply_publishes_new_session_only_after_confirmed_post(self) -> None:
        state, message, conversation = self.first_turn_reply()
        snapshots: list[dict] = []
        message["_zulip_persist"] = lambda: snapshots.append(json.loads(json.dumps(state)))

        def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(message=user_message(44, 1, "Before"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                self.assertEqual(state["zulip_threads"][conversation["thread_id"]]["session_id"], "")
                return zulip_success(id=900)
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", side_effect=fake_api):
            bridge.reply({"site": "https://example", "email": "bot@example.com"}, message, "answer")

        self.assertEqual(state["zulip_threads"][conversation["thread_id"]]["session_id"], "new-session")
        self.assertEqual(set(state["topic_sessions"].values()), {"new-session"})
        self.assertEqual([job["sent_message_id"] for job in state["reply_reconciliations"]], [900])
        self.assertEqual(snapshots[-1], state)

    def test_first_turn_reply_follows_same_stream_move_but_rejects_foreign_owner(self) -> None:
        for foreign in (False, True):
            with self.subTest(foreign=foreign):
                state, message, conversation = self.first_turn_reply()
                if foreign:
                    self.seed_topic(state, message_id=60, stream_id=1, topic="After", session_id="other-session")
                posts = mock.Mock()

                def fake_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                    if path == "/api/v1/messages/44":
                        return zulip_success(message=user_message(44, 1, "After"))
                    if path == "/api/v1/messages/matches_narrow":
                        return zulip_success(messages={"44": narrow_match()})
                    if method == "POST":
                        posts()
                        return zulip_success(id=900)
                    raise AssertionError((method, path))

                with mock.patch.object(bridge, "api", side_effect=fake_api):
                    if foreign:
                        with self.assertRaises(bridge.ReplyRoutingError):
                            bridge.reply({"site": "https://example"}, message, "answer")
                    else:
                        bridge.reply({"site": "https://example"}, message, "answer")

                self.assertEqual(posts.call_count, 0 if foreign else 1)
                self.assertEqual(
                    state["zulip_threads"][conversation["thread_id"]]["session_id"],
                    "" if foreign else "new-session",
                )
                self.assertEqual(len(state.get("reply_reconciliations", [])), 0 if foreign else 1)

    def test_first_turn_definite_post_retry_publishes_once_and_uncertain_post_never_publishes(self) -> None:
        state, message, conversation = self.first_turn_reply()
        attempts = 0

        def definite_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal attempts
            if path == "/api/v1/messages/44":
                return zulip_success(message=user_message(44, 1, "Before"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                attempts += 1
                if attempts == 1:
                    error = RuntimeError("definite failure")
                    error.__cause__ = bridge.ZulipResponseError("rejected", retryable=True, uncertain=False)
                    raise error
                return zulip_success(id=900)
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", side_effect=definite_api):
            with self.assertRaises(RuntimeError):
                bridge.reply({}, message, "answer")
            self.assertEqual(state["zulip_threads"][conversation["thread_id"]]["session_id"], "")
            self.assertEqual(state.get("reply_reconciliations", []), [])
            bridge.reply({}, message, "answer")

        self.assertEqual(attempts, 2)
        self.assertEqual(state["zulip_threads"][conversation["thread_id"]]["session_id"], "new-session")

        uncertain_state, uncertain_message, uncertain_conversation = self.first_turn_reply()

        def uncertain_api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/44":
                return zulip_success(message=user_message(44, 1, "Before"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                error = RuntimeError("timeout")
                error.__cause__ = bridge.ZulipResponseError("unknown", uncertain=True)
                raise error
            raise AssertionError((method, path))

        with mock.patch.object(bridge, "api", side_effect=uncertain_api), self.assertRaises(
            bridge.ReplyPostUncertain
        ):
            bridge.reply({}, uncertain_message, "answer")
        self.assertEqual(
            uncertain_state["zulip_threads"][uncertain_conversation["thread_id"]]["session_id"], ""
        )
        self.assertEqual(uncertain_state.get("reply_reconciliations", []), [])

    def test_parent_native_ids_migrate_atomically_idempotently_and_support_existing_scale(self) -> None:
        state: dict = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        for index in range(33):
            old = f"native-parent-{index}"
            topic = f"Topic {index}"
            state["zulip_threads"][old] = {
                "thread_id": old,
                "conversation_key": bridge.conversation_key("example", 7, old),
                "realm": "example",
                "stream": "stream-7",
                "stream_id": "7",
                "current_display_topic": topic,
                "topic_aliases": [topic],
                "session_id": f"session-{index}",
                "last_seen_message_id": index + 1,
            }
            state["zulip_topic_aliases"][bridge.topic_alias_lookup_key("example", 7, topic)] = old

        bridge.bind_state_realm(state, "example")
        scope = bridge._native_scope("example", 7)
        self.assertEqual(len(state["zulip_threads"]), 33)
        self.assertTrue(all(thread_id.startswith(f"native-{scope}-parent-") for thread_id in state["zulip_threads"]))
        self.assertTrue(all(owner in state["zulip_threads"] for owner in state["zulip_topic_aliases"].values()))
        migrated = json.loads(json.dumps(state))
        bridge.bind_state_realm(state, "example")
        self.assertEqual(state, migrated)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            bridge.save_json(path, state)
            self.assertEqual(bridge.require_state_object(bridge.load_json(path, {})), state)

    def test_parent_native_migration_fails_closed_on_scoped_or_cross_scope_conflict(self) -> None:
        scope = bridge._native_scope("example", 7)
        old = "native-parent"
        new = f"native-{scope}-parent"

        def thread(thread_id: str, session: str) -> dict:
            return {
                "thread_id": thread_id,
                "conversation_key": bridge.conversation_key("example", 7, thread_id),
                "realm": "example",
                "stream": "stream-7",
                "stream_id": "7",
                "current_display_topic": "Topic",
                "topic_aliases": ["Topic"],
                "session_id": session,
                "last_seen_message_id": 1,
            }

        conflict = {"realm": "example", "topic_sessions": {}, "zulip_threads": {old: thread(old, "s1"), new: thread(new, "s2")}}
        before = json.loads(json.dumps(conflict))
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "legacy and scoped"):
            bridge.bind_state_realm(conflict, "example")
        self.assertEqual(conflict, before)

        cross_scope_id = "native-0000000000000000-parent"
        cross_scope = {"realm": "example", "topic_sessions": {}, "zulip_threads": {cross_scope_id: thread(cross_scope_id, "s1")}}
        before = json.loads(json.dumps(cross_scope))
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "another realm/stream"):
            bridge.bind_state_realm(cross_scope, "example")
        self.assertEqual(cross_scope, before)

        scoped = {"realm": "example", "topic_sessions": {}, "zulip_threads": {new: thread(new, "s1")}}
        before = json.loads(json.dumps(scoped))
        bridge.bind_state_realm(scoped, "example")
        self.assertEqual(scoped, before)

    def test_partial_binary_and_image_attachments_are_omitted_without_materialization(self) -> None:
        items = {
            "screen.png": ("image/png", b"1234", True, 8),
            "archive.bin": ("application/octet-stream", b"1234", True, None),
            "misleading.bin": ("text/plain", b"1234", True, 5),
        }

        def fetch(_rc: dict, path: str) -> dict:
            name = path.rsplit("/", 1)[-1]
            content_type, data, truncated, length = items[name]
            return {
                "path": path,
                "filename": name,
                "content_type": content_type,
                "content_length": length,
                "data": data,
                "truncated_bytes": truncated,
                "error": "",
            }

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            bridge, "fetch_zulip_attachment", side_effect=fetch
        ), mock.patch.object(bridge, "ATTACHMENT_MAX_BYTES", 4):
            directory = Path(tmpdir)
            context = bridge.build_attachment_context(
                {"site": "https://example"},
                " ".join(f"/user_uploads/1/a/{name}" for name in items),
                directory,
            )
            self.assertEqual(list(directory.iterdir()), [])

        self.assertEqual(context.count("[Omitted: incomplete binary/image attachment"), 3)
        self.assertIn("limit 4 bytes", context)
        self.assertNotIn("local path:", context)

    def test_exact_limit_binary_materializes_while_text_keeps_separate_truncation_semantics(self) -> None:
        def fetch(_rc: dict, path: str) -> dict:
            text = path.endswith("note.txt")
            return {
                "path": path,
                "filename": path.rsplit("/", 1)[-1],
                "content_type": "text/plain" if text else "image/png",
                "content_length": 4 if not text else 8,
                "data": b"abcd",
                "truncated_bytes": text,
                "error": "",
            }

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            bridge, "fetch_zulip_attachment", side_effect=fetch
        ), mock.patch.object(bridge, "ATTACHMENT_MAX_BYTES", 4):
            context = bridge.build_attachment_context(
                {"site": "https://example"},
                "/user_uploads/1/a/exact.png /user_uploads/1/a/note.txt",
                Path(tmpdir),
            )
            materialized = {path.name: path.read_bytes() for path in Path(tmpdir).iterdir()}

        self.assertEqual(materialized, {"1-exact.png": b"abcd"})
        self.assertIn("Image local path:", context)
        self.assertIn("----- BEGIN ZULIP ATTACHMENT: note.txt -----", context)
        self.assertIn("[Truncated: read limit of 4 bytes reached.]", context)

    def test_live_generation_authorization_rejects_identity_route_and_policy_changes_but_accepts_edit(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")

        def admitted() -> dict:
            return {
                **user_message(44, 1, "Topic", content="original"),
                "_zulip_state": state,
                "_zulip_bridge": {**source, "session_id": "s1"},
            }

        edited = user_message(44, 1, "Topic", content="edited")
        message = admitted()
        with mock.patch.object(bridge, "live_origin_message", return_value=edited), mock.patch.object(
            bridge, "ensure_reply_destination_owner", return_value=None
        ):
            self.assertEqual(bridge.refresh_generation_origin({"email": "bot@example.com"}, message)["content"], "edited")
        self.assertEqual(message["content"], "edited")

        cases = {
            "bot": {**user_message(44, 1, "Topic"), "sender_is_bot": True},
            "sender": {**user_message(44, 1, "Topic"), "sender_email": "other@example.com"},
            "missing-sender": {key: value for key, value in user_message(44, 1, "Topic").items() if key != "sender_email"},
            "missing-content": {key: value for key, value in user_message(44, 1, "Topic").items() if key != "content"},
            "moved": user_message(44, 1, "Other"),
            "native": {**user_message(44, 1, "Topic"), "topic_id": "changed-native"},
        }
        for label, live in cases.items():
            message = admitted()
            with self.subTest(label=label), mock.patch.object(
                bridge, "live_origin_message", return_value=live
            ), mock.patch.object(bridge, "ensure_reply_destination_owner", return_value=None), self.assertRaises(
                bridge.ReplyRoutingError
            ) as raised:
                bridge.refresh_generation_origin({"email": "bot@example.com"}, message)
            self.assertNotIn("_zulip_generation_route", message)
            self.assertEqual(raised.exception.retryable, label.startswith("missing"))

        message = admitted()
        with mock.patch.object(bridge, "ALLOW_STREAM_IDS", {"2"}), mock.patch.object(
            bridge, "live_origin_message", return_value=user_message(44, 1, "Topic")
        ), mock.patch.object(bridge, "ensure_reply_destination_owner", return_value=None), self.assertRaises(
            bridge.ReplyRoutingError
        ):
            bridge.refresh_generation_origin({"email": "bot@example.com"}, message)

    def test_normal_turn_refetches_edited_raw_markdown_with_attachment_for_hermes(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")
        message = {
            **user_message(44, 1, "Topic", content="**raw prompt**"),
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }
        edited = "**edited raw prompt** [notes](/user_uploads/1/ab/notes.md)"
        single_params: list[dict] = []
        history_params: list[dict] = []
        stream_kwargs: list[dict] = []
        anchor_kwargs: list[dict] = []

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            self.assertEqual(method, "GET")
            params = dict(kwargs.get("params") or {})
            if path == "/api/v1/messages/44":
                single_params.append(params)
                content = edited if params.get("apply_markdown") == "false" else "<p><strong>rendered</strong></p>"
                return {"message": user_message(44, 1, "Topic", content=content)}
            if path == "/api/v1/streams":
                stream_kwargs.append(dict(kwargs))
                return {"streams": [{"stream_id": 1, "name": "stream-1"}]}
            if path == "/api/v1/messages/matches_narrow":
                anchor_kwargs.append(dict(kwargs))
                return zulip_success(messages={"44": narrow_match()})
            if path == "/api/v1/messages":
                history_params.append(params)
                content = "_raw history_" if params.get("apply_markdown") == "false" else "<p><em>history</em></p>"
                return {
                    "ignored_parameters_unsupported": [],
                    "messages": [user_message(43, 1, "Topic", content=content)],
                }
            raise AssertionError((method, path, kwargs))

        attachment = {
            "path": "/user_uploads/1/ab/notes.md",
            "filename": "notes.md",
            "content_type": "text/markdown",
            "content_length": 17,
            "data": b"# raw attachment\n",
            "truncated_bytes": False,
            "error": "",
        }
        script = self.python_console_script(
            "import json,sys\nprint(json.dumps({'prompt':sys.argv[sys.argv.index('-z')+1]}))"
        )
        rc = {"site": "https://example", "email": "bot@example.com", "key": "test-api-key"}
        with (
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.object(bridge, "fetch_zulip_attachment", return_value=attachment) as fetch,
            mock.patch.object(bridge, "HERMES", script),
            mock.patch.object(bridge, "HERMES_EXTRA_ARGS", ["--toolsets", "coding"]),
            mock.patch.object(bridge, "typing_status"),
            mock.patch.object(bridge, "find_session_by_marker", return_value="child-session"),
            mock.patch.object(bridge, "clean_session_record"),
            mock.patch.object(bridge, "merge_session_into", return_value="s1"),
            mock.patch.object(bridge, "set_session_archived"),
        ):
            answer, session_id = bridge.hermes_reply(rc, message, "s1")

        prompt = json.loads(answer)["prompt"]
        self.assertEqual(session_id, "s1")
        self.assertIn(edited, prompt)
        self.assertIn("# raw attachment", prompt)
        self.assertIn("_raw history_", prompt)
        self.assertNotIn("<strong>rendered</strong>", prompt)
        self.assertEqual(single_params, [{"apply_markdown": "false"}])
        self.assertEqual(history_params[0]["apply_markdown"], "false")
        self.assertEqual(stream_kwargs, [{}])
        self.assertNotIn("apply_markdown", anchor_kwargs[0]["params"])
        fetch.assert_called_once_with(rc, "/user_uploads/1/ab/notes.md")

    def test_live_origin_raw_fetch_retries_missing_or_malformed_envelopes(self) -> None:
        valid = user_message(44, 1, "Topic")
        malformed = [
            {},
            {"message": None},
            {"message": {**valid, "id": 45}},
            {"message": {key: value for key, value in valid.items() if key != "display_recipient"}},
            {"message": {key: value for key, value in valid.items() if key != "topic"}},
            {"message": {**valid, "stream_id": "invalid"}},
        ]
        for payload in malformed:
            api = mock.Mock(return_value=payload)
            with self.subTest(payload=payload), mock.patch.object(bridge, "api", api), self.assertRaises(
                bridge.ReplyRoutingError
            ) as raised:
                bridge.live_origin_message({}, {"id": 44})
            self.assertTrue(raised.exception.retryable)
            api.assert_called_once_with(
                {}, "GET", "/api/v1/messages/44", params={"apply_markdown": "false"}
            )

    def test_active_steering_refetch_requests_raw_markdown(self) -> None:
        raw = "**steer raw** [link](https://example.com/path)"
        calls: list[dict] = []

        def fake_api(_rc: dict, _method: str, _path: str, **kwargs: object) -> dict:
            params = dict(kwargs.get("params") or {})
            calls.append(params)
            content = raw if params.get("apply_markdown") == "false" else "<p><strong>steer rendered</strong></p>"
            return {"message": user_message(222, 1, "Topic", content=content)}

        with mock.patch.object(bridge, "api", side_effect=fake_api), mock.patch.object(
            bridge, "ensure_reply_destination_owner"
        ):
            live = bridge.validated_active_steering_message(
                {"email": "bot@example.com"}, user_message(222, 1, "Topic")
            )
        self.assertEqual(live["content"], raw)
        self.assertEqual(calls, [{"apply_markdown": "false"}])

    def test_incomplete_live_origin_returns_admission_to_retry_unseen_and_not_in_flight(self) -> None:
        state: dict = {"topic_sessions": {}}
        message = user_message(44, 1, "Topic")
        incomplete = {key: value for key, value in message.items() if key != "sender_email"}

        class ImmediateFuture:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error:
                    raise self.error
                return self.value

        class ImmediateExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, function, *args: object) -> ImmediateFuture:
                return ImmediateFuture(function, *args)

            def shutdown(self, **_kwargs: object) -> None:
                pass

        def worker(rc: dict, worker_message: dict, _session_id: str | None) -> str | None:
            bridge.refresh_generation_origin(rc, worker_message)
            raise AssertionError("incomplete live origin reached Hermes")

        sleeps = 0

        def stop_after_completion(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            if sleeps == 2:
                raise StopIteration

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "live_origin_message", return_value=incomplete),
            mock.patch.object(bridge, "handle_message", side_effect=worker),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=stop_after_completion),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        self.assertNotIn(44, state["seen_ids"])
        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [44])
        self.assertEqual(state["origin_in_flight"], [])

    def test_overlong_state_inputs_and_mutations_fail_without_amplification_or_partial_write(self) -> None:
        overlong = "x" * (bridge.MAX_NATIVE_ID_CHARS + 1)
        logger = mock.Mock()
        with mock.patch.object(bridge, "log", logger), self.assertRaisesRegex(
            bridge.ReplyRoutingError, "native thread ID"
        ):
            bridge.stable_zulip_thread_id("example", 1, "Topic", {"topic_id": overlong})
        logger.assert_not_called()

        state = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        conversation = {
            "thread_id": "t" * (bridge.MAX_IDENTIFIER_CHARS + 1),
            "conversation_key": "key",
            "realm": "example",
            "stream": "stream-1",
            "stream_id": "1",
            "topic": "Topic",
            "message_id": "1",
        }
        before = json.loads(json.dumps(state))
        self.assertFalse(bridge.note_bridge_thread(state, conversation, session_id="s1"))
        self.assertEqual(state, before)

        with mock.patch.object(bridge, "MAX_STATE_REGISTRY_ITEMS", 1):
            bridge.require_state_object({"zulip_threads": {"one": {"topic_aliases": []}}})
            with self.assertRaisesRegex(ValueError, "zulip_threads"):
                bridge.require_state_object(
                    {"zulip_threads": {"one": {"topic_aliases": []}, "two": {"topic_aliases": []}}}
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            path.write_bytes(b"sentinel")
            with mock.patch.object(bridge, "MAX_STATE_BYTES", 10), self.assertRaises(
                bridge.StatePersistenceError
            ):
                bridge.save_json(path, {"value": "too large"})
            self.assertEqual(path.read_bytes(), b"sentinel")
            path.write_bytes(b"x" * 11)
            with mock.patch.object(bridge, "MAX_STATE_BYTES", 10), self.assertRaisesRegex(ValueError, "exceeds"):
                bridge.load_json(path, {})

            aliases = Path(tmpdir) / "aliases.json"
            aliases.write_bytes(b"x" * 11)
            aliases.chmod(0o600)
            with mock.patch.object(bridge, "ALIASES_PATH", aliases), mock.patch.object(
                bridge, "MAX_STEERING_BYTES", 10
            ), self.assertRaises(bridge.StatePersistenceError):
                bridge.load_alias_entries()

            steering = Path(tmpdir) / "steering.jsonl"
            with self.assertRaisesRegex(bridge.ReplyRoutingError, "overlong routing"):
                bridge.append_steering_message(
                    steering,
                    {"conversation_key": "x" * (bridge.MAX_IDENTIFIER_CHARS * 3 + 1)},
                    {"id": 1, "content": "ok"},
                )
            with self.assertRaisesRegex(bridge.ReplyRoutingError, "content exceeds"):
                bridge.append_steering_message(
                    steering,
                    {"conversation_key": "key"},
                    {"id": 1, "content": "x" * (bridge.MAX_MESSAGE_CONTENT_CHARS + 1)},
                )
            self.assertFalse(steering.exists())

    def test_persisted_state_schema_rejects_each_bounded_registry_shape_and_migrates_legacy_retry(self) -> None:
        migrated = bridge.require_state_object({"retry_origin_ids": [7]})
        self.assertNotIn("retry_origin_ids", migrated)
        self.assertEqual(migrated["origin_retries"][0]["origin_message_id"], 7)

        retry = {"origin_message_id": 1, "attempts": 1, "created_at": 0.0, "next_attempt_at": 0.0}
        in_flight = {"origin_message_id": 2, "stage": "admitted", "attempts": 0, "created_at": 0.0}
        dead = {
            "kind": "origin",
            "origin_message_id": 3,
            "sent_message_id": None,
            "attempts": 1,
            "created_at": 0.0,
            "terminal_at": 1.0,
            "reason": "terminal",
        }
        recovery = bridge._definite_reply_recovery(
            {
                "id": 3,
                "_zulip_bridge": {"realm": "example", "thread_id": "thread", "session_id": "s1"},
            },
            user_message(3, 1, "Topic"),
            SIGNING_KEY,
            "exact answer",
            400,
        )
        recovery_dead = {**dead, "recovery": recovery}
        self.assertEqual(
            bridge.require_state_object({"dead_letters": [recovery_dead]})["dead_letters"][0]["recovery"]["answer"],
            "exact answer",
        )
        bridge.validate_definite_reply_recoveries({"dead_letters": [recovery_dead]}, SIGNING_KEY)
        with self.assertRaisesRegex(bridge.StatePersistenceError, "provenance"):
            bridge.validate_definite_reply_recoveries(
                {"dead_letters": [recovery_dead]}, b"wrong-signing-key-material-00000"
            )
        self.assertEqual(bridge.require_state_object({"dead_letters": [dead]})["dead_letters"], [dead])
        invalid = [
            ("retry list", {"origin_retries": {}}, "origin_retries"),
            ("duplicate retry", {"origin_retries": [retry, retry]}, "duplicate"),
            ("in-flight list", {"origin_in_flight": {}}, "in_flight"),
            ("in-flight stage", {"origin_in_flight": [{**in_flight, "stage": "bad"}]}, "in-flight"),
            ("dead list", {"dead_letters": {}}, "dead_letters"),
            ("dead entry", {"dead_letters": [{**dead, "reason": ""}]}, "dead letter"),
            (
                "recovery bound",
                {"dead_letters": [{**recovery_dead, "recovery": {**recovery, "answer": "x" * (bridge.MAX_MESSAGE_CONTENT_CHARS + 1)}}]},
                "recovery",
            ),
            (
                "recovery digest",
                {"dead_letters": [{**recovery_dead, "recovery": {**recovery, "answer_digest": "0" * 64}}]},
                "recovery",
            ),
            (
                "recovery transient status",
                {"dead_letters": [{**recovery_dead, "recovery": {**recovery, "http_status": 503}}]},
                "recovery",
            ),
            ("thread field", {"zulip_threads": {"t": {"realm": 1, "topic_aliases": []}}}, "realm must"),
            (
                "thread field length",
                {"zulip_threads": {"t": {"realm": "x" * (bridge.MAX_IDENTIFIER_CHARS + 1), "topic_aliases": []}}},
                "exceeds",
            ),
            ("thread stream", {"zulip_threads": {"t": {"stream_id": 0, "topic_aliases": []}}}, "stream_id"),
            ("thread key", {"zulip_threads": {"t": {"thread_id": "other", "topic_aliases": []}}}, "inconsistent"),
            ("realm", {"realm": ""}, "realm"),
            ("jobs", {"reply_reconciliations": {}}, "reply_reconciliations"),
            ("json", {"unknown": b"not-json"}, "serializable"),
        ]
        for label, state, pattern in invalid:
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, pattern):
                bridge.require_state_object(state)

        with mock.patch.object(bridge, "MAX_ORIGIN_RETRIES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds capacity"):
                bridge.require_state_object({"origin_retries": [retry, {**retry, "origin_message_id": 2}]})
            with self.assertRaisesRegex(ValueError, "durable origin"):
                bridge.require_state_object({"origin_retries": [retry], "origin_in_flight": [in_flight]})
        with mock.patch.object(bridge, "MAX_DEAD_LETTERS", 0), self.assertRaisesRegex(ValueError, "dead_letters"):
            bridge.require_state_object({"dead_letters": [dead]})

        legacy_job = {
            "origin_message_id": 1,
            "sent_message_id": 2,
            "realm": "example",
            "source_thread_id": "thread",
            "session_id": "",
            "confirmed_stream_id": 1,
            "confirmed_stream": "stream-1",
            "confirmed_topic": "Topic",
        }
        migrated_job = bridge.require_state_object({"reply_reconciliations": [legacy_job]})[
            "reply_reconciliations"
        ][0]
        self.assertEqual((migrated_job["attempts"], migrated_job["next_attempt_at"]), (0, 0.0))
        with mock.patch.object(bridge, "MAX_REPLY_RECONCILIATIONS", 0), self.assertRaisesRegex(
            ValueError, "exceeds capacity"
        ):
            bridge.require_state_object({"reply_reconciliations": [legacy_job]})

        for field, value, pattern in (
            ("sent_message_id", 0, "message IDs"),
            ("confirmed_stream_id", 0, "stream ID"),
            ("source_thread_id", "x" * (bridge.MAX_IDENTIFIER_CHARS + 1), "source_thread_id"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, pattern):
                bridge.require_state_object({"reply_reconciliations": [{**legacy_job, field: value}]})

    def test_attachment_transport_marks_declared_short_reads_and_handles_nonmaterialized_binary(self) -> None:
        class Response:
            headers = {"Content-Type": "application/octet-stream", "Content-Length": "8"}

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def read(self, _limit: int) -> bytes:
                return b"1234"

        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch.object(bridge.urllib.request, "build_opener", return_value=opener), mock.patch.object(
            bridge, "ATTACHMENT_MAX_BYTES", 8
        ):
            item = bridge.fetch_zulip_attachment(
                {"site": "https://example", "email": "bot@example.com", "key": "key"},
                "/user_uploads/1/a/file.bin",
            )
        self.assertTrue(item["truncated_bytes"])

        complete = {**item, "content_length": 4, "truncated_bytes": False, "error": ""}
        with mock.patch.object(bridge, "fetch_zulip_attachment", return_value=complete):
            context = bridge.build_attachment_context(
                {"site": "https://example"}, "/user_uploads/1/a/file.bin"
            )
        self.assertIn("no local materialization directory", context)

        with mock.patch.object(bridge.urllib.request, "build_opener", side_effect=RuntimeError("transport")):
            failed = bridge.fetch_zulip_attachment(
                {"site": "https://example", "email": "bot@example.com", "key": "key"},
                "/user_uploads/1/a/file.bin",
            )
        self.assertEqual((failed["error"], failed["retryable"]), ("RuntimeError", True))

    def test_process_identity_fallbacks_and_pidfd_signal_are_birth_checked(self) -> None:
        proc_stat = "123 (cmd) " + " ".join(["S", *(["0"] * 18), "42"])
        with mock.patch.object(Path, "read_text", return_value=proc_stat):
            self.assertEqual(bridge._process_birth_identity(123), "linux:42")

        ps = mock.Mock()
        ps.communicate.return_value = ("Mon Jan  1 00:00:00 2024\n", "")
        with mock.patch.object(Path, "read_text", side_effect=OSError), mock.patch.object(
            bridge.sys, "platform", "other"
        ), mock.patch.object(bridge, "SYSTEM_POPEN", return_value=ps):
            self.assertEqual(bridge._process_birth_identity(123), "ps:Mon Jan 1 00:00:00 2024")

        table_ps = mock.Mock()
        table_ps.communicate.return_value = (
            f"10 1 10 {os.geteuid()} Mon Jan  1 00:00:00 2024\ninvalid\n",
            "",
        )
        with mock.patch.object(bridge.sys, "platform", "other"), mock.patch.object(
            bridge, "SYSTEM_POPEN", return_value=table_ps
        ):
            self.assertEqual(bridge._local_process_table()[10], (1, 10, "ps:Mon Jan 1 00:00:00 2024"))

        pidfd_open = mock.Mock(return_value=55)
        pidfd_signal = mock.Mock()
        close = mock.Mock()
        with mock.patch.object(bridge.os, "pidfd_open", pidfd_open, create=True), mock.patch.object(
            bridge.signal, "pidfd_send_signal", pidfd_signal, create=True
        ), mock.patch.object(bridge.os, "close", close), mock.patch.object(
            bridge, "_local_process_table", return_value={10: (1, 10, "birth")}
        ):
            self.assertTrue(bridge._signal_pid_if_current(10, 10, "birth", bridge.signal.SIGTERM))
        pidfd_signal.assert_called_once_with(55, bridge.signal.SIGTERM)
        close.assert_called_once_with(55)

    def test_latest_message_and_alias_inputs_reject_overlong_or_malformed_members_as_one_page(self) -> None:
        valid_private = {"id": 1, "type": "private", "content": "hello"}
        with mock.patch.object(bridge, "api", return_value=zulip_success(messages=[valid_private])):
            self.assertEqual(bridge.latest_messages({}), [valid_private])

        malformed = [
            {"id": 1, "type": "stream", "stream_id": 1, "topic": "x" * (bridge.MAX_ROUTE_CHARS + 1)},
            {
                **user_message(1, 1, "Topic"),
                "topic_id": "x" * (bridge.MAX_NATIVE_ID_CHARS + 1),
            },
            {"id": 1, "type": "stream", "stream_id": 0, "topic": "Topic"},
            {"id": 1, "type": "unknown"},
        ]
        for member in malformed:
            with self.subTest(member=list(member)), mock.patch.object(
                bridge, "api", return_value=zulip_success(messages=[valid_private, member])
            ), self.assertRaises(bridge.ZulipResponseError):
                bridge.latest_messages({})

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "aliases.json"
            entries = [
                {"stream_id": 1, "topic": "Topic", "session_id": "s1"},
                {"stream_id": 1, "topic": "Other", "session_id": "s2"},
            ]
            path.write_text(json.dumps({"aliases": entries}), encoding="utf-8")
            path.chmod(0o600)
            with mock.patch.object(bridge, "ALIASES_PATH", path), mock.patch.object(
                bridge, "MAX_STATE_REGISTRY_ITEMS", 1
            ), self.assertRaisesRegex(ValueError, "exceeds capacity"):
                bridge.load_alias_entries()
            for field, value in (
                ("topic", "x" * (bridge.MAX_ROUTE_CHARS + 1)),
                ("session_id", "x" * (bridge.MAX_IDENTIFIER_CHARS + 1)),
                ("stream", "x" * (bridge.MAX_ROUTE_CHARS + 1)),
                ("realm", "x" * (bridge.MAX_IDENTIFIER_CHARS + 1)),
            ):
                path.write_text(json.dumps({"aliases": [{**entries[0], field: value}]}), encoding="utf-8")
                with self.subTest(field=field), mock.patch.object(bridge, "ALIASES_PATH", path), self.assertRaises(
                    ValueError
                ):
                    bridge.load_alias_entries()

    def test_due_origin_fetch_outcomes_persist_terminal_and_retry_states_atomically(self) -> None:
        state = {
            "origin_retries": [
                {"origin_message_id": 1, "attempts": 1, "created_at": 0.0, "next_attempt_at": 0.0},
                {"origin_message_id": 2, "attempts": 1, "created_at": 0.0, "next_attempt_at": 0.0},
            ]
        }

        def fetch(_rc: dict, message: dict) -> dict:
            error = bridge.ReplyRoutingError(
                "temporary" if message["id"] == 2 else "gone",
                retryable=message["id"] == 2,
            )
            raise error

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge, "live_origin_message", side_effect=fetch),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=StopIteration),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        self.assertIn(1, state["seen_ids"])
        self.assertNotIn(2, state["seen_ids"])
        self.assertEqual([item["origin_message_id"] for item in state["dead_letters"]], [1])
        self.assertEqual(state["origin_retries"][0]["origin_message_id"], 2)
        self.assertEqual(state["origin_retries"][0]["attempts"], 2)

    def test_slash_worker_handles_invalid_origin_post_exit_timeout_and_nonzero_exit(self) -> None:
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "stable Zulip message ID"):
            bridge.run_slash_worker("/status", "s1", 0)

        exited = mock.Mock(pid=12345, returncode=0)
        exited.poll.return_value = 0
        exited.communicate.return_value = ('{"ok": true, "output": "done"}\n', "")
        with (
            mock.patch.object(bridge.subprocess, "Popen", return_value=exited),
            mock.patch.object(
                bridge, "_communicate_registered", side_effect=subprocess.TimeoutExpired("slash", 1)
            ),
            mock.patch.object(bridge, "terminate_and_reap_process_group"),
        ):
            self.assertEqual(bridge.run_slash_worker("/status", "s1", 77), "done")

        failed = mock.Mock(pid=12346, returncode=2)
        failed.poll.return_value = 2
        failed.communicate.return_value = ("", "redacted")
        with mock.patch.object(bridge.subprocess, "Popen", return_value=failed), mock.patch.object(
            bridge, "_communicate_registered", return_value=("", "redacted")
        ), self.assertRaisesRegex(RuntimeError, "exit code 2"):
            bridge.run_slash_worker("/status", "s1", 78)

    def test_ownership_mutation_capacity_identity_and_reservation_checks_leave_state_unchanged(self) -> None:
        base = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        conversation = bridge.resolve_zulip_conversation_key(
            {"id": 2, "stream_id": 1, "display_recipient": "stream-1", "topic": "Topic"},
            "example",
            thread_id="thread",
        )

        for label, state, patches in (
            (
                "thread capacity",
                {**base, "zulip_threads": {"existing": {"topic_aliases": []}}},
                {"MAX_STATE_REGISTRY_ITEMS": 1},
            ),
            (
                "alias capacity",
                {**base, "zulip_topic_aliases": {"existing": "existing"}},
                {"MAX_STATE_REGISTRY_ITEMS": 1},
            ),
            (
                "topic alias capacity",
                {
                    **base,
                    "zulip_threads": {
                        "thread": {
                            "thread_id": "thread",
                            "conversation_key": bridge.conversation_key("example", 1, "thread"),
                            "realm": "example",
                            "stream_id": "1",
                            "topic_aliases": ["Old"],
                        }
                    },
                },
                {"MAX_TOPIC_ALIASES_PER_THREAD": 1},
            ),
        ):
            before = json.loads(json.dumps(state))
            with self.subTest(label=label), mock.patch.multiple(bridge, **patches):
                self.assertFalse(bridge._note_bridge_thread_unlocked(state, conversation, "s1"))
            self.assertEqual(state, before)

        invalid_threads = [
            {
                "thread_id": "thread",
                "conversation_key": bridge.conversation_key("example", 1, "thread"),
                "realm": "other",
                "stream_id": "1",
                "topic_aliases": [],
            },
            {
                "thread_id": "thread",
                "conversation_key": "wrong",
                "realm": "example",
                "stream_id": "1",
                "topic_aliases": [],
            },
        ]
        for thread in invalid_threads:
            state = {**base, "zulip_threads": {"thread": thread}}
            before = json.loads(json.dumps(state))
            with self.subTest(thread=thread.get("realm")):
                self.assertFalse(bridge._note_bridge_thread_unlocked(state, conversation, "s1"))
            self.assertEqual(state, before)

        state = {**base}
        bridge.STATE_GENERATIONS[id(state)] = 2
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "ownership changed"):
            bridge._reserve_destination_owner(state, "example", "1", "Topic", "thread", "s1", 1)
        token = bridge._reserve_destination_owner(state, "example", "1", "Topic", "thread", "s1", 2)
        try:
            with self.assertRaisesRegex(bridge.ReplyRoutingError, "reserved"):
                bridge._reserve_destination_owner(state, "example", "1", "Topic", "other", "s2", 2)
        finally:
            bridge.release_destination_reservation(state, token)
            bridge.STATE_GENERATIONS.pop(id(state), None)

    def test_confirmed_reply_publication_rolls_back_every_owner_or_capacity_failure(self) -> None:
        state, message, _conversation = self.first_turn_reply()
        job = bridge._reply_reconciliation_job(
            message,
            user_message(44, 1, "Before"),
            900,
            SIGNING_KEY,
            "answer",
        )

        missing = {**message, "_zulip_bridge": None}
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "no source"):
            bridge._publish_confirmed_reply(state, missing, job)

        for label, bridge_result, topic_result in (
            ("thread", False, True),
            ("topic", True, False),
        ):
            before = json.loads(json.dumps(state))
            with self.subTest(label=label), mock.patch.object(
                bridge, "_note_bridge_thread_unlocked", return_value=bridge_result
            ), mock.patch.object(bridge, "_note_topic_session_unlocked", return_value=topic_result), self.assertRaises(
                bridge.ReplyRoutingError
            ):
                bridge._publish_confirmed_reply(state, message, job)
            self.assertEqual(state, before)

        before = json.loads(json.dumps(state))
        with mock.patch.object(bridge, "MAX_REPLY_RECONCILIATIONS", 0), self.assertRaises(
            bridge.DurableQueueFull
        ):
            bridge._publish_confirmed_reply(state, message, job)
        self.assertEqual(state, before)

    def test_signal_helpers_skip_stale_instances_and_use_current_group_leader(self) -> None:
        proc = mock.Mock(pid=100)
        proc.poll.return_value = None
        killpg = mock.Mock()
        with mock.patch.object(
            bridge, "_local_process_table", return_value={100: (1, 100, "birth")}
        ), mock.patch.object(bridge.os, "killpg", killpg):
            self.assertTrue(bridge._signal_group_if_current(proc, 100, "birth", bridge.signal.SIGTERM))
        killpg.assert_called_once_with(100, bridge.signal.SIGTERM)

        proc.poll.return_value = 0
        with mock.patch.object(bridge.os, "killpg", killpg):
            self.assertFalse(bridge._signal_group_if_current(proc, 100, "birth", bridge.signal.SIGTERM))

        killed = mock.Mock()
        with mock.patch.object(bridge, "_local_process_table", return_value={10: (1, 10, "new")}), mock.patch.object(
            bridge.os, "kill", killed
        ):
            self.assertFalse(bridge._signal_pid_if_current(10, 10, "old", bridge.signal.SIGTERM))
        killed.assert_not_called()

    def test_reply_owner_guard_rejects_wrong_realm_unowned_new_route_and_foreign_native_owner(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")
        message = {
            **user_message(44, 1, "Topic"),
            "_zulip_state": state,
            "_zulip_bridge": {**source, "session_id": "s1"},
        }

        state["zulip_threads"][source["thread_id"]]["realm"] = "other"
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "another Zulip realm"):
            bridge.ensure_reply_destination_owner({}, message, user_message(44, 1, "Topic"))
        state["zulip_threads"][source["thread_id"]]["realm"] = "example"

        state["zulip_threads"][source["thread_id"]]["session_id"] = ""
        state["zulip_topic_aliases"].clear()
        message["_zulip_bridge"]["session_id"] = "new-session"
        with mock.patch.object(bridge, "_thread_for_matching_anchors", return_value=""), self.assertRaisesRegex(
            bridge.ReplyRoutingError, "new Hermes conversation"
        ):
            bridge.ensure_reply_destination_owner({}, message, user_message(44, 1, "Unowned"))

        native_origin = {**user_message(44, 1, "Topic"), "topic_id": "foreign-native"}
        native_id = bridge.stable_zulip_thread_id("example", 1, "Topic", native_origin)
        state["zulip_threads"][source["thread_id"]]["session_id"] = "s1"
        state["zulip_threads"][native_id] = {
            "thread_id": native_id,
            "conversation_key": bridge.conversation_key("example", 1, native_id),
            "realm": "example",
            "stream_id": "1",
            "topic_aliases": [],
            "session_id": "s2",
        }
        message["_zulip_bridge"]["session_id"] = "s1"
        with mock.patch.object(
            bridge, "_stored_topic_owner", return_value=(source["thread_id"], "s1")
        ), mock.patch.object(
            bridge, "_thread_for_matching_anchors", return_value=source["thread_id"]
        ), self.assertRaisesRegex(bridge.ReplyRoutingError, "another Hermes session"):
            bridge.ensure_reply_destination_owner({}, message, native_origin)

    def test_worker_durable_failures_escape_pending_completion_without_reclassifying_origin(self) -> None:
        class ImmediateFuture:
            def __init__(self, function, *args: object) -> None:
                try:
                    function(*args)
                    self.error = None
                except BaseException as exc:
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error:
                    raise self.error

        class ImmediateExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, function, *args: object) -> ImmediateFuture:
                return ImmediateFuture(function, *args)

            def shutdown(self, **_kwargs: object) -> None:
                pass

        for error, expected in (
            (bridge.StatePersistenceError("save"), SystemExit),
            (bridge.DurableQueueFull("full"), bridge.DurableQueueFull),
        ):
            state: dict = {"topic_sessions": {}}
            message = user_message(44, 1, "Topic")
            with self.subTest(error=type(error).__name__), (
                mock.patch.object(bridge, "load_json", return_value=state)
            ), mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
            ), mock.patch.object(bridge, "load_alias_entries", return_value=[]), mock.patch.object(
                bridge, "load_state_signing_key", return_value=SIGNING_KEY
            ), mock.patch.object(bridge, "latest_messages", return_value=[message]), mock.patch.object(
                bridge, "handle_message", side_effect=error
            ), mock.patch.object(bridge, "save_json"), mock.patch.object(
                bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor
            ), mock.patch.object(bridge.time, "sleep", return_value=None), mock.patch.object(
                bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1
            ), self.assertRaises(expected):
                bridge._main()

    def test_rc_sources_process_monitor_and_registered_communicate_cover_secure_fallbacks(self) -> None:
        inline = {
            "HERMES_ZULIP_SITE": "https://example/",
            "HERMES_ZULIP_EMAIL": "bot@example.com",
            "HERMES_ZULIP_API_KEY": "generic-key",
        }
        with mock.patch.dict(os.environ, inline, clear=True):
            self.assertEqual(
                bridge.load_rc(),
                {"site": "https://example", "email": "bot@example.com", "key": "generic-key"},
            )
        with mock.patch.dict(os.environ, {"HERMES_ZULIP_SITE": "https://example"}, clear=True), self.assertRaisesRegex(
            SystemExit, "Incomplete inline"
        ):
            bridge.load_rc()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            bridge, "secure_read_text", side_effect=ValueError("unsafe")
        ), self.assertRaisesRegex(SystemExit, "unsafe"):
            bridge.load_rc()

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                bridge._communicate_registered(proc, None, 0.5)
        finally:
            bridge.terminate_and_reap_process_group(proc, grace_seconds=0.05)

        if hasattr(bridge.select, "kqueue"):
            monitored = mock.Mock(pid=100)
            monitored.poll.return_value = 0
            queue = mock.Mock()
            with (
                mock.patch.object(bridge.sys, "platform", "darwin"),
                mock.patch.object(bridge.select, "kqueue", return_value=queue),
                mock.patch.object(bridge, "_snapshot_registered_descendants", return_value={(101, 101, "child")}),
                mock.patch.object(
                    bridge, "_process_birth_identity", side_effect=lambda pid: "root" if pid == 100 else "child"
                ),
                mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {100: set()}, clear=True),
                mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {100: "root"}, clear=True),
            ):
                bridge._watch_registered_descendants(monitored)
            self.assertTrue(queue.control.called)
            queue.close.assert_called_once_with()

    def test_resolve_session_rejects_missing_large_changed_reserved_and_unpublishable_routes(self) -> None:
        base = user_message(44, 1, "Topic")
        for label, message, pattern in (
            ("missing", {**base, "topic": ""}, "exact topic"),
            ("large", {**base, "topic": "x" * (bridge.MAX_ROUTE_CHARS + 1)}, "supported length"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(bridge.ReplyRoutingError, pattern):
                bridge.resolve_session(message, {}, {"topic_sessions": {}}, "example")

        state = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        with mock.patch.object(bridge, "_ownership_generation", side_effect=[0, 1]), self.assertRaisesRegex(
            bridge.ReplyRoutingError, "ownership changed"
        ):
            bridge.resolve_session(base.copy(), {}, state, "example")

        state = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        with mock.patch.object(
            bridge, "_stored_topic_owner", side_effect=[("", None), ("foreign", "s2")]
        ), self.assertRaisesRegex(bridge.ReplyRoutingError, "current Hermes owner"):
            bridge.resolve_session(base.copy(), {}, state, "example")

        state = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        bridge.STATE_RESERVATIONS[id(state)] = {
            object(): ("example", "1", "Topic", "foreign", "s2")
        }
        try:
            with self.assertRaisesRegex(bridge.ReplyRoutingError, "reserved Hermes owner"):
                bridge.resolve_session(base.copy(), {}, state, "example")
        finally:
            bridge.STATE_RESERVATIONS.pop(id(state), None)

        state = {"realm": "example", "topic_sessions": {}, "zulip_threads": {}, "zulip_topic_aliases": {}}
        with mock.patch.object(bridge, "note_bridge_thread", return_value=False), self.assertRaisesRegex(
            bridge.ReplyRoutingError, "failed to publish"
        ):
            bridge.resolve_session(base.copy(), {}, state, "example", reserve=True)
        self.assertNotIn(id(state), bridge.STATE_RESERVATIONS)

    def test_main_startup_realm_key_and_poll_limit_fail_before_worker_execution(self) -> None:
        common = {
            "load_rc": mock.Mock(
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}
            ),
            "load_alias_entries": mock.Mock(return_value=[]),
            "latest_messages": mock.Mock(return_value=[]),
            "save_json": mock.Mock(),
        }
        with mock.patch.multiple(
            bridge,
            load_json=mock.Mock(return_value={"realm": "other", "topic_sessions": {"legacy": "s1"}}),
            **common,
        ), self.assertRaisesRegex(SystemExit, bridge.STATE_REALM_MIGRATION_REQUIRED):
            bridge._main()

        with mock.patch.multiple(
            bridge,
            load_json=mock.Mock(return_value={"topic_sessions": {}}),
            load_state_signing_key=mock.Mock(return_value=None),
            **common,
        ), self.assertRaises(bridge.StatePersistenceError):
            bridge._main()

        with mock.patch.multiple(
            bridge,
            load_json=mock.Mock(return_value={"topic_sessions": {}}),
            load_state_signing_key=mock.Mock(return_value=SIGNING_KEY),
            MAX_CONSECUTIVE_POLL_FAILURES=0,
            **common,
        ), self.assertRaisesRegex(ValueError, "at least 1"):
            bridge._main()

    def test_process_reuse_between_validation_and_signal_is_skipped(self) -> None:
        proc = mock.Mock(pid=41000)
        proc.poll.return_value = 0
        member = (42000, 42000, "old-birth")
        killed = mock.Mock()
        with (
            mock.patch.object(bridge, "_snapshot_registered_descendants", return_value={member}),
            mock.patch.object(
                bridge,
                "_local_process_table",
                side_effect=[
                    {42000: (1, 42000, "old-birth")},
                    {42000: (1, 42000, "new-birth")},
                    {42000: (1, 42000, "new-birth")},
                ],
            ),
            mock.patch.object(bridge.os, "kill", killed),
            mock.patch.object(bridge.os, "killpg", killed),
        ):
            bridge._signal_registered_descendants(proc, bridge.signal.SIGKILL)
        killed.assert_not_called()

    def test_secure_sidecars_reject_symlinks_without_touching_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sentinel = root / "sentinel"
            sentinel.write_text('{"aliases": []}', encoding="utf-8")
            sentinel.chmod(0o600)
            steering = root / "steering.jsonl"
            steering.symlink_to(sentinel)
            with self.assertRaises(bridge.StatePersistenceError):
                bridge.append_steering_message(steering, {"conversation_key": "key"}, {"id": 2}, 1)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), '{"aliases": []}')

    def test_legacy_steering_and_smoke_files_migrate_from_0644_to_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for name in ("steering.jsonl", "steering.jsonl.smoke"):
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(b"")
                    path.chmod(0o644)
                    bridge.append_steering_message(
                        path, {"conversation_key": "key"}, {"id": 2, "content": "steer"}, 1
                    )
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["message_id"], 2)

    def test_legacy_steering_migration_rejects_hostile_file_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"sentinel")
            sentinel.chmod(0o644)
            hardlink = root / "hardlink"
            os.link(sentinel, hardlink)
            unsafe_mode = root / "unsafe-mode"
            unsafe_mode.write_bytes(b"")
            unsafe_mode.chmod(0o660)
            wrong_owner = root / "wrong-owner"
            wrong_owner.write_bytes(b"")
            wrong_owner.chmod(0o644)
            directory = root / "directory"
            directory.mkdir()

            for label, path in (("hardlink", hardlink), ("mode", unsafe_mode), ("non-regular", directory)):
                with self.subTest(label=label), self.assertRaises(bridge.StatePersistenceError):
                    bridge.append_steering_message(
                        path, {"conversation_key": "key"}, {"id": 2, "content": "steer"}, 1
                    )
            with mock.patch.object(bridge.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaises(
                bridge.StatePersistenceError
            ):
                bridge.append_steering_message(
                    wrong_owner, {"conversation_key": "key"}, {"id": 2, "content": "steer"}, 1
                )
            self.assertEqual(sentinel.read_bytes(), b"sentinel")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o644)

            aliases = root / "aliases.json"
            aliases.symlink_to(sentinel)
            with mock.patch.object(bridge, "ALIASES_PATH", aliases), self.assertRaises(bridge.StatePersistenceError):
                bridge.load_alias_entries()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "sentinel")

    def test_steering_append_fsyncs_before_acknowledging(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "steering.jsonl"
            actual_fsync = os.fsync
            fsynced: list[bool] = []

            def checked_fsync(fd: int) -> None:
                fsynced.append(stat.S_ISREG(os.fstat(fd).st_mode))
                actual_fsync(fd)

            with mock.patch.object(bridge.os, "fsync", side_effect=checked_fsync):
                record = bridge.append_steering_message(
                    path,
                    {"conversation_key": "key"},
                    {"id": 2, "content": "steer"},
                    1,
                )

        self.assertEqual(record["message_id"], 2)
        self.assertEqual(fsynced, [True, False])

    def test_steering_retry_after_fsync_failure_does_not_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "steering.jsonl"
            conversation = {"conversation_key": "key", "thread_id": "thread", "stream_id": "1", "topic": "Topic"}
            message = {"id": 2, "stream_id": 1, "topic": "Topic", "content": "steer"}
            actual_fsync = os.fsync
            failed = False

            def fail_after_file_fsync(fd: int) -> None:
                nonlocal failed
                actual_fsync(fd)
                if stat.S_ISREG(os.fstat(fd).st_mode) and not failed:
                    failed = True
                    raise OSError("reported fsync failure")

            with mock.patch.object(bridge.os, "fsync", side_effect=fail_after_file_fsync), self.assertRaises(
                bridge.StatePersistenceError
            ):
                bridge.append_steering_message(path, conversation, message, 1)

            retried = bridge.append_steering_message(path, conversation, message, 1)
            replayed = bridge.append_steering_message(path, conversation, {**message, "content": "edited"}, 1)
            with self.assertRaisesRegex(bridge.StatePersistenceError, "conflicts"):
                bridge.append_steering_message(path, conversation, message, 3)
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(retried["message_id"], 2)
            self.assertEqual(replayed, retried)
            self.assertEqual([record["message_id"] for record in records], [2])

    def test_steering_restart_repairs_only_trailing_partial_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "steering.jsonl"
            conversation = {"conversation_key": "key"}
            bridge.append_steering_message(path, conversation, {"id": 1, "content": "one"}, 9)
            with path.open("ab") as handle:
                handle.write(b'{"message_id":')

            bridge.append_steering_message(path, conversation, {"id": 2, "content": "two"}, 9)
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([record["message_id"] for record in records], [1, 2])

            with path.open("ab") as handle:
                handle.write(b"not-json\n")
            before = path.read_bytes()
            with self.assertRaises(bridge.StatePersistenceError):
                bridge.append_steering_message(path, conversation, {"id": 3, "content": "three"}, 9)
            self.assertEqual(path.read_bytes(), before)

    def test_steering_interrupted_short_write_rolls_back_before_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "steering.jsonl"
            actual_write = os.write
            writes = 0

            def interrupted_write(fd: int, data: bytes) -> int:
                nonlocal writes
                writes += 1
                if writes == 1:
                    return actual_write(fd, data[:7])
                raise OSError("interrupted append")

            with mock.patch.object(bridge.os, "write", side_effect=interrupted_write), self.assertRaises(
                bridge.StatePersistenceError
            ):
                bridge.append_steering_message(
                    path, {"conversation_key": "key"}, {"id": 2, "content": "steer"}, 1
                )
            self.assertEqual(path.read_bytes(), b"")

            bridge.append_steering_message(
                path, {"conversation_key": "key"}, {"id": 2, "content": "steer"}, 1
            )
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

    def test_steering_compaction_bounds_records_bytes_and_preserves_active_idempotence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "steering.jsonl"
            conversation = {"conversation_key": "key"}
            with (
                mock.patch.object(bridge, "MAX_STEERING_RECORDS", 5),
                mock.patch.object(bridge, "MAX_STEERING_BYTES", 2200),
                mock.patch.dict(bridge.ACTIVE_PROCESSES, {99: mock.Mock()}, clear=True),
            ):
                for message_id in range(1, 9):
                    active_id = 99 if message_id <= 2 else 88
                    bridge.append_steering_message(
                        path,
                        conversation,
                        {"id": message_id, "content": "x" * 180},
                        active_id,
                    )
                records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                ids = [record["message_id"] for record in records]
                self.assertEqual(ids[:2], [1, 2])
                self.assertEqual(ids[-1], 8)
                self.assertLessEqual(len(records), 5)
                self.assertLessEqual(path.stat().st_size, 2200)

                replayed = bridge.append_steering_message(
                    path, conversation, {"id": 1, "content": "edited"}, 99
                )
                self.assertEqual(replayed["message_id"], 1)
                self.assertEqual(
                    sum(json.loads(line)["message_id"] == 1 for line in path.read_text(encoding="utf-8").splitlines()),
                    1,
                )

    def test_steering_compaction_failure_keeps_original_and_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "steering.jsonl"
            conversation = {"conversation_key": "key"}
            with mock.patch.object(bridge, "MAX_STEERING_RECORDS", 2):
                bridge.append_steering_message(path, conversation, {"id": 1, "content": "one"}, 9)
                bridge.append_steering_message(path, conversation, {"id": 2, "content": "two"}, 9)
                before = path.read_bytes()
                with mock.patch.object(bridge.os, "replace", side_effect=OSError("replace failed")), self.assertRaises(
                    bridge.StatePersistenceError
                ):
                    bridge.append_steering_message(path, conversation, {"id": 3, "content": "three"}, 9)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(root.iterdir()), [path])

    def test_steering_file_lock_deduplicates_ten_workers_replaying_fifty_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "steering.jsonl"
            conversation = {"conversation_key": "key", "thread_id": "thread", "stream_id": "1", "topic": "Topic"}
            barrier = threading.Barrier(10)
            errors: list[BaseException] = []

            def append_all() -> None:
                try:
                    barrier.wait()
                    for message_id in range(1, 51):
                        bridge.append_steering_message(
                            path,
                            conversation,
                            {"id": message_id, "stream_id": 1, "topic": "Topic", "content": f"steer {message_id}"},
                            99,
                        )
                except BaseException as exc:
                    errors.append(exc)

            workers = [threading.Thread(target=append_all) for _index in range(10)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)

            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertEqual(errors, [])
            self.assertEqual(len(records), 50)
            self.assertEqual({record["message_id"] for record in records}, set(range(1, 51)))

    def test_topic_history_rejects_ignored_or_off_route_members_before_hermes(self) -> None:
        origin = {"id": 10, "type": "stream", "stream_id": 7, "display_recipient": "hermes", "topic": "Topic"}
        valid = {"id": 9, "type": "stream", "stream_id": 7, "topic": "Topic", "content": "prior"}
        hostile = {
            "ignored narrow": {"ignored_parameters_unsupported": ["narrow"], "messages": [valid]},
            "ignored extra": {"ignored_parameters_unsupported": ["unexpected"], "messages": [valid]},
            "wrong stream": {"messages": [{**valid, "stream_id": 8}]},
            "wrong topic": {"messages": [{**valid, "topic": "Other"}]},
            "conflicting topic fields": {"messages": [{**valid, "subject": "Other"}]},
            "direct message": {"messages": [{**valid, "type": "private"}]},
            "unstable id": {"messages": [{**valid, "id": True}]},
            "unstable content": {"messages": [{**valid, "content": 42}]},
            "duplicate id": {"messages": [valid, dict(valid)]},
            "malformed member": {"messages": [None]},
        }
        popen = mock.Mock()
        for label, payload in hostile.items():
            with self.subTest(label=label), mock.patch.object(
                bridge, "api", return_value=zulip_success(**payload)
            ), mock.patch.object(bridge.subprocess, "Popen", popen), self.assertRaises(bridge.ReplyRoutingError):
                bridge.topic_history({}, origin)
        popen.assert_not_called()

    def test_topic_history_uses_exact_narrow_and_only_prior_valid_members(self) -> None:
        origin = {"id": 10, "type": "stream", "stream_id": 7, "display_recipient": "hermes", "topic": "Topic"}
        api = mock.Mock(
            return_value=zulip_success(
                messages=[
                    {
                        "id": 9,
                        "type": "stream",
                        "stream_id": 7,
                        "topic": "Topic",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                        "content": " prior text ",
                    },
                    {
                        "id": 10,
                        "type": "stream",
                        "stream_id": 7,
                        "subject": "Topic",
                        "sender_id": 17,
                        "sender_email": "user@example.com",
                        "sender_is_bot": False,
                        "content": "current",
                    },
                ]
            )
        )

        with mock.patch.object(bridge, "api", api):
            history = bridge.topic_history({}, origin)

        self.assertEqual(history, "- user@example.com: prior text")
        params = api.call_args.kwargs["params"]
        self.assertEqual(
            json.loads(params["narrow"]),
            [{"operator": "channel", "operand": "hermes"}, {"operator": "topic", "operand": "Topic"}],
        )

    def test_topic_history_excludes_non_allowlisted_humans_and_other_bots(self) -> None:
        origin = {"id": 10, "type": "stream", "stream_id": 7, "display_recipient": "hermes", "topic": "Topic"}
        base = {"type": "stream", "stream_id": 7, "topic": "Topic"}
        messages = [
            {**base, "id": 7, "sender_id": 18, "sender_email": "other@example.com", "sender_is_bot": False, "content": "inject"},
            {**base, "id": 8, "sender_id": 50, "sender_email": "other-bot@example.com", "sender_is_bot": True, "content": "bot inject"},
            {**base, "id": 6, "sender_id": 99, "sender_email": "bot@example.com", "content": "laundered inject"},
            {**base, "id": 9, "sender_id": 17, "sender_email": "user@example.com", "sender_is_bot": False, "content": "authorized"},
        ]
        with mock.patch.object(bridge, "api", return_value=zulip_success(messages=messages)):
            history = bridge.topic_history({"email": "bot@example.com"}, origin)
        self.assertEqual(history, "- user@example.com: authorized")
        self.assertNotIn("inject", history)

    def test_active_sidecar_is_private_scoped_and_removed_after_turn(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            root.chmod(0o755)
            with mock.patch.object(bridge, "STEERING_PATH", root / "steering.jsonl"):
                path = bridge.active_steering_path(111)
                bridge.append_steering_message(
                    path,
                    {"conversation_key": "key", "thread_id": "thread", "stream_id": "7", "topic": "Topic"},
                    user_message(222, 7, "Topic", content="change course"),
                    111,
                )
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotEqual(path, bridge.active_steering_path(112))
                bridge.remove_active_steering_path(111)
                self.assertFalse(path.exists())
                bridge.STEERING_PATH.write_text("legacy plaintext", encoding="utf-8")
                bridge.STEERING_PATH.chmod(0o644)
                for active_id in (112, 113):
                    stale = bridge.active_steering_path(active_id)
                    stale.write_text("stale private steering", encoding="utf-8")
                    stale.chmod(0o600)
                bridge.retire_stale_steering_paths()
                self.assertFalse(bridge.STEERING_PATH.exists())
                self.assertFalse(bridge.active_steering_path(112).exists())
                self.assertFalse(bridge.active_steering_path(113).exists())

    def test_soft_steering_append_is_the_exactly_once_delivery_contract(self) -> None:
        active: dict = {}
        seen: set[int] = set()
        conversation = {"conversation_key": "key", "thread_id": "thread", "stream_id": "1", "topic": "Topic"}
        message, state = self.admitted_message(
            {"id": 222, "stream_id": 1, "topic": "Topic", "content": "steer"}
        )
        reaction = mock.Mock()
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                mock.patch.object(bridge, "STEERING_PATH", Path(tmpdir) / "steering.jsonl"),
                mock.patch.object(bridge, "HARD_INTERRUPT_ON_STEERING", False),
                mock.patch.dict(
                    bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True
                ),
                mock.patch.object(
                    bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current
                ),
                mock.patch.object(bridge, "add_reaction", reaction),
            ):
                first = bridge.handle_active_topic_message({}, message, "s1", conversation, 111, active, seen)
                second = bridge.handle_active_topic_message({}, message, "s1", conversation, 111, active, seen)
                lines = bridge.active_steering_path(111).read_text(encoding="utf-8").splitlines()
        self.assertEqual((first, second), ("delivered", "delivered"))
        self.assertEqual(len(lines), 1)
        self.assertEqual(seen, set())
        self.assertEqual(active, {"key": {222: (111, "thread")}})
        self.assertEqual(state["origin_in_flight"][0]["stage"], "hermes_may_start")
        reaction.assert_not_called()

    def test_soft_steering_parent_failure_requeues_once_without_second_append(self) -> None:
        state = {"topic_sessions": {}}
        parent = {
            "id": 44,
            "type": "stream",
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Topic",
            "sender_id": 17,
            "sender_email": "user@example.com",
            "sender_is_bot": False,
            "content": "start",
        }
        steering = {**parent, "id": 45, "content": "change course"}
        sidecar_appends: list[int] = []
        normal_runs: list[int] = []
        parent_future = None

        class Future:
            def __init__(self, *, value: object = None, error: BaseException | None = None, done: bool = True) -> None:
                self.value = value
                self.error = error
                self.ready = done

            def done(self) -> bool:
                return self.ready

            def result(self):
                if self.error:
                    raise self.error
                return self.value

        class Executor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, function, *args: object) -> Future:
                nonlocal parent_future
                message = args[1]
                if message["id"] == 44:
                    message["_zulip_execution"]["hermes_started"] = True
                    parent_future = Future(error=RuntimeError("parent failed"), done=False)
                    return parent_future
                return Future(value=function(*args))

            def shutdown(self, **_kwargs: object) -> None:
                pass

        def worker(_rc: dict, message: dict, _session_id: str | None) -> str:
            normal_runs.append(message["id"])
            return "s1"

        def store_steering(
            _rc: dict, message: dict, _conversation: dict, _active: int, before: object
        ) -> tuple[bool, bool]:
            before()
            sidecar_appends.append(message["id"])
            return True, True

        def fake_api(_rc: dict, _method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/messages/45":
                return zulip_success(message=steering)
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"45": narrow_match()})
            raise AssertionError(path)

        sleeps = 0

        def advance(_seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            if sleeps == 1:
                self.assertIsNotNone(parent_future)
                parent_future.ready = True
                return
            raise StopIteration

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "latest_messages", side_effect=[[parent, steering], []]),
            mock.patch.object(bridge, "api", side_effect=fake_api),
            mock.patch.object(bridge, "handle_message", side_effect=worker),
            mock.patch.object(
                bridge,
                "store_active_steering_if_live",
                side_effect=store_steering,
            ),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge, "HARD_INTERRUPT_ON_STEERING", False),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", side_effect=advance),
            self.assertRaises(StopIteration),
        ):
            bridge._main()

        self.assertEqual(sidecar_appends, [45])
        self.assertEqual(normal_runs, [])
        self.assertIn(45, state["seen_ids"])
        self.assertEqual(state["origin_retries"], [])
        self.assertEqual(state["origin_in_flight"], [])
        self.assertIn(45, {item["origin_message_id"] for item in state["dead_letters"]})

    def test_uncertain_patch_history_verifies_intermediate_route_then_moves_to_newest(self) -> None:
        state = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="A", session_id="s1")
        job = bridge._reply_reconciliation_job(
            {"id": 44, "_zulip_bridge": {**source, "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "A"},
            900,
            SIGNING_KEY,
            "answer",
        )
        state["reply_reconciliations"] = [job]
        origin_topic = "B"
        sent_topic = "A"
        patches: list[str] = []
        persisted: list[list[dict]] = []

        def persist() -> None:
            current = state["reply_reconciliations"][0]
            bridge._validate_reconciliation_tag(SIGNING_KEY, current)
            persisted.append(json.loads(json.dumps(current["attempted_routes"])))

        def fake_api(_rc: dict, method: str, path: str, **kwargs: object) -> dict:
            nonlocal sent_topic
            if path == "/api/v1/messages/44":
                return zulip_success(
                    message={
                        "id": 44,
                        "type": "stream",
                        "stream_id": 1,
                        "display_recipient": "stream-1",
                        "topic": origin_topic,
                    }
                )
            if method == "GET" and path == "/api/v1/messages/900":
                return zulip_success(message=bot_message(900, 1, sent_topic, stream="stream-1"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "PATCH":
                target = str((kwargs.get("data") or {})["topic"])
                patches.append(target)
                sent_topic = target
                if target == "B":
                    raise TimeoutError("PATCH response lost")
                return zulip_success()
            raise AssertionError((method, path))

        rc = {"site": "https://example", "email": "bot@example.com", "key": BOT_KEY}
        with mock.patch.object(bridge, "api", side_effect=fake_api):
            bridge.reconcile_pending_replies(rc, state, SIGNING_KEY, now=job["next_attempt_at"], persist=persist)
            origin_topic = "C"
            retry_at = state["reply_reconciliations"][0]["next_attempt_at"]
            bridge.reconcile_pending_replies(rc, state, SIGNING_KEY, now=retry_at, persist=persist)

        self.assertEqual(patches, ["B", "C"])
        self.assertEqual(persisted, [[{"stream_id": 1, "topic": "B"}], [{"stream_id": 1, "topic": "B"}, {"stream_id": 1, "topic": "C"}]])
        self.assertEqual(state["reply_reconciliations"], [])
        self.assertEqual(state.get("dead_letters", []), [])

    def test_attempted_route_history_is_hmac_authenticated_and_strictly_bounded(self) -> None:
        job = bridge._reply_reconciliation_job(
            {"id": 44, "_zulip_bridge": {"realm": "example", "thread_id": "thread", "session_id": "s1"}},
            {"stream_id": 1, "display_recipient": "stream-1", "topic": "A"},
            900,
            SIGNING_KEY,
            "answer",
        )
        forged = {**job, "attempted_routes": [{"stream_id": 1, "topic": "B"}]}
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "provenance"):
            bridge._validate_reconciliation_tag(SIGNING_KEY, forged)

        oversized = {
            **job,
            "attempted_routes": [
                {"stream_id": 1, "topic": f"Topic {index}"}
                for index in range(bridge.MAX_ATTEMPTED_ROUTES + 1)
            ],
        }
        with self.assertRaisesRegex(ValueError, "attempted routes"):
            bridge.require_state_object({"reply_reconciliations": [oversized]})

    def test_main_admission_publication_failure_rolls_back_durable_state(self) -> None:
        state: dict = {"topic_sessions": {}}
        message = user_message(44, 1, "Topic")

        class PendingFuture:
            def done(self) -> bool:
                return False

        class PendingExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, *_args: object) -> PendingFuture:
                return PendingFuture()

            def shutdown(self, **_kwargs: object) -> None:
                pass

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[message]),
            mock.patch.object(bridge, "note_bridge_thread", return_value=False),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", PendingExecutor),
            mock.patch.object(bridge.time, "sleep", return_value=None),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1),
            self.assertRaises(SystemExit),
        ):
            bridge._main()

        self.assertEqual(state.get("origin_in_flight", []), [])
        self.assertEqual(state.get("origin_retries", []), [])
        self.assertEqual(state.get("zulip_threads", {}), {})
        self.assertNotIn(44, state.get("seen_ids", []))

    def test_main_active_delivery_outcomes_preserve_each_durable_contract(self) -> None:
        class PendingFuture:
            def done(self) -> bool:
                return False

        class PendingExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, *_args: object) -> PendingFuture:
                submissions.append(_args[2]["id"])
                return PendingFuture()

            def shutdown(self, **_kwargs: object) -> None:
                pass

        cases = (
            ("failure", ValueError("delivery failed")),
            ("deferred", "deferred"),
            ("handled", "handled"),
        )
        for label, outcome in cases:
            state: dict = {"topic_sessions": {}}
            messages = [user_message(44, 1, "Topic"), user_message(45, 1, "Topic")]
            durable_admission = False
            acknowledgements: list[int] = []
            submissions: list[int] = []

            def save(_path: Path, candidate: dict) -> None:
                nonlocal durable_admission
                durable_admission = any(
                    item.get("origin_message_id") == 45
                    for item in candidate.get("origin_in_flight", [])
                )

            def acknowledge(_rc: dict, message: dict, _emoji: str) -> None:
                self.assertTrue(durable_admission)
                acknowledgements.append(message["id"])

            def active_delivery(*args: object) -> str:
                self.assertEqual(acknowledgements, [45])
                if isinstance(outcome, BaseException):
                    raise outcome
                if outcome == "handled":
                    args[-1].add(45)
                return outcome

            with self.subTest(label=label), (
                mock.patch.object(bridge, "load_json", return_value=state)
            ), mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
            ), mock.patch.object(bridge, "load_alias_entries", return_value=[]), mock.patch.object(
                bridge, "load_state_signing_key", return_value=SIGNING_KEY
            ), mock.patch.object(bridge, "latest_messages", return_value=messages), mock.patch.object(
                bridge, "handle_active_topic_message", side_effect=active_delivery
            ), mock.patch.object(bridge, "save_json", side_effect=save), mock.patch.object(
                bridge, "acknowledge_message", side_effect=acknowledge
            ), mock.patch.object(
                bridge.concurrent.futures, "ThreadPoolExecutor", PendingExecutor
            ), mock.patch.object(bridge.time, "sleep", side_effect=StopIteration), mock.patch.object(
                bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1
            ), mock.patch.object(
                bridge, "MAX_DURABLE_ATTEMPTS", 1 if label == "failure" else 5
            ), self.assertRaises(StopIteration):
                bridge._main()

            retry_ids = {item["origin_message_id"] for item in state.get("origin_retries", [])}
            in_flight_ids = {item["origin_message_id"] for item in state.get("origin_in_flight", [])}
            if label == "deferred":
                self.assertIn(45, retry_ids)
            else:
                self.assertNotIn(45, retry_ids)
            self.assertNotIn(45, in_flight_ids)
            if label in {"failure", "handled"}:
                self.assertIn(45, state["seen_ids"])
            self.assertEqual(acknowledgements, [45])
            self.assertEqual(submissions, [44])

    def test_fetch_outcome_persistence_failure_restores_seen_and_queue_state(self) -> None:
        retries = [
            {"origin_message_id": 1, "attempts": 1, "created_at": 0.0, "next_attempt_at": 0.0},
            {"origin_message_id": 2, "attempts": 1, "created_at": 0.0, "next_attempt_at": 0.0},
        ]
        state = {"topic_sessions": {}, "origin_retries": retries}

        def fetch(_rc: dict, message: dict) -> dict:
            raise bridge.ReplyRoutingError("temporary" if message["id"] == 2 else "gone", retryable=message["id"] == 2)

        def save(_path: Path, candidate: dict) -> None:
            if candidate.get("dead_letters"):
                raise bridge.StatePersistenceError("simulated durable write failure")

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge, "live_origin_message", side_effect=fetch),
            mock.patch.object(bridge, "save_json", side_effect=save),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", return_value=None),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1),
            self.assertRaises(SystemExit),
        ):
            bridge._main()

        self.assertEqual([(item["origin_message_id"], item["attempts"]) for item in state["origin_retries"]], [(1, 1), (2, 1)])
        self.assertEqual(state.get("dead_letters", []), [])
        self.assertNotIn(1, state.get("seen_ids", []))

    def test_reconciliation_errors_release_reservation_and_restore_owner_state(self) -> None:
        state, message, conversation = self.first_turn_reply()
        job = bridge._reply_reconciliation_job(
            message,
            user_message(44, 1, "Before"),
            900,
            SIGNING_KEY,
            "answer",
        )
        bridge._publish_confirmed_reply(state, message, job)
        current = user_message(44, 1, "Before")
        reservation = object()
        release = mock.Mock()

        missing = {**message, "_zulip_bridge": None}
        with (
            mock.patch.object(bridge, "live_origin_message", return_value=current),
            mock.patch.object(bridge, "_verified_reconciliation_sent_message", return_value=({}, True)),
            mock.patch.object(bridge, "ensure_reply_destination_owner", return_value=reservation),
            mock.patch.object(bridge, "release_destination_reservation", release),
            self.assertRaisesRegex(bridge.ReplyRoutingError, "no source"),
        ):
            bridge._reconcile_reply_job({}, state, job, SIGNING_KEY, missing)
        release.assert_called_once_with(state, reservation)

        for label, bridge_result, topic_result in (("thread", False, True), ("topic", True, False)):
            before = json.loads(json.dumps(state))
            with self.subTest(label=label), mock.patch.object(
                bridge, "live_origin_message", return_value=current
            ), mock.patch.object(
                bridge, "_verified_reconciliation_sent_message", return_value=({}, True)
            ), mock.patch.object(
                bridge, "ensure_reply_destination_owner", return_value=None
            ), mock.patch.object(
                bridge, "_note_bridge_thread_unlocked", return_value=bridge_result
            ), mock.patch.object(
                bridge, "_note_topic_session_unlocked", return_value=topic_result
            ), self.assertRaises(bridge.ReplyRoutingError):
                bridge._reconcile_reply_job({}, state, job, SIGNING_KEY, {**message, "_zulip_bridge": conversation.copy()})
            self.assertEqual(state, before)

        job = state["reply_reconciliations"][0]
        moved = user_message(44, 1, "After")
        with (
            mock.patch.object(bridge, "live_origin_message", return_value=moved),
            mock.patch.object(bridge, "_verified_reconciliation_sent_message", return_value=({}, False)),
            mock.patch.object(bridge, "ensure_reply_destination_owner", return_value=None),
            self.assertRaisesRegex(bridge.StatePersistenceError, "cannot be durably persisted"),
        ):
            bridge._reconcile_reply_job({}, state, job, SIGNING_KEY, message)
        self.assertEqual(job["attempted_routes"], [{"stream_id": 1, "topic": "After"}])

        definite_patch_failure = bridge.ZulipResponseError("definite PATCH rejection")
        with (
            mock.patch.object(bridge, "live_origin_message", return_value=moved),
            mock.patch.object(bridge, "_verified_reconciliation_sent_message", return_value=({}, False)),
            mock.patch.object(bridge, "ensure_reply_destination_owner", return_value=None),
            mock.patch.object(bridge, "api", side_effect=definite_patch_failure),
            self.assertRaisesRegex(bridge.ZulipResponseError, "definite PATCH rejection"),
        ):
            bridge._reconcile_reply_job({}, state, job, SIGNING_KEY, message, persist=mock.Mock())

    def test_state_save_rejects_non_json_input_before_creating_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            with self.assertRaisesRegex(bridge.StatePersistenceError, "not serializable"):
                bridge.save_json(path, {"unsafe": object()})
            self.assertFalse(path.exists())

    def test_registered_process_start_failure_kills_wrapper_and_never_marks_execution(self) -> None:
        proc = mock.Mock(pid=12345)
        execution = {"hermes_started": False}
        with (
            mock.patch.object(bridge.subprocess, "Popen", return_value=proc),
            mock.patch.object(bridge, "register_active_process", side_effect=RuntimeError("registration failed")),
            self.assertRaisesRegex(RuntimeError, "registration failed"),
        ):
            bridge._start_registered_process(44, ["/bin/echo", "ok"], execution)
        self.assertFalse(execution["hermes_started"])
        proc.kill.assert_called_once_with()
        proc.wait.assert_called_once_with(timeout=1)
        self.assertNotIn(44, bridge.ACTIVE_PROCESSES)

        execution = {"hermes_started": False}
        with mock.patch.object(bridge, "SHUTTING_DOWN", True), mock.patch.object(
            bridge.subprocess, "Popen"
        ) as popen, self.assertRaises(bridge.HermesInterrupted):
            bridge._start_registered_process(44, ["/bin/echo", "ok"], execution)
        popen.assert_not_called()
        self.assertFalse(execution["hermes_started"])

    def test_trusted_process_group_adoption_requires_registered_live_leader_birth(self) -> None:
        root_pid = 41000
        candidate = (42000, root_pid, "child-birth")
        proc = mock.Mock(pid=root_pid)
        proc.poll.return_value = None
        cases = (
            (
                "reused leader",
                {root_pid: (1, root_pid, "new-root"), candidate[0]: (root_pid, root_pid, candidate[2])},
                set(),
                set(),
            ),
            ("missing leader", {candidate[0]: (root_pid, root_pid, candidate[2])}, set(), set()),
            (
                "matching leader",
                {root_pid: (1, root_pid, "old-root"), candidate[0]: (root_pid, root_pid, candidate[2])},
                set(),
                {candidate},
            ),
            (
                "registered member survives reused leader",
                {root_pid: (1, root_pid, "new-root"), candidate[0]: (1, root_pid, candidate[2])},
                {candidate},
                {candidate},
            ),
        )
        for label, table, registered, expected in cases:
            with self.subTest(label=label), mock.patch.dict(
                bridge.ACTIVE_PROCESSES, {1: proc}, clear=True
            ), mock.patch.dict(
                bridge.ACTIVE_DESCENDANTS, {root_pid: registered}, clear=True
            ), mock.patch.dict(
                bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "old-root"}, clear=True
            ), mock.patch.dict(
                bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {}, clear=True
            ), mock.patch.object(bridge, "_local_process_table", return_value=table):
                self.assertEqual(
                    bridge._snapshot_registered_descendants(proc, trust_new_process_group=True),
                    expected,
                )

        killpg = mock.Mock()
        with mock.patch.dict(
            bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "old-root"}, clear=True
        ), mock.patch.dict(
            bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {root_pid: "old-root"}, clear=True
        ), mock.patch.object(bridge.os, "killpg", killpg), mock.patch.object(
            bridge, "_process_instance_held_unreaped", return_value=False
        ):
            self.assertFalse(bridge._signal_held_registered_group(proc, bridge.signal.SIGKILL))
        killpg.assert_not_called()

        with mock.patch.dict(
            bridge.ACTIVE_PROCESS_IDENTITIES, {root_pid: "old-root"}, clear=True
        ), mock.patch.dict(
            bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {root_pid: "old-root"}, clear=True
        ), mock.patch.object(bridge.os, "killpg", killpg), mock.patch.object(
            bridge, "_process_instance_held_unreaped", return_value=True
        ):
            self.assertTrue(bridge._signal_held_registered_group(proc, bridge.signal.SIGKILL))
        killpg.assert_called_once_with(root_pid, bridge.signal.SIGKILL)

    def test_process_instance_wait_and_signal_errors_fail_closed(self) -> None:
        class Process:
            def __init__(self, *, returncode=None) -> None:
                self.pid = 41000
                self.returncode = returncode
                self.poll = mock.Mock(return_value=None)

        proc = Process()
        with mock.patch.object(bridge, "SYSTEM_POPEN", Process), mock.patch.object(
            bridge.os, "waitid", side_effect=ChildProcessError, create=True
        ):
            self.assertFalse(bridge._process_instance_held_unreaped(proc))
            self.assertFalse(bridge._process_exited_unreaped(proc))
            proc.poll.assert_called_once_with()

        proc.poll.reset_mock()
        with mock.patch.object(bridge, "SYSTEM_POPEN", Process), mock.patch.object(
            bridge.os, "waitid", None, create=True
        ):
            self.assertFalse(bridge._process_instance_held_unreaped(proc))
            self.assertFalse(bridge._process_exited_unreaped(proc))
            proc.poll.assert_called_once_with()

        proc.poll.reset_mock()
        with (
            mock.patch.object(bridge, "SYSTEM_POPEN", Process),
            mock.patch.object(bridge.sys, "platform", "darwin"),
            mock.patch.object(bridge.os, "waitid", None, create=True),
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {1: proc}, clear=True),
            mock.patch.dict(bridge.ACTIVE_DESCENDANTS, {proc.pid: set()}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {proc.pid: "birth"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_EXITED_PROCESS_IDENTITIES, {}, clear=True),
        ):
            self.assertFalse(bridge._process_exited_unreaped(proc))
            proc.poll.assert_not_called()
            bridge.ACTIVE_EXITED_PROCESS_IDENTITIES[proc.pid] = "birth"
            self.assertTrue(bridge._process_exited_unreaped(proc))
            proc.poll.assert_not_called()

        proc.returncode = 0
        with mock.patch.object(bridge, "SYSTEM_POPEN", Process):
            self.assertTrue(bridge._process_exited_unreaped(proc))

        proc.returncode = None
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESS_IDENTITIES, {proc.pid: "birth"}, clear=True),
            mock.patch.dict(bridge.ACTIVE_PROCESS_GROUP_IDENTITIES, {proc.pid: "birth"}, clear=True),
            mock.patch.object(bridge, "_process_instance_held_unreaped", return_value=True),
            mock.patch.object(bridge.os, "killpg", side_effect=ProcessLookupError),
        ):
            self.assertFalse(bridge._signal_held_registered_group(proc, bridge.signal.SIGKILL))

        process_table = {proc.pid: (1, proc.pid, "birth")}
        with (
            mock.patch.object(bridge.os, "pidfd_open", None, create=True),
            mock.patch.object(bridge.signal, "pidfd_send_signal", None, create=True),
            mock.patch.object(bridge, "_local_process_table", return_value=process_table),
            mock.patch.object(bridge.os, "kill", side_effect=ProcessLookupError),
        ):
            self.assertFalse(
                bridge._signal_pid_if_current(proc.pid, proc.pid, "birth", bridge.signal.SIGKILL)
            )

        pidfd_send = mock.Mock(side_effect=ProcessLookupError)
        with (
            mock.patch.object(bridge.os, "pidfd_open", return_value=9, create=True),
            mock.patch.object(bridge.signal, "pidfd_send_signal", pidfd_send, create=True),
            mock.patch.object(bridge, "_local_process_table", return_value=process_table),
            mock.patch.object(bridge.os, "close") as close,
        ):
            self.assertFalse(
                bridge._signal_pid_if_current(proc.pid, proc.pid, "birth", bridge.signal.SIGKILL)
            )
        pidfd_send.assert_called_once_with(9, bridge.signal.SIGKILL)
        close.assert_called_once_with(9)

    def test_confirmed_post_persistence_retries_without_reexecuting_worker(self) -> None:
        original_save_json = bridge.save_json

        class ImmediateFuture:
            def __init__(self, function, *args: object) -> None:
                self.result_calls = 0
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                self.result_calls += 1
                if self.error is not None:
                    raise self.error
                return self.value

        class ImmediateExecutor:
            instances: list["ImmediateExecutor"] = []

            def __init__(self, **_kwargs: object) -> None:
                self.futures: list[ImmediateFuture] = []
                self.instances.append(self)

            def submit(self, function, *args: object) -> ImmediateFuture:
                future = ImmediateFuture(function, *args)
                self.futures.append(future)
                return future

            def shutdown(self, **_kwargs: object) -> None:
                pass

        def run_case(
            failures: int | None, resolved_session: str = "s1"
        ) -> tuple[dict, dict, int, int, int, ImmediateFuture]:
            state: dict = {"topic_sessions": {}}
            message = user_message(44, 1, "Topic")
            state_path = Path(self.state_dir.name) / f"confirmed-{resolved_session}-{failures}.json"
            proof_attempts = 0
            generations = 0
            posts = 0
            alias_calls = 0
            sleeps = 0
            monotonic = 0.0

            def save(path: Path, candidate: dict) -> None:
                nonlocal proof_attempts
                has_proof = any(job.get("sent_message_id") == 900 for job in state.get("reply_reconciliations", []))
                in_flight = any(item.get("origin_message_id") == 44 for item in state.get("origin_in_flight", []))
                if has_proof and in_flight:
                    proof_attempts += 1
                    if failures is None or proof_attempts <= failures:
                        raise bridge.StatePersistenceError("injected confirmed POST persistence failure")
                original_save_json(path, candidate)

            def aliases() -> list[dict]:
                nonlocal alias_calls
                alias_calls += 1
                if failures is not None and alias_calls == 3:
                    raise KeyboardInterrupt
                return []

            def hermes(_rc: dict, posted: dict, _session_id: str | None) -> tuple[str, str]:
                nonlocal generations
                generations += 1
                posted["_zulip_before_hermes_start"]()
                return "answer", resolved_session

            def api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                nonlocal posts
                if path == "/api/v1/messages/44":
                    return zulip_success(message=user_message(44, 1, "Topic"))
                if path == "/api/v1/messages/matches_narrow":
                    return zulip_success(messages={"44": narrow_match()})
                if method == "POST":
                    posts += 1
                    return zulip_success(id=900)
                raise AssertionError((method, path))

            def sleep(_seconds: float) -> None:
                nonlocal sleeps
                sleeps += 1
                if failures is None and sleeps == 3:
                    raise KeyboardInterrupt

            def clock() -> float:
                nonlocal monotonic
                if failures is None:
                    return 100.0
                monotonic += 100.0
                return monotonic

            ImmediateExecutor.instances.clear()
            with (
                mock.patch.object(bridge, "load_json", return_value=state),
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                ),
                mock.patch.object(bridge, "load_alias_entries", side_effect=aliases),
                mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
                mock.patch.object(bridge, "latest_messages", return_value=[message]),
                mock.patch.object(bridge, "save_json", side_effect=save),
                mock.patch.object(bridge, "api", side_effect=api),
                mock.patch.object(bridge, "hermes_slash_reply", return_value=None),
                mock.patch.object(bridge, "hermes_reply", side_effect=hermes),
                mock.patch.object(bridge, "add_reaction"),
                mock.patch.object(bridge, "remove_reaction"),
                mock.patch.object(bridge, "post_goal_turns") as goal_turns,
                mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", ImmediateExecutor),
                mock.patch.object(bridge.time, "sleep", side_effect=sleep),
                mock.patch.object(bridge.time, "monotonic", side_effect=clock),
            ):
                self.assertEqual(bridge._main(state_path), 0)
            goal_turns.assert_not_called()
            future = ImmediateExecutor.instances[0].futures[0]
            return state, bridge.load_json(state_path, {}), proof_attempts, generations, posts, future

        for failures in (1, 3):
            with self.subTest(transient_failures=failures):
                state, persisted, attempts, generations, posts, future = run_case(failures)
                self.assertEqual((attempts, generations, posts, future.result_calls), (failures + 1, 1, 1, 1))
                self.assertEqual([job["sent_message_id"] for job in persisted["reply_reconciliations"]], [900])
                self.assertEqual(persisted.get("origin_in_flight", []), [])
                self.assertIn(44, persisted["seen_ids"])
                self.assertEqual(state.get("origin_in_flight", []), [])
                self.assertEqual(state.get("origin_retries", []), [])

        state, persisted, attempts, generations, posts, future = run_case(None)
        self.assertEqual((attempts, generations, posts, future.result_calls), (3, 1, 1, 1))
        self.assertEqual([job["sent_message_id"] for job in state["reply_reconciliations"]], [900])
        self.assertEqual(state["origin_in_flight"][0]["stage"], "hermes_may_start")
        self.assertEqual(persisted.get("reply_reconciliations", []), [])
        self.assertEqual(persisted["origin_in_flight"][0]["stage"], "hermes_may_start")
        recovered_seen: set[int] = set()
        bridge._recover_in_flight_origins(persisted, recovered_seen, now=200.0)
        self.assertEqual(recovered_seen, {44})
        self.assertEqual(persisted.get("origin_retries", []), [])
        self.assertEqual([item["origin_message_id"] for item in persisted["dead_letters"]], [44])

        state, persisted, attempts, generations, posts, future = run_case(2, "s2")
        self.assertEqual((attempts, generations, posts, future.result_calls), (3, 1, 1, 1))
        self.assertEqual(persisted["reply_reconciliations"][0]["session_id"], "s2")
        self.assertEqual(state.get("origin_in_flight", []), [])

        state, persisted, attempts, generations, posts, future = run_case(None, "s2")
        self.assertEqual((attempts, generations, posts, future.result_calls), (3, 1, 1, 1))
        self.assertEqual(state["reply_reconciliations"][0]["session_id"], "s2")
        self.assertEqual(persisted["origin_in_flight"][0]["stage"], "hermes_may_start")

    def test_rejected_and_uncertain_answer_posts_have_durable_worker_outcomes(self) -> None:
        class Future:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error is not None:
                    raise self.error
                return self.value

        class Executor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, function, *args: object) -> Future:
                return Future(function, *args)

            def shutdown(self, **_kwargs: object) -> None:
                pass

        original_save_json = bridge.save_json
        for status, reason in ((400, "definite_reply_rejected"), (503, "uncertain_post:")):
            with self.subTest(status=status):
                state: dict = {"topic_sessions": {}}
                state_path = Path(self.state_dir.name) / f"answer-{status}.json"
                generations = posts = 0
                snapshots: list[dict] = []

                def hermes(_rc: dict, posted: dict, _session_id: str | None) -> tuple[str, str]:
                    nonlocal generations
                    generations += 1
                    posted["_zulip_before_hermes_start"]()
                    posted["_zulip_execution"]["hermes_started"] = True
                    return "private generated answer", "s1"

                def api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
                    nonlocal posts
                    if path == "/api/v1/messages/44":
                        return zulip_success(message=user_message(44, 1, "Topic"))
                    if path == "/api/v1/messages/matches_narrow":
                        return zulip_success(messages={"44": narrow_match()})
                    if method == "POST" and path == "/api/v1/messages":
                        posts += 1
                        try:
                            bridge._check_zulip_result(
                                method,
                                path,
                                {"result": "error", "msg": "private detail", "status_code": status},
                                safe_read=False,
                            )
                        except bridge.ZulipResponseError as exc:
                            raise RuntimeError("official client request failed") from exc
                    raise AssertionError((method, path))

                def save(path: Path, candidate: dict) -> None:
                    snapshots.append(json.loads(json.dumps(candidate)))
                    original_save_json(path, candidate)

                visible = io.StringIO()
                with (
                    mock.patch.object(bridge, "load_json", return_value=state),
                    mock.patch.object(
                        bridge,
                        "load_rc",
                        return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
                    ),
                    mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                    mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
                    mock.patch.object(bridge, "latest_messages", return_value=[user_message(44, 1, "Topic")]),
                    mock.patch.object(bridge, "save_json", side_effect=save),
                    mock.patch.object(bridge, "api", side_effect=api),
                    mock.patch.object(bridge, "hermes_slash_reply", return_value=None),
                    mock.patch.object(bridge, "hermes_reply", side_effect=hermes),
                    mock.patch.object(bridge, "add_reaction"),
                    mock.patch.object(bridge, "remove_reaction"),
                    mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
                    mock.patch.object(bridge.time, "sleep", side_effect=KeyboardInterrupt),
                    mock.patch("sys.stdout", visible),
                ):
                    self.assertEqual(bridge._main(state_path), 0)

                persisted = bridge.require_state_object(bridge.load_json(state_path, {}))
                self.assertEqual((generations, posts), (1, 1))
                self.assertEqual(persisted["seen_ids"], [44])
                self.assertEqual(persisted.get("origin_in_flight", []), [])
                self.assertEqual(persisted.get("origin_retries", []), [])
                self.assertEqual(len(persisted["dead_letters"]), 1)
                dead_letter = persisted["dead_letters"][0]
                self.assertTrue(dead_letter["reason"].startswith(reason))
                self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
                self.assertNotIn("private generated answer", visible.getvalue())
                if status == 400:
                    recovery = dead_letter["recovery"]
                    self.assertEqual(recovery["answer"], "private generated answer")
                    self.assertEqual(
                        (recovery["origin_message_id"], recovery["stream_id"], recovery["topic"]),
                        (44, 1, "Topic"),
                    )
                    self.assertEqual(recovery["session_id"], "s1")
                    unsigned = {key: value for key, value in recovery.items() if key != "provenance_tag"}
                    payload = json.dumps(unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
                    self.assertEqual(
                        recovery["provenance_tag"],
                        bridge.hmac.new(SIGNING_KEY, payload, bridge.hashlib.sha256).hexdigest(),
                    )
                    checkpoints = [
                        snapshot
                        for snapshot in snapshots
                        if any("recovery" in item for item in snapshot.get("dead_letters", []))
                    ]
                    self.assertGreaterEqual(len(checkpoints), 2)
                    self.assertEqual([item["origin_message_id"] for item in checkpoints[0]["origin_in_flight"]], [44])
                    self.assertNotIn(44, checkpoints[0].get("seen_ids", []))
                    self.assertEqual(checkpoints[-1].get("origin_in_flight", []), [])
                    self.assertIn(44, checkpoints[-1]["seen_ids"])
                else:
                    self.assertNotIn("recovery", dead_letter)
                    self.assertNotIn("private generated answer", json.dumps(persisted))

    def test_definite_reply_recovery_survives_crash_before_terminal_retirement(self) -> None:
        class Future:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                if self.error is not None:
                    raise self.error
                return self.value

        class Executor:
            submissions = 0

            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, function, *args: object) -> Future:
                type(self).submissions += 1
                return Future(function, *args)

            def shutdown(self, **_kwargs: object) -> None:
                pass

        original_save_json = bridge.save_json
        state: dict = {"topic_sessions": {}}
        state_path = Path(self.state_dir.name) / "definite-recovery-crash.json"
        generations = posts = recovery_saves = 0

        def hermes(_rc: dict, posted: dict, _session_id: str | None) -> tuple[str, str]:
            nonlocal generations
            generations += 1
            posted["_zulip_before_hermes_start"]()
            posted["_zulip_execution"]["hermes_started"] = True
            return "recover this exact answer", "s1"

        def api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posts
            if path == "/api/v1/messages/44":
                return zulip_success(message=user_message(44, 1, "Topic"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST" and path == "/api/v1/messages":
                posts += 1
                try:
                    bridge._check_zulip_result(
                        method,
                        path,
                        {"result": "error", "msg": "private detail", "status_code": 400},
                        safe_read=False,
                    )
                except bridge.ZulipResponseError as exc:
                    raise RuntimeError("official client request failed") from exc
            raise AssertionError((method, path))

        def crash_before_retirement(path: Path, candidate: dict) -> None:
            nonlocal recovery_saves
            if any("recovery" in item for item in candidate.get("dead_letters", [])):
                recovery_saves += 1
                if not candidate.get("origin_in_flight"):
                    raise bridge.StatePersistenceError("injected retirement crash")
            original_save_json(path, candidate)

        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[user_message(44, 1, "Topic")]),
            mock.patch.object(bridge, "save_json", side_effect=crash_before_retirement),
            mock.patch.object(bridge, "api", side_effect=api),
            mock.patch.object(bridge, "hermes_slash_reply", return_value=None),
            mock.patch.object(bridge, "hermes_reply", side_effect=hermes),
            mock.patch.object(bridge, "add_reaction"),
            mock.patch.object(bridge, "remove_reaction"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge.time, "sleep", side_effect=KeyboardInterrupt),
            self.assertRaisesRegex(bridge.StatePersistenceError, "retirement crash"),
        ):
            bridge._main(state_path)

        crashed = bridge.require_state_object(bridge.load_json(state_path, {}))
        self.assertEqual((generations, posts, Executor.submissions, recovery_saves), (1, 1, 1, 2))
        self.assertEqual(crashed["dead_letters"][0]["recovery"]["answer"], "recover this exact answer")
        self.assertEqual([item["origin_message_id"] for item in crashed["origin_in_flight"]], [44])
        self.assertNotIn(44, crashed.get("seen_ids", []))

        Executor.submissions = 0
        with (
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[]),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(bridge._main(state_path), 0)

        recovered = bridge.require_state_object(bridge.load_json(state_path, {}))
        self.assertEqual(Executor.submissions, 0)
        self.assertEqual(recovered["dead_letters"][0]["recovery"]["answer"], "recover this exact answer")
        self.assertEqual(recovered.get("origin_in_flight", []), [])
        self.assertIn(44, recovered["seen_ids"])

    def test_confirmed_post_persistence_max_one_stops_polling_and_exits_without_replay(self) -> None:
        original_save_json = bridge.save_json
        state: dict = {"topic_sessions": {}}
        state_path = Path(self.state_dir.name) / "confirmed-max-one.json"
        message = user_message(44, 1, "Topic")
        proof_attempts = generations = posts = result_calls = 0

        class Future:
            def __init__(self, function, *args: object) -> None:
                try:
                    self.value = function(*args)
                    self.error = None
                except BaseException as exc:
                    self.value = None
                    self.error = exc

            def done(self) -> bool:
                return True

            def result(self):
                nonlocal result_calls
                result_calls += 1
                if self.error is not None:
                    raise self.error
                return self.value

        class Executor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, function, *args: object) -> Future:
                return Future(function, *args)

            def shutdown(self, **_kwargs: object) -> None:
                pass

        def save(path: Path, candidate: dict) -> None:
            nonlocal proof_attempts
            if state.get("reply_reconciliations") and state.get("origin_in_flight"):
                proof_attempts += 1
                raise bridge.StatePersistenceError("permanent proof failure")
            original_save_json(path, candidate)

        def hermes(_rc: dict, posted: dict, _session_id: str | None) -> tuple[str, str]:
            nonlocal generations
            generations += 1
            posted["_zulip_before_hermes_start"]()
            return "answer", "s1"

        def api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posts
            if path == "/api/v1/messages/44":
                return zulip_success(message=user_message(44, 1, "Topic"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                posts += 1
                return zulip_success(id=900)
            raise AssertionError((method, path))

        latest = mock.Mock(return_value=[message])
        launcher_proof = self.launcher_proof()
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "save_json", side_effect=save),
            mock.patch.object(bridge, "api", side_effect=api),
            mock.patch.object(bridge, "hermes_slash_reply", return_value=None),
            mock.patch.object(bridge, "hermes_reply", side_effect=hermes),
            mock.patch.object(bridge, "add_reaction"),
            mock.patch.object(bridge, "remove_reaction"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge.time, "sleep", return_value=None),
            mock.patch.object(bridge.time, "monotonic", return_value=100.0),
            mock.patch.object(bridge, "MAX_DURABLE_ATTEMPTS", 1),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 2),
            self.assertRaisesRegex(SystemExit, "2 consecutive iterations"),
        ):
            bridge._main(state_path, launcher_proof)

        persisted = bridge.load_json(state_path, {})
        self.assertEqual((proof_attempts, generations, posts, result_calls), (1, 1, 1, 1))
        self.assertEqual(latest.call_count, 1)
        self.assertEqual(state["reply_reconciliations"][0]["sent_message_id"], 900)
        self.assertEqual(state["origin_in_flight"][0]["stage"], "hermes_may_start")
        self.assertEqual(persisted.get("reply_reconciliations", []), [])
        self.assertEqual(persisted["origin_in_flight"][0]["stage"], "hermes_may_start")

    def test_uncertain_steering_retirement_max_one_exits_without_reappend_or_poll(self) -> None:
        state: dict = {"topic_sessions": {}}
        parent = user_message(44, 1, "Topic", content="start")
        steering = user_message(45, 1, "Topic", content="stop")
        appends: list[int] = []
        review_saves = 0

        class Future:
            def done(self) -> bool:
                return False

        class Executor:
            submissions: list[int] = []

            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, _function, _rc: dict, message: dict, _session_id: str | None) -> Future:
                self.submissions.append(message["id"])
                return Future()

            def shutdown(self, **_kwargs: object) -> None:
                pass

        def store(_rc: dict, message: dict, _conversation: dict, _active: int, before: object):
            before()
            appends.append(message["id"])
            return True, False

        def save(_path: Path, candidate: dict) -> None:
            nonlocal review_saves
            if bridge._uncertain_steering_origin_ids(candidate):
                review_saves += 1
                raise bridge.StatePersistenceError("permanent review failure")

        latest = mock.Mock(return_value=[parent, steering])
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", latest),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current),
            mock.patch.object(bridge, "store_active_steering_if_live", side_effect=store),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", Executor),
            mock.patch.object(bridge, "save_json", side_effect=save),
            mock.patch.object(bridge.time, "time", return_value=100.0),
            mock.patch.object(bridge.time, "sleep", return_value=None),
            mock.patch.object(bridge, "MAX_DURABLE_ATTEMPTS", 1),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 1),
            self.assertRaisesRegex(SystemExit, "1 consecutive iterations"),
        ):
            bridge._main()

        self.assertEqual((Executor.submissions, appends, review_saves), ([44], [45], 1))
        self.assertEqual(latest.call_count, 1)
        self.assertEqual(bridge._uncertain_steering_origin_ids(state), {45})
        self.assertNotIn(45, state.get("seen_ids", []))
        self.assertEqual([item["origin_message_id"] for item in state["origin_in_flight"]], [44])

    def test_unrelated_worker_persistence_error_keeps_existing_retry_behavior(self) -> None:
        result_calls = 0

        class FailedFuture:
            def done(self) -> bool:
                return True

            def result(self):
                nonlocal result_calls
                result_calls += 1
                raise bridge.StatePersistenceError("pre-POST durable failure")

        class FailedExecutor:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def submit(self, *_args: object) -> FailedFuture:
                return FailedFuture()

            def shutdown(self, **_kwargs: object) -> None:
                pass

        state: dict = {"topic_sessions": {}}
        with (
            mock.patch.object(bridge, "load_json", return_value=state),
            mock.patch.object(
                bridge,
                "load_rc",
                return_value={"site": "https://example", "email": "bot@example.com", "key": BOT_KEY},
            ),
            mock.patch.object(bridge, "load_alias_entries", return_value=[]),
            mock.patch.object(bridge, "load_state_signing_key", return_value=SIGNING_KEY),
            mock.patch.object(bridge, "latest_messages", return_value=[user_message(44, 1, "Topic")]),
            mock.patch.object(bridge, "save_json"),
            mock.patch.object(bridge.concurrent.futures, "ThreadPoolExecutor", FailedExecutor),
            mock.patch.object(bridge.time, "sleep", return_value=None),
            mock.patch.object(bridge, "MAX_CONSECUTIVE_POLL_FAILURES", 2),
            self.assertRaises(SystemExit),
        ):
            bridge._main(Path(self.state_dir.name) / "pre-post.json")
        self.assertEqual(result_calls, 2)
        self.assertEqual(state["origin_in_flight"][0]["stage"], "admitted")
        self.assertEqual(state.get("reply_reconciliations", []), [])

    def test_private_prompt_pipe_supports_long_console_prompt_without_visible_argv(self) -> None:
        script = self.python_console_script(
            "import hashlib,json,os,subprocess,sys\n"
            "prompt=sys.argv[sys.argv.index('-z')+1]\n"
            "try:\n"
            " visible=open(f'/proc/{os.getpid()}/cmdline','rb').read().replace(b'\\0',b' ').decode()\n"
            "except OSError:\n"
            " ps='/usr/bin/ps' if os.path.exists('/usr/bin/ps') else '/bin/ps'\n"
            " visible=subprocess.run([ps,'-o','command=','-p',str(os.getpid())],capture_output=True,text=True,check=True).stdout\n"
            "print(json.dumps({'length':len(prompt),'digest':hashlib.sha256(prompt.encode()).hexdigest(),"
            "'argv':sys.argv[1:],'visible':visible,'prefix':sys.prefix,'executable':sys.executable}))"
        )
        private_prompt = "private-zulip-prompt-" + "x" * 300_000
        command = [str(script), "--profile", "fixture", "-z", private_prompt, "--resume", "s1"]
        execution = {"hermes_started": False}
        proc = None
        pinned_command = None
        try:
            proc, interrupted = bridge._start_registered_process(
                777,
                command,
                execution,
                private_arg_index=4,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=bridge.hermes_subprocess_env(),
                start_new_session=True,
            )
            pinned_command = Path(proc.args[0])
            stdout, stderr = proc.communicate(timeout=10)
        finally:
            if proc is not None:
                bridge.unregister_active_process(777, proc)
        self.assertFalse(interrupted)
        self.assertEqual((proc.returncode, stderr), (0, ""))
        result = json.loads(stdout)
        self.assertEqual(result["length"], len(private_prompt))
        self.assertEqual(result["digest"], bridge.hashlib.sha256(private_prompt.encode()).hexdigest())
        self.assertEqual(result["argv"], ["--profile", "fixture", "-z", private_prompt, "--resume", "s1"])
        self.assertNotIn("private-zulip-prompt", "\0".join(proc.args))
        self.assertNotIn("private-zulip-prompt", result["visible"])
        self.assertEqual(Path(result["prefix"]).resolve(), self.venv.resolve())
        self.assertEqual(Path(result["executable"]), pinned_command)
        self.assertEqual(pinned_command.parent.resolve(), (self.venv / "bin").resolve())
        self.assertRegex(pinned_command.name, r"^\.hermes-python-pin-")
        self.assertFalse(pinned_command.exists())
        self.assertTrue(execution["hermes_started"])

    def test_interpreter_pin_is_verified_unique_and_cleaned_without_following_attacks(self) -> None:
        script = self.python_console_script("raise SystemExit(0)")
        proof = bridge._python_console_script(str(script))
        script_fd, source_fd = bridge._open_launcher_proof(proof)
        pins: list[tuple[Path, int, object]] = []
        try:
            pins = [bridge._pin_interpreter(proof, source_fd) for _ in range(2)]
            self.assertNotEqual(pins[0][0], pins[1][0])
            for path, fd, pinned in pins:
                opened = os.fstat(fd)
                self.assertEqual(stat.S_IMODE(opened.st_mode), 0o500)
                self.assertEqual(opened.st_nlink, 1)
                self.assertEqual(pinned.digest, proof.interpreter.digest)
                self.assertEqual(path.parent.resolve(), Path(proof.pin_directory))
        finally:
            os.close(script_fd)
            os.close(source_fd)
            for path, fd, pinned in pins:
                os.close(fd)
                bridge._remove_interpreter_pin(path, pinned)
                self.assertFalse(path.exists())

        pin_directory = Path(proof.pin_directory)
        dead_pin = pin_directory / ".hermes-python-pin-999999999-00000000000000000000000000000000"
        dead_pin.write_bytes(b"safe")
        dead_pin.chmod(0o500)
        hardlink = pin_directory / "hardlink"
        os.link(dead_pin, hardlink)
        cli._remove_stale_interpreter_pins(pin_directory)
        self.assertTrue(dead_pin.exists())
        hardlink.unlink()
        cli._remove_stale_interpreter_pins(pin_directory)
        self.assertFalse(dead_pin.exists())

        symlink_pin = pin_directory / ".hermes-python-pin-999999998-11111111111111111111111111111111"
        symlink_pin.symlink_to(script)
        cli._remove_stale_interpreter_pins(pin_directory)
        self.assertTrue(symlink_pin.is_symlink())
        symlink_pin.unlink()

        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        live_pin = pin_directory / f".hermes-python-pin-{sleeper.pid}-22222222222222222222222222222222"
        try:
            live_pin.write_bytes(b"live")
            live_pin.chmod(0o500)
            cli._remove_stale_interpreter_pins(pin_directory)
            self.assertTrue(live_pin.exists())
        finally:
            sleeper.terminate()
            sleeper.wait(timeout=5)
        cli._remove_stale_interpreter_pins(pin_directory)
        self.assertFalse(live_pin.exists())

    def test_launcher_replacement_fails_before_stage_or_popen_and_closes_verified_fds(self) -> None:
        script = self.python_console_script("print('original')")
        proof = bridge._python_console_script(str(script))
        replacement = self.python_console_script("print('replacement')")
        os.replace(replacement, script)
        before = set(os.listdir("/dev/fd"))
        execution = {"hermes_started": False}
        with mock.patch.object(bridge.subprocess, "Popen") as popen, self.assertRaisesRegex(
            RuntimeError, "identity changed"
        ):
            bridge._start_registered_process(
                700,
                [str(script), "-z", "private"],
                execution,
                private_arg_index=2,
                python_launcher=proof,
            )
        popen.assert_not_called()
        self.assertFalse(execution["hermes_started"])
        self.assertEqual(set(os.listdir("/dev/fd")), before)

        missing_proof_stage = mock.Mock()
        with (
            mock.patch.object(bridge, "HERMES", Path(self.state_dir.name) / "missing"),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "topic_history", return_value=""),
            self.assertRaises(RuntimeError),
        ):
            bridge.hermes_reply(
                {},
                {
                    "id": 701,
                    "stream_id": 1,
                    "display_recipient": "stream",
                    "topic": "Topic",
                    "content": "prompt",
                    "_zulip_before_hermes_start": missing_proof_stage,
                },
                None,
            )
        missing_proof_stage.assert_not_called()

        stage_script = self.python_console_script("print('original')")
        stage_proof = bridge._python_console_script(str(stage_script))
        stage_replacement = self.python_console_script("print('replacement')")
        execution = {"hermes_started": False}
        stage_calls = 0

        def replace_after_stage() -> None:
            nonlocal stage_calls
            stage_calls += 1
            os.replace(stage_replacement, stage_script)

        with (
            mock.patch.object(bridge, "HERMES", stage_script),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge, "build_attachment_context", return_value=""),
            mock.patch.object(bridge, "topic_history", return_value=""),
            mock.patch.object(bridge.subprocess, "Popen") as popen,
            self.assertRaisesRegex(RuntimeError, "identity changed"),
        ):
            bridge.hermes_reply(
                {},
                {
                    "id": 702,
                    "stream_id": 1,
                    "display_recipient": "stream",
                    "topic": "Topic",
                    "content": "prompt",
                    "_zulip_launcher_proof": stage_proof,
                    "_zulip_before_hermes_start": replace_after_stage,
                    "_zulip_execution": execution,
                },
                None,
            )
        self.assertEqual(stage_calls, 1)
        self.assertFalse(execution["hermes_started"])
        popen.assert_not_called()

        slash_script = self.python_console_script("print('slash')")
        slash_proof = bridge._python_console_script(str(slash_script))
        slash_replacement = self.python_console_script("print('changed')")
        slash_execution = {"hermes_started": False}

        def replace_before_slash() -> None:
            os.replace(slash_replacement, slash_script)

        with mock.patch.object(bridge, "_start_registered_process") as start, self.assertRaisesRegex(
            RuntimeError, "identity changed"
        ):
            bridge.run_slash_worker(
                "/status",
                "s1",
                703,
                {
                    "_zulip_launcher_proof": slash_proof,
                    "_zulip_before_hermes_start": replace_before_slash,
                    "_zulip_execution": slash_execution,
                },
            )
        start.assert_not_called()
        self.assertFalse(slash_execution["hermes_started"])

    def test_hermes_reply_python_console_fixture_preserves_prompt_resume_and_session(self) -> None:
        script = self.python_console_script(
            "import json,sys\n"
            "prompt=sys.argv[sys.argv.index('-z')+1]\n"
            "print(json.dumps({'prompt':prompt,'argv':sys.argv[1:]}))"
        )
        message = {
            "id": 999,
            "stream_id": 1,
            "display_recipient": "stream-1",
            "topic": "Private topic",
            "sender_full_name": "Private Sender",
            "content": "private message body",
        }

        class FakeProc:
            pid = 999001
            returncode = 0

            def __init__(self, payload: str) -> None:
                self.payload = payload

            def poll(self) -> int:
                return 0

            def wait(self, **_kwargs: object) -> int:
                return 0

            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                return self.payload, ""

        def start(_message_id: int, command: list[str], *_args: object, **_kwargs: object) -> tuple[FakeProc, bool]:
            prompt = command[command.index("-z") + 1]
            return FakeProc(json.dumps({"prompt": prompt, "argv": command[1:]})), False

        with (
            mock.patch.object(bridge, "HERMES", script),
            mock.patch.object(
                bridge, "HERMES_EXTRA_ARGS", ["--profile", "fixture", "--toolsets", "coding"]
            ),
            mock.patch.object(bridge, "RC_PATH", Path("/private/credentials/zuliprc")),
            mock.patch.object(bridge, "refresh_generation_origin"),
            mock.patch.object(bridge, "build_attachment_context", return_value="\nprivate attachment text"),
            mock.patch.object(bridge, "topic_history", return_value="private topic history"),
            mock.patch.object(bridge, "_start_registered_process", side_effect=start),
            mock.patch.object(bridge, "typing_status"),
            mock.patch.object(bridge, "find_session_by_marker", return_value="child-session"),
            mock.patch.object(bridge, "clean_session_record") as clean,
            mock.patch.object(bridge, "merge_session_into", return_value="s1") as merge,
            mock.patch.object(bridge, "set_session_archived"),
        ):
            answer, session_id = bridge.hermes_reply(
                {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "secret-api-key"},
                message,
                "s1",
            )
        result = json.loads(answer)
        self.assertEqual(session_id, "s1")
        self.assertEqual(
            result["argv"][-2:],
            ["--resume", "s1"],
        )
        for private in (
            "private message body",
            "private attachment text",
            "Private topic",
            "Private Sender",
            "private topic history",
        ):
            self.assertIn(private, result["prompt"])
        self.assertLess(
            result["prompt"].index("Hermes bridge trusted instructions:"),
            result["prompt"].index("private message body"),
        )
        self.assertNotIn("/private/credentials/zuliprc", result["prompt"])
        self.assertNotIn("secret-api-key", result["prompt"])
        clean.assert_called_once()
        merge.assert_called_once()

    def test_private_prompt_transport_and_non_python_executable_fail_closed(self) -> None:
        shell = Path(self.state_dir.name) / "hermes-shell"
        shell.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        shell.chmod(0o700)
        with mock.patch.object(bridge.subprocess, "Popen") as popen, self.assertRaisesRegex(
            RuntimeError, "not a Python console script"
        ):
            bridge._start_registered_process(1, [str(shell), "-z", "secret"], private_arg_index=2)
        popen.assert_not_called()

        script = self.python_console_script("raise SystemExit(0)")
        execution = {"hermes_started": False}
        with mock.patch.object(bridge, "_write_private_prompt", side_effect=BrokenPipeError), self.assertRaisesRegex(
            RuntimeError, "private prompt transport failed"
        ):
            bridge._start_registered_process(
                2,
                [str(script), "-z", "secret"],
                execution,
                private_arg_index=2,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        self.assertFalse(execution["hermes_started"])
        self.assertNotIn(2, bridge.ACTIVE_PROCESSES)

    def test_python_console_resolution_and_private_pipe_errors_fail_closed(self) -> None:
        script = self.python_console_script("raise SystemExit(0)")
        with mock.patch.dict(os.environ, {"PATH": str(script.parent)}, clear=True):
            resolved, interpreter = bridge._python_console_script(script.name)
        self.assertEqual(resolved, str(script.resolve()))
        self.assertEqual(interpreter, str(Path(sys.executable).resolve()))

        env_script = Path(self.state_dir.name) / "env-hermes"
        env_script.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
        env_script.chmod(0o700)
        with mock.patch.dict(os.environ, {"PATH": str(Path(sys.executable).parent)}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "not a Python console script"):
                bridge._python_console_script(str(env_script))

        malformed = Path(self.state_dir.name) / "malformed-hermes"
        malformed.write_bytes(b"#!\xff\n")
        malformed.chmod(0o700)
        for command in ("missing-hermes-command", str(Path(self.state_dir.name) / "missing"), str(malformed)):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                bridge._python_console_script(command)

        with mock.patch.object(bridge.os, "write", return_value=0), self.assertRaisesRegex(
            OSError, "no progress"
        ):
            bridge._write_private_prompt(9, "private")
        with self.assertRaisesRegex(RuntimeError, "argument is invalid"):
            bridge._start_registered_process(3, [str(script), "-z", "private"], private_arg_index=3)
        with mock.patch.object(bridge.subprocess, "Popen", side_effect=OSError("startup failed")), self.assertRaises(
            OSError
        ):
            bridge._start_registered_process(4, [str(script), "-z", "private"], private_arg_index=2)
        self.assertEqual(list((self.venv / "bin").glob(".hermes-python-pin-*")), [])

        bad_stream = mock.Mock()
        bad_stream.close.side_effect = OSError("close failed")
        proc = mock.Mock(pid=12345, stdin=bad_stream, stdout=bad_stream, stderr=bad_stream)
        proc.kill.side_effect = OSError("kill failed")
        with (
            mock.patch.object(bridge.subprocess, "Popen", return_value=proc),
            mock.patch.object(bridge, "register_active_process", side_effect=RuntimeError("register failed")),
            self.assertRaisesRegex(RuntimeError, "register failed"),
        ):
            bridge._start_registered_process(5, [str(script), "-z", "private"], private_arg_index=2)
        self.assertNotIn(5, bridge.ACTIVE_PROCESSES)

    def test_slash_payload_is_stdin_only_and_absent_from_registration_argv(self) -> None:
        payload = "/status private-slash-payload"
        code = (
            "import json,sys; request=json.loads(sys.stdin.readline()); "
            "print(json.dumps({'ok':True,'output':request['command']}))"
        )
        original_popen = subprocess.Popen
        visible_commands: list[list[str]] = []

        def popen(command: list[str], **kwargs: object):
            visible_commands.append(command)
            return original_popen(command, **kwargs)

        with (
            mock.patch.object(bridge.subprocess, "Popen", side_effect=popen),
            mock.patch.object(bridge, "_slash_worker_command", return_value=[sys.executable, "-c", code]),
            mock.patch.object(bridge, "SHUTTING_DOWN", False),
        ):
            self.assertEqual(bridge.run_slash_worker(payload, "s1", 88), payload)
        self.assertEqual(len(visible_commands), 1)
        self.assertNotIn("private-slash-payload", "\0".join(visible_commands[0]))

    def test_ps_fallback_uses_fixed_absolute_path_and_sanitized_environment(self) -> None:
        calls: list[tuple[list[str], dict]] = []

        class Ps:
            def __init__(self, command: list[str], **kwargs: object) -> None:
                calls.append((command, dict(kwargs)))
                self.command = command

            def communicate(self, **_kwargs: object) -> tuple[str, str]:
                if "-axo" in self.command:
                    return f"123 1 123 {os.geteuid()} Mon Jan  1 00:00:00 2024\n", ""
                return "Mon Jan  1 00:00:00 2024\n", ""

            def kill(self) -> None:
                pass

        with (
            mock.patch.dict(os.environ, {"PATH": str(Path(self.state_dir.name)), "HERMES_ZULIP_API_KEY": "secret"}),
            mock.patch.object(bridge.sys, "platform", "generic"),
            mock.patch.object(bridge.Path, "read_text", side_effect=OSError),
            mock.patch.object(bridge, "SYSTEM_POPEN", Ps),
        ):
            self.assertTrue(bridge._process_birth_identity(123).startswith("ps:"))
            self.assertEqual(bridge._local_process_table()[123][1], 123)
        self.assertEqual(len(calls), 2)
        for command, kwargs in calls:
            self.assertIn(command[0], {"/usr/bin/ps", "/bin/ps"})
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertNotIn("HERMES_ZULIP_API_KEY", kwargs["env"])

        with mock.patch.object(bridge, "_system_ps_path", return_value=""), mock.patch.object(
            bridge, "SYSTEM_POPEN"
        ) as popen, mock.patch.object(bridge.sys, "platform", "generic"), mock.patch.object(
            bridge.Path, "read_text", side_effect=OSError
        ):
            self.assertEqual(bridge._process_birth_identity(123), "")
            self.assertEqual(bridge._local_process_table(), {})
        popen.assert_not_called()

    def test_encoded_upload_paths_are_canonical_before_authenticated_get(self) -> None:
        hostile = (
            "https://zulip.example.com/user_uploads/1/a/file.txt",
            "/user_uploads/1/a/%2e%2e%2fapi",
            "/user_uploads/1/a/%2E%2e%2Fapi",
            "/user_uploads/1/a/%5c..%5capi",
            "/user_uploads/1/a/%252e%252e%252fapi",
            "/user_uploads/1/a/file%0aname.txt",
            "/user_uploads/1/a/file%FFname.txt",
            "/user_uploads/1/a/name%2fpart.txt",
        )
        opener = mock.Mock()
        with mock.patch.object(bridge.urllib.request, "build_opener", return_value=opener):
            for path in hostile:
                with self.subTest(path=path):
                    self.assertIsNone(bridge._safe_upload_path(path))
                    result = bridge.fetch_zulip_attachment(
                        {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "secret"},
                        path,
                    )
                    self.assertIn("unsafe", result["error"])
        opener.assert_not_called()

        links = bridge.find_zulip_upload_links(
            "files /user_uploads/1/a/file%20name.txt /user_uploads/1/a/%E2%9C%93.png",
            "https://zulip.example.com",
        )
        self.assertEqual([item["filename"] for item in links], ["file name.txt", "✓.png"])

    def test_anchor_match_schema_accepts_only_current_detail_objects(self) -> None:
        state = {"topic_sessions": {}}
        first = self.seed_topic(state, message_id=50, stream_id=1, topic="One", session_id="s1")
        second = self.seed_topic(state, message_id=60, stream_id=1, topic="Two", session_id="s2")
        message = {"stream_id": 1, "topic": "Renamed"}
        with mock.patch.object(
            bridge, "api", return_value=zulip_success(messages={"60": narrow_match()})
        ):
            self.assertEqual(
                bridge._thread_for_matching_anchors({}, state, message, "example"), second["thread_id"]
            )
        with mock.patch.object(bridge, "api", return_value=zulip_success(messages={})):
            self.assertEqual(bridge._thread_for_matching_anchors({}, state, message, "example"), "")
        self.assertNotEqual(first["thread_id"], second["thread_id"])

        for matches in (
            {"50": {}},
            {"50": True},
            {"50": False},
            {"50": 1},
            {"50": "true"},
            {"999": narrow_match()},
        ):
            with self.subTest(matches=matches), mock.patch.object(
                bridge, "api", return_value=zulip_success(messages=matches)
            ), self.assertRaises(bridge.ReplyRoutingError):
                bridge._thread_for_matching_anchors({}, state, message, "example")

    def test_steering_persistence_boundary_prevents_append_and_restart_replay(self) -> None:
        message, state = self.admitted_message({"id": 222, "content": "steer"})
        message["_zulip_persist"] = mock.Mock(side_effect=bridge.StatePersistenceError("save failed"))
        store = mock.Mock()
        with (
            mock.patch.dict(bridge.ACTIVE_PROCESSES, {111: mock.Mock(poll=mock.Mock(return_value=None))}, clear=True),
            mock.patch.object(bridge, "validated_active_steering_message", side_effect=lambda _rc, current: current),
            mock.patch.object(bridge, "store_steering_message", store),
            self.assertRaises(bridge.StatePersistenceError),
        ):
            bridge.handle_active_topic_message(
                {}, message, "s1", {"conversation_key": "key", "thread_id": "thread"}, 111, {}, set()
            )
        store.assert_not_called()
        self.assertEqual(state["origin_in_flight"][0]["stage"], "admitted")
        seen: set[int] = set()
        bridge._recover_in_flight_origins(state, seen, now=2.0)
        self.assertEqual(seen, set())
        self.assertEqual([item["origin_message_id"] for item in state["origin_retries"]], [222])

    def test_goal_session_change_uses_final_session_in_signed_persistence_outcome(self) -> None:
        state: dict = {"topic_sessions": {}}
        message = user_message(44, 1, "Topic")
        _session, conversation = bridge.resolve_session(message, {}, state, "example")
        bridge.note_bridge_thread(state, conversation, session_id="s1")
        bridge.note_topic_session(state, conversation, "s1")
        message.update(
            _zulip_state=state,
            _zulip_bridge={**conversation, "session_id": "s1"},
            _zulip_signing_key=SIGNING_KEY,
            _zulip_execution={"hermes_started": True},
            _zulip_generation_route={
                "realm": "example",
                "thread_id": conversation["thread_id"],
                "session_id": "s1",
                "stream_id": 1,
                "topic": "Topic",
                "native_id": "",
                "sender_id": 17,
                "sender_email": "user@example.com",
                "sender_is_bot": False,
            },
        )
        posts = 0
        generations = 0

        def persist() -> None:
            if any(job["sent_message_id"] == 901 for job in state.get("reply_reconciliations", [])):
                raise bridge.StatePersistenceError("injected final-session save failure")

        message["_zulip_persist"] = persist

        def hermes(_rc: dict, posted: dict, _session_id: str | None) -> tuple[str, str]:
            nonlocal generations
            generations += 1
            if generations == 2:
                posted["_zulip_generation_route"] = {
                    **message["_zulip_generation_route"],
                    "session_id": "s1",
                }
                return "continued", "s2"
            return "first", "s1"

        def api(_rc: dict, method: str, path: str, **_kwargs: object) -> dict:
            nonlocal posts
            if path == "/api/v1/messages/44":
                return zulip_success(message=user_message(44, 1, "Topic"))
            if path == "/api/v1/messages/matches_narrow":
                return zulip_success(messages={"44": narrow_match()})
            if method == "POST":
                posts += 1
                return zulip_success(id=899 + posts)
            raise AssertionError((method, path))

        with (
            mock.patch.object(bridge, "hermes_slash_reply", return_value=None),
            mock.patch.object(bridge, "hermes_reply", side_effect=hermes),
            mock.patch.object(
                bridge,
                "goal_decision_after_turn",
                return_value={"message": "", "should_continue": True, "continuation_prompt": "next"},
            ),
            mock.patch.object(bridge, "api", side_effect=api),
            mock.patch.object(bridge, "add_reaction"),
            mock.patch.object(bridge, "remove_reaction"),
        ):
            outcome = bridge.handle_message({}, message, "s1")

        self.assertIsInstance(outcome, bridge.PostCommitPersistenceOutcome)
        self.assertEqual((outcome.session_id, outcome.sent_message_id), ("s2", 901))
        self.assertEqual((generations, posts), (2, 2))
        final_job = next(job for job in state["reply_reconciliations"] if job["sent_message_id"] == 901)
        self.assertEqual(final_job["session_id"], "s2")
        bridge._validate_reconciliation_tag(SIGNING_KEY, final_job)
        self.assertEqual(state["zulip_threads"][conversation["thread_id"]]["session_id"], "s2")

    def test_confirmed_session_transition_rejects_foreign_session_and_topic_owners(self) -> None:
        state: dict = {"topic_sessions": {}}
        source = self.seed_topic(state, message_id=44, stream_id=1, topic="Topic", session_id="s1")
        self.seed_topic(state, message_id=45, stream_id=1, topic="Other", session_id="s2")
        message = user_message(44, 1, "Topic")
        message.update(
            _zulip_state=state,
            _zulip_bridge={**source, "session_id": "s2"},
            _zulip_generation_route={
                "thread_id": source["thread_id"],
                "session_id": "s2",
                "stream_id": 1,
            },
        )
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "already owned"):
            bridge.ensure_reply_destination_owner({}, message, user_message(44, 1, "Topic"))

        job = bridge._reply_reconciliation_job(
            message,
            user_message(44, 1, "Topic"),
            900,
            SIGNING_KEY,
            "answer",
        )
        before = json.loads(json.dumps(state))
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "already owned"):
            bridge._publish_confirmed_reply(state, message, job)
        self.assertEqual(state, before)

        state["zulip_threads"].pop(next(key for key, value in state["zulip_threads"].items() if value.get("session_id") == "s2"))
        conflicting_key = f"1:{bridge.topic_key(1, 'Topic')}"
        state["topic_sessions"][conflicting_key] = "s3"
        before = json.loads(json.dumps(state))
        with self.assertRaisesRegex(bridge.ReplyRoutingError, "topic owner"):
            bridge._publish_confirmed_reply(state, message, job)
        self.assertEqual(state, before)

    def test_state_size_validation_and_save_share_exact_canonical_bytes(self) -> None:
        target = 8_388_604
        overhead = len(bridge._serialized_state({"value": ""}))
        exact = {"value": "x" * (target - overhead)}
        self.assertEqual(len(bridge._serialized_state(exact)), target)
        path = Path(self.state_dir.name) / "bounded-state.json"
        bridge.require_state_object(exact)
        bridge.save_json(path, exact)
        first = path.read_bytes()
        self.assertEqual(len(first), target)
        bridge.save_json(path, exact)
        self.assertEqual(path.read_bytes(), first)

        pretty_path = Path(self.state_dir.name) / "pretty-state.json"
        unicode_state = {"value": "hello ✓"}
        pretty_path.write_text(json.dumps(unicode_state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        migrated = bridge.require_state_object(bridge.load_json(pretty_path, {}))
        bridge.save_json(pretty_path, migrated)
        self.assertEqual(pretty_path.read_bytes(), bridge._serialized_state(unicode_state))

        before = path.read_bytes()
        with mock.patch.object(bridge, "MAX_STATE_BYTES", target), self.assertRaisesRegex(
            bridge.StatePersistenceError, "exceeds"
        ):
            bridge.save_json(path, {"value": exact["value"] + "x"})
        self.assertEqual(path.read_bytes(), before)
        with mock.patch.object(bridge, "MAX_STATE_BYTES", target), self.assertRaisesRegex(ValueError, "exceeds"):
            bridge.require_state_object({"value": exact["value"] + "x"})

    @staticmethod
    def _capture_exception(errors: list[BaseException], function, *args: object) -> None:
        try:
            function(*args)
        except BaseException as exc:
            errors.append(exc)


if __name__ == "__main__":
    unittest.main()
