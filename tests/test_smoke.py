from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from hermes_zulip_bridge import smoke


class SmokeTests(unittest.TestCase):
    def test_smoke_run_posts_probe_and_checks_steering_without_hermes(self) -> None:
        calls: list[tuple[str, str]] = []
        original = {
            "load_rc": smoke.bridge.load_rc,
            "api": smoke.bridge.api,
            "HERMES": smoke.bridge.HERMES,
            "STEERING_PATH": smoke.bridge.STEERING_PATH,
            "ALLOW_STREAMS": smoke.bridge.ALLOW_STREAMS,
        }

        def fake_api(_rc: dict[str, str], method: str, path: str, **_kwargs: object) -> dict:
            calls.append((method, path))
            if path == "/api/v1/users/me":
                return {"email": "bot@example.com"}
            if path == "/api/v1/messages":
                return {"id": 123}
            if path == "/api/v1/messages/123":
                return {
                    "message": {
                        "id": 123,
                        "type": "stream",
                        "stream_id": 7,
                        "display_recipient": "hermes",
                        "topic": "Smoke",
                        "sender_full_name": "Hermes bot",
                        "sender_email": "bot@example.com",
                        "content": "probe",
                    }
                }
            raise AssertionError(path)

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                hermes = Path(tmpdir) / "hermes"
                hermes.write_text("#!/bin/sh\n", encoding="utf-8")
                smoke.bridge.load_rc = lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
                smoke.bridge.api = fake_api
                smoke.bridge.HERMES = hermes
                smoke.bridge.STEERING_PATH = Path(tmpdir) / "steering.jsonl"
                smoke.bridge.ALLOW_STREAMS = {"hermes"}
                result = smoke.run(argparse.Namespace(stream="", topic="Smoke", message="probe", post_probe=True, run_hermes=False, post_reply=False))
        finally:
            smoke.bridge.load_rc = original["load_rc"]
            smoke.bridge.api = original["api"]
            smoke.bridge.HERMES = original["HERMES"]
            smoke.bridge.STEERING_PATH = original["STEERING_PATH"]
            smoke.bridge.ALLOW_STREAMS = original["ALLOW_STREAMS"]

        self.assertTrue(result["ok"])
        self.assertEqual(calls[:3], [("GET", "/api/v1/users/me"), ("POST", "/api/v1/messages"), ("GET", "/api/v1/messages/123")])
        self.assertTrue(result["checks"]["steering_marker_ok"])

    def test_smoke_run_can_run_hermes_and_post_reply(self) -> None:
        replies: list[str] = []
        original = {
            "load_rc": smoke.bridge.load_rc,
            "api": smoke.bridge.api,
            "HERMES": smoke.bridge.HERMES,
            "STEERING_PATH": smoke.bridge.STEERING_PATH,
            "ALLOW_STREAMS": smoke.bridge.ALLOW_STREAMS,
            "hermes_reply": smoke.bridge.hermes_reply,
            "reply": smoke.bridge.reply,
        }

        def fake_api(_rc: dict[str, str], method: str, path: str, **_kwargs: object) -> dict:
            if path == "/api/v1/users/me":
                return {"email": "bot@example.com"}
            if path == "/api/v1/messages":
                return {"id": 123}
            if path == "/api/v1/messages/123":
                return {"message": {"id": 123, "type": "stream", "stream_id": 7, "display_recipient": "hermes", "topic": "Smoke", "content": "probe"}}
            raise AssertionError((method, path))

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                hermes = Path(tmpdir) / "hermes"
                hermes.write_text("#!/bin/sh\n", encoding="utf-8")
                smoke.bridge.load_rc = lambda: {"site": "https://zulip.example.com", "email": "bot@example.com", "key": "test-api-key"}
                smoke.bridge.api = fake_api
                smoke.bridge.HERMES = hermes
                smoke.bridge.STEERING_PATH = Path(tmpdir) / "steering.jsonl"
                smoke.bridge.ALLOW_STREAMS = {"hermes"}
                smoke.bridge.hermes_reply = lambda _rc, _message, _session_id: ("ok", "s1")
                smoke.bridge.reply = lambda _rc, _message, content: replies.append(content)
                result = smoke.run(argparse.Namespace(stream="", topic="Smoke", message="probe", post_probe=True, run_hermes=True, post_reply=True))
        finally:
            smoke.bridge.load_rc = original["load_rc"]
            smoke.bridge.api = original["api"]
            smoke.bridge.HERMES = original["HERMES"]
            smoke.bridge.STEERING_PATH = original["STEERING_PATH"]
            smoke.bridge.ALLOW_STREAMS = original["ALLOW_STREAMS"]
            smoke.bridge.hermes_reply = original["hermes_reply"]
            smoke.bridge.reply = original["reply"]

        self.assertTrue(result["ok"])
        self.assertEqual(result["checks"]["hermes_session_id"], "s1")
        self.assertEqual(replies, ["Smoke test response from packaged bridge:\n\nok"])


if __name__ == "__main__":
    unittest.main()
