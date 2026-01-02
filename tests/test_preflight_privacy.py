from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hermes_zulip_bridge import bridge, cli, notifier, smoke
from hermes_zulip_bridge.config import preflight_credentials


class CredentialPreflightTests(unittest.TestCase):
    def test_explicit_zuliprc_is_parsed_before_cli_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "zuliprc"
            path.write_text("[broken]\nsecret=value\n", encoding="utf-8")
            path.chmod(0o600)
            config = {"hermes": {"command": "/unused"}, "zulip": {"zuliprc": str(path)}}
            before = dict(os.environ)
            with mock.patch.object(cli, "load_config", return_value=config), mock.patch.object(
                cli, "_python_console_script", side_effect=AssertionError("launcher")
            ), mock.patch.object(cli, "process_lock", side_effect=AssertionError("lock")), mock.patch.object(
                cli, "apply_bridge_env", side_effect=AssertionError("env")
            ), self.assertRaisesRegex(SystemExit, cli.CONFIGURATION_INVALID):
                cli.main(["bridge"])
            self.assertEqual(dict(os.environ), before)

    def test_inline_credentials_are_complete_before_environment_install(self) -> None:
        config = {
            "hermes": {"command": "/unused"},
            "zulip": {"site": "https://private.invalid", "bot_email": "private@example.invalid", "bot_api_key_env": "MISSING_KEY"},
        }
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            preflight_credentials(config)

    def test_valid_explicit_preflight_value_is_reused_by_notifier_cli(self) -> None:
        rc = {"site": "https://private.invalid", "email": "private@example.invalid", "key": "secret"}
        with mock.patch.object(cli, "load_config", return_value={}), mock.patch.object(
            cli, "preflight_credentials", return_value=rc
        ) as preflight, mock.patch.object(cli, "apply_notifier_env", return_value={}), mock.patch.dict(
            os.environ, {}, clear=False
        ), mock.patch.object(notifier, "main", return_value=0) as run:
            self.assertEqual(cli.main(["notifier"]), 0)
        preflight.assert_called_once_with({})
        run.assert_called_once_with(rc=rc)

    def test_programmatic_smoke_validates_credentials_before_launcher_and_lock(self) -> None:
        args = argparse.Namespace(stream="", topic="private", message="private", post_probe=False, run_hermes=False, human_origin_message_id=None, post_reply=False)
        order: list[str] = []
        with mock.patch.object(smoke.bridge, "load_rc", side_effect=lambda: order.append("credentials") or (_ for _ in ()).throw(SystemExit("bad"))), mock.patch.object(
            smoke.bridge, "_python_console_script", side_effect=lambda *_: order.append("launcher")
        ), mock.patch.object(smoke.bridge, "process_lock", side_effect=lambda *_: order.append("lock")), self.assertRaises(SystemExit):
            smoke.run(args)
        self.assertEqual(order, ["credentials"])

    def test_programmatic_bridge_validates_credentials_before_launcher_and_lock(self) -> None:
        order: list[str] = []
        with mock.patch.object(bridge, "load_rc", side_effect=lambda: order.append("credentials") or (_ for _ in ()).throw(SystemExit("bad"))), mock.patch.object(
            bridge, "_python_console_script", side_effect=lambda *_: order.append("launcher")
        ), mock.patch.object(bridge, "process_lock", side_effect=lambda *_: order.append("lock")), self.assertRaises(SystemExit):
            bridge.main()
        self.assertEqual(order, ["credentials"])


class PublicOutputTests(unittest.TestCase):
    def test_smoke_result_boundary_drops_all_private_strings(self) -> None:
        canaries = ["site", "email", "stream", "topic", "launcher", "session", "sidecar", "/private/path", "content"]
        result = smoke.public_result({"ok": True, "checks": {name: f"secret-{name}" for name in canaries} | {"probe_message_id": 12}})
        rendered = repr(result)
        self.assertEqual(result, {"ok": True, "checks": {"probe_message_id": 12}})
        for canary in canaries:
            self.assertNotIn(f"secret-{canary}", rendered)

    def test_notifier_dry_summary_contains_counts_only(self) -> None:
        counts = notifier.scan_once
        output = io.StringIO()
        with mock.patch.object(notifier, "process_lock") as lock, mock.patch.object(
            notifier, "load_state", return_value=({"version": 2, "notified": {}, "outbox": [], "dead_letters": []}, b"k" * 32)
        ), mock.patch.object(notifier, "scan_once", return_value={"admitted": 1, "delivered": 0, "pending": 1, "primed": 0, "operator_review": 0}), mock.patch(
            "sys.argv", ["notifier", "--once", "--dry-run"]
        ), mock.patch("sys.stdout", output):
            lock.return_value.__enter__.return_value.state_path = Path("/opaque")
            self.assertEqual(notifier.main(rc={"site": "opaque", "email": "opaque", "key": "opaque"}), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(set(payload), {"ok", "counts"})


if __name__ == "__main__":
    unittest.main()
