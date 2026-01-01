from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from hermes_zulip_bridge.config import apply_bridge_env, load_config, validate_config


class ConfigTests(unittest.TestCase):
    def test_load_yaml_and_apply_bridge_env(self) -> None:
        original = dict(os.environ)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.environ["ZULIP_TEST_KEY"] = "test-api-key"
                config_path = Path(tmpdir) / "bridge.yaml"
                config_path.write_text(
                    """
instance_name: hermes
hermes:
  command: /opt/hermes/bin/hermes
  profile: default
  working_directory: /srv/hermes
zulip:
  site: https://zulip.example.com
  bot_email: hermes-bot@example.com
  bot_api_key_env: ZULIP_TEST_KEY
  stream: hermes
  stream_id: 12345
  topic_allowlist:
    - Staging
bridge:
  state_directory: {tmpdir}
  poll_interval: 2
response:
  max_message_size: 8000
""".format(tmpdir=tmpdir),
                    encoding="utf-8",
                )

                config = load_config(config_path)
                self.assertEqual(validate_config(config), [])
                env = apply_bridge_env(config)
                rc_path = Path(env["HERMES_ZULIP_RC"])

                self.assertEqual(env["HERMES_BIN"], "/opt/hermes/bin/hermes")
                self.assertEqual(env["HERMES_CWD"], "/srv/hermes")
                self.assertEqual(env["HERMES_EXTRA_ARGS"], "--profile default")
                self.assertEqual(env["HERMES_ZULIP_STREAMS"], "hermes")
                self.assertEqual(env["HERMES_ZULIP_STREAM_IDS"], "12345")
                self.assertEqual(env["HERMES_ZULIP_TOPICS"], "Staging")
                self.assertEqual(env["HERMES_ZULIP_IGNORE_CONTENT_PATTERNS"], "")
                self.assertEqual(env["HERMES_ZULIP_STEERING_REACTION"], "eyes")
                self.assertEqual(env["HERMES_ZULIP_HARD_INTERRUPT"], "1")
                self.assertEqual(env["HERMES_ZULIP_RESPONSE_MAX_CHARS"], "8000")
                self.assertTrue(rc_path.exists())
                self.assertIn("site=https://zulip.example.com", rc_path.read_text(encoding="utf-8"))
        finally:
            os.environ.clear()
            os.environ.update(original)

    def test_validate_config_reports_missing_required_fields(self) -> None:
        issues = validate_config({"zulip": {"site": "https://example.zulip.com"}})
        self.assertIn("hermes.command is required", issues)
        self.assertIn("zulip.bot_email or zulip.bot_email_env is required unless zulip.zuliprc is set", issues)
        self.assertIn("zulip.bot_api_key_env is required unless zulip.zuliprc is set", issues)


if __name__ == "__main__":
    unittest.main()
