from __future__ import annotations

import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from hermes_zulip_bridge import config as bridge_config
from hermes_zulip_bridge import security
from hermes_zulip_bridge.config import apply_bridge_env, bridge_bundle_paths, bridge_state_path, load_config, validate_config
from hermes_zulip_bridge.locking import process_lock_bundle_paths


def write_private(path: Path, content: str | bytes) -> None:
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def secure_zulip(**values: object) -> dict[str, object]:
    return {
        "allowed_senders": ["id:17"],
        "stream_id": 7,
        "topic_policy": "any",
        **values,
    }


def secure_hermes(**values: object) -> dict[str, object]:
    return {"command": "/bin/true", "toolsets": ["coding"], **values}


class ConfigTests(unittest.TestCase):
    def test_secure_config_file_matrix_and_replacement_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "config.json"
            write_private(path, '{}')
            self.assertEqual(load_config(path), {})

            for mode in (0o666, 0o640, 0o700):
                with self.subTest(mode=oct(mode)):
                    path.chmod(mode)
                    with self.assertRaisesRegex(ValueError, "unsafe"):
                        load_config(path)
            path.chmod(0o600)

            symlink = root / "symlink.json"
            symlink.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                load_config(symlink)

            hardlink = root / "hardlink.json"
            os.link(path, hardlink)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                load_config(path)
            hardlink.unlink()

            opened = path.stat()
            foreign = types.SimpleNamespace(
                **{
                    name: getattr(opened, name)
                    for name in ("st_mode", "st_nlink", "st_dev", "st_ino", "st_size", "st_mtime_ns")
                },
                st_uid=os.geteuid() + 1,
            )
            with mock.patch.object(security.os, "fstat", return_value=foreign), self.assertRaisesRegex(
                ValueError, "unsafe"
            ):
                load_config(path)

            changed = types.SimpleNamespace(
                **{
                    name: getattr(opened, name)
                    for name in ("st_mode", "st_uid", "st_nlink", "st_dev", "st_ino", "st_size")
                },
                st_mtime_ns=opened.st_mtime_ns + 1,
            )
            with mock.patch.object(
                security.os, "fstat", side_effect=[opened, changed]
            ), self.assertRaisesRegex(ValueError, "changed during read"):
                load_config(path)

            writable = root / "writable"
            writable.mkdir(mode=0o700)
            nested = writable / "config.json"
            write_private(nested, '{}')
            writable.chmod(0o777)
            try:
                with self.assertRaisesRegex(ValueError, "ancestry"):
                    load_config(nested)
            finally:
                writable.chmod(0o700)

    def test_config_rejects_invalid_utf8_and_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            write_private(path, b"\xff")
            with self.assertRaisesRegex(ValueError, "UTF-8"):
                load_config(path)
            write_private(path, "{")
            with self.assertRaises(ValueError):
                load_config(path)
            yaml_path = Path(tmpdir) / "config.yaml"
            write_private(yaml_path, "key: [unterminated")
            with self.assertRaisesRegex(ValueError, "malformed"):
                load_config(yaml_path)

    def test_config_file_size_and_required_secret_fail_before_environment_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            write_private(path, b"{" + b" " * 16 + b"}")
            with mock.patch.object(bridge_config, "MAX_CONFIG_BYTES", 8), self.assertRaisesRegex(
                ValueError, "exceeds 8 bytes"
            ):
                load_config(path)

        config = {
            "hermes": secure_hermes(),
            "zulip": {
                "site": "https://example",
                "bot_email": "bot@example.com",
                "bot_api_key_env": "MISSING_TEST_SECRET",
            },
        }
        before = dict(os.environ)
        os.environ.pop("MISSING_TEST_SECRET", None)
        try:
            with self.assertRaisesRegex(ValueError, "MISSING_TEST_SECRET"):
                apply_bridge_env(config)
        finally:
            os.environ.clear()
            os.environ.update(before)

    def test_load_yaml_and_apply_bridge_env(self) -> None:
        original = dict(os.environ)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.environ["ZULIP_TEST_KEY"] = "test-api-key"
                config_path = Path(tmpdir) / "bridge.yaml"
                write_private(
                    config_path,
                    """
instance_name: hermes
hermes:
  command: hermes
  profile: default
  toolsets: [coding, kanban]
  working_directory: .
zulip:
  site: https://zulip.example.com
  bot_email: hermes-bot@example.com
  bot_api_key_env: ZULIP_TEST_KEY
  stream: hermes
  stream_id: 12345
  allowed_senders:
    - id:17
  topic_allowlist:
    - Staging
bridge:
  state_directory: {tmpdir}
  poll_interval: 2
response:
  max_message_size: 8000
""".format(tmpdir=tmpdir),
                )

                config = load_config(config_path)
                self.assertEqual(validate_config(config), [])
                env = apply_bridge_env(config)

                self.assertEqual(env["HERMES_BIN"], "hermes")
                self.assertEqual(env["HERMES_CWD"], ".")
                self.assertEqual(env["HERMES_EXTRA_ARGS"], "--profile default --toolsets coding,kanban")
                self.assertEqual(env["HERMES_ZULIP_STREAMS"], "hermes")
                self.assertEqual(env["HERMES_ZULIP_STREAM_IDS"], "12345")
                self.assertEqual(env["HERMES_ZULIP_TOPICS"], "Staging")
                self.assertEqual(env["HERMES_ZULIP_TOPIC_POLICY"], "allowlist")
                self.assertEqual(env["HERMES_ZULIP_ALLOWED_SENDERS"], "id:17")
                self.assertEqual(env["HERMES_ZULIP_REQUIRE_MENTION"], "1")
                self.assertEqual(env["HERMES_ZULIP_IGNORE_CONTENT_PATTERNS"], "")
                self.assertEqual(env["HERMES_ZULIP_STEERING_REACTION"], "eyes")
                self.assertEqual(env["HERMES_ZULIP_HARD_INTERRUPT"], "1")
                self.assertEqual(env["HERMES_ZULIP_MAX_POLL_FAILURES"], "10")
                self.assertEqual(env["HERMES_ZULIP_RESPONSE_MAX_CHARS"], "8000")
                self.assertEqual(env["HERMES_ZULIP_SITE"], "https://zulip.example.com")
                self.assertEqual(env["HERMES_ZULIP_EMAIL"], "hermes-bot@example.com")
                self.assertEqual(env["HERMES_ZULIP_API_KEY"], "test-api-key")
                self.assertNotIn("HERMES_ZULIP_RC", env)
                self.assertEqual(list(Path(tmpdir).glob("*.zuliprc")), [])
        finally:
            os.environ.clear()
            os.environ.update(original)

    def test_validate_config_reports_missing_required_fields(self) -> None:
        issues = validate_config({"zulip": {"site": "https://example.zulip.com"}})
        self.assertIn("hermes.command is required", issues)
        self.assertIn("hermes.toolsets must contain at least one restricted Hermes toolset", issues)
        self.assertIn("zulip.bot_email or zulip.bot_email_env is required unless zulip.zuliprc is set", issues)
        self.assertIn("zulip.bot_api_key_env is required unless zulip.zuliprc is set", issues)
        self.assertIn("zulip.allowed_senders must contain at least one id:<user-id> or email:<address>", issues)
        self.assertIn("zulip.stream_id or zulip.stream_ids is required", issues)
        self.assertIn("zulip.topic_policy must be 'any' or 'allowlist'", issues)

    def test_security_policy_rejects_malformed_senders_streams_and_empty_topic_allowlist(self) -> None:
        base = {"hermes": secure_hermes(), "zulip": {"zuliprc": "/tmp/test.zuliprc"}}
        issues = validate_config(
            {
                **base,
                "zulip": {
                    **base["zulip"],
                    "allowed_senders": ["user@example.com", "id:0"],
                    "stream_ids": [0, "nope"],
                    "topic_policy": "allowlist",
                },
            }
        )
        self.assertIn("zulip.allowed_senders entries must use id:<user-id> or email:<address>", issues)
        self.assertIn("zulip.stream_id values must be positive integers", issues)
        self.assertIn("zulip.topic_allowlist is required when topic_policy is 'allowlist'", issues)

    def test_security_policy_requires_restricted_toolsets_and_blocks_argument_bypasses(self) -> None:
        base = {"zulip": secure_zulip(zuliprc="/tmp/test.zuliprc")}
        self.assertIn(
            "hermes.toolsets must contain at least one restricted Hermes toolset",
            validate_config({**base, "hermes": {"command": "/bin/true"}}),
        )
        self.assertIn(
            "hermes.toolsets contains an unsupported chat toolset",
            validate_config({**base, "hermes": secure_hermes(toolsets=["all"])}),
        )
        self.assertIn(
            "hermes.toolsets contains an unsupported chat toolset",
            validate_config({**base, "hermes": secure_hermes(toolsets=["hermes-cli"])}),
        )
        self.assertIn(
            "hermes.toolsets entries must contain only letters, numbers, underscores, or hyphens",
            validate_config({**base, "hermes": secure_hermes(toolsets=["coding,all"])}),
        )
        for extra_args in (["--yolo"], ["--yo"], ["-t", "all"], ["--toolsets=all"], ["--tools=all"]):
            with self.subTest(extra_args=extra_args):
                self.assertIn(
                    "hermes.extra_args is not allowed; use the explicit profile and toolsets fields",
                    validate_config({**base, "hermes": secure_hermes(extra_args=extra_args)}),
                )

    def test_notifier_direct_message_switch_requires_an_actual_boolean(self) -> None:
        base = {
            "hermes": secure_hermes(),
            "zulip": secure_zulip(zuliprc="/tmp/test.zuliprc"),
        }
        for value in ("false", "true", 0, 1, None):
            with self.subTest(value=value):
                config = {**base, "notifier": {"allow_direct_messages": value}}
                self.assertIn("notifier.allow_direct_messages must be a boolean", validate_config(config))
        disabled = {**base, "notifier": {"allow_direct_messages": False}}
        self.assertEqual(validate_config(disabled), [])
        self.assertEqual(bridge_config.apply_notifier_env(disabled)["HERMES_ZULIP_ALLOW_DMS"], "0")

    def test_notifier_exports_the_same_destination_and_sender_policy(self) -> None:
        config = {
            "hermes": secure_hermes(),
            "zulip": secure_zulip(zuliprc="/tmp/test.zuliprc"),
            "notifier": {
                "allow_direct_messages": True,
                "allowed_dm_recipients": ["id:42", "email:operator@example.com"],
            },
        }
        env = bridge_config.apply_notifier_env(config)
        self.assertEqual(env["HERMES_ZULIP_ALLOWED_SENDERS"], "id:17")
        self.assertEqual(env["HERMES_ZULIP_STREAM_IDS"], "7")
        self.assertEqual(env["HERMES_ZULIP_TOPIC_POLICY"], "any")
        self.assertEqual(env["HERMES_ZULIP_ALLOW_DMS"], "1")
        self.assertEqual(
            env["HERMES_ZULIP_ALLOWED_DM_RECIPIENTS"],
            "id:42,email:operator@example.com",
        )

    def test_poll_failure_limit_is_configurable_and_must_be_positive_integer(self) -> None:
        base = {
            "hermes": secure_hermes(),
            "zulip": secure_zulip(zuliprc="/tmp/test.zuliprc"),
        }
        for value in (0, -1, True, 1.5, "3"):
            with self.subTest(value=value):
                self.assertIn(
                    "bridge.poll_failure_limit must be a positive integer",
                    validate_config({**base, "bridge": {"poll_failure_limit": value}}),
                )
        config = {**base, "bridge": {"poll_failure_limit": 3}}
        self.assertEqual(validate_config(config), [])
        self.assertEqual(apply_bridge_env(config)["HERMES_ZULIP_MAX_POLL_FAILURES"], "3")

    def test_bridge_state_path_is_pure_and_matches_applied_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "not-created"
            config = {
                "instance_name": "My Bridge",
                "hermes": secure_hermes(),
                "zulip": secure_zulip(zuliprc="/tmp/test.zuliprc"),
                "bridge": {"state_directory": str(state_dir)},
            }

            calculated = bridge_state_path(config)

            self.assertEqual(calculated, state_dir / "my-bridge_zulip_bridge.json")
            self.assertFalse(state_dir.exists())
            self.assertEqual(apply_bridge_env(config)["HERMES_ZULIP_STATE"], str(calculated.resolve()))

    def test_auxiliary_defaults_rebase_to_held_state_and_custom_paths_resolve_independently(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first"
            second = root / "second"
            custom = root / "custom"
            first.mkdir()
            second.mkdir()
            custom.mkdir()
            current = root / "current"
            current.symlink_to(second, target_is_directory=True)
            custom_alias = root / "custom-current"
            custom_alias.symlink_to(custom, target_is_directory=True)
            base = {
                "instance_name": "bridge",
                "hermes": secure_hermes(),
                "zulip": secure_zulip(zuliprc="/tmp/test.zuliprc"),
                "bridge": {"state_directory": str(current)},
            }

            defaults = apply_bridge_env(base, state_path=first / "state.json")
            explicit = apply_bridge_env(
                {
                    **base,
                    "bridge": {
                        **base["bridge"],
                        "steering_sidecar_path": str(custom_alias / "steering.jsonl"),
                        "alias_manifest_path": str(custom_alias / "aliases.json"),
                    },
                },
                state_path=first / "state.json",
            )

            self.assertEqual(defaults["HERMES_ZULIP_STATE"], str((first / "state.json").resolve()))
            self.assertEqual(
                defaults["HERMES_ZULIP_STEERING"], str(first.resolve() / "bridge_zulip_steering.jsonl")
            )
            self.assertEqual(
                defaults["HERMES_ZULIP_ALIAS_MANIFEST"], str(first.resolve() / "bridge_zulip_aliases.json")
            )
            self.assertEqual(defaults["HERMES_ZULIP_STEERING_STATE_ASSOCIATED"], "1")
            self.assertEqual(explicit["HERMES_ZULIP_STEERING"], str(custom.resolve() / "steering.jsonl"))
            self.assertEqual(explicit["HERMES_ZULIP_ALIAS_MANIFEST"], str(custom.resolve() / "aliases.json"))
            self.assertEqual(explicit["HERMES_ZULIP_ALIASES_STATE_ASSOCIATED"], "0")

    def test_inline_credentials_do_not_touch_a_legacy_generated_path_under_umask_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(os.environ, {"TEST_ZULIP_KEY": "secret"}):
            state_dir = Path(tmpdir) / "state"
            state_dir.mkdir()
            sentinel = Path(tmpdir) / "sentinel"
            sentinel.write_text("untouched", encoding="utf-8")
            destination = state_dir / "safe-bridge.zuliprc"
            destination.symlink_to(sentinel)
            config = {
                "instance_name": "safe",
                "hermes": secure_hermes(),
                "zulip": secure_zulip(**{
                    "site": "https://zulip.example.com",
                    "bot_email": "bot@example.com",
                    "bot_api_key_env": "TEST_ZULIP_KEY",
                }),
                "bridge": {"state_directory": str(state_dir)},
            }

            old_umask = os.umask(0)
            try:
                env = apply_bridge_env(config)
            finally:
                os.umask(old_umask)

            self.assertTrue(destination.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertEqual(env["HERMES_ZULIP_API_KEY"], "secret")

    def test_all_configured_credential_source_names_are_exported_for_child_blocking(self) -> None:
        config = {
            "hermes": secure_hermes(env_allowlist=["REALM_URL", "BOT_LOGIN", "BOT_TOKEN"]),
            "zulip": secure_zulip(**{
                "site_env": "REALM_URL",
                "bot_email_env": "BOT_LOGIN",
                "bot_api_key_env": "BOT_TOKEN",
            }),
        }
        with mock.patch.dict(
            os.environ,
            {"REALM_URL": "https://zulip.example.com", "BOT_LOGIN": "bot@example.com", "BOT_TOKEN": "secret"},
            clear=False,
        ):
            env = apply_bridge_env(config)

        self.assertEqual(
            set(env["HERMES_ZULIP_SECRET_ENV_NAMES"].split(",")),
            {"REALM_URL", "BOT_LOGIN", "BOT_TOKEN"},
        )

    def test_bridge_bundle_rejects_every_canonical_sidecar_collision_without_creating_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "not-created"
            state = root / "state.json"
            public_lock, anchor, _guard = process_lock_bundle_paths(state)
            base = {
                "hermes": secure_hermes(),
                "zulip": {"zuliprc": "/tmp/test.zuliprc"},
                "bridge": {"state_path": str(state)},
            }
            cases = {
                "state": {"steering_path": str(state)},
                "signing key": {"steering_path": str(state) + ".signing-key"},
                "Zulip credentials": {"steering_path": "/tmp/test.zuliprc"},
                "Hermes state database": {"alias_manifest_path": str(root / "state.db")},
                "alias manifest": {
                    "steering_path": str(root / "same"),
                    "alias_manifest_path": str(root / "same"),
                },
                "public lock": {"steering_path": str(public_lock)},
                "lock anchor": {"steering_path": str(anchor)},
                "smoke steering": {
                    "state_path": str(root / "sidecar.smoke"),
                    "steering_path": str(root / "sidecar"),
                },
            }
            for label, paths in cases.items():
                config = {
                    **base,
                    "hermes": {**base["hermes"], "state_db": str(root / "state.db")},
                    "bridge": {**base["bridge"], **paths},
                }
                with self.subTest(label=label), self.assertRaisesRegex(ValueError, "must be disjoint"):
                    bridge_bundle_paths(config)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
