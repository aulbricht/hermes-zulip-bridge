from __future__ import annotations

import argparse
import json
import contextlib
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock

import hermes_zulip_bridge as package
from hermes_zulip_bridge import bridge, cli, smoke
from hermes_zulip_bridge.config import bridge_state_path
from hermes_zulip_bridge.locking import PROCESS_LOCK_FAILED, PROCESS_LOCK_UNAVAILABLE, process_lock


class CliLockTests(unittest.TestCase):
    def write_config(self, path: Path, config: dict) -> None:
        prepared = json.loads(json.dumps(config))
        zulip = prepared.setdefault("zulip", {})
        if isinstance(zulip, dict):
            zulip.setdefault("allowed_senders", ["id:17"])
            zulip.setdefault("stream_id", 7)
            zulip.setdefault("topic_policy", "any")
        path.write_text(json.dumps(prepared), encoding="utf-8")
        path.chmod(0o600)

    def trusted_venv_python(self, root: Path) -> Path:
        venv = root / ".fixture-venv"
        (venv / "bin").mkdir(parents=True, mode=0o700, exist_ok=True)
        config = venv / "pyvenv.cfg"
        if not config.exists():
            config.write_text("home = fixture\n", encoding="utf-8")
            config.chmod(0o600)
        interpreter = venv / "bin" / "python"
        if not interpreter.exists():
            interpreter.symlink_to(Path(sys.executable).resolve())
        return interpreter

    def write_python_console(self, path: Path) -> Path:
        path.write_text(f"#!{self.trusted_venv_python(path.parent)}\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_malformed_config_subprocess_output_is_fixed_and_private(self) -> None:
        hostile_path = "private-token\x1b[31m\nuser:pass@example.invalid"
        hostile_content = "https://user:pass@example.invalid/private\x00credential"
        src = Path(__file__).parents[1] / "src"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for suffix, content in (
                ("json", "{\n" + hostile_content),
                ("yaml", "secret: [\n" + hostile_content),
            ):
                path = root / f"hostile-{hostile_path}.{suffix}"
                path.write_text(content, encoding="utf-8")
                path.chmod(0o600)
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "hermes_zulip_bridge",
                        "--config",
                        str(path),
                        "validate-config",
                    ],
                    env={**os.environ, "PYTHONPATH": str(src)},
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                visible = completed.stdout + completed.stderr
                with self.subTest(suffix=suffix):
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(completed.stderr, cli.CONFIGURATION_INVALID + "\n")
                    self.assertNotIn(hostile_path, visible)
                    self.assertNotIn(hostile_content, visible)
                    self.assertNotIn(str(path), visible)
                    self.assertNotIn(str(src), visible)
                    self.assertNotIn(str(Path(sys.executable)), visible)
                    self.assertNotRegex(visible, r"https?://|Traceback|pass@example|\x1b|[\x00-\x08\x0b-\x1f\x7f]")

        with self.assertRaises(SystemExit) as raised:
            cli._config_call(lambda: (_ for _ in ()).throw(ValueError(hostile_content)))
        self.assertEqual(str(raised.exception), cli.CONFIGURATION_INVALID)
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)

    def test_in_process_locked_bridge_demo_and_smoke_dispatch_run_full_preflight(self) -> None:
        held = types.SimpleNamespace(state_path=Path("/tmp/generic-state.json"))

        @contextlib.contextmanager
        def lock(_path: Path):
            yield held

        removed = {
            name: sys.modules.pop(name)
            for name in ("hermes_zulip_bridge.bridge", "hermes_zulip_bridge.smoke")
            if name in sys.modules
        }
        try:
            common = (
                mock.patch.object(cli, "load_config", return_value={}),
                mock.patch.object(cli, "preflight_credentials", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}),
                mock.patch.object(cli, "_python_console_script", return_value=("/tmp/hermes.py", sys.executable)),
                mock.patch.object(cli, "bridge_state_path", return_value=held.state_path),
                mock.patch.object(cli, "bridge_bundle_paths"),
                mock.patch.object(cli, "process_lock", side_effect=lock),
                mock.patch.object(cli, "apply_bridge_env", return_value={}),
                mock.patch.object(bridge, "freeze_auxiliary_paths"),
                mock.patch.object(bridge, "load_json", return_value={"seen_ids": [], "topic_sessions": {}}),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "load_aliases", return_value={}),
                mock.patch.object(
                    bridge,
                    "load_rc",
                    return_value={"site": "https://example", "email": "bot@example.com", "key": "key"},
                ),
                mock.patch.object(bridge, "bind_state_realm"),
                mock.patch.object(bridge, "apply_alias_repairs"),
            )
            with contextlib.ExitStack() as stack:
                for patcher in common:
                    stack.enter_context(patcher)
                demo = stack.enter_context(mock.patch.object(bridge, "_demo"))
                self.assertEqual(cli.main(["bridge", "--demo"]), 0)
                demo.assert_called_once_with()

            result = {"ok": True, "checks": {}}
            with contextlib.ExitStack() as stack:
                for patcher in common:
                    stack.enter_context(patcher)
                stack.enter_context(mock.patch.object(smoke, "run", return_value=result))
                self.assertEqual(cli.main(["smoke-test", "--topic", "Topic"]), 0)
        finally:
            sys.modules.update(removed)

    def test_in_process_validate_notifier_and_kanban_dispatch(self) -> None:
        printed = mock.Mock()
        with mock.patch.object(cli, "load_config", return_value={}), mock.patch.object(
            cli, "validate_config", return_value=[]
        ), mock.patch("builtins.print", printed):
            self.assertEqual(cli.main(["validate-config"]), 0)
        self.assertTrue(json.loads(printed.call_args.args[0])["ok"])

        notifier = types.ModuleType("hermes_zulip_bridge.notifier")
        notifier.main = mock.Mock(return_value=7)
        notifier.RC_PATH = Path("unused")
        notifier.load_rc = mock.Mock()
        rc = {"site": "https://example", "email": "bot@example.com", "key": "key"}
        with mock.patch.object(cli, "load_config", return_value={}), mock.patch.object(
            cli, "preflight_credentials", return_value=rc
        ), mock.patch.object(
            cli, "apply_notifier_env", return_value={}
        ), mock.patch.dict(sys.modules, {"hermes_zulip_bridge.notifier": notifier}), mock.patch.object(
            package, "notifier", notifier, create=True
        ):
            self.assertEqual(cli.main(["notifier"]), 7)
        notifier.main.assert_called_once_with(rc=rc)

        kanban = types.ModuleType("hermes_zulip_bridge.kanban_task")
        kanban.main = mock.Mock(return_value=9)
        with mock.patch.object(cli, "load_config", return_value={}), mock.patch.object(
            cli, "apply_notifier_env", return_value={}
        ), mock.patch.dict(sys.modules, {"hermes_zulip_bridge.kanban_task": kanban}), mock.patch.object(
            package, "kanban_task", kanban, create=True
        ):
            self.assertEqual(cli.main(["kanban-task"]), 9)
        kanban.main.assert_called_once_with()

    def test_in_process_notifier_installs_inline_credentials_and_invalid_smoke_stops(self) -> None:
        notifier = types.ModuleType("hermes_zulip_bridge.notifier")
        notifier.main = mock.Mock(return_value=0)
        notifier.RC_PATH = Path("unused")
        notifier.load_rc = mock.Mock()
        env = {
            "HERMES_ZULIP_SITE": "https://example",
            "HERMES_ZULIP_EMAIL": "bot@example.com",
            "HERMES_ZULIP_API_KEY": "generic-test-key",
        }
        rc = {"site": "https://example", "email": "bot@example.com", "key": "generic-test-key"}
        with mock.patch.object(cli, "load_config", return_value={}), mock.patch.object(
            cli, "preflight_credentials", return_value=rc
        ), mock.patch.object(
            cli, "apply_notifier_env", return_value=env
        ), mock.patch.dict(sys.modules, {"hermes_zulip_bridge.notifier": notifier}), mock.patch.object(
            package, "notifier", notifier, create=True
        ):
            self.assertEqual(cli.main(["notifier"]), 0)
            self.assertEqual(notifier.load_rc(), {"site": "https://example", "email": "bot@example.com", "key": "generic-test-key"})

        with mock.patch.object(cli, "load_config", return_value={}), self.assertRaisesRegex(
            SystemExit, "--post-reply requires --run-hermes"
        ):
            cli.main(["smoke-test", "--topic", "Smoke", "--post-reply"])

    def test_smoke_run_hermes_validation_precedes_state_and_runtime_side_effects(self) -> None:
        with (
            mock.patch.object(cli, "bridge_state_path") as state_path,
            mock.patch.object(cli, "bridge_bundle_paths") as bundle,
            mock.patch.object(cli, "process_lock") as lock,
            mock.patch.object(cli, "apply_bridge_env") as apply_env,
            self.assertRaisesRegex(SystemExit, "--run-hermes requires --post-probe"),
        ):
            cli.main(["smoke-test", "--topic", "Smoke", "--run-hermes"])

        state_path.assert_not_called()
        bundle.assert_not_called()
        lock.assert_not_called()
        apply_env.assert_not_called()

        with (
            mock.patch.object(cli, "load_config", return_value={}),
            mock.patch.object(cli, "bridge_state_path") as state_path,
            self.assertRaisesRegex(SystemExit, "--human-origin-message-id"),
        ):
            cli.main(["smoke-test", "--topic", "Smoke", "--post-probe", "--run-hermes"])
        state_path.assert_not_called()

    def test_human_origin_raw_argv_validation_precedes_every_preflight_side_effect(self) -> None:
        flag = "--human-origin-message-id"
        invalid = (
            ["smoke-test", "--post-probe", "--run-hermes"],
            ["smoke-test", "--post-probe", "--run-hermes", flag],
            ["smoke-test", "--post-probe", "--run-hermes", flag, "0"],
            ["smoke-test", "--post-probe", "--run-hermes", flag, "-1"],
            ["smoke-test", "--post-probe", "--run-hermes", flag, "01"],
            ["smoke-test", "--post-probe", "--run-hermes", flag, "+1"],
            ["smoke-test", "--post-probe", "--run-hermes", flag, " 1"],
            ["smoke-test", "--post-probe", "--run-hermes", f"{flag}=abc"],
            ["smoke-test", "--post-probe", "--run-hermes", f"{flag}="],
            ["smoke-test", "--post-probe", "--run-hermes", f"{flag}={'9' * 65}"],
            ["smoke-test", "--post-probe", "--run-hermes", flag, "1", f"{flag}=2"],
            ["smoke-test", "--post-probe", "--run-hermes", flag, "--topic", "Smoke"],
            ["smoke-test", "--topic", "Smoke", flag, "0"],
            ["smoke-test", "--topic", "Smoke", "--unknown"],
            ["smoke-test", "--topic", "Smoke", "--topic", "Other"],
            ["smoke-test", "--topic", "Smoke", "--post-probe", "--post-probe"],
            ["smoke-test", "--topic", "Smoke", "--post-reply"],
            ["smoke-test", "--topic", "Smoke", "--run-hermes"],
            ["smoke-test", "--topic", "Smoke", "--post-probe", "--run-hermes"],
            ["smoke-test", "--stream"],
        )
        for argv in invalid:
            load_config = mock.Mock()
            state_path = mock.Mock()
            bundle = mock.Mock()
            lock = mock.Mock()
            apply_env = mock.Mock()
            with (
                self.subTest(argv=argv),
                mock.patch.object(cli, "load_config", load_config),
                mock.patch.object(cli, "preflight_credentials", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}),
                mock.patch.object(cli, "_python_console_script", return_value=("/tmp/hermes.py", sys.executable)),
                mock.patch.object(cli, "bridge_state_path", state_path),
                mock.patch.object(cli, "bridge_bundle_paths", bundle),
                mock.patch.object(cli, "process_lock", lock),
                mock.patch.object(cli, "apply_bridge_env", apply_env),
                self.assertRaises(SystemExit),
            ):
                cli.main(argv)
            for side_effect in (load_config, state_path, bundle, lock, apply_env):
                side_effect.assert_not_called()

    def test_human_origin_raw_argv_accepts_both_canonical_forms_then_runs_preflight(self) -> None:
        forms = (["--human-origin-message-id", "1"], ["--human-origin-message-id=999"])
        for form in forms:
            load_config = mock.Mock(return_value={})
            state_path = mock.Mock(return_value=Path("/tmp/generic-state.json"))
            bundle = mock.Mock()
            with (
                self.subTest(form=form),
                mock.patch.object(cli, "load_config", load_config),
                mock.patch.object(cli, "preflight_credentials", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}),
                mock.patch.object(
                    cli,
                    "_python_console_script",
                    return_value=("/tmp/hermes.py", sys.executable),
                ),
                mock.patch.object(cli, "bridge_state_path", state_path),
                mock.patch.object(cli, "bridge_bundle_paths", bundle),
                self.assertRaisesRegex(SystemExit, PROCESS_LOCK_FAILED),
            ):
                cli.main(["smoke-test", "--topic", "Smoke", "--post-probe", "--run-hermes", *form])
            load_config.assert_called_once_with(None)
            state_path.assert_called_once_with({})
            bundle.assert_called_once_with({}, state_path=Path("/tmp/generic-state.json"))

    def test_documented_smoke_command_parses_with_human_origin_placeholder_filled(self) -> None:
        readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
        matched = re.search(r"```bash\n(hermes-zulip-bridge .*?--human-origin-message-id <ID> .*?)\n```", readme, re.S)
        self.assertIsNotNone(matched)
        command = matched.group(1).replace("\\\n", " ").replace("<ID>", "456")
        argv = shlex.split(command)
        smoke_args = cli.parse_smoke_args(argv[argv.index("smoke-test") + 1 :])
        self.assertEqual(smoke_args.human_origin_message_id, "456")
        self.assertTrue(smoke_args.run_hermes)
        self.assertTrue(smoke_args.post_reply)

    def test_smoke_parser_runs_once_before_config_and_valid_path_preflights(self) -> None:
        events: list[str] = []
        parse = cli.parse_smoke_args

        def parse_once(values: list[str]) -> argparse.Namespace:
            events.append("parse")
            return parse(values)

        def load(_path: str | None) -> dict:
            events.append("config")
            return {}

        def credentials(_config: dict) -> dict[str, str]:
            events.append("credentials")
            return {"site": "https://example", "email": "bot@example.com", "key": "key"}

        def state_path(_config: dict) -> Path:
            events.append("state")
            return Path("/tmp/generic-state.json")

        def launcher(command: str) -> tuple[str, str]:
            events.append("launcher")
            self.assertEqual(command, "hermes")
            return "/tmp/hermes.py", sys.executable

        def bundle(_config: dict, *, state_path: Path) -> None:
            events.append("bundle")

        with (
            mock.patch.object(cli, "parse_smoke_args", side_effect=parse_once) as parsed,
            mock.patch.object(cli, "load_config", side_effect=load),
            mock.patch.object(cli, "preflight_credentials", side_effect=credentials),
            mock.patch.object(cli, "_python_console_script", side_effect=launcher),
            mock.patch.object(cli, "bridge_state_path", side_effect=state_path),
            mock.patch.object(cli, "bridge_bundle_paths", side_effect=bundle),
            self.assertRaisesRegex(SystemExit, PROCESS_LOCK_FAILED),
        ):
            cli.main(["smoke-test", "--topic", "Smoke", "--post-probe"])

        parsed.assert_called_once_with(["--topic", "Smoke", "--post-probe"])
        self.assertEqual(events, ["parse", "config", "credentials", "launcher", "state", "bundle"])

    def test_packaged_bridge_and_smoke_invalid_hermes_win_before_every_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            state_path = state_dir / "inline_zulip_bridge.json"
            corrupt = b'{"topic_sessions": []}\n'
            state_path.write_bytes(corrupt)
            valid = root / "valid-hermes"
            valid.write_text(f"#!{self.trusted_venv_python(root)}\n", encoding="utf-8")
            valid.chmod(0o700)
            directory = root / "directory"
            directory.mkdir()
            symlink = root / "symlink"
            symlink.symlink_to(valid)
            nonexec = root / "nonexec"
            nonexec.write_text(f"#!{self.trusted_venv_python(root)}\n", encoding="utf-8")
            nonexec.chmod(0o600)
            bad_shebang = root / "bad-shebang"
            bad_shebang.write_text("#!/bin/sh\n", encoding="utf-8")
            bad_shebang.chmod(0o700)
            fake_modules = root / "fake-modules"
            fake_modules.mkdir()
            api_marker = root / "api-created"
            (fake_modules / "zulip.py").write_text(
                "import os\nfrom pathlib import Path\n"
                "Path(os.environ['API_MARKER']).touch()\n"
                "class Client: pass\n",
                encoding="utf-8",
            )
            src = Path(__file__).parents[1] / "src"
            env = {
                key: value
                for key, value in os.environ.items()
                if key != "MISSING_SMOKE_CREDENTIAL"
            }
            env.update(
                {
                    "PYTHONPATH": os.pathsep.join((str(fake_modules), str(src))),
                    "API_MARKER": str(api_marker),
                }
            )

            for label, command in {
                "directory": directory,
                "symlink": symlink,
                "nonexec": nonexec,
                "bad shebang": bad_shebang,
            }.items():
                config = {
                    "instance_name": "inline",
                    "hermes": {"command": str(command)},
                    "zulip": {
                        "site": "https://zulip.example.com",
                        "bot_email": "bot@example.com",
                        "bot_api_key_env": "MISSING_SMOKE_CREDENTIAL",
                    },
                    "bridge": {"state_directory": str(state_dir)},
                }
                config_path = root / f"{label.replace(' ', '-')}.json"
                self.write_config(config_path, config)
                for mode in ("bridge", "smoke-test"):
                    command_args = [mode, "--topic", "Smoke"] if mode == "smoke-test" else [mode]
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "hermes_zulip_bridge",
                            "-c",
                            str(config_path),
                            *command_args,
                        ],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    with self.subTest(label=label, mode=mode):
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn(cli.CONFIGURATION_INVALID, completed.stderr)
                        self.assertNotIn("MISSING_SMOKE_CREDENTIAL", completed.stdout + completed.stderr)
                        self.assertEqual(state_path.read_bytes(), corrupt)
                        self.assertFalse((state_dir / ".hermes-zulip-locks").exists())
                        self.assertFalse(api_marker.exists())

    def test_launcher_proof_rejects_identity_mode_symlink_and_path_changes_without_fd_leaks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            default_interpreter = self.trusted_venv_python(root)

            def script(name: str, interpreter: Path = default_interpreter) -> Path:
                path = root / name
                path.write_text(f"#!{interpreter}\n", encoding="utf-8")
                path.chmod(0o700)
                return path

            valid = script("valid")
            proof = cli._python_console_script(str(valid))
            self.assertIsInstance(proof, cli.LauncherProof)
            self.assertEqual(tuple(proof), (str(valid.resolve()), str(Path(sys.executable).resolve())))
            self.assertEqual(Path(proof.pin_directory), default_interpreter.parent.resolve())
            with self.assertRaises(FrozenInstanceError):
                proof.command_path = "changed"

            replaced = script("replaced")
            replaced_proof = cli._python_console_script(str(replaced))
            replacement = script("replacement")
            os.replace(replacement, replaced)
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                cli._verify_launcher_proof(replaced_proof)

            changed_mode = script("changed-mode")
            changed_mode_proof = cli._python_console_script(str(changed_mode))
            changed_mode.chmod(0o720)
            with self.assertRaisesRegex(RuntimeError, "unsafe|identity changed"):
                cli._verify_launcher_proof(changed_mode_proof)

            interpreter_a = root / "python-a"
            interpreter_b = root / "python-b"
            shutil.copy2(Path(sys.executable).resolve(), interpreter_a)
            shutil.copy2(Path(sys.executable).resolve(), interpreter_b)
            interpreter_a.chmod(0o700)
            interpreter_b.chmod(0o700)
            interpreter_link = default_interpreter.parent / "python-current"
            interpreter_link.symlink_to(interpreter_a)
            linked_script = script("linked-interpreter", interpreter_link)
            linked_proof = cli._python_console_script(str(linked_script))
            interpreter_link.unlink()
            interpreter_link.symlink_to(interpreter_b)
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                cli._verify_launcher_proof(linked_proof)

            mode_link = default_interpreter.parent / "python-mode"
            mode_link.symlink_to(interpreter_a)
            interpreter_script = script("interpreter-mode", mode_link)
            interpreter_proof = cli._python_console_script(str(interpreter_script))
            interpreter_a.chmod(0o722)
            with self.assertRaisesRegex(RuntimeError, "unsafe|identity changed"):
                cli._verify_launcher_proof(interpreter_proof)

            hostile_parent = root / "hostile"
            hostile_parent.mkdir()
            hostile_parent.chmod(0o777)
            hostile = hostile_parent / "hermes"
            hostile.write_text(f"#!{default_interpreter}\n", encoding="utf-8")
            hostile.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                cli._python_console_script(str(hostile))

            group_parent = root / "owner-group-writable"
            group_parent.mkdir()
            group_parent.chmod(0o770)
            group_script = group_parent / "hermes"
            group_script.write_text(f"#!{default_interpreter}\n", encoding="utf-8")
            group_script.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                cli._python_console_script(str(group_script))

            default_interpreter.parent.chmod(0o770)
            with self.assertRaisesRegex(RuntimeError, "console script|virtual environment"):
                cli._python_console_script(str(valid))
            default_interpreter.parent.chmod(0o700)

            group_file = script("group-file")
            group_file.chmod(0o720)
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                cli._python_console_script(str(group_file))

            source_parent = root / "opt" / "Cellar"
            source_parent.mkdir(parents=True)
            source_parent.chmod(0o775)
            source = source_parent / "python"
            shutil.copy2(Path(sys.executable).resolve(), source)
            source.chmod(0o700)
            package_venv = root / "package-venv"
            (package_venv / "bin").mkdir(parents=True, mode=0o700)
            (package_venv / "pyvenv.cfg").write_text("home = fixture\n", encoding="utf-8")
            (package_venv / "pyvenv.cfg").chmod(0o600)
            package_python = package_venv / "bin" / "python"
            package_python.symlink_to(source)
            package_script = script("package-source", package_python)
            package_proof = cli._python_console_script(str(package_script))
            before = set(os.listdir("/dev/fd"))
            for _ in range(50):
                cli._verify_launcher_proof(package_proof)
            self.assertEqual(set(os.listdir("/dev/fd")), before)
            replacement_source = source_parent / "replacement"
            shutil.copy2(Path(sys.executable).resolve(), replacement_source)
            replacement_source.chmod(0o700)
            os.replace(replacement_source, source)
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                cli._verify_launcher_proof(package_proof)

    def test_interpreter_pin_error_paths_fail_closed_and_preserve_unsafe_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            with self.assertRaisesRegex(RuntimeError, "virtual environment"):
                cli._trusted_venv_bin(root / "missing" / "bin" / "python")

            scripts = root / "venv" / "Scripts"
            scripts.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "virtual environment"):
                cli._trusted_venv_bin(scripts / "python")

            missing_config_bin = root / "missing-config" / "bin"
            missing_config_bin.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "virtual environment"):
                cli._trusted_venv_bin(missing_config_bin / "python")

            unsafe_venv = root / "unsafe-venv"
            (unsafe_venv / "bin").mkdir(parents=True)
            unsafe_config = unsafe_venv / "pyvenv.cfg"
            unsafe_config.write_text("home = fixture\n", encoding="utf-8")
            unsafe_config.chmod(0o620)
            with self.assertRaisesRegex(RuntimeError, "virtual environment"):
                cli._trusted_venv_bin(unsafe_venv / "bin" / "python")

            with mock.patch.object(cli.os, "kill", side_effect=PermissionError):
                self.assertTrue(cli._process_exists(999999))
            self.assertFalse(cli._safe_pin_identity(root / "ordinary"))
            missing_pin = root / ".hermes-python-pin-999999999-33333333333333333333333333333333"
            self.assertFalse(cli._safe_pin_identity(missing_pin))

            interpreter = self.trusted_venv_python(root)
            script = root / "hermes"
            script.write_text(f"#!{interpreter}\n", encoding="utf-8")
            script.chmod(0o700)
            proof = cli._python_console_script(str(script))
            script_fd, source_fd = cli._open_launcher_proof(proof)
            try:
                with self.assertRaisesRegex(RuntimeError, "pin location changed"):
                    cli._pin_interpreter(replace(proof, pin_directory=str(root)), source_fd)

                with mock.patch.object(cli.os, "write", return_value=0), self.assertRaisesRegex(
                    OSError, "no progress"
                ):
                    cli._pin_interpreter(proof, source_fd)
                self.assertEqual(list(Path(proof.pin_directory).glob(".hermes-python-pin-*")), [])

                original_open = cli._open_launcher_file

                def wrong_digest(path: Path, **kwargs: object):
                    fd, pinned = original_open(path, **kwargs)
                    return fd, replace(pinned, digest="0" * 64)

                with mock.patch.object(cli, "_open_launcher_file", side_effect=wrong_digest), self.assertRaisesRegex(
                    RuntimeError, "pin verification"
                ):
                    cli._pin_interpreter(proof, source_fd)
                self.assertEqual(list(Path(proof.pin_directory).glob(".hermes-python-pin-*")), [])
            finally:
                os.close(script_fd)
                os.close(source_fd)

            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                cli._open_launcher_proof(replace(proof, pin_directory=str(root)))

            removable = Path(proof.pin_directory) / ".hermes-python-pin-999999999-44444444444444444444444444444444"
            removable.write_bytes(b"pin")
            removable.chmod(0o500)
            with mock.patch.object(Path, "unlink", side_effect=OSError):
                cli._remove_interpreter_pin(removable)
            self.assertTrue(removable.exists())
            removable.unlink()
            with mock.patch.object(Path, "iterdir", side_effect=OSError):
                cli._remove_stale_interpreter_pins(Path(proof.pin_directory))

    def test_argparse_rejects_abbreviations_before_config_and_preserves_full_help(self) -> None:
        invalid = (
            ["smoke-test", "--top", "Smoke"],
            ["smoke-test", "--top=Smoke"],
            ["smoke-test", "--topic", "Smoke", "--post-p"],
            ["smoke-test", "--post-p=true", "--topic", "Smoke"],
            ["smoke-test", "--top", "Smoke", "--topic", "Other"],
            ["--ver"],
        )
        for argv in invalid:
            load = mock.Mock()
            with (
                self.subTest(argv=argv),
                mock.patch.object(cli, "load_config", load),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                cli.main(argv)
            load.assert_not_called()

        for argv in (["--version"], ["--help"], ["smoke-test", "--help"]):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main(argv)
            self.assertEqual(raised.exception.code, 0)

    def test_packaged_smoke_passes_exact_validated_launcher_after_config(self) -> None:
        held = types.SimpleNamespace(state_path=Path("/tmp/generic-state.json"))
        launcher = ("/resolved/hermes", "/resolved/python")
        events: list[str] = []

        @contextlib.contextmanager
        def lock(_path: Path):
            events.append("lock")
            yield held

        def validate(command: str) -> tuple[str, str]:
            events.append(f"launcher:{command}")
            return launcher

        removed = {
            name: sys.modules.pop(name)
            for name in ("hermes_zulip_bridge.bridge", "hermes_zulip_bridge.smoke")
            if name in sys.modules
        }
        try:
            with (
                mock.patch.object(cli, "load_config", side_effect=lambda _path: events.append("config") or {"hermes": {"command": "/configured/hermes"}}),
                mock.patch.object(cli, "preflight_credentials", side_effect=lambda _config: events.append("credentials") or {"site": "https://example", "email": "bot@example.com", "key": "key"}),
                mock.patch.object(cli, "_python_console_script", side_effect=validate) as validated,
                mock.patch.object(cli, "bridge_state_path", return_value=held.state_path),
                mock.patch.object(cli, "bridge_bundle_paths"),
                mock.patch.object(cli, "process_lock", side_effect=lock),
                mock.patch.object(cli, "apply_bridge_env", return_value={}),
                mock.patch.object(bridge, "freeze_auxiliary_paths"),
                mock.patch.object(bridge, "load_json", return_value={"seen_ids": [], "topic_sessions": {}}),
                mock.patch.object(bridge, "load_alias_entries", return_value=[]),
                mock.patch.object(bridge, "load_aliases", return_value={}),
                mock.patch.object(bridge, "load_rc", return_value={"site": "https://example"}),
                mock.patch.object(bridge, "bind_state_realm"),
                mock.patch.object(bridge, "apply_alias_repairs"),
                mock.patch.object(smoke, "run", return_value={"ok": True, "checks": {}}) as run,
            ):
                self.assertEqual(cli.main(["smoke-test", "--topic", "Smoke"]), 0)
            validated.assert_called_once_with("/configured/hermes")
            run.assert_called_once()
            self.assertIs(run.call_args.kwargs["hermes_launcher"], launcher)
            self.assertEqual(events[:4], ["config", "credentials", "launcher:/configured/hermes", "lock"])
        finally:
            sys.modules.update(removed)

    def test_packaged_bridge_valid_launcher_reaches_running_daemon_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            hermes_marker = root / "hermes-executed"
            hermes = root / "hermes"
            hermes.write_text(
                f"#!{self.trusted_venv_python(root)}\nfrom pathlib import Path\nPath({str(hermes_marker)!r}).touch()\n",
                encoding="utf-8",
            )
            hermes.chmod(0o700)
            api_log = root / "api.log"
            fake_modules = root / "fake-modules"
            fake_modules.mkdir()
            (fake_modules / "zulip.py").write_text(
                "import os\nfrom pathlib import Path\n"
                "class Client:\n"
                "    def __init__(self, **kwargs): self.retry_on_errors=kwargs['retry_on_errors']; self.session=type('Session',(),{'hooks':{}})()\n"
                "    def ensure_session(self): pass\n"
                "    def call_endpoint(self, **kwargs):\n"
                "        with Path(os.environ['API_LOG']).open('a') as handle: handle.write(kwargs['url']+'\\n')\n"
                "        return {'result':'success','msg':'','ignored_parameters_unsupported':[],'messages':[]}\n",
                encoding="utf-8",
            )
            config = {
                "instance_name": "inline",
                "hermes": {"command": str(hermes), "working_directory": str(root)},
                "zulip": {
                    "site": "https://zulip.example.com",
                    "bot_email": "bot@example.com",
                    "bot_api_key_env": "INLINE_ZULIP_KEY",
                    "stream": "hermes",
                },
                "bridge": {"state_directory": str(state_dir), "poll_interval": 0.01},
            }
            config_path = root / "config.json"
            self.write_config(config_path, config)
            src = Path(__file__).parents[1] / "src"
            proc = subprocess.Popen(
                [sys.executable, "-m", "hermes_zulip_bridge", "-c", str(config_path), "bridge"],
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join((str(fake_modules), str(src))),
                    "INLINE_ZULIP_KEY": "generic-test-key",
                    "API_LOG": str(api_log),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if api_log.exists() and len(api_log.read_text(encoding="utf-8").splitlines()) >= 2:
                        break
                    if proc.poll() is not None:
                        break
                    time.sleep(0.01)
                self.assertIsNone(proc.poll())
                self.assertGreaterEqual(len(api_log.read_text(encoding="utf-8").splitlines()), 2)
                proc.terminate()
                stdout, stderr = proc.communicate(timeout=5)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=5)

            self.assertEqual(proc.returncode, 0, stderr)
            self.assertIn("bridge_start", stdout)
            self.assertFalse(hermes_marker.exists())

    def test_packaged_runtime_fatal_exits_nonzero_after_releasing_process_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            hermes_marker = root / "hermes-executed"
            hermes = root / "hermes"
            hermes.write_text(
                f"#!{self.trusted_venv_python(root)}\nfrom pathlib import Path\nPath({str(hermes_marker)!r}).touch()\n",
                encoding="utf-8",
            )
            hermes.chmod(0o700)
            api_log = root / "api.log"
            fake_modules = root / "fake-modules"
            fake_modules.mkdir()
            (fake_modules / "zulip.py").write_text(
                "import os\nfrom pathlib import Path\n"
                "class Client:\n"
                "    def __init__(self, **kwargs): self.retry_on_errors=kwargs['retry_on_errors']; self.calls=0; self.session=type('Session',(),{'hooks':{}})()\n"
                "    def ensure_session(self): pass\n"
                "    def call_endpoint(self, **kwargs):\n"
                "        self.calls += 1\n"
                "        with Path(os.environ['API_LOG']).open('a') as handle: handle.write(kwargs['url']+'\\n')\n"
                "        if self.calls == 1: return {'result':'success','msg':'','ignored_parameters_unsupported':[],'messages':[]}\n"
                "        return {'result':'error','msg':'busy','status_code':503}\n",
                encoding="utf-8",
            )
            config = {
                "instance_name": "inline",
                "hermes": {"command": str(hermes), "working_directory": str(root)},
                "zulip": {
                    "site": "https://zulip.example.com",
                    "bot_email": "bot@example.com",
                    "bot_api_key_env": "INLINE_ZULIP_KEY",
                    "stream": "hermes",
                },
                "bridge": {"state_directory": str(state_dir), "poll_interval": 0, "poll_failure_limit": 1},
            }
            config_path = root / "config.json"
            self.write_config(config_path, config)
            src = Path(__file__).parents[1] / "src"
            completed = subprocess.run(
                [sys.executable, "-m", "hermes_zulip_bridge", "-c", str(config_path), "bridge"],
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join((str(fake_modules), str(src))),
                    "INLINE_ZULIP_KEY": "generic-test-key",
                    "API_LOG": str(api_log),
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(api_log.read_text(encoding="utf-8").splitlines(), ["messages", "messages"])
            self.assertFalse(hermes_marker.exists())
            with process_lock(bridge_state_path(config)):
                pass

    def test_top_level_and_smoke_help_and_version_need_no_config(self) -> None:
        for argv in (["--help"], ["--version"], ["smoke-test", "--help"]):
            load = mock.Mock()
            with (
                self.subTest(argv=argv),
                mock.patch.object(cli, "load_config", load),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                cli.main(argv)
            self.assertEqual(raised.exception.code, 0)
            load.assert_not_called()

    def test_cli_preflight_stays_on_held_canonical_state_after_parent_retarget(self) -> None:
        script = """
import contextlib
import sys
from pathlib import Path
from hermes_zulip_bridge import cli

real_lock = cli.process_lock
alias = Path(sys.argv[2])
replacement = Path(sys.argv[3])

@contextlib.contextmanager
def retargeting_lock(path):
    with real_lock(path) as held:
        alias.unlink()
        alias.symlink_to(replacement, target_is_directory=True)
        yield held

cli.process_lock = retargeting_lock
raise SystemExit(cli.main(["-c", sys.argv[1], "bridge", "--demo"]))
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            alias = root / "current"
            alias.symlink_to(first, target_is_directory=True)
            good = b'{"seen_ids":[7],"topic_sessions":{}}\n'
            bad = b'[]\n'
            (first / "state.json").write_bytes(good)
            (second / "state.json").write_bytes(bad)
            (first / "hermes_zulip_aliases.json").write_text('{"aliases": []}', encoding="utf-8")
            (second / "hermes_zulip_aliases.json").write_text('{"aliases": [', encoding="utf-8")
            (first / "hermes_zulip_aliases.json").chmod(0o600)
            (second / "hermes_zulip_aliases.json").chmod(0o600)
            config = {
                "hermes": {"command": "/bin/true"},
                "zulip": {
                    "site": "https://zulip.example.com",
                    "bot_email": "bot@example.com",
                    "bot_api_key_env": "INLINE_ZULIP_KEY",
                },
                "bridge": {"state_directory": str(alias), "state_path": str(alias / "state.json")},
            }
            config_path = root / "config.json"
            self.write_config(config_path, config)
            completed = subprocess.run(
                [sys.executable, "-c", script, str(config_path), str(alias), str(second)],
                env={
                    **os.environ,
                    "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
                    "INLINE_ZULIP_KEY": "secret",
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual((first / "state.json").read_bytes(), good)
            self.assertEqual((second / "state.json").read_bytes(), bad)

    def test_same_path_preimport_rejects_before_runtime_environment_or_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            hermes = self.write_python_console(Path(tmpdir) / "hermes")
            config = {
                "hermes": {"command": str(hermes)},
                "zulip": {
                    "site": "https://new.example.com",
                    "bot_email": "new@example.com",
                    "bot_api_key_env": "BOT_TOKEN",
                },
                "bridge": {"state_path": str(bridge.STATE_PATH)},
            }
            config_path = Path(tmpdir) / "config.json"
            self.write_config(config_path, config)
            canaries = {
                "BOT_TOKEN": "old-token",
                "REALM_URL": "https://old.example.com",
                "BOT_LOGIN": "old@example.com",
            }
            apply_env = mock.Mock(side_effect=AssertionError("runtime environment mutated"))
            load_rc = mock.Mock(side_effect=AssertionError("credentials loaded"))
            save = mock.Mock(side_effect=AssertionError("state mutated"))

            with (
                mock.patch.dict(os.environ, canaries, clear=False),
                mock.patch.object(cli, "apply_bridge_env", apply_env),
                mock.patch.object(bridge, "load_rc", load_rc),
                mock.patch.object(bridge, "save_json", save),
            ):
                with self.assertRaisesRegex(SystemExit, PROCESS_LOCK_FAILED):
                    cli.main(["-c", str(config_path), "bridge"])
                self.assertEqual({name: os.environ.get(name) for name in canaries}, canaries)

            apply_env.assert_not_called()
            load_rc.assert_not_called()
            save.assert_not_called()

    def test_programmatic_cli_rejects_preimported_bridge_with_stale_state_before_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state"
            hermes = self.write_python_console(Path(tmpdir) / "hermes")
            config = {
                "hermes": {"command": str(hermes)},
                "zulip": {"zuliprc": str(Path(tmpdir) / "zuliprc")},
                "bridge": {"state_directory": str(state_dir)},
            }
            config_path = Path(tmpdir) / "config.json"
            self.write_config(config_path, config)

            with (
                mock.patch.object(cli, "preflight_credentials", return_value={"site": "https://example", "email": "bot@example.com", "key": "key"}),
                mock.patch.object(cli, "process_lock") as acquire,
                mock.patch.object(bridge, "_main") as run_bridge,
                self.assertRaisesRegex(SystemExit, PROCESS_LOCK_FAILED),
            ):
                cli.main(["-c", str(config_path), "bridge"])

            acquire.assert_not_called()
            run_bridge.assert_not_called()
            self.assertFalse(state_dir.exists())

    def test_packaged_bridge_and_smoke_lock_before_inline_credentials_create_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_dir = root / "state"
            state_dir.mkdir()
            state_dir.chmod(0o700)
            hermes_marker = root / "hermes-called"
            api_marker = root / "api-called"
            hermes = root / "hermes"
            hermes.write_text(
                f"#!{self.trusted_venv_python(root)}\nfrom pathlib import Path\nPath({str(hermes_marker)!r}).touch()\n",
                encoding="utf-8",
            )
            hermes.chmod(0o700)
            fake_modules = root / "fake-modules"
            fake_modules.mkdir()
            (fake_modules / "zulip.py").write_text(
                "import os\nfrom pathlib import Path\n"
                "class Client:\n"
                "    def __init__(self, **kwargs): pass\n"
                "    def call_endpoint(self, **kwargs):\n"
                "        Path(os.environ['API_MARKER']).write_text('called')\n"
                "        return {'result': 'success', 'msg': ''}\n",
                encoding="utf-8",
            )
            config = {
                "instance_name": "inline",
                "hermes": {"command": str(hermes), "working_directory": str(root)},
                "zulip": {
                    "site": "https://zulip.example.com",
                    "bot_email": "bot@example.com",
                    "bot_api_key_env": "INLINE_ZULIP_KEY",
                    "stream": "hermes",
                },
                "bridge": {"state_directory": str(state_dir)},
            }
            config_path = root / "config.json"
            self.write_config(config_path, config)
            state_path = bridge_state_path(config)
            src = Path(__file__).parents[1] / "src"
            env = {
                **os.environ,
                "PYTHONPATH": os.pathsep.join((str(fake_modules), str(src))),
                "INLINE_ZULIP_KEY": "inline-secret",
                "API_MARKER": str(api_marker),
            }

            with process_lock(state_path):
                for command in (
                    ["bridge"],
                    [
                        "smoke-test",
                        "--topic",
                        "Smoke",
                        "--post-probe",
                        "--run-hermes",
                        "--human-origin-message-id",
                        "456",
                        "--post-reply",
                    ],
                ):
                    with self.subTest(command=command[0]):
                        completed = subprocess.run(
                            [sys.executable, "-m", "hermes_zulip_bridge", "-c", str(config_path), *command],
                            env=env,
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn(PROCESS_LOCK_UNAVAILABLE, completed.stderr)

            self.assertFalse((state_dir / "inline-bridge.zuliprc").exists())
            self.assertFalse(state_path.exists())
            self.assertFalse((state_dir / "inline_zulip_steering.jsonl").exists())
            self.assertFalse((state_dir / "inline_zulip_aliases.json").exists())
            self.assertFalse(hermes_marker.exists())
            self.assertFalse(api_marker.exists())

    def test_packaged_smoke_rejects_malformed_success_envelopes_at_each_preflight_boundary(self) -> None:
        fake_zulip = """
import json
import os
from pathlib import Path
class Client:
    def __init__(self, **kwargs):
        self.retry_on_errors = kwargs['retry_on_errors']
        self.session = type('Session', (), {'hooks': {}})()
    def ensure_session(self): pass
    def call_endpoint(self, **kwargs):
        url = kwargs['url']
        with Path(os.environ['API_LOG']).open('a') as handle:
            handle.write(url + '\\n')
        stage = os.environ['MALFORMED_STAGE']
        if url == 'users/me':
            return {'result': 'success', 'msg': 'bad'} if stage == 'auth' else {'result': 'success', 'msg': '', 'email': 'bot@example.com'}
        if url == 'streams':
            return {'result': 'success'} if stage == 'stream' else {'result': 'success', 'msg': '', 'streams': [{'name': 'hermes', 'stream_id': 7}]}
        if url == 'messages' and kwargs['method'] == 'POST':
            return {'result': 'success', 'msg': None}
        raise AssertionError((url, kwargs['method']))
"""
        expected_calls = {
            "auth": ["users/me"],
            "stream": ["users/me", "streams"],
            "probe": ["users/me", "streams", "messages"],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fake_modules = root / "fake-modules"
            fake_modules.mkdir()
            (fake_modules / "zulip.py").write_text(fake_zulip, encoding="utf-8")
            src = Path(__file__).parents[1] / "src"
            for stage, expected in expected_calls.items():
                stage_root = root / stage
                stage_root.mkdir()
                state_dir = stage_root / "state"
                state_dir.mkdir(mode=0o700)
                state_path = state_dir / "inline_zulip_bridge.json"
                original_state = b'{"seen_ids": [99], "topic_sessions": {}}\n'
                state_path.write_bytes(original_state)
                hermes_marker = stage_root / "hermes-called"
                hermes = stage_root / "hermes"
                hermes.write_text(
                    f"#!{self.trusted_venv_python(stage_root)}\nfrom pathlib import Path\nPath({str(hermes_marker)!r}).touch()\n",
                    encoding="utf-8",
                )
                hermes.chmod(0o700)
                api_log = stage_root / "api.log"
                config = {
                    "instance_name": "inline",
                    "hermes": {"command": str(hermes), "working_directory": str(stage_root)},
                    "zulip": {
                        "site": "https://zulip.example.com",
                        "bot_email": "bot@example.com",
                        "bot_api_key_env": "INLINE_ZULIP_KEY",
                        "stream": "hermes",
                    },
                    "bridge": {"state_directory": str(state_dir)},
                }
                config_path = stage_root / "config.json"
                self.write_config(config_path, config)
                env = {
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join((str(fake_modules), str(src))),
                    "INLINE_ZULIP_KEY": "canary-secret",
                    "MALFORMED_STAGE": stage,
                    "API_LOG": str(api_log),
                }

                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "hermes_zulip_bridge",
                        "-c",
                        str(config_path),
                        "smoke-test",
                        "--topic",
                        "Smoke",
                        "--post-probe",
                        "--run-hermes",
                        "--human-origin-message-id",
                        "456",
                        "--post-reply",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                with self.subTest(stage=stage):
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("Smoke test failed (RuntimeError)", completed.stderr)
                    self.assertNotIn("canary-secret", completed.stdout + completed.stderr)
                    self.assertEqual(api_log.read_text(encoding="utf-8").splitlines(), expected)
                    self.assertEqual(state_path.read_bytes(), original_state)
                    self.assertFalse(hermes_marker.exists())
                    self.assertFalse((state_dir / "inline_zulip_steering.jsonl").exists())

    def test_packaged_corrupt_state_does_not_create_or_modify_credential_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            state_path = state_dir / "inline_zulip_bridge.json"
            corrupt = b'{"realm":"zulip.example.com","seen_ids":[],"topic_sessions":[]}\n'
            state_path.write_bytes(corrupt)
            legacy_credentials = state_dir / "inline-bridge.zuliprc"
            sentinel = root / "sentinel"
            sentinel.write_text("untouched", encoding="utf-8")
            legacy_credentials.symlink_to(sentinel)
            hermes = self.write_python_console(root / "hermes")
            config = {
                "instance_name": "inline",
                "hermes": {"command": str(hermes)},
                "zulip": {
                    "site": "https://zulip.example.com",
                    "bot_email": "bot@example.com",
                    "bot_api_key_env": "INLINE_ZULIP_KEY",
                },
                "bridge": {"state_directory": str(state_dir)},
            }
            config_path = root / "config.json"
            self.write_config(config_path, config)
            completed = subprocess.run(
                [sys.executable, "-m", "hermes_zulip_bridge", "-c", str(config_path), "bridge"],
                env={
                    **os.environ,
                    "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
                    "INLINE_ZULIP_KEY": "secret-canary",
                },
                capture_output=True,
                text=True,
                timeout=5,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("secret-canary", completed.stdout + completed.stderr)
            self.assertEqual(state_path.read_bytes(), corrupt)
            self.assertTrue(legacy_credentials.is_symlink())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertTrue((state_dir / ".hermes-zulip-locks").is_dir())


if __name__ == "__main__":
    unittest.main()
