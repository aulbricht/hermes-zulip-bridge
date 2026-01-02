from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .config import apply_bridge_env, apply_notifier_env, bridge_bundle_paths, bridge_state_path, load_config, preflight_credentials, validate_config
from .locking import PROCESS_LOCK_FAILED, ProcessLockError, process_lock


SMOKE_OPTIONS = {
    "--stream",
    "--topic",
    "--message",
    "--post-probe",
    "--run-hermes",
    "--human-origin-message-id",
    "--post-reply",
}
CONFIGURATION_INVALID = "Configuration is invalid"


def _config_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except Exception:
        raise SystemExit(CONFIGURATION_INVALID) from None


@dataclass(frozen=True)
class LauncherFileProof:
    path: str
    uid: int
    mode: int
    dev: int
    ino: int
    size: int
    mtime_ns: int
    digest: str


@dataclass(frozen=True)
class LauncherProof:
    command_path: str
    interpreter_command_path: str
    script: LauncherFileProof
    interpreter: LauncherFileProof
    pin_directory: str

    def __iter__(self):
        yield self.script.path
        yield self.interpreter.path


def _trusted_launcher_path(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parent.parts[1:]:
        current /= part
        try:
            opened = os.stat(current, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("Hermes launcher path is unavailable or unsafe") from exc
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid not in {0, os.geteuid()}
            or mode & 0o022
        ):
            raise RuntimeError("Hermes launcher path is unavailable or unsafe")


def _launcher_digest(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_launcher_file(path: Path, *, trusted_path: bool = True) -> tuple[int, LauncherFileProof]:
    if trusted_path:
        _trusted_launcher_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("Hermes launcher file is unavailable or unsafe") from exc
    try:
        opened = os.fstat(fd)
        linked = os.stat(path, follow_symlinks=False)
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            or opened.st_uid not in {0, os.geteuid()}
            or mode & 0o022
            or not mode & 0o111
            or not os.access(path, os.X_OK)
        ):
            raise RuntimeError("Hermes launcher file is unavailable or unsafe")
        proof = LauncherFileProof(
            path=str(path),
            uid=opened.st_uid,
            mode=mode,
            dev=opened.st_dev,
            ino=opened.st_ino,
            size=opened.st_size,
            mtime_ns=opened.st_mtime_ns,
            digest=_launcher_digest(fd),
        )
        return fd, proof
    except BaseException:
        os.close(fd)
        raise


def _trusted_venv_bin(interpreter_path: Path) -> Path:
    try:
        pin_directory = interpreter_path.parent.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("Hermes interpreter is not in a trusted Python virtual environment") from exc
    if pin_directory.name != "bin":
        raise RuntimeError("Hermes interpreter is not in a trusted Python virtual environment")
    _trusted_launcher_path(pin_directory / interpreter_path.name)
    config_path = pin_directory.parent / "pyvenv.cfg"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(config_path, flags)
    except OSError as exc:
        raise RuntimeError("Hermes interpreter is not in a trusted Python virtual environment") from exc
    try:
        opened = os.fstat(fd)
        linked = os.stat(config_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            or opened.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise RuntimeError("Hermes interpreter is not in a trusted Python virtual environment")
    finally:
        os.close(fd)
    return pin_directory


_INTERPRETER_PIN = re.compile(r"\.hermes-python-pin-([1-9][0-9]*)-([0-9a-f]{32})")


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (OSError, PermissionError):
        return True
    return True


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _safe_pin_identity(path: Path, expected: LauncherFileProof | None = None) -> bool:
    match = _INTERPRETER_PIN.fullmatch(path.name)
    if match is None:
        return False
    try:
        opened = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o500
    ):
        return False
    return expected is None or (
        str(path) == expected.path
        and opened.st_dev == expected.dev
        and opened.st_ino == expected.ino
        and opened.st_size == expected.size
        and opened.st_mtime_ns == expected.mtime_ns
    )


def _remove_interpreter_pin(path: Path, expected: LauncherFileProof | None = None) -> None:
    if not _safe_pin_identity(path, expected):
        return
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except OSError:
        pass


def _remove_stale_interpreter_pins(pin_directory: Path) -> None:
    try:
        entries = list(pin_directory.iterdir())
    except OSError:
        return
    for path in entries:
        match = _INTERPRETER_PIN.fullmatch(path.name)
        if match is None or _process_exists(int(match.group(1))):
            continue
        _remove_interpreter_pin(path)


def _pin_interpreter(proof: LauncherProof, source_fd: int) -> tuple[Path, int, LauncherFileProof]:
    pin_directory = Path(proof.pin_directory)
    if _trusted_venv_bin(Path(proof.interpreter_command_path)) != pin_directory:
        raise RuntimeError("Hermes interpreter pin location changed after preflight")
    _remove_stale_interpreter_pins(pin_directory)
    pin = pin_directory / f".hermes-python-pin-{os.getpid()}-{secrets.token_hex(16)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = -1
    try:
        fd = os.open(pin, flags, 0o500)
        os.fchmod(fd, 0o500)
        os.lseek(source_fd, 0, os.SEEK_SET)
        while chunk := os.read(source_fd, 1024 * 1024):
            written = 0
            while written < len(chunk):
                count = os.write(fd, chunk[written:])
                if count <= 0:
                    raise OSError("Hermes interpreter pin write made no progress")
                written += count
        os.fsync(fd)
        os.close(fd)
        fd = -1
        _fsync_directory(pin_directory)
        pin_fd, pinned = _open_launcher_file(pin)
        if pinned.digest != proof.interpreter.digest or pinned.size != proof.interpreter.size:
            os.close(pin_fd)
            raise RuntimeError("Hermes interpreter pin verification failed")
        if os.fstat(pin_fd).st_nlink != 1:
            os.close(pin_fd)
            raise RuntimeError("Hermes interpreter pin verification failed")
        return pin, pin_fd, pinned
    except BaseException:
        if fd >= 0:
            os.close(fd)
        _remove_interpreter_pin(pin)
        raise


def _declared_launcher_path(path: str, expected: LauncherFileProof, *, allow_symlink: bool) -> None:
    declared = Path(path)
    try:
        if not allow_symlink and declared.is_symlink():
            raise RuntimeError("Hermes launcher file is unavailable or unsafe")
        resolved = declared.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("Hermes launcher file is unavailable or unsafe") from exc
    if str(resolved) != expected.path:
        raise RuntimeError("Hermes launcher identity changed after preflight")


def _open_launcher_proof(proof: LauncherProof) -> tuple[int, int]:
    if not isinstance(proof, LauncherProof):
        raise RuntimeError("Hermes launcher proof is missing or invalid")
    _declared_launcher_path(proof.command_path, proof.script, allow_symlink=False)
    _declared_launcher_path(proof.interpreter_command_path, proof.interpreter, allow_symlink=True)
    if str(_trusted_venv_bin(Path(proof.interpreter_command_path))) != proof.pin_directory:
        raise RuntimeError("Hermes launcher identity changed after preflight")
    script_fd, script = _open_launcher_file(Path(proof.script.path))
    try:
        interpreter_fd, interpreter = _open_launcher_file(Path(proof.interpreter.path), trusted_path=False)
    except BaseException:
        os.close(script_fd)
        raise
    if script != proof.script or interpreter != proof.interpreter:
        os.close(script_fd)
        os.close(interpreter_fd)
        raise RuntimeError("Hermes launcher identity changed after preflight")
    return script_fd, interpreter_fd


def _verify_launcher_proof(proof: LauncherProof) -> None:
    script_fd, interpreter_fd = _open_launcher_proof(proof)
    os.close(script_fd)
    os.close(interpreter_fd)


def _python_console_script(command: str) -> LauncherProof:
    candidate = Path(command).expanduser()
    if not candidate.is_absolute():
        resolved = shutil.which(command)
        if not resolved:
            raise RuntimeError("Hermes Python console script is unavailable")
        candidate = Path(resolved)
    try:
        if candidate.is_symlink():
            raise RuntimeError("Hermes Python console script is unavailable")
        command_path = str(candidate.absolute())
        candidate = candidate.resolve(strict=True)
        script_fd, script = _open_launcher_file(candidate)
        first_line = os.read(script_fd, 4096).splitlines(keepends=True)[:1]
        first_line = first_line[0] if first_line else b""
        os.close(script_fd)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("Hermes Python console script is unavailable") from exc
    try:
        shebang = shlex.split(first_line.removeprefix(b"#!").decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        shebang = []
    interpreter = ""
    if shebang and Path(shebang[0]).name.lower().startswith("python"):
        interpreter = shebang[0]
    interpreter_path = Path(interpreter)
    if (
        not first_line.startswith(b"#!")
        or not interpreter_path.is_absolute()
    ):
        raise RuntimeError("Hermes executable is not a Python console script")
    try:
        interpreter_command_path = str(interpreter_path)
        pin_directory = _trusted_venv_bin(interpreter_path)
        interpreter_path = interpreter_path.resolve(strict=True)
        interpreter_fd, interpreter_proof = _open_launcher_file(interpreter_path, trusted_path=False)
        os.close(interpreter_fd)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("Hermes executable is not a Python console script") from exc
    return LauncherProof(command_path, interpreter_command_path, script, interpreter_proof, str(pin_directory))


def _configured_hermes_command(config: dict) -> str:
    hermes = config.get("hermes") or {}
    if not isinstance(hermes, dict):
        raise RuntimeError("Hermes executable preflight failed")
    return str(hermes.get("command") or hermes.get("executable") or "hermes")


def _fatal_process_exit(code: int) -> int:
    os._exit(code)
    return code


def _positive_message_id(value: str) -> str:
    if len(value) > 64 or re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError("must be a positive canonical decimal Zulip message ID")
    return value


def build_smoke_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a one-shot live smoke test without starting the bridge loop.",
        allow_abbrev=False,
    )
    parser.add_argument("--stream", default="", help="Zulip stream/channel to use; defaults to configured stream.")
    parser.add_argument("--topic", required=True, help="Zulip topic to use. Posting creates the topic if needed.")
    parser.add_argument("--message", default="Hermes Zulip bridge smoke connectivity probe.", help="Connectivity probe posted by the Zulip bot.")
    parser.add_argument("--post-probe", action="store_true", help="Post a probe message to Zulip before invoking Hermes.")
    parser.add_argument("--run-hermes", action="store_true", help="Invoke Hermes once through the bridge reply path.")
    parser.add_argument(
        "--human-origin-message-id",
        default=None,
        type=_positive_message_id,
        help="Existing human-authored Zulip message ID to use for --run-hermes.",
    )
    parser.add_argument("--post-reply", action="store_true", help="Post the Hermes response to Zulip. Requires --run-hermes.")
    return parser


def validate_smoke_args(args: argparse.Namespace) -> None:
    if args.post_reply and not args.run_hermes:
        raise SystemExit("--post-reply requires --run-hermes")
    if args.run_hermes and not args.post_probe:
        raise SystemExit("--run-hermes requires --post-probe")
    human_id = getattr(args, "human_origin_message_id", "")
    if human_id:
        try:
            _positive_message_id(str(human_id))
        except argparse.ArgumentTypeError:
            raise SystemExit(
                "--human-origin-message-id must be a positive canonical decimal Zulip message ID"
            ) from None
    if args.run_hermes and not human_id:
        raise SystemExit("--run-hermes requires --human-origin-message-id with a positive Zulip message ID")


def parse_smoke_args(argv: list[str] | None = None) -> argparse.Namespace:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = build_smoke_parser()
    seen: set[str] = set()
    for value in values:
        option = value.split("=", 1)[0]
        if option not in SMOKE_OPTIONS:
            continue
        if option in seen:
            parser.error(f"{option} may not be repeated")
        seen.add(option)
    args = parser.parse_args(values)
    validate_smoke_args(args)
    return args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a configurable Hermes/Zulip bridge.", allow_abbrev=False)
    parser.add_argument("-c", "--config", help="YAML or JSON config path.")
    parser.add_argument("--version", action="version", version=f"hermes-zulip-bridge {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("bridge", help="Run the Zulip -> Hermes bridge.")
    subparsers.add_parser("notifier", help="Run the Kanban -> Zulip notifier.")
    subparsers.add_parser("kanban-task", help="Create a Kanban coding task with Zulip notification metadata.")
    subparsers.add_parser("smoke-test", help="Run a one-shot live smoke test.", add_help=False)
    subparsers.add_parser("validate-config", help="Validate config without requiring secrets.")
    args, rest = parser.parse_known_args(argv)
    if args.command in {None, "bridge", "validate-config"}:
        allowed = {"--demo"} if (args.command or "bridge") == "bridge" else set()
        unknown = [value for value in rest if value not in allowed]
        if unknown:
            parser.error(f"unrecognized arguments: {' '.join(unknown)}")
    smoke_args = parse_smoke_args(rest) if args.command == "smoke-test" else None
    config = _config_call(load_config, args.config)
    command = args.command or "bridge"
    credential_preflight = None
    if command in {"bridge", "notifier", "smoke-test"}:
        credential_preflight = _config_call(preflight_credentials, config)
    launcher_proof = None
    bridge_module = None
    if command == "smoke-test" or (command == "bridge" and "--demo" not in rest):
        try:
            launcher_proof = _python_console_script(_configured_hermes_command(config))
        except RuntimeError:
            raise SystemExit("Hermes executable preflight failed") from None

    if command == "validate-config":
        issues = _config_call(validate_config, config, require_secret=False)
        print(json.dumps({"ok": not issues, "issue_count": len(issues)}, indent=2))
        return 0 if not issues else 1

    sys.argv = [sys.argv[0], *rest]
    if command == "notifier":
        env = _config_call(
            apply_notifier_env, config, credential_preflight=credential_preflight
        )
        from . import notifier

        if env.get("HERMES_ZULIP_SITE"):
            inline_rc = {
                "site": env["HERMES_ZULIP_SITE"],
                "email": env["HERMES_ZULIP_EMAIL"],
                "key": env["HERMES_ZULIP_API_KEY"],
            }
            notifier.load_rc = lambda _path=notifier.RC_PATH: inline_rc
        return notifier.main(rc=credential_preflight)

    if command == "kanban-task":
        _config_call(apply_notifier_env, config, require_secret=False)
        from . import kanban_task

        return kanban_task.main()

    try:
        state_path = _config_call(bridge_state_path, config)
        _config_call(bridge_bundle_paths, config, state_path=state_path)
        if any(name in sys.modules for name in (f"{__package__}.bridge", f"{__package__}.smoke")):
            raise ProcessLockError(PROCESS_LOCK_FAILED)
        with process_lock(state_path) as held_lock:
            _config_call(
                apply_bridge_env,
                config,
                state_path=held_lock.state_path,
                credential_preflight=credential_preflight,
            )
            from . import bridge
            bridge_module = bridge
            bridge.load_rc = lambda: credential_preflight

            bridge.freeze_auxiliary_paths(held_lock.state_path)

            state = bridge.require_state_object(
                bridge.load_json(held_lock.state_path, {"seen_ids": [], "topic_sessions": {}})
            )
            alias_entries = bridge.load_alias_entries()
            bridge.load_aliases(alias_entries)
            rc = bridge.load_rc()
            preflight_state = copy.deepcopy(state)
            realm = bridge.realm_key(rc["site"])
            bridge.bind_state_realm(preflight_state, realm)
            bridge.apply_alias_repairs(preflight_state, alias_entries, realm)
            if command == "smoke-test":
                from . import smoke

                result = smoke.run(smoke_args, lock=held_lock, hermes_launcher=launcher_proof, rc=credential_preflight)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if result["ok"] else 1

            if "--demo" in rest:
                bridge._demo()
                return 0
            return bridge.main(lock=held_lock, launcher_proof=launcher_proof)
    except ProcessLockError as exc:
        raise SystemExit(str(exc)) from None
    except BaseException as exc:
        if bridge_module is not None and isinstance(exc, bridge_module.FatalBridgeExit):
            return _fatal_process_exit(exc.exit_code)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
