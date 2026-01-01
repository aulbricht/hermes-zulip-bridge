from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import apply_bridge_env, apply_notifier_env, load_config, validate_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a configurable Hermes/Zulip bridge.")
    parser.add_argument("-c", "--config", help="YAML or JSON config path.")
    parser.add_argument("--version", action="version", version=f"hermes-zulip-bridge {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("bridge", help="Run the Zulip -> Hermes bridge.")
    subparsers.add_parser("notifier", help="Run the Kanban -> Zulip notifier.")
    subparsers.add_parser("kanban-task", help="Create a Kanban coding task with Zulip notification metadata.")
    subparsers.add_parser("smoke-test", help="Run a one-shot live smoke test.")
    subparsers.add_parser("validate-config", help="Validate config without requiring secrets.")
    args, rest = parser.parse_known_args(argv)
    config = load_config(args.config)
    command = args.command or "bridge"

    if command == "validate-config":
        issues = validate_config(config, require_secret=False)
        print(json.dumps({"ok": not issues, "issues": issues}, indent=2))
        return 0 if not issues else 1

    sys.argv = [sys.argv[0], *rest]
    if command == "notifier":
        apply_notifier_env(config)
        from . import notifier

        return notifier.main()

    if command == "kanban-task":
        apply_notifier_env(config, require_secret=False)
        from . import kanban_task

        return kanban_task.main()

    if command == "smoke-test":
        apply_bridge_env(config)
        from . import smoke

        return smoke.main(rest)

    apply_bridge_env(config)
    from . import bridge

    if "--demo" in rest:
        bridge._demo()
        return 0
    return bridge.main()


if __name__ == "__main__":
    raise SystemExit(main())
