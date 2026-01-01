#!/usr/bin/env python3
"""Create a Kanban coding task with the Hermes adversarial-review contract.

The task body carries machine-readable Zulip notification metadata so
the Zulip Kanban notifier can post a durable callback when the workflow reaches a
terminal state.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

AGENTOS_URL = os.environ.get("HERMES_KANBAN_URL", os.environ.get("AGENTOS_URL", "http://127.0.0.1:9120")).rstrip("/")  # agentos-env-ok: localhost fallback for optional local dev; production overrides via env/settings.
DEFAULT_BOARD = os.environ.get("HERMES_CODING_WORKFLOW_BOARD", "default")
DEFAULT_ASSIGNEE = os.environ.get("HERMES_CODING_WORKFLOW_CODER", "coder")
DEFAULT_REVIEWER = os.environ.get("HERMES_CODING_WORKFLOW_REVIEWER", "reviewer")
DEFAULT_STREAM = os.environ.get("HERMES_ZULIP_STREAMS", os.environ.get("ZULIP_BRIDGE_STREAMS", "hermes")).split(",", 1)[0]
DEFAULT_TOPIC = os.environ.get("HERMES_ZULIP_DEFAULT_TOPIC", os.environ.get("ZULIP_BRIDGE_DEFAULT_TOPIC", "Hermes bridge"))


def request_json(method: str, url: str, *, payload: dict[str, Any] | None = None, timeout: float = 30) -> dict[str, Any]:
    data = None
    headers = {"User-Agent": "Hermes-Coding-Workflow-Creator"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed: HTTP {exc.code} {raw[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def build_task_body(args: argparse.Namespace) -> str:
    origin = {
        "platform": "zulip",
        "stream": args.stream,
        "topic": args.topic,
        "message_id": args.message_id,
        "bridge_marker": args.bridge_marker,
    }
    if args.dm_to:
        origin = {
            "platform": "zulip",
            "type": "direct",
            "to": args.dm_to,
            "message_id": args.message_id,
            "bridge_marker": args.bridge_marker,
        }
    notification_target = {key: value for key, value in origin.items() if value}
    sections = [
        "Coding workflow contract:",
        "1. Coder implements the requested change in the indicated repository/workspace.",
        "2. Coder must report changed files and real verification command output.",
        "3. Coder must not declare the task done until an adversarial review has passed.",
        f"4. After implementation, route to adversarial review by `{args.reviewer}`.",
        "5. Reviewer must check correctness, regression risk, security/privacy, tests, and maintainability.",
        "6. If review fails, move the task back to coder with concrete fix instructions and repeat the cycle.",
        "7. When review passes, mark the task done or blocked with a concise final summary; the Zulip notifier posts the callback.",
        "",
        f"Repository/workspace: {args.repo or '(not specified)'}",
        "",
        "Request:",
        args.request.strip(),
        "",
        "Acceptance criteria:",
    ]
    criteria = args.acceptance or []
    if not criteria:
        criteria = [
            "Implementation satisfies the original user request.",
            "Targeted tests/checks pass and are named in the final handoff.",
            "Adversarial reviewer approval is recorded before terminal completion.",
        ]
    sections.extend(f"- {item}" for item in criteria)
    sections.extend(
        [
            "",
            "notification_target:",
            json.dumps(notification_target, sort_keys=True),
            "",
            "workflow:",
            json.dumps(
                {
                    "type": "coding_with_adversarial_review",
                    "coder": args.assignee,
                    "reviewer": args.reviewer,
                    "on_review_fail": "return_to_coder_with_instructions",
                    "on_review_pass": "mark_terminal_for_zulip_notifier",
                },
                sort_keys=True,
            ),
        ]
    )
    return "\n".join(sections)


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    notification_target = {
        "platform": "zulip",
        "stream": args.stream,
        "topic": args.topic,
        "message_id": args.message_id,
        "bridge_marker": args.bridge_marker,
    }
    if args.dm_to:
        notification_target = {
            "platform": "zulip",
            "type": "direct",
            "to": args.dm_to,
            "message_id": args.message_id,
            "bridge_marker": args.bridge_marker,
        }
    notification_target = {key: value for key, value in notification_target.items() if value}
    metadata = {
        "workflow": "coding_with_adversarial_review",
        "reviewer": args.reviewer,
        "origin": notification_target,
        "notification_target": notification_target,
        "repo": args.repo,
    }
    body = build_task_body(args)
    return {
        "title": args.title,
        # Hermes Kanban persists `body`; `description` is retained for API/UI
        # compatibility with clients that still read it before proxying.
        "body": body,
        "description": body,
        "status": args.status,
        "assignee": args.assignee,
        "priority": args.priority,
        # AgentOS currently proxies arbitrary metadata poorly to Hermes Kanban,
        # so duplicate it into source_detail as the durable structured field.
        "metadata": metadata,
        "source_detail": metadata,
    }


def create_task(args: argparse.Namespace, payload: dict[str, Any]) -> dict[str, Any]:
    query = urllib.parse.urlencode({"board": args.board})
    url = f"{args.agentos_url.rstrip('/')}/api/plugins/kanban/tasks?{query}"
    return request_json("POST", url, payload=payload)


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    query = urllib.parse.urlencode({"board": args.board})
    url = f"{args.agentos_url.rstrip('/')}/api/plugins/kanban/dispatch?{query}"
    return request_json("POST", url, payload={"board": args.board})


def current_git_repo(default: str = "") -> str:
    try:
        cp = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except Exception:
        return default
    return cp.stdout.strip() or default


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Hermes Kanban coding task with mandatory adversarial review.")
    parser.add_argument("--title", required=True)
    parser.add_argument("--request", required=True, help="The coding request to put on the task.")
    parser.add_argument("--repo", default=current_git_repo(""), help="Repository/workspace path for the coder.")
    parser.add_argument("--acceptance", action="append", help="Acceptance criterion; may be repeated.")
    parser.add_argument("--stream", default=DEFAULT_STREAM)
    parser.add_argument("--topic", default=DEFAULT_TOPIC)
    parser.add_argument("--dm-to", default="", help="Send terminal workflow notifications as a Zulip direct message to this user/email/user-id instead of a stream topic.")
    parser.add_argument("--message-id", default="")
    parser.add_argument("--bridge-marker", default="")
    parser.add_argument("--assignee", default=DEFAULT_ASSIGNEE)
    parser.add_argument("--reviewer", default=DEFAULT_REVIEWER)
    parser.add_argument("--status", default="ready")
    parser.add_argument("--priority", default="p2")
    parser.add_argument("--board", default=DEFAULT_BOARD)
    parser.add_argument("--agentos-url", default=AGENTOS_URL)
    parser.add_argument("--dispatch", action="store_true", help="Nudge the Kanban dispatcher after creation.")
    parser.add_argument("--dry-run", action="store_true", help="Print payload instead of creating the task.")
    args = parser.parse_args()
    payload = build_payload(args)
    if args.dry_run:
        print(json.dumps({"ok": True, "payload": payload}, indent=2, sort_keys=True))
        return 0
    created = create_task(args, payload)
    result = {"ok": True, "created": created}
    if args.dispatch:
        result["dispatch"] = dispatch(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
