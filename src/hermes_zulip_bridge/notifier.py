#!/usr/bin/env python3
"""Post durable Kanban coding-workflow status updates back to Zulip.

Kanban stays the source of truth. This notifier only sends a concise Zulip
callback when a task that declares a Zulip notification target reaches a
terminal status.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HOME = Path.home()


def env_value(name: str, default: str, *legacy_names: str) -> str:
    for candidate in (name, *legacy_names):
        value = os.environ.get(candidate)
        if value is not None:
            return value
    return default


HERMES_HOME = Path(env_value("HERMES_HOME", str(HOME / ".hermes")))
RC_PATH = Path(env_value("HERMES_ZULIP_RC", str(HERMES_HOME / "zuliprc"), "ZULIPRC"))
STATE_PATH = Path(env_value("HERMES_ZULIP_NOTIFIER_STATE", str(HERMES_HOME / "state/zulip_kanban_notifier.json"), "ZULIP_KANBAN_NOTIFIER_STATE"))
AGENTOS_URL = env_value("HERMES_KANBAN_URL", "http://127.0.0.1:9120", "AGENTOS_URL").rstrip("/")  # agentos-env-ok: localhost fallback for optional local dev; production overrides via env/settings.
POLL_SECONDS = float(env_value("HERMES_ZULIP_NOTIFIER_POLL_SECONDS", "30", "ZULIP_KANBAN_NOTIFIER_POLL_SECONDS"))
BOARD = env_value("HERMES_ZULIP_NOTIFIER_BOARD", "default", "ZULIP_KANBAN_NOTIFIER_BOARD")
TERMINAL_STATUSES = {
    item.strip().lower()
    for item in env_value("HERMES_ZULIP_NOTIFIER_TERMINAL_STATUSES", "done,complete,completed,blocked", "ZULIP_KANBAN_NOTIFIER_TERMINAL_STATUSES").split(",")
    if item.strip()
}
JSON_BLOCK_RE = re.compile(
    r"(?P<label>zulip_origin|notification_target|notify_target|origin)\s*:\s*(?P<json>\{.*?\})(?=\s*\n\S|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def log(*parts: object) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%S%z"), *parts, flush=True)


def load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except Exception as exc:
        log("state_load_failed", path, exc)
        return default


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def load_rc(path: Path = RC_PATH) -> dict[str, str]:
    cp = configparser.ConfigParser()
    if not cp.read(path):
        raise SystemExit(f"Missing zuliprc: {path}")
    return {
        "email": cp["api"]["email"].strip(),
        "key": cp["api"]["key"].strip(),
        "site": cp["api"]["site"].strip().rstrip("/"),
    }


def auth_header(rc: dict[str, str]) -> str:
    token = base64.b64encode(f"{rc['email']}:{rc['key']}".encode()).decode()
    return "Basic " + token


def request_json(method: str, url: str, *, headers: dict[str, str] | None = None, data: dict[str, Any] | None = None, timeout: float = 30) -> dict[str, Any]:
    body = None
    req_headers = dict(headers or {})
    if data is not None:
        body = urllib.parse.urlencode(data, doseq=True).encode()
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed: HTTP {exc.code} {raw[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def zulip_api(rc: dict[str, str], method: str, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return request_json(
        method,
        rc["site"] + path,
        headers={"Authorization": auth_header(rc), "User-Agent": "Hermes-Kanban-Zulip-Notifier"},
        data=data,
    )


def post_zulip_message(rc: dict[str, str], stream: str, topic: str, content: str) -> dict[str, Any]:
    if not stream or not topic:
        raise ValueError("Zulip stream and topic are required for notification")
    return zulip_api(
        rc,
        "POST",
        "/api/v1/messages",
        data={"type": "stream", "to": stream, "topic": topic, "content": content[:9000]},
    )


def post_zulip_direct_message(rc: dict[str, str], to: str, content: str) -> dict[str, Any]:
    if not str(to or "").strip():
        raise ValueError("Zulip direct-message recipient is required for notification")
    return zulip_api(
        rc,
        "POST",
        "/api/v1/messages",
        data={"type": "private", "to": to, "content": content[:9000]},
    )


def target_delivery_type(target: dict[str, Any]) -> str:
    raw = str(target.get("type") or target.get("message_type") or target.get("delivery") or "stream").strip().lower()
    if raw in {"dm", "direct", "direct_message", "private", "pm"}:
        return "direct"
    return "stream"


def direct_recipient_for_target(target: dict[str, Any]) -> str:
    for key in ("to", "recipient", "recipients", "user_ids", "user_id", "emails", "email"):
        value = target.get(key)
        if isinstance(value, list):
            clean = [str(item).strip() for item in value if str(item).strip()]
            if clean:
                return json.dumps(clean)
        if str(value or "").strip():
            return str(value).strip()
    return ""


def send_zulip_notification(rc: dict[str, str], target: dict[str, Any], content: str) -> dict[str, Any]:
    if target_delivery_type(target) == "direct":
        return post_zulip_direct_message(rc, direct_recipient_for_target(target), content)
    return post_zulip_message(rc, target["stream"], target["topic"], content)


def fetch_zulip_message(rc: dict[str, str], message_id: str) -> dict[str, Any] | None:
    """Return the current Zulip message payload for an origin message id.

    Zulip stream topics are mutable and the Events/Messages payloads available to
    this bridge do not expose a durable native topic/thread id. The stable anchor
    we do have is the origin message id. Re-reading that message at notification
    time gives us Zulip's current stream/topic after topic renames, while keeping
    the stored target as a fallback if the message is deleted or inaccessible.
    """
    message_id = str(message_id or "").strip()
    if not message_id:
        return None
    try:
        payload = zulip_api(rc, "GET", f"/api/v1/messages/{int(message_id)}")
    except Exception as exc:
        log("origin_message_lookup_failed", message_id, exc)
        return None
    message = payload.get("message") if isinstance(payload, dict) else None
    return message if isinstance(message, dict) else None


def current_zulip_target(rc: dict[str, str] | None, target: dict[str, Any]) -> dict[str, Any]:
    """Resolve the notification target to the current Zulip topic when possible."""
    resolved = dict(target)
    if target_delivery_type(resolved) == "direct":
        recipient = direct_recipient_for_target(resolved)
        if recipient:
            resolved["type"] = "direct"
            resolved["to"] = recipient
        return resolved
    if rc is None:
        return resolved
    message = fetch_zulip_message(rc, str(target.get("message_id") or ""))
    if not message:
        return resolved
    current_stream = str(message.get("display_recipient") or "").strip()
    current_topic = str(message.get("subject") or message.get("topic") or "").strip()
    if current_stream:
        resolved["stream"] = current_stream
    if current_topic:
        original_topic = str(target.get("topic") or "").strip()
        resolved["topic"] = current_topic
        if original_topic and current_topic != original_topic:
            resolved["original_topic"] = original_topic
    return resolved


def fetch_kanban_board(agentos_url: str = AGENTOS_URL, board: str = BOARD) -> dict[str, Any]:
    url = f"{agentos_url.rstrip('/')}/api/plugins/kanban/board?" + urllib.parse.urlencode({"board": board})
    return request_json("GET", url, headers={"User-Agent": "Hermes-Kanban-Zulip-Notifier"})


def flatten_tasks(board_payload: dict[str, Any]) -> list[dict[str, Any]]:
    columns = board_payload.get("columns") or []
    tasks: list[dict[str, Any]] = []
    for column in columns:
        if not isinstance(column, dict):
            continue
        status = str(column.get("name") or column.get("id") or "").strip().lower()
        for task in column.get("tasks") or []:
            if not isinstance(task, dict):
                continue
            row = dict(task)
            row.setdefault("status", status)
            tasks.append(row)
    if not tasks and isinstance(board_payload.get("tasks"), list):
        tasks = [task for task in board_payload["tasks"] if isinstance(task, dict)]
    return tasks


def _candidate_text_fields(task: dict[str, Any]) -> str:
    values = []
    for key in ("description", "body", "details", "content", "notes"):
        value = task.get(key)
        if isinstance(value, str):
            values.append(value)
    return "\n".join(values)


def _parse_json_blocks(text: str) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for match in JSON_BLOCK_RE.finditer(text or ""):
        try:
            value = json.loads(match.group("json"))
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            parsed.append(value)
    return parsed


def zulip_target_for_task(task: dict[str, Any]) -> dict[str, Any] | None:
    candidates: list[Any] = []
    for key in ("notification_target", "notify_target", "origin"):
        candidates.append(task.get(key))
    metadata = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
    source_detail = task.get("source_detail") if isinstance(task.get("source_detail"), dict) else {}
    candidates.extend([metadata.get("notification_target"), metadata.get("notify_target"), metadata.get("origin")])
    candidates.extend([source_detail.get("notification_target"), source_detail.get("notify_target"), source_detail.get("origin")])
    candidates.extend(_parse_json_blocks(_candidate_text_fields(task)))
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        target = candidate.get("notification_target") if isinstance(candidate.get("notification_target"), dict) else candidate
        if str(target.get("platform") or "").lower() != "zulip":
            continue
        if target_delivery_type(target) == "direct":
            recipient = direct_recipient_for_target(target)
            if recipient:
                return {**target, "type": "direct", "to": recipient}
            continue
        stream = str(target.get("stream") or target.get("stream_name") or "").strip()
        topic = str(target.get("topic") or target.get("subject") or "").strip()
        if stream and topic:
            return {**target, "stream": stream, "topic": topic}
    return None


def task_identity(task: dict[str, Any]) -> str:
    return str(task.get("id") or task.get("task_id") or task.get("uuid") or task.get("title") or "unknown-task")


def task_status(task: dict[str, Any]) -> str:
    return str(task.get("status") or "").strip().lower()


def task_signature(task: dict[str, Any]) -> str:
    return "|".join(
        str(task.get(key) or "")
        for key in ("status", "updated_at", "completed_at", "blocked_at", "last_heartbeat_at")
    )


def notification_body(task: dict[str, Any], target: dict[str, Any]) -> str:
    title = str(task.get("title") or task_identity(task)).strip()
    status = task_status(task) or "updated"
    task_id = task_identity(task)
    assignee = str(task.get("assignee") or "").strip()
    summary = str(task.get("summary") or task.get("result") or task.get("block_reason") or "").strip()
    lines = [f"Kanban update: `{title}` is now `{status}`.", "", f"Task: `{task_id}`"]
    if assignee:
        lines.append(f"Assignee: `{assignee}`")
    if target.get("message_id"):
        lines.append(f"Origin Zulip message: `{target['message_id']}`")
    if target.get("bridge_marker"):
        lines.append(f"Bridge marker: `{target['bridge_marker']}`")
    if summary:
        lines.extend(["", summary[:1200]])
    if status in {"done", "complete", "completed"}:
        lines.append("\nCoding workflow result: implementation and required review cycle are complete.")
    elif status == "blocked":
        lines.append("\nCoding workflow result: blocked; human or upstream action may be needed.")
    return "\n".join(lines)


def scan_once(state: dict[str, Any], rc: dict[str, str] | None, *, send: bool, prime: bool = False) -> list[dict[str, Any]]:
    board = fetch_kanban_board()
    notified = state.setdefault("notified", {})
    events: list[dict[str, Any]] = []
    for task in flatten_tasks(board):
        status = task_status(task)
        if status not in TERMINAL_STATUSES:
            continue
        target = zulip_target_for_task(task)
        if not target:
            continue
        task_id = task_identity(task)
        signature = task_signature(task)
        if notified.get(task_id) == signature:
            continue
        delivery_target = current_zulip_target(rc, target) if send else target
        body = notification_body(task, delivery_target)
        event = {
            "task_id": task_id,
            "status": status,
            "type": target_delivery_type(delivery_target),
            "content": body,
        }
        if target_delivery_type(delivery_target) == "direct":
            event["to"] = direct_recipient_for_target(delivery_target)
        else:
            event["stream"] = delivery_target["stream"]
            event["topic"] = delivery_target["topic"]
        if delivery_target.get("original_topic"):
            event["original_topic"] = delivery_target["original_topic"]
        if prime:
            notified[task_id] = signature
            event["primed"] = True
        elif send:
            assert rc is not None
            response = send_zulip_notification(rc, delivery_target, body)
            notified[task_id] = signature
            event["zulip_response"] = response
        events.append(event)
    if events or prime:
        save_json(STATE_PATH, state)
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Notify Zulip when Kanban tasks with Zulip targets reach terminal status.")
    parser.add_argument("--once", action="store_true", help="Run one scan and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Print pending notifications without posting to Zulip.")
    parser.add_argument("--prime", action="store_true", help="Mark current terminal tasks as already notified without posting.")
    args = parser.parse_args()
    state = load_json(STATE_PATH, {"notified": {}})
    rc = None if args.dry_run or args.prime else load_rc()
    while True:
        try:
            events = scan_once(state, rc, send=not args.dry_run and not args.prime, prime=args.prime)
            if args.dry_run:
                print(json.dumps({"ok": True, "events": events}, indent=2, sort_keys=True))
            elif events:
                for event in events:
                    if event.get("type") == "direct":
                        destination = event.get("to")
                    else:
                        destination = f"{event.get('stream')}:{event.get('topic')}"
                    log("notified" if not event.get("primed") else "primed", event["task_id"], event["status"], destination)
        except Exception as exc:
            log("scan_failed", exc)
            if args.once or args.dry_run or args.prime:
                return 1
        if args.once or args.dry_run or args.prime:
            return 0
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
