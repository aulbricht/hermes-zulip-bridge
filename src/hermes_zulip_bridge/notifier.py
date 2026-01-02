#!/usr/bin/env python3
"""Durably post terminal Kanban workflow updates to Zulip."""

from __future__ import annotations

import argparse
import base64
import configparser
import copy
import datetime
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .locking import ProcessLockError, process_lock
from .security import _trusted_ancestry, opaque_log_value, secure_read_text

HOME = Path.home()
MAX_ZULIPRC_BYTES = 1024 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_NOTIFIED = 10000
MAX_OUTBOX = 500
MAX_DEAD_LETTERS = 500
MAX_ATTEMPTS = 8
MAX_WORK_PER_SCAN = 50
RETRY_BASE_SECONDS = 5.0
RETRY_MAX_SECONDS = 900.0
STATE_VERSION = 3
SIGNING_KEY_BYTES = 32


class StateError(RuntimeError):
    pass


class RouteError(RuntimeError):
    pass


def env_value(name: str, default: str, *legacy_names: str) -> str:
    for candidate in (name, *legacy_names):
        value = os.environ.get(candidate)
        if value is not None:
            return value
    return default


HERMES_HOME = Path(env_value("HERMES_HOME", str(HOME / ".hermes")))
RC_PATH = Path(env_value("HERMES_ZULIP_RC", str(HERMES_HOME / "zuliprc"), "ZULIPRC"))
STATE_PATH = Path(env_value("HERMES_ZULIP_NOTIFIER_STATE", str(HERMES_HOME / "state/zulip_kanban_notifier.json"), "ZULIP_KANBAN_NOTIFIER_STATE"))
AGENTOS_URL = env_value("HERMES_KANBAN_URL", "http://127.0.0.1:9120", "AGENTOS_URL").rstrip("/")  # agentos-env-ok: optional local-dev default.
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
    event = str(parts[0]) if parts and re.fullmatch(r"[a-z][a-z0-9_]*", str(parts[0])) else "event"
    values = [part if type(part) is int else opaque_log_value(part) for part in parts[1:]]
    print(time.strftime("%Y-%m-%dT%H:%M:%S%z"), event, *values, flush=True)


def strict_positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value <= 2**63 - 1 else None
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,18}", value):
        parsed = int(value)
        return parsed if parsed <= 2**63 - 1 else None
    return None


def load_rc(path: Path = RC_PATH) -> dict[str, str]:
    cp = configparser.ConfigParser()
    try:
        cp.read_string(secure_read_text(path, MAX_ZULIPRC_BYTES, label="zuliprc"))
        rc = {key: cp["api"][key].strip() for key in ("email", "key", "site")}
        rc["site"] = rc["site"].rstrip("/")
        if not all(rc.values()):
            raise ValueError("incomplete Zulip credentials")
        return rc
    except (ValueError, configparser.Error, KeyError) as exc:
        raise SystemExit("zuliprc is missing, malformed, or unsafe") from exc


def auth_header(rc: dict[str, str]) -> str:
    return "Basic " + base64.b64encode(f"{rc['email']}:{rc['key']}".encode()).decode()


def request_json(method: str, url: str, *, headers: dict[str, str] | None = None, data: dict[str, Any] | None = None, timeout: float = 30) -> dict[str, Any]:
    body = None
    req_headers = dict(headers or {})
    if data is not None:
        encoded = urllib.parse.urlencode(data, doseq=True)
        if method == "GET":
            url += ("&" if "?" in url else "?") + encoded
        else:
            body = encoded.encode()
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_STATE_BYTES + 1)
            if len(raw) > MAX_STATE_BYTES:
                raise RuntimeError("remote response exceeds limit")
            payload = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(payload, dict):
                raise RuntimeError("remote response schema is invalid")
            return payload
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"request failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("request failed") from exc


def zulip_api(rc: dict[str, str], method: str, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return request_json(method, rc["site"] + path, headers={"Authorization": auth_header(rc), "User-Agent": "Hermes-Kanban-Zulip-Notifier"}, data=data)


def post_zulip_message(rc: dict[str, str], stream_id: int, topic: str, content: str) -> dict[str, Any]:
    if strict_positive_int(stream_id) is None or not topic:
        raise ValueError("numeric Zulip stream ID and topic are required")
    return zulip_api(rc, "POST", "/api/v1/messages", {"type": "stream", "to": stream_id, "topic": topic, "content": content[:9000]})


def post_zulip_direct_message(rc: dict[str, str], to: str, content: str) -> dict[str, Any]:
    if not str(to or "").strip():
        raise ValueError("Zulip direct-message recipient is required")
    return zulip_api(rc, "POST", "/api/v1/messages", {"type": "private", "to": to, "content": content[:9000]})


def fetch_zulip_message(rc: dict[str, str], message_id: object) -> dict[str, Any]:
    parsed = strict_positive_int(message_id)
    if parsed is None:
        raise RouteError("origin message ID is invalid")
    payload = zulip_api(rc, "GET", f"/api/v1/messages/{parsed}", {"apply_markdown": "false"})
    message = payload.get("message") if isinstance(payload, dict) else None
    if not isinstance(message, dict) or strict_positive_int(message.get("id")) != parsed:
        raise RouteError("origin lookup did not return the exact message")
    return message


def _verified_origin(rc: dict[str, str], origin_message_id: int, stream_id: int) -> dict[str, Any]:
    message = fetch_zulip_message(rc, origin_message_id)
    topic = str(message.get("subject") if message.get("subject") is not None else message.get("topic") or "").strip()
    sender_email = str(message.get("sender_email") or "").strip()
    if (
        strict_positive_int(message.get("id")) != origin_message_id
        or message.get("type") != "stream"
        or strict_positive_int(message.get("stream_id")) != stream_id
        or not topic
        or strict_positive_int(message.get("sender_id")) is None
        or not sender_email
        or message.get("sender_is_bot") is not False
        or sender_email == str(rc.get("email") or "")
    ):
        raise RouteError("origin message scope is invalid")
    return {**message, "id": origin_message_id, "stream_id": stream_id, "topic": topic}


def target_delivery_type(target: dict[str, Any]) -> str:
    raw = str(target.get("type") or target.get("message_type") or target.get("delivery") or "stream").strip().lower()
    return "direct" if raw in {"dm", "direct", "direct_message", "private", "pm"} else "stream"


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


def current_zulip_target(rc: dict[str, str], target: dict[str, Any]) -> dict[str, Any]:
    if target_delivery_type(target) == "direct":
        recipient = direct_recipient_for_target(target)
        if not recipient:
            raise RouteError("direct-message recipient is invalid")
        return {**target, "type": "direct", "to": recipient}
    origin_id = strict_positive_int(target.get("message_id"))
    stream_id = strict_positive_int(target.get("stream_id"))
    if origin_id is None or stream_id is None:
        raise RouteError("notification target lacks durable numeric origin scope")
    origin = _verified_origin(rc, origin_id, stream_id)
    return {**target, "message_id": origin_id, "stream_id": stream_id, "topic": origin["topic"]}


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
            if isinstance(task, dict):
                row = dict(task)
                row.setdefault("status", status)
                tasks.append(row)
    if not tasks and isinstance(board_payload.get("tasks"), list):
        tasks = [task for task in board_payload["tasks"] if isinstance(task, dict)]
    if len(tasks) > MAX_NOTIFIED:
        raise StateError("notifier board exceeds task limit")
    return tasks


def _candidate_text_fields(task: dict[str, Any]) -> str:
    return "\n".join(value for key in ("description", "body", "details", "content", "notes") if isinstance((value := task.get(key)), str))


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
    metadata = task.get("metadata") if isinstance(task.get("metadata"), dict) else {}
    source = task.get("source_detail") if isinstance(task.get("source_detail"), dict) else {}
    candidates = [*(task.get(key) for key in ("notification_target", "notify_target", "origin")), *(metadata.get(key) for key in ("notification_target", "notify_target", "origin")), *(source.get(key) for key in ("notification_target", "notify_target", "origin")), *_parse_json_blocks(_candidate_text_fields(task))]
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
        origin_id = strict_positive_int(target.get("message_id"))
        stream_id = strict_positive_int(target.get("stream_id"))
        if origin_id is not None and stream_id is not None:
            return {**target, "message_id": origin_id, "stream_id": stream_id}
    return None


def task_identity(task: dict[str, Any]) -> str:
    for name in ("id", "task_id", "uuid"):
        value = task.get(name)
        if isinstance(value, bool) or not isinstance(value, str | int):
            continue
        identity = str(value).strip()
        if identity and len(identity) <= 512:
            return identity
    raise StateError("notifier task identity is invalid")


def task_status(task: dict[str, Any]) -> str:
    return str(task.get("status") or "").strip().lower()


def _strict_revision_integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 2**63 - 1 else None
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        parsed = int(value)
        return parsed if parsed <= 2**63 - 1 else None
    return None


def _strict_revision_timestamp(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        parsed = float(value)
        return int(parsed * 1_000_000) if math.isfinite(parsed) and 0 <= parsed <= 10**11 else None
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        return None
    try:
        parsed_time = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed_time.tzinfo is None:
        return None
    timestamp = parsed_time.timestamp()
    return int(timestamp * 1_000_000) if math.isfinite(timestamp) and 0 <= timestamp <= 10**11 else None


def task_revision(task: dict[str, Any]) -> str:
    versions = []
    for name in ("version", "revision", "task_version"):
        if name not in task or task[name] is None:
            continue
        parsed = _strict_revision_integer(task[name])
        if parsed is None:
            raise StateError("notifier task revision is invalid or incomparable")
        versions.append(parsed)
    if versions:
        if len(set(versions)) != 1:
            raise StateError("notifier task revision is invalid or incomparable")
        return f"v:{versions[0]:020d}"

    timestamps = []
    for name in ("updated_at", "completed_at", "blocked_at", "last_heartbeat_at"):
        if name not in task or task[name] is None:
            continue
        parsed = _strict_revision_timestamp(task[name])
        if parsed is None:
            raise StateError("notifier task revision is invalid or incomparable")
        timestamps.append(parsed)
    if not timestamps:
        raise StateError("notifier task revision is invalid or incomparable")
    return f"t:{max(timestamps):020d}"


def _compare_revisions(left: str | None, right: str | None) -> int:
    if (
        not isinstance(left, str)
        or not isinstance(right, str)
        or re.fullmatch(r"[vt]:[0-9]{20}", left) is None
        or re.fullmatch(r"[vt]:[0-9]{20}", right) is None
        or left[:2] != right[:2]
    ):
        raise StateError("notifier task revisions are incomparable")
    return (left > right) - (left < right)


def task_signature(task: dict[str, Any]) -> str:
    selected = {
        key: task.get(key)
        for key in ("id", "task_id", "uuid", "status", "title", "assignee", "summary", "result", "block_reason")
    }
    selected["revision"] = task_revision(task)
    try:
        payload = json.dumps(selected, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError) as exc:
        raise StateError("notifier task revision schema is invalid") from exc
    return hashlib.sha256(payload).hexdigest()


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
    lines.append("\nCoding workflow result: blocked; human or upstream action may be needed." if status == "blocked" else "\nCoding workflow result: implementation and required review cycle are complete.")
    return "\n".join(lines)


def _retry_delay(attempts: int) -> float:
    return min(RETRY_BASE_SECONDS * 2 ** max(0, attempts - 1), RETRY_MAX_SECONDS)


def _marker(key: bytes, task_id: str, signature: str) -> str:
    digest = hmac.new(key, f"{task_id}\0{signature}".encode(), hashlib.sha256).hexdigest()
    return f"<!-- hermes-notifier:{digest} -->"


def _job_for_task(task: dict[str, Any], target: dict[str, Any], key: bytes, now: float) -> dict[str, Any]:
    task_id = task_identity(task)
    signature = task_signature(task)
    marker = _marker(key, task_id, signature)
    content = notification_body(task, target)[: 9000 - len(marker) - 2] + "\n\n" + marker
    job = {
        "ref": hashlib.sha256(marker.encode()).hexdigest()[:24],
        "task_id": task_id,
        "signature": signature,
        "revision": task_revision(task),
        "type": target_delivery_type(target),
        "origin_message_id": strict_positive_int(target.get("message_id")),
        "stream_id": strict_positive_int(target.get("stream_id")),
        "recipient": direct_recipient_for_target(target) if target_delivery_type(target) == "direct" else "",
        "content": content,
        "content_digest": hashlib.sha256(content.encode()).hexdigest(),
        "marker": marker,
        "stage": "admitted",
        "sent_message_id": None,
        "attempts": 0,
        "created_at": now,
        "next_attempt_at": now,
    }
    if job["type"] == "stream" and (job["origin_message_id"] is None or job["stream_id"] is None):
        raise RouteError("stream target lacks durable numeric origin scope")
    return job


def _state_payload(state: dict[str, Any]) -> bytes:
    clean = {key: value for key, value in state.items() if key != "hmac"}
    return json.dumps(clean, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _state_tag(state: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _state_payload(state), hashlib.sha256).hexdigest()


def _validate_state(state: object) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise StateError("notifier state root is invalid")
    if state.get("version") != STATE_VERSION or set(state) - {"version", "notified", "revisions", "outbox", "dead_letters", "hmac"}:
        raise StateError("notifier state schema version is invalid")
    notified = state.get("notified", {})
    revisions = state.get("revisions", {})
    outbox, dead = state.get("outbox", []), state.get("dead_letters", [])
    if not isinstance(notified, dict) or len(notified) > MAX_NOTIFIED or any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for key, value in notified.items()
    ):
        raise StateError("notifier notified registry is invalid")
    if not isinstance(revisions, dict) or len(revisions) > MAX_NOTIFIED:
        raise StateError("notifier revision registry is invalid")
    for task_id, metadata in revisions.items():
        if (
            not isinstance(task_id, str)
            or not isinstance(metadata, dict)
            or set(metadata) != {"revision", "signature"}
            or (
                metadata["revision"] is not None
                and (
                    not isinstance(metadata["revision"], str)
                    or re.fullmatch(r"[vt]:[0-9]{20}", metadata["revision"]) is None
                )
            )
            or not isinstance(metadata["signature"], str)
            or re.fullmatch(r"[0-9a-f]{64}", metadata["signature"]) is None
        ):
            raise StateError("notifier revision registry is invalid")
    if not isinstance(outbox, list) or len(outbox) > MAX_OUTBOX or not isinstance(dead, list) or len(dead) > MAX_DEAD_LETTERS:
        raise StateError("notifier durable queues are invalid or full")
    required = {"ref", "task_id", "signature", "revision", "type", "origin_message_id", "stream_id", "recipient", "content", "content_digest", "marker", "stage", "sent_message_id", "attempts", "created_at", "next_attempt_at"}
    outbox_task_ids: set[str] = set()
    for job in outbox:
        if not isinstance(job, dict) or set(job) != required or job["type"] not in {"stream", "direct"} or job["stage"] not in {"admitted", "post_started", "posted", "operator_review"}:
            raise StateError("notifier outbox entry is invalid")
        if any(not isinstance(job[name], str) for name in ("ref", "task_id", "signature", "recipient", "content", "content_digest", "marker", "stage")) or len(job["content"]) > 9000:
            raise StateError("notifier outbox content is invalid")
        if not isinstance(job["attempts"], int) or isinstance(job["attempts"], bool) or not 0 <= job["attempts"] <= MAX_ATTEMPTS:
            raise StateError("notifier outbox attempts are invalid")
        if (
            job["task_id"] in outbox_task_ids
            or re.fullmatch(r"[0-9a-f]{64}", job["signature"]) is None
            or (
                job["revision"] is not None
                and (
                    not isinstance(job["revision"], str)
                    or re.fullmatch(r"[vt]:[0-9]{20}", job["revision"]) is None
                )
            )
        ):
            raise StateError("notifier outbox task revision is invalid")
        outbox_task_ids.add(job["task_id"])
        if job["type"] == "stream" and (strict_positive_int(job["origin_message_id"]) is None or strict_positive_int(job["stream_id"]) is None):
            raise StateError("notifier outbox route is invalid")
        if job["sent_message_id"] is not None and strict_positive_int(job["sent_message_id"]) is None:
            raise StateError("notifier sent message ID is invalid")
        if hashlib.sha256(job["content"].encode()).hexdigest() != job["content_digest"] or job["marker"] not in job["content"]:
            raise StateError("notifier outbox integrity is invalid")
        if not all(isinstance(job[name], int | float) and not isinstance(job[name], bool) and 0 <= job[name] <= 10**11 for name in ("created_at", "next_attempt_at")):
            raise StateError("notifier outbox timestamps are invalid")
        metadata = revisions.get(job["task_id"])
        if not isinstance(metadata, dict):
            raise StateError("notifier outbox revision reservation is missing")
        if job["revision"] is None:
            if metadata["revision"] is not None or metadata["signature"] != job["signature"]:
                raise StateError("notifier outbox revision reservation is invalid")
        elif metadata["revision"] is None or _compare_revisions(metadata["revision"], job["revision"]) < 0:
            raise StateError("notifier outbox revision reservation is invalid")
    if any(task_id not in revisions for task_id in notified):
        raise StateError("notifier notified revision reservation is invalid")
    _require_notified_capacity(state)
    for item in dead:
        if (
            not isinstance(item, dict)
            or set(item) != {"ref", "reason", "attempts", "terminal_at"}
            or not isinstance(item["ref"], str)
            or not isinstance(item["reason"], str)
            or len(item["reason"]) > 200
            or not isinstance(item["attempts"], int)
            or isinstance(item["attempts"], bool)
            or not 0 <= item["attempts"] <= MAX_ATTEMPTS
            or not isinstance(item["terminal_at"], int | float)
            or isinstance(item["terminal_at"], bool)
            or not 0 <= item["terminal_at"] <= 10**11
        ):
            raise StateError("notifier dead letter is invalid")
    return state


def _reserved_task_ids(state: dict[str, Any]) -> set[str]:
    return set(state.get("notified", {})) | set(state.get("revisions", {})) | {
        job["task_id"] for job in state.get("outbox", []) if isinstance(job, dict) and isinstance(job.get("task_id"), str)
    }


def _require_notified_capacity(state: dict[str, Any], new_task_ids: set[str] | None = None) -> None:
    if len(_reserved_task_ids(state) | (new_task_ids or set())) > MAX_NOTIFIED:
        raise StateError("notifier notified capacity is exhausted")


def signing_key_path(path: Path) -> Path:
    return Path(str(path) + ".signing-key")


def _secure_state_bytes(path: Path, *, allow_legacy: bool = False) -> bytes:
    target = path.expanduser().absolute()
    _trusted_ancestry(target)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        linked = target.lstat()
        fd = os.open(target, flags)
    except OSError as exc:
        raise StateError("notifier state is unavailable or unsafe") from exc
    try:
        opened = os.fstat(fd)
        mode = stat.S_IMODE(opened.st_mode)
        allowed = {0o600, 0o644} if allow_legacy else {0o600}
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid() or opened.st_nlink != 1 or mode not in allowed or stat.S_IMODE(linked.st_mode) != mode or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
            raise StateError("notifier state is unavailable or unsafe")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(65536, MAX_STATE_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_STATE_BYTES:
                raise StateError("notifier state exceeds limit")
        raw = b"".join(chunks)
        after = target.lstat()
        if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino) or after.st_nlink != 1:
            raise StateError("notifier state changed during read")
        return raw
    except OSError as exc:
        raise StateError("notifier state is unavailable or unsafe") from exc
    finally:
        os.close(fd)


def _read_key(path: Path) -> bytes:
    raw = _secure_state_bytes(path)
    if len(raw) != SIGNING_KEY_BYTES:
        raise StateError("notifier signing key is corrupt")
    return raw


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.parent.stat().st_uid != os.geteuid() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise StateError("notifier state directory is unsafe")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    directory_fd = -1
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        os.fsync(directory_fd)
    except OSError as exc:
        raise StateError("notifier state persistence failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _create_key(path: Path) -> bytes:
    key = secrets.token_bytes(SIGNING_KEY_BYTES)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
    except OSError as exc:
        raise StateError("notifier signing key creation failed") from exc
    try:
        os.fchmod(fd, 0o600)
        if os.write(fd, key) != len(key):
            raise StateError("notifier signing key write failed")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
    except OSError as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise StateError("notifier signing key publication failed") from exc
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return _read_key(path)


def _migrate_state(state: dict[str, Any]) -> bool:
    if state.get("version") == STATE_VERSION:
        return False
    if state.get("version") != 2 or set(state) - {"version", "notified", "outbox", "dead_letters"}:
        raise StateError("notifier state schema version is invalid")
    notified = state.get("notified", {})
    outbox = state.get("outbox", [])
    if not isinstance(notified, dict) or not isinstance(outbox, list):
        raise StateError("notifier legacy state schema is invalid")
    revisions: dict[str, dict[str, str | None]] = {}
    for task_id, signature in notified.items():
        if not isinstance(task_id, str) or not isinstance(signature, str):
            raise StateError("notifier legacy state schema is invalid")
        revisions[task_id] = {"revision": None, "signature": signature}
    for job in outbox:
        if not isinstance(job, dict) or not isinstance(job.get("task_id"), str) or not isinstance(job.get("signature"), str):
            raise StateError("notifier legacy state schema is invalid")
        existing = revisions.get(job["task_id"])
        if existing is not None and existing["signature"] != job["signature"]:
            raise StateError("notifier legacy task revisions are incomparable")
        revisions[job["task_id"]] = {"revision": None, "signature": job["signature"]}
        job["revision"] = None
    state["version"] = STATE_VERSION
    state["revisions"] = revisions
    return True


def load_state(path: Path) -> tuple[dict[str, Any], bytes]:
    key_path = signing_key_path(path)
    try:
        raw = _secure_state_bytes(path, allow_legacy=True)
    except StateError:
        if path.exists() or path.is_symlink():
            raise
        state = {"version": STATE_VERSION, "notified": {}, "revisions": {}, "outbox": [], "dead_letters": []}
        key = _read_key(key_path) if key_path.exists() else _create_key(key_path)
        save_state(path, state, key)
        return state, key
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StateError("notifier state is corrupt") from exc
    if not isinstance(state, dict):
        raise StateError("notifier state root is invalid")
    signed = "hmac" in state or "version" in state or "outbox" in state or "dead_letters" in state
    if signed:
        key = _read_key(key_path)
        supplied = state.pop("hmac", None)
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, _state_tag(state, key)):
            raise StateError("notifier state authentication failed")
        migrated = _migrate_state(state)
        _validate_state(state)
        if migrated:
            save_state(path, state, key)
        else:
            state["hmac"] = supplied
        return state, key
    legacy = {"version": 2, "notified": state.get("notified", {}), "outbox": [], "dead_letters": []}
    _migrate_state(legacy)
    _validate_state(legacy)
    key = _create_key(key_path) if not key_path.exists() else _read_key(key_path)
    save_state(path, legacy, key)
    return legacy, key


def save_state(path: Path, state: dict[str, Any], key: bytes) -> None:
    clean = copy.deepcopy(state)
    clean.pop("hmac", None)
    clean["version"] = STATE_VERSION
    _validate_state(clean)
    clean["hmac"] = _state_tag(clean, key)
    payload = (json.dumps(clean, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
    if len(payload) > MAX_STATE_BYTES:
        raise StateError("notifier state exceeds limit")
    _atomic_write(path, payload)


def _dead_letter(state: dict[str, Any], job: dict[str, Any], reason: str, now: float) -> None:
    dead = state.setdefault("dead_letters", [])
    if len(dead) >= MAX_DEAD_LETTERS:
        job["stage"] = "operator_review"
        job["attempts"] = min(job["attempts"], MAX_ATTEMPTS)
        job["next_attempt_at"] = 10**11
        return
    dead.append({"ref": job["ref"], "reason": reason, "attempts": job["attempts"], "terminal_at": now})
    state["outbox"] = [item for item in state.get("outbox", []) if item is not job]


def _direct_identity(value: object) -> frozenset[str] | None:
    if isinstance(value, bool):
        return None
    if (user_id := strict_positive_int(value)) is not None:
        return frozenset({f"id:{user_id}"})
    if isinstance(value, str):
        email = value.strip().lower()
        if email and "@" in email and not any(character.isspace() for character in email):
            return frozenset({f"email:{email}"})
    return None


def _expected_direct_identities(rc: dict[str, str], recipient: str) -> list[frozenset[str]] | None:
    try:
        parsed = json.loads(recipient)
    except json.JSONDecodeError:
        values: list[object] = [recipient]
    else:
        values = parsed if isinstance(parsed, list) else [parsed]
    bot = {
        identity
        for value in (rc.get("user_id"), rc.get("email"))
        if (tokens := _direct_identity(value)) is not None
        for identity in tokens
    }
    identities: list[frozenset[str]] = []
    for value in values:
        tokens = _direct_identity(value)
        if tokens is None:
            return None
        if tokens.isdisjoint(bot):
            identities.append(tokens)
    return identities or None


def _actual_direct_identities(rc: dict[str, str], recipients: object) -> list[frozenset[str]] | None:
    if not isinstance(recipients, list):
        return None
    bot = {
        identity
        for value in (rc.get("user_id"), rc.get("email"))
        if (tokens := _direct_identity(value)) is not None
        for identity in tokens
    }
    identities: list[frozenset[str]] = []
    for recipient in recipients:
        if not isinstance(recipient, dict):
            return None
        tokens: set[str] = set()
        if "id" in recipient:
            identity = _direct_identity(recipient["id"])
            if identity is None or not next(iter(identity)).startswith("id:"):
                return None
            tokens.update(identity)
        if "email" in recipient:
            identity = _direct_identity(recipient["email"])
            if identity is None or not next(iter(identity)).startswith("email:"):
                return None
            tokens.update(identity)
        if not tokens:
            return None
        if tokens.isdisjoint(bot):
            identities.append(frozenset(tokens))
    return identities or None


def _direct_identities_match(rc: dict[str, str], expected: str, actual: object) -> bool:
    intended = _expected_direct_identities(rc, expected)
    recipients = _actual_direct_identities(rc, actual)
    if intended is None or recipients is None or len(intended) != len(recipients):
        return False
    remaining = list(recipients)
    for identity in intended:
        matches = [index for index, candidate in enumerate(remaining) if identity <= candidate]
        if len(matches) != 1:
            return False
        remaining.pop(matches[0])
    return not remaining


def _exact_sent_message(rc: dict[str, str], job: dict[str, Any], message: dict[str, Any], route: tuple[int, str] | None) -> bool:
    topic = str(message.get("subject") if message.get("subject") is not None else message.get("topic") or "").strip()
    if strict_positive_int(message.get("id")) is None or str(message.get("sender_email") or "") != str(rc.get("email") or "") or not hmac.compare_digest(hashlib.sha256(str(message.get("content") or "").encode()).hexdigest(), job["content_digest"]):
        return False
    if job["type"] == "direct":
        return message.get("type") in {"private", "direct"} and _direct_identities_match(
            rc, job["recipient"], message.get("display_recipient")
        )
    return message.get("type") == "stream" and route is not None and strict_positive_int(message.get("stream_id")) == route[0] and topic == route[1]


def _reconcile(rc: dict[str, str], job: dict[str, Any], route: tuple[int, str] | None) -> bool:
    sent_id = strict_positive_int(job.get("sent_message_id"))
    if sent_id is not None:
        return _exact_sent_message(rc, job, fetch_zulip_message(rc, sent_id), route)
    narrow = json.dumps([{"operator": "search", "operand": job["marker"]}], separators=(",", ":"))
    payload = zulip_api(rc, "GET", "/api/v1/messages", {"anchor": "newest", "num_before": 100, "num_after": 0, "narrow": narrow, "apply_markdown": "false"})
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list):
        raise RouteError("notification reconciliation schema is invalid")
    matches = [message for message in messages if isinstance(message, dict) and _exact_sent_message(rc, job, message, route)]
    if len(matches) == 1:
        job["sent_message_id"] = strict_positive_int(matches[0].get("id"))
        return True
    if len(matches) > 1:
        raise RouteError("notification reconciliation is ambiguous")
    return False


def _deliver_job(state: dict[str, Any], job: dict[str, Any], rc: dict[str, str], persist: Callable[[], None], now: float) -> str:
    if job not in state.get("outbox", []):
        raise StateError("notifier delivery reservation is unavailable")
    _require_notified_capacity(state)
    if job["stage"] == "operator_review":
        return "operator_review"
    route: tuple[int, str] | None = None
    if job["type"] == "stream":
        try:
            target = current_zulip_target(
                rc,
                {"message_id": job["origin_message_id"], "stream_id": job["stream_id"]},
            )
        except Exception:
            job["attempts"] = min(job["attempts"] + 1, MAX_ATTEMPTS)
            if job["attempts"] >= MAX_ATTEMPTS:
                _dead_letter(state, job, "operator_review_origin_unavailable", now)
                persist()
                return "operator_review"
            job["next_attempt_at"] = now + _retry_delay(job["attempts"])
            persist()
            return "pending"
        route = (job["stream_id"], target["topic"])
    if job["stage"] != "admitted":
        try:
            delivered = _reconcile(rc, job, route)
        except Exception:
            delivered = False
        if delivered:
            state["notified"][job["task_id"]] = job["signature"]
            state["outbox"] = [item for item in state["outbox"] if item is not job]
            persist()
            return "delivered"
        job["attempts"] = min(job["attempts"] + 1, MAX_ATTEMPTS)
        if job["attempts"] >= MAX_ATTEMPTS:
            _dead_letter(state, job, "operator_review_uncertain_post", now)
            persist()
            return "operator_review"
        job["next_attempt_at"] = now + _retry_delay(job["attempts"])
        persist()
        return "pending"

    if job["attempts"] >= MAX_ATTEMPTS:
        _dead_letter(state, job, "operator_review_retry_limit", now)
        persist()
        return "operator_review"
    job["stage"] = "post_started"
    job["attempts"] = min(job["attempts"] + 1, MAX_ATTEMPTS)
    persist()
    try:
        response = post_zulip_direct_message(rc, job["recipient"], job["content"]) if job["type"] == "direct" else post_zulip_message(rc, route[0], route[1], job["content"])
    except BaseException:
        job["next_attempt_at"] = now + _retry_delay(job["attempts"])
        persist()
        raise
    sent_id = strict_positive_int(response.get("id")) if isinstance(response, dict) else None
    if sent_id is None:
        job["next_attempt_at"] = now + _retry_delay(job["attempts"])
        persist()
        raise RouteError("notification POST returned no stable message ID")
    job["sent_message_id"] = sent_id
    job["stage"] = "posted"
    persist()
    if not _reconcile(rc, job, route):
        job["next_attempt_at"] = now + _retry_delay(job["attempts"])
        persist()
        return "pending"
    state["notified"][job["task_id"]] = job["signature"]
    state["outbox"] = [item for item in state["outbox"] if item is not job]
    persist()
    return "delivered"


def _latest_board_tasks(board: dict[str, Any]) -> dict[str, tuple[dict[str, Any], dict[str, Any], str, str]]:
    latest: dict[str, tuple[dict[str, Any], dict[str, Any], str, str]] = {}
    for task in flatten_tasks(board):
        target = zulip_target_for_task(task)
        if target is None:
            continue
        task_id = task_identity(task)
        revision = task_revision(task)
        signature = task_signature(task)
        existing = latest.get(task_id)
        if existing is None:
            latest[task_id] = (task, target, revision, signature)
            continue
        comparison = _compare_revisions(revision, existing[2])
        if comparison == 0 and signature != existing[3]:
            raise StateError("notifier task revisions are incomparable")
        if comparison > 0:
            latest[task_id] = (task, target, revision, signature)
    return latest


def scan_once(state: dict[str, Any], rc: dict[str, str] | None, *, send: bool, prime: bool = False, key: bytes | None = None, persist: Callable[[], None] | None = None, now: float | None = None) -> dict[str, int]:
    current = time.time() if now is None else now
    key = key or secrets.token_bytes(SIGNING_KEY_BYTES)
    persist = persist or (lambda: None)
    _validate_state(state)
    board = fetch_kanban_board()
    counts = {"admitted": 0, "delivered": 0, "pending": 0, "primed": 0, "operator_review": 0}
    notified = state["notified"]
    revisions = state["revisions"]
    outbox = state["outbox"]
    latest = _latest_board_tasks(board)
    _require_notified_capacity(state, set(latest))
    plans: list[dict[str, Any]] = []
    future_outbox_size = len(outbox)

    for task_id in sorted(latest):
        task, target, revision, signature = latest[task_id]
        metadata = revisions.get(task_id)
        metadata_comparison = 1
        if metadata is not None:
            metadata_comparison = _compare_revisions(revision, metadata["revision"])
            if metadata_comparison < 0:
                continue
            if metadata_comparison == 0 and signature != metadata["signature"]:
                raise StateError("notifier task revisions are incomparable")

        existing = next((job for job in outbox if job["task_id"] == task_id), None)
        replace = False
        blocked = False
        if existing is not None:
            comparison = _compare_revisions(revision, existing["revision"])
            if comparison < 0:
                continue
            if comparison == 0:
                if signature != existing["signature"]:
                    raise StateError("notifier task revisions are incomparable")
            elif existing["stage"] == "admitted":
                replace = True
                future_outbox_size -= 1
            else:
                blocked = True

        operation = "none"
        if (
            task_status(task) in TERMINAL_STATUSES
            and not (existing is not None and existing["revision"] == revision)
            and not blocked
            and notified.get(task_id) != signature
        ):
            if not send and not prime:
                operation = "count"
            elif prime:
                operation = "prime"
            else:
                operation = "admit"
                future_outbox_size += 1
        plans.append(
            {
                "task": task,
                "target": target,
                "task_id": task_id,
                "revision": revision,
                "signature": signature,
                "update_revision": metadata_comparison > 0,
                "existing": existing,
                "replace": replace,
                "operation": operation,
            }
        )

    if future_outbox_size > MAX_OUTBOX:
        raise StateError("notifier outbox is full")
    if not send and not prime:
        counts["admitted"] = sum(plan["operation"] == "count" for plan in plans)
        counts["pending"] = len(outbox)
        return counts
    changed = False
    for plan in plans:
        if plan["replace"]:
            outbox.remove(plan["existing"])
            changed = True
        if plan["update_revision"]:
            revisions[plan["task_id"]] = {"revision": plan["revision"], "signature": plan["signature"]}
            changed = True
        if plan["operation"] == "count":
            counts["admitted"] += 1
        elif plan["operation"] == "prime":
            notified[plan["task_id"]] = plan["signature"]
            counts["primed"] += 1
            changed = True
        elif plan["operation"] == "admit":
            outbox.append(_job_for_task(plan["task"], plan["target"], key, current))
            counts["admitted"] += 1
            changed = True

    if changed and (send or prime):
        persist()
    if send:
        if rc is None:
            raise ValueError("Zulip credentials are required")
        due = [
            job
            for job in list(outbox)
            if job["stage"] != "operator_review" and job["next_attempt_at"] <= current
        ][:MAX_WORK_PER_SCAN]
        for job in due:
            try:
                result = _deliver_job(state, job, rc, persist, current)
            except Exception as exc:
                log("notification_pending", job["ref"], type(exc).__name__)
                counts["pending"] += 1
            else:
                counts[result] += 1
    else:
        counts["pending"] = len(outbox)
    return counts


def main(rc: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Notify Zulip when Kanban tasks reach terminal status.")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--prime", action="store_true")
    args = parser.parse_args()
    if rc is None:
        rc = load_rc()
    try:
        with process_lock(STATE_PATH) as held:
            state, key = load_state(held.state_path)
            persist = lambda: save_state(held.state_path, state, key)
            while True:
                try:
                    counts = scan_once(state, rc, send=not args.dry_run and not args.prime, prime=args.prime, key=key, persist=persist)
                    if args.dry_run:
                        print(json.dumps({"ok": True, "counts": counts}, sort_keys=True))
                    else:
                        log("notifier_scan", sum(counts.values()))
                except Exception as exc:
                    log("scan_failed", type(exc).__name__)
                    if args.once or args.dry_run or args.prime:
                        return 1
                if args.once or args.dry_run or args.prime:
                    return 0
                time.sleep(POLL_SECONDS)
    except (ProcessLockError, StateError) as exc:
        log("notifier_start_failed", type(exc).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
