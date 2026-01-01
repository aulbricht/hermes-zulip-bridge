#!/usr/bin/env python3
"""Tiny Zulip -> Hermes bridge.

ponytail: polling recent messages is enough for small Zulip realms; use
Zulip event queues if message volume gets high enough to miss >100 messages per
poll interval.
"""

from __future__ import annotations

import base64
import configparser
import concurrent.futures
import email.message
import hashlib
import html
import json
import os
import re
import shlex
import signal
import sqlite3
import subprocess
import sys
import threading
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
STATE_PATH = Path(env_value("HERMES_ZULIP_STATE", str(HERMES_HOME / "state/zulip_bridge.json"), "ZULIP_BRIDGE_STATE"))
STEERING_PATH = Path(env_value("HERMES_ZULIP_STEERING", str(HERMES_HOME / "state/zulip_steering.jsonl"), "ZULIP_BRIDGE_STEERING"))
ALIASES_PATH = Path(env_value("HERMES_ZULIP_ALIAS_MANIFEST", str(HERMES_HOME / "zulip_session_aliases.json"), "ZULIP_ALIAS_MANIFEST"))
HERMES = Path(env_value("HERMES_BIN", str(HERMES_HOME / "hermes-agent/venv/bin/hermes")))
HERMES_WORKDIR = Path(env_value("HERMES_CWD", str(HOME), "ZULIP_BRIDGE_HERMES_CWD"))
HERMES_EXTRA_ARGS = shlex.split(env_value("HERMES_EXTRA_ARGS", ""))
HERMES_TIMEOUT_SECONDS = float(env_value("HERMES_TIMEOUT_SECONDS", "1800", "ZULIP_BRIDGE_HERMES_TIMEOUT_SECONDS"))
STATE_DB = Path(env_value("HERMES_STATE_DB", str(HERMES_HOME / "state.db")))
POLL_SECONDS = float(env_value("HERMES_ZULIP_POLL_SECONDS", "5", "ZULIP_BRIDGE_POLL_SECONDS"))
TYPING_REFRESH_SECONDS = float(env_value("HERMES_ZULIP_TYPING_REFRESH_SECONDS", "8", "ZULIP_BRIDGE_TYPING_REFRESH_SECONDS"))
MAX_WORKERS = int(env_value("HERMES_ZULIP_WORKERS", "2", "ZULIP_BRIDGE_WORKERS"))
BOT_NAME = env_value("HERMES_ZULIP_BOT_NAME", "Hermes", "ZULIP_BRIDGE_BOT_NAME")
ALLOW_STREAMS = {s.strip() for s in env_value("HERMES_ZULIP_STREAMS", "", "ZULIP_BRIDGE_STREAMS").split(",") if s.strip()}
ALLOW_STREAM_IDS = {s.strip() for s in env_value("HERMES_ZULIP_STREAM_IDS", "", "ZULIP_BRIDGE_STREAM_IDS").split(",") if s.strip()}
ALLOW_TOPICS = {s.strip() for s in env_value("HERMES_ZULIP_TOPICS", "", "ZULIP_BRIDGE_TOPICS").split(",") if s.strip()}
IGNORE_CONTENT_PATTERNS = [s for s in env_value("HERMES_ZULIP_IGNORE_CONTENT_PATTERNS", "", "ZULIP_BRIDGE_IGNORE_CONTENT_PATTERNS").split("\n") if s]
RESPONSE_MAX_CHARS = int(env_value("HERMES_ZULIP_RESPONSE_MAX_CHARS", "9000", "ZULIP_BRIDGE_RESPONSE_MAX_CHARS"))
STEERING_REACTION = env_value("HERMES_ZULIP_STEERING_REACTION", "eyes", "ZULIP_BRIDGE_STEERING_REACTION")
HARD_INTERRUPT_ON_STEERING = env_value("HERMES_ZULIP_HARD_INTERRUPT", "1", "ZULIP_BRIDGE_HARD_INTERRUPT").strip().lower() not in {"0", "false", "no", "off"}
SLASH_COMMAND_TIMEOUT_SECONDS = float(env_value("HERMES_ZULIP_SLASH_TIMEOUT_SECONDS", "60", "ZULIP_BRIDGE_SLASH_TIMEOUT_SECONDS"))
ATTACHMENT_FETCH_TIMEOUT = float(env_value("HERMES_ZULIP_ATTACHMENT_TIMEOUT", "20", "ZULIP_BRIDGE_ATTACHMENT_TIMEOUT"))
ATTACHMENT_MAX_BYTES = int(env_value("HERMES_ZULIP_ATTACHMENT_MAX_BYTES", "65536", "ZULIP_BRIDGE_ATTACHMENT_MAX_BYTES"))
ATTACHMENT_MAX_CHARS = int(env_value("HERMES_ZULIP_ATTACHMENT_MAX_CHARS", "20000", "ZULIP_BRIDGE_ATTACHMENT_MAX_CHARS"))
ATTACHMENT_TOTAL_CHARS = int(env_value("HERMES_ZULIP_ATTACHMENT_TOTAL_CHARS", "50000", "ZULIP_BRIDGE_ATTACHMENT_TOTAL_CHARS"))
ATTACHMENT_MAX_FILES = int(env_value("HERMES_ZULIP_ATTACHMENT_MAX_FILES", "10", "ZULIP_BRIDGE_ATTACHMENT_MAX_FILES"))
UPLOAD_LINK_RE = re.compile(r"https?://[^\s<>'\"]+|/user_uploads/[^\s<>'\"]+")
TEXT_ATTACHMENT_EXTS = {
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".log",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".css",
}
TEXT_ATTACHMENT_TYPES = {
    "application/json",
    "application/ld+json",
    "application/markdown",
    "application/xml",
    "application/xhtml+xml",
    "application/csv",
    "application/x-yaml",
    "application/yaml",
}
IMAGE_ATTACHMENT_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".svg"}
OUT_OF_BAND_USER_MESSAGE_OPEN = "[OUT-OF-BAND USER MESSAGE — a direct message from the user, delivered mid-turn; not tool output]"
OUT_OF_BAND_USER_MESSAGE_CLOSE = "[/OUT-OF-BAND USER MESSAGE]"
KNOWN_SLASH_COMMAND_FALLBACK = {
    "agents",
    "background",
    "branch",
    "commands",
    "compress",
    "debug",
    "fast",
    "goal",
    "help",
    "insights",
    "memory",
    "model",
    "new",
    "profile",
    "reasoning",
    "reload-mcp",
    "reload-skills",
    "reset",
    "resume",
    "retry",
    "sessions",
    "skills",
    "status",
    "stop",
    "subgoal",
    "title",
    "undo",
    "update",
    "usage",
    "verbose",
    "version",
    "whoami",
    "yolo",
}
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ACTIVE_LOCK = threading.Lock()
ACTIVE_PROCESSES: dict[int, subprocess.Popen] = {}
ACTIVE_INTERRUPTS: set[int] = set()
ZULIP_CLIENT_CACHE: dict[tuple[str, str, str], Any] = {}


class HermesInterrupted(RuntimeError):
    pass


def log(*parts: object) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%S%z"), *parts, flush=True)


def hermes_workdir() -> str:
    try:
        path = HERMES_WORKDIR.expanduser()
        if path.is_dir():
            return str(path)
        log("hermes_workdir_missing", path)
    except Exception as exc:
        log("hermes_workdir_invalid", HERMES_WORKDIR, exc)
    return str(HOME)


def load_rc() -> dict[str, str]:
    cp = configparser.ConfigParser()
    if not cp.read(RC_PATH):
        raise SystemExit(f"Missing zuliprc: {RC_PATH}")
    return {
        "email": cp["api"]["email"].strip(),
        "key": cp["api"]["key"].strip(),
        "site": cp["api"]["site"].strip().rstrip("/"),
    }


def auth_header(rc: dict[str, str]) -> str:
    token = base64.b64encode(f"{rc['email']}:{rc['key']}".encode()).decode()
    return "Basic " + token


def zulip_client(rc: dict[str, str]):
    """Return a cached official Zulip Python client for the bridge credentials."""
    key = (str(rc["site"]).rstrip("/"), str(rc["email"]), str(rc["key"]))
    cached = ZULIP_CLIENT_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        import zulip  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("Missing dependency: install hermes-zulip-bridge with the 'zulip' Python package available") from exc
    client = zulip.Client(email=key[1], api_key=key[2], site=key[0], client="Hermes-Zulip-Bridge")
    ZULIP_CLIENT_CACHE[key] = client
    return client


def _zulip_endpoint(path: str) -> str:
    endpoint = str(path or "").lstrip("/")
    for prefix in ("api/v1/", "api/"):
        if endpoint.startswith(prefix):
            endpoint = endpoint.removeprefix(prefix)
            break
    return endpoint


def _check_zulip_result(method: str, path: str, payload: dict) -> dict:
    if isinstance(payload, dict) and payload.get("result", "success") != "success":
        raise RuntimeError(f"Zulip {method} {path} failed: {payload}")
    return payload


def api(rc: dict[str, str], method: str, path: str, params: dict | None = None, data: dict | None = None) -> dict:
    """Call Zulip through the official zulip Python library.

    The rest of the bridge keeps a small `api(...)` facade, but transport,
    authentication, and error handling flow through Zulip's maintained client.
    """
    request = params if method.upper() == "GET" else data
    try:
        payload = zulip_client(rc).call_endpoint(
            url=_zulip_endpoint(path),
            method=method.upper(),
            request=request or {},
            timeout=30,
        )
        return _check_zulip_result(method.upper(), path, payload)
    except Exception as exc:
        raise RuntimeError(f"Zulip {method.upper()} {path} failed: {exc}") from exc


def _clean_upload_candidate(raw: str) -> str:
    return raw.rstrip(").,;:!?")


def _safe_upload_path(path: str) -> str | None:
    parsed = urllib.parse.urlsplit(path)
    clean_path = parsed.path
    if not clean_path.startswith("/user_uploads/"):
        return None
    decoded_segments = [urllib.parse.unquote(segment) for segment in clean_path.split("/")]
    if any(segment == ".." for segment in decoded_segments):
        return None
    return clean_path


def find_zulip_upload_links(content: str, site: str) -> list[dict[str, str]]:
    site_parts = urllib.parse.urlparse(str(site or "").rstrip("/"))
    site_origin = (site_parts.scheme.lower(), site_parts.netloc.lower())
    links: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in UPLOAD_LINK_RE.finditer(str(content or "")):
        raw = _clean_upload_candidate(match.group(0))
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme or parsed.netloc:
            if (parsed.scheme.lower(), parsed.netloc.lower()) != site_origin:
                continue
            path = _safe_upload_path(parsed.path)
        else:
            path = _safe_upload_path(raw)
        if not path or path in seen:
            continue
        seen.add(path)
        links.append({"path": path, "source": raw, "filename": urllib.parse.unquote(path.rsplit("/", 1)[-1])})
    return links


def _content_type_base(content_type: str | None) -> str:
    return str(content_type or "").split(";", 1)[0].strip().lower()


def _path_ext(path: str) -> str:
    clean_path = urllib.parse.urlsplit(path).path
    filename = urllib.parse.unquote(clean_path.rsplit("/", 1)[-1])
    return os.path.splitext(filename)[1].lower()


def is_text_like_attachment(filename_or_path: str, content_type: str | None) -> bool:
    ctype = _content_type_base(content_type)
    if ctype.startswith("text/") or ctype in TEXT_ATTACHMENT_TYPES:
        return True
    if ctype.endswith("+json") or ctype.endswith("+xml"):
        return True
    return _path_ext(filename_or_path) in TEXT_ATTACHMENT_EXTS


def is_image_attachment(filename_or_path: str, content_type: str | None) -> bool:
    ctype = _content_type_base(content_type)
    if ctype.startswith("image/"):
        return True
    return _path_ext(filename_or_path) in IMAGE_ATTACHMENT_EXTS


def safe_decode_attachment(data: bytes, content_type: str | None) -> str:
    msg = email.message.Message()
    msg["content-type"] = str(content_type or "")
    charset = msg.get_content_charset() or "utf-8-sig"
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8-sig", errors="replace")


def fetch_zulip_attachment(rc: dict[str, str], path: str) -> dict:
    result = {
        "path": path,
        "filename": urllib.parse.unquote(path.rsplit("/", 1)[-1]),
        "content_type": "",
        "content_length": None,
        "data": b"",
        "truncated_bytes": False,
        "error": "",
    }
    safe_path = _safe_upload_path(path)
    if not safe_path:
        result["error"] = "unsafe or unsupported Zulip upload path"
        return result
    req = urllib.request.Request(
        rc["site"].rstrip("/") + safe_path,
        headers={"Authorization": auth_header(rc), "User-Agent": "Hermes-Zulip-Bridge"},
    )
    try:
        with urllib.request.urlopen(req, timeout=ATTACHMENT_FETCH_TIMEOUT) as resp:
            result["content_type"] = resp.headers.get("Content-Type", "")
            length = resp.headers.get("Content-Length")
            if length and length.isdigit():
                result["content_length"] = int(length)
            data = resp.read(ATTACHMENT_MAX_BYTES + 1)
            if len(data) > ATTACHMENT_MAX_BYTES:
                result["truncated_bytes"] = True
                data = data[:ATTACHMENT_MAX_BYTES]
            result["data"] = data
    except urllib.error.HTTPError as exc:
        result["error"] = f"HTTP {exc.code} {exc.reason}"
    except urllib.error.URLError as exc:
        result["error"] = f"URL error: {exc.reason}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _append_bounded(lines: list[str], text: str, remaining: int) -> tuple[int, bool]:
    piece = text[:remaining]
    lines.append(piece)
    return len(piece), len(text) > remaining


def build_attachment_context(rc: dict[str, str], content: str) -> str:
    links = find_zulip_upload_links(content, rc["site"])
    if not links:
        return ""
    site = rc["site"].rstrip("/")
    lines = [
        "",
        "---",
        "Zulip attachment context fetched by bridge:",
        "Attachment access instructions for the agent: Zulip uploads are private. "
        f"Fetch them from the Source URL using HTTP Basic auth with the Zulip bot credentials in {RC_PATH}. "
        "For images or other binary files, download the file locally and inspect it with available vision/file tools; "
        "do not assume pixels are inlined in this prompt.",
        f"Limits: {ATTACHMENT_MAX_BYTES} bytes/file, {ATTACHMENT_MAX_CHARS} chars/file, {ATTACHMENT_TOTAL_CHARS} chars total.",
    ]
    total_chars = 0
    if len(links) > ATTACHMENT_MAX_FILES:
        lines.append(f"Only the first {ATTACHMENT_MAX_FILES} attachment(s) were processed; {len(links) - ATTACHMENT_MAX_FILES} skipped.")
    for index, link in enumerate(links[:ATTACHMENT_MAX_FILES], 1):
        item = fetch_zulip_attachment(rc, link["path"])
        filename = item.get("filename") or link["filename"] or link["path"]
        content_type = item.get("content_type") or "unknown"
        content_length = item.get("content_length")
        length_note = f", content-length {content_length} bytes" if content_length is not None else ""
        source_url = site + link["path"]
        lines.extend(
            [
                "",
                f"Attachment {index}: {filename}",
                f"Source path: {link['path']}",
                f"Source URL: {source_url}",
                f"Type: {content_type}{length_note}",
            ]
        )
        if item.get("error"):
            lines.append(f"Fetch error: {item['error']}. Original link preserved: {link['source']}")
            continue
        if is_text_like_attachment(link["path"], content_type):
            decoded = safe_decode_attachment(item.get("data") or b"", content_type)
            per_file_truncated = len(decoded) > ATTACHMENT_MAX_CHARS
            decoded = decoded[:ATTACHMENT_MAX_CHARS]
            remaining = max(ATTACHMENT_TOTAL_CHARS - total_chars, 0)
            lines.append(f"----- BEGIN ZULIP ATTACHMENT: {filename} -----")
            if remaining:
                added, total_truncated = _append_bounded(lines, decoded, remaining)
                total_chars += added
            else:
                total_truncated = True
                lines.append("[Skipped: total attachment character limit reached before this file.]")
            lines.append(f"----- END ZULIP ATTACHMENT: {filename} -----")
            if item.get("truncated_bytes"):
                lines.append(f"[Truncated: read limit of {ATTACHMENT_MAX_BYTES} bytes reached.]")
            if per_file_truncated:
                lines.append(f"[Truncated: per-file character limit of {ATTACHMENT_MAX_CHARS} reached.]")
            if total_truncated:
                lines.append(f"[Truncated or skipped: total attachment character limit of {ATTACHMENT_TOTAL_CHARS} reached.]")
            continue
        if is_image_attachment(link["path"], content_type):
            lines.append(
                "Image attachment not inlined: Hermes bridge does not inline pixels. "
                "Use the Source URL above with Zulip bot HTTP Basic auth, save the image locally, "
                "then inspect it with the available vision tool."
            )
            continue
        lines.append(
            "Attachment not inlined: non-text file type. Use the Source URL above with Zulip bot HTTP Basic auth "
            "and save it locally before inspecting with an appropriate file or vision tool."
        )
    return "\n".join(lines)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except Exception as exc:
        log("state_load_failed", path, exc)
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    tmp.replace(path)


def format_out_of_band_user_message(message: dict) -> str:
    sender = str(message.get("sender_full_name") or message.get("sender_email") or "User")
    mid = str(message.get("id") or "")
    content = str(message.get("content") or "").strip()
    header = f"User: {sender}"
    if mid:
        header += f"\nZulip message ID: {mid}"
    return f"{OUT_OF_BAND_USER_MESSAGE_OPEN}\n{header}\n\n{content}\n{OUT_OF_BAND_USER_MESSAGE_CLOSE}"


def append_steering_message(path: Path, conversation: dict, message: dict, active_message_id: int | None = None) -> dict:
    record = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "active_message_id": active_message_id,
        "message_id": int(message.get("id", 0) or 0),
        "conversation_key": conversation.get("conversation_key") or "",
        "thread_id": conversation.get("thread_id") or "",
        "stream": conversation.get("stream") or str(message.get("display_recipient") or ""),
        "stream_id": conversation.get("stream_id") or str(message.get("stream_id") or ""),
        "topic": conversation.get("topic") or str(message.get("subject") or message.get("topic") or ""),
        "sender": str(message.get("sender_full_name") or message.get("sender_email") or "User"),
        "formatted": format_out_of_band_user_message(message),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def store_steering_message(rc: dict[str, str], message: dict, conversation: dict, active_message_id: int) -> dict:
    record = append_steering_message(STEERING_PATH, conversation, message, active_message_id=active_message_id)
    add_reaction(rc, message, STEERING_REACTION)
    log("steering_saved", record["message_id"], "active", active_message_id, "key", record["conversation_key"], "path", STEERING_PATH)
    return record


def terminate_process(proc: subprocess.Popen) -> bool:
    if proc.poll() is not None:
        return False
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            return False
    return True


def register_active_process(message_id: int, proc: subprocess.Popen) -> bool:
    should_interrupt = False
    with ACTIVE_LOCK:
        ACTIVE_PROCESSES[message_id] = proc
        should_interrupt = message_id in ACTIVE_INTERRUPTS
    return terminate_process(proc) if should_interrupt else False


def pop_active_interrupt(message_id: int) -> bool:
    with ACTIVE_LOCK:
        ACTIVE_PROCESSES.pop(message_id, None)
        if message_id in ACTIVE_INTERRUPTS:
            ACTIVE_INTERRUPTS.remove(message_id)
            return True
    return False


def interrupt_active_message(message_id: int) -> bool:
    with ACTIVE_LOCK:
        ACTIVE_INTERRUPTS.add(message_id)
        proc = ACTIVE_PROCESSES.get(message_id)
    if proc is None:
        return False
    return terminate_process(proc)


def topic_key(stream_id: int | str, topic: str) -> str:
    digest = hashlib.sha256(f"{stream_id}\0{topic}".encode()).hexdigest()[:16]
    return f"topic-{digest}"


def normalize_topic(topic: str) -> str:
    return " ".join(str(topic or "").strip().casefold().split())


def realm_key(site: str) -> str:
    parsed = urllib.parse.urlparse(str(site or ""))
    return (parsed.netloc or parsed.path or "zulip").lower().strip("/")


def topic_alias_lookup_key(realm: str, stream_id: int | str, topic: str) -> str:
    return f"{realm}|{stream_id}|{normalize_topic(topic)}"


def bridge_thread_id_from_session(realm: str, stream_id: int | str, session_id: str) -> str:
    digest = hashlib.sha256(f"{realm}\0{stream_id}\0{session_id}".encode()).hexdigest()[:16]
    return f"bridge-session-{digest}"


def bridge_thread_id_from_topic(realm: str, stream_id: int | str, topic: str) -> str:
    digest = hashlib.sha256(f"{realm}\0{stream_id}\0{normalize_topic(topic)}".encode()).hexdigest()[:16]
    return f"bridge-{digest}"


def native_zulip_thread_id(message: dict) -> str:
    for key in ("topic_id", "thread_id", "conversation_id"):
        value = str(message.get(key) or "").strip()
        if value:
            return value
    return ""


def stable_zulip_thread_id(realm: str, stream_id: int | str, topic: str, message: dict) -> str:
    native = native_zulip_thread_id(message)
    if native:
        return "native-" + urllib.parse.quote(native, safe="._-")
    return bridge_thread_id_from_topic(realm, stream_id, topic)


def conversation_key(realm: str, stream_id: int | str, thread_id: str) -> str:
    return f"zulip:{realm}:{stream_id}:{thread_id}"


def ensure_bridge_registry(state: dict) -> None:
    state.setdefault("zulip_threads", {})
    state.setdefault("zulip_topic_aliases", {})


def resolve_zulip_conversation_key(message: dict, realm: str = "zulip", thread_id: str | None = None) -> dict:
    stream_id = str(message.get("stream_id") or "")
    topic = str(message.get("subject") or message.get("topic") or "")
    resolved_thread_id = thread_id or stable_zulip_thread_id(realm, stream_id, topic, message)
    return {
        "realm": realm,
        "stream": str(message.get("display_recipient") or ""),
        "stream_id": stream_id,
        "topic": topic,
        "normalized_topic": normalize_topic(topic),
        "message_id": str(message.get("id") or ""),
        "legacy_topic_key": topic_key(stream_id, topic),
        "legacy_state_key": f"{stream_id}:{topic_key(stream_id, topic)}",
        "thread_id": resolved_thread_id,
        "conversation_key": conversation_key(realm, stream_id, resolved_thread_id),
        "native_thread_id": native_zulip_thread_id(message),
    }


def note_bridge_thread(state: dict, conversation: dict, session_id: str | None = None) -> None:
    ensure_bridge_registry(state)
    thread_id = conversation["thread_id"]
    topic = conversation["topic"]
    normalized = conversation["normalized_topic"]
    alias_key = topic_alias_lookup_key(conversation["realm"], conversation["stream_id"], topic)
    threads = state["zulip_threads"]
    aliases = state["zulip_topic_aliases"]
    previous = aliases.get(alias_key)
    if previous and previous != thread_id:
        log("zulip_topic_alias_rerouted", conversation["stream_id"], topic, previous, "->", thread_id)
    aliases[alias_key] = thread_id
    thread = threads.get(thread_id)
    if not thread:
        thread = {
            "thread_id": thread_id,
            "conversation_key": conversation["conversation_key"],
            "realm": conversation["realm"],
            "stream": conversation["stream"],
            "stream_id": conversation["stream_id"],
            "current_display_topic": topic,
            "topic_aliases": [],
            "normalized_topic_aliases": [],
            "session_id": session_id or "",
            "last_seen_message_id": None,
        }
        threads[thread_id] = thread
        log("zulip_bridge_thread_created", conversation["conversation_key"], "topic", topic, "session", session_id or "new")
    if normalized and normalized not in thread.setdefault("normalized_topic_aliases", []):
        thread["normalized_topic_aliases"].append(normalized)
    if topic and topic not in thread.setdefault("topic_aliases", []):
        thread["topic_aliases"].append(topic)
        if len(thread["topic_aliases"]) > 1:
            log("zulip_topic_alias_added", thread_id, topic)
    thread["current_display_topic"] = topic or thread.get("current_display_topic") or ""
    thread["stream"] = conversation["stream"] or thread.get("stream") or ""
    if session_id:
        thread["session_id"] = session_id
    try:
        thread["last_seen_message_id"] = int(conversation.get("message_id") or 0) or thread.get("last_seen_message_id")
    except Exception:
        pass


def session_title(message: dict) -> str:
    topic = str(message.get("subject") or message.get("topic") or "untitled").strip()
    return topic[:120]


def zulip_thread_key(message: dict) -> str:
    if isinstance(message.get("_zulip_bridge"), dict):
        return str(message["_zulip_bridge"].get("conversation_key") or "")
    stream_id = str(message.get("stream_id") or "")
    topic = str(message.get("subject") or message.get("topic") or "")
    return f"zulip:{stream_id}:{topic_key(stream_id, topic)}"


def zulip_source_detail(message: dict) -> dict:
    stream = str(message.get("display_recipient") or "")
    topic = str(message.get("subject") or message.get("topic") or "")
    stream_id = str(message.get("stream_id") or "")
    message_id = str(message.get("id") or "")
    bridge = message.get("_zulip_bridge") if isinstance(message.get("_zulip_bridge"), dict) else {}
    conversation = bridge.get("conversation_key") or zulip_thread_key(message)
    thread_id = bridge.get("thread_id") or topic_key(stream_id, topic)
    return {
        "platform": "zulip",
        "bridge": "zulip",
        "zulip": {
            "stream": stream,
            "stream_id": stream_id,
            "topic": topic,
            "current_display_topic": topic,
            "topic_aliases": bridge.get("topic_aliases") or [topic],
            "message_id": message_id,
            "thread_id": thread_id,
            "thread_key": conversation,
            "conversation_key": conversation,
            "legacy_thread_key": f"zulip:{stream_id}:{topic_key(stream_id, topic)}",
        },
    }


def merge_sources(value: object, source: str) -> list[str]:
    items = []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            parsed = [value] if value.strip() else []
    elif isinstance(value, list):
        parsed = value
    else:
        parsed = []
    for item in parsed:
        text = str(item or "").strip()
        if text and text not in items:
            items.append(text)
    if source not in items:
        items.append(source)
    return items


def merge_source_detail(existing: object, detail: dict) -> dict:
    if isinstance(existing, str) and existing.strip():
        try:
            current = json.loads(existing)
        except Exception:
            current = {}
    elif isinstance(existing, dict):
        current = existing
    else:
        current = {}
    if not isinstance(current, dict):
        current = {}
    merged = {**current, **detail}
    old_zulip = current.get("zulip") if isinstance(current.get("zulip"), dict) else {}
    merged["zulip"] = {**old_zulip, **detail.get("zulip", {})}
    return merged


def alias_topic_variants(topic: str) -> list[str]:
    topic = str(topic or "").strip()
    return [topic] if topic else []


def mark_session_zulip(conn: sqlite3.Connection, session_id: str | None, message: dict, created: bool = False) -> None:
    if not session_id:
        return
    columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    optional = [name for name in ("sources", "source_detail") if name in columns]
    row = conn.execute(
        f"SELECT source{''.join(',' + name for name in optional)} FROM sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    if not row:
        return
    source = row[0]
    values = dict(zip(optional, row[1:]))
    sources = values.get("sources")
    source_detail = values.get("source_detail")
    detail = zulip_source_detail(message)
    next_source = "zulip" if created or str(source or "").strip() in {"", "cli"} else source
    merged_sources = sources
    if str(source or "").strip() not in {"", "cli", "zulip"}:
        merged_sources = merge_sources(merged_sources, str(source or "").strip())
    merged_sources = merge_sources(merged_sources, "zulip")
    updates = {"source": next_source}
    if "last_source" in columns:
        updates["last_source"] = "zulip"
    if "sources" in columns:
        updates["sources"] = json.dumps(merged_sources)
    if "source_detail" in columns:
        updates["source_detail"] = json.dumps(merge_source_detail(source_detail, detail), separators=(",", ":"))
    for name, value in {
        "session_key": detail["zulip"]["thread_key"],
        "chat_type": "zulip",
        "chat_id": detail["zulip"]["stream_id"],
        "thread_id": detail["zulip"].get("thread_id") or topic_key(detail["zulip"]["stream_id"], detail["zulip"]["topic"]),
    }.items():
        if name in columns:
            updates[name] = value
    assignments = ", ".join(f"{name} = ?" for name in updates)
    conn.execute(f"UPDATE sessions SET {assignments} WHERE id = ?", (*updates.values(), session_id))


def update_auto_title(conn: sqlite3.Connection, session_id: str, title: str, force: bool = False) -> None:
    row = conn.execute("SELECT title FROM sessions WHERE id = ?", (session_id,)).fetchone()
    current = str(row[0] or "") if row else ""
    if not force and current and not current.startswith("Zulip: ") and current != title:
        return
    try:
        conn.execute("UPDATE sessions SET title = ? WHERE id = ?", (title, session_id))
    except sqlite3.IntegrityError:
        conn.execute("UPDATE sessions SET title = ? WHERE id = ?", (f"{title} ({session_id[-6:]})", session_id))


def load_alias_entries() -> list[dict]:
    manifest = load_json(ALIASES_PATH, {"aliases": []})
    return [item for item in manifest.get("aliases", []) if isinstance(item, dict)]


def load_aliases(entries: list[dict] | None = None) -> dict[tuple[str, str], str]:
    entries = entries if entries is not None else load_alias_entries()
    aliases = {}
    for item in entries:
        stream_id = str(item.get("stream_id") or "")
        topic = str(item.get("topic") or "")
        session_id = str(item.get("session_id") or "")
        if stream_id and topic and session_id:
            for variant in alias_topic_variants(topic):
                aliases[(stream_id, normalize_topic(variant))] = session_id
    return aliases


def _thread_for_session(state: dict, stream_id: str, session_id: str) -> str:
    for thread_id, thread in (state.get("zulip_threads") or {}).items():
        if str(thread.get("stream_id") or "") == stream_id and str(thread.get("session_id") or "") == session_id:
            return str(thread_id)
    return ""


def apply_alias_repairs(state: dict, alias_entries: list[dict], realm: str) -> None:
    ensure_bridge_registry(state)
    for item in alias_entries:
        stream_id = str(item.get("stream_id") or "")
        topic = str(item.get("topic") or "")
        session_id = str(item.get("session_id") or "")
        if not stream_id or not topic or not session_id:
            continue
        thread_id = _thread_for_session(state, stream_id, session_id) or bridge_thread_id_from_session(realm, stream_id, session_id)
        message = {
            "id": item.get("last_seen_message_id") or 0,
            "stream_id": stream_id,
            "display_recipient": item.get("stream") or "",
            "topic": topic,
        }
        conversation = resolve_zulip_conversation_key(message, realm, thread_id=thread_id)
        before = (state.get("zulip_topic_aliases") or {}).get(topic_alias_lookup_key(realm, stream_id, topic))
        state.setdefault("topic_sessions", {})[conversation["legacy_state_key"]] = session_id
        note_bridge_thread(state, conversation, session_id=session_id)
        after = state["zulip_topic_aliases"].get(topic_alias_lookup_key(realm, stream_id, topic))
        if before and before != after:
            log("zulip_split_thread_repair_applied", stream_id, topic, before, "->", after)


def latest_messages(rc: dict[str, str]) -> list[dict]:
    payload = api(
        rc,
        "GET",
        "/api/v1/messages",
        params={"anchor": "newest", "num_before": 100, "num_after": 0, "apply_markdown": "false"},
    )
    return sorted(payload.get("messages") or [], key=lambda m: int(m.get("id", 0)))


def current_stream_name(rc: dict[str, str], message: dict) -> str:
    stream_id = str(message.get("stream_id") or "")
    fallback = str(message.get("display_recipient") or "")
    if not stream_id:
        return fallback
    try:
        payload = api(rc, "GET", "/api/v1/streams")
        for stream in payload.get("streams", []):
            if str(stream.get("stream_id") or "") == stream_id and str(stream.get("name") or "").strip():
                return str(stream["name"])
    except Exception as exc:
        log("stream_name_lookup_failed", stream_id, exc)
    return fallback


def topic_history(rc: dict[str, str], message: dict) -> str:
    stream = current_stream_name(rc, message)
    topic = str(message.get("subject") or message.get("topic") or "")
    if not stream or not topic:
        return ""
    payload = api(
        rc,
        "GET",
        "/api/v1/messages",
        params={
            "anchor": "newest",
            "num_before": 200,
            "num_after": 0,
            "narrow": json.dumps(
                [{"operator": "channel", "operand": stream}, {"operator": "topic", "operand": topic}]
            ),
            "apply_markdown": "false",
        },
    )
    current_id = int(message.get("id") or 0)
    messages = [
        m
        for m in payload.get("messages", [])
        if int(m.get("id") or 0) < current_id and str(m.get("content") or "").strip()
    ]
    if len(messages) > 30:
        messages = messages[:8] + [{"sender_full_name": "...", "content": "..."}] + messages[-20:]
    lines = []
    for m in messages:
        sender = str(m.get("sender_full_name") or m.get("sender_email") or "user")
        content = " ".join(str(m.get("content") or "").split())
        lines.append(f"- {sender}: {content[:500]}")
    return "\n".join(lines)


def reply(rc: dict[str, str], message: dict, content: str) -> None:
    api(
        rc,
        "POST",
        "/api/v1/messages",
        data={
            "type": "stream",
            "to": current_stream_name(rc, message),
            "topic": str(message.get("subject") or message.get("topic") or ""),
            "content": content[:RESPONSE_MAX_CHARS],
        },
    )


def add_reaction(rc: dict[str, str], message: dict, emoji_name: str) -> None:
    try:
        api(rc, "POST", f"/api/v1/messages/{int(message['id'])}/reactions", data={"emoji_name": emoji_name})
    except Exception as exc:
        if "REACTION_ALREADY_EXISTS" not in str(exc):
            log("reaction_failed", message.get("id"), emoji_name, exc)


def remove_reaction(rc: dict[str, str], message: dict, emoji_name: str) -> None:
    try:
        api(rc, "DELETE", f"/api/v1/messages/{int(message['id'])}/reactions", data={"emoji_name": emoji_name})
    except Exception as exc:
        if "REACTION_DOES_NOT_EXIST" not in str(exc):
            log("remove_reaction_failed", message.get("id"), emoji_name, exc)


def typing_status(rc: dict[str, str], message: dict, op: str) -> None:
    try:
        api(
            rc,
            "POST",
            "/api/v1/typing",
            data={
                "type": "stream",
                "op": op,
                "stream_id": str(message.get("stream_id") or ""),
                "topic": str(message.get("subject") or message.get("topic") or ""),
            },
        )
    except Exception as exc:
        log("typing_failed", message.get("id"), op, exc)


def find_session_by_marker(marker: str) -> str | None:
    if not STATE_DB.exists():
        return None
    try:
        with sqlite3.connect(STATE_DB) as conn:
            row = conn.execute(
                """
                SELECT session_id
                FROM messages
                WHERE role = 'user' AND content LIKE ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (f"%{marker}%",),
            ).fetchone()
        return str(row[0]) if row else None
    except Exception as exc:
        log("session_lookup_failed", marker, exc)
        return None


def clean_session_record(
    session_id: str | None,
    marker: str,
    visible_text: str,
    title: str,
    message: dict,
    force_title: bool = False,
    created: bool = False,
) -> None:
    if not session_id or not STATE_DB.exists():
        return
    try:
        with sqlite3.connect(STATE_DB) as conn:
            conn.execute(
                """
                UPDATE messages
                SET content = ?
                WHERE id = (
                    SELECT id
                    FROM messages
                    WHERE session_id = ? AND role = 'user' AND content LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                )
                """,
                (visible_text, session_id, f"%{marker}%"),
            )
            update_auto_title(conn, session_id, title, force=force_title)
            mark_session_zulip(conn, session_id, message, created=created)
    except Exception as exc:
        log("session_cleanup_failed", session_id, exc)


def set_session_archived(session_id: str | None, archived: bool) -> None:
    if not session_id or not STATE_DB.exists():
        return
    try:
        with sqlite3.connect(STATE_DB) as conn, conn:
            conn.execute("UPDATE sessions SET archived = ? WHERE id = ?", (1 if archived else 0, session_id))
    except Exception as exc:
        log("session_archive_failed", session_id, exc)


def merge_session_into(source_id: str | None, target_id: str | None, title: str, message: dict) -> str | None:
    if not source_id or not target_id or source_id == target_id or not STATE_DB.exists():
        return target_id or source_id
    try:
        with sqlite3.connect(STATE_DB) as conn:
            source = conn.execute("SELECT started_at, ended_at FROM sessions WHERE id = ?", (source_id,)).fetchone()
            target = conn.execute("SELECT started_at, ended_at FROM sessions WHERE id = ?", (target_id,)).fetchone()
            if not source or not target:
                return target_id
            with conn:
                conn.execute("UPDATE sessions SET parent_session_id = ? WHERE parent_session_id = ?", (target_id, source_id))
                conn.execute("UPDATE messages SET session_id = ? WHERE session_id = ?", (target_id, source_id))
                conn.execute("DELETE FROM sessions WHERE id = ?", (source_id,))
                started = min(x for x in (source[0], target[0]) if x is not None)
                ended_values = [x for x in (source[1], target[1]) if x is not None]
                ended = max(ended_values) if ended_values else None
                message_count = conn.execute("SELECT COUNT(*) FROM messages WHERE session_id = ?", (target_id,)).fetchone()[0]
                tool_count = conn.execute(
                    "SELECT COUNT(*) FROM messages WHERE session_id = ? AND (tool_calls IS NOT NULL OR tool_name IS NOT NULL)",
                    (target_id,),
                ).fetchone()[0]
                update_auto_title(conn, target_id, title)
                conn.execute(
                    """
                    UPDATE sessions
                    SET started_at = ?, ended_at = ?, message_count = ?, tool_call_count = ?
                    WHERE id = ?
                    """,
                    (started, ended, message_count, tool_count, target_id),
                )
                mark_session_zulip(conn, target_id, message)
            return target_id
    except Exception as exc:
        log("session_merge_failed", source_id, target_id, exc)
        return source_id or target_id


def clean_message_text(content: str) -> str:
    text = html.unescape(str(content or "").strip())
    if "<" in text and ">" in text:
        text = re.sub(r"(?i)<br\s*/?>", "\n", text)
        text = re.sub(r"(?i)</p\s*>", "\n", text)
        text = re.sub(r"(?s)<[^>]+>", "", text)
        text = html.unescape(text)
    return text.strip()


def strip_command_wrappers(text: str) -> str:
    text = str(text or "").strip()
    for _ in range(3):
        fenced = re.fullmatch(r"```(?:[A-Za-z0-9_-]+)?\s*([\s\S]*?)\s*```", text)
        if fenced:
            text = fenced.group(1).strip()
            continue
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {"`", '"', "'"}:
            text = text[1:-1].strip()
            continue
        break
    return text


def slash_command_candidates(content: str) -> list[str]:
    text = strip_command_wrappers(clean_message_text(content))
    candidates = [text]
    candidates.extend(strip_command_wrappers(line) for line in text.splitlines())
    match = re.search(r"(?s)(/[A-Za-z][A-Za-z0-9_-]*(?:\s+[\s\S]*?)?)\s*$", text)
    if match:
        prefix = text[: match.start(1)].strip().lower()
        # ponytail: allow User's "let's test... /goal status" habit; keep it narrow to avoid surprise /reset.
        if len(prefix) <= 80 and re.search(r"\b(test|testing|try|check)\b", prefix):
            candidates.append(match.group(1).strip())
    return [candidate for candidate in candidates if candidate]


def parse_slash_candidate(text: str) -> tuple[str, str, str] | None:
    text = str(text or "").strip()
    if not text.startswith("/"):
        return None
    match = re.match(r"^/([A-Za-z][A-Za-z0-9_-]*)(?:\s+([\s\S]*))?$", text)
    if not match:
        return None
    raw_name = match.group(1)
    args = (match.group(2) or "").strip()
    canonical = canonical_slash_command(raw_name)
    if not canonical:
        return None
    return raw_name, canonical, args


def parse_known_slash_command(content: str) -> tuple[str, str, str] | None:
    for candidate in slash_command_candidates(content):
        parsed = parse_slash_candidate(candidate)
        if parsed:
            return parsed
    return None


def canonical_slash_command(name: str) -> str | None:
    clean = str(name or "").strip().lstrip("/").replace("_", "-").lower()
    if not clean:
        return None
    try:
        from hermes_cli.commands import resolve_command

        command = resolve_command(clean)
        if command is not None:
            return str(command.name)
    except Exception:
        pass
    return clean if clean in KNOWN_SLASH_COMMAND_FALLBACK else None


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", str(text or "")).strip()


def run_slash_worker(command: str, session_id: str | None) -> str:
    session_key = session_id or "zulip-bridge"
    payload = json.dumps({"id": 1, "command": command}) + "\n"
    proc = subprocess.Popen(
        [sys.executable, "-m", "tui_gateway.slash_worker", "--session-key", session_key],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=hermes_workdir(),
    )
    try:
        stdout, stderr = proc.communicate(payload, timeout=SLASH_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError(f"Hermes slash command timed out after {SLASH_COMMAND_TIMEOUT_SECONDS:g}s")
    if proc.returncode != 0:
        raise RuntimeError(strip_ansi(stderr) or f"Hermes slash command failed with exit code {proc.returncode}")
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return ""
    response = json.loads(lines[-1])
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error") or "Hermes slash command failed"))
    return strip_ansi(str(response.get("output") or ""))


def goal_manager(session_id: str):
    from hermes_cli.config import load_config
    from hermes_cli.goals import GoalManager

    try:
        goals_cfg = (load_config() or {}).get("goals") or {}
        max_turns = int(goals_cfg.get("max_turns", 20) or 20)
    except Exception:
        max_turns = 20
    return GoalManager(session_id=session_id, default_max_turns=max_turns)


def goal_background_processes() -> list[dict[str, Any]] | None:
    try:
        from hermes_cli.goals import gather_background_processes

        return gather_background_processes()
    except Exception:
        return None


def goal_slash_starts_turn(args: str) -> bool:
    lower = str(args or "").strip().lower()
    if not lower:
        return False
    if lower in {"status", "show", "pause", "resume", "clear", "stop", "done", "unwait"}:
        return False
    if lower == "wait" or lower.startswith("wait "):
        return False
    return True


def should_run_goal_after_turn(message: dict) -> bool:
    parsed = parse_known_slash_command(str(message.get("content") or ""))
    if not parsed:
        return True
    _raw_name, canonical, args = parsed
    return canonical == "goal" and goal_slash_starts_turn(args)


def is_readonly_goal_slash(message: dict) -> bool:
    parsed = parse_known_slash_command(str(message.get("content") or ""))
    if not parsed:
        return False
    _raw_name, canonical, args = parsed
    return canonical == "goal" and str(args or "").strip().lower() in {"", "status", "show"}


def goal_decision_after_turn(session_id: str | None, last_response: str) -> dict[str, Any] | None:
    if not session_id or not str(last_response or "").strip():
        return None
    mgr = goal_manager(session_id)
    try:
        if not mgr.is_active():
            return None
        return mgr.evaluate_after_turn(
            last_response,
            user_initiated=True,
            background_processes=goal_background_processes(),
        )
    except Exception as exc:
        log("goal_evaluate_failed", session_id, exc)
        return {"message": f"{BOT_NAME} goal loop error: {exc}", "should_continue": False}


def post_goal_turns(rc: dict[str, str], message: dict, session_id: str | None, last_response: str) -> str | None:
    if not should_run_goal_after_turn(message):
        return session_id
    for _ in range(100):  # ponytail: GoalManager owns the real budget; this only catches bad injected fakes.
        decision = goal_decision_after_turn(session_id, last_response)
        if not decision:
            return session_id
        status = str(decision.get("message") or "").strip()
        if status:
            reply(rc, message, status)
            log("goal_status_posted", message.get("id"), session_id, status[:160])
        if not decision.get("should_continue"):
            return session_id
        prompt = str(decision.get("continuation_prompt") or "").strip()
        if not prompt:
            return session_id
        answer, resolved = hermes_reply(rc, {**message, "content": prompt}, session_id)
        session_id = resolved or session_id
        reply(rc, message, answer)
        last_response = answer
    reply(rc, message, "Goal loop stopped after bridge safety limit. Use /goal status to inspect it.")
    log("goal_loop_safety_stop", message.get("id"), session_id)
    return session_id


def format_goal_details(mgr: object, *, include_empty_contract: bool = False) -> str:
    lines = [str(mgr.status_line())]
    state = getattr(mgr, "state", None)
    if state is not None:
        verdict = getattr(state, "last_verdict", None)
        reason = getattr(state, "last_reason", None)
        if verdict or reason:
            lines.append(f"Last verdict: {verdict or 'n/a'}{f' - {reason}' if reason else ''}")
        paused_reason = getattr(state, "paused_reason", None)
        if paused_reason:
            lines.append(f"Paused reason: {paused_reason}")
        subgoals = [str(item).strip() for item in (getattr(state, "subgoals", None) or []) if str(item).strip()]
        if subgoals:
            lines.append("Subgoals:")
            lines.extend(f"- {item}" for item in subgoals)
    try:
        contract = str(mgr.render_contract()).strip()
    except Exception:
        contract = ""
    if contract and (include_empty_contract or not contract.startswith("(no ")):
        lines.extend(["", "Completion contract:", contract])
    return "\n".join(lines).strip()


def handle_goal_slash(rc: dict[str, str], message: dict, session_id: str | None, args: str) -> tuple[str, str | None]:
    lower = args.strip().lower()
    if not session_id and (not args.strip() or lower in {"status", "show", "pause", "resume", "clear", "stop", "done", "unwait"} or lower.startswith("wait")):
        return "No active Hermes session for this Zulip topic yet.", session_id

    if session_id:
        mgr = goal_manager(session_id)
        if not args.strip() or lower == "status":
            return format_goal_details(mgr), session_id
        if lower == "show":
            return format_goal_details(mgr, include_empty_contract=True), session_id
        if lower == "pause":
            state = mgr.pause(reason="user-paused")
            return ("No goal set." if state is None else format_goal_details(mgr)), session_id
        if lower == "resume":
            state = mgr.resume()
            return ("No goal to resume." if state is None else format_goal_details(mgr)), session_id
        if lower in {"clear", "stop", "done"}:
            had = mgr.has_goal()
            mgr.clear()
            return ("Goal cleared." if had else "No active goal."), session_id
        if lower == "unwait":
            return (format_goal_details(mgr) if mgr.stop_waiting() else "No wait barrier set."), session_id
        if lower == "wait" or lower.startswith("wait "):
            tokens = args[len("wait"):].strip().split(None, 1)
            if not tokens:
                return "Usage: /goal wait <pid> [reason]", session_id
            try:
                pid = int(tokens[0])
                reason = tokens[1].strip() if len(tokens) > 1 else ""
                mgr.wait_on(pid, reason=reason)
            except (RuntimeError, ValueError) as exc:
                return f"/goal wait: {exc}", session_id
            return format_goal_details(mgr), session_id

    goal_text = args.strip()
    contract = None
    if lower.startswith("draft"):
        objective = args[len("draft"):].strip()
        if not objective:
            return "Usage: /goal draft <objective in plain language>", session_id
        goal_text = objective
        try:
            from hermes_cli.goals import draft_contract

            contract = draft_contract(objective)
        except Exception:
            contract = None
    else:
        try:
            from hermes_cli.goals import parse_contract

            headline, parsed = parse_contract(goal_text)
            goal_text = headline or goal_text
            contract = parsed if not parsed.is_empty() else None
        except Exception:
            contract = None

    if not goal_text:
        return "Usage: /goal <goal text>", session_id

    if session_id:
        mgr = goal_manager(session_id)
        state = mgr.set(goal_text, contract=contract)
        notice = f"Goal set ({state.max_turns}-turn budget): {state.goal}"
        answer, resolved = hermes_reply(rc, {**message, "content": state.goal}, session_id)
        return f"{notice}\n{format_goal_details(mgr)}\n\n{answer}", resolved or session_id

    answer, resolved = hermes_reply(rc, {**message, "content": goal_text}, None)
    if resolved:
        mgr = goal_manager(resolved)
        state = mgr.set(goal_text, contract=contract)
        return f"Goal set ({state.max_turns}-turn budget): {state.goal}\n{format_goal_details(mgr)}\n\n{answer}", resolved
    return answer, resolved


def hermes_slash_reply(rc: dict[str, str], message: dict, session_id: str | None) -> tuple[str, str | None] | None:
    parsed = parse_known_slash_command(str(message.get("content") or ""))
    if not parsed:
        return None
    _raw_name, canonical, args = parsed
    if canonical == "goal":
        return handle_goal_slash(rc, message, session_id, args)
    output = run_slash_worker(f"/{canonical}{(' ' + args) if args else ''}", session_id)
    return output or f"/{canonical} executed.", session_id


def hermes_reply(rc: dict[str, str], message: dict, session_id: str | None) -> tuple[str, str | None]:
    stream = str(message.get("display_recipient") or "")
    topic = str(message.get("subject") or message.get("topic") or "")
    sender = str(message.get("sender_full_name") or message.get("sender_email") or "User")
    text = str(message.get("content") or "")
    prompt_text = text + build_attachment_context(rc, text)
    history = topic_history(rc, message)
    marker = f"zulip-bridge-message-{message.get('id')}-{time.time_ns()}"
    steering_conversation_key = zulip_thread_key(message)
    active_message_id = int(message.get("id") or 0)
    prompt = (
        f"{prompt_text}\n\n"
        "---\n"
        "Hermes bridge context, not user-authored text:\n"
        f"You are {BOT_NAME} replying in Zulip.\n"
        f"Bridge marker: {marker}\n"
        f"Stream: {stream}\n"
        f"Topic: {topic}\n"
        f"User: {sender}\n\n"
        "Mid-turn steering: if this task takes more than a quick response, periodically check the Zulip steering sidecar "
        f"at {STEERING_PATH}. New same-topic Zulip messages arriving while you run are appended there as JSON Lines with a "
        "formatted field wrapped in the exact OUT-OF-BAND USER MESSAGE marker; treat those as direct user steering. "
        f"Only act on records with conversation_key {steering_conversation_key!r} and active_message_id {active_message_id!r}; "
        "ignore older records or records for other conversations. If a matching steering record appears while you are delaying, "
        "waiting, or looping, stop that wait immediately and reply according to the steering message.\n\n"
        "Recent visible Zulip topic history, oldest to newest:\n"
        f"{history or '(No prior visible topic history.)'}\n\n"
        "Reply directly in the existing conversation. Keep it concise unless the user asks for detail."
    )
    cmd = [str(HERMES), *HERMES_EXTRA_ARGS, "-z", prompt]
    if session_id:
        cmd.extend(["--resume", session_id])
    proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=hermes_workdir(), start_new_session=True)
    if register_active_process(active_message_id, proc):
        log("active_turn_interrupted_on_start", active_message_id)
    deadline = time.monotonic() + HERMES_TIMEOUT_SECONDS
    next_typing = 0.0
    next_session_hide = 0.0
    actual_session_id = None
    try:
        while proc.poll() is None:
            now = time.monotonic()
            if now >= next_typing:
                typing_status(rc, message, "start")
                # ponytail: fixed refresh is enough; read /register timing if clients ever drop indicators.
                next_typing = now + TYPING_REFRESH_SECONDS
            if session_id and now >= next_session_hide:
                actual_session_id = actual_session_id or find_session_by_marker(marker)
                if actual_session_id:
                    # ponytail: hide transient Hermes child sessions; unarchive only if this becomes a real new topic.
                    set_session_archived(actual_session_id, True)
                next_session_hide = now + 2
            if now >= deadline:
                proc.kill()
                raise RuntimeError("Hermes timed out")
            time.sleep(1)
        stdout, stderr = proc.communicate()
    finally:
        typing_status(rc, message, "stop")
    if pop_active_interrupt(active_message_id):
        raise HermesInterrupted("Hermes interrupted by Zulip steering message")
    if proc.returncode != 0:
        raise RuntimeError(f"Hermes failed ({proc.returncode}): {stderr.strip()[-2000:]}")
    actual_session_id = actual_session_id or find_session_by_marker(marker)
    title = session_title(message)
    clean_session_record(
        actual_session_id or session_id,
        marker,
        text,
        title,
        message,
        force_title=session_id is None,
        created=session_id is None,
    )
    resolved_session_id = merge_session_into(actual_session_id, session_id, title, message) if session_id else actual_session_id
    if session_id is None:
        set_session_archived(resolved_session_id, False)
    return stdout.strip() or "(No response.)", resolved_session_id


def _demo() -> None:
    message = {"id": 42, "stream_id": 123, "display_recipient": "general", "topic": "hello"}
    assert topic_key(123, "hello") == topic_key("123", "hello")
    assert topic_key(123, "hello") != topic_key(123, "Hello")
    assert normalize_topic("  Hello   WORLD ") == "hello world"
    assert session_title({"display_recipient": "general", "topic": "hi"}) == "hi"
    detail = zulip_source_detail(message)
    assert detail["platform"] == "zulip"
    assert detail["zulip"]["stream"] == "general"
    assert detail["zulip"]["topic"] == "hello"
    assert merge_sources('["cli"]', "zulip") == ["cli", "zulip"]
    assert alias_topic_variants("Project update") == ["Project update"]
    upload_links = find_zulip_upload_links(
        "see [note](/user_uploads/1/ab/note.md) and https://zulip.example.com/user_uploads/1/ab/note.md "
        "but not https://evil.example/user_uploads/1/ab/ignored.txt",
        "https://zulip.example.com",
    )
    assert upload_links == [{"path": "/user_uploads/1/ab/note.md", "source": "/user_uploads/1/ab/note.md", "filename": "note.md"}]
    assert is_text_like_attachment("/user_uploads/1/ab/data.json", "application/octet-stream")
    assert is_text_like_attachment("/user_uploads/1/ab/blob", "application/vnd.example+json")
    assert is_image_attachment("/user_uploads/1/ab/screen.png", "application/octet-stream")
    assert safe_decode_attachment("hello".encode("utf-16"), "text/plain; charset=utf-16") == "hello"
    state = {"topic_sessions": {}}
    aliases: dict[tuple[str, str], str] = {}
    realm = "zulip.example.com"
    first = {"id": 1, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Project setup"}
    session_id, conv = resolve_session(first, aliases, state, realm)
    assert session_id is None
    state["zulip_threads"][conv["thread_id"]]["session_id"] = "s1"
    state["topic_sessions"][conv["legacy_state_key"]] = "s1"
    same_session, same_conv = resolve_session(dict(first, id=2), aliases, state, realm)
    assert same_session == "s1"
    assert same_conv["conversation_key"] == conv["conversation_key"]
    renamed = {"id": 3, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Renamed project setup"}
    alias_entries = [{"stream_id": "1", "stream": "hermes", "topic": "Renamed project setup", "session_id": "s1"}]
    aliases = load_aliases(alias_entries)
    apply_alias_repairs(state, alias_entries, realm)
    renamed_session, renamed_conv = resolve_session(renamed, aliases, state, realm)
    assert renamed_session == "s1"
    assert renamed_conv["conversation_key"] == conv["conversation_key"]
    old_alias_session, old_alias_conv = resolve_session(dict(first, id=4), aliases, state, realm)
    assert old_alias_session == "s1"
    assert old_alias_conv["conversation_key"] == conv["conversation_key"]
    other_stream = {"id": 5, "type": "stream", "stream_id": 2, "display_recipient": "other", "topic": "Renamed project setup"}
    other_session, other_conv = resolve_session(other_stream, aliases, state, realm)
    assert other_session is None
    assert other_conv["conversation_key"] != conv["conversation_key"]
    different_topic = {"id": 6, "type": "stream", "stream_id": 1, "display_recipient": "hermes", "topic": "Different topic"}
    different_session, different_conv = resolve_session(different_topic, aliases, state, realm)
    assert different_session is None
    assert different_conv["conversation_key"] != conv["conversation_key"]


def should_process(message: dict, bot_email: str) -> bool:
    if message.get("type") != "stream":
        return False
    stream_id = str(message.get("stream_id") or "")
    if ALLOW_STREAM_IDS and stream_id not in ALLOW_STREAM_IDS:
        return False
    if not ALLOW_STREAM_IDS and ALLOW_STREAMS and str(message.get("display_recipient") or "") not in ALLOW_STREAMS:
        return False
    if ALLOW_TOPICS and str(message.get("subject") or message.get("topic") or "") not in ALLOW_TOPICS:
        return False
    if message.get("sender_is_bot"):
        return False
    sender = str(message.get("sender_email") or "")
    if sender == bot_email or sender.endswith("@zulip.com"):
        return False
    content = str(message.get("content") or "").strip()
    if any(pattern in content for pattern in IGNORE_CONTENT_PATTERNS):
        return False
    return bool(content)


def remember_active_steering(active_steering: dict[str, set[int]], key: str, message_id: int) -> bool:
    ids = active_steering.setdefault(key, set())
    if message_id in ids:
        return False
    ids.add(message_id)
    return True


def finish_active_message(seen: set[int], active_steering: dict[str, set[int]], key: str, message_id: int, ok: bool) -> None:
    seen.add(message_id)
    steering_ids = active_steering.pop(key, set())
    if ok:
        seen.update(steering_ids)


def handle_active_topic_message(
    rc: dict[str, str],
    message: dict,
    session_id: str | None,
    conversation: dict,
    active_message_id: int,
    active_steering: dict[str, set[int]],
    seen: set[int],
) -> None:
    mid = int(message.get("id", 0))
    key = conversation["conversation_key"]
    if is_readonly_goal_slash(message):
        try:
            handle_message(rc, message, session_id)
            log("active_goal_query_replied", mid, "active", active_message_id, "key", key)
        except Exception as exc:
            log("active_goal_query_failed", mid, exc)
        seen.add(mid)
        return
    if remember_active_steering(active_steering, key, mid):
        store_steering_message(rc, message, conversation, active_message_id)
        if HARD_INTERRUPT_ON_STEERING and interrupt_active_message(active_message_id):
            log("active_turn_interrupted", active_message_id, "by", mid, "key", key)


def resolve_session(message: dict, aliases: dict[tuple[str, str], str], state: dict, realm: str) -> tuple[str | None, dict]:
    ensure_bridge_registry(state)
    stream_id = str(message.get("stream_id") or "")
    topic = str(message.get("subject") or message.get("topic") or "")
    legacy_key = f"{stream_id}:{topic_key(stream_id, topic)}"
    alias_session_id = aliases.get((stream_id, normalize_topic(topic)))
    legacy_session_id = (state.get("topic_sessions") or {}).get(legacy_key)
    alias_thread_id = (state.get("zulip_topic_aliases") or {}).get(topic_alias_lookup_key(realm, stream_id, topic))
    session_id = alias_session_id or legacy_session_id
    if alias_thread_id:
        thread_id = alias_thread_id
    elif session_id:
        thread_id = _thread_for_session(state, stream_id, session_id) or bridge_thread_id_from_session(realm, stream_id, session_id)
    else:
        thread_id = stable_zulip_thread_id(realm, stream_id, topic, message)
    conversation = resolve_zulip_conversation_key(message, realm, thread_id=thread_id)
    note_bridge_thread(state, conversation, session_id=session_id)
    thread = (state.get("zulip_threads") or {}).get(thread_id) or {}
    conversation["topic_aliases"] = thread.get("topic_aliases") or [topic]
    message["_zulip_bridge"] = conversation
    if alias_session_id and legacy_session_id and alias_session_id != legacy_session_id:
        log("zulip_renamed_topic_routed_existing_session", stream_id, topic, legacy_session_id, "->", alias_session_id)
    return session_id, conversation


def handle_message(rc: dict[str, str], message: dict, session_id: str | None) -> str | None:
    mid = int(message.get("id", 0))
    log("message", mid, message.get("display_recipient"), message.get("subject") or message.get("topic"), "session", session_id or "new")
    add_reaction(rc, message, "eyes")
    try:
        answer, resolved_session_id = hermes_slash_reply(rc, message, session_id) or hermes_reply(rc, message, session_id)
        reply(rc, message, answer)
        resolved_session_id = post_goal_turns(rc, message, resolved_session_id, answer)
        remove_reaction(rc, message, "eyes")
        add_reaction(rc, message, "thumbs_up")
        log("replied", mid)
        return resolved_session_id
    except HermesInterrupted as exc:
        log("interrupted", mid, exc)
        remove_reaction(rc, message, "eyes")
        raise
    except Exception as exc:
        log("reply_failed", mid, exc)
        remove_reaction(rc, message, "eyes")
        add_reaction(rc, message, "warning")
        reply(rc, message, f"{BOT_NAME} bridge error: {exc}")
        raise


def main() -> int:
    rc = load_rc()
    state = load_json(STATE_PATH, {"seen_ids": [], "topic_sessions": {}})
    seen = set(int(x) for x in state.get("seen_ids", []))
    realm = realm_key(rc["site"])
    alias_entries = load_alias_entries()
    aliases = load_aliases(alias_entries)
    apply_alias_repairs(state, alias_entries, realm)
    log(
        "bridge_start",
        rc["site"],
        rc["email"],
        "aliases",
        len(aliases),
        "streams",
        ",".join(sorted(ALLOW_STREAMS)) or "all",
        "stream_ids",
        ",".join(sorted(ALLOW_STREAM_IDS)) or "all",
        "cwd",
        hermes_workdir(),
    )
    pending: dict[int, tuple[dict, concurrent.futures.Future]] = {}
    active_keys: dict[str, int] = {}
    active_steering: dict[str, set[int]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        while True:
            try:
                for mid, (conversation, future) in list(pending.items()):
                    if not future.done():
                        continue
                    key = conversation["conversation_key"]
                    ok = False
                    try:
                        resolved_session_id = future.result()
                        ok = True
                        if resolved_session_id:
                            state.setdefault("topic_sessions", {})[conversation["legacy_state_key"]] = resolved_session_id
                            note_bridge_thread(state, conversation, session_id=resolved_session_id)
                    except Exception as exc:
                        if isinstance(exc, HermesInterrupted):
                            log("worker_interrupted", mid, exc)
                        else:
                            log("worker_failed", mid, exc)
                    finish_active_message(seen, active_steering, key, mid, ok)
                    active_keys.pop(key, None)
                    pending.pop(mid, None)

                alias_entries = load_alias_entries()
                aliases = load_aliases(alias_entries)
                apply_alias_repairs(state, alias_entries, realm)
                for message in latest_messages(rc):
                    mid = int(message.get("id", 0))
                    if not mid or mid in seen or mid in pending:
                        continue
                    if not should_process(message, rc["email"]):
                        seen.add(mid)
                        continue
                    session_id, conversation = resolve_session(message, aliases, state, realm)
                    key = conversation["conversation_key"]
                    if key in active_keys:
                        handle_active_topic_message(rc, message, session_id, conversation, active_keys[key], active_steering, seen)
                        continue
                    active_keys[key] = mid
                    pending[mid] = (conversation, pool.submit(handle_message, rc, message, session_id))

                state["seen_ids"] = sorted(seen)[-500:]
                save_json(STATE_PATH, state)
            except Exception as exc:
                log("loop_error", exc)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    if "--demo" in sys.argv:
        _demo()
        raise SystemExit(0)
    raise SystemExit(main())
