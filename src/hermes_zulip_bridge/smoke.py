from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any

from . import bridge


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a one-shot live smoke test without starting the bridge loop.")
    parser.add_argument("--stream", default="", help="Zulip stream/channel to use; defaults to configured stream.")
    parser.add_argument("--topic", required=True, help="Zulip topic to use. Posting creates the topic if needed.")
    parser.add_argument("--message", default="Hermes Zulip bridge smoke test. Reply with one concise sentence.", help="Probe prompt sent to Hermes.")
    parser.add_argument("--post-probe", action="store_true", help="Post a probe message to Zulip before invoking Hermes.")
    parser.add_argument("--run-hermes", action="store_true", help="Invoke Hermes once through the bridge reply path.")
    parser.add_argument("--post-reply", action="store_true", help="Post the Hermes response to Zulip. Requires --run-hermes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.post_reply and not args.run_hermes:
        raise SystemExit("--post-reply requires --run-hermes")
    rc = bridge.load_rc()
    stream = args.stream or _default_stream()
    if not stream:
        raise SystemExit("No stream supplied and no configured stream found")

    checks: dict[str, Any] = {
        "zulip_site": rc["site"],
        "zulip_email": rc["email"],
        "stream": stream,
        "topic": args.topic,
        "hermes": str(bridge.HERMES),
        "hermes_found": _hermes_found(),
    }
    me = bridge.api(rc, "GET", "/api/v1/users/me")
    checks["zulip_auth_ok"] = bool(me.get("email") or me.get("user_id"))
    checks["zulip_user_email"] = me.get("email") or ""

    message = _synthetic_message(stream, args.topic, args.message)
    if args.post_probe:
        posted = bridge.api(
            rc,
            "POST",
            "/api/v1/messages",
            data={
                "type": "stream",
                "to": stream,
                "topic": args.topic,
                "content": args.message,
            },
        )
        checks["probe_posted"] = True
        checks["probe_message_id"] = posted.get("id")
        fetched = _fetch_message(rc, posted.get("id"))
        if fetched:
            message.update(fetched)
            message["content"] = args.message
    else:
        checks["probe_posted"] = False

    steering_path = Path(str(bridge.STEERING_PATH) + ".smoke")
    steering_record = bridge.append_steering_message(
        steering_path,
        bridge.resolve_zulip_conversation_key(message, bridge.realm_key(rc["site"])),
        {**message, "id": int(message.get("id") or 0) + 1, "content": "Smoke steering check."},
        active_message_id=int(message.get("id") or 0) or None,
    )
    checks["steering_sidecar_test_path"] = str(steering_path)
    checks["steering_marker_ok"] = bridge.OUT_OF_BAND_USER_MESSAGE_OPEN in steering_record["formatted"]

    if args.run_hermes:
        answer, session_id = bridge.hermes_reply(rc, message, None)
        checks["hermes_ran"] = True
        checks["hermes_session_id"] = session_id or ""
        checks["hermes_response_chars"] = len(answer)
        if args.post_reply:
            bridge.reply(rc, message, "Smoke test response from packaged bridge:\n\n" + answer)
            checks["reply_posted"] = True
    else:
        checks["hermes_ran"] = False

    return {"ok": bool(checks["zulip_auth_ok"] and checks["hermes_found"] and checks["steering_marker_ok"]), "checks": checks}


def _default_stream() -> str:
    return sorted(bridge.ALLOW_STREAMS)[0] if bridge.ALLOW_STREAMS else ""


def _hermes_found() -> bool:
    raw = str(bridge.HERMES)
    if "/" in raw:
        return Path(raw).exists()
    return shutil.which(raw) is not None


def _synthetic_message(stream: str, topic: str, content: str) -> dict[str, Any]:
    return {
        "id": int(time.time()),
        "type": "stream",
        "stream_id": 0,
        "display_recipient": stream,
        "topic": topic,
        "sender_full_name": "Hermes bridge smoke test",
        "sender_email": "smoke-test@example.invalid",
        "content": content,
    }


def _fetch_message(rc: dict[str, str], message_id: object) -> dict[str, Any]:
    if not message_id:
        return {}
    payload = bridge.api(rc, "GET", f"/api/v1/messages/{int(message_id)}")
    message = payload.get("message") if isinstance(payload, dict) else None
    return message if isinstance(message, dict) else {}
