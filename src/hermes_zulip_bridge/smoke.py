from __future__ import annotations

import argparse
import copy
import json
import time
from pathlib import Path
from typing import Any

from . import bridge
from .cli import LauncherProof
from .cli import build_smoke_parser as build_parser
from .cli import parse_smoke_args as parse_args
from .cli import validate_smoke_args as validate_args
from .locking import HeldProcessLock


PUBLIC_CHECKS = {
    "hermes_found",
    "zulip_auth_ok",
    "probe_posted",
    "probe_message_id",
    "human_origin_message_id",
    "steering_marker_ok",
    "hermes_ran",
    "hermes_session_present",
    "hermes_response_chars",
    "reply_posted",
}


def public_result(result: dict[str, Any]) -> dict[str, Any]:
    checks = result.get("checks") if isinstance(result.get("checks"), dict) else {}
    public = {
        key: value
        for key, value in checks.items()
        if key in PUBLIC_CHECKS and (type(value) is bool or type(value) is int or value is None)
    }
    return {"ok": bool(result.get("ok")), "checks": public}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = run(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def run(
    args: argparse.Namespace,
    *,
    lock: HeldProcessLock | None = None,
    hermes_launcher: LauncherProof | None = None,
    rc: dict[str, str] | None = None,
) -> dict[str, Any]:
    validate_args(args)
    rc = bridge.load_rc() if rc is None else rc
    if hermes_launcher is None:
        try:
            hermes_launcher = bridge._python_console_script(str(bridge.HERMES))
        except RuntimeError:
            raise SystemExit("Hermes executable preflight failed") from None
    try:
        if lock is not None:
            lock.validate(lock.state_path)
            bridge.freeze_auxiliary_paths(lock.state_path)
            return public_result(_run(args, lock.state_path, hermes_launcher, rc))
        with bridge.process_lock() as held_lock:
            bridge.freeze_auxiliary_paths(held_lock.state_path)
            return public_result(_run(args, held_lock.state_path, hermes_launcher, rc))
    except bridge.ProcessLockError as exc:
        bridge.log("smoke_lock_failed")
        raise SystemExit(bridge.terminal_safe(exc)) from None
    except SystemExit:
        raise
    except Exception as exc:
        reference = bridge.exception_ref(exc)
        bridge.log("smoke_failed", reference)
        raise SystemExit(f"Smoke test failed ({reference})") from None


def _run(args: argparse.Namespace, state_path: Path, hermes_launcher: LauncherProof, rc: dict[str, str]) -> dict[str, Any]:
    state = bridge.require_state_object(
        bridge.load_json(state_path, {"seen_ids": [], "topic_sessions": {}})
    )
    human_id = bridge.strict_positive_int(args.human_origin_message_id) if args.run_hermes else None
    if human_id is not None:
        _recover_and_refuse_durable_origin(state, state_path, human_id)
    alias_entries = bridge.load_alias_entries()
    stream = args.stream or _default_stream()
    if not stream:
        raise SystemExit("No stream supplied and no configured stream found")

    aliases: dict[tuple[str, str], str] = {}
    session_id = None
    reservation = None
    realm = bridge.realm_key(rc["site"])
    if args.post_probe or args.run_hermes:
        try:
            bridge.bind_state_realm(state, realm)
        except bridge.ReplyRoutingError as exc:
            raise SystemExit(bridge.terminal_safe(exc)) from None
        try:
            aliases = bridge.load_aliases(alias_entries)
            bridge.apply_alias_repairs(state, alias_entries, realm)
        except bridge.ReplyRoutingError as exc:
            raise SystemExit("Smoke route admission failed") from exc
    else:
        state = None

    signing_key = (
        bridge.load_state_signing_key(state_path, state, create=False)
        if isinstance(state, dict)
        else None
    )

    checks: dict[str, Any] = {"hermes_found": True}
    me = bridge.api(rc, "GET", "/api/v1/users/me")
    checks["zulip_auth_ok"] = bool(str(me.get("email") or "").strip() or bridge.strict_positive_int(me.get("user_id")))
    if not checks["zulip_auth_ok"]:
        raise SystemExit("Zulip authentication preflight failed")
    probe_message = _synthetic_message(stream, args.topic, args.message)
    probe_message["stream_id"] = _stream_id(rc, stream)
    if not bridge.allowed_stream_topic(probe_message):
        raise SystemExit("Smoke route is outside the configured Zulip allowlist")
    if state is not None:
        try:
            session_id, conversation = bridge.resolve_session(
                probe_message,
                aliases,
                state,
                realm,
                rc,
                publish=False,
                reserve=True,
            )
            reservation = conversation.pop("_ownership_reservation", None)
        except bridge.ReplyRoutingError as exc:
            raise SystemExit("Smoke route admission failed") from exc
        probe_message["_zulip_bridge"] = conversation
        probe_message["_zulip_state"] = state
        probe_message["_zulip_persist"] = lambda: bridge.save_json(state_path, state)
        if signing_key is not None:
            probe_message["_zulip_signing_key"] = signing_key
    if args.post_reply and signing_key is None and isinstance(state, dict):
        signing_key = bridge.load_state_signing_key(state_path, state)
        if signing_key is None:
            raise bridge.StatePersistenceError("Hermes Zulip state signing key is unavailable")
        probe_message["_zulip_signing_key"] = signing_key
    if args.post_probe:
        try:
            posted = bridge.api(
                rc,
                "POST",
                "/api/v1/messages",
                data={
                    "type": "stream",
                    "to": probe_message["stream_id"],
                    "topic": args.topic,
                    "content": args.message,
                },
            )
        finally:
            if state is not None:
                bridge.release_destination_reservation(state, reservation)
            reservation = None
        posted_id = bridge.strict_positive_int(posted.get("id")) if isinstance(posted, dict) else None
        checks["probe_posted"] = True
        checks["probe_message_id"] = posted_id
        try:
            fetched = _fetch_message(rc, posted_id)
        except Exception as exc:
            bridge.log("smoke_probe_fetch_failed", posted_id, bridge.exception_ref(exc))
            raise SystemExit("Posted smoke probe could not be fetched exactly") from None
        fetched_topic = str(fetched.get("subject") or fetched.get("topic") or "")
        if (
            posted_id is None
            or fetched.get("id") != posted_id
            or fetched.get("type") != "stream"
            or fetched.get("stream_id") != probe_message["stream_id"]
            or fetched_topic != args.topic
            or str(fetched.get("content") or "") != args.message
        ):
            raise SystemExit("Posted smoke probe could not be fetched exactly")
        probe_message.update(fetched)
        if not bridge.allowed_stream_topic(probe_message):
            raise SystemExit("Posted smoke probe is outside the configured Zulip allowlist")
    else:
        checks["probe_posted"] = False

    message = probe_message
    if args.run_hermes:
        try:
            human = _fetch_message(rc, human_id)
        except Exception as exc:
            bridge.log("smoke_human_origin_fetch_failed", human_id, bridge.exception_ref(exc))
            raise SystemExit("Human smoke origin could not be fetched") from None
        human_topic = str(human.get("subject") or human.get("topic") or "")
        if (
            human.get("id") != human_id
            or human.get("type") != "stream"
            or human.get("stream_id") != probe_message["stream_id"]
            or str(human.get("display_recipient") or "") != stream
            or human_topic != args.topic
        ):
            raise SystemExit("Human smoke origin is not in the requested stream/topic")
        try:
            bridge._admitted_origin_scope(human)
        except bridge.ReplyRoutingError as exc:
            raise SystemExit("Human smoke origin has incomplete sender identity or content") from exc
        if not bridge.should_process(human, str(rc.get("email") or "")):
            raise SystemExit("Human smoke origin is not an authorized human message")
        if bridge.REQUIRE_MENTION and not bridge.message_directly_mentions_bot(human):
            raise SystemExit("Human smoke origin does not directly mention the Zulip bot")
        human["_zulip_bot_name"] = bridge.BOT_NAME
        if not bridge.allowed_stream_topic(human):
            raise SystemExit("Human smoke origin is outside the configured Zulip allowlist")
        if not isinstance(state, dict):
            raise bridge.StatePersistenceError("Hermes smoke state is unavailable")
        try:
            session_id, conversation = bridge.resolve_session(
                human,
                aliases,
                state,
                realm,
                rc,
                publish=False,
                reserve=True,
            )
            reservation = conversation.pop("_ownership_reservation", None)
        except bridge.ReplyRoutingError as exc:
            raise SystemExit("Human smoke origin route admission failed") from exc
        before = copy.deepcopy(state)
        before_generation = bridge._ownership_generation(state)
        try:
            if not bridge.note_bridge_thread(state, conversation, session_id=session_id):
                raise bridge.ReplyRoutingError("failed to publish admitted Hermes owner")
            if session_id and not bridge.note_topic_session(state, conversation, session_id):
                raise bridge.ReplyRoutingError("failed to publish admitted Hermes session")
            bridge._admit_origin(state, human_id)
            bridge.save_json(state_path, state)
        except BaseException:
            with bridge.STATE_LOCK:
                state.clear()
                state.update(before)
                bridge.STATE_GENERATIONS[id(state)] = before_generation
            raise
        message = human
        message["_zulip_bridge"] = conversation
        message["_zulip_state"] = state
        message["_zulip_persist"] = lambda: bridge.save_json(state_path, state)
        message["_zulip_execution"] = {"hermes_started": False}
        message["_zulip_launcher_proof"] = hermes_launcher

        def before_hermes_start() -> None:
            bridge._mark_hermes_may_start(state, human_id)
            bridge.save_json(state_path, state)

        message["_zulip_before_hermes_start"] = before_hermes_start
        if signing_key is not None:
            message["_zulip_signing_key"] = signing_key
        checks["human_origin_message_id"] = human_id

    try:
        message_id = bridge.strict_positive_int(probe_message.get("id"))
        if message_id is None:
            raise SystemExit("Smoke message has no stable message ID")
        steering_path = Path(str(bridge.STEERING_PATH) + ".smoke")
        steering_record = bridge.append_steering_message(
            steering_path,
            bridge.resolve_zulip_conversation_key(probe_message, bridge.realm_key(rc["site"])),
            {**probe_message, "id": message_id + 1, "content": "Smoke steering check."},
            active_message_id=message_id,
        )
        checks["steering_marker_ok"] = bridge.OUT_OF_BAND_USER_MESSAGE_OPEN in steering_record["formatted"]

        if args.run_hermes:
            if not args.post_probe:
                message["_zulip_suppress_side_effects"] = True
            answer, session_id = bridge.hermes_reply(rc, message, session_id)
            checks["hermes_ran"] = True
            checks["hermes_session_present"] = bool(session_id)
            checks["hermes_response_chars"] = len(answer)
            if args.post_reply:
                conversation = message.get("_zulip_bridge")
                if isinstance(conversation, dict) and session_id:
                    conversation["session_id"] = session_id
                try:
                    bridge.reply(rc, message, "Smoke test response from packaged bridge:\n\n" + answer)
                except bridge.ConfirmedReplyPersistencePending:
                    _persist_after_hermes(state_path, state)
                if state is not None:
                    if signing_key is None:
                        raise bridge.StatePersistenceError("Hermes Zulip state signing key is unavailable")
                    _mark_seen(state, human_id)
                    _persist_after_hermes(state_path, state)
                    bridge.reconcile_pending_replies(
                        rc,
                        state,
                        signing_key,
                        persist=lambda: _persist_after_hermes(state_path, state),
                    )
                    _persist_after_hermes(state_path, state)
                    if any(job.get("origin_message_id") == human_id for job in state.get("reply_reconciliations", [])):
                        raise bridge.StatePersistenceError("Smoke reply reconciliation remains pending")
                checks["reply_posted"] = True
            else:
                _mark_seen(state, human_id)
                _persist_after_hermes(state_path, state)
            bridge._remove_in_flight_origin(state, human_id)
            _persist_after_hermes(state_path, state)
        else:
            checks["hermes_ran"] = False

        return {"ok": bool(checks["zulip_auth_ok"] and checks["hermes_found"] and checks["steering_marker_ok"]), "checks": checks}
    finally:
        if state is not None:
            bridge.release_destination_reservation(state, reservation)


def _mark_seen(state: dict, message_id: int) -> None:
    previous = [
        parsed
        for value in state.get("seen_ids", [])
        if (parsed := bridge.strict_positive_int(value)) is not None and parsed != message_id
    ]
    state["seen_ids"] = [*previous, message_id][-bridge.MAX_SEEN_IDS :]


def _recover_and_refuse_durable_origin(state: dict, state_path: Path, message_id: int) -> None:
    in_flight = next(
        (item for item in state.get("origin_in_flight", []) if item.get("origin_message_id") == message_id),
        None,
    )
    reconciliations = [
        job for job in state.get("reply_reconciliations", []) if job.get("origin_message_id") == message_id
    ]
    if in_flight is not None and in_flight["stage"] == "hermes_may_start":
        _mark_seen(state, message_id)
        if reconciliations:
            bridge._remove_in_flight_origin(state, message_id)
        else:
            bridge._terminalize_origin(
                state,
                message_id,
                attempts=in_flight["attempts"],
                created_at=in_flight["created_at"],
                reason="smoke_restart_after_hermes_may_start",
            )
        bridge.save_json(state_path, state)
        in_flight = None

    has_evidence = (
        message_id in {bridge.strict_positive_int(value) for value in state.get("seen_ids", [])}
        or in_flight is not None
        or any(item.get("origin_message_id") == message_id for item in state.get("origin_retries", []))
        or bool(reconciliations)
        or any(item.get("origin_message_id") == message_id for item in state.get("dead_letters", []))
    )
    if has_evidence:
        raise SystemExit("Human smoke origin already has durable processing evidence; review state before retrying")


def _persist_after_hermes(state_path: Path, state: dict) -> None:
    bridge.persist_with_durable_limit(
        lambda: bridge.save_json(state_path, state),
        "smoke post-Hermes state",
    )


def _default_stream() -> str:
    return sorted(bridge.ALLOW_STREAMS)[0] if bridge.ALLOW_STREAMS else ""


def _stream_id(rc: dict[str, str], stream_name: str) -> int:
    payload = bridge.api(rc, "GET", "/api/v1/streams")
    streams = payload.get("streams") if isinstance(payload, dict) else None
    stream_ids = {
        stream_id
        for stream in streams or []
        if isinstance(stream, dict)
        and str(stream.get("name") or "") == stream_name
        and (stream_id := bridge.strict_positive_int(stream.get("stream_id"))) is not None
    }
    stream_id = next(iter(stream_ids), None)
    if len(stream_ids) != 1 or stream_id is None:
        raise SystemExit("Unable to resolve requested Zulip stream")
    return stream_id


def _synthetic_message(stream: str, topic: str, content: str) -> dict[str, Any]:
    return {
        "id": int(time.time()),
        "type": "stream",
        "stream_id": 0,
        "display_recipient": stream,
        "topic": topic,
        "content": content,
    }


def _fetch_message(rc: dict[str, str], message_id: object) -> dict[str, Any]:
    parsed_message_id = bridge.strict_positive_int(message_id)
    if parsed_message_id is None:
        return {}
    payload = bridge.api(
        rc,
        "GET",
        f"/api/v1/messages/{parsed_message_id}",
        params={"apply_markdown": "false"},
    )
    message = payload.get("message") if isinstance(payload, dict) else None
    if not isinstance(message, dict) or bridge.strict_positive_int(message.get("id")) != parsed_message_id:
        return {}
    stream_id = bridge.strict_positive_int(message.get("stream_id"))
    if stream_id is None:
        return {}
    return {**message, "id": parsed_message_id, "stream_id": stream_id}
