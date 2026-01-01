from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any


def load_config(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    config_path = Path(path).expanduser()
    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() == ".json":
        data = json.loads(text or "{}")
    else:
        import yaml

        data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a mapping: {config_path}")
    return data


def validate_config(config: dict[str, Any], *, require_secret: bool = False) -> list[str]:
    issues: list[str] = []
    hermes = _section(config, "hermes")
    if config and not (hermes.get("command") or hermes.get("executable")):
        issues.append("hermes.command is required")
    zulip = _section(config, "zulip")
    has_zuliprc = bool(zulip.get("zuliprc") or zulip.get("rc_path"))
    key_env = str(zulip.get("bot_api_key_env") or zulip.get("api_key_env") or "").strip()
    if not has_zuliprc:
        for key, env_key in (("site", "site_env"), ("bot_email", "bot_email_env")):
            has_direct = bool(str(zulip.get(key) or "").strip())
            env_name = str(zulip.get(env_key) or "").strip()
            has_env = bool(os.environ.get(env_name)) if require_secret and env_name else bool(env_name)
            if not has_direct and not has_env:
                issues.append(f"zulip.{key} or zulip.{env_key} is required unless zulip.zuliprc is set")
        if not key_env:
            issues.append("zulip.bot_api_key_env is required unless zulip.zuliprc is set")
        elif require_secret and not os.environ.get(key_env):
            issues.append(f"environment variable {key_env} is not set")
    return issues


def apply_bridge_env(config: dict[str, Any], *, require_secret: bool = True) -> dict[str, str]:
    env = _common_env(config, purpose="bridge", require_secret=require_secret)
    hermes = _section(config, "hermes")
    bridge = _section(config, "bridge")
    response = _section(config, "response")
    zulip = _section(config, "zulip")
    state_dir = _path(bridge.get("state_directory") or bridge.get("state_dir") or "~/.hermes/state")
    instance = _instance(config)

    env["HERMES_BIN"] = str(hermes.get("command") or hermes.get("executable") or "hermes")
    env["HERMES_CWD"] = str(_path(hermes.get("working_directory") or hermes.get("cwd") or Path.home()))
    env["HERMES_STATE_DB"] = str(_path(hermes.get("state_db") or Path.home() / ".hermes/state.db"))
    env["HERMES_TIMEOUT_SECONDS"] = str(hermes.get("timeout_seconds") or hermes.get("timeout") or 1800)
    extra_args = _list(hermes.get("extra_args"))
    if hermes.get("profile"):
        extra_args = ["--profile", str(hermes["profile"]), *extra_args]
    env["HERMES_EXTRA_ARGS"] = shlex.join(extra_args)

    env["HERMES_ZULIP_STATE"] = str(_path(bridge.get("state_path") or state_dir / f"{instance}_zulip_bridge.json"))
    env["HERMES_ZULIP_STEERING"] = str(_path(bridge.get("steering_sidecar_path") or bridge.get("steering_path") or state_dir / f"{instance}_zulip_steering.jsonl"))
    env["HERMES_ZULIP_ALIAS_MANIFEST"] = str(_path(bridge.get("alias_manifest") or bridge.get("alias_manifest_path") or state_dir / f"{instance}_zulip_aliases.json"))
    env["HERMES_ZULIP_POLL_SECONDS"] = str(bridge.get("poll_interval") or bridge.get("poll_seconds") or 5)
    env["HERMES_ZULIP_WORKERS"] = str(bridge.get("workers") or bridge.get("max_workers") or 2)
    env["HERMES_ZULIP_BOT_NAME"] = str(bridge.get("bot_name") or zulip.get("bot_name") or config.get("agent_name") or "Hermes")
    env["HERMES_ZULIP_STREAMS"] = _csv(zulip.get("streams") or zulip.get("stream")) or ""
    env["HERMES_ZULIP_STREAM_IDS"] = _csv(zulip.get("stream_ids") or zulip.get("stream_id")) or ""
    env["HERMES_ZULIP_TOPICS"] = _csv(zulip.get("topic_allowlist") or zulip.get("topics") or zulip.get("topic")) or ""
    env["HERMES_ZULIP_IGNORE_CONTENT_PATTERNS"] = "\n".join(_list(bridge.get("ignore_content_patterns"))) if bridge.get("ignore_content_patterns") is not None else ""
    env["HERMES_ZULIP_STEERING_REACTION"] = str(bridge.get("steering_reaction") or "eyes")
    env["HERMES_ZULIP_HARD_INTERRUPT"] = "1" if bridge.get("hard_interrupt_on_steering", True) else "0"
    env["HERMES_ZULIP_RESPONSE_MAX_CHARS"] = str(response.get("max_message_size") or response.get("max_chars") or 9000)
    os.environ.update(env)
    return env


def apply_notifier_env(config: dict[str, Any], *, require_secret: bool = True) -> dict[str, str]:
    env = _common_env(config, purpose="notifier", require_secret=require_secret)
    notifier = _section(config, "notifier") or _section(config, "kanban")
    bridge = _section(config, "bridge")
    zulip = _section(config, "zulip")
    state_dir = _path(bridge.get("state_directory") or bridge.get("state_dir") or "~/.hermes/state")
    instance = _instance(config)

    _set(env, "HERMES_KANBAN_URL", notifier.get("agentos_url") or notifier.get("event_source"))
    _set(env, "HERMES_ZULIP_NOTIFIER_POLL_SECONDS", notifier.get("poll_interval") or notifier.get("poll_seconds"))
    _set(env, "HERMES_ZULIP_NOTIFIER_BOARD", notifier.get("board"))
    _set(env, "HERMES_ZULIP_NOTIFIER_TERMINAL_STATUSES", _csv(notifier.get("terminal_statuses")))
    _set(env, "HERMES_ZULIP_STREAMS", _csv(zulip.get("streams") or zulip.get("stream")))
    _set(env, "HERMES_ZULIP_STREAM_IDS", _csv(zulip.get("stream_ids") or zulip.get("stream_id")))
    _set(env, "HERMES_ZULIP_DEFAULT_TOPIC", zulip.get("default_topic") or zulip.get("topic"))
    env["HERMES_ZULIP_NOTIFIER_STATE"] = str(_path(notifier.get("state_path") or state_dir / f"{instance}_zulip_kanban_notifier.json"))
    os.environ.update(env)
    return env


def _common_env(config: dict[str, Any], *, purpose: str, require_secret: bool) -> dict[str, str]:
    issues = validate_config(config, require_secret=require_secret)
    if issues:
        raise ValueError("; ".join(issues))
    env: dict[str, str] = {}
    zulip = _section(config, "zulip")
    rc_path = _zuliprc(config, purpose=purpose, require_secret=require_secret)
    if rc_path:
        env["HERMES_ZULIP_RC"] = str(rc_path)
        env["ZULIPRC"] = str(rc_path)
    return env


def _zuliprc(config: dict[str, Any], *, purpose: str, require_secret: bool) -> Path | None:
    zulip = _section(config, "zulip")
    explicit = zulip.get("zuliprc") or zulip.get("rc_path")
    if explicit:
        return Path(str(explicit)).expanduser()
    site = _config_value(zulip, "site", "site_env").rstrip("/")
    email = _config_value(zulip, "bot_email", "bot_email_env")
    key_env = str(zulip.get("bot_api_key_env") or zulip.get("api_key_env") or "").strip()
    if not (site and email and key_env):
        return None
    key = os.environ.get(key_env)
    if not key:
        if require_secret:
            raise ValueError(f"environment variable {key_env} is not set")
        return None
    state_dir = _path(_section(config, "bridge").get("state_directory") or "~/.hermes/state")
    path = Path(state_dir) / f"{_instance(config)}-{purpose}.zuliprc"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"[api]\nemail={email}\nkey={key}\nsite={site}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _section(config: dict[str, Any], key: str) -> dict[str, Any]:
    value = config.get(key)
    return value if isinstance(value, dict) else {}


def _config_value(section: dict[str, Any], key: str, env_key: str) -> str:
    direct = str(section.get(key) or "").strip()
    if direct:
        return direct
    env_name = str(section.get(env_key) or "").strip()
    return str(os.environ.get(env_name) or "").strip() if env_name else ""


def _instance(config: dict[str, Any]) -> str:
    raw = str(config.get("instance_name") or "hermes").strip().lower()
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in raw) or "hermes"


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _csv(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list | tuple | set):
        return ",".join(str(item) for item in value if str(item).strip())
    return str(value)


def _path(value: Any) -> Path:
    if isinstance(value, Path):
        return value.expanduser()
    return Path(str(value)).expanduser()


def _set(env: dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    text = str(value)
    if text:
        env[key] = text
