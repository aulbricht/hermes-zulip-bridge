from __future__ import annotations

import configparser
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from .locking import process_lock_bundle_paths
from .security import secure_read_text

MAX_CONFIG_BYTES = 1024 * 1024
MAX_ZULIPRC_BYTES = 1024 * 1024
CHAT_TOOLSETS = frozenset(
    {
        "browser",
        "clarify",
        "code_execution",
        "coding",
        "context_engine",
        "cronjob",
        "debugging",
        "delegation",
        "file",
        "image_gen",
        "kanban",
        "memory",
        "project",
        "safe",
        "search",
        "session_search",
        "skills",
        "terminal",
        "todo",
        "tts",
        "video",
        "video_gen",
        "vision",
        "web",
    }
)


def validate_hermes_invocation_args(args: list[str]) -> list[str]:
    values = list(args)
    index = 0
    if values[:1] == ["--profile"]:
        if len(values) < 2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", values[1]):
            raise ValueError("Hermes profile argument is invalid")
        index = 2
    if values[index:index + 1] != ["--toolsets"] or len(values) != index + 2:
        raise ValueError("Hermes invocation arguments do not match the restricted bridge policy")
    toolsets = values[index + 1].split(",")
    if not toolsets or any(value not in CHAT_TOOLSETS for value in toolsets):
        raise ValueError("Hermes invocation contains an unsupported chat toolset")
    return values


def preflight_credentials(config: dict[str, Any], *, require_secret: bool = True) -> dict[str, str]:
    """Resolve and validate credentials without mutating process state."""
    issues = validate_config(config, require_secret=require_secret) if config else []
    if issues:
        raise ValueError("; ".join(issues))
    zulip = _section(config, "zulip")
    explicit = zulip.get("zuliprc") or zulip.get("rc_path")
    inline = {
        "site": _config_value(zulip, "site", "site_env").rstrip("/"),
        "email": _config_value(zulip, "bot_email", "bot_email_env"),
    }
    key_env = str(zulip.get("bot_api_key_env") or zulip.get("api_key_env") or "").strip()
    inline["key"] = str(os.environ.get(key_env) or "").strip() if key_env else ""
    if explicit:
        cp = configparser.ConfigParser()
        try:
            cp.read_string(secure_read_text(Path(str(explicit)).expanduser(), MAX_ZULIPRC_BYTES, label="zuliprc"))
            rc = {name: cp["api"][name].strip() for name in ("site", "email", "key")}
            rc["site"] = rc["site"].rstrip("/")
            if not all(rc.values()):
                raise ValueError("incomplete Zulip credentials")
            return rc
        except (ValueError, configparser.Error, KeyError) as exc:
            raise ValueError("zuliprc is missing, malformed, or unsafe") from exc
    if any(inline.values()) and not all(inline.values()):
        raise ValueError("Inline Zulip credentials are incomplete")
    if all(inline.values()):
        return inline
    # Empty config retains the package's traditional default zuliprc.
    cp = configparser.ConfigParser()
    try:
        cp.read_string(secure_read_text(Path.home() / ".hermes/zuliprc", MAX_ZULIPRC_BYTES, label="zuliprc"))
        rc = {name: cp["api"][name].strip() for name in ("site", "email", "key")}
        rc["site"] = rc["site"].rstrip("/")
        if not all(rc.values()):
            raise ValueError("incomplete Zulip credentials")
        return rc
    except (ValueError, configparser.Error, KeyError) as exc:
        raise ValueError("zuliprc is missing, malformed, or unsafe") from exc


def load_config(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    config_path = Path(path).expanduser()
    text = secure_read_text(config_path, MAX_CONFIG_BYTES, label="Config")
    if config_path.suffix.lower() == ".json":
        try:
            data = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Config is malformed") from exc
    else:
        import yaml

        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError("Config is malformed") from exc
    if not isinstance(data, dict):
        raise ValueError("Config must be a mapping")
    return data


def validate_config(config: dict[str, Any], *, require_secret: bool = False) -> list[str]:
    issues: list[str] = []
    hermes = _section(config, "hermes")
    if config and not (hermes.get("command") or hermes.get("executable")):
        issues.append("hermes.command is required")
    toolsets = _list(hermes.get("toolsets"))
    if config and not toolsets:
        issues.append("hermes.toolsets must contain at least one restricted Hermes toolset")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", str(value)) for value in toolsets):
        issues.append("hermes.toolsets entries must contain only letters, numbers, underscores, or hyphens")
    if any(str(value) not in CHAT_TOOLSETS for value in toolsets):
        issues.append("hermes.toolsets contains an unsupported chat toolset")
    profile = hermes.get("profile")
    if profile is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", str(profile)):
        issues.append("hermes.profile is malformed")
    extra_args = _list(hermes.get("extra_args"))
    if extra_args:
        issues.append("hermes.extra_args is not allowed; use the explicit profile and toolsets fields")
    bridge = _section(config, "bridge")
    poll_failure_limit = bridge.get("poll_failure_limit", bridge.get("max_poll_failures"))
    if poll_failure_limit is not None and (
        isinstance(poll_failure_limit, bool)
        or not isinstance(poll_failure_limit, int)
        or poll_failure_limit < 1
    ):
        issues.append("bridge.poll_failure_limit must be a positive integer")
    zulip = _section(config, "zulip")
    allowed_senders = _list(zulip.get("allowed_senders"))
    stream_ids = _list(zulip.get("stream_ids") or zulip.get("stream_id"))
    topics = _list(zulip.get("topic_allowlist") or zulip.get("topics") or zulip.get("topic"))
    topic_policy = str(zulip.get("topic_policy") or ("allowlist" if topics else "")).strip().lower()
    if config and not allowed_senders:
        issues.append("zulip.allowed_senders must contain at least one id:<user-id> or email:<address>")
    if config and any(not _valid_sender(value) for value in allowed_senders):
        issues.append("zulip.allowed_senders entries must use id:<user-id> or email:<address>")
    if config and not stream_ids:
        issues.append("zulip.stream_id or zulip.stream_ids is required")
    if config and any(not str(value).isdigit() or int(str(value)) <= 0 for value in stream_ids):
        issues.append("zulip.stream_id values must be positive integers")
    if config and topic_policy not in {"any", "allowlist"}:
        issues.append("zulip.topic_policy must be 'any' or 'allowlist'")
    if config and topic_policy == "allowlist" and not topics:
        issues.append("zulip.topic_allowlist is required when topic_policy is 'allowlist'")
    privileged_senders = _list(bridge.get("privileged_senders"))
    privileged_commands = _list(bridge.get("privileged_slash_commands"))
    if any(not _valid_sender(value) for value in privileged_senders):
        issues.append("bridge.privileged_senders entries must use id:<user-id> or email:<address>")
    if privileged_commands and not privileged_senders:
        issues.append("bridge.privileged_senders is required when privileged_slash_commands is configured")
    if privileged_senders and not set(privileged_senders).issubset(set(allowed_senders)):
        issues.append("bridge.privileged_senders must be included in zulip.allowed_senders")
    require_mention = bridge.get("require_mention", True)
    if type(require_mention) is not bool:
        issues.append("bridge.require_mention must be a boolean")
    notifier = _section(config, "notifier") or _section(config, "kanban")
    allow_direct_messages = notifier.get("allow_direct_messages", False)
    if type(allow_direct_messages) is not bool:
        issues.append("notifier.allow_direct_messages must be a boolean")
    dm_recipients = _list(notifier.get("allowed_dm_recipients"))
    if allow_direct_messages is True and not dm_recipients:
        issues.append("notifier.allowed_dm_recipients is required when direct messages are enabled")
    if any(not _valid_sender(value) for value in dm_recipients):
        issues.append("notifier.allowed_dm_recipients entries must use id:<user-id> or email:<address>")
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


def apply_bridge_env(
    config: dict[str, Any], *, require_secret: bool = True, state_path: Path | None = None,
    credential_preflight: dict[str, str] | None = None,
) -> dict[str, str]:
    env = _common_env(config, purpose="bridge", require_secret=require_secret, credential_preflight=credential_preflight)
    hermes = _section(config, "hermes")
    bridge = _section(config, "bridge")
    response = _section(config, "response")
    zulip = _section(config, "zulip")
    steering_value = bridge.get("steering_sidecar_path") or bridge.get("steering_path")
    aliases_value = bridge.get("alias_manifest") or bridge.get("alias_manifest_path")
    state_path, steering_path, aliases_path = bridge_bundle_paths(config, state_path=state_path)

    env["HERMES_BIN"] = str(hermes.get("command") or hermes.get("executable") or "hermes")
    env["HERMES_CWD"] = str(_path(hermes.get("working_directory") or hermes.get("cwd") or Path.home()))
    env["HERMES_STATE_DB"] = str(_path(hermes.get("state_db") or Path.home() / ".hermes/state.db"))
    env["HERMES_TIMEOUT_SECONDS"] = str(hermes.get("timeout_seconds") or hermes.get("timeout") or 1800)
    extra_args = ["--toolsets", ",".join(_list(hermes.get("toolsets")))]
    if hermes.get("profile"):
        extra_args = ["--profile", str(hermes["profile"]), *extra_args]
    env["HERMES_EXTRA_ARGS"] = shlex.join(extra_args)
    env["HERMES_ENV_ALLOWLIST"] = ",".join(_list(hermes.get("env_allowlist") or hermes.get("environment_allowlist")))

    env["HERMES_ZULIP_STATE"] = str(state_path)
    env["HERMES_ZULIP_STEERING"] = str(steering_path)
    env["HERMES_ZULIP_ALIAS_MANIFEST"] = str(aliases_path)
    env["HERMES_ZULIP_STEERING_STATE_ASSOCIATED"] = "0" if steering_value else "1"
    env["HERMES_ZULIP_ALIASES_STATE_ASSOCIATED"] = "0" if aliases_value else "1"
    env["HERMES_ZULIP_POLL_SECONDS"] = str(bridge.get("poll_interval") or bridge.get("poll_seconds") or 5)
    env["HERMES_ZULIP_MAX_POLL_FAILURES"] = str(
        bridge.get("poll_failure_limit") or bridge.get("max_poll_failures") or 10
    )
    env["HERMES_ZULIP_WORKERS"] = str(bridge.get("workers") or bridge.get("max_workers") or 2)
    env["HERMES_ZULIP_BOT_NAME"] = str(bridge.get("bot_name") or zulip.get("bot_name") or config.get("agent_name") or "Hermes")
    env["HERMES_ZULIP_STREAMS"] = _csv(zulip.get("streams") or zulip.get("stream")) or ""
    env["HERMES_ZULIP_STREAM_IDS"] = _csv(zulip.get("stream_ids") or zulip.get("stream_id")) or ""
    env["HERMES_ZULIP_TOPICS"] = _csv(zulip.get("topic_allowlist") or zulip.get("topics") or zulip.get("topic")) or ""
    env["HERMES_ZULIP_TOPIC_POLICY"] = str(
        zulip.get("topic_policy") or ("allowlist" if env["HERMES_ZULIP_TOPICS"] else "")
    ).strip().lower()
    env["HERMES_ZULIP_ALLOWED_SENDERS"] = _csv(zulip.get("allowed_senders")) or ""
    env["HERMES_ZULIP_PRIVILEGED_SENDERS"] = _csv(bridge.get("privileged_senders")) or ""
    env["HERMES_ZULIP_PRIVILEGED_COMMANDS"] = _csv(bridge.get("privileged_slash_commands")) or ""
    env["HERMES_ZULIP_REQUIRE_MENTION"] = "0" if bridge.get("require_mention", True) is False else "1"
    env["HERMES_ZULIP_IGNORE_CONTENT_PATTERNS"] = "\n".join(_list(bridge.get("ignore_content_patterns"))) if bridge.get("ignore_content_patterns") is not None else ""
    env["HERMES_ZULIP_STEERING_REACTION"] = str(bridge.get("steering_reaction") or "eyes")
    env["HERMES_ZULIP_HARD_INTERRUPT"] = "1" if bridge.get("hard_interrupt_on_steering", True) else "0"
    env["HERMES_ZULIP_RESPONSE_MAX_CHARS"] = str(response.get("max_message_size") or response.get("max_chars") or 9000)
    _install_env(env)
    return env


def bridge_state_path(config: dict[str, Any]) -> Path:
    bridge = _section(config, "bridge")
    state_dir = _path(bridge.get("state_directory") or bridge.get("state_dir") or "~/.hermes/state")
    return _path(bridge.get("state_path") or state_dir / f"{_instance(config)}_zulip_bridge.json")


def bridge_bundle_paths(
    config: dict[str, Any], *, state_path: Path | None = None
) -> tuple[Path, Path, Path]:
    bridge = _section(config, "bridge")
    hermes = _section(config, "hermes")
    zulip = _section(config, "zulip")
    state = _canonical_path(state_path or bridge_state_path(config))
    steering_value = bridge.get("steering_sidecar_path") or bridge.get("steering_path")
    aliases_value = bridge.get("alias_manifest") or bridge.get("alias_manifest_path")
    instance = _instance(config)
    steering = _canonical_path(steering_value) if steering_value else state.parent / f"{instance}_zulip_steering.jsonl"
    aliases = _canonical_path(aliases_value) if aliases_value else state.parent / f"{instance}_zulip_aliases.json"
    paths = {
        "state": state,
        "signing key": Path(str(state) + ".signing-key"),
        "steering": steering,
        "smoke steering": Path(str(steering) + ".smoke"),
        "alias manifest": aliases,
        "Zulip credentials": _canonical_path(
            zulip.get("zuliprc") or zulip.get("rc_path") or Path.home() / ".hermes/zuliprc"
        ),
        "Hermes state database": _canonical_path(
            hermes.get("state_db") or Path.home() / ".hermes/state.db"
        ),
    }
    public, anchor, guard = process_lock_bundle_paths(state)
    paths.update({"public lock": public, "lock anchor": anchor, "lock guard": guard})
    by_path: dict[Path, list[str]] = {}
    for name, path in paths.items():
        by_path.setdefault(path.resolve(strict=False), []).append(name)
    collisions = [names for names in by_path.values() if len(names) > 1]
    if collisions:
        raise ValueError(
            "Hermes Zulip state bundle paths must be disjoint: "
            + "; ".join(" = ".join(names) for names in collisions)
        )
    return state, steering, aliases


def apply_notifier_env(config: dict[str, Any], *, require_secret: bool = True, credential_preflight: dict[str, str] | None = None) -> dict[str, str]:
    env = _common_env(config, purpose="notifier", require_secret=require_secret, credential_preflight=credential_preflight)
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
    env["HERMES_ZULIP_TOPIC_POLICY"] = str(
        zulip.get("topic_policy")
        or ("allowlist" if zulip.get("topic_allowlist") or zulip.get("topics") or zulip.get("topic") else "")
    ).strip().lower()
    env["HERMES_ZULIP_TOPICS"] = _csv(
        zulip.get("topic_allowlist") or zulip.get("topics") or zulip.get("topic")
    ) or ""
    env["HERMES_ZULIP_ALLOWED_SENDERS"] = _csv(zulip.get("allowed_senders")) or ""
    env["HERMES_ZULIP_ALLOW_DMS"] = "1" if notifier.get("allow_direct_messages") is True else "0"
    env["HERMES_ZULIP_ALLOWED_DM_RECIPIENTS"] = _csv(notifier.get("allowed_dm_recipients")) or ""
    env["HERMES_ZULIP_NOTIFIER_STATE"] = str(_path(notifier.get("state_path") or state_dir / f"{instance}_zulip_kanban_notifier.json"))
    _install_env(env)
    return env


def _common_env(config: dict[str, Any], *, purpose: str, require_secret: bool, credential_preflight: dict[str, str] | None = None) -> dict[str, str]:
    issues = validate_config(config, require_secret=require_secret)
    if issues:
        raise ValueError("; ".join(issues))
    env: dict[str, str] = {}
    zulip = _section(config, "zulip")
    source_env_names = {
        str(zulip.get(key) or "").strip()
        for key in ("site_env", "bot_email_env", "bot_api_key_env", "api_key_env", "zuliprc_env", "rc_path_env")
    } - {""}
    explicit = zulip.get("zuliprc") or zulip.get("rc_path")
    if explicit:
        rc_path = str(Path(str(explicit)).expanduser())
        env["HERMES_ZULIP_RC"] = rc_path
        env["ZULIPRC"] = rc_path
        env["HERMES_ZULIP_SECRET_ENV_NAMES"] = ",".join(sorted(source_env_names))
        return env
    if credential_preflight is not None:
        env.update(
            HERMES_ZULIP_SITE=credential_preflight["site"],
            HERMES_ZULIP_EMAIL=credential_preflight["email"],
            HERMES_ZULIP_API_KEY=credential_preflight["key"],
            HERMES_ZULIP_SECRET_ENV_NAMES=",".join(sorted(source_env_names)),
        )
        return env
    site = _config_value(zulip, "site", "site_env").rstrip("/")
    email = _config_value(zulip, "bot_email", "bot_email_env")
    key_env = str(zulip.get("bot_api_key_env") or zulip.get("api_key_env") or "").strip()
    key = os.environ.get(key_env, "") if key_env else ""
    if require_secret and not key:
        raise ValueError(f"environment variable {key_env} is not set")
    if site and email and key:
        env.update(
            HERMES_ZULIP_SITE=site,
            HERMES_ZULIP_EMAIL=email,
            HERMES_ZULIP_API_KEY=key,
            HERMES_ZULIP_SECRET_ENV_NAMES=",".join(sorted(source_env_names)),
        )
    return env


def _section(config: dict[str, Any], key: str) -> dict[str, Any]:
    value = config.get(key)
    return value if isinstance(value, dict) else {}


def _install_env(env: dict[str, str]) -> None:
    credential_names = {
        "HERMES_ZULIP_SITE",
        "HERMES_ZULIP_EMAIL",
        "HERMES_ZULIP_API_KEY",
        "HERMES_ZULIP_SECRET_ENV_NAMES",
        "HERMES_ZULIP_RC",
        "ZULIPRC",
    }
    for name in credential_names - env.keys():
        os.environ.pop(name, None)
    os.environ.update(env)


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


def _valid_sender(value: Any) -> bool:
    text = str(value or "").strip()
    if text.startswith("id:"):
        return text[3:].isdigit() and int(text[3:]) > 0
    if text.startswith("email:"):
        address = text[6:].strip()
        return bool(
            address.count("@") == 1
            and all(address.split("@"))
            and not any(character.isspace() for character in address)
        )
    return False


def _path(value: Any) -> Path:
    if isinstance(value, Path):
        return value.expanduser()
    return Path(str(value)).expanduser()


def _canonical_path(value: Any) -> Path:
    return _path(value).resolve(strict=False)


def _set(env: dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    text = str(value)
    if text:
        env[key] = text
