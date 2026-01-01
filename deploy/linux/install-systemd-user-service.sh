#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 CONFIG.yaml [--no-start]" >&2
  exit 2
fi
CONFIG="$1"
SERVICE_NAME="${HERMES_ZULIP_SERVICE:-hermes-zulip-bridge.service}"
PYTHON_BIN="${PYTHON:-python3}"
ENV_FILE="${HERMES_ZULIP_ENV_FILE:-$HOME/.config/hermes-zulip-bridge.env}"
SYSTEMD_DIR="${SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
SERVICE_PATH="$SYSTEMD_DIR/$SERVICE_NAME"
TMP_SERVICE="${SERVICE_PATH}.tmp.$$"
BACKUP_SERVICE=""
NO_START=0

for arg in "${@:2}"; do
  case "$arg" in
    --no-start) NO_START=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p "$SYSTEMD_DIR" "$(dirname "$ENV_FILE")"
if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/deploy/env/hermes-zulip-bridge.env.example" "$ENV_FILE"
fi
python3 - "$ROOT/deploy/linux/hermes-zulip-bridge.service.template" "$TMP_SERVICE" "$PYTHON_BIN" "$CONFIG" "$ROOT" "$ENV_FILE" <<'PY'
import sys
from pathlib import Path

template, output, python_bin, config, workdir, env_file = sys.argv[1:]
text = Path(template).read_text()
for key, value in {
    "PYTHON": python_bin,
    "CONFIG": str(Path(config).expanduser()),
    "WORKDIR": workdir,
    "ENV_FILE": str(Path(env_file).expanduser()),
}.items():
    text = text.replace("{{" + key + "}}", value)
Path(output).write_text(text)
PY
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze --user verify "$TMP_SERVICE" >/dev/null || true
fi
if [[ -f "$SERVICE_PATH" ]]; then
  BACKUP_SERVICE="${SERVICE_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$SERVICE_PATH" "$BACKUP_SERVICE"
fi
mv "$TMP_SERVICE" "$SERVICE_PATH"

systemctl --user daemon-reload
echo "Wrote $SERVICE_PATH"
if [[ "$NO_START" == "1" ]]; then
  exit 0
fi
if ! systemctl --user enable --now "$SERVICE_NAME"; then
  if [[ -n "$BACKUP_SERVICE" && -f "$BACKUP_SERVICE" ]]; then
    cp -p "$BACKUP_SERVICE" "$SERVICE_PATH"
    systemctl --user daemon-reload
    systemctl --user enable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
  echo "Failed to start $SERVICE_NAME; restored ${BACKUP_SERVICE:-no previous unit}." >&2
  exit 1
fi
systemctl --user status "$SERVICE_NAME" --no-pager
