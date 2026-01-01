#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 CONFIG.yaml [--no-start]" >&2
  exit 2
fi
CONFIG="$1"
LABEL="${HERMES_ZULIP_LABEL:-com.hermes.zulip-bridge}"
PYTHON_BIN="${PYTHON:-python3}"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
TMP_PLIST="${PLIST}.tmp.$$"
BACKUP_PLIST=""
STDOUT_LOG="${HERMES_ZULIP_STDOUT:-$ROOT/logs/${LABEL}.out.log}"
STDERR_LOG="${HERMES_ZULIP_STDERR:-$ROOT/logs/${LABEL}.err.log}"
NO_START=0

for arg in "${@:2}"; do
  case "$arg" in
    --no-start) NO_START=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$PLIST")" "$ROOT/logs"
python3 - "$ROOT/deploy/macos/com.hermes.zulip-bridge.plist.template" "$TMP_PLIST" "$LABEL" "$PYTHON_BIN" "$CONFIG" "$ROOT" "$STDOUT_LOG" "$STDERR_LOG" <<'PY'
import sys
from pathlib import Path

template, output, label, python_bin, config, workdir, stdout, stderr = sys.argv[1:]
text = Path(template).read_text()
for key, value in {
    "LABEL": label,
    "PYTHON": python_bin,
    "CONFIG": str(Path(config).expanduser()),
    "WORKDIR": workdir,
    "STDOUT": stdout,
    "STDERR": stderr,
}.items():
    text = text.replace("{{" + key + "}}", value)
Path(output).write_text(text)
PY
plutil -lint "$TMP_PLIST" >/dev/null
if [[ -f "$PLIST" ]]; then
  BACKUP_PLIST="${PLIST}.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$PLIST" "$BACKUP_PLIST"
fi
mv "$TMP_PLIST" "$PLIST"

echo "Wrote $PLIST"
if [[ "$NO_START" == "1" ]]; then
  exit 0
fi
launchctl bootout "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 || true
if ! launchctl bootstrap "gui/$(id -u)" "$PLIST"; then
  if [[ -n "$BACKUP_PLIST" && -f "$BACKUP_PLIST" ]]; then
    cp -p "$BACKUP_PLIST" "$PLIST"
    launchctl bootstrap "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 || true
  fi
  echo "Failed to bootstrap $LABEL; restored ${BACKUP_PLIST:-no previous plist}." >&2
  exit 1
fi
launchctl kickstart -k "gui/$(id -u)/$LABEL"
echo "Started $LABEL"
