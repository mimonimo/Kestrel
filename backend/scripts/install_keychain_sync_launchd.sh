#!/usr/bin/env bash
#
# Install a macOS LaunchAgent that runs sync_claude_creds_from_keychain.sh
# every hour, so the in-container claude CLI never sees a stale token.
#
# Why this exists
# ---------------
# The host's macOS Claude CLI auto-refreshes OAuth tokens on use, but
# stores them in Keychain — invisible to the Linux CLI in the kestrel
# backend container, which falls back to the legacy
# ``~/.claude/.credentials.json`` file. Without periodic mirroring that
# file goes stale within hours and the AI features start returning
# "claude CLI 응답이 비어 있습니다" or 401.
#
# This plist runs the sync script every 3600 seconds. The bind mount
# inside the container picks up the new file contents transparently —
# no backend restart needed.
#
# Run on the host (not in a container). Idempotent: re-running just
# overwrites the plist with the latest content + reloads the agent.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "이 스크립트는 macOS LaunchAgent 전용입니다. Linux 호스트는 cron 으로 직접 등록하세요:" >&2
  echo "  echo '0 * * * * $(cd "$(dirname "$0")" && pwd)/sync_claude_creds_from_keychain.sh' | crontab -" >&2
  exit 2
fi

LABEL="com.kestrel.creds-sync"
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/sync_claude_creds_from_keychain.sh"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs"

if [[ ! -x "$SCRIPT_PATH" ]]; then
  echo "sync 스크립트가 없거나 실행권한이 없습니다: $SCRIPT_PATH" >&2
  exit 1
fi

mkdir -p "$PLIST_DIR" "$LOG_DIR"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$SCRIPT_PATH</string>
  </array>
  <key>StartInterval</key>
  <integer>3600</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/$LABEL.out.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/$LABEL.err.log</string>
</dict>
</plist>
EOF

# Reload — unload first if it was already loaded, then load fresh.
# Both bootout/bootstrap (modern) and unload/load (legacy) are tried so
# this works on macOS Sequoia and older. Errors are tolerated because
# unload-when-not-loaded is the normal first-install case.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH" 2>/dev/null \
  || { launchctl unload "$PLIST_PATH" 2>/dev/null || true; launchctl load "$PLIST_PATH"; }

echo "installed: $PLIST_PATH"
echo "  · runs every 3600s + on load"
echo "  · 로그: $LOG_DIR/$LABEL.{out,err}.log"
echo "  · 제거: launchctl bootout gui/\$(id -u)/$LABEL && rm $PLIST_PATH"
