#!/usr/bin/env bash
#
# Two-step token maintenance for the kestrel backend's claude_cli mount.
#
# Why two steps
# -------------
# sync_claude_creds_from_keychain.sh on its own can't *refresh* the
# OAuth access token — it just copies whatever is currently in the
# macOS Keychain. If the token in Keychain is itself expired (because
# nobody used `claude` for ~8 hours), the sync writes an expired value
# into the legacy file and the container CLI continues to 401.
#
# Calling `claude -p 'ping'` first forces the host CLI to consume the
# Keychain token; if expired, it transparently uses the refresh_token
# to get a new access_token AND writes the new value back into Keychain.
# Then the sync step copies that fresh value into the file the
# container reads.
#
# Cost: one tiny prompt-completion per cron run (~50 input tokens, 5
# output tokens). Hourly that's ~1.3k tokens/day — negligible vs. AI
# analysis usage.
#
# Run on the host (macOS). Idempotent.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS host 전용." >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SYNC_SCRIPT="$SCRIPT_DIR/sync_claude_creds_from_keychain.sh"

if [[ ! -x "$SYNC_SCRIPT" ]]; then
  echo "sync_claude_creds_from_keychain.sh 실행권한 없음: $SYNC_SCRIPT" >&2
  exit 1
fi

# Step 1: trigger OAuth refresh by exercising the host CLI. Output goes
# to /dev/null because we just want the side-effect (Keychain rewrite),
# not the assistant reply. We use the cheapest model + a one-token reply
# to keep cost trivial.
if ! command -v claude >/dev/null 2>&1; then
  echo "claude CLI not on PATH — skipping refresh, only sync 수행" >&2
else
  # macOS has no GNU `timeout`, so wrap with perl alarm idiom. 60s is
  # generous for a one-token reply but covers cold-start refresh.
  if ! perl -e 'alarm 60; exec @ARGV' \
        claude -p 'reply: ok' --model claude-haiku-4-5 --output-format text >/dev/null 2>&1; then
    # Don't fail the whole job — sync may still copy a usable token if
    # one already exists. Surface as warning so launchd log shows it.
    echo "warn: claude refresh ping failed (token may be unrenewable — run 'claude /login')" >&2
  fi
fi

# Step 2: copy the now-fresh Keychain entry into ~/.claude/.credentials.json.
"$SYNC_SCRIPT"
