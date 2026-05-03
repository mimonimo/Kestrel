#!/usr/bin/env bash
#
# Mirror macOS Keychain `Claude Code-credentials` → ~/.claude/.credentials.json
# so the kestrel backend container's claude CLI (Linux, no Keychain access)
# can authenticate via the read-only mount.
#
# Why this is needed
# ------------------
# Modern Claude Code CLI on macOS stores OAuth tokens in macOS Keychain,
# leaving ~/.claude/.credentials.json frozen at whatever value was written
# the day Keychain integration was enabled. The Linux CLI in the kestrel
# backend container can only read the legacy on-disk file → 401 against
# the (long-expired) token.
#
# This script writes the live Keychain entry back into the legacy file. The
# read-only bind mount inside the container picks up the new token without
# a rebuild — just call the AI feature again.
#
# Run this on the *host*, not inside a container.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "이 스크립트는 macOS 호스트 전용입니다 (Keychain 접근). Linux 호스트는 호스트의 claude CLI 가 ~/.claude/.credentials.json 을 직접 갱신합니다." >&2
  exit 2
fi

CRED_PATH="${CLAUDE_CREDS_PATH:-$HOME/.claude/.credentials.json}"
KEYCHAIN_SERVICE="${CLAUDE_KEYCHAIN_SERVICE:-Claude Code-credentials}"

if ! token_json="$(security find-generic-password -s "$KEYCHAIN_SERVICE" -w 2>/dev/null)"; then
  echo "Keychain 에서 '$KEYCHAIN_SERVICE' 항목을 못 찾음. 호스트에서 'claude /login' 한번 실행해 OAuth 를 다시 만들어주세요." >&2
  exit 1
fi

# Validate JSON shape so a partial Keychain dump doesn't replace a working
# file with garbage. Look for the `claudeAiOauth` key the CLI expects.
if ! /usr/bin/python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
assert "claudeAiOauth" in d, "missing claudeAiOauth"
oauth = d["claudeAiOauth"]
for k in ("accessToken", "refreshToken"):
    assert k in oauth, f"missing {k}"
' <<<"$token_json" >/dev/null 2>&1; then
  echo "Keychain 페이로드의 JSON 모양이 예상과 달라 ~/.claude/.credentials.json 을 덮어쓰지 않았습니다. 호스트에서 'claude /login' 으로 재로그인 후 다시 시도하세요." >&2
  exit 1
fi

mkdir -p "$(dirname "$CRED_PATH")"

# Atomic replace via temp file in the same directory so the inode swap
# is single-step (avoids partial writes if the script is interrupted).
tmp="$(mktemp "${CRED_PATH}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
printf '%s' "$token_json" > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$CRED_PATH"
trap - EXIT

# Surface expiry so the user knows when to re-sync. (No secret data.)
expires_at=$(/usr/bin/python3 -c 'import json,sys,datetime; d=json.load(open(sys.argv[1])); ts=d["claudeAiOauth"].get("expiresAt"); print(datetime.datetime.fromtimestamp(ts/1000).isoformat() if ts and ts > 1e12 else "unknown")' "$CRED_PATH")
echo "synced: $CRED_PATH (expiresAt=$expires_at)"
echo "참고: 컨테이너의 mount 가 read-only 라도 호스트가 파일을 새로 쓰면 즉시 새 토큰을 읽으므로 backend rebuild 는 불필요합니다."
