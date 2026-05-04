#!/usr/bin/env bash
#
# Build every generic vulnerability lab image referenced by
# backend/app/services/sandbox/catalog.py. Run from anywhere — paths are
# resolved relative to the script's own directory.
#
# Each image is small (~150-180MB; all share the python:3.12-slim base
# layer) so the total cold build is ~3-5 minutes on a warm pip cache.
# Re-runs are cached down to a few seconds per image.

set -euo pipefail

cd "$(dirname "$0")"

# kind → context-dir mapping. Keep in lockstep with LAB_CATALOG image
# names — if you add a kind in catalog.py, append it here too.
declare -a labs=(
  "kestrel-lab-xss:latest|xss-flask"
  "kestrel-lab-rce:latest|rce-flask"
  "kestrel-lab-sqli:latest|sqli-flask"
  "kestrel-lab-ssti:latest|ssti-flask"
  "kestrel-lab-path:latest|path-flask"
  "kestrel-lab-ssrf:latest|ssrf-flask"
  "kestrel-lab-auth:latest|auth-flask"
)

for entry in "${labs[@]}"; do
  tag="${entry%%|*}"
  ctx="${entry#*|}"
  if [[ ! -d "$ctx" ]]; then
    echo "[skip] $tag — context dir '$ctx' missing" >&2
    continue
  fi
  echo "[build] $tag ← $ctx/"
  docker build -q -t "$tag" "$ctx"
done

echo "done. listing:"
docker image ls --filter 'reference=kestrel-lab-*' --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}'
