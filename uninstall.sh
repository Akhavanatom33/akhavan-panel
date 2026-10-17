#!/usr/bin/env bash
# Stops Akhavan Panel. Add --purge to also delete data/ (all configs and keys!) and .env.
set -euo pipefail
cd "$(dirname "$0")"
docker compose --profile node --profile python down || true
if [ "${1:-}" = "--purge" ]; then
  read -r -p "Delete ./data and ./.env permanently? Type YES: " ans
  if [ "$ans" = "YES" ]; then rm -rf data .env; echo "deleted."; else echo "kept."; fi
fi
