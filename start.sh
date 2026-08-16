#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
export SUSCIYUAN_ENV="${SUSCIYUAN_ENV:-$DIR/.env}"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-8787}"
cd "$DIR"
exec python3 "$DIR/app.py"
