#!/usr/bin/env bash
# Classify an Error Trigger payload, or append one JSONL log line.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/classify_error.py" "$@"
