#!/usr/bin/env bash
# Launch leaf5-adb MCP (stdio). Resolves repo root from this script.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
exec uv run python tools/mcp/adb_server.py
