# Leaf5 MCP servers

Research tooling for this repository only. Non-destructive by default.

## Servers

| Name | Script | Purpose |
|------|--------|---------|
| `leaf5-adb` | `adb_server.py` | devices, shell, uname check, push/pull, run probe, logcat |
| `leaf5-vmlinux` | `kernel_query_server.py` | symbol lookup, disasm (fixed bl/adrp), frame size, CFU sites, waiter compare |

Configured in repo `.grok/config.toml` (project scope).

## Requirements

- Repo root: `uv sync` (pulls `mcp`, `capstone`, `pyelftools`)
- Host `adb` on `PATH` for `leaf5-adb`
- `leaf5/raw/vmlinux.elf` for `leaf5-vmlinux`

## Manual smoke test

```bash
# From repo root
uv run python tools/mcp/adb_server.py &
# Prefer: grok mcp doctor leaf5-adb

uv run python -c "
from tools.mcp.common import REPO_ROOT
print(REPO_ROOT)
"
```

List tools after Grok loads project config (`/mcps` or `grok mcp list`).

## Safety

`leaf5-adb` blocks obvious destructive patterns (`fastboot`, `dd`, `flash`, …).  
EDL/fastboot rewrites still require **explicit user confirmation** per `AGENTS.md`.
