"""Shared helpers for Leaf5 MCP servers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

# tools/mcp/common.py → repo root is parents[2]
REPO_ROOT = Path(__file__).resolve().parents[2]
LEAF5 = REPO_ROOT / "leaf5"
RAW = LEAF5 / "raw"
DEFAULT_VMLINUX = RAW / "vmlinux.elf"
ABS_VMLINUX = RAW / "vmlinux_abs.elf"

# Expected runtime markers (Leaf5 #245)
EXPECTED_KERNEL_MARKERS = ("4.19.157", "#245", "g3d47a6619220")


def run_cmd(
    argv: list[str],
    *,
    timeout: float = 60.0,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> dict:
    """Run a command; always return a structured dict (never raise for nonzero)."""
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged,
            cwd=str(cwd) if cwd else None,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "argv": argv,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": e.stdout or "",
            "stderr": (e.stderr or "") + f"\n[timeout after {timeout}s]",
            "argv": argv,
            "timeout": True,
        }
    except FileNotFoundError as e:
        return {
            "ok": False,
            "returncode": -2,
            "stdout": "",
            "stderr": str(e),
            "argv": argv,
        }


def resolve_vmlinux(path: str | None = None) -> Path:
    if path:
        p = Path(path)
        if not p.is_absolute():
            p = REPO_ROOT / p
        return p
    if DEFAULT_VMLINUX.is_file():
        return DEFAULT_VMLINUX
    if ABS_VMLINUX.is_file():
        return ABS_VMLINUX
    raise FileNotFoundError(
        f"No vmlinux found. Expected {DEFAULT_VMLINUX} or {ABS_VMLINUX}"
    )
