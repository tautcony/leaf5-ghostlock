#!/usr/bin/env python3
"""Leaf5 adb MCP — structured device ops for probe push/run (non-destructive)."""

from __future__ import annotations

import shlex
import shutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from common import EXPECTED_KERNEL_MARKERS, REPO_ROOT, run_cmd

mcp = FastMCP(
    "leaf5-adb",
    instructions=(
        "ADB helpers for Onyx Leaf5 GhostLock research. "
        "Never flash, fastboot, or dd without explicit user confirmation. "
        "Prefer adb_uname_check before trusting offsets against the device."
    ),
)

ADB = shutil.which("adb") or "adb"
REMOTE_STAGES_ROOT = "/data/local/tmp/stages"


def _adb_base(serial: str | None) -> list[str]:
    cmd = [ADB]
    if serial:
        cmd.extend(["-s", serial])
    return cmd


@mcp.tool()
def adb_devices() -> dict:
    """List adb devices (serial, state)."""
    r = run_cmd([ADB, "devices", "-l"], timeout=15)
    devices = []
    for line in (r.get("stdout") or "").splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1], "raw": line})
    return {"ok": r["ok"], "devices": devices, "raw": r["stdout"], "stderr": r["stderr"]}


@mcp.tool()
def adb_shell(command: str, serial: str | None = None, timeout_sec: float = 30.0) -> dict:
    """Run a remote shell command (non-interactive). Avoid destructive ops."""
    lowered = command.lower()
    blocked = ("fastboot", "dd if=", "dd of=", "flash", "magisk", "reboot bootloader")
    for b in blocked:
        if b in lowered:
            return {
                "ok": False,
                "blocked": True,
                "reason": f"Blocked potentially destructive pattern: {b!r}. Confirm with user first.",
                "command": command,
            }
    argv = _adb_base(serial) + ["shell", command]
    return run_cmd(argv, timeout=timeout_sec)


@mcp.tool()
def adb_uname_check(serial: str | None = None) -> dict:
    """Fetch uname -a and check Leaf5 #245 / g3d47a6619220 markers."""
    r = run_cmd(_adb_base(serial) + ["shell", "uname -a"], timeout=15)
    uname = (r.get("stdout") or "").strip()
    missing = [m for m in EXPECTED_KERNEL_MARKERS if m not in uname]
    return {
        "ok": r["ok"] and not missing,
        "uname": uname,
        "expected_markers": list(EXPECTED_KERNEL_MARKERS),
        "missing_markers": missing,
        "match": len(missing) == 0,
        "stderr": r.get("stderr", ""),
        "note": (
            "Runtime matches Leaf5 analysis image."
            if not missing
            else "Mismatch — do not use leaf5/raw vmlinux offsets against this device."
        ),
    }


@mcp.tool()
def adb_push(
    local_path: str,
    remote_path: str | None = None,
    serial: str | None = None,
) -> dict:
    """Push a local file to the device. Default remote under /data/local/tmp/stages/."""
    local = Path(local_path)
    if not local.is_absolute():
        local = REPO_ROOT / local
    if not local.is_file():
        return {"ok": False, "error": f"Local file not found: {local}"}

    if remote_path is None:
        # Mirror out/stages/... layout when possible
        try:
            rel = local.relative_to(REPO_ROOT / "out" / "stages")
            remote_path = f"{REMOTE_STAGES_ROOT}/{rel.as_posix()}"
        except ValueError:
            remote_path = f"{REMOTE_STAGES_ROOT}/{local.name}"

    remote_dir = str(Path(remote_path).parent)
    mkdir = run_cmd(
        _adb_base(serial) + ["shell", f"mkdir -p {shlex.quote(remote_dir)}"],
        timeout=15,
    )
    push = run_cmd(
        _adb_base(serial) + ["push", str(local), remote_path],
        timeout=120,
    )
    chmod = run_cmd(
        _adb_base(serial) + ["shell", f"chmod 755 {shlex.quote(remote_path)}"],
        timeout=15,
    )
    return {
        "ok": push["ok"],
        "local": str(local),
        "remote": remote_path,
        "mkdir": mkdir,
        "push": push,
        "chmod": chmod,
    }


@mcp.tool()
def adb_pull(
    remote_path: str,
    local_path: str | None = None,
    serial: str | None = None,
) -> dict:
    """Pull a remote file to the host (default: repo out/device-pull/)."""
    if local_path is None:
        dest_dir = REPO_ROOT / "out" / "device-pull"
        dest_dir.mkdir(parents=True, exist_ok=True)
        local = dest_dir / Path(remote_path).name
    else:
        local = Path(local_path)
        if not local.is_absolute():
            local = REPO_ROOT / local
        local.parent.mkdir(parents=True, exist_ok=True)

    r = run_cmd(
        _adb_base(serial) + ["pull", remote_path, str(local)],
        timeout=120,
    )
    return {
        "ok": r["ok"],
        "remote": remote_path,
        "local": str(local),
        "stdout": r.get("stdout"),
        "stderr": r.get("stderr"),
        "returncode": r.get("returncode"),
    }


@mcp.tool()
def adb_run_probe(
    local_binary: str,
    args: str = "",
    serial: str | None = None,
    timeout_sec: float = 60.0,
    remote_path: str | None = None,
    skip_uname_check: bool = False,
) -> dict:
    """Push a probe binary, chmod, run it, return stdout/stderr/exit code.

    By default verifies uname markers first. Set skip_uname_check only when intentional.
    """
    if not skip_uname_check:
        check = adb_uname_check(serial=serial)
        if not check.get("match"):
            return {
                "ok": False,
                "error": "uname markers mismatch; refusing to run probe against wrong kernel",
                "uname_check": check,
            }
    else:
        check = {"skipped": True}

    pushed = adb_push(local_binary, remote_path=remote_path, serial=serial)
    if not pushed.get("ok"):
        return {"ok": False, "error": "push failed", "push": pushed, "uname_check": check}

    remote = pushed["remote"]
    # adb shell with args: keep as single remote command string
    remote_cmd = remote if not args else f"{remote} {args}"
    run = run_cmd(
        _adb_base(serial) + ["shell", remote_cmd],
        timeout=timeout_sec,
    )
    return {
        "ok": run["ok"],
        "uname_check": check,
        "remote": remote,
        "command": remote_cmd,
        "returncode": run.get("returncode"),
        "stdout": run.get("stdout"),
        "stderr": run.get("stderr"),
        "timeout": run.get("timeout", False),
    }


@mcp.tool()
def adb_logcat(
    filter_spec: str = "*:E",
    duration_sec: float = 5.0,
    serial: str | None = None,
    clear_first: bool = True,
) -> dict:
    """Capture logcat for a short duration (hard-capped at 60s)."""
    duration_sec = max(0.5, min(float(duration_sec), 60.0))
    base = _adb_base(serial)
    if clear_first:
        run_cmd(base + ["logcat", "-c"], timeout=10)
    # timeout is enforced by run_cmd; logcat runs until killed by timeout
    r = run_cmd(
        base + ["logcat", "-v", "time", filter_spec],
        timeout=duration_sec,
    )
    # timeout is expected for time-bounded capture
    return {
        "ok": True,
        "duration_sec": duration_sec,
        "filter": filter_spec,
        "stdout": r.get("stdout"),
        "stderr": r.get("stderr"),
        "note": "Process stopped by duration timeout (normal for bounded capture).",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
