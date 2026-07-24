#!/usr/bin/env python3
"""Collect Leaf5 runtime artifacts via adb into leaf5/raw/.

Usage (from leaf5/):
    uv run leaf5-collect
    # or
    uv run python -m scripts.collect_device
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"


def adb(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["adb", *args],
        text=True,
        capture_output=True,
        check=check,
    )


def adb_shell(cmd: str) -> str:
    p = adb("shell", cmd)
    out = (p.stdout or "") + (p.stderr or "")
    return out.replace("\r", "")


def write(name: str, content: str) -> Path:
    RAW.mkdir(parents=True, exist_ok=True)
    path = RAW / name
    path.write_text(content, encoding="utf-8")
    return path


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = adb("get-serialno").stdout.strip()
    if not serial or "no devices" in serial.lower() or serial == "unknown":
        print("ERROR: no adb device", file=sys.stderr)
        return 1

    props = [
        "ro.product.model",
        "ro.product.brand",
        "ro.product.manufacturer",
        "ro.product.device",
        "ro.product.board",
        "ro.board.platform",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.build.display.id",
        "ro.build.fingerprint",
        "ro.build.type",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.boot.slot_suffix",
        "ro.serialno",
        "ro.secure",
        "ro.debuggable",
        "ro.adb.secure",
    ]
    lines = [f"# Collected: {stamp}", f"# Serial: {serial}", "", "## getprop"]
    for p in props:
        v = adb_shell(f"getprop {p}").strip()
        lines.append(f"{p}={v}")
    lines += ["", "## uname / version", adb_shell("uname -a").strip()]
    lines.append(adb_shell("cat /proc/version").strip())
    write("device_identity.txt", "\n".join(lines) + "\n")

    sec = [
        f"# Collected: {stamp}",
        "",
        "## id",
        adb_shell("id").strip(),
        "## getenforce",
        adb_shell("getenforce").strip(),
        "## caps / status",
        adb_shell(
            "grep -E '^(Uid|Gid|Cap|Seccomp|NoNewPrivs)' /proc/self/status"
        ).strip(),
        "## sysctls (may be SELinux-denied)",
    ]
    for f in [
        "/proc/sys/kernel/kptr_restrict",
        "/proc/sys/kernel/dmesg_restrict",
        "/proc/sys/kernel/perf_event_paranoid",
        "/proc/sys/kernel/randomize_va_space",
        "/proc/sys/kernel/unprivileged_bpf_disabled",
        "/proc/sys/kernel/modules_disabled",
        "/proc/sys/user/max_user_namespaces",
    ]:
        sec.append(f"{f}={adb_shell(f'cat {f} 2>&1').strip()}")
    sec += [
        "",
        "## kallsyms",
        adb_shell("ls -la /proc/kallsyms 2>&1; head -c 80 /proc/kallsyms 2>&1").strip(),
        "",
        "## devices",
        adb_shell(
            "ls -la /dev/ashmem /dev/binder /dev/ion /dev/kmsg 2>&1"
        ).strip(),
        "",
        "## mounts",
        adb_shell(
            "mount | grep -E 'configfs|debugfs|tracefs|selinux|binder|cgroup'"
        ).strip(),
    ]
    write("security_runtime.txt", "\n".join(sec) + "\n")

    # config.gz
    p = adb("exec-out", "cat", "/proc/config.gz")
    if p.returncode == 0 and p.stdout is not None:
        # binary via text mode may corrupt; use raw
        pass
    raw = subprocess.run(
        ["adb", "exec-out", "cat", "/proc/config.gz"],
        capture_output=True,
        check=False,
    )
    if raw.returncode == 0 and raw.stdout[:2] == b"\x1f\x8b":
        (RAW / "config.gz").write_bytes(raw.stdout)
        import gzip

        (RAW / "kernel_config.txt").write_bytes(gzip.decompress(raw.stdout))
        print("pulled config.gz")
    else:
        print("WARN: failed to pull config.gz", file=sys.stderr)

    # kheaders
    kh = subprocess.run(
        ["adb", "exec-out", "cat", "/sys/kernel/kheaders.tar.xz"],
        capture_output=True,
        check=False,
    )
    if kh.returncode == 0 and len(kh.stdout) > 1000:
        (RAW / "kheaders.tar.xz").write_bytes(kh.stdout)
        print(f"pulled kheaders.tar.xz ({len(kh.stdout)} bytes)")
    else:
        print("WARN: failed to pull kheaders", file=sys.stderr)

    print(f"done → {RAW}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
