#!/usr/bin/env python3
"""Summarize GhostLock-relevant CONFIG options from raw/kernel_config.txt."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "raw" / "kernel_config.txt"

FOCUS = [
    "CONFIG_FUTEX",
    "CONFIG_FUTEX_PI",
    "CONFIG_RT_MUTEXES",
    "CONFIG_DEBUG_RT_MUTEXES",
    "CONFIG_USER_NS",
    "CONFIG_ASHMEM",
    "CONFIG_ANDROID_BINDER_IPC",
    "CONFIG_ANDROID_BINDERFS",
    "CONFIG_RANDOMIZE_BASE",
    "CONFIG_UNMAP_KERNEL_AT_EL0",
    "CONFIG_ARM64_VA_BITS",
    "CONFIG_ARM64_4K_PAGES",
    "CONFIG_CFI_CLANG",
    "CONFIG_LTO_NONE",
    "CONFIG_LTO_CLANG",
    "CONFIG_SHADOW_CALL_STACK",
    "CONFIG_ARM64_PTR_AUTH",
    "CONFIG_ARM64_BTI",
    "CONFIG_SECCOMP",
    "CONFIG_SECURITY_SELINUX",
    "CONFIG_IKCONFIG_PROC",
    "CONFIG_MODULES",
    "CONFIG_KALLSYMS_ALL",
    "CONFIG_SLUB",
    "CONFIG_HARDENED_USERCOPY",
    "CONFIG_FORTIFY_SOURCE",
    "CONFIG_STACKPROTECTOR_STRONG",
    "CONFIG_PANIC_ON_OOPS",
    "CONFIG_DEBUG_LIST",
    "CONFIG_VMAP_STACK",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_IO_URING",
    "CONFIG_PREEMPT",
    "CONFIG_NR_CPUS",
    "CONFIG_SLAB_FREELIST_HARDENED",
    "CONFIG_SLAB_FREELIST_RANDOM",
    "CONFIG_INIT_STACK_NONE",
    "CONFIG_KASAN",
    "CONFIG_UBSAN",
]


def conf_value(text: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}=(.*)$", text, re.M)
    if m:
        return m.group(1).strip()
    if re.search(rf"^# {re.escape(name)} is not set", text, re.M):
        return "n"
    # Absent from defconfig dump ⇒ not enabled for this build (treat as n).
    return "n"


def main() -> int:
    if not CFG.exists():
        print(f"missing {CFG}; run leaf5-collect first", file=sys.stderr)
        return 1
    text = CFG.read_text(errors="replace")
    print(f"# from {CFG}")
    for k in FOCUS:
        print(f"{k}={conf_value(text, k)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
