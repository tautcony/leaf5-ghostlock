#!/usr/bin/env python3
"""
Extract kernel structure offsets from vmlinux ELF via capstone disassembly.

Usage (from leaf5/):
    uv run python -m scripts.extract_offsets

Requires:
    - raw/vmlinux.elf or raw/vmlinux_abs.elf (from vmlinux-to-elf)
    - capstone + pyelftools (installed via uv)

Output:
    - Prints verified structure offsets to stdout
    - Generates symbol offset list for target.h
"""

from __future__ import annotations

import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_MEM  # noqa: F401
from elftools.elf.elffile import ELFFile

ROOT = next(
    p for p in Path(__file__).resolve().parents
    if (p / "raw").is_dir() and (p / "stages").is_dir()
)
RAW = ROOT / "raw"
VMLINUX_ELF = RAW / "vmlinux.elf"


def load_symbols(elf_path: Path) -> dict:
    """Load all symbols from vmlinux ELF, return {name: address}."""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            raise ValueError("No .symtab in ELF")
        return {sym.name: sym.entry.st_value for sym in symtab.iter_symbols() if sym.name}


def get_section_data(elf_path: Path) -> tuple[int, bytes, int]:
    """Return (text_base, text_data, text_size) for the .kernel code section."""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return sec.header.sh_addr, sec.data(), sec.header.sh_size
    raise ValueError("No .kernel PROGBITS section found")


def disasm_function(addr: int, data: bytes, text_base: int, size: int = 0x400) -> bytes:
    """Extract function bytes at addr from section data."""
    off = addr - text_base
    return data[off : off + size]


def find_memory_offsets(
    func_bytes: bytes, func_addr: int, base_regs: tuple[str, ...], max_insns: int = 200
) -> dict[int, list[str]]:
    """
    Disassemble function and find all unique memory access offsets
    from specified base registers.

    Returns {offset: [instruction_strings]}.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    offsets: dict[int, list[str]] = {}
    count = 0

    for insn in md.disasm(func_bytes, func_addr):
        count += 1
        for op in insn.operands:
            if op.type == 3 and op.mem.base != 0:  # ARM64_OP_MEM
                base_reg = insn.reg_name(op.mem.base)
                disp = op.mem.disp
                if base_reg in base_regs and 0 <= disp <= 0x1000:
                    detail = f"{insn.mnemonic} {insn.op_str}"
                    offsets.setdefault(disp, []).append(detail)

        if count >= max_insns or insn.mnemonic == "ret":
            break

    return offsets


# ── Key functions and what they access ──────────────────────────
ANALYSIS_TARGETS = [
    # (function_name, base_regs, description)
    ("commit_creds", ("x0", "x19", "x20", "x21"), "task->real_cred, task->cred, cred fields"),
    ("exit_creds", ("x0", "x19"), "task->real_cred=NULL, task->cred=NULL"),
    ("find_task_by_vpid", ("x0",), "pid lookup via hash"),
    ("task_blocks_on_rt_mutex", ("x0", "x19", "x20", "x23"), "task->pi_blocked_on, waiter fields"),
    (
        "rt_mutex_adjust_prio_chain",
        ("x19", "x20", "x23", "x28"),
        "task->pi_blocked_on, task->prio, pi_waiters",
    ),
    ("__put_task_struct", ("x0", "x19", "x20"), "task->usage, task->stack, cred fields"),
    ("get_task_cred", ("x0",), "task->real_cred"),
    ("pipe_write", ("x0", "x19", "x20"), "pipe_inode_info fields"),
    ("pipe_read", ("x0", "x19", "x20"), "pipe_inode_info fields"),
    ("mm_update_next_owner", ("x0", "x19", "x20"), "mm_struct->owner"),
    ("rt_mutex_init_waiter", ("x0",), "waiter struct init (size clues)"),
    ("do_futex", ("sp", "x29"), "do_futex stack frame size"),
    ("futex_wait", ("sp", "x29"), "futex_wait stack frame"),
]

# ── Symbol categories for target.h generation ──────────────────
SYMBOL_CATEGORIES = {
    "Core kernel": [
        "init_task",
        "init_cred",
        "init_nsproxy",
        "init_uts_ns",
        "init_net",
        "init_mm",
        "empty_zero_page",
        "root_task_group",
    ],
    "ashmem": [
        "ashmem_fops",
        "ashmem_misc",
        "ashmem_ioctl",
        "compat_ashmem_ioctl",
        "ashmem_mmap",
        "ashmem_open",
        "ashmem_release",
        "ashmem_show_fdinfo",
    ],
    "pipe / fops": [
        "anon_pipe_buf_ops",
        "anon_pipe_buf_nomerge_ops",
        "generic_ro_fops",
        "noop_llseek",
    ],
    "configfs": [
        "configfs_read_file",
        "configfs_write_file",
    ],
    "splice": [
        "generic_file_splice_read",
    ],
    "kmalloc / slab": [
        "kmalloc_caches",
        "cred_jar",
        "task_struct_cachep",
        "kmem_cache_alloc",
        "kmem_cache_free",
    ],
    "SELinux": [
        "selinux_state",
        "selinux_enabled",
        "selinux_enforcing_boot",
        "security_hook_heads",
    ],
    "futex / rtmutex": [
        "do_futex",
        "futex_wait",
        "futex_wake",
        "futex_requeue",
        "futex_lock_pi",
        "rt_mutex_adjust_prio_chain",
        "task_blocks_on_rt_mutex",
        "rt_mutex_slowlock",
        "remove_waiter",
        "mark_wakeup_next_waiter",
        "wake_up_state",
    ],
    "rbtree / plist": [
        "rb_erase",
        "rb_insert_color",
        "plist_add",
        "plist_del",
    ],
    "cred operations": [
        "commit_creds",
        "prepare_kernel_cred",
        "override_creds",
    ],
    "KASLR": [
        "kimage_vaddr",
        "kimage_voffset",
        "memstart_addr",
    ],
}


def main() -> int:
    if not VMLINUX_ELF.exists():
        print(f"ERROR: {VMLINUX_ELF} not found. Run vmlinux-to-elf first.")
        return 1

    symbols = load_symbols(VMLINUX_ELF)
    text_base, text_data, _ = get_section_data(VMLINUX_ELF)

    text = symbols.get("_text", text_base)
    print(f"# _text (kernel base): 0x{text:016x}")
    print(f"# Kernel: 4.19.157-perf (Qualcomm lito)")
    print()

    # ── Phase 1: Structure offset analysis ──────────────────────
    print("=" * 72)
    print("PHASE 1: Structure Offset Analysis (from binary disassembly)")
    print("=" * 72)

    for func_name, regs, desc in ANALYSIS_TARGETS:
        if func_name not in symbols:
            print(f"\n--- {func_name}: NOT FOUND ---")
            continue

        addr = symbols[func_name]
        func_bytes = disasm_function(addr, text_data, text_base)
        offsets = find_memory_offsets(func_bytes, addr, base_regs=regs)

        print(f"\n--- {func_name} ({desc}) @ 0x{addr:016x} ---")
        if offsets:
            for off in sorted(offsets):
                details = offsets[off]
                for d in details[:3]:  # max 3 details per offset
                    print(f"  +{off:#06x} ({off:5d}): {d}")
        else:
            print("  (no memory accesses found from target registers)")

    # ── Phase 2: Symbol offset dump for target.h ─────────────────
    print("\n" + "=" * 72)
    print("PHASE 2: Symbol Offsets (for target.h)")
    print("=" * 72)

    for category, sym_names in SYMBOL_CATEGORIES.items():
        print(f"\n  /* -- {category} -- */")
        for name in sym_names:
            if name in symbols:
                addr = symbols[name]
                off = addr - text
                print(f"  #define {name.upper()}_OFF 0x{off:08x}ULL  // 0x{addr:016x}")
            else:
                print(f"  // #define {name.upper()}_OFF NOT FOUND (4.19 may use different name)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
