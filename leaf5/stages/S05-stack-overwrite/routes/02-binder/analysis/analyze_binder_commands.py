#!/usr/bin/env python3
"""
GhostLock Binder Command Analysis — Leaf5 4.19 kernel

Fully disassembles binder_thread_write from vmlinux.elf and maps:
  - All BC_* command cases in the switch statement
  - All __arch_copy_from_user calls with destination SP offsets and sizes
  - All SP-relative stores (kernel pointer setup at SP+0x20..SP+0x78)
  - The switch dispatch logic and jump table

Usage:
    uv run python ghostlock-analysis/binder-commands/analyze_binder_commands.py
    uv run python ghostlock-analysis/binder-commands/analyze_binder_commands.py -v

Output: Writes ANALYSIS.md and command tables.
"""

from __future__ import annotations

import argparse
import struct
from collections import defaultdict
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

ADDR_MASK = 0xFFFFFFFFFFFFFFFF

# Waiter layout (4.19): 64 bytes, from -0x380 to -0x340
WAITER_ABS = -0x380
WAITER_SIZE = 0x40
WAITER_FIELDS = {
    0x00: "tree_entry.__rb_parent_color",
    0x08: "tree_entry.rb_right",
    0x10: "tree_entry.rb_left",
    0x18: "pi_tree_entry.__rb_parent_color",
    0x20: "pi_tree_entry.rb_right",
    0x28: "pi_tree_entry.rb_left",
    0x30: "task",
    0x38: "lock",
}

# Binder call chain depth (from syscall entry to binder_thread_write SP)
BINDER_TOTAL_DEPTH = 0x3a0
# Waiter relative to binder_thread_write SP:
WAITER_REL_SP = BINDER_TOTAL_DEPTH + WAITER_ABS  # = 0x20

# Known BC commands (from Linux binder driver)
BC_COMMAND_NAMES = {
    0x6301: "BC_TRANSACTION",
    0x6302: "BC_REPLY",
    0x6303: "BC_ACQUIRE_RESULT",
    0x6304: "BC_FREE_BUFFER",
    0x6305: "BC_INCREFS",
    0x6306: "BC_DECREFS",
    0x6307: "BC_INCREFS_DONE",
    0x6308: "BC_FREE_BUFFER_DONE",
    0x6309: "BC_DEAD_BINDER_DONE",
    0x630b: "BC_REGISTER_LOOPER",
    0x630c: "BC_ENTER_LOOPER",
    0x630d: "BC_EXIT_LOOPER",
    0x630e: "BC_REQUEST_DEATH_NOTIFICATION",
    0x630f: "BC_CLEAR_DEATH_NOTIFICATION",
    0x6310: "BC_DEAD_BINDER_DONE",
    0x6312: "BC_ACQUIRE",
}

def parse_imm(s: str) -> Optional[int]:
    s = s.strip().rstrip("]!,")
    if not s:
        return None
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
    if s.startswith("x") or s.startswith("w") or s in ("sp", "lr", "xzr", "wzr"):
        return None
    try:
        return int(s, 16 if s.startswith("0x") else 10)
    except ValueError:
        return None

def load_vmlinux(path: Path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        symbols = {sym.name: sym.entry.st_value
                   for sym in symtab.iter_symbols() if sym.name}
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return symbols, sec.header.sh_addr, sec.data()
    raise ValueError("No .kernel section")

def analyze_binder_thread_write(symbols, text_base, text_data):
    """Full analysis of binder_thread_write function."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    func_addr = symbols["binder_thread_write"]
    func_name = "binder_thread_write"
    off = func_addr - text_base
    fbytes = text_data[off:off + 0x2000]
    insns = list(md.disasm(fbytes, func_addr))

    total_frame = 0
    fp_offset = 0
    sp_stores = []
    copy_from_user_calls = []
    bl_calls = []
    bc_cases = []

    cfu_addr = symbols.get("__arch_copy_from_user", 0)

    # Track which register has which value for tracing
    reg_last_set = {}

    for i, insn in enumerate(insns):
        op = insn.op_str
        addr = insn.address

        # Frame allocation
        if insn.mnemonic == "sub" and "sp, sp" in op:
            val = parse_imm(op.split("#")[-1].strip(","))
            if val is not None:
                total_frame += val

        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            val = parse_imm(op.split("#-")[1].split("]")[0])
            if val is not None:
                total_frame += val

        elif insn.mnemonic == "add" and "x29, sp" in op:
            val = parse_imm(op.split("#")[-1])
            if val is not None:
                fp_offset = val

        # SP/X29-relative stores
        for oper in insn.operands:
            if oper.type == ARM64_OP_MEM and oper.mem.base != 0:
                base_reg = insn.reg_name(oper.mem.base)
                disp = oper.mem.disp
                if base_reg in ("sp", "x29") and 0 <= disp <= 0x200:
                    sp_off = disp
                    if base_reg == "x29":
                        sp_off = fp_offset + disp
                    if insn.mnemonic in ("str", "stp", "stur"):
                        sp_stores.append({
                            "addr": addr, "mnemonic": insn.mnemonic,
                            "op_str": op, "sp_offset": sp_off,
                        })

        # BL calls
        if insn.mnemonic == "bl":
            target = insn.operands[0].imm & ADDR_MASK
            target_name = None
            for n, a in symbols.items():
                if a == target:
                    target_name = n
                    break

            call_info = {
                "addr": addr, "target": target,
                "target_name": target_name or f"0x{target:x}",
            }
            bl_calls.append(call_info)

            # __arch_copy_from_user
            if target == cfu_addr:
                dest_sp = None
                dest_desc = ""
                copy_size = None

                # Scan backward up to 30 instructions for x0 setup
                for j in range(i - 1, max(0, i - 30), -1):
                    prev = insns[j]
                    pop = prev.op_str

                    if prev.mnemonic == "add" and "x0, sp" in pop:
                        parts = pop.split("#")
                        if len(parts) > 1:
                            val = parse_imm(parts[-1].rstrip("]"))
                            if val is not None:
                                dest_sp = val
                                dest_desc = f"SP+0x{val:x}"
                                break

                    elif prev.mnemonic == "sub" and "x0, x29" in pop:
                        parts = pop.split("#")
                        if len(parts) > 1:
                            val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                            if val is not None:
                                dest_sp = fp_offset - val
                                dest_desc = f"SP+0x{dest_sp:x} (x29-0x{val:x})"
                                break

                    elif prev.mnemonic == "sub" and "x0, sp" in pop:
                        parts = pop.split("#")
                        if len(parts) > 1:
                            val = parse_imm(parts[-1].rstrip("]"))
                            if val is not None:
                                dest_sp = -val
                                dest_desc = f"SP-0x{val:x}"
                                break

                # Find mov w2, #N for copy size
                for j in range(i - 1, max(0, i - 15), -1):
                    prev = insns[j]
                    pop = prev.op_str
                    if prev.mnemonic == "mov" and "w2, #" in pop:
                        val = parse_imm(pop.split("#")[-1])
                        if val is not None:
                            copy_size = val
                            break

                copy_from_user_calls.append({
                    "addr": addr,
                    "dest_sp": dest_sp,
                    "dest_desc": dest_desc or "(unknown)",
                    "copy_size": copy_size or 0,
                })

        # Switch cases: detect cmp w28, #IMM or cmp w28, w8
        if insn.mnemonic == "cmp" and ("w28" in op or "x28" in op):
            parts = op.split(",")
            reg = "w28" if "w28" in op else "x28"
            if len(parts) >= 2:
                val = parse_imm(parts[-1])
                if val is not None:
                    combined = val
                    # Look for preceding mov / movk sequence
                    for j in range(i - 1, max(0, i - 4), -1):
                        p = insns[j]
                        if p.mnemonic == "movk" and "lsl #16" in p.op_str:
                            p_parts = p.op_str.split(",")
                            if len(p_parts) >= 2:
                                k_val = parse_imm(p_parts[1].split("#")[1].strip().split(",")[0])
                                if k_val is not None:
                                    combined = val | (k_val << 16)
                        elif p.mnemonic == "mov" and "w8, #" in p.op_str:
                            m_val = parse_imm(p.op_str.split("#")[-1])
                            if m_val is not None:
                                combined = m_val | (combined & 0xFFFF0000) \
                                    if combined > 0xFFFF else m_val
                        else:
                            break

                    # Determine the BC command name
                    low_byte = combined & 0xFF
                    bc_name = BC_COMMAND_NAMES.get(low_byte,
                                                   f"BC_UNKNOWN(0x{low_byte:02x})")
                    high_prefix = (combined >> 16) & 0xFFFF

                    next_insn = insns[i + 1] if i + 1 < len(insns) else None

                    bc_cases.append({
                        "cmp_addr": addr,
                        "combined": combined & 0xFFFFFFFF,
                        "low_byte": low_byte,
                        "high_prefix": high_prefix,
                        "bc_name": bc_name,
                        "next_mnemonic": next_insn.mnemonic if next_insn else "",
                        "next_target": next_insn.op_str if next_insn else "",
                    })

    return {
        "func_addr": func_addr, "func_name": func_name,
        "frame_size": total_frame, "fp_offset": fp_offset,
        "num_insns": len(insns),
        "sp_stores": sp_stores,
        "copy_from_user_calls": copy_from_user_calls,
        "bl_calls": bl_calls,
        "bc_cases": bc_cases,
        "cfu_addr": cfu_addr,
    }


def print_analysis(r, symbols, verbose=False):
    """Print formatted analysis."""
    print("=" * 72)
    print("Binder Thread Write Analysis -- Leaf5 4.19")
    print("=" * 72)
    print(f"  Function:     {r['func_name']} @ 0x{r['func_addr']:x}")
    print(f"  Frame size:   0x{r['frame_size']:x} ({r['frame_size']} bytes)")
    print(f"  FP offset:    SP+0x{r['fp_offset']:x}")
    print(f"  Instructions: {r['num_insns']}")
    print()

    # ---- Section A: SP stores at the critical overlap range ----
    print("-" * 72)
    print("SECTION A: Kernel Pointer Setup at SP+0x20..SP+0x78")
    print("-" * 72)
    print(f"  Binder total call depth (from syscall entry): 0x{BINDER_TOTAL_DEPTH:x}")
    print(f"  Waiter absolute offset: {WAITER_ABS:+d}")
    print(f"  Waiter relative to binder_thread_write SP: SP+0x{WAITER_REL_SP:x}")
    print(f"  Waiter occupies: SP+0x{WAITER_REL_SP:x} .. SP+0x{WAITER_REL_SP + WAITER_SIZE:x}")
    print()

    # Group stores by offset
    stores_by_off = defaultdict(list)
    for s in r["sp_stores"]:
        stores_by_off[s["sp_offset"]].append(s)

    print(f"  Stores in range [SP+0x00, SP+0x80):")
    print(f"  {'SP+':>7s} {'Addr':>16s} {'Op':>5s}  {'Source Expression'}")
    print(f"  {'----':>7s} {'----':>16s} {'--':>5s}  {'-----------------'}")
    for off in sorted(stores_by_off):
        if off >= 0x80:
            continue
        for s in stores_by_off[off]:
            print(f"  SP+0x{off:03x} 0x{s['addr']:x} {s['mnemonic']:>5s}  {s['op_str']}")

    # Map each store in the waiter range to a waiter field
    print()
    print(f"  Waiter field mapping:")
    print(f"  {'SP off':>7s} {'Waiter+':>8s} {'Field':>35s} {'Source'}")
    print(f"  {'------':>7s} {'------':>8s} {'-----':>35s} {'------'}")
    for byte_off in range(0, WAITER_SIZE, 8):
        sp_off = WAITER_REL_SP + byte_off
        field = WAITER_FIELDS.get(byte_off, "(reserved)")
        if sp_off in stores_by_off:
            s = stores_by_off[sp_off][0]
            print(f"  SP+0x{sp_off:03x} waiter+0x{byte_off:02x} {field:>35s}  {s['op_str']}")
        else:
            print(f"  SP+0x{sp_off:03x} waiter+0x{byte_off:02x} {field:>35s}  (no direct store)")

    # ---- Section B: __arch_copy_from_user calls ----
    print()
    print("-" * 72)
    print("SECTION B: __arch_copy_from_user calls")
    print("-" * 72)
    if not r["copy_from_user_calls"]:
        print("  (none found)")
    else:
        hdr = f"  {'BL@':>16s} {'Dest SP':>10s} {'Size':>6s}  {'Δ词':>5s} {'Overlap Fields'}"
        print(hdr)
        print(f"  {'---':>16s} {'------':>10s} {'----':>6s}  {'---':>5s} {'--------------'}")
        for cfu in r["copy_from_user_calls"]:
            sz = cfu["copy_size"]
            ds = cfu["dest_sp"]
            if ds is not None:
                dest_abs = -BINDER_TOTAL_DEPTH + ds
                delta = dest_abs - WAITER_ABS
                dw = delta // 8

                # Overlap calculation
                buf_start = dest_abs
                buf_end = dest_abs + sz
                o_start = max(buf_start, WAITER_ABS)
                o_end = min(buf_end, WAITER_ABS + WAITER_SIZE)
                overlap = max(0, o_end - o_start)

                fields = ""
                if overlap > 0:
                    fnames = []
                    for wb in sorted(WAITER_FIELDS):
                        if o_start <= WAITER_ABS + wb < o_end:
                            fnames.append(f"{WAITER_FIELDS[wb]}")
                    fields = ", ".join(fnames)

                marker = " *** OVERLAP ***" if overlap > 0 else ""
                print(f"  0x{cfu['addr']:x} SP+0x{ds:03x}   {sz:3d}B  {dw:+4d}词 {fields}{marker}")
            else:
                print(f"  0x{cfu['addr']:x} {'(unknown)':>10s} {sz:3d}B  {'?':>5s}")

    # ---- Section C: BC command switch cases ----
    print()
    print("-" * 72)
    print("SECTION C: BC Command Switch Dispatch Table")
    print("-" * 72)
    print()
    print(f"  The switch uses w28 for the command code.")
    print(f"  First dispatch: low byte (BC_* command) via jump table")
    print(f"    'and x8, x28, #0xff ; cmp x8, #0x12 ; b.hi default'")
    print(f"  Then high-prefix comparison via movk-built constants.")
    print()

    # Deduplicate BC cases by combined value
    seen = {}
    for bc in r["bc_cases"]:
        key = bc["combined"]
        if key not in seen:
            seen[key] = {
                "combined": key,
                "low_byte": bc["low_byte"],
                "high_prefix": bc["high_prefix"],
                "bc_name": bc["bc_name"],
                "cmp_addrs": [],
                "next": [],
            }
        seen[key]["cmp_addrs"].append(f"0x{bc['cmp_addr']:x}")
        seen[key]["next"].append(f"{bc['next_mnemonic']} {bc['next_target']}")

    for key, info in sorted(seen.items()):
        bcn = info["bc_name"]
        lb = info["low_byte"]
        hp = info["high_prefix"]
        ca = ", ".join(info["cmp_addrs"][:2])
        nt = info["next"][0] if info["next"] else ""
        full_val = f"0x{key:08x}"
        print(f"  {full_val:>14s} = {bcn:<35s} (low=0x{lb:04x}, high=0x{hp:04x})")

    # ---- Section D: BL calls ----
    print()
    print("-" * 72)
    print("SECTION D: All BL calls in binder_thread_write")
    print("-" * 72)
    print(f"  {'BL@':>16s} {'Target':>16s} {'Function Name':40s}")
    print(f"  {'---':>16s} {'------':>16s} {'-------------':40s}")
    for call in r["bl_calls"]:
        print(f"  0x{call['addr']:x} 0x{call['target']:x} {call['target_name']:<40s}")

    # ---- Section E: Analysis and Conclusion ----
    print()
    print("=" * 72)
    print("SECTION E: Waiter Overlap Analysis & Conclusion")
    print("=" * 72)
    print()
    print(f"  waiter.task (SP+0x{WAITER_REL_SP + 0x30:x}) = binder_proc+0x30")
    print(f"  waiter.lock (SP+0x{WAITER_REL_SP + 0x38:x}) = binder_thread+0x60")
    print()
    print("  These are kernel heap pointer values, NOT user-controllable data.")
    print()

    # Check for any copy_from_user into waiter range
    has_overlap = False
    for cfu in r["copy_from_user_calls"]:
        ds = cfu["dest_sp"]
        if ds is not None:
            if WAITER_REL_SP <= ds < WAITER_REL_SP + WAITER_SIZE:
                has_overlap = True
                print(f"  *** FOUND: copy_from_user @ 0x{cfu['addr']:x} writes to SP+0x{ds:03x}")
                print(f"      This is within the waiter range! Size={cfu['copy_size']}B")
                print(f"      BC command: {cfu.get('bc_command', 'unknown')}")

    if not has_overlap:
        # Find closest copy_from_user to waiter
        closest = None
        closest_delta = 9999
        for cfu in r["copy_from_user_calls"]:
            ds = cfu["dest_sp"]
            if ds is not None:
                delta = abs(ds - WAITER_REL_SP)
                if delta < closest_delta:
                    closest_delta = delta
                    closest = cfu

        if closest:
            ds = closest["dest_sp"]
            direction = "above" if ds > WAITER_REL_SP else "below"
            print(f"  Closest copy_from_user is at SP+0x{ds:03x} ({closest_delta}B {direction} waiter)")
            print(f"    0x{closest['addr']:x}: dest={closest['dest_desc']} size={closest['copy_size']}B")
            print()
            if ds > WAITER_REL_SP:
                gap = ds - (WAITER_REL_SP + WAITER_SIZE)
                print(f"  GAP between waiter end (SP+0x{WAITER_REL_SP + WAITER_SIZE:x}) and")
                print(f"  copy_from_user dest (SP+0x{ds:x}) = {gap}B")
                print(f"  This gap contains: binder_transaction_data buffer ({closest['copy_size']}B)")
        else:
            print("  (no copy_from_user calls with known dest)")

    print()
    print("-" * 72)
    print("INDIRECT APPROACH ASSESSMENT")
    print("-" * 72)
    print()
    print("  Even without direct user-data write to the waiter range, can we")
    print("  influence the kernel pointer values at SP+0x20..SP+0x60?")
    print()
    print("  For waiter.task (SP+0x30 in binder_thread_write):")
    print("    - Stores binder_proc+0x30 (struct list_head -> async_pending)")
    print("    - binder_proc+0x30 is a linked list head of pending async transactions")
    print("    - Not directly controlled by user without a separate vulnerability")
    print()
    print("  For waiter.lock (SP+0x38 in binder_thread_write):")
    print("    - Stores binder_thread+0x60 (struct list_head -> todo)")
    print("    - binder_thread->todo is a list of pending work items")
    print("    - Work items are added by the kernel, not directly by userspace")
    print("    - However: BC_TRANSACTION can add work items to the target thread's todo")
    print("    - Work items are struct binder_work, which has a list_head at +0x00")
    print("    - Could potentially control the list_head pointers through UAF/DANGLING")
    print()
    print("  For the other fields:")
    print(f"    SP+0x20: proc->nodes (rb_root of binder_node objects)")
    print(f"    SP+0x28: thread->wait (list_head)")
    print(f"    SP+0x30: proc->async_pending (list_head)")
    print(f"    SP+0x38: thread->todo (list_head)")
    print(f"    SP+0x40: thread->return_error (stack)")
    print(f"    SP+0x48: proc->allocated_rb_node (rb_node*)")
    print(f"    SP+0x50: thread->looper (state word)")
    print()
    print("  CONCLUSION: Direct user-data write via copy_from_user to the waiter")
    print("  range is NOT possible in binder_thread_write.")
    print()
    print("  Alternatives:")
    print("    1. Search for other copy_from_user targets in different syscalls")
    print("       (sendmsg, recvmsg, etc.)")
    print("    2. Use heap spraying + pipe physrw bypass to avoid stack overwrite")
    print("    3. Exploit a separate vulnerability in binder to corrupt the")
    print("       binder_proc/binder_thread structures before calling binder_ioctl")
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    symbols, text_base, text_data = load_vmlinux(args.elf)

    required = ["binder_thread_write", "__arch_copy_from_user", "binder_transaction"]
    missing = [s for s in required if s not in symbols]
    if missing:
        print(f"ERROR: Missing symbols: {missing}")
        return 1

    results = analyze_binder_thread_write(symbols, text_base, text_data)
    print_analysis(results, symbols, verbose=args.verbose)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
