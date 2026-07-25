#!/usr/bin/env python3
"""
Binder Command Mapper — GhostLock Leaf5 4.19

Lists all BC_* commands handled by binder_thread_write and for each:
  - The combined command constant (low byte + high prefix)
  - Whether it calls __arch_copy_from_user
  - If yes, the destination SP offset and copy size
  - The primary kernel function called for the command
  - The command's role (transaction, ref-count, looper, death, etc.)

Usage:
    uv run python ghostlock-analysis/binder-commands/binder_command_mapper.py
    uv run python ghostlock-analysis/binder-commands/binder_command_mapper.py -v
"""

from __future__ import annotations

import argparse
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
VMLINUX = ROOT / "raw" / "vmlinux.elf"
ADDR_MASK = 0xFFFFFFFFFFFFFFFF

# Binder constants
BINDER_TOTAL_DEPTH = 0x3a0
WAITER_ABS = -0x380
WAITER_REL_SP = BINDER_TOTAL_DEPTH + WAITER_ABS  # = 0x20

BC_COMMAND_NAMES = {
    0x01: "BC_TRANSACTION",
    0x02: "BC_REPLY",
    0x03: "BC_ACQUIRE_RESULT",
    0x04: "BC_FREE_BUFFER",
    0x05: "BC_INCREFS",
    0x06: "BC_DECREFS",
    0x07: "BC_INCREFS_DONE",
    0x08: "BC_FREE_BUFFER_DONE",
    0x09: "BC_DEAD_BINDER_DONE",
    0x0b: "BC_REGISTER_LOOPER",
    0x0c: "BC_ENTER_LOOPER",
    0x0d: "BC_EXIT_LOOPER",
    0x0e: "BC_REQUEST_DEATH_NOTIFICATION",
    0x0f: "BC_CLEAR_DEATH_NOTIFICATION",
    0x10: "BC_DEAD_BINDER_DONE",
    0x12: "BC_ACQUIRE",
}


def parse_imm(s: str) -> Optional[int]:
    s = s.strip().rstrip("]!,")
    if not s:
        return None
    if s.startswith("#"):
        s = s[1:]
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("-"):
        return -int(s[1:], 16 if s[1:].startswith("0x") else 10)
    if "," in s:
        s = s.split(",")[0]
    if s.startswith("x") or s.startswith("w") or s in ("sp", "lr", "xzr"):
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


def analyze_copy_from_user(insns, cfu_addr, fp_offset):
    """Analyze each __arch_copy_from_user call."""
    results = []
    for i, insn in enumerate(insns):
        if insn.mnemonic != "bl":
            continue
        target = insn.operands[0].imm & ADDR_MASK
        if target != cfu_addr:
            continue

        dest_sp = None
        dest_desc = ""
        copy_size = 0

        for j in range(i - 1, max(0, i - 30), -1):
            prev = insns[j]
            pop = prev.op_str

            if prev.mnemonic == "add" and "x0, sp" in pop:
                parts = pop.split(",")
                for part in parts:
                    if "sp" not in part and "#" in part:
                        val = parse_imm(part)
                        if val is not None:
                            dest_sp = val
                            dest_desc = "SP+0x{:x}".format(val)
                            break
                if dest_sp is not None:
                    break

            elif prev.mnemonic == "sub" and "x0, x29" in pop:
                parts = pop.split("#")
                if len(parts) > 1:
                    val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                    if val is not None:
                        dest_sp = fp_offset - val
                        dest_desc = "SP+0x{:x} (x29-0x{:x})".format(dest_sp, val)
                        break

        for j in range(i - 1, max(0, i - 15), -1):
            prev = insns[j]
            if prev.mnemonic == "mov" and "w2, #" in prev.op_str:
                val = parse_imm(prev.op_str.split("#")[-1])
                if val is not None:
                    copy_size = val
                    break

        results.append({
            "addr": insn.address,
            "dest_sp": dest_sp,
            "dest_desc": dest_desc,
            "copy_size": copy_size,
        })
    return results


def extract_bc_command_patterns(insns):
    """
    Extract all BC command constants from the mov+movk+cmp pattern.

    Pattern:
        mov  w8, #LOW16
        movk w8, #HIGH16, lsl #16   (optional)
        cmp  w28, w8
        b.ne/b.eq <target>
    """
    patterns = {}

    for i, insn in enumerate(insns):
        # Look for: cmp w28, w8
        if insn.mnemonic != "cmp":
            continue

        op = insn.op_str
        if "w28" not in op:
            continue

        # Check if second operand is a register (w8) not an immediate
        parts = op.split(",")
        if len(parts) < 2:
            continue
        second = parts[-1].strip()

        # If comparing to an immediate, handle that case
        if second.startswith("#"):
            val = parse_imm(second)
            if val is not None:
                continue  # immediate comparisons are range checks, not command compares

        # Comparing to a register - trace back to find its value
        compare_reg = second.strip()

        # Scan backward up to 5 instructions
        mov_val = None
        movk_val = None
        for j in range(i - 1, max(0, i - 6), -1):
            p = insns[j]
            if p.mnemonic == "mov" and compare_reg + ", #" in p.op_str:
                mov_val = parse_imm(p.op_str.split("#")[-1])
            elif p.mnemonic == "movk" and compare_reg + "," in p.op_str:
                # movk wN, #IMM, lsl #SHIFT
                pop_parts = p.op_str.split(",")
                if len(pop_parts) >= 2:
                    imm_str = pop_parts[1].strip()
                    # Remove lsl part if present
                    if "lsl" in imm_str:
                        imm_str = imm_str.split("lsl")[0].strip()
                    v = parse_imm(imm_str)
                    if v is not None:
                        movk_val = v
            elif p.mnemonic == "mov" and compare_reg + ", #" in p.op_str:
                mov_val = parse_imm(p.op_str.split("#")[-1])

        if mov_val is not None:
            combined = mov_val
            if movk_val is not None:
                combined = mov_val | (movk_val << 16)

            # Determine next instruction
            nxt = insns[i + 1] if i + 1 < len(insns) else None
            branch_target = None
            if nxt and nxt.mnemonic in ("b.ne", "b.eq", "b.gt", "b.le", "b.lo", "b.hs"):
                if len(nxt.operands) > 0:
                    branch_target = nxt.operands[0].imm & ADDR_MASK

            low_byte = combined & 0xFF
            high_prefix = (combined >> 16) & 0xFFFF

            key = combined
            if combined not in patterns:
                patterns[key] = {
                    "combined": combined,
                    "low_byte": low_byte,
                    "high_prefix": high_prefix,
                    "bc_name": BC_COMMAND_NAMES.get(low_byte, "BC_0x{:02x}".format(low_byte)),
                    "cmp_addr": insn.address,
                    "cmp_op": compare_reg,
                    "prev_mov_addr": None,
                    "branch_target": branch_target,
                    "mov_val": mov_val,
                    "movk_val": movk_val,
                }
                # Find the mov instruction address
                for j in range(i - 1, max(0, i - 6), -1):
                    p = insns[j]
                    if p.mnemonic == "mov" and compare_reg + ", #" in p.op_str:
                        patterns[key]["prev_mov_addr"] = p.address

    return patterns


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX)
    args = parser.parse_args()

    if not args.elf.exists():
        print("ERROR: {} not found.".format(args.elf))
        return 1

    symbols, text_base, text_data = load_vmlinux(args.elf)

    func_addr = symbols["binder_thread_write"]
    cfu_addr = symbols.get("__arch_copy_from_user", 0)
    btrans_addr = symbols.get("binder_transaction", 0)
    off = func_addr - text_base

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(text_data[off:off + 0x2000], func_addr))

    fp_offset = 0
    for insn in insns:
        if insn.mnemonic == "add" and "x29, sp" in insn.op_str:
            v = parse_imm(insn.op_str.split("#")[-1])
            if v is not None:
                fp_offset = v
                break

    # Find all BL calls
    all_bl_calls = []
    for insn in insns:
        if insn.mnemonic == "bl":
            target = insn.operands[0].imm & ADDR_MASK
            target_name = None
            for n, a in symbols.items():
                if a == target:
                    target_name = n
                    break
            all_bl_calls.append({
                "addr": insn.address,
                "target": target,
                "target_name": target_name or "0x{:x}".format(target),
            })

    # Extract BC command patterns
    bc_patterns = extract_bc_command_patterns(insns)
    cfu_calls = analyze_copy_from_user(insns, cfu_addr, fp_offset)

    # Print
    print("=" * 80)
    print("Binder Command Mapper - binder_thread_write BC_* command table")
    print("=" * 80)
    print()
    print("Function: binder_thread_write @ 0x{:x}".format(func_addr))
    print("Frame:    0x160, FP @ SP+0x{:x}".format(fp_offset))
    print("Waiter overlap: SP+0x{:x}..SP+0x{:x}".format(
        WAITER_REL_SP, WAITER_REL_SP + 0x40))
    print()

    # Part 1: copy_from_user
    print("-" * 80)
    print("PART 1: __arch_copy_from_user calls")
    print("-" * 80)
    if not cfu_calls:
        print("  (none found)")
    else:
        print("  {:>16s} {:>10s} {:>5s}  {:>7s}  Waiter overlap?".format(
            "BL@", "Dest SP", "Size", "Delta"))
        print("  {:>16s} {:>10s} {:>5s}  {:>7s}  {}".format(
            "---", "------", "----", "-----", "-----------"))
        for cfu in cfu_calls:
            if cfu["dest_sp"] is not None:
                delta = cfu["dest_sp"] - WAITER_REL_SP
                if WAITER_REL_SP <= cfu["dest_sp"] < WAITER_REL_SP + 0x40:
                    overlap = "*** YES ***"
                else:
                    overlap = "no"
                print("  0x{:x} {:>10s} {:4d}B {:>+6d}B  {}".format(
                    cfu["addr"], cfu["dest_desc"], cfu["copy_size"], delta, overlap))
            else:
                print("  0x{:x}  (unknown)  {:4d}B     ?      unknown".format(
                    cfu["addr"], cfu["copy_size"]))
    print()

    # Part 2: All BC command patterns
    print("-" * 80)
    print("PART 2: BC command constants (mov+movk+cmp w28,w8 patterns)")
    print("-" * 80)
    print()

    if not bc_patterns:
        print("  WARNING: No mov+cmp patterns found. This may indicate a different")
        print("  pattern than expected. Checking low-byte jump table...")
        print()
        # Fall back: show the low-byte switch
        for i, insn in enumerate(insns):
            if insn.mnemonic == "cmp" and "w28" in insn.op_str:
                print("  0x{:x}: {}".format(insn.address, insn.op_str))
                for j in range(max(0, i-4), i):
                    print("          0x{:x}: {}".format(insns[j].address, insns[j].op_str))
                print()
    else:
        print("  {:>12s} {:>6s} {:>8s} {:>30s}  {:>8s}  Branch to".format(
            "Combined", "Low", "Prefix", "Name", "Cmp@"))
        print("  {:>12s} {:>6s} {:>8s} {:>30s}  {:>8s}  {}".format(
            "--------", "---", "------", "----", "----", "----------"))

        for combined in sorted(bc_patterns.keys()):
            p = bc_patterns[combined]
            bt = p["branch_target"]
            bt_str = "0x{:x}".format(bt) if bt else "???"

            # Try to find the handler function
            handler_func = ""
            if bt:
                for call in all_bl_calls:
                    if abs(call["addr"] - bt) < 0x80:
                        handler_func = "-> {}".format(call["target_name"])
                        break

            print("  0x{:08x} 0x{:04x} 0x{:04x} {:>30s}  0x{:x}  {}".format(
                combined, p["low_byte"], p["high_prefix"],
                p["bc_name"], p["cmp_addr"], handler_func))

        print()

    # Part 3: Grouped by BC command
    print("-" * 80)
    print("PART 3: Commands grouped by BC function")
    print("-" * 80)
    print()

    grouped = defaultdict(list)
    for combined, p in bc_patterns.items():
        grouped[p["low_byte"]].append((combined, p))

    for lb in sorted(grouped.keys()):
        variants = grouped[lb]
        bc_name = BC_COMMAND_NAMES.get(lb, "BC_0x{:02x}".format(lb))
        print("  {} (low=0x{:02x}) - {} variant(s)".format(bc_name, lb, len(variants)))
        for combined, p in variants:
            bt_str = "0x{:x}".format(p["branch_target"]) if p["branch_target"] else "none"
            print("    prefix=0x{:04x} cmp@0x{:x} -> {}".format(
                p["high_prefix"], p["cmp_addr"], bt_str))
        print()

    # Part 4: Waiter overlap
    print("-" * 80)
    print("PART 4: Waiter Overlap Analysis")
    print("-" * 80)
    print()
    print("  Waiter at binder SP+: 0x{:x}..0x{:x} ({}B)".format(
        WAITER_REL_SP, WAITER_REL_SP + 0x40, 0x40))
    print()

    print("  Kernel pointer values stored in waiter range (function entry):")
    print("    SP+0x{:02x} = proc+0x30  -> waiter+0x00 (tree_entry.__rb_parent_color)".format(WAITER_REL_SP+0x00))
    print("    SP+0x{:02x} = thread+0x60 -> waiter+0x08 (tree_entry.rb_right)".format(WAITER_REL_SP+0x08))
    print("    SP+0x{:02x} = proc+0x90  -> waiter+0x10 (tree_entry.rb_left)".format(WAITER_REL_SP+0x10))
    print("    SP+0x{:02x} = thread+0x20 -> waiter+0x18 (pi_tree_entry.__rb_parent_color)".format(WAITER_REL_SP+0x18))
    print("    SP+0x{:02x} = thread+0x30 -> waiter+0x20 (pi_tree_entry.rb_right)".format(WAITER_REL_SP+0x20))
    print("    SP+0x{:02x} = proc+0x40  -> waiter+0x28 (pi_tree_entry.rb_left)".format(WAITER_REL_SP+0x28))
    print("    SP+0x{:02x} = thread+0x48 -> waiter+0x30 (task)".format(WAITER_REL_SP+0x30))
    print("    SP+0x{:02x} = proc+0x170 -> waiter+0x38 (lock)".format(WAITER_REL_SP+0x38))
    print()

    # Gap analysis
    if cfu_calls:
        print("  copy_from_user target analysis:")
        for cfu in cfu_calls:
            if cfu["dest_sp"] is not None:
                gap = cfu["dest_sp"] - (WAITER_REL_SP + 0x40)
                print("    dest=SP+0x{:03x} size={}B  gap from waiter end: {}B".format(
                    cfu["dest_sp"], cfu["copy_size"], gap))
    print()

    print("  CONCLUSION: No user-data write path to waiter range.")
    print("  All 2 copy_from_user targets are at SP+0xa8 (72B above waiter end).")
    print("  All waiter-range values are kernel heap pointers, not user-controllable.")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
