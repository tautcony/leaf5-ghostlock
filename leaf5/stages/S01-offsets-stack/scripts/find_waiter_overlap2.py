#!/usr/bin/env python3
"""
快速扫描: 计算每个 copy_from_user 函数需要多少调用者深度才能与 waiter 重叠

不需要构建完整调用图。对于每个函数 F:
  - frame_size: F 自身分配的栈帧
  - dest_sp: copy_from_user 目标在帧内的 SP 偏移
  - 需要: caller_depth (所有调用者帧大小之和) 满足:
      -(caller_depth + frame_size) + dest_sp ∈ [-0x380, -0x340]

  即: caller_depth ∈ [dest_sp - frame_size + 0x340, dest_sp - frame_size + 0x380]

  如果 caller_depth 在合理范围 (0 到 0x800), 该函数是候选。

用法:
    uv run python -m scripts.find_waiter_overlap2
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

# Waiter position
WAITER_START = -0x380
WAITER_END = -0x340
WAITER_SIZE = 0x40


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


def find_functions_with_copy_from_user(
    symbols: dict, text_base: int, text_data: bytes
) -> list[dict]:
    """
    Find ALL functions that call __arch_copy_from_user.
    For each, extract: func_name, func_addr, frame_size, fp_offset,
    and per call: call_addr, dest_sp_offset, copy_size.
    Also find the function's direct BL callees and callers.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    cfu_addr = symbols.get("__arch_copy_from_user")
    if cfu_addr is None:
        return []

    text_end = text_base + len(text_data)
    results = []

    # First pass: build function info for all functions
    func_info = {}  # addr -> (frame_size, fp_offset, end_addr, [callee_addrs])

    for name, addr in symbols.items():
        if not (text_base <= addr < text_end):
            continue
        if addr in func_info:
            continue

        off = addr - text_base
        fbytes = text_data[off : off + 0x2000]
        insns = list(md.disasm(fbytes, addr))

        total = 0
        fp_off = 0
        callees = []
        func_end = addr
        has_ret = False
        cfu_calls = []

        for insn in insns:
            func_end = insn.address + 4
            op = insn.op_str

            if insn.mnemonic == "sub" and "sp, sp" in op:
                val = parse_imm(op.split("#")[-1].strip(","))
                if val is not None:
                    total += val
            elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
                val = parse_imm(op.split("#-")[1].split("]")[0])
                if val is not None:
                    total += val
            elif insn.mnemonic == "add" and "x29, sp" in op:
                val = parse_imm(op.split("#")[-1])
                if val is not None:
                    fp_off = val

            if insn.mnemonic == "bl":
                target = insn.operands[0].imm & ADDR_MASK
                if text_base <= target < text_end:
                    callees.append(target)

                # Check if this is a copy_from_user call
                if target == cfu_addr:
                    dest_sp = None
                    copy_size = None
                    # Look backward for dest and size setup
                    for j in range(len(cfu_calls), max(0, len(cfu_calls) - 20), -1):
                        prev = insns[j] if j < len(insns) else None
                    # Search backward in insns
                    for j in range(len(insns) - 1, max(0, len(insns) - 30), -1):
                        if insns[j].address >= insn.address:
                            continue
                        prev = insns[j]
                        pop = prev.op_str
                        if prev.mnemonic == "add" and pop.startswith("x0, sp"):
                            parts = pop.split("#")
                            if len(parts) > 1:
                                val = parse_imm(parts[-1].rstrip("]"))
                                if val is not None:
                                    dest_sp = val
                                    break
                        elif prev.mnemonic == "sub" and pop.startswith("x0, x29"):
                            parts = pop.split("#")
                            if len(parts) > 1:
                                val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                                if val is not None:
                                    dest_sp = fp_off - val
                                    break
                        elif prev.mnemonic == "mov" and "w2, #" in pop:
                            val = parse_imm(pop.split("#")[-1])
                            if val is not None:
                                copy_size = val

                    if dest_sp is not None:
                        cfu_calls.append({
                            "call_addr": insn.address,
                            "dest_sp_offset": dest_sp,
                            "copy_size": copy_size or 0,
                        })

            if insn.mnemonic == "ret":
                has_ret = True
                if total > 0 or insn.address > addr + 0x10:
                    break

        if not has_ret:
            continue

        func_info[addr] = {
            "name": name,
            "addr": addr,
            "frame_size": total,
            "fp_offset": fp_off,
            "end_addr": func_end,
            "callees": callees,
            "cfu_calls": cfu_calls,
        }

    # Extract only functions with copy_from_user calls
    for addr, info in func_info.items():
        if info["cfu_calls"]:
            for cfu in info["cfu_calls"]:
                results.append({
                    "func_name": info["name"],
                    "func_addr": addr,
                    "frame_size": info["frame_size"],
                    "fp_offset": info["fp_offset"],
                    **cfu,
                })

    print(f"  Found {len(results)} copy_from_user calls in {len(func_info)} functions")
    return results, func_info


def compute_required_depth(calls: list[dict]) -> list[dict]:
    """
    For each copy_from_user call, compute the range of caller_depth
    values that would make the destination overlap with the waiter.

    dest_abs = -(caller_depth + frame_size) + dest_sp

    For dest_abs ∈ [WAITER_START, WAITER_END]:
      caller_depth ∈ [dest_sp - frame_size - WAITER_END,
                      dest_sp - frame_size - WAITER_START]

    A NEGATIVE caller_depth means the buffer would be BELOW the waiter
    even with zero callers. A positive caller_depth means additional
    frames are needed.
    """
    ranked = []
    for call in calls:
        dest_sp = call["dest_sp_offset"]
        frame = call["frame_size"]

        # Required caller depth range
        depth_lo = dest_sp - frame - WAITER_END   # minimum needed
        depth_hi = dest_sp - frame - WAITER_START  # maximum allowed

        # Check if there's an overlap opportunity
        # If depth_lo < 0, the buffer overlaps even with zero callers
        # If depth_hi > 0, we need some callers but it's achievable

        # Calculate the exact depth needed for perfect alignment
        # (center of waiter)
        perfect_depth = dest_sp - frame - (WAITER_START + WAITER_SIZE // 2)

        # Buffer position with zero callers
        zero_depth_abs = -frame + dest_sp
        delta_zero = zero_depth_abs - WAITER_START
        delta_zero_words = delta_zero // 8

        ranked.append({
            **call,
            "depth_lo": depth_lo,
            "depth_hi": depth_hi,
            "perfect_depth": perfect_depth,
            "zero_depth_abs": zero_depth_abs,
            "delta_zero": delta_zero,
            "delta_zero_words": delta_zero_words,
            "overlap_possible": depth_lo <= 0x800,  # reasonable max depth
        })

    # Sort by |delta_zero| (closest with zero callers first)
    ranked.sort(key=lambda r: abs(r["delta_zero"]))
    return ranked


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Quick scan for copy_from_user → waiter overlap candidates"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    parser.add_argument("--max-results", type=int, default=40)
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    symbols, text_base, text_data = load_vmlinux(args.elf)
    print(f"Symbols: {len(symbols)}, .kernel @ 0x{text_base:x}")

    calls, func_info = find_functions_with_copy_from_user(
        symbols, text_base, text_data)
    ranked = compute_required_depth(calls)

    # ── Output ─────────────────────────────────────────────────────
    print(f"\nWaiter: [{WAITER_START:+d}, {WAITER_END:+d}) size={WAITER_SIZE}B")
    print(f"Copy_from_user calls: {len(calls)}")

    # Group by distance
    exact = [r for r in ranked if r["overlap_possible"]
             and r["depth_lo"] <= 0 and r["depth_hi"] >= 0]  # overlap at depth 0
    close_neg = [r for r in ranked if abs(r["delta_zero_words"]) <= 20
                 and r["delta_zero"] < 0]  # buffer below waiter
    close_pos = [r for r in ranked if abs(r["delta_zero_words"]) <= 20
                 and r["delta_zero"] > 0]  # buffer above waiter

    print(f"\n" + "=" * 70)
    print(f"CANDIDATES CLOSEST TO WAITER (zero caller depth)")
    print("=" * 70)
    print(f"  {'Δ词':>5s} {'Δ字节':>7s} {'帧大小':>6s} {'Dest@SP':>7s} "
          f"{'大小':>4s} {'需深度':>7s}  {'函数名'}")
    print(f"  {'-'*5} {'-'*7} {'-'*6} {'-'*7} {'-'*4} {'-'*7}  {'-'*50}")

    shown = 0
    for r in ranked:
        if shown >= args.max_results:
            break
        abs_dw = abs(r["delta_zero_words"])
        if abs_dw > 128:  # skip too far
            continue

        direction = "↑" if r["delta_zero"] > 0 else "↓"
        perfect = r["perfect_depth"]
        reachable = "✓" if r["overlap_possible"] and perfect < 0x800 else "?"

        print(f"  {r['delta_zero_words']:+5d} {r['delta_zero']:+7d} "
              f"0x{r['frame_size']:04x} 0x{r['dest_sp_offset']:04x} "
              f"{r['copy_size']:4d} {perfect:+6d} "
              f"{direction}{reachable} {r['func_name']}")
        shown += 1

    # Summary
    print(f"\n" + "=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)

    # Best candidates for direct (no callers) overlap
    direct = [r for r in ranked
              if r["depth_lo"] <= 0 and r["depth_hi"] >= 0]
    if direct:
        print(f"\n  Functions with DIRECT overlap (no extra callers needed): {len(direct)}")
        for r in direct[:10]:
            print(f"    {r['func_name']}: dest@SP+0x{r['dest_sp_offset']:x} "
                  f"frame=0x{r['frame_size']:x} Δ={r['delta_zero_words']:+d}词")

    # Best candidates needing moderate caller depth (0 to 0x400)
    moderate = [r for r in ranked
                if 0 <= r["depth_lo"] <= 0x400 and r["depth_lo"] <= r["depth_hi"]]
    if moderate:
        print(f"\n  Functions needing moderate caller depth (0-0x400): {len(moderate)}")
        for r in moderate[:10]:
            print(f"    {r['func_name']}: need depth [{r['depth_lo']:#x}, {r['depth_hi']:#x}] "
                  f"Δ@0={r['delta_zero_words']:+d}词")

    # Functions closest to waiter regardless
    print(f"\n  Top 5 overall closest:")
    for r in ranked[:5]:
        print(f"    {r['func_name']}: Δ@0={r['delta_zero_words']:+d}词 "
              f"dest@SP+0x{r['dest_sp_offset']:x} frame=0x{r['frame_size']:x} "
              f"need_depth={r['perfect_depth']:+d}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
