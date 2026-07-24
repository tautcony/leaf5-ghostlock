#!/usr/bin/env python3
"""
GhostLock Global copy_from_user Scanner

Strategy:
  1. Raw BL instruction scan across .kernel section to find ALL functions
     that call __arch_copy_from_user (fast: ~2s, no full Capstone).
  2. For each candidate function, disassemble to extract frame_size,
     dest_sp_offset, copy_size for each copy_from_user call site.
  3. BFS from syscall entries to compute min_depth for BL-reachable functions.
  4. For each candidate, compute overlap at actual call depths (zero-depth,
     BFS min_depth, estimated ioctl/read/write path depths).
  5. Report candidates sorted by exploitability.

Usage:
    cd /Users/tautcony/Documents/repos/leaf5-ghostlock/leaf5
    python3 ghostlock-analysis/copy-from-user-scan/scanner.py
    python3 ghostlock-analysis/copy-from-user-scan/scanner.py --verbose
    python3 ghostlock-analysis/copy-from-user-scan/scanner.py --show-all

Waiter position (rt_mutex_waiter on kernel stack):
    kernel_stack_top - 0x380, size 0x40 bytes ([-0x380, -0x340))
"""

from __future__ import annotations

import argparse
import bisect
import struct
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


# ── Constants ────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "raw"
VMLINUX_ELF = RAW / "vmlinux.elf"
ADDR_MASK = 0xFFFFFFFFFFFFFFFF

# Waiter position (from futex_wait frame analysis)
WAITER_START = -0x380   # inclusive; offset from kernel_stack_top
WAITER_END = -0x340     # exclusive
WAITER_SIZE = 0x40


# ── Helper functions ─────────────────────────────────────────────────

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


def alog(msg: str, verbose: bool = True):
    if verbose:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    else:
        print(msg, flush=True)


# ── ELF Loading ──────────────────────────────────────────────────────

def load_vmlinux(path: Path) -> tuple[dict, int, bytes]:
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        symbols = {
            sym.name: sym.entry.st_value
            for sym in symtab.iter_symbols()
            if sym.name
        }
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return symbols, sec.header.sh_addr, sec.data()
    raise ValueError("No .kernel section in ELF")


def build_func_range_table(text_base: int, text_end: int) -> list[tuple]:
    with open(VMLINUX_ELF, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        raw = []
        for sym in symtab.iter_symbols():
            if not sym.name:
                continue
            typ = sym.entry.st_info.get("type", "")
            if typ not in ("STT_FUNC", 2):
                continue
            addr = sym.entry.st_value
            if not (text_base <= addr < text_end):
                continue
            raw.append((addr, sym.entry.st_size, sym.name))
    raw.sort(key=lambda x: x[0])
    func_list = []
    for i, (addr, size, name) in enumerate(raw):
        if size > 0:
            end = addr + size
        elif i < len(raw) - 1:
            end = raw[i + 1][0]
        else:
            end = addr + 0x10
        func_list.append((addr, end, name))
    return func_list


def find_function(addr: int, func_list: list[tuple],
                  func_starts: list[int]):
    idx = bisect.bisect_right(func_starts, addr) - 1
    if idx >= 0 and func_list[idx][0] <= addr < func_list[idx][1]:
        return func_list[idx]
    return None


# ── Raw BL Scanning ──────────────────────────────────────────────────

def raw_scan_bl_instructions(
    text_data: bytes, text_base: int, text_end: int
) -> list[tuple[int, int]]:
    bl_edges = []
    data_len = len(text_data)
    for i in range(0, data_len - 4, 4):
        word = struct.unpack("<I", text_data[i:i+4])[0]
        if (word & 0xFC000000) != 0x94000000:
            continue
        imm26 = word & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 = imm26 - 0x04000000
        pc = text_base + i
        target = pc + (imm26 << 2)
        if text_base <= target < text_end:
            bl_edges.append((pc, target))
    return bl_edges


def map_bl_edges_to_functions(
    bl_edges: list[tuple[int, int]],
    func_list: list[tuple],
    func_starts: list[int],
) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    forward: dict[int, set[int]] = defaultdict(set)
    reverse: dict[int, set[int]] = defaultdict(set)
    for pc, target in bl_edges:
        caller_info = find_function(pc, func_list, func_starts)
        if not caller_info:
            continue
        callee_info = find_function(target, func_list, func_starts)
        if not callee_info:
            continue
        forward[caller_info[0]].add(callee_info[0])
        reverse[callee_info[0]].add(caller_info[0])
    return dict(forward), dict(reverse)


# ── Frame Size Extraction ────────────────────────────────────────────

def analyze_function(
    func_addr: int, func_end: int, text_base: int, text_data: bytes,
    cfu_addr: int,
) -> Optional[dict]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    off = func_addr - text_base
    size = func_end - func_addr
    if size <= 0 or size > 0x20000:
        return None
    fbytes = text_data[off:off + size]
    insns = list(md.disasm(fbytes, func_addr))
    total = 0
    fp_off = 0
    call_sites = []

    for i, insn in enumerate(insns):
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            val = parse_imm(op.split("#")[-1].strip(","))
            if val is not None and val > 0:
                total += val
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            val = parse_imm(op.split("#-")[1].split("]")[0])
            if val is not None and val > 0:
                total += val
        elif insn.mnemonic == "add" and "x29, sp" in op:
            val = parse_imm(op.split("#")[-1])
            if val is not None:
                fp_off = val
        if insn.mnemonic == "bl":
            target = insn.operands[0].imm & ADDR_MASK
            if target == cfu_addr:
                dest_sp = None
                copy_size = None
                for j in range(i - 1, max(0, i - 30), -1):
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
                            val = parse_imm(
                                parts[-1].split(",")[0].rstrip("]"))
                            if val is not None:
                                dest_sp = fp_off - val
                                break
                for j in range(i - 1, max(0, i - 15), -1):
                    prev = insns[j]
                    if prev.mnemonic == "mov" and "w2, #" in prev.op_str:
                        val = parse_imm(prev.op_str.split("#")[-1])
                        if val is not None:
                            copy_size = val
                        break
                if dest_sp is not None:
                    call_sites.append({
                        "call_addr": insn.address,
                        "dest_sp_offset": dest_sp,
                        "copy_size": copy_size or 0,
                    })
    if not call_sites:
        return None
    return {
        "func_addr": func_addr, "func_end": func_end,
        "frame_size": total, "fp_offset": fp_off,
        "call_sites": call_sites,
    }


def extract_func_frame_size(
    func_addr: int, func_end: int, text_base: int, text_data: bytes,
) -> int:
    """Fast single-purpose frame size extraction."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    off = func_addr - text_base
    size = func_end - func_addr
    if size <= 0 or size > 0x20000:
        return 0
    total = 0
    for insn in md.disasm(text_data[off:off + size], func_addr):
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            val = parse_imm(op.split("#")[-1].strip(","))
            if val is not None and val > 0:
                total += val
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            val = parse_imm(op.split("#-")[1].split("]")[0])
            if val is not None and val > 0:
                total += val
        if insn.mnemonic == "ret":
            break
    return total


# ── BFS ──────────────────────────────────────────────────────────────

def compute_reachable_depths(
    forward_graph: dict[int, set[int]],
    reverse_graph: dict[int, set[int]],
    syscall_entry_addrs: set[int],
    text_base: int, text_data: bytes,
    func_list: list[tuple], func_starts: list[int],
) -> dict[int, tuple[int, int]]:
    """
    BFS from syscall entries to compute min cumulative frame depth
    to each reachable function. Frame sizes computed lazily.
    Returns: {func_addr: (min_depth, parent_addr)}
    """
    all_funcs = set(forward_graph.keys()) | set(reverse_graph.keys())
    for addr in syscall_entry_addrs:
        all_funcs.add(addr)

    min_depths: dict[int, tuple[int, int]] = {}
    frame_cache: dict[int, int] = {}

    def get_frame(addr: int) -> int:
        if addr not in frame_cache:
            idx = bisect.bisect_right(func_starts, addr) - 1
            if idx >= 0 and func_list[idx][0] == addr:
                fs = extract_func_frame_size(
                    addr, func_list[idx][1], text_base, text_data)
                frame_cache[addr] = fs
            else:
                frame_cache[addr] = 0
        return frame_cache[addr]

    queue = deque()
    for addr in syscall_entry_addrs:
        min_depths[addr] = (0, addr)
        if addr in forward_graph:
            queue.append((addr, 0))

    visited = 0
    while queue:
        current, curr_depth = queue.popleft()
        new_depth = curr_depth + get_frame(current)
        for callee in forward_graph.get(current, set()):
            if callee not in all_funcs:
                continue
            if callee in min_depths and min_depths[callee][0] <= new_depth:
                continue
            min_depths[callee] = (new_depth, current)
            visited += 1
            if callee in forward_graph:
                queue.append((callee, new_depth))

    alog(f"  BFS: {visited} edges, {len(min_depths)} reachable functions")
    return min_depths


# ── Overlap Analysis ─────────────────────────────────────────────────

def compute_waiter_overlap(
    dest_sp_offset: int, buf_size: int, frame_size: int, caller_depth: int,
) -> int:
    """
    Compute overlap bytes between buffer at the given call depth and waiter.
    dest_abs = -(caller_depth + frame_size) + dest_sp_offset
    Buffer spans [dest_abs, dest_abs + buf_size).
    """
    dest_abs = -(caller_depth + frame_size) + dest_sp_offset
    o_start = max(dest_abs, WAITER_START)
    o_end = min(dest_abs + buf_size, WAITER_END)
    return max(0, o_end - o_start)


def compute_analysis(
    candidate: dict,
    min_depths: Optional[dict[int, tuple[int, int]]] = None,
) -> list[dict]:
    """
    For each call site, compute overlap at various depths.
    Returns list of analysis dicts.
    """
    frame_size = candidate["frame_size"]
    results = []
    reaches_waiter = False

    for site in candidate["call_sites"]:
        dest_sp = site["dest_sp_offset"]
        copy_size = site["copy_size"]
        buf_size = max(copy_size, 1) if copy_size > 0 else 0x40

        # ── BFS-based exact depth (if reachable) ─────────────────────
        bfs_depth = None
        bfs_overlap = 0
        func_addr = candidate["func_addr"]
        if min_depths and func_addr in min_depths:
            bfs_depth = min_depths[func_addr][0]
            bfs_overlap = compute_waiter_overlap(
                dest_sp, buf_size, frame_size, bfs_depth)

        # ── Zero depth (minimum possible) ─────────────────────────────
        zero_overlap = compute_waiter_overlap(
            dest_sp, buf_size, frame_size, 0)

        # ── Overlap at various depths ─────────────────────────────────
        def ov_at(d: int) -> int:
            return compute_waiter_overlap(dest_sp, buf_size, frame_size, d)

        depths_to_check = [
            0x000, 0x080, 0x100, 0x180, 0x200, 0x280, 0x300, 0x400,
        ]
        overlap_map = {d: ov_at(d) for d in depths_to_check}

        # Find depth range where overlap > 0
        best_depth = 0
        best_overlap = 0
        for d in range(0, 0x401):
            o = ov_at(d)
            if o > best_overlap:
                best_overlap = o
                best_depth = d

        max_overlap_over_depths = best_overlap

        if max_overlap_over_depths > 0:
            reaches_waiter = True

        # Calculate zero-depth delta (in words)
        zero_abs = -(0 + frame_size) + dest_sp
        delta_words = (zero_abs - WAITER_START) // 8

        results.append({
            "call_addr": site["call_addr"],
            "dest_sp_offset": dest_sp,
            "copy_size": copy_size,
            "frame_size": frame_size,
            "buf_size": buf_size,
            "zero_overlap": zero_overlap,
            "zero_abs": zero_abs,
            "delta_words": delta_words,
            "bfs_depth": bfs_depth,
            "bfs_overlap": bfs_overlap,
            "best_depth": best_depth,
            "max_overlap": max_overlap_over_depths,
            "overlap_map": overlap_map,
        })

    return results


# ── Output ───────────────────────────────────────────────────────────

def fmt_overlap_chart(r: dict) -> str:
    """Format compact overlap-at-depth chart."""
    om = r.get("overlap_map", {})
    parts = []
    for d in [0x000, 0x080, 0x100, 0x180, 0x200, 0x280, 0x300, 0x400]:
        v = om.get(d, 0)
        if v >= 64:
            parts.append(f"{d:#05x}=FULL")
        elif v > 0:
            parts.append(f"{d:#05x}={v}B")
        else:
            parts.append(f"{d:#05x}=--")
    return " ".join(parts)


def output_results(
    all_analyses: list[tuple[dict, list[dict]]],
    min_depths: Optional[dict[int, tuple[int, int]]] = None,
    verbose: bool = False,
):
    """Output formatted analysis results."""
    total_funcs = len(all_analyses)
    total_calls = sum(len(a[1]) for a in all_analyses)

    # Collect stats
    candidates_with_overlap = []  # (name, analysis)
    bfs_reachable = 0
    bfs_overlapping = 0
    any_depth_overlap = 0

    for candidate, analyses in all_analyses:
        name = candidate.get("name", f"0x{candidate['func_addr']:x}")
        for r in analyses:
            if r["bfs_depth"] is not None:
                bfs_reachable += 1
                if r["bfs_overlap"] > 0:
                    bfs_overlapping += 1
                    candidates_with_overlap.append((name, r, "BFS"))
            if r["max_overlap"] > 0:
                any_depth_overlap += 1
                if r["bfs_depth"] is None:
                    candidates_with_overlap.append((name, r, "depth"))

    print()
    print("=" * 78)
    print("  GhostLock Global copy_from_user Scanner -- Results")
    print("=" * 78)
    print(f"  Waiter: [{WAITER_START:+d}, {WAITER_END:+d}) size={WAITER_SIZE}B")
    print(f"  Candidates: {total_funcs} functions, {total_calls} CFU call sites")
    print(f"  BFS reachable: {bfs_reachable} call sites")
    print(f"  BFS overlapping: {bfs_overlapping} call sites")
    print(f"  Overlap at SOME depth: {any_depth_overlap} call sites")
    print()

    # ── Section 1: BFS-overlapping candidates ────────────────────────
    bfs_candidates = []
    for candidate, analyses in all_analyses:
        name = candidate.get("name", f"0x{candidate['func_addr']:x}")
        for r in analyses:
            if r["bfs_depth"] is not None and r["bfs_overlap"] > 0:
                bfs_candidates.append((name, candidate, r))

    if bfs_candidates:
        print("=" * 78)
        print("  SECTION 1: BFS-REACHABLE CANDIDATES WITH OVERLAP")
        print("  These have a direct BL call chain from a syscall entry")
        print("  and their buffer already overlaps the waiter.")
        print("=" * 78)
        for name, candidate, r in sorted(
            bfs_candidates, key=lambda x: -x[2]["bfs_overlap"]
        ):
            print(f"\n  >>> {name}")
            print(f"      frame=0x{r['frame_size']:04x} "
                  f"dest@SP+0x{r['dest_sp_offset']:04x} "
                  f"size={r['copy_size']}B")
            print(f"      bfs_depth=0x{r['bfs_depth']:04x} "
                  f"bfs_overlap={r['bfs_overlap']}B")
            print(f"      overlap_at_depth chart:")
            print(f"        {fmt_overlap_chart(r)}")

    # ── Section 2: Top exploitability candidates ─────────────────────
    print()
    print("=" * 78)
    print("  SECTION 2: TOP EXPLOITABILITY CANDIDATES")
    print("=" * 78)
    print("  Scored by: max_overlap, then -|delta_words|, then +copy_size/64")
    print()

    # Score and deduplicate (function, best_site)
    scored = []
    func_scores: dict = {}

    for candidate, analyses in all_analyses:
        name = candidate.get("name", f"0x{candidate['func_addr']:x}")
        for r in analyses:
            # Score: high overlap good, low |delta| good
            s = r["max_overlap"] * 2
            if r["bfs_overlap"] > 0:
                s += 50  # bonus for already overlapping via BFS
            if r["bfs_depth"] is not None:
                s += 30  # bonus for being BFS-reachable
            s -= abs(r["delta_words"])
            if r["copy_size"] >= 64:
                s += 10
            # Prefer BUFFER-COVERS-WHOLE-WAITER candidates
            if r["max_overlap"] >= WAITER_SIZE:
                s += 200
            elif r["max_overlap"] >= WAITER_SIZE // 2:
                s += 100

            key = name
            if key not in func_scores or s > func_scores[key][0]:
                func_scores[key] = (s, r, candidate)

    scored = sorted(func_scores.items(), key=lambda x: -x[1][0])

    print(f"  {'Scr':>4s} {'Δ词':>5s} {'帧':>6s} {'Dest':>7s} "
          f"{'大小':>4s} {'BFS深':>6s} {'BFS重叠':>7s} "
          f"{'最佳深':>6s} {'最大重叠':>7s}  函数名")
    print(f"  {'-'*4} {'-'*5} {'-'*6} {'-'*7} {'-'*4} "
          f"{'-'*6} {'-'*7} {'-'*6} {'-'*7}  {'-'*55}")

    for name, (s, r, candidate) in scored[:35]:
        bfs_d = f"0x{r['bfs_depth']:04x}" if r["bfs_depth"] is not None else "N/A"
        bfs_ov = f"{r['bfs_overlap']}B" if r["bfs_overlap"] else "0B"
        print(f"  {s:4d} {r['delta_words']:+5d} 0x{r['frame_size']:04x} "
              f"0x{r['dest_sp_offset']:04x} {r['copy_size']:4d} "
              f"{bfs_d:>6s} {bfs_ov:>7s} "
              f"0x{r['best_depth']:04x} {r['max_overlap']:4d}B  {name}")

    # ── Section 3: Candidates with FULL waiter coverage ──────────────
    full_coverage = [
        (name, r, candidate)
        for name, (s, r, candidate) in func_scores.items()
        if r["max_overlap"] >= WAITER_SIZE
    ]

    if full_coverage:
        print()
        print("=" * 78)
        print("  SECTION 3: FULL WAITER COVERAGE "
              f"({len(full_coverage)} candidates)")
        print("  These candidates can overwrite the ENTIRE 64-byte waiter")
        print("  at some achievable caller_depth.")
        print("=" * 78)

        for name, r, candidate in sorted(
            full_coverage,
            key=lambda x: abs(x[1]["delta_words"])
        ):
            bfs_info = ""
            if r["bfs_depth"] is not None:
                bfs_info = (f" BFS_depth=0x{r['bfs_depth']:04x} "
                           f"BFS_overlap={r['bfs_overlap']}B")
            print(f"\n  >>> {name}{bfs_info}")
            print(f"      frame=0x{r['frame_size']:04x} "
                  f"dest@SP+0x{r['dest_sp_offset']:04x} "
                  f"size={r['copy_size']}B")
            print(f"      best_overlap: {r['max_overlap']}B "
                  f"at caller_depth=0x{r['best_depth']:04x}")
            print(f"      overlap chart:")
            print(f"        {fmt_overlap_chart(r)}")

    # ── Section 4: Depth scan for all functions ──────────────────────
    if verbose or True:
        print()
        print("=" * 78)
        print("  SECTION 4: OVERLAP AT VARIOUS DEPTHS")
        print("  Shows overlap at depth 0x000, 0x080, 0x100, 0x180, ...")
        print("  'FULL' = full 64B waiter covered. '--' = no overlap.")
        print("=" * 78)
        print(f"  {'Δ词':>5s} {'帧':>6s} {'Dest':>7s} {'大小':>4s} "
              f"{'BFS':>5s}   {'Overlap at depth'}")
        print(f"  {'-'*5} {'-'*6} {'-'*7} {'-'*4} {'-'*5}  "
              f"{'0x000 0x080 0x100 0x180 0x200 0x280 0x300 0x400'}")

        scored_by_delta = sorted(
            func_scores.items(),
            key=lambda x: abs(x[1][1]["delta_words"])
        )

        printed = 0
        for name, (s, r, candidate) in scored_by_delta:
            if printed >= 40:
                break
            printed += 1

            b = "BFS" if r["bfs_depth"] is not None else "IND"
            om = r.get("overlap_map", {})

            def fmt_ov(v: int) -> str:
                if v >= 64:
                    return "FULL"
                elif v > 0:
                    return f"{v:2d}B"
                else:
                    return " --"

            ov_str = " ".join(
                fmt_ov(om.get(d, 0))
                for d in [0x000, 0x080, 0x100, 0x180,
                          0x200, 0x280, 0x300, 0x400]
            )

            print(f"  {r['delta_words']:+5d} 0x{r['frame_size']:04x} "
                  f"0x{r['dest_sp_offset']:04x} {r['copy_size']:4d} "
                  f"{b:>5s}  {ov_str}  {name}")

    # ── Summary ──────────────────────────────────────────────────────
    print()
    print("=" * 78)
    print("  SUMMARY")
    print("=" * 78)
    print(f"  Total candidate functions: {total_funcs}")
    print(f"  Total CFU call sites: {total_calls}")
    print(f"  BFS-reachable (direct BL chain): {bfs_reachable}")
    print(f"  BFS-overlapping: {bfs_overlapping}")
    print(f"  Full waiter coverage at some depth: {len(full_coverage)}")
    print(f"  Any overlap at some depth: {any_depth_overlap}")
    print(f"  Indirect-call candidates (ioctl/read/write): "
          f"{total_calls - bfs_reachable}")
    print()

    if full_coverage:
        print("  *** FULL WAITER COVERAGE FOUND ***")
        print("  These candidates can overwrite all 64 bytes of the")
        print("  rt_mutex_waiter at an achievable stack depth.")
        print()
        print("  Exploitation strategy:")
        print("  1. Pick an ioctl-based driver (like qcedev or ipa3)")
        print("  2. Forge a call chain with the RIGHT caller_depth")
        print("     a) Standard ioctl path: ~0x100-0x200 depth")
        print("     b) Adjust depth by nesting calls or using compat")
        print("     c) The buffer may cover waiter if copy_size >= ~128B")
        print("  3. The user-controlled copy_from_user data goes into")
        print("     the waiter, overwriting the stack position.")
        print()

    print("  Key notes on BFS limitation:")
    print("  - The BFS only follows direct BL instructions.")
    print("  - Most ioctl/file_operation handlers are called via")
    print("    function pointers (BLR/BLRAA), invisible to BL scan.")
    print("  - Many 'BFS unreachable' candidates ARE actually reachable")
    print("    through standard kernel paths (ioctl, read, write).")
    print("  - For ioctl handlers: caller_depth ≈ 0x150-0x200 typical.")
    print("  - For read/write handlers: caller_depth ≈ 0x180-0x250.")
    print()


# ── Main ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optimized scanner for copy_from_user -> waiter overlap"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF,
                        help="Path to vmlinux.elf")
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    vprint = alog if args.verbose else lambda *a, **k: None

    t_start = time.time()

    # ── Phase 1: Load ELF ────────────────────────────────────────────
    t0 = time.time()
    vprint("Phase 1: Loading ELF...")
    symbols_by_name, text_base, text_data = load_vmlinux(args.elf)
    text_end = text_base + len(text_data)
    vprint(f"  .kernel: {len(text_data)} bytes @ 0x{text_base:x}")

    func_list = build_func_range_table(text_base, text_end)
    func_starts = [f[0] for f in func_list]
    vprint(f"  Range table: {len(func_list)} entries")

    cfu_addr = symbols_by_name.get("__arch_copy_from_user")
    if cfu_addr is None:
        print("ERROR: __arch_copy_from_user not found")
        return 1
    vprint(f"  CFU @ 0x{cfu_addr:x}")
    vprint(f"  [{time.time()-t0:.2f}s]")

    # ── Phase 2: Raw BL scan → forward/reverse graph ────────────────
    t0 = time.time()
    vprint("\nPhase 2: BL scan & graph building...")
    bl_edges = raw_scan_bl_instructions(text_data, text_base, text_end)
    vprint(f"  {len(bl_edges)} BL instructions")
    forward, reverse = map_bl_edges_to_functions(
        bl_edges, func_list, func_starts)
    vprint(f"  Forward: {len(forward)} callers, "
           f"Reverse: {len(reverse)} callees")
    vprint(f"  [{time.time()-t0:.2f}s]")

    # ── Phase 3: Find CFU callers ────────────────────────────────────
    t0 = time.time()
    vprint("\nPhase 3: Finding CFU callers...")
    cfu_callers: set[int] = set()
    for caller_addr, callees in forward.items():
        if cfu_addr in callees:
            cfu_callers.add(caller_addr)
    vprint(f"  {len(cfu_callers)} unique callers")
    vprint(f"  [{time.time()-t0:.2f}s]")

    # ── Phase 4: Analyze each candidate ──────────────────────────────
    t0 = time.time()
    vprint("\nPhase 4: Analyzing candidates...")
    all_analyses: list[tuple[dict, list[dict]]] = []

    for func_addr in sorted(cfu_callers):
        func_info = find_function(func_addr, func_list, func_starts)
        if not func_info:
            continue
        candidate = analyze_function(
            func_addr, func_info[1], text_base, text_data, cfu_addr)
        if not candidate:
            continue
        candidate["name"] = func_info[2]
        all_analyses.append((candidate, []))  # analyses filled after BFS
    vprint(f"  {len(all_analyses)} candidates analyzed")
    vprint(f"  [{time.time()-t0:.2f}s]")

    # ── Phase 5: BFS from syscall entries ────────────────────────────
    t0 = time.time()
    vprint("\nPhase 5: BFS from syscall entries...")
    syscall_entries = set()
    for name, addr in symbols_by_name.items():
        if name.startswith("__arm64_sys_") or name.startswith("__se_sys_"):
            if text_base <= addr < text_end:
                syscall_entries.add(addr)
    vprint(f"  {len(syscall_entries)} syscall entries")

    min_depths = compute_reachable_depths(
        forward, reverse, syscall_entries,
        text_base, text_data, func_list, func_starts)
    vprint(f"  [{time.time()-t0:.2f}s]")

    # ── Phase 6: Compute overlap for all candidates ──────────────────
    t0 = time.time()
    vprint("\nPhase 6: Computing overlap analysis...")

    # Add frame size of vfs_ioctl etc. to estimate indirect-call depth
    # for ioctl handlers. Find common wrapper frames.
    ioctl_wrapper_depth = 0
    for name_list, expected in [
        (["__arm64_sys_ioctl", "ksys_ioctl", "vfs_ioctl"], 0x170),
        (["__arm64_sys_read", "ksys_read", "vfs_read"], 0x1A0),
    ]:
        pass  # estimate below

    new_analyses = []
    for candidate, _ in all_analyses:
        analyses = compute_analysis(candidate, min_depths)
        new_analyses.append((candidate, analyses))
    all_analyses = new_analyses
    vprint(f"  [{time.time()-t0:.2f}s]")

    # ── Phase 7: Output ──────────────────────────────────────────────
    t0 = time.time()
    vprint("\nPhase 7: Output...")
    output_results(all_analyses, min_depths, args.verbose)

    total_time = time.time() - t_start
    print(f"  Total time: {total_time:.2f}s")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
