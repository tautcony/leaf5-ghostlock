#!/usr/bin/env python3
"""
GhostLock Global copy_from_user Scanner (Optimized)

Strategy:
  1. Raw BL instruction scan across the entire .kernel section (fast: ~2s)
     to find ALL functions that call __arch_copy_from_user.
  2. For each candidate function, disassemble with Capstone to extract
     frame_size, dest_sp_offset, copy_size.
  3. Compute the caller_depth range needed for the user-controlled buffer
     to overlap with the rt_mutex_waiter at [-0x380, -0x340).
  4. Build a reverse call graph from raw BL scan to determine if the
     required caller_depth is achievable from syscall entries.
  5. BFS from syscall entries to compute min_depth for each candidate.

Key insight: Instead of disassembling all 63K functions to build a call
graph, we pre-filter by doing a raw binary scan for BL instructions
targeting __arch_copy_from_user. This reduces Capstone disassembly
from 63K functions to ~500 candidate functions.

Then for the BFS, we build the call graph from raw BL scan data
and compute frame sizes on-demand.

Usage:
    cd /Users/tautcony/Documents/repos/leaf5-ghostlock/leaf5
    python3 ghostlock-analysis/copy-from-user-scan/scanner.py
    python3 ghostlock-analysis/copy-from-user-scan/scanner.py --verbose
    python3 ghostlock-analysis/copy-from-user-scan/scanner.py --min-overlap 8

Waiter position (rt_mutex_waiter on kernel stack):
    kernel_stack_top - 0x380, size 0x40 bytes ([-0x380, -0x340))
"""

from __future__ import annotations

import argparse
import bisect
import functools
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
WAITER_START = -0x380   # inclusive
WAITER_END = -0x340     # exclusive
WAITER_SIZE = 0x40


# ── Helper functions ─────────────────────────────────────────────────

def parse_imm(s: str) -> Optional[int]:
    """Parse an immediate value from a Capstone operand string."""
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
    """Print with timestamp."""
    if verbose:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    else:
        print(msg, flush=True)


# ── ELF Loading ──────────────────────────────────────────────────────

def load_vmlinux(path: Path) -> tuple[dict, int, bytes]:
    """Load ELF, return (symbols_by_name, text_base, text_data)."""
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


def build_func_range_table(
    symbols_by_name: dict, text_base: int, text_end: int
) -> tuple[list[tuple], list[int]]:
    """
    Build function range table from STT_FUNC symbols in the ELF.

    Returns:
      func_list: [(start_addr, end_addr, func_name), ...] sorted by start_addr
      func_starts: [start_addr, ...] for bisect lookups
    """
    from elftools.elf.elffile import ELFFile

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

    # Sort by address
    raw.sort(key=lambda x: x[0])

    # Build ranges: for functions with size=0, use next function's start
    func_list = []
    for i, (addr, size, name) in enumerate(raw):
        if size > 0:
            end = addr + size
        elif i < len(raw) - 1:
            end = raw[i + 1][0]
        else:
            end = addr + 0x10
        func_list.append((addr, end, name))

    func_starts = [f[0] for f in func_list]
    return func_list, func_starts


# ── Raw BL Scanning ──────────────────────────────────────────────────

def raw_scan_bl_instructions(
    text_data: bytes, text_base: int, text_end: int
) -> list[tuple[int, int]]:
    """
    Scan the entire .kernel section for BL instructions.

    Returns: [(pc, target_addr), ...] for every BL instruction found.
    Fast: uses raw word comparison, no Capstone.
    """
    bl_edges = []
    data_len = len(text_data)

    for i in range(0, data_len - 4, 4):
        word = struct.unpack("<I", text_data[i : i + 4])[0]
        if (word & 0xFC000000) != 0x94000000:
            continue

        # Decode BL target
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
    """
    Map BL instruction PCs to caller/callee function start addresses.

    Returns:
      forward_graph: {caller_func_addr: set(callee_func_addrs)}
      reverse_graph: {callee_func_addr: set(caller_func_addrs)}
    """
    forward: dict[int, set[int]] = defaultdict(set)
    reverse: dict[int, set[int]] = defaultdict(set)
    mapped = 0
    unmapped = 0

    for pc, target in bl_edges:
        # Find caller function
        idx = bisect.bisect_right(func_starts, pc) - 1
        if idx < 0 or pc >= func_list[idx][1]:
            unmapped += 1
            continue

        caller_addr = func_list[idx][0]

        # Find callee function
        idx2 = bisect.bisect_right(func_starts, target) - 1
        if idx2 < 0 or target >= func_list[idx2][1]:
            unmapped += 1
            continue

        callee_addr = func_list[idx2][0]

        forward[caller_addr].add(callee_addr)
        reverse[callee_addr].add(caller_addr)
        mapped += 1

    alog(f"  Mapped {mapped}/{len(bl_edges)} BL edges to functions"
         f" ({unmapped} unmapped)")
    return dict(forward), dict(reverse)


# ── Frame Size Extraction ─────────────────────────────────────────────

def extract_func_frame_size(
    func_addr: int,
    func_end: int,
    text_base: int,
    text_data: bytes,
) -> tuple[int, int]:
    """
    Disassemble a function to extract frame_size and fp_offset.

    Returns: (frame_size, fp_offset)
    Uses Capstone but only for one function at a time.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    off = func_addr - text_base
    size = func_end - func_addr
    if size <= 0 or size > 0x10000:
        return 0, 0

    fbytes = text_data[off : off + size]

    total = 0
    fp_off = 0

    for insn in md.disasm(fbytes, func_addr):
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

        if insn.mnemonic == "ret":
            break

    return total, fp_off


@functools.lru_cache(maxsize=None)
def get_frame_size_cached(
    func_addr: int,
    func_end: int,
    text_base: int,
    text_data_key: int = 0,  # dummy: prevents caching incorrect data
) -> tuple[int, int]:
    """
    Cached wrapper around extract_func_frame_size.
    The text_data_key is just to force re-cache if text changes.
    """
    return extract_func_frame_size(func_addr, func_end, text_base, text_data)


# ── Candidate Discovery ──────────────────────────────────────────────

def find_copy_from_user_candidates(
    cfu_addr: int,
    text_base: int,
    text_end: int,
    text_data: bytes,
    forward_graph: dict[int, set[int]],
    func_list: list[tuple],
    func_starts: list[int],
) -> list[dict]:
    """
    Find all functions that call __arch_copy_from_user.
    Uses the raw forward graph from BL scan.

    Returns list of candidate dicts with func info.
    """
    candidates_by_func: dict = {}

    for caller_addr, callees in forward_graph.items():
        if cfu_addr not in callees:
            continue

        # Get function name
        idx = bisect.bisect_right(func_starts, caller_addr) - 1
        if idx < 0:
            continue
        func_name = func_list[idx][2] if idx < len(func_list) else f"0x{caller_addr:x}"
        func_end = func_list[idx][1]

        # Extract frame info
        frame_size, fp_offset = extract_func_frame_size(
            caller_addr, func_end, text_base, text_data
        )

        if caller_addr not in candidates_by_func:
            candidates_by_func[caller_addr] = {
                "func_addr": caller_addr,
                "func_name": func_name,
                "func_end": func_end,
                "frame_size": frame_size,
                "fp_offset": fp_offset,
                "call_sites": [],
            }

    # Now, for each candidate, find the actual __arch_copy_from_user call sites
    # and their dest_sp_offset
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    for func_addr, candidate in candidates_by_func.items():
        off = func_addr - text_base
        size = candidate["func_end"] - func_addr
        if size <= 0 or size > 0x10000:
            continue

        fbytes = text_data[off : off + size]
        insns = list(md.disasm(fbytes, func_addr))

        fp_off = candidate["fp_offset"]
        frame_size = candidate["frame_size"]

        for i, insn in enumerate(insns):
            if insn.mnemonic != "bl":
                continue

            target = insn.operands[0].imm & ADDR_MASK
            if target != cfu_addr:
                continue

            # Look backward for x0 (dest) setup
            dest_sp = None
            copy_size = None

            for j in range(i - 1, max(0, i - 30), -1):
                prev = insns[j]
                op = prev.op_str

                # add x0, sp, #N
                if prev.mnemonic == "add" and op.startswith("x0, sp"):
                    parts = op.split("#")
                    if len(parts) > 1:
                        val = parse_imm(parts[-1].rstrip("]"))
                        if val is not None:
                            dest_sp = val
                            break

                # sub x0, x29, #N → dest = fp - N = (sp + fp_off) - N
                elif prev.mnemonic == "sub" and op.startswith("x0, x29"):
                    parts = op.split("#")
                    if len(parts) > 1:
                        val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                        if val is not None:
                            dest_sp = fp_off - val
                            break

            # Look for w2 (size)
            for j in range(i - 1, max(0, i - 15), -1):
                prev = insns[j]
                if prev.mnemonic == "mov" and "w2, #" in prev.op_str:
                    val = parse_imm(prev.op_str.split("#")[-1])
                    if val is not None:
                        copy_size = val
                    break

            if dest_sp is not None:
                candidate["call_sites"].append({
                    "call_addr": insn.address,
                    "dest_sp_offset": dest_sp,
                    "copy_size": copy_size or 0,
                })

    # Filter to only candidates with valid call_sites
    result = [c for c in candidates_by_func.values() if c["call_sites"]]
    return result


# ── Depth Computation (BFS from syscall entries) ─────────────────────

def compute_reachable_depths(
    forward_graph: dict[int, set[int]],
    reverse_graph: dict[int, set[int]],
    syscall_entry_addrs: set[int],
    text_base: int,
    text_data: bytes,
    func_list: list[tuple],
    func_starts: list[int],
) -> dict[int, tuple[int, int]]:
    """
    BFS from syscall entries to compute minimum cumulative frame depth
    to each reachable function.

    Returns: {func_addr: (min_depth, entry_func_addr)}

    Frame sizes are computed lazily (on first visit).

    All functions that exist in either forward_graph or reverse_graph
    are tracked. Leaf functions (only in reverse_graph) are recorded
    in min_depths but not enqueued (no outgoing edges to traverse).
    """
    # All functions that participate in call graph
    all_funcs = set(forward_graph.keys()) | set(reverse_graph.keys())
    for addr in syscall_entry_addrs:
        all_funcs.add(addr)

    min_depths: dict[int, tuple[int, int]] = {}
    frame_cache: dict[int, int] = {}

    def get_frame(addr: int) -> int:
        if addr not in frame_cache:
            idx = bisect.bisect_right(func_starts, addr) - 1
            if idx >= 0 and func_list[idx][0] == addr:
                fs, _ = extract_func_frame_size(
                    addr, func_list[idx][1], text_base, text_data
                )
                frame_cache[addr] = fs
            else:
                frame_cache[addr] = 0
        return frame_cache[addr]

    # Initialize queue with syscall entries
    queue = deque()
    for addr in syscall_entry_addrs:
        min_depths[addr] = (0, addr)
        if addr in forward_graph:
            queue.append((addr, 0))
        # If entry not in forward_graph, it's a leaf (no outgoing calls)
        # Record it with depth 0 but don't enqueue

    visited_edges = 0
    while queue:
        current_addr, current_depth = queue.popleft()

        frame_size = get_frame(current_addr)
        new_depth = current_depth + frame_size

        for callee in forward_graph.get(current_addr, set()):
            if callee not in all_funcs and callee != current_addr:
                continue
            if callee in min_depths and min_depths[callee][0] <= new_depth:
                continue

            min_depths[callee] = (new_depth, current_addr)
            visited_edges += 1

            # Only enqueue if it has outgoing edges (is in forward_graph)
            if callee in forward_graph:
                queue.append((callee, new_depth))

    alog(f"  BFS: {visited_edges} edges traversed, "
         f"{len(min_depths)} reachable functions")
    return min_depths


# ── Overlap Computation ──────────────────────────────────────────────

def compute_overlap_for_candidate(
    candidate: dict,
    min_depths: dict[int, tuple[int, int]],
) -> list[dict]:
    """
    For each call site in a candidate function, compute overlap with waiter.

    Formula:
        dest_abs = -(min_depth + frame_size) + dest_sp_offset
        overlap if dest_abs in [WAITER_START, WAITER_END)

    Also compute the required caller depth range for overlap:
        caller_depth ∈ (0x340 + dest_sp - frame_size, 0x380 + dest_sp - frame_size]

    Returns list of overlap results per call site.
    """
    func_addr = candidate["func_addr"]
    if func_addr not in min_depths:
        return []

    min_depth, entry_addr = min_depths[func_addr]
    frame_size = candidate["frame_size"]

    results = []
    for site in candidate["call_sites"]:
        dest_sp = site["dest_sp_offset"]
        copy_size = site["copy_size"]

        # Absolute position (with actual BFS depth)
        total_depth = min_depth + frame_size
        dest_abs = -total_depth + dest_sp

        # Buffer extent
        buf_size = max(copy_size, 1) if copy_size > 0 else 0x40
        buf_start = dest_abs
        buf_end = dest_abs + buf_size

        # Overlap with waiter [WAITER_START, WAITER_END)
        overlap_start = max(buf_start, WAITER_START)
        overlap_end = min(buf_end, WAITER_END)
        overlap_bytes = max(0, overlap_end - overlap_start)

        # Required caller depth for perfect overlap (center of waiter)
        # dest_abs = -0x360 → caller_depth = 0x360 - dest_sp + frame_size
        perfect_depth_for_overlap = 0x360 - dest_sp + frame_size

        # Zero-caller depth buffer position
        zero_depth_abs = -frame_size + dest_sp
        delta_to_waiter = zero_depth_abs - WAITER_START
        delta_words = delta_to_waiter // 8

        # Required caller depth range for ANY overlap with waiter.
        # Condition: WAITER_START <= dest_abs < WAITER_END
        #   -0x380 <= -(depth + frame) + dest_sp < -0x340
        #   depth > dest_sp - frame + 0x340  (for top of overlap)
        #   depth <= dest_sp - frame + 0x380 (for bottom of overlap)
        # So: depth ∈ (dest_sp - frame + 0x340, dest_sp - frame + 0x380]
        overlap_lo = dest_sp - frame_size + 0x340  # exclusive lower bound
        overlap_hi = dest_sp - frame_size + 0x380  # inclusive upper bound

        results.append({
            "call_addr": site["call_addr"],
            "dest_sp_offset": dest_sp,
            "copy_size": copy_size,
            "frame_size": frame_size,
            "min_depth": min_depth,
            "total_depth": total_depth,
            "entry_addr": entry_addr,
            "dest_abs": dest_abs,
            "buf_start": buf_start,
            "buf_end": buf_end,
            "overlap_bytes": overlap_bytes,
            "overlap_start": overlap_start,
            "overlap_end": overlap_end,
            "zero_depth_abs": zero_depth_abs,
            "delta_to_waiter": delta_to_waiter,
            "delta_words": delta_words,
            "perfect_depth": perfect_depth_for_overlap,
            "overlap_depth_lo": overlap_lo,
            "overlap_depth_hi": overlap_hi,
            "depth_in_range": overlap_lo < min_depth <= overlap_hi,
            "reachable": min_depth >= 0,
        })

    return results


# ── Output ───────────────────────────────────────────────────────────

def format_route(min_depths: dict, entry_addr: int) -> str:
    """Format a route from entry to candidate."""
    return f"via syscall entry 0x{entry_addr:x}"


def output_results(
    all_results: list[dict],
    min_depths: dict,
    candidates: list[dict],
    verbose: bool,
    min_overlap: int,
):
    """Output formatted results."""
    overlapping = [r for r in all_results if r["overlap_bytes"] > 0]
    close = [r for r in all_results if r["overlap_bytes"] == 0
             and abs(r["delta_words"]) <= 32]
    depth_match = [r for r in all_results if r["depth_in_range"]]

    print()
    print("=" * 78)
    print("  GhostLock Global copy_from_user Scanner Results")
    print("=" * 78)
    print(f"  Waiter: [{WAITER_START:+d}, {WAITER_END:+d}) size={WAITER_SIZE}B")
    print(f"  Functions analyzed: {len(candidates)}")
    print(f"  Call sites total: {sum(len(c['call_sites']) for c in candidates)}")
    print(f"  Reachable from syscall: {len(all_results)}")
    print(f"  With overlap > 0: {len(overlapping)}")
    print(f"  With depth range match: {len(depth_match)}")
    print(f"  Close (|delta| <= 32 words): {len(close)}")

    # ── Depth-range matched ──────────────────────────────────────────
    if depth_match:
        print()
        print("-" * 78)
        print("  ** DEPTH-RANGE MATCHED ** (min_depth already in overlap range)")
        print("-" * 78)
        # Group by function
        seen_funcs = set()
        for r in depth_match:
            fname = r.get("func_name", f"0x{r['func_addr']:x}")
            if fname not in seen_funcs:
                seen_funcs.add(fname)
                print(f"\n  >>> {fname} @ 0x{r['func_addr']:x}")
                print(f"      min_depth=0x{r['min_depth']:04x} "
                      f"frame=0x{r['frame_size']:04x} "
                      f"dest@SP+0x{r['dest_sp_offset']:04x} "
                      f"size={r['copy_size']}B")
                print(f"      overlap_depth_lo=0x{r['overlap_depth_lo']:04x} "
                      f"overlap_depth_hi=0x{r['overlap_depth_hi']:04x}")
                print(f"      overlap: {r['overlap_bytes']}B "
                      f"[{r['overlap_start']:+d}, {r['overlap_end']:+d})")
        print()

    # ── Overlapping ──────────────────────────────────────────────────
    if overlapping and not depth_match:
        print()
        print("-" * 78)
        print(f"  ** FUNCTIONS WITH OVERLAP ({len(overlapping)}) **")
        print("-" * 78)
        # Group and deduplicate by function
        seen = set()
        for r in overlapping:
            fkey = r.get("func_name", f"0x{r['func_addr']:x}")
            if fkey not in seen:
                seen.add(fkey)
                print(f"\n  >>> {fkey} @ 0x{r['func_addr']:x}")
                print(f"      min_depth=0x{r['min_depth']:04x} "
                      f"frame=0x{r['frame_size']:04x} "
                      f"dest@SP+0x{r['dest_sp_offset']:04x} "
                      f"size={r['copy_size']}B")
                print(f"      overlap: {r['overlap_bytes']}B "
                      f"[{r['overlap_start']:+d}, {r['overlap_end']:+d}) "
                      f"delta_to_waiter={r['delta_words']:+d}words")
        print()

    # ── Close matches ────────────────────────────────────────────────
    if close:
        print()
        print("-" * 78)
        print(f"  ** CLOSE MATCHES (|delta| <= 32 words) **")
        print("-" * 78)
        print(f"  {'Δ词':>5s} {'重叠':>5s} {'深度':>6s} {'帧大小':>6s} "
              f"{'Dest@SP':>7s} {'大小':>4s}  {'函数名'}")
        print(f"  {'-'*5} {'-'*5} {'-'*6} {'-'*6} {'-'*7} {'-'*4}  {'-'*55}")
        for r in close[:30]:
            marker = "✓" if r["overlap_bytes"] > 0 else " "
            dw = r["delta_words"]
            print(f"  {dw:+5d} {r['overlap_bytes']:4d}B "
                  f"0x{r['total_depth']:04x} 0x{r['frame_size']:04x} "
                  f"0x{r['dest_sp_offset']:04x} {r['copy_size']:3d}B "
                  f"{marker} {r.get('func_name', '?')}")
        print()

    # ── Best candidates summary ──────────────────────────────────────
    print()
    print("=" * 78)
    print("  RECOMMENDED CANDIDATES (sorted by exploitability)")
    print("=" * 78)

    # Score candidates by:
    # 1. overlap > 0
    # 2. |delta| small
    # 3. copy_size known and sufficient
    # 4. reachable from simple syscall path

    def score(r):
        s = 0
        if r["overlap_bytes"] > 0:
            s += 100
        s -= abs(r["delta_words"])  # closer is better
        if r["copy_size"] >= 64:
            s += 20
        elif r["copy_size"] >= 32:
            s += 10
        return s

    scored = sorted(all_results, key=score, reverse=True)[:15]

    print(f"  {'得分':>4s} {'重叠':>5s} {'Δ词':>5s} {'深度':>6s} "
          f"{'帧':>6s} {'Dest':>7s}  函数名")
    print(f"  {'-'*4} {'-'*5} {'-'*5} {'-'*6} {'-'*6} {'-'*7}  {'-'*55}")
    for r in scored:
        print(f"  {score(r):4d} {r['overlap_bytes']:4d}B "
              f"{r['delta_words']:+5d} 0x{r['total_depth']:04x} "
              f"0x{r['frame_size']:04x} 0x{r['dest_sp_offset']:04x}  "
              f"{r.get('func_name', '?')}")
    print()


# ── Main ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optimized scanner for copy_from_user → waiter overlap"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF,
                        help="Path to vmlinux.elf")
    parser.add_argument("--min-overlap", type=int, default=1,
                        help="Minimum overlap bytes to report (default: 1)")
    parser.add_argument("--show-all", action="store_true",
                        help="Show all candidates, not just overlapping")
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    vprint = alog if args.verbose else lambda *a, **k: None

    # ── Phase 1: Load ELF ────────────────────────────────────────────
    t0 = time.time()
    vprint("Phase 1: Loading vmlinux.elf...")
    symbols_by_name, text_base, text_data = load_vmlinux(args.elf)
    text_end = text_base + len(text_data)
    vprint(f"  .kernel: {len(text_data)} bytes @ 0x{text_base:x}")
    vprint(f"  Symbols: {len(symbols_by_name)}")

    # Build function range table
    func_list, func_starts = build_func_range_table(
        symbols_by_name, text_base, text_end
    )
    vprint(f"  Function range table: {len(func_list)} entries")

    cfu_addr = symbols_by_name.get("__arch_copy_from_user")
    if cfu_addr is None:
        print("ERROR: __arch_copy_from_user not found")
        return 1
    vprint(f"  __arch_copy_from_user @ 0x{cfu_addr:x}")
    t1 = time.time()
    vprint(f"  [{t1-t0:.2f}s]")

    # ── Phase 2: Raw BL scan ─────────────────────────────────────────
    t0 = time.time()
    vprint("\nPhase 2: Raw BL scan...")
    bl_edges = raw_scan_bl_instructions(text_data, text_base, text_end)
    vprint(f"  Found {len(bl_edges)} BL instructions in .kernel")

    # Map to functions
    forward_graph, reverse_graph = map_bl_edges_to_functions(
        bl_edges, func_list, func_starts
    )
    vprint(f"  Forward graph: {len(forward_graph)} callers")
    vprint(f"  Reverse graph: {len(reverse_graph)} callees")
    t1 = time.time()
    vprint(f"  [{t1-t0:.2f}s]")

    # ── Phase 3: Find candidates ─────────────────────────────────────
    t0 = time.time()
    vprint("\nPhase 3: Finding __arch_copy_from_user callers...")
    candidates = find_copy_from_user_candidates(
        cfu_addr, text_base, text_end, text_data,
        forward_graph, func_list, func_starts
    )
    vprint(f"  Found {len(candidates)} candidate functions")
    for c in candidates:
        vprint(f"    {c['func_name']}: frame=0x{c['frame_size']:04x} "
               f"{len(c['call_sites'])} call(s)", verbose=args.verbose)
        for s in c["call_sites"]:
            vprint(f"      @ 0x{s['call_addr']:x}: "
                   f"dest=SP+0x{s['dest_sp_offset']:04x} "
                   f"size={s['copy_size']}B", verbose=args.verbose)
    t1 = time.time()
    vprint(f"  [{t1-t0:.2f}s]")

    # ── Phase 4: Find syscall entries ─────────────────────────────────
    syscall_entry_addrs = set()
    for name, addr in symbols_by_name.items():
        if name.startswith("__arm64_sys_") or name.startswith("__se_sys_"):
            if text_base <= addr < text_end:
                syscall_entry_addrs.add(addr)
    vprint(f"\n  Syscall entries: {len(syscall_entry_addrs)}")

    # ── Phase 5: BFS for reachable depths ─────────────────────────────
    t0 = time.time()
    vprint("\nPhase 5: Computing reachable depths (BFS)...")
    min_depths = compute_reachable_depths(
        forward_graph, reverse_graph, syscall_entry_addrs,
        text_base, text_data, func_list, func_starts
    )
    t1 = time.time()
    vprint(f"  [{t1-t0:.2f}s]")

    # ── Phase 6: Compute overlap ─────────────────────────────────────
    t0 = time.time()
    vprint("\nPhase 6: Computing overlap with waiter...")
    all_results = []

    for candidate in candidates:
        # Look up the function name by addr in func_list
        idx = bisect.bisect_right(func_starts, candidate["func_addr"]) - 1
        func_name = func_list[idx][2] if idx >= 0 else f"0x{candidate['func_addr']:x}"

        results = compute_overlap_for_candidate(candidate, min_depths)
        for r in results:
            r["func_name"] = func_name
            r["func_addr"] = candidate["func_addr"]
        all_results.extend(results)

    all_results.sort(
        key=lambda r: (-r["overlap_bytes"], abs(r["delta_words"]), -r["copy_size"])
    )
    t1 = time.time()
    vprint(f"  [{t1-t0:.2f}s]")

    # ── Output ───────────────────────────────────────────────────────
    output_results(all_results, min_depths, candidates,
                   args.verbose, args.min_overlap)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
