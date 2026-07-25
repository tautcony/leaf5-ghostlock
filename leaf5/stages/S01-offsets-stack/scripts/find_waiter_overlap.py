#!/usr/bin/env python3
"""
全局扫描: 寻找 copy_from_user 目标与 GhostLock waiter 栈位置重叠的函数

策略:
  1. 构建内核调用图 (BL 指令)
  2. 从所有 __arm64_sys_* entry 点 BFS 计算最小栈深度
  3. 扫描所有调用 __arch_copy_from_user 的函数
  4. 找到目标缓冲区在栈上的 SP 偏移
  5. 计算绝对栈位置, 与 waiter (-0x380) 比较
  6. 按重叠程度排序输出候选

用法:
    uv run python -m scripts.find_waiter_overlap -v
    uv run python -m scripts.find_waiter_overlap --min-overlap 8 --max-depth 0x800
"""

from __future__ import annotations

import argparse
import struct
from collections import defaultdict, deque
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

# Waiter position (from futex_wait frame analysis)
WAITER_ABS_OFFSET = -0x380  # relative to kernel_stack_top (after exception entry)
WAITER_SIZE = 0x40          # 4.19: 64 bytes
WAITER_START = WAITER_ABS_OFFSET
WAITER_END = WAITER_ABS_OFFSET + WAITER_SIZE  # = -0x340


def parse_imm(s: str) -> Optional[int]:
    s = s.strip().rstrip("]!,")
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("#"):
        s = s[1:]
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("-"):
        return -int(s[1:], 16 if s[1:].startswith("0x") else 10)
    if "," in s:
        s = s.split(",")[0]
    # Check if it's a register name (not a number)
    if s.startswith("x") or s.startswith("w") or s.startswith("sp") or s.startswith("lr"):
        return None
    try:
        return int(s, 16 if s.startswith("0x") else 10)
    except ValueError:
        return None


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
    raise ValueError("No .kernel section")


def build_call_graph(
    symbols: dict, text_base: int, text_data: bytes
) -> dict[int, tuple[int, list[int], int, int]]:
    """
    Build call graph by analyzing BL instructions in each function.

    Returns: {func_addr: (frame_size, [callee_addrs], fp_offset, func_end_addr)}

    Only processes functions up to 0x2000 bytes.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    graph = {}
    func_count = 0

    # Only process functions that are in the symbol table and have valid addresses
    text_end = text_base + len(text_data)

    for name, addr in symbols.items():
        if not (text_base <= addr < text_end):
            continue
        if addr in graph:
            continue

        off = addr - text_base
        fbytes = text_data[off : off + 0x2000]

        total = 0
        fp_off = 0
        callees = []
        func_end = addr
        has_ret = False

        for insn in md.disasm(fbytes, addr):
            func_end = insn.address + 4
            op = insn.op_str

            # Frame allocation
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

            # Direct calls
            if insn.mnemonic == "bl":
                target = insn.operands[0].imm & ADDR_MASK
                if text_base <= target < text_end:
                    callees.append(target)

            if insn.mnemonic == "ret":
                has_ret = True
                if total > 0 or insn.address > addr + 0x10:
                    break

        if not has_ret:
            continue  # skip non-function symbols

        graph[addr] = (total, callees, fp_off, func_end)
        func_count += 1

        if func_count % 10000 == 0:
            print(f"  ... processed {func_count} functions", flush=True)

    print(f"  Call graph: {func_count} functions processed", flush=True)
    return graph


def find_syscall_entries(symbols: dict) -> dict[str, int]:
    """Find all __arm64_sys_* and __se_sys_* entry points."""
    entries = {}
    for name, addr in symbols.items():
        if name.startswith("__arm64_sys_") or name.startswith("__se_sys_"):
            entries[name] = addr
    return entries


def compute_min_depths(
    graph: dict, syscall_entries: dict[str, int]
) -> dict[int, tuple[int, int]]:
    """
    BFS from each syscall entry to compute minimum frame depth to each function.

    Returns: {func_addr: (min_depth, entry_func_addr)}
    min_depth is the cumulative frame size from the syscall entry frame.
    This DOES NOT include the syscall entry's own frame (that's at depth 0).
    """
    # Use Dijkstra-like BFS with priority on minimum depth
    # For each function, track the minimum depth found so far

    min_depths: dict[int, tuple[int, int]] = {}  # addr -> (min_depth, entry_addr)

    # Initialize with all syscall entries at depth 0
    # (their own frame is not counted in the path to deeper functions)
    pq = deque()
    for name, addr in syscall_entries.items():
        if addr not in graph:
            continue
        frame_size = graph[addr][0]
        # The callee's depth starts at this entry's frame size
        min_depths[addr] = (0, addr)
        pq.append((addr, 0))

    # BFS
    visited_count = 0
    while pq:
        current_addr, current_depth = pq.popleft()

        if current_addr not in graph:
            continue

        frame_size, callees, _, func_end = graph[current_addr]

        # When calling a callee, the callee's frame sits below the caller's frame
        # So the cumulative depth to the callee SP = current_depth + frame_size
        new_depth = current_depth + frame_size

        for callee in callees:
            if callee not in graph:
                continue
            if callee in min_depths and min_depths[callee][0] <= new_depth:
                continue  # already found a shorter path

            min_depths[callee] = (new_depth, current_addr)
            pq.append((callee, new_depth))
            visited_count += 1

    print(f"  BFS: {visited_count} edges traversed, "
          f"{len(min_depths)} reachable functions", flush=True)
    return min_depths


def find_copy_from_user_calls(
    symbols: dict, text_base: int, text_data: bytes, graph: dict
) -> list[dict]:
    """
    Scan all functions for __arch_copy_from_user calls.
    For each call, determine the destination stack offset.

    Returns list of:
      {func_addr, func_name, call_addr, dest_sp_offset, copy_size, frame_size, fp_offset}
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    cfu_addr = symbols.get("__arch_copy_from_user")
    if cfu_addr is None:
        print("  ERROR: __arch_copy_from_user not found in symbols")
        return []

    text_end = text_base + len(text_data)
    found = []

    for func_addr, (frame_size, callees, fp_offset, func_end) in graph.items():
        off = func_addr - text_base
        fbytes = text_data[off : off + min(0x2000, func_end - func_addr + 0x100)]

        insns = list(md.disasm(fbytes, func_addr))

        for i, insn in enumerate(insns):
            if insn.mnemonic != "bl":
                continue
            target = insn.operands[0].imm & ADDR_MASK
            if target != cfu_addr:
                continue

            # Found a copy_from_user call — look backward for x0 (dest) and w2 (size)
            dest_sp = None
            copy_size = None

            for j in range(i - 1, max(0, i - 20), -1):
                prev = insns[j]
                op = prev.op_str

                # add x0, sp, #N → dest = sp + N
                if prev.mnemonic == "add" and op.startswith("x0, sp"):
                    parts = op.split("#")
                    if len(parts) > 1:
                        val = parse_imm(parts[-1].rstrip("]"))
                        if val is not None:
                            dest_sp = val
                            break

                # sub x0, x29, #N → dest = fp - N = (sp + fp_offset) - N
                elif prev.mnemonic == "sub" and op.startswith("x0, x29"):
                    parts = op.split("#")
                    if len(parts) > 1:
                        val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                        if val is not None:
                            dest_sp = fp_offset - val
                            break

                # mov x0, Xn (where Xn was set from sp earlier) — skip for now

            # Try to find w2 (size) nearby
            for j in range(i - 1, max(0, i - 10), -1):
                prev = insns[j]
                if prev.mnemonic == "mov" and "w2, #" in prev.op_str:
                    val = parse_imm(prev.op_str.split("#")[-1])
                    if val is not None:
                        copy_size = val
                    break

            if dest_sp is not None:
                # Find the function name
                func_name = None
                for n, a in symbols.items():
                    if a == func_addr:
                        func_name = n
                        break

                found.append({
                    "func_addr": func_addr,
                    "func_name": func_name or f"0x{func_addr:x}",
                    "call_addr": insn.address,
                    "dest_sp_offset": dest_sp,
                    "copy_size": copy_size or 0,
                    "frame_size": frame_size,
                    "fp_offset": fp_offset,
                })

    print(f"  Found {len(found)} __arch_copy_from_user calls", flush=True)
    return found


def compute_overlap(
    cfu_calls: list[dict],
    min_depths: dict,
    graph: dict,
    verbose: bool = False,
) -> list[dict]:
    """
    For each copy_from_user call, compute the absolute stack position
    of the destination buffer and compare with waiter position.

    KEY INSIGHT: BFS min_depth is the cumulative depth to the function's
    ENTRY SP (NOT including the function's own frame allocation).

    The function allocates its frame via sub sp, sp, #frame_size,
    then the variable at SP+dest_sp is at:
      var_abs = -(min_depth + frame_size) + dest_sp

    This accounts for ALL frames between kernel_stack_top and the variable.
    """
    results = []

    for call in cfu_calls:
        func_addr = call["func_addr"]
        if func_addr not in min_depths:
            continue

        min_depth, entry_addr = min_depths[func_addr]
        frame_size = call["frame_size"]
        dest_sp = call["dest_sp_offset"]
        copy_size = call["copy_size"]

        # Absolute position accounting for function's own frame
        total_depth = min_depth + frame_size
        dest_abs = -total_depth + dest_sp

        # Buffer extent (use copy_size if known, else assume 0x40)
        buf_size = max(copy_size, 0x40) if copy_size > 0 else 0x100
        buf_start = dest_abs
        buf_end = dest_abs + buf_size

        # Overlap with waiter [WAITER_START, WAITER_END)
        overlap_start = max(buf_start, WAITER_START)
        overlap_end = min(buf_end, WAITER_END)
        overlap_bytes = max(0, overlap_end - overlap_start)

        if overlap_bytes > 0 or verbose:
            results.append({
                **call,
                "min_depth": min_depth,
                "total_depth": total_depth,
                "entry_addr": entry_addr,
                "dest_abs": dest_abs,
                "buf_start": buf_start,
                "buf_end": buf_end,
                "overlap_bytes": overlap_bytes,
                "overlap_start": overlap_start,
                "overlap_end": overlap_end,
                "delta_bytes": dest_abs - WAITER_START,
                "delta_words": (dest_abs - WAITER_START) // 8,
            })

    # Sort by overlap (descending), then by delta (ascending)
    results.sort(key=lambda r: (-r["overlap_bytes"], abs(r["delta_bytes"])))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan kernel for copy_from_user destinations overlapping GhostLock waiter"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    parser.add_argument("--min-overlap", type=int, default=1,
                        help="Minimum overlap bytes to report (default: 1)")
    parser.add_argument("--max-depth", type=lambda x: int(x, 0), default=0x1000,
                        help="Maximum call depth to consider (default: 0x1000)")
    parser.add_argument("--show-all", action="store_true",
                        help="Show all copy_from_user calls, not just overlapping ones")
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    print("=" * 70)
    print("Phase 1: Load vmlinux and build call graph")
    print("=" * 70)
    symbols, text_base, text_data = load_vmlinux(args.elf)
    print(f"  Symbols: {len(symbols)}")
    print(f"  .kernel: 0x{text_base:x} ({len(text_data)} bytes)")

    print("\n" + "=" * 70)
    print("Phase 2: Build call graph from BL instructions")
    print("=" * 70)
    graph = build_call_graph(symbols, text_base, text_data)

    print("\n" + "=" * 70)
    print("Phase 3: Find syscall entry points")
    print("=" * 70)
    syscall_entries = find_syscall_entries(symbols)
    print(f"  Found {len(syscall_entries)} syscall entries")

    print("\n" + "=" * 70)
    print("Phase 4: BFS compute minimum frame depths")
    print("=" * 70)
    min_depths = compute_min_depths(graph, syscall_entries)

    print("\n" + "=" * 70)
    print("Phase 5: Scan for __arch_copy_from_user calls")
    print("=" * 70)
    cfu_calls = find_copy_from_user_calls(symbols, text_base, text_data, graph)

    print("\n" + "=" * 70)
    print("Phase 6: Compute overlap with waiter position")
    print("=" * 70)
    results = compute_overlap(cfu_calls, min_depths, graph, verbose=args.show_all)

    # ── Output ─────────────────────────────────────────────────────
    print(f"\n  Waiter position: {WAITER_START:+d} to {WAITER_END:+d} "
          f"(size={WAITER_SIZE}B)")
    print(f"  Total copy_from_user calls analyzed: {len(cfu_calls)}")
    print(f"  Reachable from syscall: {len([r for r in results])}")
    print(f"  With overlap > 0: {len([r for r in results if r['overlap_bytes'] > 0])}")

    if args.show_all:
        print(f"\n  Showing all reachable copy_from_user calls:")
        header = (f"  {'Δ词':>5s} {'重叠':>5s} {'深度':>6s} {'Dest@SP':>7s} "
                  f"{'大小':>5s}  {'函数名'}")
        print(header)
        print(f"  {'-'*5} {'-'*5} {'-'*6} {'-'*7} {'-'*5}  {'-'*50}")
        for r in results:
            if abs(r["delta_words"]) > 128 and r["overlap_bytes"] == 0:
                continue  # skip far-away ones
            marker = "✓" if r["overlap_bytes"] > 0 else " "
            print(f"  {r['delta_words']:+5d} {r['overlap_bytes']:4d}B "
                  f"0x{r['total_depth']:04x} 0x{r['dest_sp_offset']:04x} "
                  f"{r['copy_size']:4d}B {marker} {r['func_name']}")

    # ── Best matches ───────────────────────────────────────────────
    print(f"\n" + "=" * 70)
    print("BEST MATCHES (overlap > 0 or closest)")
    print("=" * 70)

    overlapping = [r for r in results if r["overlap_bytes"] > 0]
    close = [r for r in results if r["overlap_bytes"] == 0 and abs(r["delta_words"]) <= 16]

    if overlapping:
        print(f"\n  *** FUNCTIONS WITH DIRECT OVERLAP ({len(overlapping)}) ***\n")
        for r in overlapping[:20]:
            print(f"  ✓ {r['func_name']}")
            print(f"    depth=0x{r['min_depth']:04x} dest@SP+0x{r['dest_sp_offset']:04x} "
                  f"size={r['copy_size']}B")
            print(f"    overlap: [{r['overlap_start']:+d}, {r['overlap_end']:+d}) "
                  f"({r['overlap_bytes']}B of {WAITER_SIZE}B waiter)")
            print(f"    waiter field range covered: "
                  f"bytes [{max(0, r['overlap_start']-WAITER_START)}.."
                  f"{min(WAITER_SIZE, r['overlap_end']-WAITER_START)})")
            print()

    if close and not overlapping:
        print(f"\n  *** CLOSE MATCHES (within ±16 words, {len(close)}) ***\n")
        for r in close[:15]:
            direction = "above" if r["delta_bytes"] > 0 else "below"
            print(f"  ~ {r['func_name']}: {abs(r['delta_bytes'])}B {direction} waiter")
            print(f"    depth=0x{r['min_depth']:04x} dest@SP+0x{r['dest_sp_offset']:04x} "
                  f"size={r['copy_size']}B  Δ={r['delta_words']:+d}词")

    if not overlapping and not close:
        print(f"\n  No close matches found within ±16 words.")
        print(f"  Showing top 10 closest by |Δ|:")
        top = sorted(results, key=lambda r: abs(r["delta_bytes"]))[:10]
        for r in top:
            direction = "above" if r["delta_bytes"] > 0 else "below"
            print(f"  {r['func_name']}: {abs(r['delta_bytes'])}B {direction} "
                  f"(Δ={r['delta_words']:+d}词) "
                  f"depth=0x{r['min_depth']:04x} dest@SP+0x{r['dest_sp_offset']:04x}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
