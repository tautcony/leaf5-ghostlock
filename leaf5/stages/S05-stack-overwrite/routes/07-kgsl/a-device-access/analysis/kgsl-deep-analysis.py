#!/usr/bin/env python3
"""
Deep analysis of kgsl ioctl dispatch and CFU sites.

1. Traces kgsl_ioctl_helper to find all sub-handlers it calls
2. Computes exact caller depth via BL chain
3. For each CFU site with known copy size, checks waiter coverage
4. Reports full exploitation feasibility
"""

from __future__ import annotations

import bisect
import struct
from pathlib import Path
from collections import defaultdict, deque
from typing import Optional

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


ROOT = Path(__file__).resolve().parents[1]
VMLINUX_ELF = ROOT / "raw" / "vmlinux.elf"
WAITER_START = -0x380
WAITER_END = -0x340
WAITER_SIZE = 0x40


def parse_imm(s):
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


def fmt_addr(x):
    return f"0x{x:016x}"


# ---- Load ELF ----

with open(VMLINUX_ELF, "rb") as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name(".symtab")

    sym_by_name = {}
    raw_funcs = []
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

    func_list = []
    for i, (addr, size, name) in enumerate(raw_funcs):
        if size > 0:
            end = addr + size
        elif i < len(raw_funcs) - 1:
            end = raw_funcs[i + 1][0]
        else:
            end = addr + 0x10
        func_list.append((addr, end, name))

    func_starts = [f[0] for f in func_list]

    for sec in elf.iter_sections():
        if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
            text_base = sec.header.sh_addr
            text_data = sec.data()
            text_end = text_base + len(text_data)
            break
    else:
        raise ValueError("No .kernel section")


def find_func(addr):
    idx = bisect.bisect_right(func_starts, addr) - 1
    if idx >= 0 and func_list[idx][0] <= addr < func_list[idx][1]:
        return func_list[idx]
    return None


def get_func_name(addr):
    info = find_func(addr)
    return info[2] if info else f"0x{addr:x}"


cfu_addr = sym_by_name["__arch_copy_from_user"]

# ---- Disassemble helper ----

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True


def disasm_func(func_addr, func_end):
    off = func_addr - text_base
    size = func_end - func_addr
    if size <= 0 or size > 0x20000:
        return []
    return list(md.disasm(text_data[off:off + size], func_addr))


def extract_frame(insns):
    total = 0
    fp_off = 0
    for insn in insns:
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            val = parse_imm(op.split("#")[-1].strip(","))
            if val is not None and val > 0:
                total += val
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            val = parse_imm(op.split("#-")[1].split("]")[0])
            if val is not None and val > 0:
                total += val
        if insn.mnemonic == "add" and "x29, sp" in op:
            val = parse_imm(op.split("#")[-1])
            if val is not None:
                fp_off = val
    return total, fp_off


# ============================================================
# 1. Trace kgsl_ioctl_helper dispatch targets
# ============================================================

print("=" * 100)
print("  PHASE 1: kgsl_ioctl_helper dispatch analysis")
print("=" * 100)

kih_addr = sym_by_name.get("kgsl_ioctl_helper")
if kih_addr:
    kih_info = find_func(kih_addr)
    if kih_info:
        kih_insns = disasm_func(kih_addr, kih_info[1])
        kih_frame, kih_fp = extract_frame(kih_insns)
        print(f"  kgsl_ioctl_helper: @{fmt_addr(kih_addr)} frame=0x{kih_frame:04x}")

        # Find all BL calls and function-pointer lookups (BLR targets)
        dispatched_funcs = {}  # bl_addr -> (target_name, target_addr)
        for insn in kih_insns:
            if insn.mnemonic == "bl":
                target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                t_info = find_func(target)
                if t_info:
                    dispatched_funcs[insn.address] = (t_info[2], t_info[0], t_info[1])

        print(f"  Dispatches to {len(dispatched_funcs)} functions:")
        for bl_addr, (name, taddr, tend) in sorted(dispatched_funcs.items(), key=lambda x: x[1][0]):
            # Only show kgsl functions
            if "kgsl" in name:
                frame, fp = extract_frame(disasm_func(taddr, tend))
                print(f"    BL @{fmt_addr(bl_addr)} -> {name} @{fmt_addr(taddr)} (frame=0x{frame:04x})")

        # Find BLR (function pointer call) patterns
        print(f"\n  Function pointer calls (BLR) in kgsl_ioctl_helper:")
        for insn in kih_insns:
            if insn.mnemonic == "blr":
                op = insn.op_str
                print(f"    BLR @{fmt_addr(insn.address)}: {op}")
            if insn.mnemonic == "ldr" and "x8" in insn.op_str and "[x" in insn.op_str:
                # Look for LDR X8 = function pointer load
                pass

# ============================================================
# 2. Build full BL call graph for kgsl
# ============================================================

print()
print("=" * 100)
print("  PHASE 2: BL call graph analysis (all kgsl functions)")
print("=" * 100)

# Build BL edges for kgsl functions
kgsl_funcs = {}  # addr -> (name, end)
for addr, end, name in func_list:
    if "kgsl" not in name:
        continue
    if any(name.startswith(p) for p in ("trace_", "perf_trace_", "__bpf_trace_",
                                         "trace_raw_output_", "__event_", "__initcall_",
                                         "trace_event_define_fields_")):
        continue
    kgsl_funcs[addr] = (name, end)

forward = defaultdict(set)
reverse = defaultdict(set)

for addr, (name, end) in kgsl_funcs.items():
    insns = disasm_func(addr, end)
    for insn in insns:
        if insn.mnemonic == "bl":
            target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            if target in kgsl_funcs:
                forward[addr].add(target)
                reverse[target].add(addr)

# Find entry points (from kgsl_ioctl_helper dispatch table)
entry_points = set()
for bl_addr, (name, taddr, tend) in dispatched_funcs.items():
    if taddr in kgsl_funcs:
        entry_points.add(taddr)

print(f"  kgsl functions: {len(kgsl_funcs)}")
print(f"  BL edges among kgsl: {sum(len(v) for v in forward.values())}")
print(f"  Directly dispatched by kgsl_ioctl_helper: {len(entry_points)}")

# Find call chain from entry points to CFU functions
# BFS from entry points to find reachable CFU callers
entry_to_cfu = {}  # entry -> list of (chain depth, cfu_func)

for entry in entry_points:
    # BFS
    visited = {entry: (0, None)}  # func_addr -> (depth_in_calls, parent)
    q = deque([(entry, 0)])

    while q:
        cur, depth = q.popleft()
        for callee in forward.get(cur, set()):
            if callee not in visited:
                visited[callee] = (depth + 1, cur)
                q.append((callee, depth + 1))

    # Check if any visited function has CFU
    for addr, (call_depth, parent) in visited.items():
        name, end = kgsl_funcs[addr]
        insns = disasm_func(addr, end)
        for insn in insns:
            if insn.mnemonic == "bl":
                target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if target == cfu_addr:
                    if entry not in entry_to_cfu:
                        entry_to_cfu[entry] = []
                    entry_to_cfu[entry].append((addr, call_depth, name, end))

print(f"\n  CFU reachable from ioctl dispatch ({len(entry_to_cfu)} entry points):")
for entry, cfus in sorted(entry_to_cfu.items(), key=lambda x: -len(x[1])):
    ename = kgsl_funcs[entry][0]
    print(f"\n    {ename} calls {len(cfus)} CFU-containing functions:")
    for cfu_addr, call_depth, cfu_name, cfu_end in cfus:
        frame, fp = extract_frame(disasm_func(cfu_addr, cfu_end))
        calls = []
        insns_cfu = disasm_func(cfu_addr, cfu_end)
        for i, insn in enumerate(insns_cfu):
            if insn.mnemonic == "bl":
                t = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if t == cfu_addr:
                    # Find dest and size
                    dest_sp = None
                    for j in range(i - 1, max(0, i - 30), -1):
                        p = insns_cfu[j]
                        if p.mnemonic == "add" and p.op_str.startswith("x0, sp"):
                            parts = p.op_str.split("#")
                            if len(parts) > 1:
                                dest_sp = parse_imm(parts[-1].rstrip("]"))
                            break
                        elif p.mnemonic == "sub" and p.op_str.startswith("x0, x29"):
                            parts = p.op_str.split("#")
                            if len(parts) > 1:
                                dest_sp = fp - parse_imm(parts[-1].split(",")[0].rstrip("]"))
                            break
                        elif p.mnemonic == "mov" and p.op_str == "x0, sp":
                            dest_sp = 0
                            break
                    copy_sz = None
                    for j in range(i - 1, max(0, i - 15), -1):
                        p = insns_cfu[j]
                        if p.mnemonic == "mov" and "#" in p.op_str and ("w2, #" in p.op_str or "x2, #" in p.op_str):
                            copy_sz = parse_imm(p.op_str.split("#")[-1])
                            break
                    calls.append((insn.address, dest_sp, copy_sz or 0))

        call_depth_info = f" (call_depth={call_depth})" if call_depth > 0 else ""
        print(f"      {cfu_name}{call_depth_info}")
        print(f"        frame=0x{frame:04x} fp=0x{fp:04x}")
        for ca, ds, cs in calls:
            ds_str = f"SP+0x{ds:04x}" if ds is not None else "UNKNOWN"
            print(f"        CFU @{fmt_addr(ca)}: dest={ds_str} size={cs}")

# ============================================================
# 3. Compute actual caller depth for kgsl sub-handlers
# ============================================================

print()
print("=" * 100)
print("  PHASE 3: Caller depth computation for kgsl sub-handlers")
print("=" * 100)

# Key functions in the call path
path_segments = [
    ("__arm64_sys_ioctl", "__arm64_sys_ioctl"),
    ("ksys_ioctl", "ksys_ioctl"),
    ("vfs_ioctl", "vfs_ioctl"),
    ("kgsl_ioctl", "kgsl_ioctl"),
    ("kgsl_ioctl_helper", "kgsl_ioctl_helper"),
]

depth_info = {}
total_depth = 0
print(f"  Call path from syscall to kgsl sub-handler:")
for label, sym in path_segments:
    addr = sym_by_name.get(sym)
    if not addr:
        print(f"    ??? {sym} not found")
        continue
    info = find_func(addr)
    if not info:
        continue
    frame, _ = extract_frame(disasm_func(addr, info[1]))
    depth_info[sym] = {"addr": addr, "frame": frame, "end": info[1]}
    total_depth += frame
    print(f"    {label:30s} @{fmt_addr(addr)} frame=0x{frame:04x}")

# For each entry point dispatch, compute total depth
print(f"\n  Base ioctl depth to kgsl_ioctl_helper dispatch: 0x{total_depth:04x}")

# Now compute depth for each entry point (which is a terminal function from kgsl_ioctl_helper)
for entry in sorted(entry_points, key=lambda e: kgsl_funcs[e][0]):
    ename = kgsl_funcs[entry][0]
    e_info = find_func(entry)
    if not e_info:
        continue
    e_frame, _ = extract_frame(disasm_func(entry, e_info[1]))
    handler_depth = total_depth + e_frame  # depth at the DISPATCH point (before handler runs)

    # For depth inside the handler (at its CFU call), we need: handler_depth + handler_frame
    # But the CFU is called from within the handler, so the CFU caller_depth = handler_depth
    # The CFU's dest depends on the handler's frame:
    # dest_abs = -(handler_depth) + dest_sp_offset
    # Wait, that doesn't account for the handler's own frame for the dest calculation
    # Let me think about this more carefully

    # When analyzing CFU in handler_func:
    #   caller_depth for CFU = total_depth (depth at handler entry)
    #   dest_abs = -(caller_depth + handler_frame) + dest_sp_offset
    #   = -(total_depth + handler_frame) + dest_sp_offset

    # Actually wait, the caller_depth should be the depth accumulated BEFORE entering
    # the function that has the CFU. So for kgsl_drawobj_cmd_add_ibdesc_list called from
    # kgsl_ioctl_helper:
    #
    # Path: sys(0x40) -> ksys(0x40) -> vfs(0x20) -> kgsl_ioctl(0x30) -> kih(0xD0) -> drawobj_cmd_add_ibdesc_list(0x90)
    #
    # The depth at drawobj_cmd_add_ibdesc_list entry is: 0x40 + 0x40 + 0x20 + 0x30 + 0xD0 = 0x1A0
    # Within drawobj, the frame adds 0x90, so the SP has moved down by 0x1A0 + 0x90.
    # dest_abs = -(0x1A0 + 0x90) + dest_sp_offset = -(0x230) + dest_sp_offset

    # For dest_sp = 0x28:
    # dest_abs = -0x230 + 0x28 = -0x208 = -520
    # Buffer = [-520, -504) for 16B copy
    # Waiter = [-896, -832)
    # No overlap!

    # We need to add more depth. The compat ioctl path or additional nesting could help.

    # Actually, let me reconsider. The actual path might include more functions:
    # - Security hooks (selinux_*)
    # - Lockdep
    # - ftrace/tracing
    # These add significant depth.

    print(f"\n    {ename}:")
    print(f"      handler frame = 0x{e_frame:04x}")

    # Find CFU sites in this handler
    insns = disasm_func(entry, e_info[1])
    has_cfu = False
    for i, insn in enumerate(insns):
        if insn.mnemonic == "bl":
            target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            if target == cfu_addr:
                # Find dest and size
                fp = e_frame  # approximate
                dest_sp = None
                copy_sz = 0

                for j in range(i - 1, max(0, i - 30), -1):
                    p = insns[j]
                    if p.mnemonic == "add" and p.op_str.startswith("x0, sp"):
                        parts = p.op_str.split("#")
                        if len(parts) > 1:
                            dest_sp = parse_imm(parts[-1].rstrip("]"))
                        break
                    elif p.mnemonic == "sub" and p.op_str.startswith("x0, x29"):
                        parts = p.op_str.split("#")
                        if len(parts) > 1:
                            val = parse_imm(parts[-1].split(",")[0].rstrip("]"))
                            if val is not None:
                                dest_sp = fp - val
                        break
                    elif p.mnemonic == "mov" and p.op_str == "x0, sp":
                        dest_sp = 0
                        break

                for j in range(i - 1, max(0, i - 15), -1):
                    p = insns[j]
                    if p.mnemonic == "mov" and ("w2, #" in p.op_str or "x2, #" in p.op_str):
                        copy_sz = parse_imm(p.op_str.split("#")[-1]) or 0
                        break

                if dest_sp is not None and copy_sz > 0:
                    has_cfu = True
                    dest_abs = -(total_depth + e_frame) + dest_sp
                    buf_end = dest_abs + copy_sz

                    o_start = max(dest_abs, WAITER_START)
                    o_end = min(buf_end, WAITER_END)
                    overlap = max(0, o_end - o_start)

                    print(f"      CFU @{fmt_addr(insn.address)}:")
                    print(f"        dest=SP+0x{dest_sp:04x} size={copy_sz}")
                    print(f"        dest_abs={dest_abs:+d} buf_end={buf_end:+d}")
                    print(f"        overlap @ actual depth: {overlap}B")

                    # What depth would give best overlap?
                    best_ov = 0
                    best_d = 0
                    for d in range(0, 0x401):
                        abs_start = -(d + e_frame) + dest_sp
                        o = max(0, min(abs_start + copy_sz, WAITER_END) - max(abs_start, WAITER_START))
                        if o > best_ov:
                            best_ov = o
                            best_d = d

                    depth_gap = best_d - total_depth
                    if best_ov > 0:
                        print(f"        best overlap: {best_ov}B at caller_depth=0x{best_d:04x}")
                        print(f"        depth gap from actual: {depth_gap:+d} (need {'+' if depth_gap > 0 else ''}0x{abs(depth_gap):04x})")

                        # Coverage at different adjusted depths
                        if overlap > 0:
                            waiter_off_start = o_start - WAITER_START
                            waiter_off_end = o_end - WAITER_START
                            print(f"        actual: waiter offset [{waiter_off_start:#04x}, {waiter_off_end:#04x})")

                        if best_ov > 0:
                            b_abs = -(best_d + e_frame) + dest_sp
                            b_os = max(b_abs, WAITER_START) - WAITER_START
                            b_oe = min(b_abs + copy_sz, WAITER_END) - WAITER_START
                            print(f"        best:   waiter offset [{b_os:#04x}, {b_oe:#04x})")
                elif dest_sp is not None:
                    has_cfu = True
                    print(f"      CFU @{fmt_addr(insn.address)}:")
                    print(f"        dest=SP+0x{dest_sp:04x} size=REGISTER-BASED (unknown)")
                    print(f"        dest_abs at actual depth = {-(total_depth + e_frame) + dest_sp:+d}")
                else:
                    print(f"      CFU @{fmt_addr(insn.address)}: unknown dest")

    if not has_cfu:
        print(f"      (no CFU calls in this function, but may call sub-functions with CFU)")

# ============================================================
# 4. Check if compat ioctl path has different depth
# ============================================================

print()
print("=" * 100)
print("  PHASE 4: Compat ioctl path depth")
print("=" * 100)

compat_path = [
    ("__arm64_compat_sys_ioctl", "__arm64_compat_sys_ioctl"),
    ("compat_ioctl", "compat_SyS_ioctl"),  # may not exist
    ("kgsl_compat_ioctl", "kgsl_compat_ioctl"),
]

for label, sym in compat_path:
    addr = sym_by_name.get(sym)
    if addr:
        info = find_func(addr)
        if info:
            frame, _ = extract_frame(disasm_func(addr, info[1]))
            print(f"    {label:30s} @{fmt_addr(addr)} frame=0x{frame:04x}")
        else:
            print(f"    {label:30s} @{fmt_addr(addr)} (no func info)")
    else:
        print(f"    {label:30s} NOT FOUND")

# Check kgsl_compat_ioctl dispatch
kci_addr = sym_by_name.get("kgsl_compat_ioctl")
if kci_addr:
    kci_info = find_func(kci_addr)
    if kci_info:
        kci_insns = disasm_func(kci_addr, kci_info[1])
        kci_frame, _ = extract_frame(kci_insns)
        print(f"\n  kgsl_compat_ioctl frame=0x{kci_frame:04x}")
        # Find what it calls
        compat_targets = set()
        for insn in kci_insns:
            if insn.mnemonic == "bl":
                target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                t_info = find_func(target)
                if t_info and "kgsl" in t_info[2] and "_compat" in t_info[2]:
                    t_frame, _ = extract_frame(disasm_func(target, t_info[1]))
                    compat_targets.add((t_info[2], t_frame))

        for name, f in sorted(compat_targets):
            print(f"    -> {name:45s} frame=0x{f:04x}")

# ============================================================
# 5. Summary
# ============================================================

print()
print("=" * 100)
print("  EXPLOITATION FEASIBILITY SUMMARY")
print("=" * 100)

print("""
  The key challenge for kgsl-based GhostLock is achieving sufficient
  call depth such that the copy_from_user destination buffer overlaps
  the waiter at [-896, -832).

  Standard ioctl path depth (syscall -> kgsl sub-handler): ~0x1A0-0x220

  The waiter is deep in the stack; kgsl buffers are typically at
  SP+0x00 to SP+0x38 offsets within their frame. For partial overlap,
  we need an ADDITIONAL ~0xC0-0x160 bytes of caller depth beyond the
  standard ioctl path.

  The buffer that comes closest: kgsl_drawobj_cmd_add_ibdesc_list
  (16 bytes at SP+0x28) can cover the task+lock fields at depth 0x2E8,
  which is 0xC8 more than the standard path.

  OPTIONS FOR ACHIEVING EXTRA DEPTH:
  1. Nested ioctl calls (ioctl within ioctl)
  2. Compat ioctl path (may have different frame sizes)
  3. The vfs_ioctl -> security hooks path
  4. Use of synchronous ioctls that block and unwind

  However, NONE of the current kgsl CFU buffers have copy sizes >= 64
  with the right positioning to cover the ENTIRE waiter. The partial
  overlaps only cover specific fields.

  RECOMMENDATION:
  - kgsl_drawobj_cmd_add_ibdesc_list is the most promising (16B copy
    at SP+0x28 can cover waiter task+lock at depth 0x2E8)
  - The struct size being copied (struct kgsl_ibdesc = 16 bytes) limits
    coverage to exactly 2 waiter fields (task and lock)
  - Additional call depth of ~0xC8 is needed from the standard ioctl
    path depth of ~0x220
""")
