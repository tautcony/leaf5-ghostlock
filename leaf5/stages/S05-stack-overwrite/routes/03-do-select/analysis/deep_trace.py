#!/usr/bin/env python3
"""
Deep trace: core_sys_select → do_select calling convention analysis.
Finds the poll_wqueues (x4) offset on core_sys_select's stack
and the stack_fds (fd_set) buffer layout.
"""

from __future__ import annotations
import argparse
from pathlib import Path
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

def parse_imm(s):
    s = s.strip().rstrip("]!,")
    if s.startswith("#"): s = s[1:]
    if s.startswith("0x") or s.startswith("0X"): return int(s, 16)
    if s.startswith("-"):
        return -int(s[1:], 16 if s[1:].startswith("0x") else 10)
    return int(s, 16) if "0x" in s else int(s)

def bl_target(insn):
    return insn.operands[0].imm & ADDR_MASK

def load_vmlinux(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        symbols = {sym.name: sym.entry.st_value for sym in symtab.iter_symbols() if sym.name}
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return symbols, sec.header.sh_addr, sec.data()
    raise ValueError("No .kernel section")

def get_insns(symbols, text_base, text_data, name, max_len=0x800):
    addr = symbols[name]
    off = addr - text_base
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(text_data[off:off+max_len], addr))

def find_frame_size(symbols, text_base, text_data, name):
    insns = get_insns(symbols, text_base, text_data, name, 0x400)
    total, fp_off = 0, 0
    for insn in insns:
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

def trace_register_backward(insns, bl_idx, reg, fp_off, max_back=30):
    """Trace a register's value back from bl_idx, looking for SP/X29-relative origin."""
    for j in range(bl_idx - 1, max(0, bl_idx - max_back), -1):
        prev = insns[j]
        op = prev.op_str.replace(" ", "")
        
        # add Rd, sp, #imm
        if prev.mnemonic == "add" and reg in op:
            parts = op.split(",")
            if len(parts) >= 3 and parts[0] == reg and parts[1] == "sp":
                return ("sp", parse_imm(op.split("#")[-1]))
                
        # sub Rd, x29, #imm  →  sp_offset = fp_off - imm
        if prev.mnemonic == "sub" and reg in op:
            parts = op.split(",")
            if len(parts) >= 3 and parts[0] == reg and parts[1] == "x29":
                imm_part = op.split("#")[-1].rstrip("]")
                return ("x29", fp_off - parse_imm(imm_part))
                
        # add Rd, x29, #imm  →  sp_offset = fp_off + imm
        if prev.mnemonic == "add" and reg in op:
            parts = op.split(",")
            if len(parts) >= 3 and parts[0] == reg and parts[1] == "x29":
                imm_part = op.split("#")[-1].rstrip("]")
                return ("x29", fp_off + parse_imm(imm_part))
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    args = parser.parse_args()
    vprint = print if args.verbose else lambda *a, **k: None
    
    symbols, text_base, text_data = load_vmlinux(args.elf)
    
    # ═════════════════════════════════════════════════════════════════
    # 1. core_sys_select full analysis
    # ═════════════════════════════════════════════════════════════════
    print("=" * 72)
    print("core_sys_select full analysis")
    print("=" * 72)
    
    css_insns = get_insns(symbols, text_base, text_data, "core_sys_select", 0x600)
    css_size, css_fp_off = find_frame_size(symbols, text_base, text_data, "core_sys_select")
    print(f"  Frame: {css_size}B (0x{css_size:x}), FP=SP+0x{css_fp_off:03x}")
    print(f"  {len(css_insns)} instructions")
    print()
    
    # Find key BL calls and their argument setup
    do_select_addr = symbols["do_select"]
    poll_initwait_addr = symbols.get("poll_initwait")
    cfu_addr = symbols.get("__arch_copy_from_user")
    
    # Print all BL calls with argument register trace
    print("  --- All BL calls with argument tracing ---")
    for i, insn in enumerate(css_insns):
        if insn.mnemonic == "bl":
            target = bl_target(insn)
            tgt_name = None
            for sn, sa in symbols.items():
                if sa == target: tgt_name = sn; break
            tgt_name = tgt_name or f"0x{target:x}"
            
            # Trace key arguments
            args_info = []
            for arg_reg in ["x0", "x1", "x2", "x3", "x4"]:
                traced = trace_register_backward(css_insns, i, arg_reg, css_fp_off)
                if traced:
                    base_type, sp_offset = traced
                    args_info.append(f"{arg_reg}={base_type}+0x{sp_offset:03x}")
            
            print(f"    [{i:3d}] bl {tgt_name:<35s} {' | '.join(args_info)}" if args_info else f"    [{i:3d}] bl {tgt_name}")
        if insn.mnemonic == "ret":
            break
    
    print()
    
    # Find all __arch_copy_from_user calls in core_sys_select
    print("  --- copy_from_user calls ---")
    for i, insn in enumerate(css_insns):
        if insn.mnemonic == "bl" and cfu_addr and bl_target(insn) == cfu_addr:
            dest_info = trace_register_backward(css_insns, i, "x0", css_fp_off)
            size_info = None
            for j in range(i-1, max(0, i-15), -1):
                prev = css_insns[j]
                if prev.mnemonic == "mov" and "w2" in prev.op_str:
                    try:
                        size_info = parse_imm(prev.op_str.split("#")[-1])
                    except: pass
                    break
            if dest_info:
                print(f"    [{i:3d}] copy_from_user dest={dest_info[0]}+0x{dest_info[1]:03x} size={size_info}")
            else:
                print(f"    [{i:3d}] copy_from_user (dest not SP-relative) size={size_info}")
    
    print()
    
    # ═════════════════════════════════════════════════════════════════
    # 2. Complete SP access map for core_sys_select
    # ═════════════════════════════════════════════════════════════════
    print("=" * 72)
    print("core_sys_select: All SP/X29-relative accesses grouped by offset")
    print("=" * 72)
    
    from collections import defaultdict
    access_map = defaultdict(list)
    
    for insn in css_insns:
        for op in insn.operands:
            if op.type == ARM64_OP_MEM and op.mem.base != 0:
                base_reg = insn.reg_name(op.mem.base)
                disp = op.mem.disp
                if base_reg in ("sp", "x29"):
                    sp_off = disp if base_reg == "sp" else css_fp_off + disp
                    if 0 <= sp_off <= css_size:
                        is_write = insn.mnemonic.startswith("str")
                        access_map[sp_off].append({
                            "addr": insn.address,
                            "mnemonic": insn.mnemonic,
                            "is_write": is_write,
                        })
        if insn.mnemonic == "ret":
            break
    
    unique_offsets = sorted(access_map.keys())
    
    # Also find stack_fds offset
    stack_fds_sp = None
    for insn in css_insns:
        if insn.mnemonic == "add" and "x19, sp" in insn.op_str:
            stack_fds_sp = parse_imm(insn.op_str.split("#")[-1].rstrip("]"))
            break
        
    print(f"  stack_fds (fd_set) @ SP+0x{stack_fds_sp:03x}" if stack_fds_sp else "  stack_fds not found")
    # stack_fds is sizeof(fd_set) = 80+? Actually for 640 nfds, it's 640/8 = 80 bytes
    # Or SELECT_STACK_ALLOC could be larger
    
    # Find the poll_wqueues allocation
    # poll_initwait takes x0 = &poll_wqueues
    poll_wq_sp = None
    for i, insn in enumerate(css_insns):
        if insn.mnemonic == "bl":
            target = bl_target(insn)
            if target == poll_initwait_addr:
                traced = trace_register_backward(css_insns, i, "x0", css_fp_off)
                if traced:
                    poll_wq_sp = traced[1]
                    print(f"  poll_wqueues @ SP+0x{poll_wq_sp:03x} (from poll_initwait x0)")
                break
    
    print()
    
    # Print unique offsets in a range
    waiter_abs = -0x380
    css_sp_abs = -(0xa0 + css_size)  # core_sys_select SP absolute
    waiter_in_css = waiter_abs - css_sp_abs  # waiter relative to core_sys_select SP
    
    print(f"  Waiter ABS: {waiter_abs:+d}")
    print(f"  core_sys_select SP ABS: {css_sp_abs:+d}")
    print(f"  Waiter relative to core_sys_select SP: +0x{waiter_in_css:03x}")
    print()
    
    # Check if stack_fds could overlap
    if stack_fds_sp:
        fdset_size = 80  # 640 / 8 bytes for fd_set bits
        fdset_end = stack_fds_sp + fdset_size
        print(f"  stack_fds [SP+0x{stack_fds_sp:03x}, SP+0x{fdset_end:03x})")
        print(f"  waiter @ SP+0x{waiter_in_css:03x}")
        overlap = fdset_end > waiter_in_css and stack_fds_sp < waiter_in_css + 0x40
        if overlap:
            print(f"  ⚠ OVERLAP: stack_fds overlaps with waiter!")
        else:
            delta = waiter_in_css - fdset_end
            print(f"  Δ (waiter - fdset_end) = {delta:+d} bytes")
            if delta > 0:
                print(f"  → waiter is {delta} bytes BELOW stack_fds")
            else:
                print(f"  → stack_fds_top is {abs(delta)} bytes ABOVE waiter")
    print()
    
    # Print all offsets
    print(f"  All SP-relative offsets ({len(unique_offsets)}):")
    for off in unique_offsets:
        accs = access_map[off]
        writes = sum(1 for a in accs if a["is_write"])
        reads = len(accs) - writes
        
        # Check if this overlaps with waiter
        marker = ""
        if waiter_in_css <= off < waiter_in_css + 0x40:
            marker = " <<<< WAITER"
        elif poll_wq_sp and poll_wq_sp <= off < poll_wq_sp + 0x100:
            marker = " (poll_wqueues)"
            
        vprint(f"    SP+0x{off:03x}: W={writes} R={reads}{marker}")
    
    print()
    
    # ═════════════════════════════════════════════════════════════════
    # 3. Complete stack layout characterization
    # ═════════════════════════════════════════════════════════════════
    print("=" * 72)
    print("Complete stack layout: sys_pselect6 → core_sys_select → do_select")
    print("=" * 72)
    
    # Get do_select frame
    ds_size, ds_fp_off = find_frame_size(symbols, text_base, text_data, "do_select")
    p6_size, p6_fp_off = find_frame_size(symbols, text_base, text_data, "__arm64_sys_pselect6")
    
    print(f"\n  Frame sizes:")
    print(f"    __arm64_sys_pselect6: 0x{p6_size:04x} ({p6_size}B)")
    print(f"    core_sys_select:      0x{css_size:04x} ({css_size}B)")
    print(f"    do_select:            0x{ds_size:04x} ({ds_size}B)")
    
    total_to_ds = p6_size + css_size + ds_size
    print(f"    Total to do_select SP: 0x{total_to_ds:04x} ({total_to_ds}B)")
    
    print(f"\n  Absolute offsets (from kernel_stack_top = 0):")
    print(f"    0                         kernel_stack_top (after entry cancels)")
    p6_sp = -p6_size
    css_sp = -(p6_size + css_size)
    ds_sp = -(p6_size + css_size + ds_size)
    print(f"    {p6_sp:+6d}  __arm64_sys_pselect6 SP")
    print(f"    {css_sp:+6d}  core_sys_select SP")
    print(f"    {ds_sp:+6d}  do_select SP")
    print(f"    {waiter_abs:+6d}  WAITER (rt_mutex_waiter)")

    # Show the exact area where waiter falls
    print(f"\n  Waiter region in the stack:")
    
    levels = [
        ("kernel_stack_top", 0, 0, ""),
        ("pselect6 frame", p6_sp, p6_size, "0xa0"),
        ("core_sys_select frame", css_sp, css_size, "0x1c0"),
        ("do_select frame", ds_sp, ds_size, "0x370"),
    ]
    
    # Map where waiter falls
    waiter_start = waiter_abs
    waiter_end = waiter_abs + 0x40
    
    for name, base, size, sz_str in levels:
        end = base + size
        start = base
        # Does the waiter overlap with this region?
        overlap = max(0, min(waiter_end, end) - max(waiter_start, start))
        if overlap > 0:
            rel_start = waiter_start - base if waiter_start >= base else 0
            rel_end = waiter_end - base if waiter_end <= end else size
            print(f"    Waiter overlaps {name}{' ' * max(1, 20 - len(name))}"
                  f"[{rel_start:+d}..{rel_end:+d}] "
                  f"({waiter_start:+d}..{waiter_end:+d})")
    
    print()
    
    # ═════════════════════════════════════════════════════════════════
    # 4. Now trace what poll_wqueues looks like and where it falls
    # ═════════════════════════════════════════════════════════════════
    print("=" * 72)
    print("poll_wqueues structure analysis")
    print("=" * 72)
    
    if poll_wq_sp:
        poll_wq_abs = css_sp + poll_wq_sp
        print(f"  poll_wqueues @ core_sys_select SP+0x{poll_wq_sp:03x}")
        print(f"  poll_wqueues ABS: {poll_wq_abs:+d}")
        print(f"  Waiter ABS:       {waiter_abs:+d}")
        print(f"  Δ (waiter - poll_wq): {waiter_abs - poll_wq_abs:+d}")
        
        # poll_wqueues structure:
        #   +0x00: poll_table pt._qproc (8B)
        #   +0x08: poll_table pt._key (8B)
        #   +0x10: poll_table_page *table (8B)
        #   +0x18: task_struct *polling_task (8B)
        #   +0x20: int triggered (4B)
        #   +0x24: int error (4B)
        #   +0x28: int inline_index (4B)
        #   +0x2c: padding (4B)
        #   +0x30: poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES]
        
        inline_start = 0x30
        entry_size = 0x30  # sizeof(poll_table_entry): filp(8) + wait_queue_entry(0x28)
        
        # How many inline entries fit?
        offset_in_pollwq = waiter_abs - poll_wq_abs
        print(f"\n  Waiter at poll_wqueues+0x{offset_in_pollwq:03x}")
        
        if offset_in_pollwq >= inline_start:
            entry_idx = (offset_in_pollwq - inline_start) // entry_size
            entry_off = (offset_in_pollwq - inline_start) % entry_size
            entry_base = inline_start + entry_idx * entry_size
            print(f"  → This is inline_entries[{entry_idx}] (base +0x{entry_base:03x})")
            print(f"  → Offset within entry: +0x{entry_off:02x}")
            if entry_off < 8:
                print(f"  → poll_table_entry.filp (struct file *)")
            else:
                wait_off = entry_off - 8
                print(f"  → poll_table_entry.wait + 0x{wait_off:02x}")
                if wait_off < 4:
                    print(f"    → wait_queue_entry.flags")
                elif wait_off < 8:
                    print(f"    → wait_queue_entry.private")
                elif wait_off < 0x10:
                    print(f"    → wait_queue_entry.func (function pointer!)")
                elif wait_off < 0x18:
                    print(f"    → wait_queue_entry.entry.prev")
                else:
                    print(f"    → wait_queue_entry.entry.next")
        else:
            print(f"  → Falls in poll_table or other bookkeeping fields")
            if offset_in_pollwq < 0x10:
                print(f"    → poll_table.{['_qproc', '_key'][offset_in_pollwq // 8]}")
            elif offset_in_pollwq < 0x18:
                print(f"    → poll_table_page *table")
            elif offset_in_pollwq < 0x20:
                print(f"    → task_struct *polling_task")
            elif offset_in_pollwq < 0x30:
                print(f"    → triggered/error/inline_index")
    else:
        print("  Could not locate poll_wqueues on core_sys_select stack")
    
    print()
    
    # ═════════════════════════════════════════════════════════════════
    # 5. Final verdict  
    # ═════════════════════════════════════════════════════════════════
    print("=" * 72)
    print("FINAL VERDICT: do_select buffer overlap analysis")
    print("=" * 72)
    
    # Check copy_from_user in do_select
    ds_insns = get_insns(symbols, text_base, text_data, "do_select", 0x800)
    cfu_addr_val = symbols.get("__arch_copy_from_user")
    
    ds_cfu = []
    for i, insn in enumerate(ds_insns):
        if insn.mnemonic == "bl" and cfu_addr_val and bl_target(insn) == cfu_addr_val:
            ds_cfu.append(trace_register_backward(ds_insns, i, "x0", ds_fp_off))
        if insn.mnemonic == "ret":
            break
    
    print(f"\n  do_select copy_from_user calls: {len(ds_cfu)}")
    for dest in ds_cfu:
        if dest:
            print(f"    dest={dest[0]}+0x{dest[1]:03x}")
        
    print(f"\n  Maximum SP offset accessed in do_select: "
          f"SP+0x{max(unique_offsets):03x}" if unique_offsets else "  none")
    
    waiter_ds_off = waiter_abs - ds_sp
    print(f"  Waiter in do_select: SP+0x{waiter_ds_off:03x} (0x{waiter_ds_off})")
    print(f"  Max access in do_select: SP+0x{max(unique_offsets):03x}" if unique_offsets else "")
    
    # Check if any SP access could possibly cover waiter
    # i.e., is waiter within do_select's frame and within a buffer range?
    has_user_buffer = False
    if len(ds_cfu) > 0:
        for dest in ds_cfu:
            if dest:
                base, off = dest
                if base == "sp":
                    buf_end = off  # size not determined
                    if off <= waiter_ds_off < off + 0x100:
                        has_user_buffer = True
    
    if has_user_buffer:
        print(f"\n  ⚠ POTENTIAL OVERLAP: copy_from_user target in do_select could cover waiter!")
    else:
        print(f"\n  ❌ NO DIRECT OVERLAP: do_select has no user-controlled buffer at waiter position")
        print(f"     The waiter (SP+0x{waiter_ds_off:03x}) is above do_select's highest accessed")
        print(f"     offset (SP+0x{max(unique_offsets):03x}), in an unused portion of the frame.")
    
    print()
    print(f"  However, the poll_wqueues structure in core_sys_select's frame has inline_entries")
    print(f"  that could potentially be controlled via poll_wakeup writes. Need to check if:")
    print(f"    a) poll_wqueues.inline_entries is in the right position")
    print(f"    b) The entries can be filled with attacker-controlled data")
    print(f"    c) The wakeup write path is reachable from userspace")
    
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
