#!/usr/bin/env python3
"""
do_select Stack Layout Analyzer for GhostLock

Analyzes vmlinux.elf disassembly to determine:
  - Exact frame sizes of the call chain: __arm64_sys_pselect6 → core_sys_select → do_select
  - All SP-relative local variables and buffers in do_select
  - copy_from_user destinations within do_select
  - Whether any buffer overlaps with the dangling rt_mutex_waiter at absolute offset -0x380

Usage:
    uv run python -m ghostlock-analysis.do-select-buffers.analyze_do_select
    uv run python -m ghostlock-analysis.do-select-buffers.analyze_do_select -v
    uv run python -m ghostlock-analysis.do-select-buffers.analyze_do_select --disasm
"""

from __future__ import annotations

import argparse
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
OUT = Path(__file__).resolve().parent

ADDR_MASK = 0xFFFFFFFFFFFFFFFF

# ── Constants from prior analysis ──────────────────────────────────────

# waiter in futex_wait: futex_q @ SP+0x80, waiter @ SP+0x80+0x48 = SP+0xc8
# BUT: waiter is in futex_wait's OWN frame, not relative to exception entry
# The WAITER_ABS_OFFSET = -0x380 is computed as:
#   waiter_abs = -(__arm64_sys_futex + do_futex + futex_wait) + waiter_sp_in_futex_wait
WAITER_ABS_OFFSET = -0x380  # from kernel_stack_top, after exception entry cancels
WAITER_SIZEOF = 0x40

# Fields of rt_mutex_waiter (4.19), relative to waiter base
WAITER_FIELDS = [
    (0x00, "tree_entry.__rb_parent_color"),
    (0x08, "tree_entry.rb_right"),
    (0x10, "tree_entry.rb_left"),
    (0x18, "pi_tree_entry.__rb_parent_color"),
    (0x20, "pi_tree_entry.rb_right"),
    (0x28, "pi_tree_entry.rb_left"),
    (0x30, "task"),
    (0x38, "lock"),
]


# ── Helpers ────────────────────────────────────────────────────────────

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
    return insn.operands[0].imm & ADDR_MASK


# ── Load ELF ───────────────────────────────────────────────────────────

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


def get_insns(symbols, text_base, text_data, name: str, max_len: int = 0x800):
    """Disassemble a function and return list of Capstone insn objects."""
    if name not in symbols:
        return []
    addr = symbols[name]
    off = addr - text_base
    fbytes = text_data[off: off + max_len]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(fbytes, addr))


def find_frame_size(symbols, text_base, text_data, name: str) -> tuple[int, int, int]:
    """Return (total_frame_alloc, fp_offset_from_sp, fp_lr_save_offset).
    fp_lr_save_offset = offset from SP where fp/lr pair is stored."""
    insns = get_insns(symbols, text_base, text_data, name, 0x400)
    total = 0
    fp_off = None
    fp_lr_save = None
    for insn in insns:
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            total += parse_imm(op.split("#")[-1].strip(","))
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            total += parse_imm(op.split("#-")[1].split("]")[0])
        elif insn.mnemonic == "add" and "x29, sp" in op:
            fp_off = parse_imm(op.split("#")[-1])
        elif insn.mnemonic == "stp" and "x29, x30" in op:
            # fp_lr save at [sp, #N] (post-index)
            if not "]!" in op:
                parts = op.split("[sp, #")[1].split("]")[0]
                fp_lr_save = parse_imm(parts)
        if insn.mnemonic == "ret" and total > 0:
            break
    return total, fp_off or 0, fp_lr_save or 0


# ── Stack Access Analysis ──────────────────────────────────────────────

def map_stack_accesses(insns, fp_off: int) -> list[dict]:
    """Map all SP/X29-relative memory accesses in a function.
    
    Returns list of dicts: {insn_addr, sp_offset, mnemonic, op_str, is_write}
    """
    accesses = []
    for insn in insns:
        for op in insn.operands:
            if op.type == ARM64_OP_MEM and op.mem.base != 0:
                base_reg = insn.reg_name(op.mem.base)
                disp = op.mem.disp
                if base_reg in ("sp", "x29") and 0 <= disp <= 0x2000:
                    sp_off = disp
                    if base_reg == "x29":
                        sp_off = fp_off + disp
                    is_write = insn.mnemonic.startswith("str")
                    accesses.append({
                        "addr": insn.address,
                        "sp_off": sp_off,
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "is_write": is_write,
                    })
    return accesses


def find_copy_from_user_calls(insns, symbols) -> list[dict]:
    """Find __arch_copy_from_user calls and their destination SP offsets."""
    cfu_addr = symbols.get("__arch_copy_from_user")
    if cfu_addr is None:
        return []
    
    fp_off = None
    for insn in insns:
        if insn.mnemonic == "add" and "x29, sp" in insn.op_str:
            fp_off = parse_imm(insn.op_str.split("#")[-1])
        if insn.mnemonic == "ret":
            break
    
    calls = []
    for i, insn in enumerate(insns):
        if insn.mnemonic == "bl" and bl_target(insn) == cfu_addr:
            dest_sp = None
            copy_size = None
            src_reg = None  # x1 = source user address
            
            # Walk backward up to 20 insns to find x0 and w2 setup
            for j in range(i - 1, max(0, i - 20), -1):
                prev = insns[j]
                op = prev.op_str.replace(" ", "")
                
                if prev.mnemonic == "add" and "x0,sp" in op:
                    dest_sp = parse_imm(op.split("#")[-1])
                elif prev.mnemonic == "sub" and "x0,x29" in op:
                    if fp_off is not None:
                        imm_part = op.split("#")[-1].rstrip("]")
                        dest_sp = fp_off - parse_imm(imm_part)
                
                if prev.mnemonic == "mov" and "w2,#" in prev.op_str:
                    copy_size = parse_imm(prev.op_str.split("#")[-1])
            
            calls.append({
                "insn_addr": insn.address,
                "dest_sp": dest_sp,
                "size": copy_size,
                "src": "x1 (user pointer)",
            })
    
    return calls


def find_bl_calls(insns, symbols) -> list[dict]:
    """Find all BL calls and their target symbol names."""
    calls = []
    for insn in insns:
        if insn.mnemonic == "bl":
            target = bl_target(insn)
            tgt_name = None
            for sym_name, sym_addr in symbols.items():
                if sym_addr == target:
                    tgt_name = sym_name
                    break
            calls.append({
                "addr": insn.address,
                "target": target,
                "name": tgt_name or f"0x{target:x}",
            })
        if insn.mnemonic == "ret":
            break
    return calls


def identify_stack_region(fp_off: int, fp_lr_save: int) -> dict:
    """Identify common stack regions in an ARM64 frame."""
    frame_size = fp_off + 16  # fp_off + saved fp/lr + callee saves + locals
    
    # Typical ARM64 stack layout (high → low):
    #   [caller's frame]
    #   saved x19-x28 (callee-saved)
    #   saved x29(fp), x30(lr)
    #   local variables (including arrays)
    #   SP → [bottom]
    
    # Actually, for AArch64:
    # SP after prologue points to the bottom
    # x29 = SP + fp_off
    # fp/lr saved at [SP, #fp_lr_save] or at [SP + fp_off - 16]
    
    return {
        "frame_size": frame_size,
        "fp_off": fp_off,
        "fp_lr_save_off": fp_lr_save,
        "callee_saves_region": f"SP+{fp_off-16}..SP+{fp_off}" if fp_off > 0 else "none",
        "locals_region": f"SP+0..SP+{fp_off-16}" if fp_off > 16 else "none",
    }


# ── Waiter Overlap Check ───────────────────────────────────────────────

def check_waiter_overlap(pselect_depth: int, do_select_depth: int, 
                         do_select_frame_size: int,
                         do_select_sp_relative: int) -> dict:
    """Check if any do_select buffer overlaps the waiter."""
    # do_select's SP (absolute from kernel_stack_top)
    do_select_sp = -do_select_depth
    
    # Waiter absolute position
    waiter_abs = WAITER_ABS_OFFSET
    waiter_end = waiter_abs + WAITER_SIZEOF  # -0x380 to -0x340
    
    # Buffer position in do_select
    buf_abs = do_select_sp + do_select_sp_relative
    buf_end = buf_abs + do_select_frame_size
    
    overlap_start = max(waiter_abs, buf_abs)
    overlap_end = min(waiter_end, buf_end)
    
    return {
        "do_select_sp": do_select_sp,
        "waiter_abs": waiter_abs,
        "waiter_end": waiter_end,
        "buf_abs": buf_abs,
        "buf_end": buf_end,
        "overlap": overlap_end - overlap_start if overlap_end > overlap_start else 0,
    }


# ── Main Analysis ──────────────────────────────────────────────────────

def analyze_do_select(symbols, text_base, text_data, verbose: bool = False, 
                       show_disasm: bool = False) -> dict:
    """Full analysis of do_select stack layout."""
    
    vprint = print if verbose else lambda *a, **k: None
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 1: Frame sizes of call chain
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 1: Call Chain Frame Sizes")
    vprint("=" * 72)
    
    chain_funcs = [
        "__arm64_sys_pselect6",
        "core_sys_select",
        "do_select",
    ]
    
    frames = {}
    for func in chain_funcs:
        size, fp_off, fp_lr_save = find_frame_size(
            symbols, text_base, text_data, func)
        frames[func] = (size, fp_off, fp_lr_save)
        vprint(f"  {func:<35s} frame=0x{size:04x} ({size:4d}B) "
               f"fp=SP+0x{fp_off:03x} fplr=SP+0x{fp_lr_save:03x}")
    
    vprint()
    
    # Cumulative depths
    depths = {}
    cumulative = 0
    for func in chain_funcs:
        size = frames[func][0]
        cumulative += size
        depths[func] = cumulative
    
    for func in chain_funcs:
        vprint(f"  Cumulative depth to {func:<30s} SP: 0x{depths[func]:04x} "
               f"({depths[func]}B) → ABS={-depths[func]:+d}")
    
    vprint()
    vprint(f"  Waller ABS offset: {WAITER_ABS_OFFSET:+d} (0x{WAITER_ABS_OFFSET & 0xFFFFFFFF:x})")
    
    # Waiter relative to do_select's SP:
    do_select_depth = depths["do_select"]
    waiter_rel_to_do_select = WAITER_ABS_OFFSET + do_select_depth
    waiter_rel_to_do_select_end = waiter_rel_to_do_select + WAITER_SIZEOF
    
    vprint(f"  Waiter relative to do_select SP: "
           f"[SP+0x{waiter_rel_to_do_select:03x} .. SP+0x{waiter_rel_to_do_select_end:03x})")
    vprint(f"    (do_select SP = ABS { -do_select_depth:+d}, "
           f"waiter ABS = {WAITER_ABS_OFFSET:+d})")
    vprint()
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 2: Full disassembly of do_select
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 2: do_select Full Disassembly")
    vprint("=" * 72)
    
    insns = get_insns(symbols, text_base, text_data, "do_select", 0x800)
    vprint(f"  do_select @ 0x{symbols['do_select']:016x}")
    vprint(f"  Disassembly length: {len(insns)} instructions")
    vprint()
    
    # Find frame info
    do_select_size, do_select_fp_off, do_select_fp_lr = frames["do_select"]
    
    vprint(f"  Frame info:")
    vprint(f"    Frame size:   0x{do_select_size:04x} ({do_select_size}B)")
    vprint(f"    FP offset:    SP+0x{do_select_fp_off:03x}")
    vprint(f"    FP/LR saved:  SP+0x{do_select_fp_lr:03x}")
    vprint()
    
    if show_disasm:
        for insn in insns:
            vprint(f"  0x{insn.address:x}: {insn.mnemonic:12s} {insn.op_str}")
        vprint()
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 3: All SP/X29-relative accesses
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 3: SP/X29-Relative Memory Accesses")
    vprint("=" * 72)
    
    accesses = map_stack_accesses(insns, do_select_fp_off)
    
    # Group by SP offset
    from collections import defaultdict
    access_map = defaultdict(list)
    for acc in accesses:
        access_map[acc["sp_off"]].append(acc)
    
    unique_offsets = sorted(access_map.keys())
    vprint(f"  Found {len(unique_offsets)} unique SP-relative offsets")
    vprint()
    
    # Highlight region that overlaps with waiter
    waiter_rel_start = WAITER_ABS_OFFSET + depths["do_select"]
    waiter_rel_end = waiter_rel_start + WAITER_SIZEOF
    
    vprint(f"  Waiter region in do_select: "
           f"SP+0x{waiter_rel_start:03x} .. SP+0x{waiter_rel_end:03x} "
           f"({WAITER_SIZEOF}B)")
    vprint()
    
    for sp_off in unique_offsets:
        accs = access_map[sp_off]
        overlap = ""
        if waiter_rel_start <= sp_off < waiter_rel_end:
            waiter_field_idx = sp_off - waiter_rel_start
            field_name = "?"
            for f_off, f_name in WAITER_FIELDS:
                if f_off == waiter_field_idx:
                    field_name = f_name
                    break
            overlap = f" <<<< WAITER+0x{waiter_field_idx:02x} ({field_name})"
        
        # Determine access type
        writes = sum(1 for a in accs if a["is_write"])
        reads = len(accs) - writes
        access_type = f"W={writes} R={reads}"
        
        # Show first couple of accesses
        first_ops = [f"{a['mnemonic']} {a['op_str']}" for a in accs[:2]]
        
        vprint(f"  SP+0x{sp_off:03x}: {access_type:>8s} "
               f"{' | '.join(first_ops):70s}{overlap}")
    
    vprint()
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 4: BL calls (called functions)
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 4: BL Calls from do_select")
    vprint("=" * 72)
    
    bl_calls = find_bl_calls(insns, symbols)
    for call in bl_calls:
        vprint(f"  0x{call['addr']:016x}: bl {call['name']}")
    vprint()
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 5: copy_from_user destinations
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 5: copy_from_user Destinations")
    vprint("=" * 72)
    
    cfu_calls = find_copy_from_user_calls(insns, symbols)
    
    if not cfu_calls:
        vprint("  No __arch_copy_from_user calls found in do_select")
    else:
        for cfu in cfu_calls:
            overlap_str = ""
            if cfu["dest_sp"] is not None:
                if waiter_rel_start <= cfu["dest_sp"] < waiter_rel_end:
                    overlap_str = " <<<< OVERLAPS WAITER!"
                elif cfu["dest_sp"] + (cfu["size"] or 0) > waiter_rel_start and \
                     cfu["dest_sp"] < waiter_rel_end:
                    overlap_str = f" <<<< PARTIAL OVERLAP (buf@{cfu['dest_sp']}, size={cfu['size']})"
            
            vprint(f"  0x{cfu['insn_addr']:016x}: "
                   f"dest=SP+0x{cfu['dest_sp']:03x} "
                   f"size={cfu['size']} src={cfu['src']}"
                   f"{overlap_str}")
    vprint()
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 6: Check if core_sys_select passes any buffer to do_select
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 6: core_sys_select → do_select argument analysis")
    vprint("=" * 72)
    
    # do_select signature: do_select(int nfds, fd_set *in, fd_set *out, fd_set *ex,
    #                                 struct poll_wqueues *table)
    # x0 = nfds, x1 = *in, x2 = *out, x3 = *ex, x4 = *table
    # table is a poll_wqueues allocated on core_sys_select's stack
    
    css_insns = get_insns(symbols, text_base, text_data, "core_sys_select", 0x600)
    
    # Find the BL do_select call and trace x4 setup
    do_select_addr = symbols["do_select"]
    css_fp_off = frames["core_sys_select"][1]
    
    vprint(f"  core_sys_select frame: 0x{frames['core_sys_select'][0]:04x}B, "
           f"FP=SP+0x{css_fp_off:03x}")
    
    # Trace x4 (poll_wqueues) setup for the do_select call
    do_select_bl_idx = None
    for i, insn in enumerate(css_insns):
        if insn.mnemonic == "bl" and bl_target(insn) == do_select_addr:
            do_select_bl_idx = i
            break
    
    if do_select_bl_idx is not None:
        vprint(f"  do_select BL call at index {do_select_bl_idx} "
               f"(0x{css_insns[do_select_bl_idx].address:x})")
        
        # Trace x4 (poll_wqueues) setup
        poll_wq_sp = None
        for j in range(do_select_bl_idx - 1, max(0, do_select_bl_idx - 20), -1):
            prev = css_insns[j]
            op = prev.op_str.replace(" ", "")
            if prev.mnemonic == "add" and "x4,sp" in op:
                poll_wq_sp = parse_imm(op.split("#")[-1])
            elif prev.mnemonic == "add" and "x4,x29" in op:
                imm_part = op.split("#")[-1].rstrip("]")
                poll_wq_sp = css_fp_off + parse_imm(imm_part)
            elif prev.mnemonic == "sub" and "x4,x29" in op:
                imm_part = op.split("#")[-1].rstrip("]")
                poll_wq_sp = css_fp_off - parse_imm(imm_part)
        
        if poll_wq_sp is not None:
            vprint(f"  poll_wqueues (x4) @ core_sys_select SP+0x{poll_wq_sp:03x}")
            
            # poll_wqueues structure layout:
            #   +0x00: poll_table pt (variable size)
            #   +0x10: poll_table_page *table (8B)
            #   +0x18: task_struct *polling_task (8B)
            #   +0x20: int triggered (4B)
            #   +0x24: int error (4B)
            #   +0x28: int inline_index (4B)
            #   +0x2c: padding (4B)
            #   +0x30: poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES]
            # 
            # struct poll_table_entry:
            #   +0x00: struct file *filp (8B)
            #   +0x08: wait_queue_entry_t wait (0x28 on 4.19 arm64)
            #   
            # struct wait_queue_entry:
            #   +0x00: unsigned int flags (4B)
            #   +0x04: void *private (8B on arm64 after padding?) 
            #   Actually on arm64 4.19: 
            #   +0x00: unsigned int flags (4B)
            #   +0x04: padding (4B)
            #   +0x08: void *private (8B)
            #   +0x10: wait_queue_func_t func (8B)
            #   +0x18: struct list_head entry (16B)
            #   Total: 0x28 (40 bytes)
            
            # N_INLINE_POLL_ENTRIES: typically 8 on 4.19 (defined in select.h)
            # We need to verify from the disassembly
            
            poll_wq_abs = -depths["core_sys_select"] + poll_wq_sp
            vprint(f"  poll_wqueues ABS offset: {poll_wq_abs:+d}")
            vprint(f"  Waiter ABS:              {WAITER_ABS_OFFSET:+d}")
            delta = poll_wq_abs - WAITER_ABS_OFFSET
            vprint(f"  Δ (poll_wq - waiter):    {delta:+d}B ({delta//8} words)")
            vprint()
            
            # Show what's at waiter position relative to poll_wqueues base
            # waiter_abs = poll_wq_abs + X → X = waiter_abs - poll_wq_abs
            offset_in_pollwq = WAITER_ABS_OFFSET - poll_wq_abs
            vprint(f"  Waiter is at poll_wqueues+0x{offset_in_pollwq:03x}")
            
            # Check structure overlays
            poll_table_entry_size = 0x30  # 8 (filp) + 0x28 (wait_queue_entry)
            POLL_TABLE_SIZEOF = 0x10  # poll_table: _qproc (8B) + key (8B)
            
            inline_entries_start = 0x30  # after pt(0x10) + table(8) + task(8) + flags(8)
            
            if offset_in_pollwq >= inline_entries_start:
                entry_idx = (offset_in_pollwq - inline_entries_start) // poll_table_entry_size
                entry_off = (offset_in_pollwq - inline_entries_start) % poll_table_entry_size
                vprint(f"  This falls within inline_entries[{entry_idx}]")
                vprint(f"    Entry base offset from poll_wqueues: +0x{inline_entries_start + entry_idx * poll_table_entry_size:03x}")
                vprint(f"    Offset within entry: +0x{entry_off:02x}")
                if entry_off < 8:
                    vprint(f"    → poll_table_entry.filp (file pointer)")
                elif entry_off < 0x30:
                    vprint(f"    → poll_table_entry.wait (wait_queue_entry)")
                    wait_off = entry_off - 8
                    if wait_off < 4:
                        vprint(f"      → wait_queue_entry.flags")
                    elif wait_off < 8:
                        vprint(f"      → wait_queue_entry.private")
                    elif wait_off < 0x10:
                        vprint(f"      → wait_queue_entry.func")
                    elif wait_off < 0x18:
                        vprint(f"      → wait_queue_entry.entry.prev")
                    else:
                        vprint(f"      → wait_queue_entry.entry.next")
        else:
            vprint("  Could not determine poll_wqueues stack offset")
    else:
        vprint("  Could not find do_select BL call in core_sys_select!")
    vprint()
    
    # ═══════════════════════════════════════════════════════════════════
    # Step 7: Summary
    # ═══════════════════════════════════════════════════════════════════
    vprint("=" * 72)
    vprint("Step 7: Summary — Waiter Overlap Check")
    vprint("=" * 72)
    
    do_select_sp = -do_select_depth
    waiter_rel = WAITER_ABS_OFFSET + do_select_depth
    
    vprint(f"  do_select SP (ABS):      {do_select_sp:+d}")
    vprint(f"  Waiter region (ABS):     {WAITER_ABS_OFFSET:+d} .. {WAITER_ABS_OFFSET+WAITER_SIZEOF:+d}")
    vprint(f"  Waiter relative to do_select SP: +0x{waiter_rel:03x} .. +0x{waiter_rel+WAITER_SIZEOF:03x}")
    vprint(f"  do_select frame size:    0x{do_select_size:04x} ({do_select_size}B)")
    vprint()
    
    # Check overlap with waiter region
    waiter_reg = set(range(waiter_rel, waiter_rel + WAITER_SIZEOF))
    sp_offsets_set = set(unique_offsets)
    
    overlapping_offsets = sorted(waiter_reg & sp_offsets_set)
    
    if overlapping_offsets:
        vprint(f"  ⚠ Found {len(overlapping_offsets)} SP offsets overlapping waiter region!")
        for sp_off in overlapping_offsets:
            waiter_field = sp_off - waiter_rel
            field_name = "?"
            for f_off, f_name in WAITER_FIELDS:
                if f_off == waiter_field:
                    field_name = f_name
                    break
            vprint(f"    SP+0x{sp_off:03x} (waiter+0x{waiter_field:02x} = {field_name})")
            for acc in access_map[sp_off]:
                vprint(f"      {acc['mnemonic']:10s} {acc['op_str']}")
    else:
        vprint(f"  No SP-relative stack accesses found in waiter region "
               f"[SP+0x{waiter_rel:03x}, SP+0x{waiter_rel+WAITER_SIZEOF:03x})")
    vprint()
    
    # Check if any copy_from_user writes to waiter region
    waiter_overlap_cfu = []
    if cfu_calls:
        for cfu in cfu_calls:
            if cfu["dest_sp"] is not None:
                buf_start = cfu["dest_sp"]
                buf_end = buf_start + (cfu["size"] or 0)
                if buf_start < waiter_rel_end and buf_end > waiter_rel:
                    waiter_overlap_cfu.append(cfu)
    
    if waiter_overlap_cfu:
        vprint(f"  ✅ FOUND copy_from_user targeting waiter region!")
        for cfu in waiter_overlap_cfu:
            vprint(f"    dest=SP+0x{cfu['dest_sp']:03x} size={cfu['size']} bytes")
            vprint(f"    Covers waiter bytes "
                   f"[{max(0, cfu['dest_sp'] - waiter_rel)}.."
                   f"{min(cfu['size'], cfu['dest_sp'] + cfu['size'] - waiter_rel)})")
    else:
        vprint(f"  ❌ No copy_from_user targets waiter region in do_select")
    vprint()
    
    return {
        "frames": frames,
        "depths": depths,
        "insns": insns,
        "accesses": accesses,
        "access_map": access_map,
        "unique_offsets": unique_offsets,
        "bl_calls": bl_calls,
        "cfu_calls": cfu_calls,
        "waiter_rel_start": waiter_rel,
        "waiter_rel_end": waiter_rel_end,
        "overlapping_offsets": overlapping_offsets,
        "waiter_overlap_cfu": waiter_overlap_cfu,
        "do_select_size": do_select_size,
        "do_select_fp_off": do_select_fp_off,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="do_select Stack Layout Analyzer for GhostLock"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--disasm", action="store_true",
                       help="Show full do_select disassembly")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    args = parser.parse_args()
    
    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1
    
    symbols, text_base, text_data = load_vmlinux(args.elf)
    
    result = analyze_do_select(symbols, text_base, text_data, 
                                verbose=args.verbose, 
                                show_disasm=args.disasm)
    
    # ── Final report ──────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("do_select Buffer Analysis — Final Report")
    print("=" * 60)
    
    do_select_size = result["do_select_size"]
    waiter_rel_start = result["waiter_rel_start"]
    waiter_rel_end = result["waiter_rel_end"]
    
    print(f"  do_select frame:               0x{do_select_size:04x}B ({do_select_size}B)")
    print(f"  do_select SP (abs):            { -result['depths']['do_select']:+d}")
    print(f"  Waiter region in do_select:    SP+0x{waiter_rel_start:03x}..SP+0x{waiter_rel_end:03x}")
    print(f"  Overlapping SP offsets:        {len(result['overlapping_offsets'])}")
    
    wait_region_used = len(result['overlapping_offsets'])
    if wait_region_used > 0:
        print(f"  ⚠  Waiter region has {wait_region_used} stack accesses")
        for soff in result['overlapping_offsets']:
            wf = soff - waiter_rel_start
            print(f"     SP+0x{soff:03x} = waiter+0x{wf:02x}")
    
    cfu_hits = result["waiter_overlap_cfu"]
    if cfu_hits:
        print(f"  ✅ copy_from_user overlaps waiter: {len(cfu_hits)} calls")
        for cfu in cfu_hits:
            print(f"     dest=SP+0x{cfu['dest_sp']:03x} size={cfu['size']}")
    else:
        print(f"  ❌ No copy_from_user overlaps waiter in do_select")
    
    # Import for json output
    import json
    report = {
        "do_select_frame_size": result["do_select_size"],
        "do_select_fp_offset": result["do_select_fp_off"],
        "chain_depths": result["depths"],
        "waiter_abs_offset": WAITER_ABS_OFFSET,
        "waiter_relative_to_do_select": {
            "start": waiter_rel_start,
            "end": waiter_rel_end,
        },
        "overlapping_stack_offsets": result["overlapping_offsets"],
        "copy_from_user_overlaps": [
            {"dest_sp": c["dest_sp"], "size": c["size"]}
            for c in result["waiter_overlap_cfu"]
        ],
        "total_unique_sp_accesses": len(result["unique_offsets"]),
    }
    
    report_path = OUT / "analysis_results.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  JSON report saved to: {report_path}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
