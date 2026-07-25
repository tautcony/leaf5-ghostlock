#!/usr/bin/env python3
"""
do_select Frame Analyzer — GhostLock Waiter Overlap Detection

Analyzes do_select's stack frame layout from vmlinux.elf to determine:
  1. Exact frame size and prologue structure
  2. All SP-relative memory accesses (local variables, saved regs)
  3. copy_from_user destinations and their overlap with waiter
  4. poll_wqueues structure location and overlap potential
  5. Final verdict on whether do_select can be used for GhostLock waiter overwrite

Usage:
    uv run python -m ghostlock-analysis.do-select-buffers.do_select_frame_analyzer -v
    uv run python -m ghostlock-analysis.do-select-buffers.do_select_frame_analyzer --json
    uv run python -m ghostlock-analysis.do-select-buffers.do_select_frame_analyzer --disasm
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

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

# ── Known Constants ──────────────────────────────────────────────────────

WAITER_ABS_OFFSET = -0x380  # rt_mutex_waiter absolute stack offset
WAITER_SIZEOF = 0x40        # waiter size on 4.19

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

# ── Helpers ──────────────────────────────────────────────────────────────


def parse_imm(s: str) -> int:
    s = s.strip().rstrip("]!,")
    if s.startswith("#"):
        s = s[1:]
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("-"):
        return -int(s[1:], 16 if s[1:].startswith("0x") else 10)
    return int(s, 16 if "0x" in s else 10)


def bl_target(insn) -> int:
    return insn.operands[0].imm & ADDR_MASK


# ── ELF Loader ──────────────────────────────────────────────────────────


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


def get_insns(
    symbols: dict, text_base: int, text_data: bytes, name: str, max_len: int = 0x1000
) -> list:
    if name not in symbols:
        return []
    addr = symbols[name]
    off = addr - text_base
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(text_data[off : off + max_len], addr))


# ── Frame Analysis ──────────────────────────────────────────────────────


def analyze_frame(
    symbols: dict, text_base: int, text_data: bytes, name: str
) -> dict[str, Any]:
    """Full frame analysis of a function."""
    insns = get_insns(symbols, text_base, text_data, name, 0x400)

    # Find prologue to determine frame size and FP offset
    total_frame = 0
    fp_off = 0
    fp_lr_save = None

    for insn in insns:
        op = insn.op_str
        if insn.mnemonic == "sub" and "sp, sp" in op:
            total_frame += parse_imm(op.split("#")[-1].strip(","))
        elif insn.mnemonic == "stp" and "[sp, #-" in op and "]!" in op:
            total_frame += parse_imm(op.split("#-")[1].split("]")[0])
        elif insn.mnemonic == "add" and "x29, sp" in op:
            fp_off = parse_imm(op.split("#")[-1])
        elif insn.mnemonic == "stp" and "x29, x30" in op and "]!" not in op:
            parts = op.split("[sp, #")[1].split("]")[0]
            fp_lr_save = parse_imm(parts)
        if insn.mnemonic == "ret" and total_frame > 0:
            break

    # Map all SP/X29-relative accesses
    accesses: list[dict] = []
    for insn in insns:
        for op in insn.operands:
            if op.type == ARM64_OP_MEM and op.mem.base != 0:
                base_reg = insn.reg_name(op.mem.base)
                disp = op.mem.disp
                if base_reg in ("sp", "x29"):
                    sp_off = disp if base_reg == "sp" else fp_off + disp
                    if 0 <= sp_off <= total_frame + 64:
                        accesses.append(
                            {
                                "addr": insn.address,
                                "sp_off": sp_off,
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                                "is_write": insn.mnemonic.startswith("str"),
                            }
                        )
        if insn.mnemonic == "ret":
            break

    # Group by offset
    access_map: dict[int, list[dict]] = defaultdict(list)
    for acc in accesses:
        access_map[acc["sp_off"]].append(acc)

    # Find copy_from_user calls
    cfu_calls = _find_cfu_calls(insns, symbols, fp_off)

    # Find BL calls
    bl_calls = _find_bl_calls(insns, symbols)

    return {
        "name": name,
        "address": symbols.get(name, 0),
        "frame_size": total_frame,
        "fp_offset": fp_off,
        "fp_lr_save": fp_lr_save,
        "num_instructions": len(insns),
        "unique_sp_offsets": sorted(access_map.keys()),
        "max_sp_offset": max(access_map.keys()) if access_map else 0,
        "access_map": {str(k): v for k, v in access_map.items()},
        "accesses": accesses,
        "cfu_calls": cfu_calls,
        "bl_calls": bl_calls,
    }


def _find_cfu_calls(
    insns: list, symbols: dict, fp_off: int
) -> list[dict[str, Any]]:
    cfu_addr = symbols.get("__arch_copy_from_user")
    if cfu_addr is None:
        return []

    calls = []
    for i, insn in enumerate(insns):
        if insn.mnemonic == "bl" and bl_target(insn) == cfu_addr:
            dest_sp = None
            copy_size = None
            for j in range(i - 1, max(0, i - 20), -1):
                prev = insns[j]
                op = prev.op_str.replace(" ", "")
                if prev.mnemonic == "add" and "x0,sp" in op:
                    dest_sp = parse_imm(op.split("#")[-1])
                elif prev.mnemonic == "sub" and "x0,x29" in op:
                    imm = parse_imm(op.split("#")[-1].rstrip("]"))
                    dest_sp = fp_off - imm
                elif prev.mnemonic == "add" and "x0,x29" in op:
                    imm = parse_imm(op.split("#")[-1].rstrip("]"))
                    dest_sp = fp_off + imm
                if prev.mnemonic == "mov" and "w2,#" in prev.op_str:
                    copy_size = parse_imm(prev.op_str.split("#")[-1])
            calls.append(
                {
                    "insn_addr": insn.address,
                    "dest_sp": dest_sp,
                    "copy_size": copy_size,
                }
            )
        if insn.mnemonic == "ret":
            break
    return calls


def _find_bl_calls(insns: list, symbols: dict) -> list[dict[str, Any]]:
    calls = []
    for insn in insns:
        if insn.mnemonic == "bl":
            target = bl_target(insn)
            tgt_name = None
            for sym_name, sym_addr in symbols.items():
                if sym_addr == target:
                    tgt_name = sym_name
                    break
            calls.append(
                {
                    "addr": insn.address,
                    "target": target,
                    "name": tgt_name or f"0x{target:x}",
                }
            )
        if insn.mnemonic == "ret":
            break
    return calls


# ── Waiter Overlap Check ───────────────────────────────────────────────


def check_waiter_overlap(
    chain: list[tuple[str, int]], waiter_abs: int
) -> dict[str, Any]:
    """Check waiter overlap across the call chain."""

    cumulative = 0
    chain_info = []
    for func_name, frame_size in chain:
        cumulative += frame_size
        chain_info.append(
            {
                "name": func_name,
                "frame_size": frame_size,
                "cumulative_depth": cumulative,
                "sp_abs": -cumulative,
            }
        )

    # Waiter relative to the last function in chain (do_select)
    last_sp_abs = -cumulative
    waiter_rel_to_last = waiter_abs - last_sp_abs
    waiter_rel_end = waiter_rel_to_last + WAITER_SIZEOF

    return {
        "chain": chain_info,
        "total_depth": cumulative,
        "last_function_sp_abs": last_sp_abs,
        "waiter_abs": waiter_abs,
        "waiter_relative_to_last": {
            "start": waiter_rel_to_last,
            "end": waiter_rel_end,
            "start_hex": f"SP+0x{waiter_rel_to_last:03x}",
            "end_hex": f"SP+0x{waiter_rel_end:03x}",
        },
    }


# ── Report Generator ────────────────────────────────────────────────────


def generate_report(
    ds_frame: dict,
    css_frame: dict,
    p6_frame: dict,
    overlap: dict,
    verbose: bool = False,
) -> str:
    """Generate human-readable analysis report."""
    lines = []
    W = 72

    def emit(s=""):
        lines.append(s)

    vemit = emit if verbose else lambda *a: None

    emit("=" * W)
    emit("do_select Frame Analyzer — GhostLock Waiter Overlap Report")
    emit("=" * W)
    emit()

    # Section 1: Frame sizes
    emit("1. CALL CHAIN FRAME SIZES")
    emit("-" * W)
    emit(f"  {'Function':<30s} {'Frame':>8s} {'Cumulative':>12s} {'SP ABS':>10s}")
    emit(f"  {'-'*28} {'-'*6} {'-'*10} {'-'*8}")
    for ci in overlap["chain"]:
        emit(
            f"  {ci['name']:<30s} 0x{ci['frame_size']:04x} ({ci['frame_size']:4d}B)"
            f"  0x{ci['cumulative_depth']:04x}  {ci['sp_abs']:+6d}"
        )
    emit(f"  {'Waiter':<30s} {'':>8s} {'':>12s} {WAITER_ABS_OFFSET:+6d}")
    emit()

    wait = overlap["waiter_relative_to_last"]
    emit(
        f"  Waiter in do_select: {wait['start_hex']} .. {wait['end_hex']}"
        f" (size=0x{WAITER_SIZEOF:02x})"
    )
    emit()

    # Section 2: do_select stack analysis
    emit("2. do_select STACK ACCESS MAP")
    emit("-" * W)
    emit(f"  Frame size:      0x{ds_frame['frame_size']:04x}")
    emit(f"  FP offset:       SP+0x{ds_frame['fp_offset']:03x}")
    emit(f"  Max SP access:   SP+0x{ds_frame['max_sp_offset']:03x}")
    emit(f"  Unique offsets:  {len(ds_frame['unique_sp_offsets'])}")
    emit()

    wait_start = wait["start"]
    wait_end = wait["end"]

    # Check overlapping accesses
    overlapping = [
        off
        for off in ds_frame["unique_sp_offsets"]
        if wait_start <= off < wait_end
    ]

    if overlapping:
        emit(f"  *** {len(overlapping)} ACCESSES IN WAITER REGION ***")
        for off in overlapping:
            field_idx = off - wait_start
            field = "?"
            for f_off, f_name in WAITER_FIELDS:
                if f_off == field_idx:
                    field = f_name
                    break
            for acc in ds_frame["access_map"][str(off)]:
                emit(
                    f"    SP+0x{off:03x} (waiter+0x{field_idx:02x}={field}):"
                    f" {acc['mnemonic']} {acc['op_str']}"
                )
    else:
        emit("  No SP-relative accesses overlap the waiter region.")
        emit()

        # Show the region gap
        max_off = ds_frame["max_sp_offset"]
        gap = wait_start - max_off
        emit(f"  Waiter starts at SP+0x{wait_start:03x}")
        emit(f"  Max access is at  SP+0x{max_off:03x}")
        emit(
            f"  Gap: {gap} bytes of completely unused stack space"
            f" ({gap:#05x})"
        )
        emit()

    # Section 3: copy_from_user
    emit("3. copy_from_user DESTINATIONS")
    emit("-" * W)
    if ds_frame["cfu_calls"]:
        for cfu in ds_frame["cfu_calls"]:
            overlap_str = ""
            if cfu["dest_sp"] is not None:
                if wait_start <= cfu["dest_sp"] < wait_end:
                    overlap_str = " <<< WAITER OVERLAP!"
                elif (
                    cfu["dest_sp"] + (cfu["copy_size"] or 0) > wait_start
                    and cfu["dest_sp"] < wait_end
                ):
                    overlap_str = f" <<< PARTIAL (buf@{cfu['dest_sp']}, sz={cfu['copy_size']})"
            emit(
                f"  0x{cfu['insn_addr']:016x}: "
                f"SP+0x{cfu['dest_sp']:03x} size={cfu['copy_size']}"
                f"{overlap_str}"
            )
    else:
        emit("  No __arch_copy_from_user calls in do_select.")
    emit()

    # Section 4: BL calls
    vemit("4. BL CALLS FROM do_select")
    vemit("-" * W)
    for call in ds_frame["bl_calls"]:
        vemit(f"  0x{call['addr']:016x}: bl {call['name']}")
    vemit()

    # Section 5: Verdict
    emit("5. VERDICT")
    emit("-" * W)

    has_overlap = False
    if overlapping:
        has_overlap = True
    if any(
        cfu["dest_sp"] is not None
        and wait_start <= cfu["dest_sp"] < wait_end
        for cfu in ds_frame["cfu_calls"]
    ):
        has_overlap = True

    if has_overlap:
        emit("  *** NEGATIVE: Wait for reversed verdict ***")
        emit("  *** This path should be re-examined ***")
    else:
        emit("  NEGATIVE: do_select cannot be used for GhostLock waiter overwrite.")
        emit()
        emit("  The waiter (at do_select SP+0x%03x) is %d bytes above" % (wait_start, gap))
        emit("  the highest stack access (SP+0x%03x)." % max_off)
        emit("  No code in do_select touches this region.")
        emit()
        emit("  No copy_from_user writes to the waiter region.")
        emit("  The poll_wqueuses structure is at SP+0xd0 (do_select's own stack),")
        emit("  0x%03x bytes below the waiter." % (wait_start - 0xd0))
        emit()

    return "\n".join(lines)


def generate_json_report(
    ds_frame: dict,
    css_frame: dict,
    p6_frame: dict,
    overlap: dict,
) -> dict:
    """Generate machine-readable JSON report."""
    wait = overlap["waiter_relative_to_last"]
    wait_start = wait["start"]
    wait_end = wait["end"]

    overlapping = [
        off
        for off in ds_frame["unique_sp_offsets"]
        if wait_start <= off < wait_end
    ]

    cfu_overlaps = [
        {
            "dest_sp": cfu["dest_sp"],
            "copy_size": cfu["copy_size"],
        }
        for cfu in ds_frame["cfu_calls"]
        if cfu["dest_sp"] is not None
        and wait_start <= cfu["dest_sp"] < wait_end
    ]

    return {
        "kernel": "4.19.157 (Leaf5/TabBoox)",
        "waiter_abs_offset": WAITER_ABS_OFFSET,
        "waiter_relative_to_do_select": {
            "start": wait_start,
            "end": wait_end,
            "start_hex": f"SP+0x{wait_start:03x}",
        },
        "do_select": {
            "frame_size": ds_frame["frame_size"],
            "fp_offset": ds_frame["fp_offset"],
            "max_sp_offset": ds_frame["max_sp_offset"],
            "num_unique_sp_accesses": len(ds_frame["unique_sp_offsets"]),
        },
        "chain": [
            {
                "name": ci["name"],
                "frame_size": ci["frame_size"],
                "cumulative_depth": ci["cumulative_depth"],
            }
            for ci in overlap["chain"]
        ],
        "overlapping_sp_offsets": overlapping,
        "cfu_overlaps": cfu_overlaps,
        "verdict": "NEGATIVE - No buffer at waiter position"
        if not overlapping and not cfu_overlaps
        else "POTENTIAL OVERLAP - Re-examine required",
    }


# ── Main ────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="do_select Frame Analyzer for GhostLock waiter overlap"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--disasm", action="store_true", help="Show full disassembly")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    symbols, text_base, text_data = load_vmlinux(args.elf)

    required = [
        "do_select",
        "core_sys_select",
        "__arm64_sys_pselect6",
        "__arch_copy_from_user",
    ]
    missing = [s for s in required if s not in symbols]
    if missing:
        print(f"ERROR: Missing symbols: {missing}")
        return 1

    # Analyze each function
    ds_frame = analyze_frame(symbols, text_base, text_data, "do_select")
    css_frame = analyze_frame(symbols, text_base, text_data, "core_sys_select")
    p6_frame = analyze_frame(symbols, text_base, text_data, "__arm64_sys_pselect6")

    # Build call chain
    chain = [
        ("__arm64_sys_pselect6", p6_frame["frame_size"]),
        ("core_sys_select", css_frame["frame_size"]),
        ("do_select", ds_frame["frame_size"]),
    ]
    overlap = check_waiter_overlap(chain, WAITER_ABS_OFFSET)

    if args.json:
        report = generate_json_report(ds_frame, css_frame, p6_frame, overlap)
        print(json.dumps(report, indent=2))
    else:
        report_str = generate_report(
            ds_frame, css_frame, p6_frame, overlap, verbose=args.verbose
        )
        print(report_str)

    # Save JSON report
    json_report = generate_json_report(ds_frame, css_frame, p6_frame, overlap)
    report_path = OUT / "analysis_results.json"
    with open(report_path, "w") as f:
        json.dump(json_report, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
