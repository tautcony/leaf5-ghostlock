#!/usr/bin/env python3
"""
Extract MM_STRUCT_SZ (sizeof struct mm_struct) and calculate MM_ORDER (SLUB
page order) from a kernel vmlinux ELF.

Method
------
1. Disassemble fork_init() and find the call to
   kmem_cache_create_usercopy("mm_struct", size, ...).
2. Extract the ``size`` argument (w1 / x1) by tracing register writes across
   ARM64 instructions, taking care to invalidate caller-saved registers after
   each intervening ``bl``.
3. Calculate the SLUB page order from the struct size, PAGE_SIZE, and
   CONFIG_NR_CPUS using the Linux 4.19 ``calculate_order()`` algorithm.

Usage (from leaf5/)::

    uv run leaf5-mm-params
    uv run python -m scripts.extract_mm_struct_params --json

Requires
--------
- raw/vmlinux.elf            vmlinux-to-elf output (symbols required)
- raw/kernel_config.txt      zcat /proc/config.gz > raw/kernel_config.txt
- capstone >= 5.0, pyelftools (in pyproject.toml)
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Optional

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG  # noqa: F401
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
VMLINUX_ELF = RAW / "vmlinux.elf"
KERNEL_CONFIG = RAW / "kernel_config.txt"

# ── ARM64 caller-saved registers (x0-x18, and their W variants) ────────
CALLER_SAVED = {f"x{i}" for i in range(19)} | {f"w{i}" for i in range(19)}

# Register name normalisation: capstone sometimes returns "x1", sometimes "w1".
# We track both variants per canonical 64-bit name.
_W_TO_X = {f"w{i}": f"x{i}" for i in range(31)}
_X_TO_W = {v: k for k, v in _W_TO_X.items()}


def _canonical(reg: str) -> str:
    """Return the canonical 64-bit register name (e.g. w1 → x1)."""
    return _W_TO_X.get(reg, reg)


def _has_64bit(regs: set[str], x_reg: str) -> bool:
    """Check whether either the 64-bit or 32-bit variant is present."""
    return x_reg in regs or _X_TO_W.get(x_reg, "") in regs


# ────────────────────────────────────────────────────────────────────────
# ELF helpers
# ────────────────────────────────────────────────────────────────────────


def load_symbols(elf_path: Path) -> dict[str, int]:
    """Return {symbol_name: virtual_address} from .symtab."""
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError("No .symtab section in ELF — re-run vmlinux-to-elf")
        return {
            sym.name: sym.entry.st_value
            for sym in symtab.iter_symbols()
            if sym.name
        }


def get_section_data(elf_path: Path) -> tuple[int, bytes]:
    """Return (base_va, raw_bytes) of the .kernel PROGBITS section."""
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return sec.header.sh_addr, sec.data()
    raise ValueError("No .kernel PROGBITS section found")


def read_string_at(va: int, text_base: int, text_data: bytes) -> str:
    """Read a NUL-terminated string at a given virtual address."""
    off = va - text_base
    if off < 0 or off >= len(text_data):
        return "<out of bounds>"
    end = text_data.find(b"\x00", off)
    return text_data[off:end].decode("ascii", errors="replace")


# ────────────────────────────────────────────────────────────────────────
# ARM64 instruction helpers
# ────────────────────────────────────────────────────────────────────────


def decode_bl_target(insn_bytes: bytes, insn_addr: int) -> int:
    """Decode the absolute target address of an ARM64 ``bl`` instruction.

    Capstone 5.x ``op.imm`` is unreliable for branch immediates on ARM64,
    so we decode the imm26 field from the raw instruction word.
    """
    raw = int.from_bytes(insn_bytes[:4], "little")
    imm26 = raw & 0x3FFFF_FF
    if imm26 & 0x200_0000:          # sign-extend 26 bits → 64
        imm26 = imm26 - 0x400_0000
    return insn_addr + (imm26 << 2)


def decode_adrp_page(insn_bytes: bytes, insn_addr: int) -> int:
    """Decode the page-aligned target address of an ARM64 ``adrp``.

    Capstone 5.x does not provide a reliable immediate for this instruction
    through the Python API, so we decode the imm21 field directly.
    """
    raw = int.from_bytes(insn_bytes[:4], "little")
    immlo = (raw >> 29) & 0x3
    immhi = (raw >> 5) & 0x7FFFF
    imm21 = (immhi << 2) | immlo
    if imm21 & 0x10_0000:           # sign-extend 21 bits → 64
        imm21 = imm21 - 0x20_0000
    pc_page = insn_addr & ~0xFFF
    return pc_page + (imm21 << 12)

# Instructions that only *read* their register operands (never write).
_READ_ONLY_MNEMONICS = {
    "str", "stp", "stur", "sturb", "strh", "strb",
    "stxr", "stxp", "stlxr", "stlxp",
    "cbz", "cbnz", "tbz", "tbnz",
    "cmp", "cmn", "tst",
    "b", "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
    "b.lo", "b.ls", "b.hi", "b.hs",  "b.mi", "b.pl",
    "b.vs", "b.vc", "b.cs", "b.cc",
    "ret", "br", "blr",
    "ccmp", "ccmn",
}

# Instructions whose *first* operand is a write destination.
_FIRST_OP_IS_DST = {
    "mov", "movk", "movz", "movn",
    "add", "sub", "and", "orr", "eor", "orn", "bic",
    "adds", "subs", "ands",
    "lsl", "lsr", "asr", "ror", "uxth", "uxtw", "uxtb", "sxtw", "sxth", "sxtb",
    "mvn", "neg", "negs",
    "adr", "adrp",
    "mrs", "msr",
    "ldr", "ldrb", "ldrh", "ldur", "ldurb", "ldurh",
    "ldp", "ldpsw", "ldar", "ldaxr", "ldxr", "ldxp",
    "csel", "csinc", "csinv", "csneg",
    "ubfm", "sbfm", "ubfiz", "sbfiz", "ubfx", "sbfx",
    "extr",
    "bfi", "bfxil", "bfm",
    "clz", "cls", "rbit", "rev", "rev16", "rev32",
    "mul", "madd", "msub", "mneg",
    "sdiv", "udiv",
    "scvtf", "ucvtf", "fcvtzs", "fcvtzu", "fmov",
}


def _reg_written(insn) -> str | None:
    """Return the canonical register name written by *insn*, or None."""
    mnemonic = insn.mnemonic.lower()
    if mnemonic in _READ_ONLY_MNEMONICS:
        return None
    if mnemonic.startswith("b.") or mnemonic in ("b", "br", "blr", "ret", "eret"):
        return None
    if mnemonic == "bl":
        # bl writes x30 (link register)
        return "x30"

    if mnemonic in _FIRST_OP_IS_DST:
        for op in insn.operands:
            if op.type == 1:  # ARM64_OP_REG
                return _canonical(insn.reg_name(op.reg))
        return None

    # For everything else, conservatively return the first register operand
    # as written (covers most ALU instructions).
    for op in insn.operands:
        if op.type == 1:
            return _canonical(insn.reg_name(op.reg))
    return None


def _is_imm_write(insn, reg_canon: str) -> tuple[int, str] | None:
    """If *insn* writes an immediate value to *reg_canon*, return (value, desc)."""
    mnemonic = insn.mnemonic.lower()
    if mnemonic == "mov":
        if len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == 1 and src.type == 2 and _canonical(insn.reg_name(dst.reg)) == reg_canon:
                return src.imm, f"mov {insn.op_str} @ {insn.address:#018x}"
    elif mnemonic == "movk":
        if len(insn.operands) >= 2:
            dst = insn.operands[0]
            imm_op = insn.operands[1]
            shift = insn.operands[2].imm if len(insn.operands) > 2 else 0
            if dst.type == 1 and imm_op.type == 2 and _canonical(insn.reg_name(dst.reg)) == reg_canon:
                return imm_op.imm, f"movk lsl#{shift} @ {insn.address:#018x}"
    elif mnemonic == "movz":
        if len(insn.operands) >= 2:
            dst, imm_op = insn.operands[0], insn.operands[1]
            shift = insn.operands[2].imm if len(insn.operands) > 2 else 0
            if dst.type == 1 and imm_op.type == 2 and _canonical(insn.reg_name(dst.reg)) == reg_canon:
                return imm_op.imm, f"movz lsl#{shift} @ {insn.address:#018x}"
    return None


# ────────────────────────────────────────────────────────────────────────
# Core analysis: extract mm_struct size from fork_init
# ────────────────────────────────────────────────────────────────────────


def _backward_scan_imm(
    insns: list,
    call_idx: int,
    target_reg: str,
) -> tuple[int, str] | None:
    """Scan backwards from *call_idx* through preceding ``bl`` boundaries,
    looking for the most recent immediate write to *target_reg*.

    Returns (value, source_desc) or None."""
    val = None
    src = ""
    partial = False  # whether we've seen a movk (upper bits set)

    # Walk backwards until we hit another bl (basic block boundary).
    for i in range(call_idx - 1, -1, -1):
        insn = insns[i]

        # Stop at preceding bl — we cannot track across call-clobbered regs.
        if insn.mnemonic.lower() == "bl":
            break

        # If this instruction writes target_reg in a non-trivial way, stop.
        written = _reg_written(insn)
        if written == target_reg:
            imm_info = _is_imm_write(insn, target_reg)
            if imm_info is not None:
                imm_val, imm_src = imm_info
                if insn.mnemonic.lower() == "movk":
                    if val is None:
                        # movk without a prior mov — assume zero base
                        val = imm_val << 16  # or appropriate shift
                    else:
                        val = val | (imm_val << (insn.operands[2].imm if len(insn.operands) > 2 else 0))
                    partial = True
                    src = imm_src
                else:
                    if partial:
                        # mov after movk — lower bits overwrite
                        shift = 0
                        val = (val & ~0xFFFF) | (imm_val & 0xFFFF) if val is not None else imm_val
                    else:
                        val = imm_val
                    src = imm_src
            else:
                # Non-immediate write → unknown, stop scanning.
                return None

    if val is None:
        return None
    return val, src


def _resolve_string_va(
    insns: list,
    call_idx: int,
    text_base: int,
    text_data: bytes,
) -> tuple[str, str]:
    """Find the string passed in x0 at a function call by scanning backwards
    for adrp+add pairs.

    Returns (string_value, source_description).
    """
    # Walk backwards from the call to find:
    #   add  x0, xn, #offset   ← string offset
    #   adrp xn, #page         ← page base
    for i in range(call_idx - 1, -1, -1):
        insn = insns[i]
        if insn.mnemonic.lower() == "bl":
            break  # don't cross prior calls

        if insn.mnemonic.lower() == "add" and len(insn.operands) == 3:
            dst, src, imm_op = insn.operands
            if dst.type == 1 and _canonical(insn.reg_name(dst.reg)) == "x0":
                if src.type == 1 and imm_op.type == 2:
                    src_reg = _canonical(insn.reg_name(src.reg))
                    add_off = imm_op.imm
                    add_addr = insn.address
                    # Now scan further back for adrp on src_reg
                    for j in range(i - 1, -1, -1):
                        prev = insns[j]
                        if prev.mnemonic.lower() == "bl":
                            break
                        if prev.mnemonic.lower() == "adrp" and len(prev.operands) >= 2:
                            adrp_dst = _canonical(prev.reg_name(prev.operands[0].reg))
                            if adrp_dst == src_reg:
                                page = decode_adrp_page(prev.bytes, prev.address)
                                va = page + add_off
                                name = read_string_at(va, text_base, text_data)
                                return name, (
                                    f"adrp+add @ {add_addr:#018x} → \"{name}\""
                                )
        # If something *other* than adrp+add writes x0 before the call,
        # we can't resolve the string.
        if insn.mnemonic.lower() == "mov" and len(insn.operands) >= 1:
            if insn.operands[0].type == 1 and _canonical(insn.reg_name(insn.operands[0].reg)) == "x0":
                break  # x0 set via mov, not adrp+add — bail

    return "<unresolved>", "unresolved"


def extract_mm_struct_size(
    symbols: dict[str, int],
    text_base: int,
    text_data: bytes,
) -> tuple[int, int, int, str]:
    """Find the call to kmem_cache_create_usercopy("mm_struct", ...) in
    fork_init and return (struct_size, useroffset, usersize, source_desc).

    Raises ValueError if the call site cannot be identified.
    """

    required = {"fork_init", "kmem_cache_create_usercopy", "kmem_cache_create"}
    missing = [k for k in required if k not in symbols]
    if missing:
        raise ValueError(f"Symbols not found: {', '.join(missing)}")

    fork_init_addr = symbols["fork_init"]
    kmem_create_usercopy_addr = symbols["kmem_cache_create_usercopy"]
    kmem_create_addr = symbols["kmem_cache_create"]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    off = fork_init_addr - text_base
    func_bytes = text_data[off : off + 0x2000]
    insns = list(md.disasm(func_bytes, fork_init_addr))

    # Scan for every bl to kmem_cache_create* and check if the string is
    # "mm_struct".  Use backward scanning so we stay inside the same basic
    # block (bounded by prior bl / branch).
    targets = {kmem_create_usercopy_addr: "kmem_cache_create_usercopy",
               kmem_create_addr: "kmem_cache_create"}

    for idx, insn in enumerate(insns):
        if insn.mnemonic.lower() != "bl":
            continue
        target = decode_bl_target(insn.bytes, insn.address)
        if target not in targets:
            continue

        # Resolve the string argument.
        name, str_src = _resolve_string_va(insns, idx, text_base, text_data)
        if name != "mm_struct":
            continue

        # Extract size (w1), useroffset (w4), usersize (w5).
        size_info = _backward_scan_imm(insns, idx, "x1")
        uoff_info = _backward_scan_imm(insns, idx, "x4")
        usize_info = _backward_scan_imm(insns, idx, "x5")

        if size_info is None:
            raise ValueError(
                f"Found mm_struct call @ {insn.address:#018x} but could not "
                f"resolve the size argument (w1)."
            )

        size, size_src = size_info
        uoff = uoff_info[0] if uoff_info else 0
        usize = usize_info[0] if usize_info else 0

        desc = (
            f"fork_init @ {fork_init_addr:#018x}\n"
            f"  call: {targets[target]} @ {insn.address:#018x}\n"
            f"  string: {str_src}\n"
            f"  size (w1): {size:#x} ({size}) — {size_src}\n"
            f"  useroffset (w4): {uoff:#x}\n"
            f"  usersize (w5): {usize:#x}"
        )
        return size, uoff, usize, desc

    raise ValueError(
        "Could not locate kmem_cache_create(usercopy?) call for \"mm_struct\" "
        "in fork_init. The kernel may inline the call or use a different "
        "initialisation pattern."
    )


# ────────────────────────────────────────────────────────────────────────
# MM_ORDER calculation (Linux 4.19 SLUB calculate_order)
# ────────────────────────────────────────────────────────────────────────


def fls(n: int) -> int:
    """find last set bit (1-indexed), analogous to the kernel's fls()."""
    return n.bit_length()


def get_order(size: int) -> int:
    """Minimum page order needed for *size* bytes."""
    if size == 0:
        return 0
    # ceiling of log2(size) minus PAGE_SHIFT
    return (size - 1).bit_length() - 12


def order_objects(order: int, object_size: int, reserved: int = 0) -> int:
    """How many objects fit in an order-N slab?"""
    slab_size = 0x1000 << order
    return (slab_size - reserved) // object_size


def slab_order(
    object_size: int,
    min_objects: int,
    max_order: int,
    fract_leftover: int,
    slub_min_order: int = 0,
    reserved: int = 0,
) -> int | None:
    """Return the lowest order that fits *min_objects* with acceptable waste,
    or None if no order up to max_order satisfies."""
    min_order = max(slub_min_order, get_order(min_objects * object_size + reserved))
    for order in range(min_order, max_order + 1):
        slab_size = 0x1000 << order
        if slab_size < min_objects * object_size + reserved:
            continue
        rem = (slab_size - reserved) % object_size
        max_waste = slab_size // fract_leftover
        if rem <= max_waste:
            return order
    return None


def calculate_mm_order(
    object_size: int,
    nr_cpus: int,
    slub_max_order: int = 3,
    slub_min_order: int = 0,
    page_size: int = 4096,
    reserved: int = 0,
) -> tuple[int, int, str]:
    """Calculate the SLUB page order for *object_size* using the Linux 4.19
    ``calculate_order()`` heuristic.

    Returns (order, objects_per_slab, trace).
    """
    min_objects = 4 * (fls(nr_cpus) + 1)
    max_objects = order_objects(slub_max_order, object_size, reserved)
    min_objects = min(min_objects, max_objects)

    lines = [
        f"PAGE_SIZE = {page_size}",
        f"CONFIG_NR_CPUS = {nr_cpus}",
        f"slub_max_order = {slub_max_order}, slub_min_order = {slub_min_order}",
        f"min_objects = 4 * (fls({nr_cpus}) + 1) = 4 * ({fls(nr_cpus)} + 1) = {min_objects}",
        f"max_objects (order={slub_max_order}) = {max_objects}",
    ]

    result_order: int | None = None
    while min_objects > 1:
        fraction = 16
        while fraction >= 4:
            order = slab_order(object_size, min_objects, slub_max_order, fraction, slub_min_order, reserved)
            if order is not None:
                slab_size = page_size << order
                objs = (slab_size - reserved) // object_size
                waste = (slab_size - reserved) % object_size

                marker = " ← ACCEPTED" if result_order is None else ""
                lines.append(
                    f"  min_obj={min_objects:3d} frac=1/{fraction:<2d} "
                    f"order={order} slab={slab_size//1024:4d}KB objs={objs:3d} "
                    f"waste={waste:4d}B ({waste/slab_size*100:.2f}%){marker}"
                )
                if result_order is None:
                    result_order = order
            fraction //= 2
        if result_order is not None:
            break
        min_objects -= 1

    if result_order is None:
        # Fallback: single-object slab
        result_order = get_order(object_size)
        lines.append(f"  → fallback: order={result_order} (single-object slab)")

    slab_size = page_size << result_order
    objects_per_slab = (slab_size - reserved) // object_size
    lines.append(
        f"  RESULT: order={result_order}, {objects_per_slab} objects/slab "
        f"({slab_size//1024}KB slab)"
    )

    return result_order, objects_per_slab, "\n".join(lines)


# ────────────────────────────────────────────────────────────────────────
# Config reader
# ────────────────────────────────────────────────────────────────────────


def read_kernel_config(config_path: Path) -> dict[str, str]:
    """Parse a Linux kernel .config file into a dict."""
    config: dict[str, str] = {}
    if not config_path.exists():
        return config
    for line in config_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        config[key.lstrip("CONFIG_")] = val.strip('"')
    return config


# ────────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract MM_STRUCT_SZ and MM_ORDER from vmlinux ELF"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--elf",
        type=Path,
        default=VMLINUX_ELF,
        help=f"Path to vmlinux.elf (default: {VMLINUX_ELF})",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=KERNEL_CONFIG,
        help=f"Path to kernel_config.txt (default: {KERNEL_CONFIG})",
    )
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.", file=__import__("sys").stderr)
        print("Run vmlinux-to-elf on the kernel Image first.", file=__import__("sys").stderr)
        return 1

    # 1. Extract MM_STRUCT_SZ from fork_init
    symbols = load_symbols(args.elf)
    text_base, text_data = get_section_data(args.elf)

    try:
        mm_sz, useroffset, usersize, sz_desc = extract_mm_struct_size(
            symbols, text_base, text_data
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1

    # 2. MM_ORDER from config + calculation
    config = read_kernel_config(args.config)
    nr_cpus = int(config.get("NR_CPUS", "8"))
    page_size = 4096 if config.get("ARM64_4K_PAGES") == "y" else 65536

    order, objs_per_slab, order_trace = calculate_mm_order(
        object_size=mm_sz,
        nr_cpus=nr_cpus,
        page_size=page_size,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "MM_STRUCT_SZ": f"0x{mm_sz:x}",
                    "MM_STRUCT_SZ_dec": mm_sz,
                    "useroffset": f"0x{useroffset:x}",
                    "usersize": f"0x{usersize:x}",
                    "MM_ORDER": order,
                    "objects_per_slab": objs_per_slab,
                    "slab_size_bytes": page_size << order,
                    "nr_cpus": nr_cpus,
                    "page_size": page_size,
                },
                indent=2,
            )
        )
    else:
        print("=" * 64)
        print("MM_STRUCT_SZ & MM_ORDER — Leaf5 (4.19) kernel analysis")
        print("=" * 64)
        print()
        print(sz_desc)
        print()
        print("─" * 64)
        print("MM_ORDER calculation (4.19 SLUB calculate_order)")
        print("─" * 64)
        print(order_trace)
        print()
        print("─" * 64)
        print("Summary")
        print("─" * 64)
        print(f"  MM_STRUCT_SZ    = {mm_sz:#05x}  ({mm_sz} bytes)")
        print(f"  MM_ORDER        = {order}  ({page_size << order} bytes / {(page_size << order)//1024}KB slab)")
        print(f"  objects / slab  = {objs_per_slab}")
        print(f"  useroffset      = {useroffset:#05x}")
        print(f"  usersize        = {usersize:#05x}")
        print(f"  CONFIG_NR_CPUS  = {nr_cpus}")
        print(f"  PAGE_SIZE       = {page_size}")
        print()
        print("─" * 64)
        print("Relevant source files")
        print("─" * 64)
        print(f"  ELF:      {args.elf.resolve()}")
        if args.config.exists():
            print(f"  config:   {args.config.resolve()}")
        print(f"  common.h: exploit/src/common.h  (verify #define MM_STRUCT_SZ)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
