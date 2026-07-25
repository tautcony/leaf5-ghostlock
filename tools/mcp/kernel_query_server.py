#!/usr/bin/env python3
"""Leaf5 vmlinux-query MCP — symbol lookup, disasm, frame size, CFU sites."""

from __future__ import annotations

import struct
from functools import lru_cache
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile
from mcp.server.fastmcp import FastMCP

from common import resolve_vmlinux

# Leaf5 documented waiter task slot relative to KSP0
WAITER_TASK_KSP0_DELTA = 0x2B0

mcp = FastMCP(
    "leaf5-vmlinux",
    instructions=(
        "Query Leaf5 vmlinux.elf with Capstone. "
        "bl/adrp immediates are hand-decoded (Capstone 5.x often wrong). "
        "kheaders are not authority; binary is."
    ),
)


def _load_elf(path: Path):
    f = open(path, "rb")
    elf = ELFFile(f)
    return f, elf


@lru_cache(maxsize=4)
def _symbols(path_str: str) -> dict[str, dict]:
    path = Path(path_str)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            return {}
        out: dict[str, dict] = {}
        for sym in symtab.iter_symbols():
            if not sym.name:
                continue
            # keep first definition-ish entry; prefer nonzero size later if needed
            prev = out.get(sym.name)
            ent = {
                "name": sym.name,
                "value": int(sym.entry.st_value),
                "size": int(sym.entry.st_size),
                "type": sym.entry.st_info.type,
                "bind": sym.entry.st_info.bind,
            }
            if prev is None or (prev["size"] == 0 and ent["size"] > 0):
                out[sym.name] = ent
        return out


@lru_cache(maxsize=4)
def _text_blob(path_str: str) -> tuple[int, bytes]:
    path = Path(path_str)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return int(sec.header.sh_addr), sec.data()
        # fallback: first executable PROGBITS
        for sec in elf.iter_sections():
            if sec.header.sh_type == "SHT_PROGBITS" and sec.header.sh_flags & 0x4:
                return int(sec.header.sh_addr), sec.data()
    raise ValueError("No code section found in ELF")


def _bl_target(pc: int, word: int) -> int | None:
    # BL / B: op 0b100101 / 0b000101 — we handle BL (with link) primarily
    if (word & 0xFC000000) not in (0x94000000, 0x14000000):
        return None
    imm26 = word & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return (pc + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF


def _adrp_page(pc: int, word: int) -> int | None:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immhi = (word >> 5) & 0x7FFFF
    immlo = (word >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    page = (pc & ~0xFFF) + (imm << 12)
    return page & 0xFFFFFFFFFFFFFFFF


def _read_words(text_base: int, data: bytes, addr: int, size: int) -> bytes:
    off = addr - text_base
    if off < 0 or off >= len(data):
        raise ValueError(f"Address 0x{addr:x} outside text (base 0x{text_base:x})")
    return data[off : off + size]


def _disasm_insns(
    path: Path,
    addr: int,
    size: int,
    max_insns: int = 200,
) -> list[dict]:
    text_base, data = _text_blob(str(path))
    blob = _read_words(text_base, data, addr, size)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns: list[dict] = []
    for i, insn in enumerate(md.disasm(blob, addr)):
        if i >= max_insns:
            break
        word = struct.unpack_from("<I", blob, insn.address - addr)[0] if insn.address - addr + 4 <= len(blob) else 0
        # re-read carefully
        off = insn.address - addr
        word = struct.unpack_from("<I", blob, off)[0] if off + 4 <= len(blob) else 0
        entry: dict = {
            "address": f"0x{insn.address:x}",
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": f"{word:08x}",
        }
        bl = _bl_target(insn.address, word)
        if bl is not None and insn.mnemonic in ("bl", "b"):
            entry["target_fixed"] = f"0x{bl:x}"
            # try reverse symbol
            entry["target_symbol"] = _nearest_symbol(path, bl)
        adrp = _adrp_page(insn.address, word)
        if adrp is not None and insn.mnemonic == "adrp":
            entry["page_fixed"] = f"0x{adrp:x}"
        # stack-ish immediates
        if insn.mnemonic in ("sub", "add") and "sp" in insn.op_str:
            entry["sp_note"] = insn.op_str
        for op in insn.operands:
            if op.type == 3 and op.mem.base != 0:  # MEM
                base = insn.reg_name(op.mem.base)
                disp = op.mem.disp
                entry.setdefault("mem", []).append({"base": base, "disp": disp})
        insns.append(entry)
        if insn.mnemonic == "ret":
            break
    return insns


def _nearest_symbol(path: Path, addr: int) -> str | None:
    syms = _symbols(str(path))
    best = None
    best_delta = 1 << 62
    for name, ent in syms.items():
        v = ent["value"]
        if v <= addr:
            d = addr - v
            if d < best_delta and d < 0x100000:
                best_delta = d
                best = f"{name}+0x{d:x}" if d else name
    return best


def _frame_size_from_insns(insns: list[dict]) -> dict:
    """Heuristic: first sub sp,sp,#imm or stp with pre-index sp."""
    frame = None
    evidence = []
    for ent in insns[:40]:
        m = ent["mnemonic"]
        op = ent["op_str"]
        if m == "sub" and op.startswith("sp, sp, #"):
            imm_s = op.split("#", 1)[1].split(",")[0]
            try:
                imm = int(imm_s, 0)
            except ValueError:
                continue
            frame = imm
            evidence.append(f"{ent['address']}: sub sp, sp, #{imm:#x}")
            break
        if m == "stp" and "sp," in op and "#-" in op:
            # e.g. stp x29, x30, [sp, #-0x50]!
            try:
                imm_s = op.split("#-")[1].split("]")[0].split("!")[0]
                imm = int(imm_s, 0)
                frame = imm
                evidence.append(f"{ent['address']}: {m} {op}")
                break
            except (IndexError, ValueError):
                pass
    return {"frame_size": frame, "frame_size_hex": f"0x{frame:x}" if frame else None, "evidence": evidence}


@mcp.tool()
def symbol_lookup(name: str, vmlinux_path: str | None = None, substring: bool = False) -> dict:
    """Look up symbol address/size in vmlinux.elf by exact name or substring."""
    path = resolve_vmlinux(vmlinux_path)
    syms = _symbols(str(path))
    if substring:
        hits = [
            {"name": n, "value": f"0x{e['value']:x}", "size": e["size"]}
            for n, e in sorted(syms.items())
            if name in n
        ][:50]
        return {"ok": True, "vmlinux": str(path), "query": name, "matches": hits, "count": len(hits)}
    ent = syms.get(name)
    if not ent:
        # soft suggest
        sugg = [n for n in syms if name in n][:10]
        return {"ok": False, "error": f"symbol not found: {name}", "suggestions": sugg, "vmlinux": str(path)}
    return {
        "ok": True,
        "vmlinux": str(path),
        "name": ent["name"],
        "value": f"0x{ent['value']:x}",
        "value_int": ent["value"],
        "size": ent["size"],
        "size_hex": f"0x{ent['size']:x}",
    }


@mcp.tool()
def disasm_range(
    address: str,
    size: int = 0x100,
    max_insns: int = 80,
    vmlinux_path: str | None = None,
) -> dict:
    """Disassemble at VA. bl/adrp targets include hand-fixed immediates."""
    path = resolve_vmlinux(vmlinux_path)
    addr = int(address, 0)
    size = max(4, min(int(size), 0x2000))
    max_insns = max(1, min(int(max_insns), 400))
    insns = _disasm_insns(path, addr, size, max_insns=max_insns)
    return {
        "ok": True,
        "vmlinux": str(path),
        "start": f"0x{addr:x}",
        "size": size,
        "instructions": insns,
        "nearest_symbol": _nearest_symbol(path, addr),
    }


@mcp.tool()
def frame_size(symbol: str, vmlinux_path: str | None = None, peek_size: int = 0x80) -> dict:
    """Estimate stack frame size from function prologue (sub sp / stp pre-index)."""
    path = resolve_vmlinux(vmlinux_path)
    syms = _symbols(str(path))
    ent = syms.get(symbol)
    if not ent:
        return {"ok": False, "error": f"symbol not found: {symbol}"}
    addr = ent["value"]
    size = max(ent["size"] or 0, peek_size)
    size = min(size, 0x400)
    insns = _disasm_insns(path, addr, size, max_insns=40)
    fr = _frame_size_from_insns(insns)
    return {
        "ok": True,
        "symbol": symbol,
        "address": f"0x{addr:x}",
        **fr,
        "prologue": insns[:12],
        "vmlinux": str(path),
    }


@mcp.tool()
def find_cfu_sites(
    symbol: str,
    vmlinux_path: str | None = None,
    max_insns: int = 300,
) -> dict:
    """Find bl targets that look like copy_from_user / _copy_from_user within a function."""
    path = resolve_vmlinux(vmlinux_path)
    syms = _symbols(str(path))
    ent = syms.get(symbol)
    if not ent:
        return {"ok": False, "error": f"symbol not found: {symbol}"}
    addr = ent["value"]
    size = ent["size"] or 0x800
    size = min(max(size, 0x100), 0x2000)
    insns = _disasm_insns(path, addr, size, max_insns=max_insns)
    keywords = (
        "copy_from_user",
        "_copy_from_user",
        "copy_to_user",
        "__arch_copy_from_user",
        "arm64_copy_from_user",
    )
    sites = []
    for ent_i in insns:
        if ent_i["mnemonic"] != "bl":
            continue
        tgt_sym = ent_i.get("target_symbol") or ""
        tgt = ent_i.get("target_fixed")
        if any(k in tgt_sym for k in keywords) or (
            tgt_sym and "copy" in tgt_sym and "user" in tgt_sym
        ):
            sites.append(
                {
                    "call_site": ent_i["address"],
                    "target": tgt,
                    "target_symbol": tgt_sym,
                    "insn": f"{ent_i['mnemonic']} {ent_i['op_str']}",
                }
            )
    # also list all bl for manual review (capped)
    all_bl = [
        {
            "call_site": e["address"],
            "target": e.get("target_fixed"),
            "target_symbol": e.get("target_symbol"),
        }
        for e in insns
        if e["mnemonic"] == "bl"
    ][:80]
    return {
        "ok": True,
        "symbol": symbol,
        "address": f"0x{addr:x}",
        "cfu_like_sites": sites,
        "all_bl_sample": all_bl,
        "frame": _frame_size_from_insns(insns),
        "vmlinux": str(path),
        "note": "CFU-like filter is name-based; confirm with full call chain depth separately.",
    }


@mcp.tool()
def compare_to_waiter(
    cfu_delta_from_ksp0: str,
    note: str = "",
) -> dict:
    """Compare a CFU write depth (KSP0 - X) to waiter->task @ KSP0 - 0x2B0.

    Pass cfu_delta_from_ksp0 as hex/int X meaning write at KSP0 - X.
    """
    x = int(cfu_delta_from_ksp0, 0)
    waiter = WAITER_TASK_KSP0_DELTA
    # If write at KSP0-x covers pointer at KSP0-0x2B0, need x >= 0x2B0 and reach into that slot.
    # For a write of `size` bytes starting at KSP0-x, coverage is [KSP0-x, KSP0-x+size).
    # Here we only report position delta of the start relative to waiter slot.
    delta = x - waiter  # positive: CFU start deeper than waiter slot (lower address)
    if x == waiter:
        relation = "aligned_start"
    elif x < waiter:
        relation = "shallower_than_waiter_task"  # higher address, smaller depth
    else:
        relation = "deeper_than_waiter_task"
    return {
        "ok": True,
        "cfu_at": f"KSP0 - 0x{x:x}",
        "waiter_task_at": f"KSP0 - 0x{waiter:x}",
        "byte_delta_start": abs(x - waiter),
        "signed_delta_cfu_minus_waiter": x - waiter,
        "relation": relation,
        "note": note
        or (
            "Positive signed_delta means CFU start is deeper (lower SP) than waiter->task. "
            "Coverage also depends on write length and which field is targeted."
        ),
        "leaf5_endgame_hint": (
            "Documented 64-bit KGSL path ~KSP0-0x228 is shallower by 0x88 (136) bytes vs 0x2B0."
        ),
    }


@mcp.tool()
def vmlinux_info(vmlinux_path: str | None = None) -> dict:
    """Basic vmlinux.elf facts: path, size, symbol count, text base."""
    path = resolve_vmlinux(vmlinux_path)
    syms = _symbols(str(path))
    try:
        text_base, data = _text_blob(str(path))
        text = {"base": f"0x{text_base:x}", "size": len(data)}
    except Exception as e:
        text = {"error": str(e)}
    return {
        "ok": True,
        "path": str(path),
        "file_size": path.stat().st_size,
        "symbol_count": len(syms),
        "text": text,
        "waiter_task_ksp0_delta": f"0x{WAITER_TASK_KSP0_DELTA:x}",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
