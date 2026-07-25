#!/usr/bin/env python3
"""Static map of EDEADLK → remove_waiter on Leaf5 4.19 vmlinux.elf.

Authority: binary disassembly (hand-fixed bl/b targets). kheaders are clues only.

Usage (repo root):
  uv run python leaf5/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/analysis/map_edeadlk_paths.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

ROOT = next(
    p
    for p in Path(__file__).resolve().parents
    if (p / "raw" / "vmlinux.elf").is_file()
    or (p / "leaf5" / "raw" / "vmlinux.elf").is_file()
)
if (ROOT / "leaf5" / "raw" / "vmlinux.elf").is_file():
    VMLINUX = ROOT / "leaf5" / "raw" / "vmlinux.elf"
else:
    VMLINUX = ROOT / "raw" / "vmlinux.elf"

# errno constants
EDEADLK = 35  # typically on Linux
EAGAIN = 11


def bl_b_target(pc: int, word: int) -> int | None:
    if (word & 0xFC000000) not in (0x94000000, 0x14000000):
        return None
    imm26 = word & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return (pc + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF


def cond_branch_target(pc: int, word: int) -> int | None:
    # B.cond: 0101010x imm19 0 cond
    if (word & 0xFF000010) != 0x54000000:
        return None
    imm19 = (word >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= 1 << 19
    return (pc + (imm19 << 2)) & 0xFFFFFFFFFFFFFFFF


def cbz_target(pc: int, word: int) -> int | None:
    # CBZ/CBNZ: 1011010x imm19 Rt / 1011011x
    top = word >> 24
    if top not in (0x34, 0x35, 0xB4, 0xB5):
        return None
    imm19 = (word >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= 1 << 19
    return (pc + (imm19 << 2)) & 0xFFFFFFFFFFFFFFFF


def tbz_target(pc: int, word: int) -> int | None:
    # TBZ/TBNZ: 0011011x b5:imm14:Rt
    if (word & 0x7E000000) != 0x36000000:
        return None
    imm14 = (word >> 5) & 0x3FFF
    if imm14 & (1 << 13):
        imm14 -= 1 << 14
    return (pc + (imm14 << 2)) & 0xFFFFFFFFFFFFFFFF


def load_symbols(path: Path) -> dict[str, dict]:
    with open(path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        out: dict[str, dict] = {}
        for sym in symtab.iter_symbols():
            if not sym.name:
                continue
            ent = {
                "name": sym.name,
                "value": int(sym.entry.st_value),
                "size": int(sym.entry.st_size),
            }
            prev = out.get(sym.name)
            if prev is None or (prev["size"] == 0 and ent["size"] > 0):
                out[sym.name] = ent
        return out


def load_text(path: Path) -> tuple[int, bytes]:
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                return int(sec.header.sh_addr), sec.data()
        for sec in elf.iter_sections():
            if sec.header.sh_type == "SHT_PROGBITS" and sec.header.sh_flags & 0x4:
                return int(sec.header.sh_addr), sec.data()
    raise SystemExit("no text section")


def nearest_sym(syms: dict[str, dict], addr: int) -> str:
    best = None
    best_d = 1 << 62
    for name, e in syms.items():
        v = e["value"]
        if v <= addr:
            d = addr - v
            if d < best_d and d < 0x200000:
                best_d = d
                best = f"{name}+0x{d:x}" if d else name
    return best or f"0x{addr:x}"


def read_at(text_base: int, data: bytes, addr: int, size: int) -> bytes:
    off = addr - text_base
    if off < 0 or off + size > len(data):
        raise ValueError(f"OOB 0x{addr:x}")
    return data[off : off + size]


def disasm_func(
    text_base: int,
    data: bytes,
    syms: dict[str, dict],
    name: str,
    size_override: int | None = None,
    max_insns: int = 600,
) -> list[dict]:
    ent = syms.get(name)
    if not ent:
        raise KeyError(name)
    addr = ent["value"]
    size = size_override or ent["size"] or 0x400
    size = max(size, 0x40)
    size = min(size, 0x3000)
    blob = read_at(text_base, data, addr, size)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    out: list[dict] = []
    for i, insn in enumerate(md.disasm(blob, addr)):
        if i >= max_insns:
            break
        off = insn.address - addr
        word = struct.unpack_from("<I", blob, off)[0]
        e: dict = {
            "addr": insn.address,
            "m": insn.mnemonic,
            "op": insn.op_str,
            "word": word,
            "line": f"0x{insn.address:x}:  {insn.mnemonic:8s} {insn.op_str}",
        }
        if insn.mnemonic in ("bl", "b"):
            t = bl_b_target(insn.address, word)
            if t is not None:
                e["tgt"] = t
                e["tgt_sym"] = nearest_sym(syms, t)
        elif insn.mnemonic.startswith("b."):
            t = cond_branch_target(insn.address, word)
            if t is not None:
                e["tgt"] = t
                e["tgt_sym"] = nearest_sym(syms, t)
        elif insn.mnemonic in ("cbz", "cbnz"):
            t = cbz_target(insn.address, word)
            if t is not None:
                e["tgt"] = t
                e["tgt_sym"] = nearest_sym(syms, t)
        elif insn.mnemonic in ("tbz", "tbnz"):
            t = tbz_target(insn.address, word)
            if t is not None:
                e["tgt"] = t
                e["tgt_sym"] = nearest_sym(syms, t)
        mems = []
        for op in insn.operands:
            if op.type == 3 and op.mem.base != 0:
                mems.append((insn.reg_name(op.mem.base), op.mem.disp))
        if mems:
            e["mem"] = mems
        out.append(e)
        # stop only after true ret at function end if size known small
        if insn.mnemonic == "ret" and size_override is None and ent["size"] and (insn.address - addr) > max(ent["size"] - 0x20, 0x10):
            break
    return out


def fmt_imm(n: int) -> str:
    if n < 0:
        return f"-0x{-n:x}"
    return f"0x{n:x}"


def print_section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    print(f"vmlinux: {VMLINUX}")
    syms = load_symbols(VMLINUX)
    text_base, data = load_text(VMLINUX)

    names = [
        "remove_waiter",
        "rt_mutex_start_proxy_lock",
        "task_blocks_on_rt_mutex",
        "try_to_take_rt_mutex",
        "rt_mutex_adjust_prio_chain",
        "futex_requeue",
        "rt_mutex_wait_proxy_lock",
        "rt_mutex_cleanup_proxy_lock",
        "mark_wake_futex",
        "wake_futex_pi",
        "rt_mutex_next_owner",
        "rt_mutex_top_waiter",
    ]
    print_section("SYMBOL TABLE")
    for n in names:
        e = syms.get(n)
        if e:
            print(f"  {n:40s} 0x{e['value']:x}  size=0x{e['size']:x}")
        else:
            # substring
            hits = [k for k in syms if n in k][:8]
            print(f"  {n:40s} MISSING  hints={hits}")

    # ---- remove_waiter ----
    print_section("remove_waiter FULL")
    rw = disasm_func(text_base, data, syms, "remove_waiter", size_override=0x100, max_insns=80)
    for e in rw:
        extra = ""
        if e.get("tgt_sym"):
            extra = f"  -> {e['tgt_sym']}"
        if e.get("mem"):
            extra += f"  mem={e['mem']}"
        print(e["line"] + extra)

    # highlight sp_el0 / 0x8d0
    print("\n[KEY] remove_waiter sp_el0 / pi_blocked_on:")
    for e in rw:
        if "sp_el0" in e["op"] or any(d == 0x8D0 for _, d in e.get("mem", [])):
            print("  " + e["line"])

    # ---- rt_mutex_start_proxy_lock ----
    print_section("rt_mutex_start_proxy_lock FULL + call graph")
    sp = disasm_func(
        text_base, data, syms, "rt_mutex_start_proxy_lock", size_override=0x200, max_insns=120
    )
    for e in sp:
        extra = ""
        if e.get("tgt_sym"):
            extra = f"  -> {e['tgt_sym']}"
        print(e["line"] + extra)

    print("\n[CALLS / BRANCHES of interest]")
    for e in sp:
        if e["m"] in ("bl", "b") or e["m"].startswith("b.") or e["m"] in (
            "cbz",
            "cbnz",
            "tbz",
            "tbnz",
        ):
            print(f"  0x{e['addr']:x}: {e['m']} {e['op']} -> {e.get('tgt_sym')}")

    # ret values: look for mov w0, #imm near ret paths
    print("\n[RETURN IMMEDIATES in rt_mutex_start_proxy_lock]")
    for e in sp:
        if e["m"] in ("mov", "movz", "movn", "movk") and ("w0" in e["op"] or "x0" in e["op"]):
            print("  " + e["line"])
        if e["m"] == "ret":
            print("  " + e["line"] + "  (ret)")

    # ---- task_blocks_on_rt_mutex ----
    print_section("task_blocks_on_rt_mutex (calls + ret imm + 0x8d0 + detect)")
    tb = disasm_func(
        text_base, data, syms, "task_blocks_on_rt_mutex", size_override=0x500, max_insns=350
    )
    print(f"  insn_count={len(tb)}  start=0x{tb[0]['addr']:x}")
    print("\n[BL targets]")
    for e in tb:
        if e["m"] == "bl":
            print(f"  0x{e['addr']:x}: bl {e.get('tgt_sym')}")
    print("\n[pi_blocked_on 0x8d0 stores/loads]")
    for e in tb:
        for base, disp in e.get("mem", []):
            if disp == 0x8D0:
                print(f"  {e['line']}  base={base}")
    print("\n[return immediates / cmp patterns]")
    for e in tb:
        op = e["op"]
        if e["m"] in ("mov", "movz", "movn") and ("w0," in op or "x0," in op or op.startswith("w0")):
            print("  " + e["line"])
        if e["m"] == "cmn" or (e["m"] == "cmp" and "w0" in op):
            print("  " + e["line"])
        if e["m"] == "ret":
            print("  " + e["line"])

    # find EDEADLK = 35 = 0x23 as immediate in task_blocks / chain
    print("\n[IMMEDIATES == 0x23 (EDEADLK) or #-0x23 in task_blocks]")
    for e in tb:
        if "#0x23" in e["op"] or "#35" in e["op"] or "#-0x23" in e["op"] or "#-35" in e["op"]:
            print("  " + e["line"])

    # ---- rt_mutex_adjust_prio_chain ----
    print_section("rt_mutex_adjust_prio_chain (EDEADLK return sites)")
    if "rt_mutex_adjust_prio_chain" in syms:
        ac = disasm_func(
            text_base,
            data,
            syms,
            "rt_mutex_adjust_prio_chain",
            size_override=0x1200,
            max_insns=800,
        )
        print(f"  insn_count={len(ac)} size_sym=0x{syms['rt_mutex_adjust_prio_chain']['size']:x}")
        print("\n[IMMEDIATES EDEADLK 0x23 / -35]")
        for e in ac:
            if any(x in e["op"] for x in ("#0x23", "#35", "#-0x23", "#-35", "#0xffffffffffffffdd")):
                print("  " + e["line"])
        print("\n[mov w0 patterns near ends / returns]")
        for e in ac:
            if e["m"] in ("mov", "movz", "movn") and ("w0," in e["op"] or e["op"].startswith("w0")):
                print(f"  0x{e['addr']:x}: {e['m']} {e['op']}")
            if e["m"] == "ret":
                print(f"  0x{e['addr']:x}: ret")
        print("\n[BL sample]")
        for e in ac:
            if e["m"] == "bl":
                print(f"  0x{e['addr']:x}: bl {e.get('tgt_sym')}")

    # ---- futex_requeue ----
    print_section("futex_requeue: proxy lock + EDEADLK handling")
    fr = disasm_func(
        text_base, data, syms, "futex_requeue", size_override=0x1800, max_insns=1000
    )
    print(f"  insn_count={len(fr)} size_sym=0x{syms['futex_requeue']['size']:x}")
    print("\n[BL to proxy/start/cleanup/blocks/remove]")
    keys = (
        "proxy",
        "remove_waiter",
        "task_blocks",
        "rt_mutex",
        "wake",
        "mark_wake",
        "queue_me",
        "unqueue",
        "get_futex",
        "double_lock",
        "hb_waiters",
        "put_pi",
        "free_pi",
        "rt_mutex_init",
        "pi_state",
    )
    for e in fr:
        if e["m"] != "bl":
            continue
        ts = e.get("tgt_sym") or ""
        if any(k in ts for k in keys):
            print(f"  0x{e['addr']:x}: bl {ts}")

    print("\n[ALL BL in futex_requeue]")
    for e in fr:
        if e["m"] == "bl":
            print(f"  0x{e['addr']:x}: bl {e.get('tgt_sym')}")

    print("\n[EDEADLK immediates / cmp after start_proxy]")
    for e in fr:
        if any(x in e["op"] for x in ("#0x23", "#35", "#-0x23", "#-35", "#0xffffffffffffffdd")):
            print("  " + e["line"])
        if e["m"] in ("cmn", "cmp") and "w0" in e["op"]:
            # print with context marker
            print("  " + e["line"] + "  [cmp]")

    # locate start_proxy call site and following 30 insns
    print_section("CONTEXT after bl rt_mutex_start_proxy_lock in futex_requeue")
    sp_addr = syms["rt_mutex_start_proxy_lock"]["value"]
    for i, e in enumerate(fr):
        if e["m"] == "bl" and e.get("tgt") == sp_addr:
            print(f"call site index={i} @ 0x{e['addr']:x}")
            for j in range(i, min(i + 40, len(fr))):
                ee = fr[j]
                extra = f" -> {ee['tgt_sym']}" if ee.get("tgt_sym") else ""
                print("  " + ee["line"] + extra)

    # also rt_mutex_wait_proxy_lock sites
    print_section("CONTEXT around wait_proxy / cleanup_proxy in futex_requeue")
    for name in ("rt_mutex_wait_proxy_lock", "rt_mutex_cleanup_proxy_lock", "remove_waiter"):
        if name not in syms:
            continue
        a = syms[name]["value"]
        for i, e in enumerate(fr):
            if e["m"] == "bl" and e.get("tgt") == a:
                print(f"\n--- bl {name} @ 0x{e['addr']:x} ---")
                for j in range(max(0, i - 5), min(i + 25, len(fr))):
                    ee = fr[j]
                    extra = f" -> {ee['tgt_sym']}" if ee.get("tgt_sym") else ""
                    mark = " <<<" if j == i else ""
                    print("  " + ee["line"] + extra + mark)

    # try_to_take return path in start_proxy already covered
    print_section("SUMMARY HINTS")
    print("EDEADLK errno value on Linux aarch64 userspace: 35 (0x23)")
    print("Look for mov w0,#0xffffffdd (-35) or cmn wN,#0x23 after chain detect")
    print("remove_waiter BUG: clears current->pi_blocked_on via mrs sp_el0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
