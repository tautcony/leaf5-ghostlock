#!/usr/bin/env python3
"""
栈覆盖路由比较分析 — 多路径 waiter 偏移计算

分析 pselect、sendmsg、recvmsg、binder 等多种栈覆盖路由，
计算每个路径的栈帧深度并与 waiter 位置比较，找出最佳覆盖方案。

用法:
    uv run python -m scripts.compute_stack_routes -v
"""

from __future__ import annotations

import argparse
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_MEM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
VMLINUX_ELF = RAW / "vmlinux.elf"

ADDR_MASK = 0xFFFFFFFFFFFFFFFF

# Known constants from futex_wait analysis
WAITER_SP_OFFSET = 0x50  # waiter at futex_wait SP + 0x50
FUTEX_TOTAL_DEPTH = 0x3d0  # sys_futex(0x70) + do_futex(0x220) + futex_wait(0x140)
WAITER_ABS_OFFSET = -(FUTEX_TOTAL_DEPTH - WAITER_SP_OFFSET)  # = -0x380


# ── Routing path definitions ───────────────────────────────────────

# Each route defines the call chain from syscall entry to the target function
# Format: (name, [(function_name, frame_size), ...])
# frame_size = None means "compute from binary"

ROUTES = {
    "pselect": {
        "chain": [
            ("__arm64_sys_pselect6", None),
            ("core_sys_select", None),
        ],
        "buf_func": "core_sys_select",    # function where user buffer is
        "buf_sp_offset": 0x50,            # stack_fds offset from func's SP
        "buf_size": 256,                   # SELECT_STACK_ALLOC
        "control": "user fd_set bits",     # type of user control
        "notes": "nfds <= 320: stack path; nfds >= 321: kmalloc heap path"
    },
    "sendmsg": {
        "chain": [
            ("__arm64_sys_sendmsg", None),
            ("___sys_sendmsg", None),
        ],
        "buf_func": "___sys_sendmsg",
        "buf_sp_offset": None,             # need to find copy_from_user dest
        "buf_size": None,
        "control": "msghdr + iovec data",
        "notes": "user-controlled msghdr copied via copy_from_user"
    },
    "recvmsg": {
        "chain": [
            ("__arm64_sys_recvmsg", None),
            ("___sys_recvmsg", None),
        ],
        "buf_func": "___sys_recvmsg",
        "buf_sp_offset": None,
        "buf_size": None,
        "control": "msghdr + iovec data",
        "notes": "user-controlled msghdr copied via copy_from_user"
    },
    "binder-ioctl": {
        "chain": [
            ("binder_ioctl", None),
            ("binder_ioctl_write_read", None),
            ("binder_thread_write", None),
        ],
        "buf_func": "binder_thread_write",
        "buf_sp_offset": 0x20,             # local struct init at SP+0x20
        "buf_size": 0x60,                  # 8 fields × 8 bytes (local ptr struct)
        "control": "indirect (kernel ptrs from binder structs)",
        "notes": "SP+0x20 stores binder_proc+0x30; values are kernel addresses, "
                 "not directly user-controlled but influenced by prior ioctls"
    },
    "binder-deep": {
        "chain": [
            ("binder_ioctl", None),
            ("binder_ioctl_write_read", None),
            ("binder_thread_write", None),
            ("binder_transaction", None),
        ],
        "buf_func": "binder_transaction",
        "buf_sp_offset": None,
        "buf_size": None,
        "control": "binder transaction data",
        "notes": "Deepest binder path; copy_from_user of transaction data"
    },
}


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


def find_frame_size(symbols, text_base, text_data, name: str) -> tuple[int, int]:
    """Return (total_frame_alloc, fp_offset_from_sp)."""
    if name not in symbols:
        return 0, 0
    addr = symbols[name]
    off = addr - text_base
    fbytes = text_data[off : off + 0x600]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    total = 0
    fp_off = 0
    for insn in md.disasm(fbytes, addr):
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


def find_copy_from_user_dest(
    symbols, text_base, text_data, func_name: str
) -> list[tuple[int, int, int]]:
    """
    Find __arch_copy_from_user calls and their stack destinations.
    Returns [(call_addr, dest_sp_offset, copy_size), ...]
    """
    if func_name not in symbols:
        return []

    addr = symbols[func_name]
    off = addr - text_base
    fbytes = text_data[off : off + 0x1000]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    fp_off = 0
    insns = list(md.disasm(fbytes, addr))

    # Find frame pointer offset
    for insn in insns:
        if insn.mnemonic == "add" and "x29, sp" in insn.op_str:
            fp_off = parse_imm(insn.op_str.split("#")[-1])
            break
        if insn.mnemonic == "ret":
            break

    # Check if __arch_copy_from_user exists
    cfu_addr = symbols.get("__arch_copy_from_user")
    if cfu_addr is None:
        return []

    results = []
    for i, insn in enumerate(insns):
        if insn.mnemonic == "bl":
            target = insn.operands[0].imm & ADDR_MASK
            if target == cfu_addr:
                # Look backward for x0 (dest) and w2 (size) setup
                dest_sp = None
                copy_size = None
                for j in range(i - 1, max(0, i - 15), -1):
                    prev = insns[j]
                    # add/sub x0, sp, #N or add/sub x0, x29, #N
                    if prev.mnemonic == "add" and "x0, sp" in prev.op_str:
                        parts = prev.op_str.split("#")
                        if len(parts) > 1:
                            dest_sp = parse_imm(parts[-1].rstrip("]"))
                    elif prev.mnemonic == "sub" and "x0, x29" in prev.op_str:
                        parts = prev.op_str.split("#")
                        if len(parts) > 1:
                            dest_sp = fp_off - parse_imm(
                                parts[-1].split(",")[0].rstrip("]"))
                    # mov w2, #N
                    if prev.mnemonic == "mov" and "w2, #" in prev.op_str:
                        copy_size = parse_imm(prev.op_str.split("#")[-1])
                if dest_sp is not None:
                    results.append((insn.address, dest_sp, copy_size or 0))

    return results


def analyze_routes(symbols, text_base, text_data, verbose: bool = False) -> dict:
    """Analyze all stack routes and compare with waiter position."""

    vprint = print if verbose else lambda *a, **k: None

    # Fill in frame sizes
    for route_name, route in ROUTES.items():
        chain = route["chain"]
        for i, (func_name, _) in enumerate(chain):
            size, _ = find_frame_size(symbols, text_base, text_data, func_name)
            chain[i] = (func_name, size)

        # Find copy_from_user destinations for the buffer function
        if route["buf_sp_offset"] is None:
            buf_func = route["buf_func"]
            cfu_dests = find_copy_from_user_dest(
                symbols, text_base, text_data, buf_func)
            if cfu_dests:
                # Use the first (shallowest) destination
                route["buf_sp_offset"] = cfu_dests[0][1]
                route["buf_size"] = cfu_dests[0][2]

    # Compute depths and deltas
    results = {}
    for route_name, route in ROUTES.items():
        total_depth = sum(size for _, size in route["chain"])
        buf_sp = route["buf_sp_offset"] or 0

        # Buffer absolute offset from kernel_stack_top:
        # buffer_abs = -(total_depth) + buf_sp_offset
        buffer_abs = -total_depth + buf_sp

        # Delta: how many bytes the buffer is above the waiter
        # Positive = buffer is above waiter (higher address)
        # Negative = buffer is below waiter (lower address)
        delta_bytes = buffer_abs - WAITER_ABS_OFFSET
        delta_words = delta_bytes // 8

        results[route_name] = {
            "total_depth": total_depth,
            "buf_sp_offset": buf_sp,
            "buf_size": route.get("buf_size") or 0,
            "buffer_abs": buffer_abs,
            "delta_bytes": delta_bytes,
            "delta_words": delta_words,
            "control": route["control"],
            "notes": route["notes"],
            "chain": route["chain"],
        }

    # Print summary
    vprint("=" * 80)
    vprint("栈覆盖路由比较分析")
    vprint("=" * 80)
    vprint(f"  Waiter 绝对偏移: {WAITER_ABS_OFFSET:+d} (0x{WAITER_ABS_OFFSET & 0xfff:x})")
    vprint(f"  Waiter 相对偏移: futex_wait SP + 0x{WAITER_SP_OFFSET:x}")
    vprint(f"  Futex 总深度:    0x{FUTEX_TOTAL_DEPTH:x} ({FUTEX_TOTAL_DEPTH}B)")
    vprint()

    # Table header
    header = (
        f"  {'路由':<16s} {'深度':>6s} {'Buf@SP':>7s} "
        f"{'Buf大小':>7s} {'Δ字节':>7s} {'Δ词':>5s}  "
        f"{'覆盖?':<5s}  {'控制方式'}"
    )
    vprint(header)
    vprint(f"  {'-'*16} {'-'*6} {'-'*7} {'-'*7} {'-'*7} {'-'*5}  {'-'*5}  {'-'*40}")

    for route_name, r in results.items():
        reachable = "无"
        abs_delta = abs(r["delta_words"])
        if r["buf_sp_offset"] is not None and r["buf_size"]:
            buf_start = r["buf_sp_offset"]
            buf_end = buf_start + r["buf_size"]
            # Waiter occupies word offsets [0, 8) from its base
            # We need the buffer to cover these positions
            waiter_in_buf_start = -r["delta_bytes"]
            waiter_in_buf_end = waiter_in_buf_start + 0x40  # waiter is 64 bytes
            if waiter_in_buf_start >= 0 and waiter_in_buf_end <= r["buf_size"]:
                reachable = "完全"
            elif waiter_in_buf_end > 0 and waiter_in_buf_start < r["buf_size"]:
                overlap_bytes = min(waiter_in_buf_end, r["buf_size"]) - max(waiter_in_buf_start, 0)
                reachable = f"部分({overlap_bytes}B)"

        vprint(
            f"  {route_name:<16s} 0x{r['total_depth']:04x} "
            f"0x{r['buf_sp_offset']:04x} "
            f"{r['buf_size']:5d}B {r['delta_bytes']:+7d} "
            f"{r['delta_words']:+5d}  {reachable:<5s}  {r['control']}"
        )

    vprint()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare stack overlap routes for GhostLock"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--elf", type=Path, default=VMLINUX_ELF)
    args = parser.parse_args()

    if not args.elf.exists():
        print(f"ERROR: {args.elf} not found.")
        return 1

    with open(args.elf, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        symbols = {sym.name: sym.entry.st_value
                   for sym in symtab.iter_symbols() if sym.name}
        for sec in elf.iter_sections():
            if sec.name == ".kernel" and sec.header.sh_type == "SHT_PROGBITS":
                text_base = sec.header.sh_addr
                text_data = sec.data()
                break
        else:
            print("ERROR: No .kernel section")
            return 1

    results = analyze_routes(symbols, text_base, text_data,
                            verbose=args.verbose)

    # ── Best route recommendation ──────────────────────────────────
    print("=" * 60)
    print("最佳栈覆盖路由推荐")
    print("=" * 60)

    # Find routes with the smallest |delta|
    ranked = sorted(results.items(), key=lambda x: abs(x[1]["delta_words"]))

    for i, (name, r) in enumerate(ranked):
        abs_dw = abs(r["delta_words"])
        reachable = "否"
        if r["buf_sp_offset"] is not None and r["buf_size"]:
            waiter_start_in_buf = -r["delta_bytes"]
            waiter_end_in_buf = waiter_start_in_buf + 0x40
            if 0 <= waiter_start_in_buf and waiter_end_in_buf <= r["buf_size"]:
                reachable = "✅ 完全覆盖"
            elif waiter_end_in_buf > 0 and waiter_start_in_buf < r["buf_size"]:
                overlap = min(waiter_end_in_buf, r["buf_size"]) - max(waiter_start_in_buf, 0)
                reachable = f"⚠️ 部分覆盖 ({overlap}B/{0x40}B)"

        score = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else "  "
        print(f"  {score} {name:<16s} |Δ|={abs_dw}词 "
              f"({r['delta_bytes']:+d}B)  {reachable}")
        print(f"      深度=0x{r['total_depth']:04x} "
              f"Buf@SP+0x{r['buf_sp_offset']:04x} "
              f"大小={r['buf_size']}B")
        print(f"      {r['control']}")

    # Specific recommendations
    print()
    print("  建议:")
    print(f"    1. binder-ioctl: SP+0x20 与 waiter 精确对齐 (Δ=0词)，")
    print(f"       但存储的是内核指针，非直接用户可控")
    print(f"    2. sendmsg/recvmsg: 需要分析 ___sys_sendmsg/_recvmsg")
    print(f"       中的 copy_from_user 目标偏移")
    print(f"    3. binder-deep: binder_transaction 路径最深，")
    print(f"       需分析其内部 copy_from_user 目标")
    print(f"    4. 运行时: PSELECT_SHIFT_OVERRIDE 环境变量二分搜索")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
