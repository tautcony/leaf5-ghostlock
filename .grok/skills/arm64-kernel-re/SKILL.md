---
name: arm64-kernel-re
description: >
  ARM64 Linux kernel reverse-engineering for Leaf5 GhostLock (kernel 4.19.157 #245).
  Use when extracting offsets, disassembling vmlinux, computing stack frame depth,
  locating copy_from_user sites, verifying [EST]→[BIN], reading capstone output,
  fixing bl/adrp immediates, computing MM_STRUCT_SZ, waiter layout, or any static
  analysis against leaf5/raw/vmlinux*. Prefer this over guessing from kheaders or
  mainline source. Slash: /arm64-kernel-re. Triggers: vmlinux, capstone, offset,
  disasm, frame size, CFU site, KSP0, stack depth, target.h, [BIN], [EST].
---

# ARM64 kernel RE (Leaf5)

## Authority order

1. **Runtime-matched `leaf5/raw/vmlinux.elf`** (or abs variant) + banner/`uname` match
2. Device probe behavior (errno, crash site)
3. `kheaders` / mainline 4.19 — **clues only**, never sole proof for critical offsets

Before extracting: confirm build **#245** / `g3d47a6619220`. Mismatch → stop.

## Tooling in this repo

```bash
# Repo root
uv sync
uv run leaf5-extract-offsets
uv run leaf5-mm-params
```

Prefer MCP **`leaf5-vmlinux`** when configured:

- `symbol_lookup` — name → VA
- `disasm_range` — window with fixed bl/adrp imm
- `frame_size` — prologue-derived frame
- `find_cfu_sites` — copy_from_user-like calls in a function
- `compare_to_waiter` — depth vs `KSP0-0x2B0`

Fallback: scripts under `leaf5/stages/S01-offsets-stack/scripts/`.

## Capstone 5.x pitfalls (critical)

On ARM64 with Capstone 5.x:

| Item | Reality |
|------|---------|
| `bl` / `bl` target via `op.imm` | **Often wrong** — decode imm from raw insn |
| `adrp` page imm | **Often wrong** — hand-decode |
| `mov wN, #imm` / simple ldr/str imm | Usually OK |
| Memory `disp` on ldr/str | Usually OK for small offsets |

### Hand decode helpers

```text
# bl (imm26), PC-relative, ±128MB
imm26 = insn_word & 0x03FFFFFF
if imm26 & (1 << 25): imm26 -= (1 << 26)
target = pc + (imm26 << 2)

# adrp Rd, label
immhi = (insn_word >> 5) & 0x7FFFF
immlo = (insn_word >> 29) & 0x3
imm = (immhi << 2) | immlo
if imm & (1 << 20): imm -= (1 << 21)
page = (pc & ~0xFFF) + (imm << 12)
```

When documenting an offset, cite **raw VA + mnemonic line**, not only Capstone pretty-print of branch targets.

## Stack depth rules

1. Walk the **call chain that is nested on the stack** (A calls B calls C).
2. **Do not** add frame sizes of sequential non-nested helpers called one after another.
3. Sum frames (and known SP adjustments) from entry to the CFU site.
4. Express the write as **KSP0 − delta** (or SP+off within a known frame, then lift to KSP0).
5. Compare to Leaf5 waiter:

```text
waiter->task @ KSP0 - 0x2B0
```

If CFU is shallower/deeper by tens of bytes, report the **byte delta**, not "almost".

## Known Leaf5 endgame numbers (do not re-guess)

| Item | Value |
|------|-------|
| `rt_mutex_waiter` size | **0x40** (no prio/deadline) |
| `waiter->task` | **KSP0 - 0x2B0** |
| Typical 64-bit KGSL CFU | ~KSP0-0x228 (too shallow ~88B) |
| pselect SHIFT | **-46** (standard pselect cover unusable) |
| `MM_STRUCT_SZ` / `MM_ORDER` | **0x388** / **3** |
| `real_cred` / `cred` | **0x7d8** / **0x7e0** |
| `pi_blocked_on` | **0x8d0** |
| futex_key | **V1** (`FUTEX_KEY_LAYOUT_V1`) |

Full table: `exploit/targets/onyx-leaf5/target.h` and `AGENTS.md`.

## MM_STRUCT_SZ method

1. Disassemble `fork_init` (or path that calls `kmem_cache_create_usercopy`).
2. Find the call with name pointer `"mm_struct"`.
3. Track the size argument register at the call (often x1) after prior mov/imm loads.
4. Cross-check with `mm_alloc` memset/copy size if present.
5. Promote to `[BIN]` only with both paths agreeing or one strong path + runtime.

## Offset promotion protocol

```text
[EST] / [SRC]  →  disasm or probe evidence  →  [BIN]
```

When promoting:

1. Record function VA, insn evidence, extracted value.
2. Update `target.h` with `[BIN]` and a short comment.
3. Update the stage node README (S01 or the route that needed it).
4. Never leave a critical exploit path on `[EST]`.

## Output format for RE claims

```text
Symbol/site: <name> @ <VA>
Evidence: <insn or register trace>
Derived: <offset or depth>
Compare: waiter->task @ KSP0-0x2B0 → Δ = <bytes> (shallower|deeper|overlap)
Status: [BIN] | needs probe
Next: <optional>
```

## Anti-patterns

- Trusting kheaders struct layout for futex_key / task offsets without binary check
- Adding non-nested frames into depth
- Using Capstone `bl` target without imm fix
- Copying offsets from another device (OPPO Find N2 etc.) into Leaf5 `target.h`
