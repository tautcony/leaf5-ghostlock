---
name: leaf5-stages-workflow
description: >
  Leaf5 GhostLock stage-pipeline discipline for Onyx Leaf5 (CVE-2026-43499).
  Use whenever writing or moving probes, opening a new CFU/stack route, recording
  success/failure, updating PROCESS_LOG, correcting offsets, integrating into
  exploit/, or when the user mentions stages, S00–S07, CORRECTED, target.h,
  probe placement, or "不要重打死路". Prefer this skill over free-form exploration
  for any experimental work in this repo. Slash: /leaf5-stages-workflow.
---

# Leaf5 stages workflow

Authority: `leaf5/stages/*/README.md` + `leaf5/PROCESS_LOG.md` win over other docs.
`AGENTS.md` is the short rule card; this skill is the execution checklist.

## Before any experimental work

1. Read `leaf5/stages/README.md` matrix for the relevant stage.
2. Open the **node README** for the route you touch (e.g. `S05/.../07-kgsl/e-.../README.md`).
3. If the node is already marked **❌** and there is **no new evidence** (new disasm, new errno matrix, new binary offset), **do not re-run the same probe path**. Say why it is closed and what new evidence would reopen it.
4. Confirm runtime identity before trusting offsets or device results:
   - `adb shell uname -a` must match **4.19.157**, **#245**, **g3d47a6619220**
   - if mismatch: stop; do not use `leaf5/raw/vmlinux*` offsets against this device

## Where code goes

| Work | Location |
|------|----------|
| New probe | `leaf5/stages/Sxx/.../probes/*.c` |
| Static analysis script | `leaf5/stages/Sxx/.../analysis/` or `scripts/` |
| Integrated exploit path | `exploit/` only **after** stage probe proves the claim |
| Constants / sizes / offsets | `exploit/targets/onyx-leaf5/target.h` only — no magic numbers in `.c` |

Build/deploy:

```bash
cd leaf5/stages
make SRC=<rel-path-to.c> BITS=64   # or 32
make SRC=<rel-path-to.c> deploy
```

Outputs live under repo `out/` (not committed). Prefer MCP `leaf5-adb` for device runs when available.

## Node README contract

Every node you change must keep a short README with:

1. **目标** — one hypothesis
2. **文件** — probes / scripts list
3. **结果** — ✅ / ❌ / ⚠️ / ⛔ with date if new
4. **原因** — evidence: VA, insn, errno matrix, depth vs `waiter->task @ KSP0-0x2B0`
5. **下游** — what unblocks next

When overturning an old conclusion, mark **CORRECTED** and point at the new evidence. Do not silently rewrite history in `docs/` alone.

## Constants discipline

- Read/write offsets only via `target.h` (or generated notes that then land in `target.h`).
- Tag levels: `[BIN]` (disasm/device), `[SYM]`, `[SRC]`, `[EST]`.
- **`[EST]` never on critical path** until upgraded to `[BIN]`.
- Changing an offset: update `target.h` + the stage node that proved it in the **same** change set; append PROCESS_LOG if it is a milestone.

## Control experiments (errno matrix)

When a probe fails, classify the failure layer before concluding "path dead":

| Observation | Meaning |
|-------------|---------|
| ENOTTY | never reached handler |
| EINVAL | validation failed early |
| EFAULT | reached copy_from_user (or equivalent) |
| success / other | document ret + side effects |

Prefer paired cases: valid vs bad pointer, 32 vs 64, with/without context. Record a table in the node README or a log file under the node — do not leave results only in chat.

## Stack / CFU claims

- Depth: **nested frames only**; sequential sibling calls do not stack.
- Compare CFU write site to **KSP0**, then to `waiter->task @ KSP0 - 0x2B0`.
- Leaf5 endgame (standard GhostLock CFU cover task): **closed on layout** unless new route evidence appears. See stages README.

## Reporting to the user (Chinese)

Always structure:

```text
做了什么 → 证据 → 结论 → 下一步（可选）
```

Keep technical terms in English (`CFU`, `waiter->task`, `EFAULT`, symbol names).

## Hard stops

- No destructive `dd`, flash, Magisk, or unauthorized attacks.
- EDL is **read-only** extraction; ask before anything that rewrites device storage.
- Do not invent offsets "from similar kernels"; use vmlinux or a real probe.
---

## Quick reopen test for a ❌ route

Only reopen if at least one holds:

1. New disassembly of a different call site / different frame size
2. New privilege path (e.g. capability or SELinux change) with proof
3. New user-controlled buffer that lands at a different SP offset
4. Documented bug in prior depth math with corrected KSP0 formula
