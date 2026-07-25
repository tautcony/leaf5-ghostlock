---
name: leaf5-image-elf
description: >
  Leaf5 kernel image acquisition, unpack, ELF rebuild, and static reverse-engineering
  pipeline (EDL/boot → Image → vmlinux-to-elf → capstone offsets). Use whenever the user
  mentions boot image, boot_a, EDL, Firehose, extract partition, unpack boot, Android
  boot.img, kernel Image, vmlinux, vmlinux-to-elf, kallsyms, rebuild ELF, extract
  offsets, decompile/disassemble the kernel binary, raw/, kheaders pull, banner match,
  or "镜像/elf/反编译/提取". Prefer this skill for S00/S01 data-source work before
  deep stack/CFU analysis (then hand off to arm64-kernel-re). Slash: /leaf5-image-elf.
---

# Leaf5 image → ELF → RE pipeline

End-to-end **data source** workflow for GhostLock on Onyx Leaf5.  
Deep offset/stack math lives in **`arm64-kernel-re`**; this skill owns **how binaries appear and stay trustworthy**.

## Pipeline (always left → right)

```text
runtime (adb uname)
    ↓
[A] device profile     leaf5-collect → raw/* , config.gz
    ↓
[B] acquire boot       EDL r boot_a (read-only) → leaf5/boot_a.bin
    ↓
[C] banner gate        strings boot ↔ uname  MUST match #245 / g3d47a6619220
    ↓
[D] extract Image      boot.img → ARM64 Image / payload
    ↓
[E] rebuild ELF        vmlinux-to-elf → raw/vmlinux.elf (+ optional abs)
    ↓
[F] batch offsets      leaf5-extract-offsets / leaf5-mm-params → target.h
    ↓
[G] interactive RE     MCP leaf5-vmlinux / arm64-kernel-re skill
```

**Hard gate:** if [C] fails, **stop**. Offsets from a mismatched image poison everything.

Read details when needed:

- `references/artifacts.md` — paths, gitignore, which file is authority
- `references/commands.md` — concrete commands per stage
- `references/pitfalls.md` — known wrong sources and tool bugs

## Authority order

| Rank | Source | Use |
|------|--------|-----|
| 1 | Runtime `uname` / `/proc/version` on device | Identity of “truth” |
| 2 | `leaf5/boot_a.bin` whose banner **matches** runtime | Kernel binary |
| 3 | `leaf5/raw/vmlinux.elf` (or abs) rebuilt from that boot | Symbols + disasm |
| 4 | `/proc/config.gz` (via collect) | CONFIG authority |
| 5 | `kheaders` | Layout **clues only** (build # may differ by 1) |
| 6 | Mainline / other device (OPPO, old boot.img #119) | **Never** critical offsets |

`/proc/kallsyms` on Leaf5 shell: **Permission denied** — do not plan around it; rely on ELF `.symtab` from vmlinux-to-elf.

## Safety

| Allowed | Forbidden without explicit user confirm |
|---------|----------------------------------------|
| EDL **read** (`printgpt`, `r`, `rl`) | EDL write / flash / Magisk / patch boot |
| adb pull of readable paths | `dd` of boot when denied is not a workaround to force |
| Host unpack + vmlinux-to-elf | fastboot flash; reboot bootloader only if user OK |

EDL procedure: `leaf5/edl/README.md`. Loader/HWID is device-specific — do not copy P6 Pro loader blindly.

## Stage map

| Stage | Skill touch | Artifacts |
|-------|-------------|-----------|
| S00 profile | [A] | `raw/device_identity.txt`, `config.gz`, … |
| S01 offsets | [C]–[G] | `vmlinux.elf`, scripts under `stages/S01-…/scripts/` |
| Later stages | consume `target.h` only | probes — not new image extract |

## Minimal verify checklist (run often)

```bash
# Device
adb shell uname -a
# expect: 4.19.157 … g3d47a6619220 … #245

# Boot image on host
strings leaf5/boot_a.bin | grep 'Linux version'
# same git short hash + #245

# ELF
file leaf5/raw/vmlinux.elf
# ELF 64-bit … aarch64 … not stripped

# Optional MCP
# leaf5-vmlinux.vmlinux_info / symbol_lookup
# leaf5-adb.adb_uname_check
```

Mismatch → **do not** run extract_offsets against that ELF.

## What “反编译” means here

This repo does **not** use full decompilers (Ghidra/IDA) as the default path.

| Goal | Tool |
|------|------|
| Symbol VA | ELF `.symtab` / MCP `symbol_lookup` |
| Instruction stream | Capstone + **hand-fixed** `bl`/`adrp` imm |
| Frame size / CFU sites | MCP `frame_size` / `find_cfu_sites` or S01 scripts |
| Batch struct offsets | `uv run leaf5-extract-offsets` |
| MM slab params | `uv run leaf5-mm-params` |

Capstone 5.x ARM64: `bl`/`adrp` `op.imm` is often wrong — see **`arm64-kernel-re`**. Never trust Capstone branch targets alone when writing `[BIN]` offsets.

## Handoff

After ELF is validated:

1. Offsets / stack depth / CFU vs waiter → load **`arm64-kernel-re`**
2. Probe compile & device run → **`ndk-probe-loop`**
3. Writing conclusions → **`leaf5-stages-workflow`**

## Report template

```text
做了什么: [A–G which steps]
证据: uname banner | boot strings | ELF path | symbol count or sample VA
结论: data source OK / blocked (reason)
下一步: extract_offsets | mm-params | arm64-kernel-re on <symbol>
```
