# Commands by pipeline stage

Run from **repo root** unless noted. Prefer MCP wrappers when available.

## [A] Device profile

```bash
# Device online
adb devices
adb shell uname -a

# Collect into leaf5/raw/
uv sync
uv run leaf5-collect
uv run leaf5-summarize
```

MCP: `leaf5-adb.adb_devices`, `leaf5-adb.adb_uname_check`.

## [B] Acquire boot (read-only EDL)

Full procedure: `leaf5/edl/README.md`.

```bash
adb reboot edl
# Host: bkerler/edl + SoC-matched loader
python3 edl --loader=<LOADER.bin> --memory=eMMC printgpt
python3 edl --loader=<LOADER.bin> --memory=eMMC r boot_a stock_read/boot_a.img

# After banner OK:
cp stock_read/boot_a.img leaf5/boot_a.bin
```

**Do not** document Magisk/write paths. fastboot fetch: only with user confirmation.

Shell `dd` of `/dev/block/by-name/boot_a` on Leaf5 is **Permission denied** — expected.

## [C] Banner gate

```bash
adb shell cat /proc/version
strings leaf5/boot_a.bin | grep 'Linux version'
# Require same: g3d47a6619220 and #245
```

## [D] Extract kernel Image from boot

Android boot image → payload. Tooling varies; typical options:

```bash
# Example with unpack_bootimg (AOSP) or abootimg / magiskboot — use whatever is installed
# Goal: produce ARM64 Image (magic ARM\x64) matching banner

# Quick presence check without full unpack:
strings leaf5/boot_a.bin | grep -E 'Linux version|ARM'
```

If only compressed Image is present (gzip/lz4), decompress before vmlinux-to-elf.

Save intermediate as e.g. `leaf5/raw/vmlinux_extracted` (already used historically).

## [E] Rebuild ELF (`vmlinux-to-elf`)

Host tool: [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (install separately if missing).

```bash
# Conceptual (adjust to local install):
vmlinux-to-elf leaf5/raw/vmlinux_extracted leaf5/raw/vmlinux.elf \
  2>&1 | tee leaf5/raw/vmlinux_to_elf.log

# If tool warns about absolute vs relative bases, produce abs variant:
# (flags depend on tool version — mirror successful log in raw/vmlinux_to_elf_abs.log)
```

Success signals in log:

- Version string contains **#245** / `g3d47a6619220`
- Architecture aarch64
- kallsyms names ~**121k** symbols
- Base guess near `0xffffff8008080000`

```bash
file leaf5/raw/vmlinux.elf
# ELF 64-bit LSB executable, ARM aarch64, … not stripped
```

## [F] Batch offset extraction (repo scripts)

```bash
uv run leaf5-extract-offsets
uv run leaf5-mm-params
# optional JSON:
uv run leaf5-mm-params --json

# Other S01 helpers:
# uv run python leaf5/stages/S01-offsets-stack/scripts/compute_pselect_shift.py
# uv run python leaf5/stages/S01-offsets-stack/scripts/compute_stack_routes.py
```

Defaults read `leaf5/raw/vmlinux.elf`. Many scripts accept `--elf` if present.

Promote results into `exploit/targets/onyx-leaf5/target.h` with `[BIN]`/`[SYM]` and update S01 README when values change.

## [G] Interactive disasm (no full decompiler required)

### MCP `leaf5-vmlinux` (preferred)

| Tool | Use |
|------|-----|
| `vmlinux_info` | path, symbol count, text base |
| `symbol_lookup` | name → VA |
| `disasm_range` | window; **fixed** bl/adrp targets |
| `frame_size` | prologue frame heuristic |
| `find_cfu_sites` | bl to copy_*user* |
| `compare_to_waiter` | KSP0-delta vs 0x2B0 |

### Manual Capstone

See skill **`arm64-kernel-re`** and `leaf5/stages/S01-offsets-stack/scripts/extract_offsets.py`.

## Optional: kheaders

```bash
# Often already pulled by leaf5-collect from /sys/kernel/kheaders.tar.xz
# Extract for browsing only:
# tar -xJf leaf5/raw/kheaders.tar.xz -C leaf5/raw/kheaders
```

Never sole proof for futex_key / task offsets.
