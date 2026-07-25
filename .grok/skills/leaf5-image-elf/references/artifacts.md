# Artifact map (Leaf5)

Paths relative to repo root unless noted. Many binaries are **gitignored**.

## Primary chain

| Path | Role | Notes |
|------|------|-------|
| `leaf5/boot_a.bin` | Runtime-matched boot partition dump | gitignore; from EDL `r boot_a` |
| `leaf5/raw/vmlinux_extracted` / `vmlinux` | Unpacked/stripped kernel payload | intermediate |
| `leaf5/raw/vmlinux.elf` | **Default** analysis ELF | kallsyms → .symtab; text ~`0xffffff8008080000` |
| `leaf5/raw/vmlinux_abs.elf` | Absolute-base rebuild variant | use if relocations need abs; same symbol set typically |
| `leaf5/raw/vmlinux_to_elf.log` | Rebuild log | prove banner + base guess |
| `exploit/targets/onyx-leaf5/target.h` | Code-side offset truth | only after [BIN]/[SYM] |

## Device collect (`leaf5-collect` → `leaf5/raw/`)

| File | Role |
|------|------|
| `config.gz` / `kernel_config.txt` | CONFIG authority |
| `device_identity.txt` | uname / getprop |
| `security_runtime.txt` | SELinux, caps, devices |
| `partitions.txt` | by-name; shows boot `dd` denied |
| `kheaders.tar.xz` / `kheaders/` | clues only; may be #244 vs uname #245 |
| `version_compare.txt` | old boot vs runtime diffs |
| `kernel_payload.bin` | from **old** non-runtime boot — do not use for offsets |

## Dangerous / wrong sources

| Path / item | Problem |
|-------------|---------|
| Repo root old `boot.img` (if present) | Historically **#119** / different git hash |
| `raw/kernel_payload.bin` | From old boot, not #245 |
| Other OEM devices’ `target.h` | Different layouts (e.g. OPPO 5.10) |
| kheaders alone for futex_key | Leaf5 binary is **V1**; headers misled once |

## gitignore patterns (careful)

Root `.gitignore` has `vmlinux*` and `*.bin` — host tools named `vmlinux_*.py` get ignored.  
MCP server is named `tools/mcp/kernel_query_server.py` for that reason.

## Symbol / base facts (validated #245)

| Item | Value |
|------|-------|
| Banner markers | `4.19.157`, `g3d47a6619220`, `#245` |
| Approx symbol count | ~121883 |
| Linked `_text` / KIMAGE | `0xffffff8008080000` |
| VA_BITS | 39 |
| Direct map | see `target.h` |

If symbol count collapses or base is nonsense after rebuild, re-run vmlinux-to-elf and check logs.
