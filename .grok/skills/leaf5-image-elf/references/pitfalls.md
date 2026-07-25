# Pitfalls (image / ELF / RE)

## Data source

1. **Old boot.img (#119)**  
   Same 4.19.157 series, different git hash (`g87880838aed5`) and build number.  
   Offsets and symbols from it are **invalid** for current Leaf5.

2. **Banner match is not optional**  
   “Almost the same kernel” is not enough. Require `g3d47a6619220` **and** `#245`.

3. **kheaders build # off-by-one**  
   Device kheaders may report #244 while uname is #245. Treat headers as hints.

4. **kheaders futex_key layout lied**  
   Headers suggested non-V1; binary + timing proved **V1**. Always confirm in vmlinux.

5. **Cross-device target.h**  
   OPPO Find N2 (5.10) waiter size 0x50, different cred/pipe offsets — never paste.

## Acquisition

6. **shell dd boot denied**  
   Expected on Leaf5. Use EDL read (or user-approved fastboot), not privilege escalation theater.

7. **EDL write docs**  
   Out of scope. No Magisk, no patched boot in this repo.

8. **Wrong Firehose loader**  
   P6 Pro printgpt is format sample only. Wrong loader can fail or target wrong device.

## Rebuild / ELF

9. **Relative vs absolute base**  
   vmlinux-to-elf may warn about relocation style. Keep both logs; prefer the ELF that yields coherent disasm of known symbols (`commit_creds` loads `0x7d8`/`0x7e0`).

10. **Junk prefix on Image**  
    Tool notes: load address may need tuning if tables do not line up. Re-check with known symbol disasm.

11. **gitignore `vmlinux*`**  
    New scripts named `vmlinux_*.py` will not be committed. Use names like `kernel_query_*.py`.

## Capstone / “decompile”

12. **bl / adrp imm wrong in Capstone 5.x**  
    Hand-decode imm26 / adrp page. MCP `disasm_range` already fixes this.

13. **Nested vs sequential frames**  
    Only nested calls add stack depth. Sequential helpers do not.

14. **Calling it reverse engineering without VA evidence**  
    Claims need: symbol, VA, insn line or register trace — not “looks like mainline”.

## Process

15. **Extract before stages README**  
    New offset conclusions must land in S01 (or relevant node) + `target.h`, not only chat.

16. **Re-running full EDL when boot_a.bin already matches**  
    Wasteful and riskier. Prefer banner re-check + existing ELF unless OTA/kernel OTA changed.
