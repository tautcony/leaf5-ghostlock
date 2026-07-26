# Aarch64-specific GhostLock Exploitation Analysis

> **Date**: 2026-07-26
> **Context**: Terminal B closed (shell GhostLock→fops write chain not achieved).
> **Goal**: Identify aarch64-specific root causes + new exploitation strategies.
> **Status**: ✅ Complete — **rb_erase unreachable from sched_setattr PI walk on this Qualcomm 4.19 build**. See PROCESS_LOG §57–§58 for crash probe evidence.

---

## 0. Executive Summary (2026-07-26)

Crash probe testing on device #245 definitively proved:

| Probe | Method | Result | Interpretation |
|-------|--------|--------|----------------|
| trylock reach | `PSELECT_LOCK_CRASH=1` (lock=0x41) | **Kernel panic** | PI walk enters, reads pi_blocked_on, calls trylock ✅ |
| rb_erase reach | `PSELECT_PARENT_CRASH=1` (parent=0x41/0xdead/0x4141...) × 10+ tests, all prio values 80–139 | **Device survived** | rb_erase is NEVER called ❌ |

The PI walk exits between `_raw_spin_trylock` success and the `rb_erase_cached` call at `0xffffff80080ca1d8`. The aarch64 disassembly shows `w28` controls this branch; while `w28=1` at entry, the actual control flow on this Qualcomm kernel does not reach `rb_erase_cached` through the `sched_setattr` consumer.

**This is a kernel-internal control flow issue, not a user-controllable parameter.** All tested parameter combinations (priority, lock owner, shape, SHIFT) produce the same result.

---

## 1. Root Cause: Why the rb_erase write fails

### 1.1 The BLACK-node rebalancing problem (HIGH confidence)

The current exploit code at `exploit/src/fops.c:192`:

```c
parent = (target >= 8) ? ((target - 8) | 1ull) : 1ull;
```

The `| 1ull` sets `rb_color(node) == RB_BLACK`. In Linux's `rb_erase`, a BLACK
node triggers `__rb_erase_color()` which traverses up the parent chain performing
rotations and color flips. Since our fake pi_tree_entry is NOT part of any valid
rb-tree, this rebalancing:

1. Follows invalid parent chains (parent = target - 8, but target points to
   kernel data with arbitrary contents, not a valid rb_node)
2. Reads and writes to unpredictable kernel addresses near the "parent" chain
3. Likely corrupts kernel state before the intended store lands
4. May crash silently within the PI walk or produce side effects that cause
   the subsequent write to fail

**This is the single most likely reason why `sched_setattr success=1` but
`uts hit=0` and `cfi pwrite errno=22` across ALL tested SHIFT/shape variants.**

The test matrix (Terminal B) proves this:
- All LOCK_SHAPE variants (0/1/2) → same errno=22
- All SHIFT values (13-17) → same errno=22
- All PI consumers (sched_setattr/setpriority/nice/...) → same result
- The ONLY variant that causes observable kernel effect is `PI_CONSUMER=all`
  (multiple concurrent PI walks) which triggers panic

The fact that sched_setattr returns 0 but no store is observed is consistent
with BLACK-node rebalancing corrupting state in ways that:
- Don't crash immediately (the PI walk completes)
- But prevent the rb_erase store from landing where intended
- Or cause the store to be overwritten by subsequent operations

### 1.2 The fix: RED-node rb_erase (one-line change)

On aarch64, Linux 4.19's `rb_erase` skips rebalancing entirely for RED nodes:

```c
// kernel/lib/rbtree.c
void rb_erase(struct rb_node *node, struct rb_root *root) {
    struct rb_node *child, *parent;
    int color;

    if (!node->rb_left)
        child = node->rb_right;
    else if (!node->rb_right)
        child = node->rb_left;       // ← our case: right=NULL, child=left
    else { /* two children: complex case */ }

    parent = rb_parent(node);     // reads node->__rb_parent_color & ~3
    color = rb_color(node);       // reads node->__rb_parent_color & 1

    if (child)
        rb_set_parent(child, parent);  // writes parent to child+0

    if (parent) {
        if (parent->rb_left == node)
            parent->rb_left = child;
        else
            parent->rb_right = child;  // ← WRITES child TO target!
    }

    if (color == RB_BLACK)             // ← SKIPPED for RED nodes!
        __rb_erase_color(child, parent, root);
}
```

**With RED node (color=0):**
- `rb_set_parent(child, parent)` → writes `parent` to `child->__rb_parent_color`
- `parent->rb_right = child` → writes `child` value to `target`
- `__rb_erase_color` → SKIPPED — no rebalancing, no tree traversal

**Proposed code change in `fops.c`:**

```diff
-    parent = (target >= 8) ? ((target - 8) | 1ull) : 1ull;
+    parent = (target >= 8) ? (target - 8) : 0;   // RED node: no rebalancing
```

### 1.3 The child corruption: rb_set_parent side effect

Even with RED node, `rb_set_parent(child, parent)` writes `parent` to
`*(child + 0)`. This means the first 8 bytes of whatever `child` points to
get corrupted with the parent address (waiter_task + target_offset - 8).

**For target = ashmem_misc.fops (current approach):**
- child = fake_fops (spray page address)
- rb_set_parent writes to fake_fops->owner (offset 0 of file_operations)
- fake_fops->owner gets corrupted ← but try_module_get handles non-NULL owner gracefully (returns false for non-live modules)
- Survivable! fops still functional for configfs read/write

**For target = init_uts_ns.sysname (UTS oracle):**
- child = UTS_ORACLE_MARKER_LE (0x454c4341524f4c47 = "GLORACLE")
- rb_set_parent writes to *(0x454c4341524f4c47) — this is NOT a valid kernel address!
- Would cause a page fault → kernel oops/panic
- **This explains why WRITE_ORACLE=uts + zero-lock (empty_zero_page) panics!**

**For target = waiter_task->cred (cred overwrite approach):**
- child = spray_fake_cred (spray page address with uid=0 cred)
- rb_set_parent writes parent (waiter_task + offset) to fake_cred + 0
- corrupts fake_cred->usage (4B) + fake_cred->uid (4B)
- uid gets upper 32 bits of parent = 0xffffff80 → uid = 0xffffff80 (NOT root!)
- **BLOCKED: rb_set_parent corrupts uid field of fake cred**

### 1.4 Workaround for child corruption

**Option A: Use child=0 (NULL write)**
If both rb_left and rb_right are 0:
- child = NULL → no rb_set_parent call
- parent->rb_right = NULL → writes 8 zero bytes to target
- No child corruption at all
- But can only write NULL, not arbitrary values

**Option B: Child = spray page address**
- The corrupted 8 bytes at child+0 are on the spray page (we own it)
- For fops overwrite: fops->owner corruption is survivable
- For cred overwrite: need to handle uid corruption (see §3 below)

**Option C: Use tree_entry (first rb_erase) for the write, make pi_tree_entry safe**
- tree_entry rb_erase: writes to target (tree_parent = target - 8)
- pi_tree_entry rb_erase: writes to spray (pi_parent = spray_addr - 8)
- Both rb_erase calls happen during the PI walk

---

## 2. Aarch64-specific Exploitation Advantages

### 2.1 No kernel CFI (CONFIG_CFI_CLANG not set)
Function pointer overwrites work without CFI checks. Any fops function pointer
overwrite is directly callable.

### 2.2 No KPTI (CONFIG_UNMAP_KERNEL_AT_EL0 not set)
After gaining kernel code execution (e.g., via fops hijack), return to userspace
is straightforward — no trampoline needed.

### 2.3 No PAN? (needs verification)
If `CONFIG_ARM64_PAN` is not set, the kernel can directly access userspace
memory without `uaccess_*` helpers. This would allow placing controlled data
in userspace for the PI walk to dereference.

### 2.4 `sp_el0` as current pointer (the bug mechanism)
The `remove_waiter` bug uses aarch64's `mrs x20, sp_el0` to get `current`,
then clears `current->pi_blocked_on` instead of `waiter->task->pi_blocked_on`.
This is the aarch64-specific realization of the CVE.

### 2.5 39-bit VA space
The kernel direct map is 16GB (0xffffff8000000000 - 0xffffffc000000000),
providing a predictable address range for spray pages.

---

## 3. New Exploitation Strategies (Beyond Terminal B)

### Strategy A: RED-node + NULL write → disable SELinux (EASIEST)

**Concept**: Write 0 to `selinux_state.enforcing` using rb_erase with child=NULL.

**Target**: `data_addr(SELINUX_STATE) + enforcing_offset`

**Prerequisites**:
- Determine exact offset of `enforcing` in `selinux_state` (4.19 + Qualcomm)
- With RED node, both children NULL → clean NULL write, no rebalancing

**Advantages**:
- No child corruption (child=NULL → no rb_set_parent)
- Disables SELinux enforcement → opens BPF, ioctl, and other previously blocked paths
- Combined with existing GhostLock chain, enables alternative write primitives
- 8 zero bytes written atomically

**Risk**: Wrong offset → only zeros adjacent fields, doesn't crash

**Code diff** (for target = selinux_state):
```c
// pi_tree_entry: MUST be RED node (no |1)
parent = (selinux_state_addr >= 8) ? (selinux_state_addr - 8) : 0;  // NO |1!
right = 0;   // node->rb_right = NULL
left = 0;    // node->rb_left = NULL → child = NULL
// rb_erase: parent->rb_right = NULL → writes 0 to selinux_state_addr
```

### Strategy B: RED-node + cred pointer overwrite (MOST POWERFUL)

**Concept**: Overwrite waiter's `real_cred` or `cred` pointer to point to a
spray page containing a fake credential structure.

**Problem**: rb_set_parent corrupts child's uid (see §1.3)

**Workaround — Two-step approach**:
1. First rb_erase (tree_entry): Write a "uid-corrected" value to a staging
   area on spray. Set up tree_parent = (staging_area - 8), tree_left = 0,
   tree_right = 0. This writes 0 to staging_area+0.

Wait, that doesn't help either. Let me think...

**Better workaround — Padding cred struct**:
Place the fake cred at `spray_addr + 4` instead of `spray_addr`. Then:
- child = spray_addr (points to pre-cred padding)
- rb_set_parent writes parent to spray_addr[0:8] (our padding, don't care)
- The actual cred being pointed to is at spray_addr + 4
  - uid at spray_addr + 4 + 4 = spray_addr + 8 → NOT corrupted!
  - usage at spray_addr + 4 + 0 = spray_addr + 4 → first 4 bytes of parent (don't care)

Wait, cred->uid is at +0x04 from the start of the cred struct. If the cred starts
at spray_addr + 4:
- spray_addr + 4 + 0: usage (4 bytes) = lower 32 bits of parent (from corruption)
- spray_addr + 4 + 4: uid (4 bytes) = upper 32 bits of parent → STILL CORRUPTED!

The problem persists because uid is always at offset 4 from the child pointer.

**Actual workaround**: Set left child to NOT point to the cred directly.
Instead, use a write to a DIFFERENT target that achieves root indirectly.

**Alternative B1**: Overwrite the waiter's SELinux security blob pointer.
- target = waiter_task + CRED_SECURITY_OFF (0x78 in cred struct)
- But we can't target inside cred because cred ptr isn't known
- Need to target inside task_struct directly

**Alternative B2**: Overwrite `selinux_state.enforcing` (same as Strategy A)
- NULL write (child=0) avoids ALL corruption issues
- Most practical aarch64 approach

**Alternative B3**: Overwrite the waiter's `seccomp.mode` at task+0x888
- target = waiter_task_direct_map + 0x888
- child = 0 → disables seccomp
- Limited benefit: seccomp is already not the main blocker

### Strategy C: PI walk sequence manipulation (MOST SUBTLE)

**Concept**: The PI walk does TWO rb_erase calls. Use the first for a safe
no-op and the second for the useful write.

Currently:
1. First rb_erase (tree_entry from lock->waiters): parent = (fake_lock+0x08), writes to spray
2. Second rb_erase (pi_tree_entry from task->pi_waiters): parent = (target-8)|1, writes to target (BLACK → rebalancing!)

Fix:
1. First rb_erase: parent = (target-8) RED, writes value to target
2. Second rb_erase: parent = (fake_lock+0x10) RED, child=0, safe write to spray

This way the FIRST rb_erase does the useful work before any potential PI walk
early-exit condition.

### Strategy D: Fake cred on spray with uid post-patch (COMPLEX)

**Concept**: Accept the uid corruption from rb_set_parent, then use a second
write primitive to fix the uid.

The flow:
1. rb_erase writes spray_fake_cred to waiter_task->cred
2. rb_set_parent corrupts spray_fake_cred + 0..7 (usage + uid)
3. BUT: uid was originally set to 0 in our spray... 

Wait, this is the issue. We SET uid=0 in the spray. Then rb_set_parent
OVERWRITES uid with garbage. We can't "fix after" because the cred is
already corrupted.

**Actual solution**: Place the fake cred such that the FIRST 8 bytes
are NOT {usage, uid}. This requires:
- Custom layout where uid is at a different offset
- OR write to a pointer slot that skips the first 8 bytes

In the cred struct on 4.19 aarch64:
```c
struct cred {
    atomic_t usage;     // +0x00 (4B)
    kuid_t uid;         // +0x04 (4B)  ← gets corrupted!
    kgid_t gid;         // +0x08
    ...
    void *security;     // +0x78 [BIN]
};
```

If we write to `task_struct + 0x7d8` (real_cred offset), the value is a
POINTER. The pointer's first 8 bytes are not relevant — what matters is
the cred struct that the pointer points to.

So rb_set_parent writes to *(fake_cred + 0) = parent. This corrupts fake_cred's
usage and uid. But the pointer write to task_struct->real_cred succeeds (the
pointer value is unchanged by rb_set_parent).

But then the uid is WRONG (0xffffff80).

**The fundamental issue**: rb_erase writes a pointer VALUE to target. The
rb_set_parent writes TO that pointer's target. If the pointer points to our
fake cred, the fake cred's uid gets corrupted.

**There is no clean solution for direct cred overwrite via rb_erase with
non-NULL child.** The NULL write approach (Strategy A) is the cleanest.

---

## 4. Concrete Action Plan

### Phase 1: Verify the RED-node fix (minimal change)

1. Change `fops.c:192` from `| 1ull` to no color bit:
```c
parent = (target >= 8) ? (target - 8) : 0;
```

2. Test with `WRITE_ORACLE=uts` (same as §55 matrix but with RED node)
   - Expected: Either `uname hit=1` (GLORACLE appears) or different errno
   - If hit=1: BLACK-node rebalancing WAS the problem → proceed to Phase 2

3. Test with default (fops) path
   - Expected: `cfi pwrite errno != 22` or `cfi_stage_done=1`

### Phase 2: If RED-node fix produces clean writes

1. **NULL write to selinux_state.enforcing** (disable SELinux):
   - Set WRITE_ORACLE to a new "selinux" mode
   - Target: data_addr(SELINUX_STATE) + enforcing_offset
   - Need to determine `enforcing` offset in struct selinux_state on 4.19
   - Both tree_entry children = NULL → clean NULL write
   - Verified by reading /sys/fs/selinux/enforce after exploit

2. **If SELinux disabled**: Open BPF, retry fops overwrite with BPF-assisted
   precision, or directly use KGSL/binder paths that were blocked by SELinux

### Phase 3: True cred overwrite approach

If RED-node fix works and we have a clean write primitive:

1. Allocate a fake cred on spray page
2. Accept uid corruption in first 8 bytes
3. Place the REAL uid at spray_cred + 8 (as gid, but also set uid at +4 to a
   non-zero but acceptable value)
4. OR: Use the write to target a DIFFERENT kernel slot that doesn't have
   the uid-at-offset-4 problem

**Alternative cred approach**: Instead of rb_erase, use the
`rt_mutex_setprio` path which writes to `task->prio` and `task->normal_prio`.
If task = a real task_struct (not spray), these writes modify the real task.
Combined with a pipe physrw (once fops is overwritten), we can read/write
any kernel memory including cred structures.

---

## 5. Aarch64 Pipeline Checklist

| Step | Status | Blocked by |
|------|--------|------------|
| Kernelsnitch (S02) | ✅ | — |
| sk_buff spray (S03) | ✅ | — |
| EDEADLK priming (S04) | ✅ errno=35 | — |
| Pselect reclaim | ✅ SHIFT=+15 | — |
| PI walk consumer | 🔄 success=1, no store | BLACK-node rebalancing |
| RED-node rb_erase | ⚠️ PROPOSED | needs device test |
| NULL-write SELinux | ⚠️ PROPOSED | needs RED-node fix + offset |
| Fops overwrite | ⚠️ PROPOSED | needs RED-node fix |
| Pipe physrw (S07) | ⚠️ code ready | needs fops overwrite |
| Cred patch → root | ⚠️ code ready | needs physrw |

---

## 6. Immediate Next Action

**Compile and test the RED-node fix** (one-line change in `fops.c`):

```diff
@@ -189,7 +189,7 @@
   } else {
     /* shape 0: write value → *target via parent->rb_right */
-    parent = (target >= 8) ? ((target - 8) | 1ull) : 1ull;
+    parent = (target >= 8) ? (target - 8) : 0;
     right = 0;
     left = value;
   }
```

And in `util.c` for the spray page waiter (W0), also remove `| 1` if present.

Run with `WRITE_ORACLE=uts PSELECT_LOCK_SHAPE=0 ROUTE_WAIT_SECONDS=4`.
If `uname.sysname` changes to contain "GLORACLE", the RED-node fix works.
