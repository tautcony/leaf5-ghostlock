# GhostLock full chain: popsicle vs Leaf5

See parent `README.md` for the authoritative matrix. This file is a short side-by-side.

| Step | Mechanism | popsicle (6.12) | Leaf5 (4.19 #245) |
|------|-----------|-----------------|-------------------|
| T0 | Leak | KernelSnitch-class | ✅ S02 KernelSnitch |
| T1 | EDEADLK requeue | 3-futex | ✅ errno=35 on device |
| T2 | Waiter returns | yes | ✅ ETIMEDOUT (no immediate wake) |
| T3 | Stack reclaim | **pselect** fd_set | adjtimex 208B ✅; pselect SHIFT **+15** geometry OK |
| T4 | PI walk | sched_setattr | ✅ causes **kernel_panic** after 0x41 paint |
| T5 | Root | direct init_cred + SELinux | ⛔ shaped fake not yet |

**Leaf5 CORRECTED**: `waiter->task @ stack_top − 0x168`; old KSP0−0x2B0 / SHIFT=−46 obsolete for this path.
