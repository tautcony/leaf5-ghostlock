---
name: leaf5-check-work
description: >
  Verify Leaf5 GhostLock changes: target.h consistency, no magic offsets in
  probes, stages README status, build of touched probes, and doc/code sync.
  Use after implementing probes or exploit changes, before commit, or when the
  user asks to check work, verify, self-verify, /leaf5-check-work, or /check
  in this repo. Prefer this over generic check-work for leaf5-ghostlock.
---

# Leaf5 check-work

Run after non-trivial edits. Report findings; fix only if the user asked to fix.

## 1. Scope the diff

```bash
git status
git diff
git diff --stat
```

List touched paths under:

- `exploit/targets/onyx-leaf5/target.h`
- `exploit/src/`
- `leaf5/stages/`
- `leaf5/PROCESS_LOG.md`
- `.grok/` / `tools/mcp/` (tooling only)

## 2. Constants / magic numbers

- New structure offsets or sizes should live in **`target.h`**, not raw hex in probe `.c` unless clearly local and documented.
- Flag any new `[EST]` on a critical path without a verification plan.
- If `target.h` changed: matching stage node or PROCESS_LOG mention should exist (or call out the gap).

## 3. Stages discipline

For each new/changed probe:

- [ ] Under `leaf5/stages/.../probes/` (or analysis/), not only under `exploit/`
- [ ] Parent node `README.md` mentions the file and result
- [ ] No silent reopen of a matrix ❌ without CORRECTED + new evidence
- [ ] Chinese/English report quality not required in code; **evidence** required in README

## 4. Build checks

If C probes changed:

```bash
cd leaf5/stages
make SRC=<changed.c> BITS=64   # and/or BITS=32 if relevant
```

If exploit sources changed:

```bash
# Prefer docker if NDK local missing
make exploit
# or: cd exploit && ./docker-build.sh
```

Record compile success/fail. Do not push to device unless user wants a live check.

## 5. Optional device check

Only if device is connected and user expects runtime validation:

1. `adb_uname_check` / `uname -a` match #245
2. Run the specific probe once
3. Do not stress-loop crash paths

## 6. Docs sync

| Change | Expected doc touch |
|--------|--------------------|
| Offset / depth conclusion | stage node README (+ PROCESS_LOG if milestone) |
| Route open/close | `leaf5/stages/README.md` matrix if top-level status flips |
| New workflow tools | brief note in `tools/mcp/README.md` or AGENTS if user-facing |

Do not dump process history into `AGENTS.md`.

## 7. Output template

```text
## Leaf5 check-work

### Scope
- files: ...

### Pass
- ...

### Issues
- [P0/P1/P2] ...

### Builds
- probe X BITS=64: ok/fail
- exploit: ok/fail/skipped

### Suggested fixes
- ...
```

Severity:

- **P0** — wrong constant on critical path, broken build, runtime/image mismatch ignored
- **P1** — missing stage README update, magic number drift
- **P2** — style, optional docs
