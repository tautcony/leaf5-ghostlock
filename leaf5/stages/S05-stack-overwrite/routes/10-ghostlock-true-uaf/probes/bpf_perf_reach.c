/**
 * bpf_perf_reach.c — shell 可达性探针（非 GhostLock）
 *
 * 画像: unprivileged_bpf_disabled=0, CONFIG_BPF_SYSCALL=y, perf_event_paranoid=-1
 * 但 SELinux Enforcing 可能直接拒。
 *
 * 只测 open/load 层 errno，不做利用。避免依赖完整 linux/bpf.h（NDK 可能缺字段）。
 *
 * 退出码: 0=至少一项可达; 1=全部拒绝/失败
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#else
#define __NR_bpf 321
#endif
#endif

#ifndef __NR_perf_event_open
#if defined(__aarch64__)
#define __NR_perf_event_open 241
#elif defined(__arm__)
#define __NR_perf_event_open 364
#else
#define __NR_perf_event_open 298
#endif
#endif

#define BPF_MAP_CREATE 0
#define BPF_PROG_LOAD 5
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_MAP_TYPE_HASH 1

/* Minimal bpf_attr for PROG_LOAD / MAP_CREATE (kernel uapi layout prefix) */
struct bpf_attr_min {
  uint32_t map_type; /* also prog_type when prog load */
  uint32_t key_size; /* also insn_cnt */
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t map_flags;
  uint32_t inner_map_fd;
  uint32_t numa_node;
  char map_name[16];
  uint32_t map_ifindex;
  uint32_t btf_fd;
  uint32_t btf_key_type_id;
  uint32_t btf_value_type_id;
  uint32_t btf_vmlinux_value_type_id;
};

/* Alternative overlay for PROG_LOAD (same storage) */
struct bpf_prog_load_attr {
  uint32_t prog_type;
  uint32_t insn_cnt;
  uint64_t insns;
  uint64_t license;
  uint32_t log_level;
  uint32_t log_size;
  uint64_t log_buf;
  uint32_t kern_version;
  uint32_t prog_flags;
};

struct bpf_insn {
  uint8_t code;
  uint8_t dst_src;
  int16_t off;
  int32_t imm;
};

static void print_result(const char *name, long ret, int err) {
  printf("%-32s ret=%ld errno=%d (%s)\n", name, ret, err,
         err ? strerror(err) : "ok");
}

int main(void) {
  int any_ok = 0;
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("=== bpf_perf_reach (shell capability surface) ===\n");
  printf("uid=%d euid=%d\n", getuid(), geteuid());

  /* BPF_PROG_LOAD: r0=0; exit */
  {
    struct bpf_insn insns[2] = {
        {.code = 0xb7, .dst_src = 0, .off = 0, .imm = 0},
        {.code = 0x95, .dst_src = 0, .off = 0, .imm = 0},
    };
    char log_buf[256];
    char lic[] = "GPL";
    struct bpf_prog_load_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (uint64_t)(uintptr_t)insns;
    attr.license = (uint64_t)(uintptr_t)lic;
    attr.log_level = 1;
    attr.log_size = sizeof(log_buf);
    attr.log_buf = (uint64_t)(uintptr_t)log_buf;
    memset(log_buf, 0, sizeof(log_buf));
    errno = 0;
    long r = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    print_result("bpf(BPF_PROG_LOAD)", r, r < 0 ? e : 0);
    if (r >= 0) {
      any_ok = 1;
      close((int)r);
    } else if (log_buf[0]) {
      printf("  bpf log: %.200s\n", log_buf);
    }
  }

  /* BPF_MAP_CREATE */
  {
    struct bpf_attr_min attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    errno = 0;
    long r = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    int e = errno;
    print_result("bpf(BPF_MAP_CREATE)", r, r < 0 ? e : 0);
    if (r >= 0) {
      any_ok = 1;
      close((int)r);
    }
  }

  /* perf_event_open software */
  {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    errno = 0;
    long r = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    int e = errno;
    print_result("perf_event_open(SW_CPU_CLOCK)", r, r < 0 ? e : 0);
    if (r >= 0) {
      any_ok = 1;
      close((int)r);
    }
  }

  /* perf_event_open HW (may fail for PMU) */
  {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    errno = 0;
    long r = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    int e = errno;
    print_result("perf_event_open(HW_CYCLES)", r, r < 0 ? e : 0);
    if (r >= 0) {
      any_ok = 1;
      close((int)r);
    }
  }

  printf("\n=== RESULT any_reachable=%d ===\n", any_ok);
  printf("EACCES/EPERM → SELinux or capability; ENOSYS → no syscall\n");
  return any_ok ? 0 : 1;
}
