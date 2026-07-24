/**
 * test_kgsl_compat.c — Comprehensive KGSL compat path test
 *
 * Compile (64-bit ARM):
 *   aarch64-linux-android35-clang -static -O2 test_kgsl_compat.c -o test_kgsl_compat
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define PER_LINUX32 0x0008

static inline int personality(unsigned long persona) {
    return (int)syscall(SYS_personality, persona);
}

#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOCTL(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

/* Known KGSL ioctls from vmlinux kgsl_ioctl_funcs table */
#define IOCTL(nr,sz) KGSL_IOCTL(nr, sz)

struct kgsl_ibdesc {
    uint64_t gpuaddr;
    uint64_t sizedwords;
};

struct issueibcmds_compat {
    uint32_t drawctxt_id;
    uint32_t flags;
    uint32_t ibdesc_addr;
    uint32_t timestamp;
    uint32_t numibs;
    uint32_t pad[3];  /* pad to 32 bytes */
};

/* ── Test helpers ─────────────────────────────────────────────────── */

static int kgsl_fd = -1;

static void test_ioctl(const char *name, uint32_t cmd, void *arg, int arg_sz) {
    errno = 0;
    int ret = ioctl(kgsl_fd, cmd, arg);
    printf("  %-30s cmd=0x%08x sz=%d ret=%d errno=%d (%s)\n",
           name, cmd, arg_sz, ret, errno,
           ret < 0 ? strerror(errno) : "OK");
}

int main(void) {
    printf("=== KGSL Compat Route Comprehensive Test ===\n\n");

    kgsl_fd = open(KGSL_DEVICE, O_RDWR);
    if (kgsl_fd < 0) {
        printf("ERROR: open %s failed (errno=%d)\n", KGSL_DEVICE, errno);
        return 1;
    }
    printf("[+] %s opened (fd=%d)\n", KGSL_DEVICE, kgsl_fd);
    printf("[+] Process is %d-bit\n\n", (int)(sizeof(void*) * 8));

    /* ── Part 1: Test basic ioctls (no context needed) ──────────── */
    printf("── Part 1: Basic ioctls (no context) ──\n");

    /* GET_VERSION: nr=0x01, size varies */
    { uint8_t buf[256] = {0}; test_ioctl("GET_VERSION_32B",  IOCTL(0x01, 0x20), buf, 0x20); }
    { uint8_t buf[256] = {0}; test_ioctl("GET_VERSION_64B",  IOCTL(0x01, 0x40), buf, 0x40); }

    /* GET_PROPERTY: nr=0x03 */
    { uint8_t buf[256] = {0}; test_ioctl("GET_PROPERTY_32B", IOCTL(0x03, 0x20), buf, 0x20); }
    { uint8_t buf[256] = {0}; test_ioctl("GET_PROPERTY_64B", IOCTL(0x03, 0x40), buf, 0x40); }

    /* SET_PROPERTY: nr=0x02 */
    { uint8_t buf[256] = {0}; test_ioctl("SET_PROPERTY_32B", IOCTL(0x02, 0x20), buf, 0x20); }
    { uint8_t buf[256] = {0}; test_ioctl("SET_PROPERTY_32B8",IOCTL(0x02, 0x08), buf, 0x08); }

    /* ── Part 2: Test DRAWCTXT_CREATE with different layouts ───── */
    printf("\n── Part 2: DRAWCTXT_CREATE variants ──\n");

    /* Standard 8-byte struct */
    { struct { uint32_t flags; uint32_t id; } c = {0, 0};
      test_ioctl("CREATE_8B",          IOCTL(0x13, 0x08), &c, 0x08);
      printf("    → id=%u\n", c.id); }

    /* with flag=1 */
    { struct { uint32_t flags; uint32_t id; } c = {1, 0};
      test_ioctl("CREATE_8B_flags1",   IOCTL(0x13, 0x08), &c, 0x08);
      printf("    → id=%u\n", c.id); }

    /* with flag=0x2 */
    { struct { uint32_t flags; uint32_t id; } c = {2, 0};
      test_ioctl("CREATE_8B_flags2",   IOCTL(0x13, 0x08), &c, 0x08);
      printf("    → id=%u\n", c.id); }

    /* 12-byte struct */
    { struct { uint32_t flags; uint64_t id; } c = {0, 0};
      test_ioctl("CREATE_12B",         IOCTL(0x13, 0x0c), &c, 0x0c); }

    /* 16-byte struct */
    { struct { uint32_t flags; uint32_t pad; uint64_t id; } c = {0, 0, 0};
      test_ioctl("CREATE_16B",         IOCTL(0x13, 0x10), &c, 0x10); }

    /* 24-byte struct (larger) */
    { uint8_t buf[24] = {0};
      test_ioctl("CREATE_24B",         IOCTL(0x13, 0x18), buf, 0x18); }

    /* ── Part 3: Test RB_ISSUEIBCMDS with personality ──────────── */
    printf("\n── Part 3: RB_ISSUEIBCMDS (with/without personality) ──\n");

    struct kgsl_ibdesc ibdesc = {
        .gpuaddr = 0x4141414141414141ULL,
        .sizedwords = 0x4242424242424242ULL,
    };
    struct issueibcmds_compat cmd = {
        .drawctxt_id = 0,  /* try default context */
        .flags = 0,
        .ibdesc_addr = (uint32_t)(uint64_t)(uintptr_t)&ibdesc,
        .timestamp = 0,
        .numibs = 1,
    };

    /* Without personality (64-bit native path) */
    printf("  [64-bit native mode]\n");
    test_ioctl("ISSUEIBCMDS_native",   IOCTL(0x10, 0x20), &cmd, 0x20);
    test_ioctl("ISSUEIBCMDS_32B",      IOCTL(0x10, 0x38), &cmd, 0x38);

    /* With different ctx_id values */
    { struct issueibcmds_compat c2 = cmd; c2.drawctxt_id = 1;
      test_ioctl("ISSUEIBCMDS_ctx1",   IOCTL(0x10, 0x20), &c2, 0x20); }
    { struct issueibcmds_compat c2 = cmd; c2.drawctxt_id = 2;
      test_ioctl("ISSUEIBCMDS_ctx2",   IOCTL(0x10, 0x20), &c2, 0x20); }

    /* With PER_LINUX32 personality */
    printf("  [PER_LINUX32 personality]\n");
    int old_pers = personality(PER_LINUX32);
    printf("  old personality=0x%08x, set to 0x%08x\n", old_pers, PER_LINUX32);

    { struct issueibcmds_compat c2 = cmd; c2.drawctxt_id = 0;
      test_ioctl("ISSUEIBCMDS_PER32_0",IOCTL(0x10, 0x20), &c2, 0x20); }
    { struct issueibcmds_compat c2 = cmd; c2.drawctxt_id = 1;
      test_ioctl("ISSUEIBCMDS_PER32_1",IOCTL(0x10, 0x20), &c2, 0x20); }
    { struct issueibcmds_compat c2 = cmd; c2.drawctxt_id = 2;
      test_ioctl("ISSUEIBCMDS_PER32_2",IOCTL(0x10, 0x20), &c2, 0x20); }

    /* Also try with PER_LINUX32 + invalid ibdesc address (should get EFAULT, not EINVAL) */
    {
        struct issueibcmds_compat c2 = cmd;
        c2.drawctxt_id = 1;
        c2.ibdesc_addr = 0xdead0000;  /* invalid → EFAULT if CFU reached */
        test_ioctl("PER32_badptr_ctx1",IOCTL(0x10, 0x20), &c2, 0x20);
    }

    /* Restore personality */
    personality(old_pers);
    printf("  personality restored to 0x%08x\n", old_pers);

    /* ── Part 4: SUBMIT_COMMANDS path ───────────────────────────── */
    printf("\n── Part 4: SUBMIT_COMMANDS (direct add_ibdesc_list) ──\n");

    /* SUBMIT_COMMANDS: nr=0x3d, size=0x60 (96 bytes) */
    {
        uint8_t buf[96] = {0};
        *(uint32_t *)&buf[0] = 0;  /* drawctxt_id */
        test_ioctl("SUBMIT_64B_native",  IOCTL(0x3d, 0x60), buf, 0x60);
    }

    /* With personality */
    personality(PER_LINUX32);
    {
        uint8_t buf[96] = {0};
        *(uint32_t *)&buf[0] = 1;  /* drawctxt_id */
        test_ioctl("SUBMIT_64B_PER32",   IOCTL(0x3d, 0x60), buf, 0x60);
    }
    personality(old_pers);

    /* ── Part 5: Other ioctls that might work ──────────────────── */
    printf("\n── Part 5: Other ioctls ──\n");
    {
        uint8_t buf[256] = {0};
        /* Try various ioctl numbers to find ones that work without context */
        test_ioctl("CMD_0x00 (GET_VERSION?)",  IOCTL(0x00, 0x20), buf, 0x20);
        test_ioctl("CMD_0x04",                 IOCTL(0x04, 0x20), buf, 0x20);
        test_ioctl("CMD_0x05",                 IOCTL(0x05, 0x20), buf, 0x20);
        test_ioctl("CMD_0x06",                 IOCTL(0x06, 0x20), buf, 0x20);
        /* GPUOBJ_ALLOC? */
        test_ioctl("CMD_0x0f",                 IOCTL(0x0f, 0x18), buf, 0x18);
        /* CMDSTREAM_CREATE? */
        test_ioctl("CMD_0x17",                 IOCTL(0x17, 0x10), buf, 0x10);
    }

    /* ── Part 6: Try with PER_LINUX32 from the start ───────────── */
    printf("\n── Part 6: Full PER_LINUX32 run ──\n");
    personality(PER_LINUX32);
    printf("  personality=0x%08x\n", personality(0xffffffff));

    /* Try context creation with PER_LINUX32 */
    { struct { uint32_t flags; uint32_t id; } c = {0, 0};
      test_ioctl("CREATE_8B_PER32",    IOCTL(0x13, 0x08), &c, 0x08);
      printf("    → id=%u\n", c.id); }

    { struct { uint32_t flags; uint32_t id; } c = {1, 0};
      test_ioctl("CREATE_8Bf1_PER32",  IOCTL(0x13, 0x08), &c, 0x08);
      printf("    → id=%u\n", c.id); }

    /* Try get version with PER_LINUX32 */
    { uint8_t buf[256] = {0};
      test_ioctl("GET_VERSION_PER32",  IOCTL(0x01, 0x20), buf, 0x20); }

    personality(old_pers);

    close(kgsl_fd);
    printf("\n=== Test complete ===\n");
    return 0;
}
