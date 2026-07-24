/**
 * test_personality.c — Test if personality(PER_LINUX32) triggers compat KGSL path
 *
 * Theory: personality(PER_LINUX32) might cause the kernel to handle ioctl
 * as if from a 32-bit process, triggering kgsl_compat_ioctl → 16B CFU path.
 *
 * Compile (64-bit ARM):
 *   aarch64-linux-android35-clang -static -O2 test_personality.c -o test_personality
 *
 * Run:
 *   adb push test_personality /data/local/tmp/
 *   adb shell /data/local/tmp/test_personality
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/* ── personality ──────────────────────────────────────────────────── */
#define PER_LINUX32 0x0008

/* On arm64, personality syscall is __NR_personality = 92 (asm-generic) */
static inline int personality(unsigned long persona) {
    return (int)syscall(SYS_personality, persona);
}

/* ── KGSL ioctl ──────────────────────────────────────────────────── */
#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOCTL(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

#define IOCTL_KGSL_DRAWCTXT_CREATE  KGSL_IOCTL(0x13, 0x08)
#define IOCTL_KGSL_DRAWCTXT_DESTROY KGSL_IOCTL(0x14, 0x04)
#define IOCTL_KGSL_RB_ISSUEIBCMDS   KGSL_IOCTL(0x10, 0x20)
/* Also try the regular 64-bit sized version */
#define IOCTL_KGSL_RB_ISSUEIBCMDS_64BIT  KGSL_IOCTL(0x10, 0x38)  /* 56 bytes with 64-bit ptrs */

/* 32-bit compat ibdesc (16 bytes) */
struct kgsl_ibdesc_compat {
    uint64_t gpuaddr;
    uint64_t sizedwords;
};
/* 64-bit native ibdesc (24 bytes) */
struct kgsl_ibdesc_native {
    uint64_t gpuaddr;
    uint64_t sizedwords;
    uint64_t reserved;
};

/* 32-bit compat issueibcmds struct (20 bytes) */
struct kgsl_issueibcmds_compat {
    uint32_t drawctxt_id;
    uint32_t flags;
    uint32_t ibdesc_addr;
    uint32_t timestamp;
    uint32_t numibs;
};

/* 64-bit native issueibcmds struct (56 bytes) */
struct kgsl_issueibcmds_native {
    uint32_t drawctxt_id;
    uint32_t flags;
    uint64_t ibdesc_addr;
    uint32_t numibs;
    uint32_t timestamp;
    /* padding to 56 bytes */
    uint8_t pad[28];
};

int main(void) {
    printf("=== personality(PER_LINUX32) + KGSL ioctl test ===\n\n");

    /* Step 1: Open /dev/kgsl-3d0 */
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("ERROR: open %s failed (errno=%d: %s)\n",
               KGSL_DEVICE, errno, strerror(errno));
        return 1;
    }
    printf("[+] %s opened (fd=%d)\n", KGSL_DEVICE, fd);

    /* Step 2: Create GPU context (needed for issueibcmds) */
    struct { uint32_t flags; uint32_t drawctxt_id; } ctxt = {0, 0};
    int r = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctxt);
    printf("[+] DRAWCTXT_CREATE: ret=%d id=%u (errno=%d)\n",
           r, ctxt.drawctxt_id, errno);
    if (r < 0) {
        printf("[-] Cannot create GPU context, test invalid\n");
        close(fd);
        return 1;
    }

    /* ── Test 1: 64-bit normal path (baseline) ──────────────────── */
    printf("\n── Test 1: 64-bit normal (no personality) ──\n");
    {
        struct kgsl_issueibcmds_native cmd_native = {0};
        cmd_native.drawctxt_id = ctxt.drawctxt_id;
        cmd_native.numibs = 1;
        int old_pers = personality(0xffffffff); /* read current */
        printf("    current personality: 0x%08x\n", old_pers);

        /* Use native 64-bit struct + 64-bit sized ioctl */
        int ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS_64BIT, &cmd_native);
        printf("    ioctl(64-bit struct, 64-bit op): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");

        /* Try native 64-bit struct + 32-bit compat sized ioctl */
        errno = 0;
        ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd_native);
        printf("    ioctl(64-bit struct, 32-bit op): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");
    }

    /* ── Test 2: 32-bit compat struct, NO personality ───────────── */
    printf("\n── Test 2: compat struct, NO personality ──\n");
    {
        struct kgsl_ibdesc_compat ibdesc = {
            .gpuaddr = 0x0,
            .sizedwords = 0x0,
        };
        struct kgsl_issueibcmds_compat cmd_compat = {
            .drawctxt_id = ctxt.drawctxt_id,
            .flags = 0,
            .ibdesc_addr = (uint32_t)(uint64_t)(uintptr_t)&ibdesc,
            .timestamp = 0,
            .numibs = 1,
        };

        int ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd_compat);
        printf("    ioctl(compat struct, 32-bit op): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");

        /* Also try with EFAULT-triggering ibdesc addr */
        cmd_compat.ibdesc_addr = 0xdead0000; /* invalid */
        ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd_compat);
        printf("    ioctl(compat struct, bad ptr): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");
    }

    /* ── Test 3: personality(PER_LINUX32) ───────────────────────── */
    printf("\n── Test 3: personality(PER_LINUX32) ──\n");
    {
        int old_pers = personality(PER_LINUX32);
        printf("    old personality: 0x%08x → set PER_LINUX32 (0x%08x)\n",
               old_pers, PER_LINUX32);

        int new_pers = personality(0xffffffff); /* read back */
        printf("    new personality: 0x%08x (PER_LINUX32 bit: %s)\n",
               new_pers, (new_pers & PER_LINUX32) ? "YES" : "NO");

        /* Now try compat struct with personality set */
        struct kgsl_ibdesc_compat ibdesc = {
            .gpuaddr = 0x4141414141414141ULL,
            .sizedwords = 0x4242424242424242ULL,
        };
        struct kgsl_issueibcmds_compat cmd_compat = {
            .drawctxt_id = ctxt.drawctxt_id,
            .flags = 0,
            .ibdesc_addr = (uint32_t)(uint64_t)(uintptr_t)&ibdesc,
            .timestamp = 0,
            .numibs = 1,
        };

        int ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd_compat);
        printf("    ioctl(compat, PER_LINUX32): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");

        /* Try with different struct sizes to probe handler selection */
        /* Use native-sized ioctl op (0x38) with compat struct */
        {
            struct kgsl_issueibcmds_native cmd_n64 = {0};
            cmd_n64.drawctxt_id = ctxt.drawctxt_id;
            cmd_n64.numibs = 1;
            errno = 0;
            ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS_64BIT, &cmd_n64);
            printf("    ioctl(64bit struct, PER_LINUX32): ret=%d errno=%d (%s)\n",
                   ret, errno, ret < 0 ? strerror(errno) : "OK");
        }

        /* Restore personality */
        personality(old_pers);
        printf("    personality restored to 0x%08x\n", old_pers);
    }

    /* ── Test 4: Try SUBMIT_COMMANDS (simpler handler, might bypass context check) ── */
    printf("\n── Test 4: SUBMIT_COMMANDS (0xc060093d) ──\n");
    {
        /* SUBMIT_COMMANDS also goes through add_ibdesc_list */
        /* Format unknown — just test dispatch */
        char buf[96] = {0};
        *(uint32_t *)&buf[0] = ctxt.drawctxt_id;
        errno = 0;
        int ret = ioctl(fd, 0xc060093d, buf);
        printf("    SUBMIT_COMMANDS (normal): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");

        /* With personality */
        personality(PER_LINUX32);
        errno = 0;
        ret = ioctl(fd, 0xc060093d, buf);
        printf("    SUBMIT_COMMANDS (PER_LINUX32): ret=%d errno=%d (%s)\n",
               ret, errno, ret < 0 ? strerror(errno) : "OK");
        personality(0xffffffff); /* read, don't change */
    }

    /* Cleanup */
    if (ctxt.drawctxt_id) {
        ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &ctxt.drawctxt_id);
    }
    close(fd);
    printf("\n=== Test complete ===\n");

    return 0;
}
