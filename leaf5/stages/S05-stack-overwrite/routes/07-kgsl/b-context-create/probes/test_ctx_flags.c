#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOCTL(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

#define KGSL_CONTEXT_TYPE_GL      (1u << 20)
#define KGSL_CONTEXT_TYPE_CL      (2u << 20)
#define KGSL_CONTEXT_TYPE_VK      (5u << 20)
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002u
#define KGSL_CONTEXT_PREAMBLE      0x00000010u

int main(void) {
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) { printf("ERROR: open failed\n"); return 1; }
    printf("fd=%d\n", fd);

    /* Documented success on Leaf5: PREAMBLE|NO_GMEM_ALLOC = 0x12 */
    uint32_t flag_tests[] = {
        0,
        KGSL_CONTEXT_PREAMBLE,                          /* 0x10 alone */
        KGSL_CONTEXT_NO_GMEM_ALLOC,                     /* 0x02 alone */
        KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC, /* 0x12 */
        0x12u,
        KGSL_CONTEXT_TYPE_GL, KGSL_CONTEXT_TYPE_CL, KGSL_CONTEXT_TYPE_VK,
        KGSL_CONTEXT_TYPE_GL | 0x2, KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PREAMBLE,
        0x00100001u, 0x20000000u,
    };

    for (int i = 0; i < sizeof(flag_tests)/sizeof(flag_tests[0]); i++) {
        struct { uint32_t flags; uint32_t id; } c = {flag_tests[i], 0};
        errno = 0;
        int r = ioctl(fd, KGSL_IOCTL(0x13, 0x08), &c);
        printf("CREATE flags=0x%08x: ret=%d id=%u errno=%d (%s)\n",
               flag_tests[i], r, c.id, errno, r<0?strerror(errno):"OK");
        if (r == 0) {
            printf("  *** SUCCESS! ctx_id=%u ***\n", c.id);
            /* Destroy it */
            ioctl(fd, KGSL_IOCTL(0x14, 0x04), &c.id);
            break;
        }
    }

    close(fd);
    return 0;
}
