#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define DRM_IOCTL_BASE 'd'
#define DRM_IOWR(nr,size) _IOC(_IOC_READ|_IOC_WRITE, DRM_IOCTL_BASE, nr, size)

int main(void) {
    printf("=== DRM device test ===\n");

    int card = open("/dev/dri/card0", O_RDWR);
    printf("card0: fd=%d (errno=%d)\n", card, errno);

    int render = open("/dev/dri/renderD128", O_RDWR);
    printf("renderD128: fd=%d (errno=%d)\n", render, errno);

    if (render >= 0) {
        /* DRM_IOCTL_VERSION: struct drm_version with 8-byte pointers */
        struct { int32_t major; int32_t minor; int32_t patch;
                 uint32_t name_len; uint32_t name_ptr;
                 uint32_t date_len; uint32_t date_ptr;
                 uint32_t desc_len; uint32_t desc_ptr; } ver = {0};
        int r = ioctl(render, DRM_IOWR(0x00, 0x30), &ver);
        printf("  VERSION(0x30): ret=%d errno=%d major=%d minor=%d patch=%d\n",
               r, errno, ver.major, ver.minor, ver.patch);

        /* Try native 64-bit struct size (40 bytes: 3*4B + 3*(4Bpad+8B) = 48) */
        struct { int32_t major; int32_t minor; int32_t patch; int32_t pad;
                 uint64_t name_len; uint64_t name_ptr;
                 uint64_t date_len; uint64_t date_ptr;
                 uint64_t desc_len; uint64_t desc_ptr; } ver64 = {0};
        r = ioctl(render, DRM_IOWR(0x00, 0x38), &ver64);
        printf("  VERSION(0x38): ret=%d errno=%d\n", r, errno);

        /* Probe various ioctl numbers */
        for (int nr = 0; nr < 0x60; nr++) {
            uint8_t buf[128] = {0};
            uint32_t cmd = _IOC(_IOC_READ|_IOC_WRITE, DRM_IOCTL_BASE, nr, 0x30);
            errno = 0;
            r = ioctl(render, cmd, buf);
            if (errno != 25 && errno != 22) { /* interesting! */
                printf("  nr=0x%02x cmd=0x%08x: ret=%d errno=%d\n", nr, cmd, r, errno);
            }
        }
    }

    if (card >= 0) close(card);
    if (render >= 0) close(render);
    return 0;
}
