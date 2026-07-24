#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return 1; }
    printf("fd=%d\n", fd);

    /* Try SET_PROPERTY with compat command code (0xc00c0902, size=12) */
    /* The compat struct has 32-bit pointers: type (4B), value_ptr (4B), sizebytes (4B) */
    struct { uint32_t type; uint32_t value_ptr; uint32_t sizebytes; } sp = {0};
    char valbuf[256] = {0};
    sp.type = 0;
    sp.value_ptr = (uint32_t)(uintptr_t)valbuf;
    sp.sizebytes = 4;
    
    /* Compat SET_PROPERTY: 0xc00c0902 */
    int r = ioctl(fd, 0xc00c0902, &sp);
    printf("SETPROP(compat) type=0: ret=%d errno=%d (%s)\n", r, errno, strerror(errno));

    /* Try with different types */
    for (int t = 0; t < 10; t++) {
        sp.type = t;
        errno = 0;
        r = ioctl(fd, 0xc00c0902, &sp);
        if (errno != 19) { /* not ENODEV */
            printf("SETPROP(compat) type=%d: ret=%d errno=%d\n", t, r, errno);
        }
    }

    /* Now try context creation again */
    struct { uint32_t flags; uint32_t id; } c = {0x00100000, 0};
    r = ioctl(fd, 0xc0080913, &c);
    printf("CREATE: ret=%d id=%u errno=%d\n", r, c.id, errno);

    close(fd);
    return 0;
}
