#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_bind) real_bind = dlsym(RTLD_NEXT, "bind");
    fprintf(stderr, "[CAPFUNNEL] bind() GRANTED fd=%d\n", fd);
    return real_bind(fd, addr, len);
}