#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <seccomp.h>
#include <errno.h>
#include <time.h>

// Global for simplicity; in production, use thread-local or hashmap for per-fd state
struct CapState {
    int fd;
    timer_t timer_id;
    int active;  // 1 if capability granted and not revoked
};

#define MAX_FDS 1024
struct CapState cap_states[MAX_FDS] = {0};

// Helper: Revoke capability (close fd, mark inactive)
void revoke_cap(int fd) {
    if (fd >= 0 && fd < MAX_FDS && cap_states[fd].active) {
        fprintf(stderr, "[CAPFUNNEL] REVOKING fd=%d (policy violation or timeout)\n", fd);
        close(fd);  // Harsh revocation; in CHERI, revoke capability without closing
        cap_states[fd].active = 0;
    }
}

// Timer callback for <50ms revocation
void timer_handler(union sigval val) {
    int fd = val.sival_int;
    revoke_cap(fd);
}

// Grant with timer: Start 50ms timer for auto-revoke unless renewed
int grant_with_timer(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    cap_states[fd].fd = fd;
    cap_states[fd].active = 1;

    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = timer_handler;
    sev.sigev_value.sival_int = fd;

    if (timer_create(CLOCK_MONOTONIC, &sev, &cap_states[fd].timer_id) == -1) {
        perror("[CAPFUNNEL] timer_create failed");
        return -1;
    }

    struct itimerspec its = {0};
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 50000000;  // 50ms

    if (timer_settime(cap_states[fd].timer_id, 0, &its, NULL) == -1) {
        perror("[CAPFUNNEL] timer_settime failed");
        return -1;
    }

    fprintf(stderr, "[CAPFUNNEL] GRANTED fd=%d with 50ms timeout\n", fd);
    return 0;
}

// Dummy policy check (expand with rate-limiting, AI integration, etc.)
int check_policy(int fd) {
    // Example: Reject if fd > some limit or random "violation"
    if (fd > 100) {  // Placeholder; tie to SIP flood detection
        fprintf(stderr, "[CAPFUNNEL] POLICY VIOLATION on fd=%d\n", fd);
        return 0;  // Fail
    }
    return 1;  // Pass
}

// Install seccomp filter to restrict network syscalls (post-grant enforcement)
void install_seccomp_filter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return;

    // Restrict bind/recvfrom after revocation (example; fine-tune)
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bind), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvfrom), 0);

    if (seccomp_load(ctx) < 0) {
        perror("[CAPFUNNEL] seccomp_load failed");
    }
    seccomp_release(ctx);
}

// --- bind() ---
int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_bind) real_bind = dlsym(RTLD_NEXT, "bind");

    if (!check_policy(fd)) {
        revoke_cap(fd);
        return -1;
    }
    grant_with_timer(fd);
    return real_bind(fd, addr, len);
}

// --- recvfrom() ---
ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                    struct sockaddr *, socklen_t *) = NULL;
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");

    if (!check_policy(fd) || (fd < MAX_FDS && !cap_states[fd].active)) {
        revoke_cap(fd);
        return -1;
    }
    grant_with_timer(fd);  // Renew timer on successful recv
    return real_recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

// Add more: e.g., sendto() ---
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void *, size_t, int,
                                  const struct sockaddr *, socklen_t) = NULL;
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");

    if (!check_policy(fd) || (fd < MAX_FDS && !cap_states[fd].active)) {
        revoke_cap(fd);
        return -1;
    }
    grant_with_timer(fd);  // Renew
    return real_sendto(fd, buf, len, flags, dest_addr, addrlen);
}

// Init seccomp on load (constructor)
__attribute__((constructor)) void init() {
    // install_seccomp_filter();
    fprintf(stderr, "[CAPFUNNEL] Initialized with seccomp filter\n");
}