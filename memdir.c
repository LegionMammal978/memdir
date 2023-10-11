#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/wait.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdnoreturn.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "memdir.h"

#define SET_ERR(cond) ((cond) && (err = -errno, true))

#if defined(__mips__)
#define K__NSIG 128
#else
#define K__NSIG 64 // asm-generic/signal.h:7
#endif

#define K_MAX_ERRNO 4095 // linux/err.h:18
#define K_PROC_SUPER_MAGIC 0x9fa0 // linux/magic.h:80
#define K_MFD_CLOEXEC 0x1U // linux/memfd.h:8
#define K_MOVE_MOUNT_F_EMPTY_PATH 0x4 // linux/mount.h:72
#define K_MOVE_MOUNT_T_EMPTY_PATH 0x40 // linux/mount.h:75
#define K_FSOPEN_CLOEXEC 0x1 // linux/mount.h:82
#define K_FSCONFIG_SET_STRING 1 // linux/mount.h:97
#define K_FSCONFIG_CMD_CREATE 6 // linux/mount.h:102
#define K_FSMOUNT_CLOEXEC 0x1 // linux/mount.h:109
#define K_PROC_ROOT_INO 1U // linux/proc_ns.h:42

typedef struct { // asm-generic/signal.h:61
    unsigned long sig[K__NSIG / (sizeof(long) * 8)];
} k_sigset_t;

struct k_clone_args { // linux/sched.h:92
    alignas(8) uint64_t flags;
    alignas(8) uint64_t pidfd;
    alignas(8) uint64_t child_tid;
    alignas(8) uint64_t parent_tid;
    alignas(8) uint64_t exit_signal;
    alignas(8) uint64_t stack;
    alignas(8) uint64_t stack_size;
    alignas(8) uint64_t tls;
};

static pid_t k_clone3(struct k_clone_args *uargs, size_t size) {
#ifdef SYS_clone3
    return syscall(SYS_clone3, uargs, size);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_close_range(unsigned int fd, unsigned int max_fd, unsigned int flags) {
#ifdef SYS_close_range
    return syscall(SYS_close_range, fd, max_fd, flags);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_dup3(unsigned int oldfd, unsigned int newfd, int flags) {
#ifdef SYS_dup3
    return syscall(SYS_dup3, oldfd, newfd, flags);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_fsconfig(int fd, unsigned int cmd, const char *key, const void *value, int aux) {
#ifdef SYS_fsconfig
    return syscall(SYS_fsconfig, fd, cmd, key, value, aux);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags) {
#ifdef SYS_fsmount
    return syscall(SYS_fsmount, fs_fd, flags, attr_flags);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_fsopen(const char *fs_name, unsigned int flags) {
#ifdef SYS_fsopen
    return syscall(SYS_fsopen, fs_name, flags);
#else
    return errno = ENOSYS, -1;
#endif
}

static gid_t k_getegid(void) {
#ifdef SYS_getegid
    return syscall(SYS_getegid);
#else
    return errno = ENOSYS, -1;
#endif
}

static uid_t k_geteuid(void) {
#ifdef SYS_geteuid
    return syscall(SYS_geteuid);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_memfd_create(const char *uname, unsigned int flags) {
#ifdef SYS_memfd_create
    return syscall(SYS_memfd_create, uname, flags);
#else
    return errno = ENOSYS, -1;
#endif
}

static int k_rt_sigprocmask(int how, k_sigset_t *nset, k_sigset_t *oset, size_t sigsetsize) {
#ifdef SYS_rt_sigprocmask
    return syscall(SYS_rt_sigprocmask, how, nset, oset, sigsetsize);
#else
    return errno = ENOSYS, -1;
#endif
}

#if defined(__sparc__)
// If the clone succeeds, then %o1 is set to 0 in the parent and 1 in the child.
// %o0 is set to the child's PID (in the parent's PID namespace) in the parent,
// and the parent's PID (in the initial PID namespace) in the child. If the
// latter respected the child's PID namespace, then we could tell the two apart
// by comparing the output of clone() with the output of getppid(). But it
// doesn't, so we're forced to use assembly to get the value of %o1. This
// helper function sets %o0 to 0 in the child to emulate a regular clone.
long sparc_clone_helper(unsigned long clone_flags, ...);
__asm__(
    "sparc_clone_helper:\n\t"
    "mov 217, %g1\n\t" // SYS_clone
#if defined(__arch64__)
    "ta 0x6d\n\t"
#else
    "ta 0x10\n\t"
#endif
    "movrlz %o0, %g0, %o1\n\t"
    "retl\n\t"
    "movrnz %o1, %g0, %o0"
);
#endif

static pid_t perform_clone(unsigned long flags) {
    enum { METHOD_CLONE3, METHOD_CLONE };
    static int method = METHOD_CLONE3;
    int err;
    pid_t child_pid;
    if (atomic_load_explicit(&method, memory_order_relaxed) == METHOD_CLONE3) {
        struct k_clone_args clone_args = {.flags = flags};
        if (!SET_ERR((child_pid = k_clone3(&clone_args, sizeof(struct k_clone_args))) < 0))
            return child_pid;
        if (err != -ENOSYS)
            return err;
        atomic_store_explicit(&method, METHOD_CLONE, memory_order_relaxed);
    }
#if defined(__sparc__)
    // Like CONFIG_CLONE_BACKWARDS, except with a different convention for
    // return values. We fix this up in a helper function rather than inline
    // assembly, to avoid specifying dozens of clobbered floating-point
    // registers.
    if ((child_pid = sparc_clone_helper(flags, 0L, 0L, 0L, 0L)) < 0)
        return child_pid;
#elif defined(__ia64__)
    // CONFIG_CLONE_BACKWARDS3 under a different name.
    if ((child_pid = syscall(SYS_clone2, flags, 0L, 0L, 0L, 0L, 0L)) < 0)
        return -errno;
#elif defined(__CRIS__) || defined(__s390__)
    // CONFIG_CLONE_BACKWARDS2.
    if ((child_pid = syscall(SYS_clone, 0L, flags, 0L, 0L, 0L)) < 0)
        return -errno;
#else
    // The default order, CONFIG_CLONE_BACKWARDS, or CONFIG_CLONE_BACKWARDS3.
    if ((child_pid = syscall(SYS_clone, flags, 0L, 0L, 0L, 0L, 0L)) < 0)
        return -errno;
#endif
    return child_pid;
}

static char *format_uint32_dec(char *ptr, uint32_t value) {
    do {
        *--ptr = '0' + value % 10;
        value /= 10;
    } while (value != 0);
    return ptr;
}

static char *format_uint32_oct(char *ptr, uint32_t value) {
    do {
        *--ptr = '0' + value % 8;
        value /= 8;
    } while (value != 0);
    return ptr;
}

static size_t format_extent(char *dest, uint32_t id) {
    memcpy(dest, "0 ", 2);
    char *ptr = format_uint32_dec(dest + 12, id);
    size_t len = dest + 12 - ptr;
    memmove(dest + 2, ptr, len);
    memcpy(dest + len + 2, " 1", 2);
    return len + 4;
}

static int proc_verify_root(int proc_fd, struct statfs *statfs_buf, struct stat *stat_buf) {
    if (fstatfs(proc_fd, statfs_buf) != 0)
        return -errno;
    if (statfs_buf->f_type != K_PROC_SUPER_MAGIC)
        return -ENOTSUP;
    if (fstat(proc_fd, stat_buf) != 0)
        return -errno;
    if (stat_buf->st_ino != K_PROC_ROOT_INO)
        return -ENOTSUP;
    return 0;
}

static int proc_openat(int *proc_fd, const char *filename, int flags, int *fd) {
    int err;
    struct statfs statfs_buf;
    struct stat stat_buf;
    if (*proc_fd == -1) {
        if ((*proc_fd = open("/proc/", O_RDONLY|O_CLOEXEC|O_PATH)) == -1)
            return -errno;
        if ((err = proc_verify_root(*proc_fd, &statfs_buf, &stat_buf)) != 0)
            return err;
    }
    if ((*fd = openat(*proc_fd, filename, flags)) == -1)
        return -errno;
    if (SET_ERR(fstatfs(*fd, &statfs_buf) != 0))
        goto fail;
    if (statfs_buf.f_type != K_PROC_SUPER_MAGIC) {
        err = -ENOTSUP;
        goto fail;
    }
    return 0;
fail:
    close(*fd);
    return err;
}

static int write_id_maps(int *proc_fd, uid_t uid, gid_t gid) {
    int err;
    int fd;
    if ((err = proc_openat(proc_fd, "self/uid_map", O_WRONLY|O_CLOEXEC, &fd)) != 0)
        goto fail1;
    char extent[14];
    size_t len = format_extent(extent, uid);
    if (SET_ERR(write(fd, extent, len) < 0))
        goto fail2;
    if (SET_ERR(close(fd) != 0))
        goto fail1;
    if ((err = proc_openat(proc_fd, "self/setgroups", O_WRONLY|O_CLOEXEC, &fd)) != 0) {
        if (err != -ENOENT)
            goto fail1;
    } else {
        static const char deny[4] = "deny";
        if (SET_ERR(write(fd, deny, 4) < 0))
            goto fail2;
        if (SET_ERR(close(fd) != 0))
            goto fail1;
    }
    if ((err = proc_openat(proc_fd, "self/gid_map", O_WRONLY|O_CLOEXEC, &fd)) != 0)
        goto fail1;
    len = format_extent(extent, gid);
    if (SET_ERR(write(fd, extent, len) < 0))
        goto fail2;
    if (SET_ERR(close(fd) != 0))
        goto fail1;
    err = close(*proc_fd), *proc_fd = -1;
    if (err != 0)
        return -errno;
    return 0;
fail2:
    close(fd);
fail1:
    if (*proc_fd != -1) {
        close(*proc_fd);
        *proc_fd = -1;
    }
    return err;
}

static void cmsg_embed_fd(struct cmsghdr *cmsg, int fd) {
    char *cmsg_ptr = (char *)cmsg;
    size_t cmsg_len = CMSG_LEN(sizeof(int));
    int cmsg_level = SOL_SOCKET, cmsg_type = SCM_RIGHTS;
    memcpy(cmsg_ptr + offsetof(struct cmsghdr, cmsg_len), &cmsg_len, sizeof(size_t));
    memcpy(cmsg_ptr + offsetof(struct cmsghdr, cmsg_level), &cmsg_level, sizeof(int));
    memcpy(cmsg_ptr + offsetof(struct cmsghdr, cmsg_type), &cmsg_type, sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
}

static int cmsg_extract_fd(const struct cmsghdr *cmsg) {
    const char *cmsg_ptr = (const char *)cmsg;
    size_t cmsg_len;
    int cmsg_level, cmsg_type;
    memcpy(&cmsg_len, cmsg_ptr + offsetof(struct cmsghdr, cmsg_len), sizeof(size_t));
    memcpy(&cmsg_level, cmsg_ptr + offsetof(struct cmsghdr, cmsg_level), sizeof(int));
    memcpy(&cmsg_type, cmsg_ptr + offsetof(struct cmsghdr, cmsg_type), sizeof(int));
    if (cmsg_len != CMSG_LEN(sizeof(int)) || cmsg_level != SOL_SOCKET || cmsg_type != SCM_RIGHTS)
        return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

static int socket_send_err(int socket_fd, int err, bool *did_send) {
    *did_send = false;
    ssize_t sent;
    while (SET_ERR((sent = send(socket_fd, &err, sizeof(int), MSG_NOSIGNAL)) < 0))
        if (err != -EINTR)
            return err;
    *did_send = true;
    if (sent != sizeof(int))
        return -EIO;
    return 0;
}

static int socket_send_fd(int socket_fd, int err, int fd, bool *did_send) {
    struct iovec err_vec = {
        .iov_base = &err,
        .iov_len = sizeof(int)
    };
    alignas(struct cmsghdr) char cmsg_buf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {
        .msg_iov = &err_vec,
        .msg_iovlen = 1,
        .msg_control = &cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };
    cmsg_embed_fd(CMSG_FIRSTHDR(&msg), fd);
    *did_send = false;
    ssize_t sent;
    while (SET_ERR((sent = sendmsg(socket_fd, &msg, MSG_NOSIGNAL)) < 0))
        if (err != -EINTR)
            return err;
    *did_send = true;
    if (sent != sizeof(int))
        return -EIO;
    return 0;
}

static int socket_recv_fd(int socket_fd, int *fd, bool *did_recv) {
    int err;
    struct iovec err_vec = {
        .iov_base = &err,
        .iov_len = sizeof(int)
    };
    alignas(struct cmsghdr) char cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_iov = &err_vec,
        .msg_iovlen = 1,
        .msg_control = &cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };
    *did_recv = false;
    ssize_t recvd;
    while (SET_ERR((recvd = recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC)) < 0))
        if (err != -EINTR)
            return err;
    *did_recv = true;
    if (recvd != sizeof(int) || (msg.msg_flags & MSG_TRUNC))
        err = -EIO;
    struct cmsghdr *cmsg;
    if ((cmsg = CMSG_FIRSTHDR(&msg)) == NULL) {
        if (recvd == 0 && !(msg.msg_flags & MSG_CTRUNC))
            return -EPIPE;
        return err;
    }
    *fd = cmsg_extract_fd(cmsg);
    if (err < 0)
        goto fail;
    if (*fd == -1 || (msg.msg_flags & MSG_CTRUNC)) {
        err = -EIO;
        goto fail;
    }
    return err;
fail:
    if (*fd != -1)
        close(*fd);
    return err;
}

#define DIR_REQ_ANON 0x1U

struct dir_req_head {
    unsigned int flags;
    mode_t mode;
    unsigned int attrs;
};

struct dir_req {
    struct dir_req_head head;
    const char *name;
};

static int socket_send_request(int socket_fd, const char *name, mode_t mode, unsigned int attrs, bool *did_send) {
    int err;
    struct dir_req_head request_head = {
        .flags = name == NULL ? DIR_REQ_ANON : 0,
        .mode = mode,
        .attrs = attrs
    };
    size_t name_len = name == NULL ? 0 : strnlen(name, 255);
    struct iovec vecs[2] = {
        {.iov_base = &request_head, .iov_len = sizeof(struct dir_req_head)},
        {.iov_base = (char *)name, .iov_len = name_len}
    };
    struct msghdr msg = {
        .msg_iov = vecs,
        .msg_iovlen = 2
    };
    *did_send = false;
    ssize_t sent;
    while (SET_ERR((sent = sendmsg(socket_fd, &msg, MSG_NOSIGNAL)) < 0))
        if (err != -EINTR)
            return err;
    *did_send = true;
    if ((size_t)sent != sizeof(struct dir_req_head) + name_len)
        return -EIO;
    return 0;
}

static int socket_recv_request(int socket_fd, struct dir_req *request, char *name_buf, bool *did_recv) {
    int err;
    struct iovec vecs[2] = {
        {.iov_base = request, .iov_len = sizeof(struct dir_req_head)},
        {.iov_base = name_buf, .iov_len = 255}
    };
    struct msghdr msg = {
        .msg_iov = vecs,
        .msg_iovlen = 2
    };
    *did_recv = false;
    ssize_t recvd;
    while (SET_ERR((recvd = recvmsg(socket_fd, &msg, 0)) < 0))
        if (err != -EINTR)
            return err;
    *did_recv = true;
    if (recvd == 0 && !(msg.msg_flags & MSG_CTRUNC))
        return -EPIPE;
    if ((size_t)recvd < sizeof(struct dir_req_head) || (msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC)))
        return -EIO;
    if (request->head.flags & DIR_REQ_ANON) {
        if (recvd != sizeof(struct dir_req_head))
            return -EIO;
        request->name = NULL;
    } else {
        name_buf[recvd - sizeof(struct dir_req_head)] = '\0';
        request->name = name_buf;
    }
    return 0;
}

static void child_setup_fds(int *socket_fd, int *proc_fd, bool send_err) {
    int err;
    if (*socket_fd != 0) {
        if (*proc_fd == 0)
            if (SET_ERR((*proc_fd = fcntl(*proc_fd, F_DUPFD_CLOEXEC, 1)) == -1))
                goto fail;
        if (SET_ERR(k_dup3(*socket_fd, 0, O_CLOEXEC) != 0))
            goto fail;
        *socket_fd = 0;
    }
    if (*proc_fd != -1 && *proc_fd != 1)
        if (SET_ERR(k_dup3(*proc_fd, 1, O_CLOEXEC) != 1))
            goto fail;
    if (SET_ERR(k_close_range(*proc_fd == -1 ? 1 : 2, UINT_MAX, 0) != 0))
        goto fail;
    return;
fail:
    if (send_err) {
        bool did_send;
        if ((err = socket_send_err(*socket_fd, err, &did_send)) == 0)
            _exit(0);
    }
    _exit(-err <= 0xff ? -err : EIO);
}

static int mount_dir_fsmount(const struct dir_req *request, int *dir_fd) {
    int err;
    *dir_fd = -1;
    int tmpfs_fd;
    if (SET_ERR((tmpfs_fd = k_fsopen("tmpfs", K_FSOPEN_CLOEXEC)) == -1))
        goto fail0;
    char mode_buf[12];
    mode_buf[11] = '\0';
    char *mode_ptr = format_uint32_oct(mode_buf + 11, request->head.mode);
    if (SET_ERR(k_fsconfig(tmpfs_fd, K_FSCONFIG_SET_STRING, "mode", mode_ptr, 0) != 0))
        goto fail1;
    if (request->name != NULL)
        if (SET_ERR(k_fsconfig(tmpfs_fd, K_FSCONFIG_SET_STRING, "source", request->name, 0) != 0))
            goto fail1;
    if (SET_ERR(k_fsconfig(tmpfs_fd, K_FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0))
        goto fail1;
    if (SET_ERR((*dir_fd = k_fsmount(tmpfs_fd, K_FSMOUNT_CLOEXEC, request->head.attrs)) == -1))
        goto fail1;
    if (SET_ERR(close(tmpfs_fd) != 0))
        goto fail0;
    return 0;
fail1:
    close(tmpfs_fd);
fail0:
    if (*dir_fd != -1)
        close(*dir_fd);
    return err;
}

static int mount_dir_detach(const struct dir_req *request, int *dir_fd) {
    int err;
    char mode_buf[17];
    memcpy(mode_buf, "mode=", 5);
    char *mode_ptr = format_uint32_oct(mode_buf + 16, request->head.mode);
    size_t mode_len = mode_buf + 16 - mode_ptr;
    memmove(mode_buf + 5, mode_ptr, mode_len);
    mode_buf[mode_len + 5] = '\0';
    if (mount(request->name, "/", "tmpfs", request->head.attrs, mode_buf) != 0)
        return -errno;
    if ((*dir_fd = open("/..", O_RDONLY|O_CLOEXEC|O_PATH)) == -1)
        goto fail1;
    if (SET_ERR(umount2("/", MNT_DETACH) != 0))
        goto fail0;
    return 0;
fail1:
    umount2("/", MNT_DETACH);
fail0:
    if (*dir_fd != -1)
        close(*dir_fd);
    return err;
}

enum { MOUNT_METHOD_FSMOUNT, MOUNT_METHOD_DETACH };
static int mount_method = MOUNT_METHOD_FSMOUNT;

static int mount_dir(const struct dir_req *request, int *dir_fd, bool in_mountns) {
    int err;
    bool update_method = false;
    if (atomic_load_explicit(&mount_method, memory_order_relaxed) == MOUNT_METHOD_FSMOUNT) {
        if ((err = mount_dir_fsmount(request, dir_fd)) != -ENOSYS)
            return err;
        update_method = true;
    }
    if (!in_mountns)
        return -ENOTSUP;
    if ((err = mount_dir_detach(request, dir_fd)) != 0)
        return err;
    return update_method;
}

static int child_handle_request(int socket_fd, const struct dir_req *request) {
    int err;
    int dir_fd;
    if ((err = mount_dir(request, &dir_fd, true)) != 0)
        goto fail0;
    bool did_send;
    if ((err = socket_send_fd(socket_fd, err, dir_fd, &did_send)) != 0)
        goto fail1;
    if (SET_ERR(close(dir_fd) != 0))
        return err;
    return 0;
fail1:
    close(dir_fd);
fail0:
    if (!did_send && (err = socket_send_err(socket_fd, err, &did_send)) != 0)
        return err;
    return 0;
}

static noreturn void child_proc(const struct dir_req *init_request, int socket_fd, int proc_fd, uid_t euid, gid_t egid, bool in_userns) {
    int err;
    sigset_t full_libc_mask;
    sigfillset(&full_libc_mask);
    sigprocmask(SIG_SETMASK, &full_libc_mask, NULL);
    child_setup_fds(&socket_fd, &proc_fd, init_request != NULL);
    if (SET_ERR(mount("", "/", "", MS_PRIVATE|MS_REC, NULL) != 0))
        goto fail1;
    if (in_userns)
        if ((err = write_id_maps(&proc_fd, euid, egid)) != 0)
            goto fail1;
    if (init_request != NULL) {
        if ((err = child_handle_request(socket_fd, init_request)) != 0)
            goto fail1;
    } else {
        struct dir_req request;
        static char name_buf[256];
        bool did_recv;
        while ((err = socket_recv_request(socket_fd, &request, name_buf, &did_recv)) == 0) {
            if ((err = child_handle_request(socket_fd, &request)) != 0)
                goto fail1;
        }
        if (err != -EPIPE)
            goto fail1;
    }
    if (SET_ERR(close(socket_fd) != 0))
        goto fail0;
    _exit(0);
fail1:
    close(socket_fd);
fail0:
    _exit(-err <= 0xff ? -err : EIO);
}

static int spawn_child(const struct dir_req *init_request, const struct memdir_options *options, int *socket_fd, pid_t *child_pid) {
    int err;
    int socket_fds[2];
    *child_pid = -1;
    if (SET_ERR(socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, socket_fds) != 0)) {
        socket_fds[0] = -1;
        goto fail1;
    }
    *socket_fd = socket_fds[0];
    int proc_fd = -1;
    unsigned long clone_flags = CLONE_NEWNS;
    bool new_userns = !(options->method_flags & MEMDIR_OPT_SHARED_USERNS);
    if (new_userns) {
        proc_fd = options->proc_fd;
        clone_flags |= CLONE_NEWUSER;
    }
    k_sigset_t full_mask, old_mask;
    memset(&full_mask, -1, sizeof(k_sigset_t));
    if (SET_ERR(k_rt_sigprocmask(SIG_BLOCK, &full_mask, &old_mask, sizeof(k_sigset_t)) != 0))
        goto fail1;
    uid_t euid = k_geteuid();
    gid_t egid = k_getegid();
    *child_pid = perform_clone(clone_flags);
    if (*child_pid == 0)
        child_proc(init_request, socket_fds[1], proc_fd, euid, egid, new_userns);
    k_rt_sigprocmask(SIG_SETMASK, &old_mask, NULL, sizeof(k_sigset_t));
    if (*child_pid < 0)
        goto fail1;
    if (SET_ERR(close(socket_fds[1]) != 0))
        goto fail0;
    return 0;
fail1:
    close(socket_fds[1]);
fail0:
    if (socket_fds[0] != -1)
        close(socket_fds[0]);
    if (*child_pid >= 0) {
        kill(*child_pid, SIGKILL);
        while (waitpid(*child_pid, NULL, __WCLONE) != *child_pid && -errno == -EINTR);
    }
    *socket_fd = -1;
    *child_pid = -1;
    return err;
}

int memdir_create_file(const char *name) {
    return k_memfd_create(name != NULL ? name : "", K_MFD_CLOEXEC);
}

void memdir_get_supported_options(struct memdir_options *options) {
    char *options_ptr = (char *)options;
    uint32_t method_flags = MEMDIR_OPT_SHARED_MOUNTNS|MEMDIR_OPT_SHARED_USERNS;
    uint32_t opt_flags = MEMDIR_OPT_HAVE_PROC_FD;
    memcpy(options_ptr + offsetof(struct memdir_options, method_flags), &method_flags, sizeof(uint32_t));
    memcpy(options_ptr + offsetof(struct memdir_options, opt_flags), &opt_flags, sizeof(uint32_t));
}

static int transfer_options(struct memdir_options *dest, const void *src) {
    memdir_init_options(dest);
    if (src != NULL) {
        size_t opt_size = *(size_t *)src;
        if (opt_size > sizeof(struct memdir_options))
            opt_size = sizeof(struct memdir_options);
        memcpy(dest, src, opt_size);
    }
    if ((dest->method_flags & ~(MEMDIR_OPT_SHARED_MOUNTNS|MEMDIR_OPT_SHARED_USERNS)) != 0)
        return -EINVAL;
    if ((dest->opt_flags & ~MEMDIR_OPT_HAVE_PROC_FD) != 0)
        return -EINVAL;
    if ((dest->opt_flags & MEMDIR_OPT_HAVE_PROC_FD) == 0)
        dest->proc_fd = -1;
    return 0;
}

enum {
    WORKER_STATE_RUNNING,
    WORKER_STATE_TERMINATED,
    WORKER_STATE_WAITED
};

static int get_worker_state(const struct memdir_worker *worker, int *state) {
    int err;
    siginfo_t wait_info;
    wait_info.si_pid = 0;
    if (SET_ERR(waitid(P_PID, worker->child_pid, &wait_info, WEXITED|WNOHANG|WNOWAIT|__WCLONE) != 0)) {
        if (err != -ECHILD)
            return err;
        return *state = WORKER_STATE_WAITED, 0;
    }
    if (wait_info.si_pid != 0)
        return *state = WORKER_STATE_TERMINATED, 0;
    return *state = WORKER_STATE_RUNNING, 0;
}

int memdir_start_worker(struct memdir_worker *worker, const struct memdir_options *options) {
    int err, orig_err = -errno;
    struct memdir_options opts;
    if ((err = transfer_options(&opts, options)) != 0)
        return errno = -err, -1;
    if ((err = spawn_child(NULL, &opts, &worker->socket_fd, &worker->child_pid)) != 0)
        return errno = -err, -1;
    return errno = -orig_err, 0;
}

int memdir_worker_create_dir(struct memdir_worker *worker, int *dir_fd, const char *name, mode_t mode, unsigned int attrs) {
    int err, orig_err = -errno;
    bool did_send, did_recv = false;
    if ((err = socket_send_request(worker->socket_fd, name, mode, attrs, &did_send)) != 0)
        goto fail;
    if ((err = socket_recv_fd(worker->socket_fd, dir_fd, &did_recv)) < 0)
        goto fail;
    if (err != 0)
        atomic_store_explicit(&mount_method, MOUNT_METHOD_DETACH, memory_order_relaxed);
    return errno = -orig_err, 0;
fail:
    if (err == -EPIPE) {
        err = -ECHILD;
        int state;
        if (get_worker_state(worker, &state) == 0 && state == WORKER_STATE_RUNNING) {
            err = -EIO;
            if (did_send && !did_recv)
                kill(worker->child_pid, SIGKILL);
        }
    }
    *dir_fd = -1;
    return errno = -err, -1;
}

int memdir_stop_worker(struct memdir_worker *worker, int *status) {
    int err, orig_err = -errno;
    if (SET_ERR(close(worker->socket_fd) != 0))
        goto fail1;
    while (SET_ERR(waitpid(worker->child_pid, status, __WCLONE) != worker->child_pid))
        if (err != -EINTR)
            goto fail0;
    worker->socket_fd = -1;
    worker->child_pid = -1;
    return errno = -orig_err, 0;
fail1:
    kill(worker->child_pid, SIGKILL);
    while (waitpid(worker->child_pid, NULL, __WCLONE) != worker->child_pid && -errno == -EINTR);
fail0:
    worker->socket_fd = -1;
    worker->child_pid = -1;
    return errno = -err, -1;
}

int memdir_create_dir(const char *name, mode_t mode, unsigned int attrs, const struct memdir_options *options) {
    int err, orig_err = -errno;
    struct memdir_options opts;
    if ((err = transfer_options(&opts, options)) != 0)
        return errno = -err, -1;
    struct dir_req request = {
        .head.mode = mode,
        .head.attrs = attrs,
        .name = name
    };
    int dir_fd;
    if (opts.method_flags & MEMDIR_OPT_SHARED_MOUNTNS) {
        if ((err = mount_dir(&request, &dir_fd, false)) < 0)
            return errno = -err, -1;
        if (err != 0)
            atomic_store_explicit(&mount_method, MOUNT_METHOD_DETACH, memory_order_relaxed);
        return errno = -orig_err, dir_fd;
    }
    struct memdir_worker worker;
    if ((err = spawn_child(&request, &opts, &worker.socket_fd, &worker.child_pid)) != 0)
        return errno = -err, -1;
    bool did_recv;
    if ((err = socket_recv_fd(worker.socket_fd, &dir_fd, &did_recv)) < 0)
        dir_fd = -1;
    if (err >= 0)
        atomic_store_explicit(&mount_method, MOUNT_METHOD_DETACH, memory_order_relaxed);
    int status;
    if (memdir_stop_worker(&worker, &status) != 0) {
        if (err >= 0)
            err = -errno;
        goto fail;
    }
    if (!WIFEXITED(status))
        err = -ECHILD;
    else if (WEXITSTATUS(status) != 0)
        err = -WEXITSTATUS(status);
    if (err < 0)
        goto fail;
    return errno = -orig_err, dir_fd;
fail:
    if (dir_fd != -1)
        close(dir_fd);
    if (err == -EPIPE)
        err = -EIO;
    return errno = -err, -1;
}

const char *memdir_get_version(void) {
    return "0.1.0";
}
