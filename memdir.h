#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMDIR_OPT_SHARED_MOUNTNS 0x1U
#define MEMDIR_OPT_SHARED_USERNS 0x2U

#define MEMDIR_OPT_HAVE_PROC_FD 0x1U

struct memdir_options {
    size_t opt_size;
    uint32_t method_flags;
    uint32_t opt_flags;
    int proc_fd;
};

#define memdir_init_options(options) ( \
    (options)->opt_size = sizeof(struct memdir_options), \
    (options)->method_flags = 0, \
    (options)->opt_flags = 0, \
(void)0)

#define memdir_set_shared_mountns(options, value) ( \
    (value) \
    ? ((options)->method_flags |= MEMDIR_OPT_SHARED_MOUNTNS) \
    : ((options)->method_flags &= ~MEMDIR_OPT_SHARED_MOUNTNS), \
(void)0)

#define memdir_set_shared_userns(options, value) ( \
    (value) \
    ? ((options)->method_flags |= MEMDIR_OPT_SHARED_USERNS) \
    : ((options)->method_flags &= ~MEMDIR_OPT_SHARED_USERNS), \
(void)0)

#define memdir_set_proc_fd(options, value) ( \
    (options)->opt_flags |= MEMDIR_OPT_HAVE_PROC_FD, \
    (options)->proc_fd = (value), \
(void)0)

struct memdir_worker {
    int socket_fd;
    pid_t child_pid;
};

int memdir_create_file(const char *name);
void memdir_get_supported_options(struct memdir_options *options);
int memdir_start_worker(struct memdir_worker *worker, const struct memdir_options *options);
int memdir_worker_create_dir(struct memdir_worker *worker, int *dir_fd, const char *name, mode_t mode, unsigned int attrs);
int memdir_stop_worker(struct memdir_worker *worker, int *status);
int memdir_create_dir(const char *name, mode_t mode, unsigned int attrs, const struct memdir_options *options);
const char *memdir_get_version(void);

#ifdef __cplusplus
}
#endif
