#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

static pid_t exec_port_pid = -1;

__attribute__((constructor))
static void remember_exec_port_pid(void)
{
    exec_port_pid = getpid();
}

pid_t setsid(void)
{
    static pid_t (*real_setsid)(void) = NULL;
    if (real_setsid == NULL)
        real_setsid = (pid_t (*)(void))dlsym(RTLD_NEXT, "setsid");

    if (getpid() != exec_port_pid)
        usleep(200000);

    return real_setsid();
}

int setpgid(pid_t pid, pid_t pgid)
{
    static int (*real_setpgid)(pid_t, pid_t) = NULL;
    if (real_setpgid == NULL)
        real_setpgid = (int (*)(pid_t, pid_t))dlsym(RTLD_NEXT, "setpgid");

    if (getpid() != exec_port_pid) {
        errno = EPERM;
        return -1;
    }

    return real_setpgid(pid, pgid);
}
