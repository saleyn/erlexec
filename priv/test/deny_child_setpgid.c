#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static pid_t exec_port_pid = -1;

__attribute__((constructor))
static void remember_exec_port_pid(void)
{
    exec_port_pid = getpid();
}

int setpgid(pid_t pid, pid_t pgid)
{
    static int (*real_setpgid)(pid_t, pid_t) = NULL;
    if (real_setpgid == NULL)
        real_setpgid = (int (*)(pid_t, pid_t))dlsym(RTLD_NEXT, "setpgid");

    if (getpid() != exec_port_pid) {
        /* Let the parent establish the group before forcing the child error. */
        usleep(200000);
        errno = EPERM;
        return -1;
    }

    if (pid != 0 && pid != getpid() && getenv("ERLEXEC_TEST_DENY_PARENT_GROUP")) {
        errno = EPERM;
        return -1;
    }

    return real_setpgid(pid, pgid);
}
