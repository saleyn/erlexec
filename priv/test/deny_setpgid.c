#define _GNU_SOURCE

#include <errno.h>
#include <unistd.h>

int setpgid(pid_t pid, pid_t pgid)
{
    errno = EPERM;
    return -1;
}
