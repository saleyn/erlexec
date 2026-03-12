#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    const char* real = getenv("ERLEXEC_REAL_PORTEXE");
    const char* preload = getenv("ERLEXEC_FAIL_SETPGID_PRELOAD");
    if (!real || !*real || !preload || !*preload)
        return 127;

    pid_t pid = fork();
    if (pid < 0)
        return 127;

    if (pid == 0) {
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDERR_FILENO);
            if (dev_null > STDERR_FILENO)
                close(dev_null);
        }
        setenv("LD_PRELOAD", preload, 1);
        argv[0] = (char*)real;
        execv(real, argv);
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0)
        return 127;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 127;
}
