#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    const char* real = getenv("ERLEXEC_REAL_PORTEXE");
    const char* preload = getenv("ERLEXEC_TEST_PRELOAD");
    const char* variable = getenv("ERLEXEC_TEST_PRELOAD_ENV");
    if (!real || !preload || !variable || setenv(variable, preload, 1) < 0)
        return 127;
    argv[0] = (char*)real;
    execv(real, argv);
    return 127;
}
