#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_REVISION([$Revision$])
AC_INIT([erlexec], [1.0], [saleyn at gmail dot com])
AC_CONFIG_AUX_DIR([config])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability])

AC_CONFIG_SRCDIR([c_src/exec.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AC_ERLANG_NEED_ERL
AC_ERLANG_NEED_ERLC
AC_ERLANG_SUBST_INSTALL_LIB_DIR
AC_ERLANG_SUBST_INSTALL_LIB_SUBDIR([exec], [1.0])

# Checks for libraries.
AC_CHECK_LIB([cap], [cap_from_text])

AC_ERLANG_CHECK_LIB([erl_interface])

AC_LANG_PUSH([Erlang])

AC_CACHE_CHECK([for ARCH subdirectory], [erlang_ei_cv_arch], [
    AC_RUN_IFELSE(
        [AC_LANG_PROGRAM([], [
            SysArch = erlang:system_info(system_architecture),
            file:write_file("conftest.out", SysArch), halt(0)])
        ],
        [erlang_ei_cv_arch=`cat conftest.out`],
        [AC_MSG_FAILURE([test Erlang program execution failed])]
    )
])
AC_SUBST([ARCH_ERL], [$erlang_ei_cv_arch])
AC_SUBST([ARCH_CXX], [$build])

AC_LANG_POP([Erlang])

AC_ARG_VAR([ARCH], [
    architecture-dependent subdirectory, where exec-port will be placed:
    @ERLANG_INSTALL_LIB_DIR_exec@/priv/@ARCH@/bin/exec-port
])

if test "$ARCH" = ""; then
    if test "$ARCH_ERL" != "$ARCH_CXX"; then
        AC_MSG_WARN([Architecture-dependent subdirectory dnl
is different for Erlang/OTP and C/C++ compilers: "$ARCH_ERL" != "$ARCH_CXX"
Please use ARCH=<subdir> option to specify it explicitly!
        ])
        if test "$ARCH_ERL" != ""; then
            AC_SUBST([ARCH], [$ARCH_ERL])
        else
            AC_SUBST([ARCH], [$ARCH_CXX])
        fi
    else
        AC_SUBST([ARCH], [$ARCH_ERL])
    fi
else
    AC_SUBST([ARCH], [$ARCH])
fi

# Checks for header files.
AC_CHECK_HEADERS([limits.h string.h sys/time.h unistd.h sys/capability.h sys/prctl.h fcntl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm gettimeofday memset select strerror])

AC_CONFIG_FILES([Makefile c_src/Makefile src/Makefile])
AC_OUTPUT

