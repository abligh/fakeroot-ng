#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([fakeroot-ng], [0.18], [shachar@debian.org])
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE([no-dist])
AC_CONFIG_SRCDIR([parent.h])
AC_CONFIG_HEADER([config.h])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_RANLIB

AC_LANG(C)

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/file.h sys/socket.h sys/time.h unistd.h sys/prctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_DECLS([PR_SET_PTRACER],[],[],[#include <sys/prctl.h>])

dnl Globally define the root UID
AC_DEFINE([ROOT_UID],[0],[UID for root])
AC_DEFINE([ROOT_GID],[0],[GID for root])

dnl Check whether we have PTRACE_GETREGS
AC_MSG_CHECKING([for PTRACE_GETREGS])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
        #include <sys/ptrace.h>
        ],
        [ptrace(PTRACE_GETREGS, 0, 0, 0);])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_PTRACE_GETREGS], [1], [Ptrace defines a single syscall for getting all registers])
    ],
    [AC_MSG_RESULT([no])])

dnl Check whether we have PTRACE_PEEKUSER
AC_MSG_CHECKING([for PTRACE_PEEKUSER])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
        #include <sys/ptrace.h>
        ],
        [ptrace(PTRACE_PEEKUSER, 0, 0, 0);])],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_PTRACE_PEEKUSER], [1], [Ptrace defines a syscall for getting a single register])
    ],
    [AC_MSG_RESULT([no])])

dnl Check which std::map variant to use
AC_LANG_PUSH(C++)
#AC_LANG_WERROR

AC_MSG_CHECKING([what flags are needed for compiler support of the ISO C++11 standard])
saved_CXXFLAGS=$CXXFLAGS
CXXFLAGS="$saved_CXXFLAGS -Werror"
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
            #include <unordered_map>
            class testcpp11 { public: testcpp11() = default; };
        ],
        [
            std::unordered_map<int, int> test;
            decltype(test)::iterator iterator;
            int *nullable=nullptr;
            int i;
            if( nullable!=0 )
                nullable=&i;
        ])],
    [
        AC_MSG_RESULT([none])
        CXXFLAGS="$saved_CXXFLAGS"
    ],
    [
        CXXFLAGS="$saved_CXXFLAGS -std=c++11 -Werror"
        AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([
                    #include <unordered_map>
                    class testcpp11 { public: testcpp11() = default; };
                ],
                [
                    std::unordered_map<int, int> test;
                    decltype(test)::iterator iterator;
                    int *nullable=nullptr;
                    int i;
                    if( nullable!=0 )
                        nullable=&i;
                ])],
            [
                AC_MSG_RESULT([-std=c++11])
                CXXFLAGS="$saved_CXXFLAGS -std=c++11"
            ],
            [
                AC_MSG_RESULT([not supported])
                AC_ERROR([Fakeroot-ng needs a compiler that supports C++11. If you are using gcc, that
                  means version 4.7 or higher.])
            ]
        )
    ]
)

dnl gcc supports indicating that a function is a printf style function. It then has protections against format string
dnl mismatches
AC_MSG_CHECKING([whether compiler supports custom printf style protection])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([int dummy( const char *format, ... ) __attribute__ ((format(printf, 1, 2)));],[] )],
        [
                AC_MSG_RESULT([__attribute__ ((format(...)))])
                AC_DEFINE([COMPHINT_PRINTF( f, c )], [__attribute__ (( format ( printf, f, c )))],
                        [How to tell the compiler that this is a printf style function])
        ],
        [
                AC_MSG_RESULT([no])
                AC_MSG_ERROR([Compiler does not support format string checking on custom functions])
        ]
)

AC_LANG_POP

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_VPRINTF
AC_FUNC_MMAP
AC_CHECK_FUNCS([ftruncate getcwd memset mkdir munmap realpath select socket strchr strerror strtoul])

AC_MSG_CHECKING([whether openat class functions are supported])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([
    #include <sys/stat.h>
    #include <sys/fcntl.h>
    ], [struct stat stat; fstatat(AT_FDCWD, "/etc/passwd", &stat, AT_SYMLINK_NOFOLLOW);])],
    [ AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_OPENAT], [1], [Supports the openat class of functions])],
    [
        dnl Let's try again, this time with _ATFILE_SOURCE at the beginning
        AC_COMPILE_IFELSE(
            [ AC_LANG_PROGRAM([
                #define _ATFILE_SOURCE
                #include <sys/stat.h>
                #include <sys/fcntl.h>
                ], [struct stat stat; fstatat(AT_FDCWD, "/etc/passwd", &stat, AT_SYMLINK_NOFOLLOW);])],
            [
                AC_MSG_RESULT([_ATFILE_SOURCE])
                AC_DEFINE([HAVE_OPENAT], [1])
                AC_DEFINE([_ATFILE_SOURCE],[], [Enable openat functions])
            ],
            [ AC_MSG_RESULT([no]) ]
        )
    ] )

AC_MSG_CHECKING([what alternate location to use for shared memory files])
AC_ARG_WITH([memdir], [AC_HELP_STRING([--with-memdir=DIR],[Where to create shared memory files (default /tmp)])],
[
    if [[ "$with_memdir" ]]
    then
        AC_MSG_RESULT([$with_memdir])
        AC_DEFINE_UNQUOTED([DEFAULT_TMPDIR], ["$with_memdir"])
    fi

], [
        AC_MSG_RESULT([/tmp])
        AC_DEFINE([DEFAULT_TMPDIR], ["/tmp"], [Where to create shared memory files if no environment overrides])
])

# Custom steps

dnl Canoninize the canonical system names
[
if [ "$target_os" = "linux-gnu" ]
then
    target_os=linux
fi

case "$target_cpu" in
i686|i586|i486)
    target_cpu=i386
    ;;
esac
]

# Check whether we are ported to this platform
AC_MSG_CHECKING([whether platform $target_os/$target_cpu is supported])

[
if [ ! -f "$srcdir/arch/$target_os/$target_cpu/platform_specific.h" ]
then
]
    AC_MSG_RESULT(no)
    echo "$srcdir"
    AC_MSG_ERROR(Platform detected is not yet supported.)
[
else
]    AC_MSG_RESULT([yes]) [
fi
]

dnl We generate all Makefiles for all platforms, and then only invoke those for the platforms we need
AC_CONFIG_FILES([Makefile
        tests/Makefile
        arch/Makefile
        arch/$target_os/Makefile.template
        arch/$target_os/$target_cpu/Makefile])
AC_OUTPUT
