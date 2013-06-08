#ifndef PLATFORM_SPECIFIC_H
#define PLATFORM_SPECIFIC_H

#include <asm/ptrace.h>
#include <sys/syscall.h>
#include <sys/resource.h>

/* Marks the library as supporting debugging children */
#define PTLIB_SUPPORTS_FORK 1
#define PTLIB_SUPPORTS_VFORK 1
#define PTLIB_SUPPORTS_CLONE 1

#define PTLIB_PARENT_CAN_WAIT 1

#define PTLIB_STATE_SIZE (FRAME_SIZE)

/* This is defined to 1 if the platform sends a SIGTRAP to the process after a successful execve if it's being traced */
#define PTLIB_TRAP_AFTER_EXEC 1

typedef unsigned long long ptlib_inode_t;

struct ptlib_stat {
        unsigned long long      dev;
        unsigned char   __pad0[4];

#define STAT64_HAS_BROKEN_ST_INO        1
        unsigned long   __ino;

        unsigned int    mode;
        unsigned int    nlink;

        unsigned long   uid;
        unsigned long   gid;

        unsigned long long      rdev;
        unsigned char   __pad3[4];

        long long       size;
        unsigned long   blksize;

        unsigned long long      blocks;      /* Number 512-byte blocks allocated. */

        unsigned long   atime;
        unsigned long   atime_nsec;

        unsigned long   mtime;
        unsigned int    mtime_nsec;

        unsigned long   ctime;
        unsigned long   ctime_nsec;

        unsigned long long      ino;
};

typedef struct rusage ptlib_extra_data;

/* Platform specific format specifiers for printing pid, dev and inode */
#define PID_F "%d"
#define DEV_F "%llx"
#define INODE_F "%lld"
#define UID_F "%lu"
#define GID_F "%lu"

/* Preferred stat functions to use */
#define PREF_STAT SYS_stat64
#define PREF_LSTAT SYS_lstat64
#define PREF_FSTAT SYS_fstat64
#define PREF_FSTATAT SYS_fstatat64

#define PREF_NOP SYS_geteuid32
#define PREF_MMAP SYS_mmap2

/* An unsigned int as long as a pointer */
typedef unsigned long int_ptr;

#endif /* PLATFORM_SPECIFIC_H */
