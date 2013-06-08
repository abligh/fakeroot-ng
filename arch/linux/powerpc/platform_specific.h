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

#define PTLIB_STATE_SIZE 50

/* This is defined to 1 if the platform sends a SIGTRAP to the process after a successful execve if it's being traced */
#define PTLIB_TRAP_AFTER_EXEC 1

typedef unsigned long long ptlib_inode_t;

struct ptlib_stat {
	unsigned long long dev;		/* Device.  */
	unsigned long long ino;		/* File serial number.  */
	unsigned int	mode;	/* File mode.  */
	unsigned int	nlink;	/* Link count.  */
	unsigned int	uid;		/* User ID of the file's owner.  */
	unsigned int	gid;		/* Group ID of the file's group. */
	unsigned long long rdev;	/* Device number, if device.  */
	unsigned short	__pad2;
	long long	size;	/* Size of file, in bytes.  */
	int		blksize;	/* Optimal block size for I/O.  */
	long long	blocks;	/* Number 512-byte blocks allocated. */
	int		atime;	/* Time of last access.  */
	unsigned int	atime_nsec;
	int		mtime;	/* Time of last modification.  */
	unsigned int	mtime_nsec;
	int		ctime;	/* Time of last status change.  */
	unsigned int	ctime_nsec;
	unsigned int	__unused4;
	unsigned int	__unused5;
};

typedef struct rusage ptlib_extra_data;

/* Platform specific format specifiers for printing pid, dev and inode */
#define PID_F "%d"
#define DEV_F "%llx"
#define INODE_F "%lld"
#define UID_F "%lu"
#define GID_F "%lu"

/* Preferred syscalls to perform certain actions */
#define PREF_STAT SYS_stat64
#define PREF_FSTAT SYS_fstat64
#define PREF_LSTAT SYS_lstat64
#define PREF_FSTATAT SYS_fstatat64

#define PREF_NOP SYS_geteuid
#define PREF_MMAP SYS_mmap2

/* An unsigned int as long as a pointer */
typedef unsigned long int_ptr;

#endif /* PLATFORM_SPECIFIC_H */
