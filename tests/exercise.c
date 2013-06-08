/* This is a tool for exercising the various system calls we would potentially like to emulate with fakeroot-ng.
 * By definition, this tool should produce identical results when running under fakeroot-ng and when running as
 * root.
 */

#include "../config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main( int argc, char *argv[] )
{
    uid_t uid=getuid(), euid=geteuid();
    gid_t gid=getgid(), egid=getegid();
    int dirfd;

    umask(0022);
    printf("uid %d euid %d gid %d egid %d\n", uid, euid, gid, egid );
    
    if( mkdir("testdir", 0777)==0 ) {
        printf("mkdir succeeded\n");
    } else {
        perror("mkdir failed");

        exit(1);
    }

    chdir("testdir");

    if( mknod( "file1", 0666 | S_IFREG, 0 )==0 ) {
        printf("file1 created using mknod\n");
    } else {
        perror("file1 not created");
    }

#if HAVE_OPENAT
    if( fchownat( AT_FDCWD, "file1", 0, 12, 0 )==0 ) {
        printf("file1 fchownat to 0,12\n");
    } else {
        perror("fchownat(file1, 0, 12) failed");
    }

    dirfd = open(".", O_RDONLY|O_DIRECTORY);
    if (dirfd == -1) {
      perror("open .");
    }

    chdir("..");

    if( symlinkat( "file1", dirfd, "file2" )>=0 ) {
        printf("symlinkat file2->file1\n");
    } else {
        perror("symlinkat file2->file1 failed");
    }

    if( syscall( SYS_fchmodat, dirfd, "file2", 0000, AT_SYMLINK_NOFOLLOW )==0 ) {
        printf("file1 fchmodat 0000 through a symlink with flag to not follow symlinks\n");
    } else {
        perror("file1 fchmodat failed");
    }

    chdir("testdir");

    struct stat stat;
    if( fstatat(dirfd, "file1", &stat, AT_SYMLINK_NOFOLLOW)>=0 ) {
        if( stat.st_mode==(S_IFREG|0000) ) {
            printf("fstatat of file1 returned correct permissions (no permissions)\n");
        } else {
            printf("fstatat of file1 returned incorrect permissions (%04o)\n", stat.st_mode);
        }
    } else {
        perror("fstatat of file1 failed");
    }
#endif

    return 0;
}
