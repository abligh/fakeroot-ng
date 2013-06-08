#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

int main()
{
    char buffer[PATH_MAX];

    getcwd( buffer, sizeof(buffer) );

    printf("Current directory is %s\n", buffer );
    mkdir("dir", 0777);
    chroot( "dir");

    getcwd( buffer, sizeof(buffer) );
    printf("With chroot to dir, current directory is %s\n", buffer);

    chdir("dir");

    getcwd( buffer, sizeof(buffer) );
    printf("After chdir, current directory is %s\n", buffer);

    return 0;
}
