#include "../config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main( int argc, char * argv[] )
{
    // Create a "fork bomb", but with finite scope.
    // argv[1] should be the depth
    // argv[2]='r' means that we should recurse (creating 2^argv[1] processes, instead of just argv[1])

    if( argc<2 )
        return 1;

    int depth=0;
    int target=atoi(argv[1]);
    bool recurse=argc>=3 && argv[2][0]=='r';

    int num_children=0;
    int serial=1;
    int origserial=1;
    bool stop=false;

    while( !stop && depth<target ) {
        pid_t child=fork();
        depth++;

        if( recurse )
            serial*=2;

        if( child<0 ) {
            fprintf(stderr, "Fork failed for process %d (child %d): %s\n", getpid(), serial, strerror(errno) );
            break;
        } else if( child==0 ) {
            // We are the child
            serial++;
            origserial=serial;
            num_children=0;
        } else {
            num_children++;
            if( !recurse ) {
                stop=true;
            }
        }
    }

    printf("Pid %d is child %d running with uid %d\n", getpid(), origserial, getuid());

    for( int i=0; i<num_children; ++i ) {
        int status;
        pid_t child=wait(&status);

        printf("Child %d terminated\n", child);
    }

    return 0;
}
