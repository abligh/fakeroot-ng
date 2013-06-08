#include "../config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>

#include <iostream>

using namespace std;

int parent_wait_test()
{
    int pfd[2];

    if( pipe(pfd)!=0 ) {
        perror("parent_wait_test: pipe creation error");
        exit(1);
    }

    pid_t child1, child2, parent=getpid();

    child1=fork();
    if( child1==-1 ) {
        perror("parent_wait_test: fork1 error");

        exit(1);
    }

    if( child1==0 ) {
        /* We are the first child - sync on the pipe and then exit */
        close( pfd[1] ); /* Close the writing end */

        char buffer;
        if( read( pfd[0], &buffer, 1 )!=1 ) {
            perror("parent_wait_test: child1 sync read error");

            exit(1);
        }

        exit(0);
    }

    child2=fork();
    if( child2==-1 ) {
        perror("parent_wait_test: fork2 error");

        kill( child1, SIGKILL );
        exit(1);
    }

    if( child2==0 ) {
        close( pfd[0] );

        /* We are the second child - detach ourselves */
        pid_t grandchild=fork();

        if( grandchild==-1 ) {
            perror("parent_wait_test: grandchild fork error");

            exit(1);
        }

        if( grandchild==0 ) {
            /* We are the grand child */
            if( ptrace( PTRACE_ATTACH, child1, 0, 0 )!=0 ) {
                perror("parent_wait_test: ptrace attach failed");

                kill( child1, SIGKILL );

                exit(1);
            }

            // Attched ok - free child1 to exit
            write( pfd[1], "a", 1 );
            close( pfd[1] );

            // Now wait for the child to exit
            int status;
            while( waitpid( child1, &status, 0 )==child1 && !WIFEXITED(status) ) {
                ptrace(PTRACE_CONT, child1, 0, 0);
            }

            // Sleep for a second (should be enough to make sure the parent waits successfully) and then kill the parent
            sleep(1);
            kill( parent, SIGKILL );

            exit(0);
        } else {
            /* We are the second child */
            exit(0);
        }
    }

    /* We are the parent */
    int status;
    if( waitpid( child2, &status, 0 )<0 ) {
        perror("parent_wait_test: wait(child2) failed");

        kill( child1, SIGKILL);

        exit(1);
    }

    if( !WIFEXITED(status) || WEXITSTATUS(status)!=0 ) {
        // Something failed with the child
        
        kill( child1, SIGKILL );

        exit(1);
    }

    // Debugger child is ok (probably) - lets wait for the debuggee
    if( waitpid( child1, &status, 0 )==child1 ) {
        // Wait successful - make sure it really is
        if( WIFEXITED(status) && WEXITSTATUS(status)==0 ) {
            // Yes, everything is ok
            return 1;
        } else {
            // The wait was successfull, but the subprocess not - exit with failure
            exit(1);
        }
    } else {
        // Maybe the wait failed, but maybe the system just told us that this process is not our child
        if( errno==ECHILD ) {
            // It's just that we cannot wait on this particular child. Signal the parent so
            kill( parent, SIGKILL );
            exit(1);
        }
    }

    return 0;
}

int main()
{
    cerr<<"Sizes: char "<<sizeof(char)<<", short "<<sizeof(short)<<", int "<<sizeof(int)<<", long "<<sizeof(long)<<", long long "<<sizeof(long long)<<
        ", void * "<<sizeof(void *)<<", size_t "<<sizeof(size_t)<<endl;
    cerr<<"Sizes: pid_t "<<sizeof(pid_t)<<", gid_t "<<sizeof(gid_t)<<", dev_t "<<sizeof(dev_t)<<", ino_t "<<sizeof(ino_t)<<endl;

    /* Check status of PTLIB_PARENT_CAN_WAIT */

    pid_t child=fork();

    if( child<0 ) {
        perror("fork failed");

        return 1;
    }

    if( child==0 ) {
        /* Child processing */
        if( parent_wait_test() )
            exit(0);
        
        exit(1);
    } else {
        /* Parent processing */
        int status;
        if( waitpid(child, &status, 0)==child ) {
            if( WIFEXITED(status) && WEXITSTATUS(status)==0 ) {
                /* Parent can wait */
                printf("#define PTLIB_PARENT_CAN_WAIT 1\n");
            } else if( WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL ) {
                printf("#define PTLIB_PARENT_CAN_WAIT 0\n");
            } else {
                fprintf(stderr, "Couldn't determine PTLIB_PARENT_CAN_WAIT value\n");
            }
        }
    }

#if HAVE_PTRACE_GETREGS
    /* Value for PTLIB_STATE_SIZE */
    child=fork();

    if( child<0 ) {
        perror("Failed to create child process");

        return 1;
    }

    if( child==0 ) {
        /* We are the child */
        ptrace( PTRACE_TRACEME, 0, 0, 0 );
        kill( getpid(), SIGTRAP );
    } else {
        /* We are the parent */
        int status;

        waitpid( child, &status, 0 );

        if( WIFSTOPPED(status) ) {
            void *buffer[4096]; /* Large enough for sure */
            int i=0;
            int max1, max2;

            /* Set the buffer to a known state */
            for( i=0; i<4096; ++i )
                buffer[i]=0;

            /* Transfer registers */
            ptrace(PTRACE_GETREGS, child, buffer, buffer);
            /* The manual page says that only data (arg 4) is needed, but on some
             * platforms addr (arg 3) is used instead */

            /* Find out at least how high the buffer was filled */
            for( max1=4095; max1>=0 && buffer[max1]==0; --max1)
                buffer[max1]=(void*)1;

            /* Transfer registers, again */
            ptrace(PTRACE_GETREGS, child, buffer, buffer);

            /* Find out at how high the buffer was filled when initialized to a differnet value */
            for( max2=4095; max2>max1 && buffer[max2]==(void *)1; --max2)
                ;

            /* Max2 is now how much data is being copied during a GETREGS call */
            printf("#define PTLIB_STATE_SIZE (%d)\n", max2+1);

            /* Kill the waiting process */
            ptrace(PTRACE_KILL, child, 0, 0);
            waitpid(child, &status, 0 );
        } else {
            fprintf(stderr, "Error: child %d did not trace correctly\n", child);

            return 1;
        }
    }
#endif /* PTRACE_GETREGS */

    return 0;
}
