/*
    Copyright (C) 2009 by Shachar Shemesh

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>

const char *translate_signal( int sig )
{
#define DEFSIG(s) case s: return #s
    switch( sig ) {
        DEFSIG(SIGHUP);
        DEFSIG(SIGINT);
        DEFSIG(SIGQUIT);
        DEFSIG(SIGILL);
        DEFSIG(SIGABRT);
        DEFSIG(SIGFPE);
        DEFSIG(SIGKILL);
        DEFSIG(SIGSEGV);
        DEFSIG(SIGPIPE);
        DEFSIG(SIGALRM);
        DEFSIG(SIGTERM);
        DEFSIG(SIGUSR1);
        DEFSIG(SIGUSR2);
        DEFSIG(SIGCHLD);
        DEFSIG(SIGCONT);
        DEFSIG(SIGSTOP);
        DEFSIG(SIGTSTP);
        DEFSIG(SIGTTIN);
        DEFSIG(SIGTTOU);
        DEFSIG(SIGBUS);
        DEFSIG(SIGPOLL);
        DEFSIG(SIGPROF);
        DEFSIG(SIGSYS);
        DEFSIG(SIGTRAP);
        DEFSIG(SIGURG);
        DEFSIG(SIGVTALRM);
        DEFSIG(SIGXCPU);
        DEFSIG(SIGXFSZ);
    default:
        {
            static char buffer[50];
            sprintf( buffer, "signal %d", sig );

            return buffer;
        }
    }
}

// Returns 0 if process terminated
// Signal number if stopped by that signal
int print_wait_res( pid_t pid, int status )
{
    if( WIFEXITED(status) ) {
        printf("Process %d exit with exit code %d\n", pid, WEXITSTATUS(status) );

        return 0;
    }

    if( WIFSIGNALED(status) ) {
        printf("Process %d exit with %s%s\n", pid, translate_signal(WTERMSIG(status)),
                WCOREDUMP(status) ? "" : "(core dumped)" );

        return 0;
    }

    int signal=-1;
    if( WIFSTOPPED(status) ) {
        signal=WSTOPSIG(status);
        printf("Process %d stopped with %s\n", pid, translate_signal(signal) );
    }

    return signal;
}

int process_parent( pid_t child )
{
    int sig;

    do {
        int status;
        pid_t pid;

        pid=wait(&status);
        sig=print_wait_res( pid, status );

        if( sig==SIGTRAP ) {
            siginfo_t siginfo;
            long res=ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);

            if( res<0 ) {
                perror("ptrace(GETSIGINFO failed)");
            } else {
                printf("siginfo.si_code=%d\n", siginfo.si_code );
            }

            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        } else {
            int sig2=sig;
            if( sig2==SIGSTOP )
                sig2=0;

            ptrace(PTRACE_SINGLESTEP, pid, 0, sig2);
        }
    } while( sig>0 );

    return 0;
}

int process_child( char *us )
{
    if( ptrace( PTRACE_TRACEME, 0, 0, 0 )<0 ) {
        perror("ptrace(TRACEME) failed");

        return 1;
    }

    kill(getpid(), SIGSTOP );

    kill(getpid(), SIGTRAP );

    char *argv[]={ us, "arg", NULL };
    execvp( argv[0], argv );

    return 2;
}

// Called when we exec ourselves
int second_child_run()
{
    return 3;
}

int main(int argc, char *argv[])
{
    pid_t child=fork();

    if( argc>1 ) {
        return second_child_run();
    }

    if( child<0 ) {
        perror("fork failed");
        return 1;
    }

    if( child==0 ) {
        return process_child(argv[0]);
    }

    return process_parent( child );
}
