/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "syscalls.h"
#include "arch/platform.h"
#include "process.h"
#include "chroot.h"

// XXX
// Not implemented functions:
// acct

bool sys_fork( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // XXX It is not clear whether we should lock the shared memory while in this call.
        // PROC_MEM_LOCK();
        if( ptlib_fork_enter( pid, sc_num, state->mem->get_shared(), state->mem->get_loc(), state->saved_state,
                    state->context_state+1 ) )
        {
            state->state=pid_state::RETURN;
        } else {
            state->state=pid_state::REDIRECT2;
        }

        state->context_state[0]=0;
    } else if( state->state==pid_state::RETURN || state->state==pid_state::REDIRECT2 ) {
        pid_t newpid;
        if( ptlib_fork_exit( pid, &newpid, state->saved_state, state->context_state+1 ) && newpid>0 ) {
            handle_new_process( pid, newpid );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_vfork( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        sys_fork( sc_num, pid, state );
        state->context_state[0]=NEW_PROCESS_SAME_VM;
        // XXX Is this a Linux specific thing?
    } else {
        sys_fork( sc_num, pid, state );
    }

    return true;
}

#ifdef SYS_clone
bool sys_clone( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;

        // Need to mark context_state[0] based on the type of new process being created
        state->context_state[0]=0;
        int_ptr flags=ptlib_get_argument( pid, 1 );

        if( (flags&(CLONE_PARENT|CLONE_THREAD))!=0 )
            state->context_state[0]|=NEW_PROCESS_SAME_PARENT;
        if( (flags&CLONE_FS)!=0 )
            state->context_state[0]|=NEW_PROCESS_SAME_ROOT;
        if( (flags&CLONE_FILES)!=0 )
            state->context_state[0]|=NEW_PROCESS_SAME_FD;
        if( (flags&CLONE_VM)!=0 )
            state->context_state[0]|=NEW_PROCESS_SAME_VM;
        if( (flags&CLONE_PTRACE)!=0 )
            state->context_state[0]|=NEW_PROCESS_SAME_DEBUGGER;

        dlog(PID_F": clone called with flags %lx\n", pid, (unsigned long)flags );

        // Whatever it originally was, add a CLONE_PTRACE to the flags so that we remain in control
        flags|=CLONE_PTRACE;
        flags&=~CLONE_UNTRACED; // Reset the UNTRACED flag

        ptlib_set_argument( pid, 1, flags );
    } else if( state->state==pid_state::RETURN ) {
        // Was the call successful?
        state->state=pid_state::NONE;

        if( ptlib_success( pid, state->orig_sc ) ) {
            pid_t newpid=(pid_t)ptlib_get_retval( pid );
            dlog(PID_F": clone succeeded, new process " PID_F "\n", pid, newpid );
            handle_new_process( pid, newpid );
        } else {
            dlog(PID_F": clone failed: %s\n", pid, strerror( ptlib_get_error( pid, state->orig_sc ) ) );
        }
    }

    return true;
}
#endif // SYS_CLONE

// Function interface is different - returns an extra bool to signify whether to send a trap after the call
// context_state[0] is state machine:
// 0 - just returned from execve
// 1 - got a SIGTRAP after execve
// if context_state[1] is not 0, force error on syscall
bool sys_execve( int sc_num, pid_t pid, pid_state *state, bool &trap_after_call )
{
    trap_after_call=false;

    if( state->state==pid_state::NONE ) {
        PROC_MEM_LOCK();

        state->context_state[1]=0; // Don't force error by default

        if( log_level>0 ) {
            char cmd[PATH_MAX];
            ptlib_get_string( pid, ptlib_get_argument( pid, 1 ), cmd, sizeof(cmd) );
            dlog("execve: " PID_F " calling execve for executing %s\n", pid, cmd );
            dlog(NULL);
        }

        if( chroot_is_chrooted( state ) ) {
            if( !chroot_translate_param( pid, state, 1, true, true ) ) {
                // We had an error translating the file name - pass the error on
                state->context_state[1]=errno;

                ptlib_set_syscall( pid, PREF_NOP );
                // REDIRECT2 is set anyways
            }
        }

        // On some platforms "execve" returns, when successful, with SYS_restart_syscall or some such thing
        state->state=pid_state::REDIRECT2;
        state->context_state[0]=0;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( state->context_state[0]==0 ) {
            // Execve returned
            state->state=pid_state::NONE;

            if( ptlib_success( pid, sc_num ) && state->context_state[1]==0 ) {
                dlog("execve: " PID_F " successfully execed a new command\n", pid );

                // All memory allocations performed before the exec are now null and void
                state->mem=ref_count<pid_state::process_memory>(new pid_state::process_memory);

#if PTLIB_TRAP_AFTER_EXEC
                // The platform sends a SIGTRAP to the process after a successful execve, which results in us thinking it was
                // a syscall. We need to absorb it
                state->state=pid_state::REDIRECT2;
                state->context_state[0]=1;

                if( state->trace_mode==TRACE_SYSCALL ) {
                    // We are not in the "NONE" state, but the syscall is over. Tell parent to trap
                    trap_after_call=true;
                }
#endif
            } else if( state->context_state[1]!=0 ) {
                dlog("execve: " PID_F " chroot translation forced error on us: %s\n", pid, strerror(state->context_state[1]) );

                ptlib_set_error( pid, state->orig_sc, state->context_state[1] );
            } else {
                dlog("execve: " PID_F " failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)) );
            }
        } else {
            state->state=pid_state::NONE;
            dlog("execve: " PID_F " absorbed dummy SIGTRAP after successful execve\n", pid );
            
            // If the trace mode is not SYSCALL, the post handling will not generate a TRACE. If PTLIB_TRAP_AFTER_EXEC is set,
            // a trace is required, however, even if not in TRACE_SYSCALL
            trap_after_call=true;
        }
    }

    return true;
}

bool sys_sigreturn( int sc_num, pid_t pid, pid_state *state )
{
    // This is not a function call. In particular, this "not function call" may wreak haevoc in our state keeping, and
    // thus the special handling
    if( state->state==pid_state::NONE ) {
        // Upon syscall exit, at least on Linux, the syscall is "-1"
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setsid( int sc_num, pid_t pid, pid_state *state )
{
    // We do not do any actual manipulation on the syscall. We just keep track over the process' session ID
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) ) {
            state->session_id=pid;
        }
    }

    return true;
}

// This call needs to be emulated under one of two conditions:
// 1. Platform does not support "wait" by parent on a debugged child (PTLIB_PARENT_CAN_WAIT=0)
// 2. The parent is a debugger (we are emulating the entire ptrace interface)
//
// Of course, with PTRACE_TRACEME, it is possible that the process not have a debugee when it
// starts the wait, but does have one by the time wait should return. We therefor emulate the
// entire system call, always :-(
static bool real_wait4( int sc_num, pid_t pid, pid_state *state, pid_t param1, int *param2, int param3, void *param4 )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=param1; // pid
        state->context_state[1]=(int_ptr)param2; // status
        state->context_state[2]=param3; // options
        state->context_state[3]=(int_ptr)param4; // rusage

        dlog("wait4: %d num debugees: %d num children: %d, queue %s\n", pid, state->num_debugees, state->num_children,
                state->waiting_signals.empty()?"is empty":"has signals" );

        // Test whether the (emulated) call should fail
        // XXX This is nowhere near the exhustive tests we need to do. We only aim to emulate strace and ourselves at this point in time
        if( state->num_children!=0 || state->num_debugees!=0 || !state->waiting_signals.empty() ) {
            // Only wait if there was no error
            state->state=pid_state::WAITING;
        } else {
            // Set an ECHILD return code
            state->state=pid_state::REDIRECT2;
            ptlib_set_syscall( pid, PREF_NOP ); // NOP call
            state->context_state[0]=-ECHILD;
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        // We may get here under two conditions.
        // Either the wait was performed by us and a NOP was carried out, in which case the syscall is going to be PREF_NOP
        // and context_state[0] contains the desired return code (negative for error)
        // Or 
        // A function substancially similar to wait was carried out, in which case context_state[0] contains a backup of the original
        // content of the fourth parameter register, which may have not been used by the original syscall if it was not wait4
        if( sc_num==PREF_NOP ) {
            // Performed NOP - set return codes
            if( ((long)state->context_state[0])>=0 )
                ptlib_set_retval( pid, state->context_state[0] );
            else
                ptlib_set_error( pid, state->orig_sc, -state->context_state[0] );

            ptlib_set_syscall( pid, state->orig_sc );
        } else {
            // If an actual wait syscall was carried out, we may need to restore the original content of argument 4
            ptlib_set_argument( pid, 4, state->context_state[0] );
        }

        ptlib_set_syscall( pid, state->orig_sc );
        state->state=pid_state::NONE;
    }

    if( state->state==pid_state::WAITING ) {
        if( !state->waiting_signals.empty() ) {
            // Let's see what was asked for
            pid_t wait_pid=(pid_t)state->context_state[0];
            std::list<pid_state::wait_state>::iterator child=state->waiting_signals.begin();
            assert(child!=state->waiting_signals.end());

            pid_state *child_state=NULL;

            if( wait_pid<-1 ) {
                // We are looking for process with session id= -pid
                child_state=lookup_state(child->pid());
                while( child!=state->waiting_signals.end() && child_state->session_id!=-wait_pid )
                {
                    if( (++child)!=state->waiting_signals.end() )
                    {
                        child_state=lookup_state(child->pid());
                        assert(child_state!=NULL);
                    }
                }
            } else if( wait_pid==-1 ) {
                // Wait for anything. Just leave child as it is
            } else if( wait_pid==0 ) {
                // Wait for session_id==parent's
                child_state=lookup_state(child->pid());
                while( child!=state->waiting_signals.end() && child_state->session_id!=state->session_id )
                {
                    if( (++child)!=state->waiting_signals.end() )
                    {
                        child_state=lookup_state(child->pid());
                        assert(child_state!=NULL);
                    }
                }
            } else {
                // Wait for exact match
                while( child!=state->waiting_signals.end() && child->pid()!=wait_pid )
                    ++child;
            }

            if( child!=state->waiting_signals.end() ) {
                // We have what to report
                if( child_state==NULL ) {
                    child_state=lookup_state(child->pid());
                    assert(child_state!=NULL);
                }

                assert( child_state->state!=pid_state::INIT );
               
                if( child_state->state==pid_state::ZOMBIE ) {
                    // We can dispense with the pid entry
                    delete_state(child->pid());
                    dlog("%s: Child " PID_F " removed from process table\n", __func__, child->pid() );
                    child_state=NULL;
                }

                // allow the syscall to return
                
                // Fill in the rusage
                if( ((void *)state->context_state[3])!=NULL )
                    ptlib_set_mem( pid, &child->usage(), state->context_state[3], sizeof(child->usage()) );

                // Is this a report about a terminated program?
                if( !child->debugonly() )
                {
                    // If the parent never carried out the actual "wait", the child will become a zombie
                    // We turn the syscall into a waitpid with the child's pid explicitly given
#ifdef SYS_wait4
                    ptlib_set_syscall( pid, SYS_wait4 );
#else
                    ptlib_set_syscall( pid, SYS_waitpid );
#endif
                    state->saved_state[0]=(void *)ptlib_get_argument( pid, 4 ); // Save the fourth argument
                    ptlib_set_argument( pid, 1, child->pid() );
                    ptlib_set_argument( pid, 2, state->context_state[1] );
                    ptlib_set_argument( pid, 3, state->context_state[2] );
                    ptlib_set_argument( pid, 4, state->context_state[3] );
                } else {
                    // We need to explicitly set all the arguments
                    if( ((void *)state->context_state[1])!=NULL )
                        ptlib_set_mem( pid, &child->status(), state->context_state[1], sizeof(child->status()) );

                    ptlib_set_syscall( pid, PREF_NOP );

                    state->context_state[0]=child->pid();
                }

                state->waiting_signals.erase( child );

                state->state=pid_state::REDIRECT2;
            } else {
                dlog("wait4: " PID_F " hanged in wait for %d\n", pid, wait_pid );
            }
        }
        
        if( state->state==pid_state::WAITING && (state->context_state[2]&WNOHANG)!=0 ) {
            // Client asked never to hang
            state->state=pid_state::REDIRECT2;
            ptlib_set_syscall( pid, PREF_NOP );
            state->context_state[0]=0;
        }
    }

    return state->state!=pid_state::WAITING;
}

bool sys_wait4( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        pid_t param1=(pid_t)ptlib_get_argument(pid, 1); // pid
        int *param2=(int *)ptlib_get_argument(pid, 2); // status
        int param3=ptlib_get_argument(pid, 3); // options
        void *param4=(void *)ptlib_get_argument(pid, 4); // rusage

        return real_wait4( sc_num, pid, state, param1, param2, param3, param4 );
    } else {
        return real_wait4( sc_num, pid, state, 0, NULL, 0, NULL );
    }
}

// We just set the variables and let wait4 handle our case
bool sys_waitpid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        pid_t param1=ptlib_get_argument(pid, 1); // pid
        int *param2=(int *)ptlib_get_argument(pid, 2); // status
        int param3=ptlib_get_argument(pid, 3); // options

        return real_wait4( sc_num, pid, state, param1, param2, param3, NULL );
    } else {
        return real_wait4( sc_num, pid, state, 0, NULL, 0, NULL );
    }
}

// We want to prevent the process from killing us
bool sys_kill( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;

        if( ((pid_t)ptlib_get_argument( pid, 1 ))==getpid() ) {
            // Process tried to send us a signal. Can't allow that
            state->state=pid_state::REDIRECT2;
            ptlib_set_syscall( pid, PREF_NOP);
        }
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;
        ptlib_set_error( pid, state->orig_sc, EPERM );
    }

    return true;
}
