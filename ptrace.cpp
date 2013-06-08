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

#include <sys/ptrace.h>
#include <errno.h>

#include <string.h>

#include "syscalls.h"
#include "arch/platform.h"

// Retruns true of the specified pid has permission to perform a ptrace operation
static bool verify_permission( pid_t pid, pid_state *state )
{
    pid_t traced=(pid_t)state->context_state[1];

    // First, find out whether the pid we work on even exists

    pid_state *child_state=lookup_state( traced );
    if( child_state==NULL || child_state->debugger!=pid )
    {
        dlog("ptrace verify_permission: %d failed permission - not the debugger for " PID_F "\n", pid, traced);
        errno=ESRCH;
        return false;
    }
    if( child_state->trace_mode!=TRACE_STOPPED1 && child_state->trace_mode!=TRACE_STOPPED2 )
    {
        dlog("ptrace verify_permission: %d failed permission - " PID_F " is not stopped\n", pid, traced);
        errno=ESRCH;
        return false;
    }

    return true;
}

static bool begin_trace( pid_t debugger, pid_t child )
{
    pid_state *child_state=lookup_state( child );
    pid_state *parent_state=lookup_state( debugger );

    if( child_state==NULL || parent_state==NULL || child_state->debugger!=0 ) {
        dlog("begin_trace: %d Failed to start trace for " PID_F ": child_state=%p, parent_state=%p", debugger, child, child_state,
            parent_state );
        if( child_state!=NULL ) {
            dlog("child_state debugger=" PID_F, child_state->debugger);
        }
        dlog("\n");

        errno=EPERM;
        return false;
    }

    child_state->debugger=debugger;
    child_state->trace_mode=PTRACE_CONT;
    parent_state->num_debugees++;

    return true;
}

static void real_handle_cont( pid_t pid, pid_state *state )
{
    pid_t child=(pid_t)state->context_state[1];
    pid_state *child_state=lookup_state( child );
    __ptrace_request req=(__ptrace_request)state->context_state[0];
    if( req==PTRACE_CONT ) {
        child_state->trace_mode|=TRACE_CONT;
        dlog("ptrace: %d PTRACE_CONT(" PID_F ")\n", pid, child );
    } else if( req==PTRACE_SYSCALL ) {
        child_state->trace_mode|=TRACE_SYSCALL;
        dlog("ptrace: %d PTRACE_SYSCALL(" PID_F ")\n", pid, child );
    } else if( req==PTRACE_DETACH ) {
        child_state->trace_mode&=TRACE_MASK2;
    } else {
        // Wrong mode for calling this function!
    }

    long rc=0;

    if( (child_state->trace_mode&TRACE_MASK2)==TRACE_STOPPED1 ) {
        dlog("handle_cont_syscall: " PID_F " process " PID_F " was in pre-syscall hook\n", pid, child );
        // Need to restart the syscall
        int status=child_state->context_state[1];
        PTLIB_WAIT_RET wait_state=(PTLIB_WAIT_RET)child_state->context_state[0];
        long ret=ptlib_get_syscall( child );
        int sig=process_sigchld( child, wait_state, status, ret );
        // If our processing requested no special handling, use the signal requested by the debugger
        if( sig==0 ) {
            sig=(int)state->context_state[3];
        }
        if( sig>=0 ) {
            rc=ptlib_continue(PTRACE_SYSCALL, child, sig);
        }
    } else if( (child_state->trace_mode&TRACE_MASK2)==TRACE_STOPPED2 ) {
        dlog("handle_cont_syscall: " PID_F " process " PID_F " was in post-syscall hook\n", pid, child );
        child_state->trace_mode&=TRACE_MASK1;
        rc=ptlib_continue( PTRACE_SYSCALL, child, (int)state->context_state[3] );
    } else {
        // Our child was not stopped (at least, by us)
        // This is an internal inconsistency

        dlog("handle_cont_syscall: " PID_F " process " PID_F " was started with no specific state (%x)\n", pid, child,
                child_state->trace_mode );
        dlog(NULL);
        rc=-1;
    }

    if( rc!=-1 ) {
        dlog("ptrace: %d request successful\n", pid );
        ptlib_set_retval( pid, rc );
    } else {
        ptlib_set_error( pid, state->orig_sc, errno );
        dlog("ptrace: %d request failed: %s\n", pid, strerror(errno) );
    }
}

static void handle_cont_syscall( pid_t pid, pid_state *state )
{
    if( verify_permission( pid, state ) ) {
        real_handle_cont( pid, state );
    } else {
        ptlib_set_error( pid, state->orig_sc, errno );
    }
}

static bool handle_detach( pid_t pid, pid_state *state )
{
    if( verify_permission( pid, state ) ) {
        dlog("ptrace: %d PTRACE_DETACH(" PID_F ")\n", pid, (pid_t)state->context_state[1]);

        pid_state *child_state=lookup_state((pid_t)state->context_state[1]);

        child_state->debugger=0;
        state->num_debugees--;

        child_state->trace_mode&=TRACE_MASK2;

        // Call the cont handler to make sure the debuggee is runing again
        real_handle_cont( pid, state );

        return true;
    } else {
        ptlib_set_error( pid, state->orig_sc, errno );
        return false;
    }
}

static void handle_kill( pid_t pid, pid_state *state )
{
    pid_t child=(pid_t)state->context_state[1];

    if( verify_permission( pid, state ) ) {
        dlog("handle_kill: %d is sending a kill to " PID_F "\n", pid, child );

        ptlib_continue(PTRACE_KILL, child, 0);
        ptlib_set_retval( pid, 0 );
    } else {
        ptlib_set_error( pid, state->orig_sc, errno );
        dlog("handle_kill: %d tried to kill " PID_F ": %s\n", pid, child, strerror(errno));
    }
}

static void handle_peek_data( pid_t pid, pid_state *state )
{
    pid_t child=(pid_t)state->context_state[1];

    if( verify_permission( pid, state ) ) {
        errno=0;
        long data=ptrace( (__ptrace_request)state->context_state[0], child, state->context_state[2], 0 );
        if( data!=-1 || errno==0 ) {
            dlog("handle_peek_data: %d is peeking data from " PID_F " at address %p\n", pid, child, (void*)state->context_state[2] );

            // Write the result where applicable
            // XXX This may be a Linux only semantics - pass addres to write result to as "data" argument
            data=ptlib_set_mem( pid, &data, state->context_state[3], sizeof(data));
            if( data!=-1 ) {
                ptlib_set_retval( pid, 0 );
            } else {
                ptlib_set_error( pid, state->orig_sc, errno );
                dlog("handle_peek_data: Our own poke failed: %s\n", strerror(errno) );
            }
        }
    } else {
        ptlib_set_error( pid, state->orig_sc, errno );
        dlog("handle_peek_data: %d tried get data from " PID_F ": %s\n", pid, child, strerror(errno));
    }
}

static void handle_poke_data( pid_t pid, pid_state *state )
{
    pid_t child=(pid_t)state->context_state[1];

    if( verify_permission( pid, state ) &&
        ptrace( (__ptrace_request)state->context_state[0], child, state->context_state[2], state->context_state[3] )==0 )
    {
        dlog("handle_poke_data: %d is pokeing data in " PID_F " at address %p\n", pid, child, (void*)state->context_state[2] );
        ptlib_set_retval( pid, 0 );
    } else {
        ptlib_set_error( pid, state->orig_sc, errno );
        dlog("handle_poke_data: %d tried push data to " PID_F ": %s\n", pid, child, strerror(errno));
    }
}

bool sys_ptrace( int sc_num, pid_t pid, pid_state *state )
{
    bool ret=true;

    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 1 ); // request
        state->context_state[1]=ptlib_get_argument( pid, 2 ); // pid
        state->context_state[2]=ptlib_get_argument( pid, 3 ); // addr
        state->context_state[3]=ptlib_get_argument( pid, 4 ); // data

        dlog("ptrace: " PID_F " ptrace( %d, " PID_F ", %p, %p )\n", pid, (int)state->context_state[0], (pid_t)state->context_state[1],
            (void*)state->context_state[2], (void*)state->context_state[3] );

        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        // Let's see what whether we need to succeed
        switch( state->context_state[0] ) {
        case PTRACE_TRACEME:
            if( begin_trace( state->parent, pid ) ) {
                dlog("ptrace: %d PTRACE_TRACEME parent " PID_F "\n", pid, state->parent );
                ptlib_set_retval( pid, 0 );
            } else {
                dlog("ptrace: %d PTRACE_TRACEME failed %s\n", pid, strerror(errno) );
                ptlib_set_error( pid, state->orig_sc, errno );
            }
            break;
        case PTRACE_ATTACH:
            if( begin_trace( pid, (pid_t)state->context_state[1] ) ) {
                dlog("ptrace: " PID_F " PTRACE_ATTACH(" PID_F ") succeeded\n", pid, (pid_t)state->context_state[1] );
                ptlib_set_retval( pid, 0 );
            } else {
                dlog("ptrace: " PID_F " PTRACE_ATTACH(" PID_F ") failed %s\n", pid, (pid_t)state->context_state[1], strerror(errno) );
                ptlib_set_error( pid, state->orig_sc, errno );
            }
            break;
        case PTRACE_PEEKTEXT:
        case PTRACE_PEEKDATA:
#if HAVE_PTRACE_PEEKUSER
        case PTRACE_PEEKUSER:
#endif
            handle_peek_data( pid, state );
            break;
        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA:
#if HAVE_PTRACE_PEEKUSER
        case PTRACE_POKEUSER:
#endif
            handle_poke_data( pid, state );
            break;
#if 0
        case PTRACE_GETREGS:
        case PTRACE_GETFPREGS:
            dlog("ptrace: %d GETREGS not yet implemented\n", pid);
            ptlib_set_error( pid, state->orig_sc, EINVAL );
            break;
        case PTRACE_SETREGS:
        case PTRACE_SETFPREGS:
            dlog("ptrace: %d SETREGS not yet implemented\n", pid);
            ptlib_set_error( pid, state->orig_sc, EINVAL );
            break;
        case PTRACE_GETSIGINFO:
            dlog("ptrace: %d GETSIGINFO not yet implemented\n", pid);
            ptlib_set_error( pid, state->orig_sc, EINVAL );
            break;
        case PTRACE_SETSIGINFO:
            dlog("ptrace: %d SETSIGINFO not yet implemented\n", pid);
            ptlib_set_error( pid, state->orig_sc, EINVAL );
            break;
#endif
        case PTRACE_SINGLESTEP:
            // We do not support single step right now
            ptlib_set_error( pid, state->orig_sc, EINVAL );
            dlog("ptrace: " PID_F " tried to call SINGLESTEP on " PID_F "\n", pid, (pid_t)state->context_state[1]);
            break;
        case PTRACE_CONT:
        case PTRACE_SYSCALL:
            handle_cont_syscall( pid, state );
            break;
        case PTRACE_KILL:
            handle_kill( pid, state );
            break;
        case PTRACE_DETACH:
            handle_detach( pid, state );
            break;
        default:
            dlog("ptrace: " PID_F " Unsupported option %lx\n", pid, state->context_state[0] );
            ptlib_set_error(pid, state->orig_sc, EINVAL);
            break;
        }

        ptlib_set_syscall( pid, state->orig_sc );
    }

    return ret;
}
