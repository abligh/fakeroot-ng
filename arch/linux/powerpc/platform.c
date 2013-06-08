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
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/syscall.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../platform.h"
#include "../os.h"

#define mem_offset 8
static const char memory_image[mem_offset]=
{
    0x44, 0x00, 0x00, 0x02, /* sc */
};

void ptlib_init()
{
    // Nothing to be done on this platform
}

int ptlib_continue( int request, pid_t pid, int signal )
{
    return ptlib_linux_continue( request, pid, signal );
}

const void *ptlib_prepare_memory( )
{
    return memory_image;
}


size_t ptlib_prepare_memory_len()
{
    return mem_offset;
}

void ptlib_prepare( pid_t pid )
{
    ptlib_linux_prepare( pid );
}

int ptlib_wait( pid_t *pid, int *status, ptlib_extra_data *data, int async )
{
    return ptlib_linux_wait( pid, status, data, async );
}

long ptlib_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type )
{
    return ptlib_linux_parse_wait( pid, status, type );
}

int ptlib_get_syscall( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*PT_R0, 0 );
}

int ptlib_set_syscall( pid_t pid, int sc_num )
{
    return ptrace( PTRACE_POKEUSER, pid, 4*PT_R0, sc_num );
}

int ptlib_generate_syscall( pid_t pid, int sc_num, int_ptr base_memory )
{
    /* Cannot generate a syscall per-se. Instead, set program counter to an instruction known to generate one */
    ptrace( PTRACE_POKEUSER, pid, 4*PT_R0, sc_num );
    ptrace( PTRACE_POKEUSER, pid, 4*PT_NIP, base_memory-mem_offset );

    return 1;
}

int_ptr ptlib_get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return ptrace( PTRACE_PEEKUSER, pid, 4*(PT_R3+argnum-1), 0 );

    /* Illegal arg num */
    dlog("ptlib_get_argument: "PID_F" Illegal argnum %d was asked for\n", pid, argnum );
    errno=EINVAL;

    return -1;
}

int ptlib_set_argument( pid_t pid, int argnum, int_ptr value )
{
    if( argnum<=6 && argnum>0 )
        return ptrace( PTRACE_POKEUSER, pid, 4*(PT_R3+argnum-1), value )==0;

    /* Illegal arg num */
    dlog("ptlib_set_argument: "PID_F" Illegal argnum %d was asked for\n", pid, argnum );
    errno=EINVAL;

    return -1;
}

int_ptr ptlib_get_retval( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*PT_R3 );
}

#define SO_MASK 0x10000000

void ptlib_set_retval( pid_t pid, int_ptr val )
{
    // Clear SO so we register success
    unsigned long cr=ptrace( PTRACE_PEEKUSER, pid, PT_CCR*4, 0 );
    cr&=~SO_MASK;
    ptrace( PTRACE_POKEUSER, pid, PT_CCR*4, cr );
    ptrace( PTRACE_POKEUSER, pid, 4*PT_R3, val );
}

int ptlib_get_error( pid_t pid, int sc_num )
{
    return (int)ptlib_get_retval( pid );
}

void ptlib_set_error( pid_t pid, int sc_num, int val )
{
    unsigned long cr=ptrace( PTRACE_PEEKUSER, pid, PT_CCR*4, 0 );
    cr|=SO_MASK;
    ptrace( PTRACE_POKEUSER, pid, PT_CCR*4, cr );
    ptrace( PTRACE_POKEUSER, pid, 4*PT_R3, val );
}

int ptlib_success( pid_t pid, int sc_num )
{
    /* PowerPC sets the Summary Overflow upon error */
    unsigned long cr=ptrace( PTRACE_PEEKUSER, pid, PT_CCR*4, 0 );

    return (cr&SO_MASK)==0;
}

int ptlib_get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len )
{
    return ptlib_linux_get_mem( pid, process_ptr, local_ptr, len );
}

int ptlib_set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len )
{
    return ptlib_linux_set_mem( pid, local_ptr, process_ptr, len );
}

int ptlib_get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen )
{
    return ptlib_linux_get_string( pid, process_ptr, local_ptr, maxlen );
}

int ptlib_set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr )
{
    return ptlib_linux_set_string( pid, local_ptr, process_ptr );
}

ssize_t ptlib_get_cwd( pid_t pid, char *buffer, size_t buff_size )
{
    return ptlib_linux_get_cwd( pid, buffer, buff_size );
}

ssize_t ptlib_get_fd( pid_t pid, int fd, char *buffer, size_t buff_size )
{
    return ptlib_linux_get_fd( pid, fd, buffer, buff_size );
}

void ptlib_save_state( pid_t pid, void *buffer )
{
    int i;
    for( i=0; i<PTLIB_STATE_SIZE; ++i ) {
        ((long *)buffer)[i]=ptrace(PTRACE_PEEKUSER, pid, i*4, 0 );
    }
}

void ptlib_restore_state( pid_t pid, const void *buffer )
{
    int i;
    for( i=0; i<PTLIB_STATE_SIZE; ++i ) {
        ptrace(PTRACE_POKEUSER, pid, i*4, ((long *)buffer)[i] );
    }
}

pid_t ptlib_get_parent( pid_t pid )
{
    return ptlib_linux_get_parent(pid);
}

int ptlib_fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[PTLIB_STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] )
{
    return ptlib_linux_fork_enter( pid, orig_sc, process_mem, our_mem, registers, context );
}

int ptlib_fork_exit( pid_t pid, pid_t *newpid, void *registers[PTLIB_STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] )
{
    return ptlib_linux_fork_exit( pid, newpid, registers, context );
}
