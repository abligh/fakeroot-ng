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

#include <errno.h>

#include "syscalls.h"
#include "arch/platform.h"

bool sys_getuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->uid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_geteuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->euid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_getgid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->gid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_getegid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->egid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

#ifdef SYS_getresuid
bool sys_getresuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        
        // Do not trust the syscall not to change the pointers
        state->context_state[0]=ptlib_get_argument( pid, 1 );
        state->context_state[1]=ptlib_get_argument( pid, 2 );
        state->context_state[2]=ptlib_get_argument( pid, 3 );
        break;
    case pid_state::RETURN:
        if( ptlib_success(pid, sc_num) ) {
            bool success;
            success=ptlib_set_mem( pid, &state->uid, state->context_state[0], sizeof(state->uid) );
            success=success && ptlib_set_mem( pid, &state->euid, state->context_state[1], sizeof(state->euid) );
            success=success && ptlib_set_mem( pid, &state->suid, state->context_state[2], sizeof(state->suid) );

            if( !success ) {
                ptlib_set_error( pid, state->orig_sc, errno );
            }
        }
        state->state=pid_state::NONE;
        break;
    }

    return true;
}
#endif

#ifdef SYS_getresgid
bool sys_getresgid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        
        // Do not trust the syscall not to change the pointers
        state->context_state[0]=ptlib_get_argument( pid, 1 );
        state->context_state[1]=ptlib_get_argument( pid, 2 );
        state->context_state[2]=ptlib_get_argument( pid, 3 );
        break;
    case pid_state::RETURN:
        if( ptlib_success(pid, sc_num) ) {
            bool success;
            success=ptlib_set_mem( pid, &state->gid, state->context_state[0], sizeof(state->gid) );
            success=success && ptlib_set_mem( pid, &state->egid, state->context_state[1], sizeof(state->egid) );
            success=success && ptlib_set_mem( pid, &state->sgid, state->context_state[2], sizeof(state->sgid) );

            if( !success ) {
                ptlib_set_error( pid, state->orig_sc, errno );
            }
        }
        state->state=pid_state::NONE;
        break;
    }

    return true;
}
#endif

bool sys_getgroups( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        ptlib_set_syscall(pid, PREF_NOP);
        state->state=pid_state::REDIRECT2;

        // Store the arguments for later
        state->context_state[0]=ptlib_get_argument( pid, 1 );
        state->context_state[1]=ptlib_get_argument( pid, 2 );
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        // What is the size?
        if( state->context_state[0]==0 ) {
            // Merely report the number of groups we have
            ptlib_set_retval( pid, state->groups.size() );
        } else if( state->context_state[0]<state->groups.size() ) {
            // Not enough room
            ptlib_set_error( pid, state->orig_sc, EINVAL );
        } else {
            unsigned int count=0;
            gid_t *groups=(gid_t *)state->context_state[1];
            bool success=true;
            for( std::set<gid_t>::const_iterator i=state->groups.begin(); success && i!=state->groups.end(); ++i, ++count ) {
                success=ptlib_set_mem( pid, &*i, (int_ptr)(groups+count), sizeof(gid_t) );
            }

            if( success )
                ptlib_set_retval( pid, count );
            else
                ptlib_set_error( pid, state->orig_sc, errno );
        }
    }

    return true;
}

bool sys_setuid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        uid_t uid=(uid_t)state->context_state[0];
        if( state->euid==ROOT_UID ) {
            // Super user version
            state->uid=state->euid=state->suid=state->fsuid=uid;
            ptlib_set_retval( pid, 0 );
        } else if( state->uid==uid || state->suid==uid ) {
            // Regular user, but with an operation that is ok
            state->euid=state->fsuid=uid;
            ptlib_set_retval (pid, 0 );
        } else {
            // No permission
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

static bool check_uids( uid_t new_uid, const pid_state *state )
{
    return state->euid==ROOT_UID || new_uid==state->uid || new_uid==state->euid || new_uid==state->suid;
}

bool sys_seteuid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        uid_t uid=(uid_t)state->context_state[0];

        if( check_uids( uid, state ) ) {
            state->euid=state->fsuid=uid;
            ptlib_set_retval( pid, 0 );
        } else {
            // No permission
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setfsuid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        uid_t uid=(uid_t)state->context_state[0];
        uid_t old_fsuid=state->fsuid;

        if( check_uids( uid, state ) ) {
            state->fsuid=uid;
        } else {
            // No permission - nothing to do
        }

        ptlib_set_retval( pid, old_fsuid );

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setresuid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 ); //ruid
        state->context_state[1]=ptlib_get_argument( pid, 2 ); //euid
        state->context_state[2]=ptlib_get_argument( pid, 3 ); //suid

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        bool success=true;
        uid_t new_uid=state->uid, new_euid=state->euid, new_suid=state->suid;

        if( state->context_state[0]!=(int_ptr)-1 ) {
            if( check_uids( state->context_state[0], state ) )
                new_uid=state->context_state[0];
            else
                success=false;
        }

        if( state->context_state[1]!=(int_ptr)-1 ) {
            if( success && check_uids( state->context_state[1], state ) )
                new_euid=state->context_state[1];
            else
                success=false;
        }

        if( state->context_state[2]!=(int_ptr)-1 ) {
            if( success && check_uids( state->context_state[2], state ) )
                new_suid=state->context_state[2];
            else
                success=false;
        }

        // If all checks passed, commit the changes
        if( success ) {
            state->uid=new_uid;
            state->euid=new_euid;
            state->suid=new_suid;

            ptlib_set_retval( pid, 0 );
        } else {
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setreuid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 ); //ruid
        state->context_state[1]=ptlib_get_argument( pid, 2 ); //euid

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        bool success=true;
        uid_t new_uid=state->uid, new_euid=state->euid, new_suid=state->suid;

        if( state->context_state[0]!=(int_ptr)-1 ) {
            // XXX Linux specific behavior
            if( state->euid==ROOT_UID || state->context_state[0]==state->uid || state->context_state[0]==state->suid )
                new_uid=state->context_state[0];
            else
                success=false;
        }

        if( state->context_state[1]!=(int_ptr)-1 ) {
            if( success && check_uids( state->context_state[1], state ) )
                new_euid=state->context_state[1];
            else
                success=false;
        }

        // There is no POSIX documentation on what should happen to the saved UID. The following is the Linux logic
        if( success && (state->context_state[0]!=(int_ptr)-1 ||
                    ( state->context_state[1]!=(int_ptr)-1 && state->context_state[1]!=state->uid )) )
        {
            new_suid=new_euid;
        }

        // If all checks passed, commit the changes
        if( success ) {
            state->uid=new_uid;
            state->euid=state->fsuid=new_euid;
            state->suid=new_suid;

            ptlib_set_retval( pid, 0 );
        } else {
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setgroups( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        ptlib_set_syscall(pid, PREF_NOP);
        state->state=pid_state::REDIRECT2;

        // Store the arguments for later
        state->context_state[0]=ptlib_get_argument( pid, 1 );
        state->context_state[1]=ptlib_get_argument( pid, 2 );
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        std::set<gid_t> new_groups;
        gid_t *process_groups=(gid_t *)state->context_state[1];

        int error=0;
        while( error==0 && state->context_state[0]>0 ) {
            gid_t group;

            if( ptlib_get_mem( pid, (int_ptr)process_groups++, &group, sizeof(gid_t) ) ) {
                new_groups.insert(group);
                --state->context_state[0];
            } else {
                error=errno;
            }
        }

        if( error==0 ) {
            state->groups=new_groups;

            ptlib_set_retval( pid, 0 );
        } else {
            ptlib_set_error( pid, state->orig_sc, error );
        }
    }

    return true;
}

bool sys_setgid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        gid_t gid=(gid_t)state->context_state[0];
        if( state->egid==ROOT_UID ) {
            // Super user version
            state->gid=state->egid=state->sgid=state->fsgid=gid;
            ptlib_set_retval( pid, 0 );
        } else if( state->gid==gid || state->sgid==gid ) {
            // Regular user, but with an operation that is ok
            state->egid=state->fsgid=gid;
            ptlib_set_retval (pid, 0 );
        } else {
            // No permission
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

static bool check_gids( gid_t new_gid, const pid_state *state )
{
    return state->egid==ROOT_GID || new_gid==state->gid || new_gid==state->egid || new_gid==state->sgid;
}

bool sys_setegid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Save the original arguments
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        gid_t gid=(gid_t)state->context_state[0];

        if( check_gids( gid, state ) ) {
            state->egid=state->fsgid=gid;
            ptlib_set_retval( pid, 0 );
        } else {
            // No permission
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setfsgid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        gid_t gid=(gid_t)state->context_state[0];
        gid_t old_fsgid=state->fsgid;

        if( check_gids( gid, state ) ) {
            state->fsgid=gid;
        } else {
            // No permission - nothing to do
        }

        ptlib_set_retval( pid, old_fsgid );

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setresgid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 ); //rgid
        state->context_state[1]=ptlib_get_argument( pid, 2 ); //egid
        state->context_state[2]=ptlib_get_argument( pid, 3 ); //sgid

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        bool success=true;
        gid_t new_gid=state->gid, new_egid=state->egid, new_sgid=state->sgid;

        if( state->context_state[0]!=(int_ptr)-1 ) {
            if( check_gids( state->context_state[0], state ) )
                new_gid=state->context_state[0];
            else
                success=false;
        }

        if( state->context_state[1]!=(int_ptr)-1 ) {
            if( success && check_gids( state->context_state[1], state ) )
                new_egid=state->context_state[1];
            else
                success=false;
        }

        if( state->context_state[2]!=(int_ptr)-1 ) {
            if( success && check_gids( state->context_state[2], state ) )
                new_sgid=state->context_state[2];
            else
                success=false;
        }

        // If all checks passed, commit the changes
        if( success ) {
            state->gid=new_gid;
            state->egid=new_egid;
            state->sgid=new_sgid;

            ptlib_set_retval( pid, 0 );
        } else {
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_setregid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 ); //rgid
        state->context_state[1]=ptlib_get_argument( pid, 2 ); //egid

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        bool success=true;
        gid_t new_gid=state->gid, new_egid=state->egid, new_sgid=state->sgid;

        if( state->context_state[0]!=(int_ptr)-1 ) {
            // XXX Linux specific behavior
            if( state->egid==ROOT_GID || state->context_state[0]==state->gid || state->context_state[0]==state->sgid )
                new_gid=state->context_state[0];
            else
                success=false;
        }

        if( state->context_state[1]!=(int_ptr)-1 ) {
            if( success && check_gids( state->context_state[1], state ) )
                new_egid=state->context_state[1];
            else
                success=false;
        }

        // There is no POSIX documentation on what should happen to the saved UID. The following is the Linux logic
        if( success && (state->context_state[0]!=(int_ptr)-1 || 
                    ( state->context_state[1]!=(int_ptr)-1 && state->context_state[1]!=state->gid )) )
        {
            new_sgid=new_egid;
        }

        // If all checks passed, commit the changes
        if( success ) {
            state->gid=new_gid;
            state->egid=state->fsgid=new_egid;
            state->sgid=new_sgid;

            ptlib_set_retval( pid, 0 );
        } else {
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state=pid_state::NONE;
    }

    return true;
}
