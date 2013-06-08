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
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "syscalls.h"
#include "parent.h"
#include "chroot.h"

// These are the Linux kernel parameters
static const int GLOBAL_LINKS=40, // How many links are globally allowed in the dir part of the resolution
    LOCAL_LINKS=8, // How many links each directory level is allowed to have nested
    LAST_MILE_LINKS=32; // How many links are allowed in the file part of the link

bool chroot_is_chrooted( const pid_state *state )
{
    return *state->root!="" && *state->root!="/";
}

// XXX The memory efficiency of the implementation can use a DRASTIC improvement
static std::string chroot_parse_path_recursion( const pid_state *state, char *path, const std::string &wd, struct stat *stat,
    int &global_link_count, int dir_link_count, bool resolve_links )
{
    std::string partial_path;
    
    // Body of function - find out the last path component position
    int last_slash=-1;
    for( int i=0; path[i]!='\0'; ++i )
        if( path[i]=='/' )
            last_slash=i;

    std::string file_part( path+last_slash+1 );

    // Remove redundant slashes
    while( last_slash>0 && path[last_slash-1]=='/' )
        last_slash--;

    std::string dir_part;

    if( last_slash>0 ) {
        // A slash appears in the file name, and it is not the first character
        
        path[last_slash]='\0'; // Chop off the file part
        dir_part=chroot_parse_path_recursion( state, path, wd, stat, global_link_count, LOCAL_LINKS, true ); // Translate the rest of the path

        if( (int)stat->st_ino==-1 ) {
            // Pass the error on - no further processing
            return dir_part+"/"+file_part;
        }
    } else if( last_slash==0 ) {
        // Need to process the leading slash
        dir_part=*state->root;
    } else {
        // A file part is all we have to begin with - see what the we are relative to
        dir_part=wd;
    }

    // At this point we have the leading directory in our (debugger) context, and the file part in debugee context
    if( file_part=="." || file_part=="" ) {
        // Same directory - do nothing more
        return dir_part;
    }

    if( file_part==".." ) {
        // We need to go one directory up. This is not as simple as it sounds

        // Are we currently at the root (either real or jail)?
        if( dir_part==*state->root || dir_part=="/" ) {
            // Going up is the same as staying at the same place
            return dir_part;
        }

        // Again - find the last slash in the string, and strip everything after it
        size_t last=dir_part.rfind('/');

        if( last==std::string::npos ) {
            dlog("chroot_parse_path: dir part \"%s\" with file part \"..\" has no way to go one up\n", dir_part.c_str());
            dlog(NULL);

            assert( last!=std::string::npos );
        }

        // Eliminate repeats
        while( last>0 && dir_part[last-1]=='/' )
            last--;

        if( last==0 ) // Leave one slash in place if that's all there is
            last++;

        return dir_part.substr(0, last);
    }

    // We now, finally, have an honest to god, non empty, non special, file part to handle
    std::string combined_path=dir_part+"/"+file_part;
    if( lstat( combined_path.c_str(), stat )==-1 ) {
        // We failed to stat the file. Just bounce the error to the caller
        stat->st_ino=-1;
        return combined_path;
    }

    // Is this a symbolic link?
    while( resolve_links && dir_link_count>0 && S_ISLNK(stat->st_mode) ) {
        if( (dir_link_count--)==0 || (global_link_count--)==0 ) {
            // We are out of patience for link processing
            errno=ELOOP;
            stat->st_ino=-1;
            return "";
        }

        char buffer[PATH_MAX+1];

        ssize_t link_len=readlink( combined_path.c_str(), buffer, sizeof(buffer) );

        if( link_len==-1 ) {
            dlog("chroot_parse_path_recursion: lstat succeeded for %s, but readlink failed: %s\n", combined_path.c_str(),
                strerror(errno) );

            return combined_path;
        }

        if( link_len==sizeof(buffer) ) {
            // Symbolic link's content is too long
            errno=ENAMETOOLONG;
            stat->st_ino=-1;

            return "";
        }

        buffer[link_len]='\0';

        if( strchr( buffer, '/' )==NULL ) {
            // The / character does not appear - just replace file_part with the new version
            file_part=buffer;
            combined_path=dir_part+"/"+file_part;
            if( lstat( combined_path.c_str(), stat )==-1 ) {
                // We failed to stat the file. Just bounce the error to the caller
                stat->st_ino=-1;
                return combined_path;
            }
        } else {
            // The symlink is a complex path - use ourselves recursively to figure out where it actually links to
            return chroot_parse_path_recursion( state, buffer, dir_part, stat, global_link_count, dir_link_count, false );
        }
    }

    return combined_path;
}

// Actual implementation - some sanity checking, and then call the recursive version
std::string chroot_parse_path( const pid_state *state, char *path, const std::string &wd, struct stat *stat, bool resolve_last_link )
{
    stat->st_ino=-2; // Mark this as a no-op. If we later do run a stat, it will be overridden

    if( path==NULL || path[0]=='\0' ) {
        stat->st_ino=-1;
        errno=ENOENT;
        return "";
    }

    int total_links=GLOBAL_LINKS;

    if( log_level==0 )
        return chroot_parse_path_recursion( state, path, wd, stat, total_links, LAST_MILE_LINKS, resolve_last_link );
    else {
        dlog("chroot_parse_path: translating %s with work dir of %s\n", path, wd.c_str());

        std::string ret=chroot_parse_path_recursion( state, path, wd, stat, total_links, LAST_MILE_LINKS, resolve_last_link );
        dlog("chroot_parse_path: translated path is %s\n", ret.c_str() );

        return ret;
    }
}

std::string chroot_translate_addr( pid_t pid, const pid_state *state, struct stat *stat, int dirfd, int_ptr addr, bool resolve_last_link )
{
    char filename[PATH_MAX], wd[PATH_MAX];
    ptlib_get_string( pid, addr, filename, sizeof(filename) );

    strcpy( wd, "/" );

    // Get the process' working dir
    if( dirfd==CHROOT_PWD )
        ptlib_get_cwd( pid, wd, sizeof(wd) );
    else
        ptlib_get_fd( pid, dirfd, wd, sizeof(wd) );

    return chroot_parse_path( state, filename, wd, stat, resolve_last_link );
}

bool chroot_translate_param( pid_t pid, const pid_state *state, int param_num, bool resolve_last_link, bool abort_error, int_ptr offset )
{
    return chroot_translate_paramat( pid, state, CHROOT_PWD, param_num, resolve_last_link, abort_error, offset );
}

// Same as chroot_translate_param, only for the *at family of functions
bool chroot_translate_paramat( pid_t pid, const pid_state *state, int dirfd, int param_num, bool resolve_last_link,
    bool abort_error, int_ptr offset )
{
    // Short path if we are not chrooted
    if( !chroot_is_chrooted(state) )
        return true;

    int_ptr path_addr=ptlib_get_argument( pid, param_num );
    if( path_addr==(int_ptr)NULL ) {
        // The process asked to work directly on the file descriptor - do not touch the path
        return true;
    }

    struct stat stat;

    std::string newpath=chroot_translate_addr( pid, state, &stat, dirfd, path_addr, resolve_last_link );

    if( stat.st_ino!=(ino_t)-1 || !abort_error ) {
        strcpy( state->mem->get_loc_c()+offset, newpath.c_str() );
        ptlib_set_argument( pid, param_num, state->mem->get_shared()+offset );
    }

    return stat.st_ino!=(ino_t)-1;
}

bool sys_chroot( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Save the path pointer and NOP the call
        state->context_state[0]=ptlib_get_argument( pid, 1 );
        state->state=pid_state::REDIRECT2;
        ptlib_set_syscall( pid, PREF_NOP );
    } else if( state->state==pid_state::REDIRECT2 ) {
        // We may already be chrooted - need to translate the path
        struct stat stat;
        ref_count<std::string> newroot(new std::string(
                    chroot_translate_addr( pid, state, &stat, CHROOT_PWD, state->context_state[0], true )));

        if( (int)stat.st_ino!=-1 ) {
            // The call succeeded
            state->root=newroot;
            ptlib_set_retval( pid, 0 ); // Success returns 0
        } else {
            // The call failed
            ptlib_set_error( pid, sc_num, errno );
        }

        state->state=pid_state::NONE;
    }

    return true;
}

// This function handles the generic case where the function is one that does not need fake root
// special handling, except we need to translate the first parameter in case we are chrooted
bool sys_generic_chroot_support_param1( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        PROC_MEM_LOCK();

        state->state=pid_state::RETURN;

        chroot_translate_param( pid, state, 1, true );
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}

// Same as above, only when the last link is not resolved
bool sys_generic_chroot_support_link_param1( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        PROC_MEM_LOCK();

        state->state=pid_state::RETURN;

        chroot_translate_param( pid, state, 1, false );
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_generic_chroot_support_param2( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        PROC_MEM_LOCK();

        state->state=pid_state::RETURN;

        chroot_translate_param( pid, state, 2, true );
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}
