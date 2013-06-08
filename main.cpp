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

#include <string>
#include <memory>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <sys/mman.h>
#include <unistd.h>

#include "arch/platform.h"
#include "log.h"
#include "daemon.h"

static void print_version(void)
{
    printf(PACKAGE_NAME " version " PACKAGE_VERSION "\n");
    printf("This is free software. Please read the AUTHORS file for details on copyright\n"
        "and redistribution rights.\n");
}

static void print_usage(void)
{
    printf(PACKAGE_NAME " version " PACKAGE_VERSION "\n");
    printf("Usage: fakeroot-ng [options]... command\n"
            "Options:\n"
            "-pstate\tStore persistent state\n"
            "-llog\tProduce debugging log operation\n"
            "-f\tFlush the log after each write.\n"
            "-d\tDo not detach\n"
            "-v\tPrint version information and quit\n"
            "-h\tShort help (this text)\n"
          );
            
}

static bool nodetach=false;
static const char *persistent_file;
static char orig_wd[PATH_MAX];

int parse_options( int argc, char *argv[] )
{
    int opt;
    const char * logfile=NULL;
    bool log_flush=false;

    while( (opt=getopt(argc, argv, "+p:l:dvfh" ))!=-1 ) {
        switch( opt ) {
        case 'p': // Persist file
            persistent_file=optarg;
            orig_wd[0]='\0';
            if( optarg[0]!='/' ) {
                getcwd( orig_wd, sizeof(orig_wd) );
            }
            break;
        case 'l':
            if( logfile==NULL ) {
                logfile=optarg;
            } else {
                fprintf(stderr, "-l option given twice\n");

                return -1;
            }
            break;
        case 'f':
            log_flush=true;
            break;
        case 'd':
            nodetach=true;
            break;
        case 'v':
            print_version();
            return -2;
        case 'h':
            print_usage();
            return -2;
        case '?':
            /* Error in parsing */
            return -1;
            break;
        default:
            fprintf(stderr, "%s: internal error: unrecognized option '-%c'\n", argv[0], opt);
            return -1;
            break;
        }
    }

    if( log_flush && logfile==NULL ) {
        fprintf( stderr, "%s: -f makes no sense if -l is not also given\n", argv[0] );
        return -1;
    }

    if( logfile && ! init_log( logfile, log_flush ) ) {
        perror( "Failed to create log file" );

        return -1;
    }

    return optind;
}

// Make sure we are running in a sane environment
static bool sanity_check()
{
    // Make sure that /tmp (or $TMPDIR, or $FAKEROOT_TMPDIR) allow us to map executable files
    const char *tmp=getenv("FAKEROOT_TMPDIR");

    if( tmp==NULL )
        tmp=getenv("TMPDIR");

    std::string tmppath;

    if( tmp!=NULL ) {
        tmppath=tmp;
    } else {
        tmppath=DEFAULT_TMPDIR;
    }

    std::auto_ptr<char> templt(new char[tmppath.length()+20]);
    sprintf( templt.get(), "%s/fakeroot-ng.XXXXXX", tmppath.c_str() );

    int file=mkstemp( templt.get() );

    if( file==-1 ) {
        perror("Couldn't create temporary file");

        return false;
    }

    // First - make sure we don't leave any junk behind
    unlink( templt.get() );

    // Write some data into the file so it's not empty
    if( write( file, templt.get(), tmppath.length() )<0 ) {
        perror("Couldn't write into temporary file");

        return false;
    }

    // Map the file into memory
    void *map=mmap( NULL, 1, PROT_EXEC|PROT_READ, MAP_SHARED, file, 0 );
    int error=errno;

    close( file );

    if( map==MAP_FAILED ) {
        if( error==EPERM ) {
            fprintf( stderr, "Temporary area points to %s, but it is mounted with \"noexec\".\n"
                    "Set either the FAKEROOT_TMPDIR or TMPDIR environment variables to point to a\n"
                    "directory from which executables can be run.\n",
                    tmppath.c_str() );
        } else {
            perror("Couldn't mmap temporary file");
        }

        return false;
    }

    munmap( map, 1 );

    return true;
}

static int real_perform_child( daemonCtrl &daemon_ctrl, char *argv[] )
{
    // Don't leave the log file open for the program to come
    close_log();

    try {
        daemon_ctrl.cmd_attach();

        execvp(argv[0], argv);

        perror("Fakeroot-ng exec failed");
    } catch( const errno_exception &exception ) {
        fprintf(stderr, "%s: %s\n", exception.what(), exception.get_error_message() );
    } catch( const std::exception &exception ) {
        fprintf(stderr, "Fatal error: %s\n", exception.what() );
    }

    return 2;
}

#if PTLIB_PARENT_CAN_WAIT
static int perform_child( daemonCtrl & daemon_ctrl, char *argv[] )
{
    return real_perform_child( daemon_ctrl, argv );
}
#else
// Parent cannot wait on debugged child
#error Stale code
static int perform_child( daemonCtrl & daemon_ctrl, char *argv[] )
{
    int pipes[2];
    pipe(pipes);

    pid_t child=fork();

    if( child<0 ) {
        perror("Failed to create child process");

        return 2;
    } else if( child==0 ) {
        // We are the child
        close( pipes[0] );
        return real_perform_child( daemon_ctrl, argv, pipes[1] );
    }

    // We are the parent.

    close( pipes[1] );

    if( debug_log!=NULL ) {
        fclose( debug_log );
        debug_log=NULL;
    }

    int buffer;
    int numret;
    // Read from pipe to know when child finished talking to the debugger
    read( pipes[0], &buffer, sizeof(buffer) );

    close( pipes[0] );

    // Cannot "wait" for child - instead listen on socket
    if( (numret=read( child_socket, &buffer, sizeof(int) ))<(int)sizeof(int) ) {
        if( numret>=0 ) {
            fprintf(stderr, "Debugger terminated early\n");
        } else {
            perror("Parent: read failed");
        }
        exit(1);
    }

    // Why did "child" exit?
    if( WIFEXITED(buffer) ) {
        // Child has terminated. Terminate with same return code
        return WEXITSTATUS(buffer);
    }
    if( WIFSIGNALED(buffer) ) {
        // Child has terminated with a signal.
        return WTERMSIG(buffer);
    }

    fprintf(stderr, "Child " PID_F " terminated with unknown termination status %x\n", child, buffer );

    return 3;
}
#endif

int main(int argc, char *argv[])
{
    int opt_offset=parse_options( argc, argv );
    if( opt_offset==-1 )
        return 1;
    if( opt_offset==-2 )
        return 0;

    if( opt_offset==argc ) {
        // Fakeroot-ng called with no arguments - assume it wanted to run the current shell
 
        // We have at least one spare argv to work with (argv[0]) - use that
        argv[argc-1]=getenv("SHELL");
        opt_offset--;
    }

    // Check the environment to make sure it allows us to run
    if( !sanity_check() ) {
        return 1;
    }

    try {
        daemonCtrl daemon_ctrl(persistent_file, nodetach);

        return perform_child( daemon_ctrl, argv+opt_offset );
    } catch( const std::exception &exception ) {
        fprintf( stderr, "Execution failed with error %s\n", exception.what() );
    }
}
