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

#include <unordered_map>

#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "arch/platform.h"
#include "parent.h"
#include "syscalls.h"
#include "process.h"
#include "daemon.h"

// forward declaration of function
static bool handle_memory_allocation( int sc_num, pid_t pid, pid_state *state );

// Keep track of handled syscalls
static std::unordered_map<int, syscall_hook> syscalls;

// Keep track of the states for the various processes
template <class key, class data> class map_class : public  std::unordered_map<key, data> 
{
    // Inherit everything, just disable the dangerous operator[]
public:
    data &operator[] (const key &k)
    {
        return std::unordered_map<key,data>::operator[] (k);
    }
    const data &operator[] ( const key &k) const
    {
        return std::unordered_map<key,data>::operator[] (k);
    }
};

static map_class<pid_t, pid_state> state;

size_t static_mem_size, shared_mem_size;

static std::unordered_map<pid_t, int> root_children; // Map of all root children

static int num_processes; // Number of running processes

// Definitions of some methods
pid_state::process_memory::~process_memory()
{
    if( shared_mem_local!=MAP_FAILED ) {
        if( munmap( (void*)(((int_ptr)shared_mem_local)-shared_overhead), shared_size )<0 ) {
            // Log the error, but do not otherwise do anything interesting ...
            dlog("~process_memory: munmap( %p, %lu ) failed with %s\n", (void*)(((int_ptr)shared_mem_local)-shared_overhead),
                    (unsigned long)shared_size, strerror(errno) );
            // ... unless we're in debug mode :-)
            dlog(NULL);
            assert(false);
        }

        shared_mem_local=MAP_FAILED;
    }
}

static void init_handlers()
{
    // A macro for defining a system call with different syscall and handler names
#define DEF_SYS2( syscall, function ) syscalls[SYS_##syscall]=syscall_hook(sys_##function, #syscall)
    // A macro fro defining a system call with the same syscall and handler names
#define DEF_SYS1( syscall ) DEF_SYS2( syscall, syscall )

    DEF_SYS1(geteuid);
#if defined(SYS_geteuid32)
    DEF_SYS2(geteuid32, geteuid);
#endif
    DEF_SYS1(getuid);
#if defined(SYS_getuid32)
    DEF_SYS2(getuid32, getuid);
#endif
    DEF_SYS1(getegid);
#if defined(SYS_getegid32)
    DEF_SYS2(getegid32, getegid);
#endif
    DEF_SYS1(getgid);
#if defined(SYS_getgid32)
    DEF_SYS2(getgid32, getgid);
#endif
    DEF_SYS1(getresuid);
#if defined(SYS_getresuid32)
    DEF_SYS2(getresuid32, getresuid);
#endif
    DEF_SYS1(getresgid);
#if defined(SYS_getresgid32)
    DEF_SYS2(getresgid32, getresgid);
#endif
    DEF_SYS1(getgroups);
#if defined(SYS_getgroups32)
    DEF_SYS2(getgroups32, getgroups);
#endif

    DEF_SYS1(setuid);
#ifdef SYS_seteuid
    DEF_SYS1(seteuid);
#endif
#ifdef SYS_seteuid32
    DEF_SYS2(seteuid32, seteuid);
#endif
#ifdef SYS_setfsuid
    DEF_SYS1(setfsuid);
#endif
#ifdef SYS_setfsuid32
    DEF_SYS2(setfsuid32, setfsuid);
#endif
#ifdef SYS_setresuid
    DEF_SYS1(setresuid);
#endif
#ifdef SYS_setresuid32
    DEF_SYS2(setresuid32, setresuid);
#endif
    DEF_SYS1(setreuid);
#ifdef SYS_setreuid32
    DEF_SYS2(setreuid32, setreuid);
#endif

    DEF_SYS1(setgid);
#ifdef SYS_setegid
    DEF_SYS1(setegid);
#endif
#ifdef SYS_setegid32
    DEF_SYS2(setegid32, setegid);
#endif
#ifdef SYS_setfsgid
    DEF_SYS1(setfsgid);
#endif
#ifdef SYS_setfsgid32
    DEF_SYS2(setfsgid32, setfsgid);
#endif
#ifdef SYS_setresgid
    DEF_SYS1(setresgid);
#endif
#ifdef SYS_setresgid32
    DEF_SYS2(setresgid32, setresgid);
#endif
    DEF_SYS1(setregid);
#ifdef SYS_setregid32
    DEF_SYS2(setregid32, setregid);
#endif
    DEF_SYS1(setgroups);
#if defined(SYS_setgroups32)
    DEF_SYS2(setgroups32, setgroups);
#endif

    DEF_SYS1(fork);
    DEF_SYS1(vfork);
#if defined(SYS_clone)
    DEF_SYS1(clone);
#endif

//    Execve is special cased
//    DEF_SYS1(execve);
#if defined(SYS_sigreturn)
    DEF_SYS1(sigreturn);
#endif
#if defined(SYS_rt_sigreturn)
    DEF_SYS2(rt_sigreturn, sigreturn);
#endif
    DEF_SYS1(setsid);
#if defined(SYS_wait4)
    DEF_SYS1(wait4);
#endif
#if defined(SYS_waitpid)
    DEF_SYS1(waitpid);
#endif
    DEF_SYS1(ptrace);
    DEF_SYS1(kill);

    DEF_SYS1(stat);
#ifdef SYS_stat64
    DEF_SYS2(stat64, stat);
#endif
    DEF_SYS2(fstat, stat);
#ifdef SYS_fstat64
    DEF_SYS2(fstat64, stat);
#endif
    DEF_SYS2(lstat, stat);
#ifdef SYS_lstat64
    DEF_SYS2(lstat64, stat);
#endif
#if defined(SYS_newfstatat) && HAVE_OPENAT
    DEF_SYS2(newfstatat, fstatat64);
#endif
#if defined(SYS_fstatat64) && HAVE_OPENAT
    DEF_SYS1(fstatat64);
#endif

    DEF_SYS1(chown);
#if defined(SYS_chown32)
    DEF_SYS2(chown32, chown);
#endif
    DEF_SYS1(fchown);
#if defined(SYS_fchown32)
    DEF_SYS2(fchown32, fchown);
#endif
    DEF_SYS1(lchown);
#if defined(SYS_lchown32)
    DEF_SYS2(lchown32, lchown);
#endif
#if defined(SYS_fchownat) && HAVE_OPENAT
    DEF_SYS1(fchownat);
#endif

    DEF_SYS1(chmod);
    DEF_SYS1(fchmod);
#if defined(SYS_fchmodat) && HAVE_OPENAT
    DEF_SYS1(fchmodat);
#endif

    DEF_SYS1(mknod);
#if defined(SYS_mknodat) && HAVE_OPENAT
    DEF_SYS1(mknodat);
#endif
    DEF_SYS1(open);
#if defined(SYS_openat) && HAVE_OPENAT
    DEF_SYS1(openat);
#endif
    DEF_SYS1(mkdir);
#if defined(SYS_mkdirat) && HAVE_OPENAT
    DEF_SYS1(mkdirat);
#endif
    DEF_SYS1(symlink);
#if defined(SYS_mkdirat) && HAVE_OPENAT
    DEF_SYS1(symlinkat);
#endif
    DEF_SYS1(link);
#if defined(SYS_linkat) && HAVE_OPENAT
    DEF_SYS1(linkat);
#endif
    DEF_SYS1(unlink);
#if defined(SYS_unlinkat) && HAVE_OPENAT
    DEF_SYS1(unlinkat);
#endif
    DEF_SYS1(rename);
#if defined(SYS_renameat) && HAVE_OPENAT
    DEF_SYS1(renameat);
#endif
    DEF_SYS1(rmdir);
    DEF_SYS2(readlink, generic_chroot_support_link_param1);
#if defined(SYS_renameat) && HAVE_OPENAT
    DEF_SYS2(readlinkat, generic_chroot_link_at);
#endif
    DEF_SYS2(truncate, generic_chroot_support_param1);
#ifdef SYS_truncate64
    DEF_SYS2(truncate64, generic_chroot_support_param1);
#endif
    DEF_SYS2(statfs, generic_chroot_support_param1); // XXX Should last link be resolved?
#ifdef SYS_statfs64
    DEF_SYS2(statfs64, generic_chroot_support_param1); // XXX Should last link be resolved?
#endif
    DEF_SYS2(chdir, generic_chroot_support_param1);
    DEF_SYS2(access, generic_chroot_support_param1);
#if defined(SYS_faccessat) && HAVE_OPENAT
    DEF_SYS2(faccessat, generic_chroot_at_link4);
#endif
    DEF_SYS2(utime, generic_chroot_support_param1);
    DEF_SYS2(utimes, generic_chroot_support_param1);
#ifdef SYS_setxattr
    DEF_SYS2(setxattr, generic_chroot_support_param1);
    DEF_SYS2(getxattr, generic_chroot_support_param1);
    DEF_SYS2(listxattr, generic_chroot_support_param1);
    DEF_SYS2(removexattr, generic_chroot_support_param1);
#endif
#ifdef SYS_lsetxattr
    DEF_SYS2(lsetxattr, generic_chroot_support_link_param1);
    DEF_SYS2(lgetxattr, generic_chroot_support_link_param1);
    DEF_SYS2(llistxattr, generic_chroot_support_link_param1);
    DEF_SYS2(lremovexattr, generic_chroot_support_link_param1);
#endif
#ifdef SYS_uselib
    DEF_SYS2(uselib, generic_chroot_support_param1);
#endif
#ifdef SYS_inotify_add_watch
    DEF_SYS2(inotify_add_watch, generic_chroot_support_param1);
#endif
#if defined(SYS_futimesat) && HAVE_OPENAT
    DEF_SYS2(futimesat, generic_chroot_at);
#endif
#if defined(SYS_utimensat) && HAVE_OPENAT
    DEF_SYS2(utimensat, generic_chroot_at_link4);
#endif

    DEF_SYS1(chroot);
    DEF_SYS1(getcwd);

    DEF_SYS1(mmap);
#ifdef SYS_mmap2
    DEF_SYS2(mmap2, mmap);
#endif
    DEF_SYS1(munmap);
}

void init_globals()
{
    size_t page_size=sysconf(_SC_PAGESIZE);

    static_mem_size=page_size;
    shared_mem_size=2*PATH_MAX+ptlib_prepare_memory_len();
    // Round this to the higher page size
    shared_mem_size+=page_size-1;
    shared_mem_size-=shared_mem_size%page_size;
}

// Debug related functions
static const char *sig2str( int signum )
{
    static char buffer[64];

    switch(signum) {
#define SIGNAME(a) case a: return #a;
        SIGNAME(SIGHUP);
        SIGNAME(SIGINT);
        SIGNAME(SIGQUIT);
        SIGNAME(SIGILL);
        SIGNAME(SIGTRAP);
        SIGNAME(SIGABRT);
        SIGNAME(SIGBUS);
        SIGNAME(SIGFPE);
        SIGNAME(SIGKILL);
        SIGNAME(SIGSEGV);
        SIGNAME(SIGPIPE);
        SIGNAME(SIGALRM);
        SIGNAME(SIGTERM);
        SIGNAME(SIGCHLD);
        SIGNAME(SIGCONT);
        SIGNAME(SIGSTOP);
#undef SIGNAME
    default:
        sprintf(buffer, "signal %d", signum);
    }

    return buffer;
}

static const char *state2str( pid_state::states state )
{
    static char buffer[64];

    switch(state) {
#define STATENAME(a) case pid_state::a: return #a;
        STATENAME(INIT)
        STATENAME(NONE)
        STATENAME(RETURN)
        STATENAME(REDIRECT1)
        STATENAME(REDIRECT2)
        STATENAME(REDIRECT3)
        STATENAME(ALLOCATE)
        STATENAME(ALLOC_RETURN)
        STATENAME(WAITING)
        STATENAME(ZOMBIE)
#undef STATENAME
    }

    sprintf(buffer, "Unknown state %d", state);

    return buffer;
}

void dump_registers( pid_t pid )
{
    if( log_level>0 ) {
        void *state[PTLIB_STATE_SIZE];

        ptlib_save_state( pid, state );

        for( unsigned int i=0; i<PTLIB_STATE_SIZE; ++i )
            dlog("state[%d]=%p\n", i, state[i]);
    }
}

// State handling functions
static void notify_parent( pid_t parent, const pid_state::wait_state &waiting )
{
    if( parent==1 || parent==0 ) {
        // This process has no parent, or had a parent that already quit
        return;
    }
    dlog("notify_parent: " PID_F " sent a notify about " PID_F "(%x)\n", parent, waiting.pid(), waiting.status());
    pid_state *proc_state=lookup_state(parent);
    assert(proc_state!=NULL);

    proc_state->waiting_signals.push_back( waiting );

    // Is the parent currently waiting?
    if( proc_state->state==pid_state::WAITING ) {
        // Call the original function handler, now that it has something to do
        if( syscalls[proc_state->orig_sc].func( -1, parent, proc_state ) ) {
            dlog("notify_parent: " PID_F " released from wait\n", parent);
            ptlib_continue(PTRACE_SYSCALL, parent, 0);
        }
    }
}

static void handle_exit( pid_t pid, int status, const struct rusage &usage )
{
    // Let's see if the process doing the exiting is even registered
    pid_state *proc_state=lookup_state(pid);
    dlog(NULL);
    assert(proc_state!=NULL);

    // Set the process state to ZOMBIE with usage count of 1
    proc_state->state=pid_state::ZOMBIE;
    proc_state->context_state[0]=1;
    dlog("%s: " PID_F " is now a zombie\n", __func__, pid );

    pid_state *parent_state=lookup_state(proc_state->parent);

    // Notify the parent
#if PTLIB_PARENT_CAN_WAIT
    // If a parent can wait on a debugged child we need to notify it even if the child is being debugged,
    // but only if it actually has a parent (i.e. - was not reparented to init)
    // Of course, if the debugger IS the parent, there is no need to notify it twice
    if( proc_state->parent!=0 && proc_state->parent!=1 )
#else
    // If a parent cannot wait, we need to let it know ourselves only if it's not being debugged
    if( (proc_state->debugger==0 || proc_state->debugger==proc_state->parent) && proc_state->parent!=0 && proc_state->parent!=1 )
#endif
    {
        proc_state->context_state[0]++; // Update use count
        notify_parent( proc_state->parent, pid_state::wait_state( pid, status, &usage, false ) );
    }

    // Regardless of whether it is being notified or not, the parent's child num needs to be decreased
    if( parent_state!=NULL ) {
        parent_state->num_children--;
    }

    if( proc_state->debugger!=0 && proc_state->debugger!=proc_state->parent ) {
        // The process was being debugged - notify the debugger as well
        proc_state->context_state[0]++; // Update use count
        notify_parent( proc_state->parent, pid_state::wait_state( pid, status, &usage, true ) );
        state[proc_state->debugger].num_debugees--;
    }

    // Is any process a child of this process?
    // We need to delete all child zombie processes. This means changing the list while scanning it.
    // Instead, create a list of pids to delete
    std::set<pid_t> need_delete;
    for( std::unordered_map<pid_t, pid_state>::iterator i=state.begin(); i!=state.end(); ++i ) {
        if( i->second.parent==pid ) {
            dlog("Reparenting process %d to init from %d\n", i->first, pid);
            i->second.parent=1;

            if( i->second.state==pid_state::ZOMBIE ) {
                // "init" should release it
                need_delete.insert(i->first);
            }
        } 
        
        if( i->second.debugger==pid ) {
            dlog("Detaching process %d from recursive debugger %d\n", i->first, pid );
            i->second.debugger=0;

            if( i->second.state==pid_state::ZOMBIE && i->second.parent!=pid ) {
                // The process is in zombie state, pid is its debugger but not parent
                need_delete.insert(i->first);
            }
        }
    }

    for( std::set<pid_t>::iterator i=need_delete.begin(); i!=need_delete.end(); ++i ) {
        delete_state(*i);
    }

    // Delete the state from our end. The state is reference counted, so it may not actually be deleted just yet
    delete_state(pid);
}

void handle_new_process( pid_t parent_id, pid_t child_id )
{
    // Copy the session information
    pid_state *child=&state[child_id]; // We actually want to create the state if it did not already exist

    if( child->state!=pid_state::INIT ) {
        // Due to platform incompatibilities and other issues, we may be called several times over the same
        // child. Don't make a fuss - just return.

        dlog("%s: Process " PID_F " already registered - not performing any operation\n", __FUNCTION__, child_id );

        return;
    }

    dlog("%s: Registering " PID_F " with parent " PID_F "\n", __FUNCTION__, child_id, parent_id );

    // The platform may want to init the process in some way
    ptlib_prepare(child_id);

    // If this is a new root process, we do not actually start monitoring it just yet.
    if( parent_id!=-1 )
        child->state=pid_state::NONE;

    pid_state *parent=lookup_state(parent_id);
    if( parent!=NULL ) {
        // If this assert fails, we somehow created a -1 process - not good
        dlog(NULL);
        assert(parent_id!=-1);

        // This process is not a root process - it has a parent
        // Copy everything from the parent, except what you don't copy
        *child=*parent;

        int_ptr process_type=parent->context_state[0];

        if( (process_type&NEW_PROCESS_SAME_PARENT)==0 )
            child->parent=parent_id;

        pid_state *child_parent=lookup_state(child->parent);
        if( child_parent!=NULL ) {
            child_parent->num_children++;
        }

        child->num_children=0;
        child->num_debugees=0;

        // Whether the VM was copied or shared, the new process has the same static and shared memory
        // If the VM is not shared, setting shared_memory but not shared_mem_local is an indication that the
        // old memory needs to be freed
        if( (process_type&NEW_PROCESS_SAME_VM)==0 ) {
            // The processes do not share the same VM
            child->mem=ref_count<pid_state::process_memory>(new pid_state::process_memory);
            child->mem->set_remote_static(parent->mem->get_mem());

            /*
               The remote shared pointer for the parent is also valid for the child, but it is the same memory,
               not a copy.
               Keep the "shared_memory" pointer valid, but the "shared_mem_local" will be NULL to signify this is
               memory we need to munmap.
             */
            child->mem->set_remote_shared( parent->mem->get_shared() );
        }

        if( (process_type&NEW_PROCESS_SAME_DEBUGGER)==0 ) {
            // The process inherits the debugger from the parent
            child->debugger=0;
            child->trace_mode=TRACE_DETACHED;
        }
    } else {
        // This is a root process - no parent. Set it with the real session ID
        child->session_id=getsid(child_id);
        child->root=ref_count<std::string>(new std::string());
    }

    num_processes++;
}

int process_sigchld( pid_t pid, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
    long sig=0;

    pid_state *proc_state=lookup_state(pid);
    if( wait_state!=NEWPROCESS && proc_state==NULL ) {
        // The process does not exist!
        // Register it
        pid_t parent_pid=ptlib_get_parent(pid);
        dlog("Caught unknown new process " PID_F ", detected parent " PID_F "\n", pid, parent_pid );
        dlog(NULL);
        assert( parent_pid==0 || parent_pid==1 || state.find(parent_pid)!=state.end() ); // Make sure the parent is, indeed, ours

        // Handle the process creation before handling the syscall return
        process_sigchld( parent_pid, NEWPROCESS, status, pid );

        // Handle the rest of the syscall as a return from a syscall
        wait_state=SYSCALL;
        proc_state=lookup_state(pid);
        assert(proc_state!=NULL);
        ret=proc_state->orig_sc;
    }

    switch(wait_state) {
    case SYSCALL:
        {
            bool posttrap_always=false;

            if( proc_state->state==pid_state::REDIRECT1 ) {
                // REDIRECT1 is just a filler state between the previous call, where the arguments were set up and
                // the call initiated, and the call's return (REDIRECT2). No need to actually call the handler
                dlog(PID_F ": Calling syscall %ld redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );
                proc_state->state=pid_state::REDIRECT2;
            } else if( proc_state->state==pid_state::REDIRECT2 || proc_state->state==pid_state::REDIRECT3 ) {
                // REDIRECT2 means a return from a syscall generated by us.
                // REDIRECT3 means entering a syscall generated by us, but for which the handler function would like
                // to be notified (unlike REDIRECT1 above, which is short circuited)
                if( proc_state->orig_sc!=SYS_execve ) {
                    dlog(PID_F ": Called syscall %ld, redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );

                    if( !syscalls[proc_state->orig_sc].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else {
                    // Special handling of the execve case
                    dlog(PID_F ": Called syscall %ld, redirected from execve\n", pid, ret );

                    if( !sys_execve( ret, pid, proc_state, posttrap_always ) )
                        sig=-1;
                }
            } else {
                if( proc_state->state==pid_state::ALLOCATE ) {
                    if( !handle_memory_allocation( ret, pid, proc_state ) )
                        sig=-1;
                }

                if( proc_state->state!=pid_state::ALLOCATE ) {
                    // Sanity check - returning from same syscall that got us in
                    if( proc_state->state==pid_state::RETURN && ret!=proc_state->orig_sc ) {
                        dlog("process " PID_F " orig_sc=%d actual sc=%ld state=%s\n", pid, proc_state->orig_sc, ret,
                                state2str(proc_state->state));
                        dlog(NULL);
                        assert( proc_state->state!=pid_state::RETURN || ret==proc_state->orig_sc );
                    }

                    if( proc_state->state==pid_state::NONE && proc_state->debugger!=0 && proc_state->trace_mode==TRACE_SYSCALL ) {
                        dlog(PID_F ": pre-syscall hook called for debugger " PID_F "\n", pid, proc_state->debugger );

                        // Notify the debugger before the syscall
                        proc_state->context_state[0]=wait_state;
                        proc_state->context_state[1]=status;
                        proc_state->context_state[2]=ret;
                        proc_state->trace_mode=TRACE_STOPPED1;

                        pid_state::wait_state waiting;
                        waiting.pid()=pid;
                        waiting.status()=status;
                        getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG This is the wrong function!
                        waiting.debugonly()=true;
                        notify_parent( proc_state->debugger, waiting );
                        sig=-1; // We'll halt the program until the "debugger" decides what to do with it
                    } else if( !proc_state->mem->get_loc() && proc_state->state==pid_state::NONE && ret!=SYS_execve && ret!=SYS_exit ) {
                        // We need to allocate memory
                        // No point in allocating memory when we are just entering an execve that will get rid of it
                        if( !allocate_process_mem( pid, proc_state, ret ) )
                            sig=-1;
                    } else {
                        // No debugger or otherwise we need to go ahead with this syscall
                        if( (proc_state->trace_mode&TRACE_MASK2)==TRACE_STOPPED1 ) {
                            proc_state->trace_mode&=TRACE_MASK1;

                            // The debugger may have changed the system call to execute - we will respect it
                            ret=ptlib_get_syscall( pid );
                        }

                        if( proc_state->state==pid_state::NONE )
                            // Store the syscall type here (we are not in override)
                            proc_state->orig_sc=ret;

                        if( syscalls.find(ret)!=syscalls.end() ) {
                            dlog(PID_F ": Called %s(%s)\n", pid, syscalls[ret].name, state2str(proc_state->state));

                            if( !syscalls[ret].func( ret, pid, proc_state ) ) {
                                sig=-1; // Mark for ptrace not to continue the process
                            }
                        } else if( ret==SYS_execve ) {
                            dlog(PID_F ": Called execve(%s)\n", pid, state2str(proc_state->state));

                            if( !sys_execve(ret, pid, proc_state, posttrap_always ) )
                                sig=-1;
                        } else {
                            dlog(PID_F ": Unknown syscall %ld(%s)\n", pid, ret, state2str(proc_state->state));
                            if( proc_state->state==pid_state::NONE ) {
                                proc_state->state=pid_state::RETURN;
                            } else if( proc_state->state==pid_state::RETURN ) {
                                proc_state->state=pid_state::NONE;
                            }
                        }
                    }
                }
            }

            // Check for post-syscall debugger callback
            // If the system sends a SIGTRAP after a successful execve, the logic is entirely different
            if( proc_state->debugger!=0 && (
                    (proc_state->state==pid_state::NONE && proc_state->trace_mode==TRACE_SYSCALL) ||
                    posttrap_always )
              )
            {
                dlog(PID_F ": notify debugger " PID_F " about post-syscall hook\n", pid, proc_state->debugger );
                proc_state->trace_mode=TRACE_STOPPED2;

                pid_state::wait_state waiting;
                waiting.pid()=pid;
                waiting.status()=status;
                getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG This is the wrong function!
                waiting.debugonly()=true;
                notify_parent( proc_state->debugger, waiting );
                sig=-1; // Halt process until "debugger" decides it can keep on going
            }
        }
        break;
    case SIGNAL:
        dlog(PID_F ": Signal %s\n", pid, sig2str(ret));
        if( proc_state->debugger==0 ) {
            if( proc_state->state==pid_state::INIT ) {
                // When a process is being debugged, it appears to receive a SIGSTOP after the PTRACE_ATTACH. We use
                // that signal to synchronize the states of the debugee and us
                if( ret==SIGSTOP ) {
                    dlog(PID_F ": initial signal of process\n", pid );
                    sig=0;
                    proc_state->state=pid_state::NONE;
                } else {
                    dlog(PID_F ": received unexpected signal while in INIT mode\n", pid);

                    // Deliver the signal and continue the process - the SIGSTOP may yet be coming
                    ptrace( PTRACE_CONT, pid, ret, 0 );
                    sig=-1;
                }
            } else {
                sig=ret;
            }
        } else {
            // Pass the signal to the debugger
            pid_state::wait_state waiting;
            waiting.pid()=pid;
            waiting.status()=status;
            getrusage( RUSAGE_CHILDREN, &waiting.usage() ); // XXX BUG this is the wrong function!
            waiting.debugonly()=true;
            proc_state->trace_mode=TRACE_STOPPED2;
            notify_parent( proc_state->debugger, waiting );
            sig=-1;
        }
        break;
    case EXIT:
    case SIGEXIT:
        {
            if( wait_state==EXIT ) {
                dlog(PID_F ": Exit with return code %ld\n", pid, ret);
            } else {
                dlog(PID_F ": Exit with %s\n", pid, sig2str(ret));
            }

            struct rusage rusage;
            getrusage( RUSAGE_CHILDREN, &rusage );
            handle_exit(pid, status, rusage );
            
            // If this was a root child, we may need to perform notification of exit status
            std::unordered_map<pid_t, int>::iterator root_child=root_children.find(pid);
            if( root_child!=root_children.end() ) {
                if( root_child->second!=-1 ) {
                    write( root_child->second, &status, sizeof(status) );
                    close( root_child->second );
                }

                root_children.erase(root_child);
            }

            num_processes--;
        }
        break;
    case NEWPROCESS:
        {
            dlog(PID_F ": Created new child process %ld\n", pid, ret);
            handle_new_process( pid, ret );
        }
    }

    return sig;
}

bool attach_debugger( pid_t child )
{
    dlog(NULL);

    // Attach a debugger to the child
    if( ptrace(PTRACE_ATTACH, child, 0, 0)!=0 ) {
        dlog("Could not start trace of process " PID_F ": %s\n", child, strerror(errno) );

        throw errno_exception( "Could not start trace of process" );
    }
    dlog("Debugger successfully attached to process " PID_F "\n", child );

    // Child has started, and is debugged
    // root_children[child]=socket; // Mark this as a root child
    // XXX Above line disabled pending rewrite of "parent can't wait" code

    handle_new_process( -1, child ); // No parent - a root process

    return true;
}

// Do nothing signal handler for sigchld
static void sigchld_handler(int signum)
{
}

// Signify whether an alarm was received while we were waiting
static bool alarm_happened=false;

static void sigalrm_handler(int signum)
{
    alarm_happened=true;
}

int process_children( daemonProcess *daemon )
{
    // Initialize the ptlib library
    ptlib_init();

    init_handlers();
    init_globals();

    dlog( "Begin the process loop\n" );

    // Prepare the signal masks so we do not lose SIGCHLD while we wait

    struct sigaction action;
    memset( &action, 0, sizeof( action ) );

    action.sa_handler=sigchld_handler;
    sigemptyset( &action.sa_mask );
    action.sa_flags=0;

    sigaction( SIGCHLD, &action, NULL );

    action.sa_handler=sigalrm_handler;
    sigaction( SIGALRM, &action, NULL );

    sigset_t orig_signals, child_signals;

    sigemptyset( &child_signals );
    sigaddset( &child_signals, SIGCHLD );
    sigaddset( &child_signals, SIGALRM );
    sigprocmask( SIG_BLOCK, &child_signals, &orig_signals );

    sigdelset( &orig_signals, SIGCHLD );
    sigdelset( &orig_signals, SIGALRM );

    bool clientsockets=true;
    while(num_processes>0 || clientsockets) {
        int status;
        pid_t pid;
        long ret;
        ptlib_extra_data data;

        enum PTLIB_WAIT_RET wait_state;
        if( !ptlib_wait( &pid, &status, &data, true ) ) {
            if( errno==EAGAIN || (errno==ECHILD && num_processes==0) ) {
                clientsockets=daemon->handle_request( &orig_signals, num_processes>0 );

                // Did an alarm signal arrive?
                if( alarm_happened ) {
                    alarm_happened=false;

                    dump_states();
                }

            } else if( errno==ECHILD ) {
                // We should never get here. If we have no more children, we should have known about it already
                dlog( "BUG - ptlib_wait failed with %s while numchildren is still %d\n", strerror(errno), num_processes );
                dlog(NULL);
                num_processes=0;
            } else {
                dlog("ptlib_wait failed %d: %s\n", errno, strerror(errno) );
            }

            continue;
        }

        ret=ptlib_parse_wait( pid, status, &wait_state );

        long sig=process_sigchld( pid, wait_state, status, ret );

        // The show must go on
        if( sig>=0 )
            ptlib_continue(PTRACE_SYSCALL, pid, sig);
    }

    return 0;
}

bool allocate_process_mem( pid_t pid, pid_state *state, int sc_num )
{
    dlog("allocate_process_mem: " PID_F " running syscall %d needs process memory\n", pid, sc_num );

    state->orig_sc=sc_num;

    // Save the old state
    ptlib_save_state( pid, state->saved_state );
    state->state=pid_state::ALLOCATE;
    if( state->mem->get_shared()!=0 )
        state->context_state[0]=20; // Internal allocation state
    else
        state->context_state[0]=0; // Internal allocation state

    return handle_memory_allocation( sc_num, pid, state );
}

static bool allocate_shared_mem( pid_t pid, pid_state *state )
{
    char filename[PATH_MAX];

    const char *tmpdir=getenv("FAKEROOT_TMPDIR");

    if( tmpdir==NULL )
        tmpdir=getenv("TMPDIR");

    if( tmpdir==NULL || strlen(tmpdir)>=PATH_MAX-sizeof("/fakeroot-ng.XXXXXX") )
        tmpdir=DEFAULT_TMPDIR;

    sprintf(filename, "%s/fakeroot-ng.XXXXXX", tmpdir);

    int fd=mkstemp(filename);

    if( fd==-1 ) {
        dlog("allocate_shared_mem: " PID_F " Failed to create file %s: %s\n", pid, filename, strerror(errno) );

        // We'll kill the process
        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false; // Freeze the process until the signal arrives
    }

    // Make sure that the file is big enough, but create it sparse
    ftruncate( fd, shared_mem_size );

    // Map the file into the local address space
    char *memory=(char *)mmap( NULL, shared_mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0 );

    if( memory==MAP_FAILED ) {
        dlog("allocate_shared_mem: " PID_F " filed to map file %s into memory: %s\n", pid, filename, strerror(errno) );

        // Cleanup
        close(fd);
        unlink(filename);

        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false;
    }

    // Fill in the memory with necessary commands and adjust the pointer
    memcpy( memory, ptlib_prepare_memory(), ptlib_prepare_memory_len() );

    // We need to remember the name of the temporary file so we can unlink it
    strcpy(memory+ptlib_prepare_memory_len(), filename);

    // Cleanup
    close(fd);

    // Set the shared memory class to know who we are
    state->mem->set_local_addr(memory, shared_mem_size, ptlib_prepare_memory_len());

    // The local shared memory is mapped. Now we need to map the remote end
    // Generate a new system call
    // Copy the instructions for generating a syscall to the newly created memory
    ptlib_set_mem( pid, ptlib_prepare_memory(), state->mem->get_mem(), ptlib_prepare_memory_len() );

    // Fill in the parameters to open the same file
    ptlib_set_argument( pid, 1, state->mem->get_mem()+ptlib_prepare_memory_len() );
    ptlib_set_string( pid, state->mem->get_loc_c(), state->mem->get_mem()+ptlib_prepare_memory_len() );
    ptlib_set_argument( pid, 2, O_RDONLY );

    return true;
}

// Table of states:
// Start states - if have nothing - 0
// if have static buffer and old shared buffer - 20

// First we define the various stages of the state machine:
static bool hma_state0( int sc_num, pid_t pid, pid_state *state )
{
    // Translate the whatever call into an mmap to allocate the process local memory
    ptlib_set_syscall( pid, PREF_MMAP );

    ptlib_set_argument( pid, 1, 0 ); // start pointer
    ptlib_set_argument( pid, 2, static_mem_size ); // Length of page(s)
    ptlib_set_argument( pid, 3, (PROT_EXEC|PROT_READ|PROT_WRITE) ); // Protection - allow execute
    ptlib_set_argument( pid, 4, (MAP_PRIVATE|MAP_ANONYMOUS) ); // Flags - anonymous memory allocation
    ptlib_set_argument( pid, 5, -1 ); // File descriptor
    ptlib_set_argument( pid, 6, 0 ); // Offset

    return true;
}

static bool hma_state1( int sc_num, pid_t pid, pid_state *state )
{
    // First step - mmap just returned
    if( ptlib_success( pid, sc_num ) ) {
        state->mem->set_remote_static(ptlib_get_retval( pid ));
        dlog("handle_memory_allocation: " PID_F " allocated for our use %lu bytes at %p\n", pid,
                (unsigned long)static_mem_size, (void *)state->mem->get_mem());

        // "All" we need now is the shared memory. First, let's generate the local version for it.
        if(allocate_shared_mem( pid, state ))
            return ptlib_generate_syscall( pid, SYS_open, state->mem->get_mem()+ptlib_prepare_memory_len() );
        else
            return false;
    } else {
        // The allocation failed. What can you do except kill the process?
        dlog("handle_memory_allocation: " PID_F " our memory allocation failed with error. Kill process. %s\n", pid,
                strerror(ptlib_get_error(pid, sc_num)) );
        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false;
    }
}

static bool hma_state20( int sc_num, pid_t pid, pid_state *state )
{
    // Start state for the case where there is already an allocated shared mem

    // Save the remote pointer to the old memory, so we can free it later
    state->context_state[2]=state->mem->get_shared();

    // Need to reallocate the shared memory
    if(allocate_shared_mem( pid, state ) ) {
        return ptlib_set_syscall( pid, SYS_open )==0;
    } else {
        return false;
    }
}

static bool hma_state3( int sc_num, pid_t pid, pid_state *state )
{
    // The "open" syscall returned

    // Whether it failed or succeeded, we no longer need the file
    unlink( state->mem->get_loc_c() );

    if( ptlib_success( pid, sc_num ) ) {
        // Store the fd for our own future use
        state->context_state[1]=ptlib_get_retval( pid );

        // Perform the mmap
        ptlib_set_argument( pid, 1, (int_ptr)NULL );
        ptlib_set_argument( pid, 2, shared_mem_size );
        ptlib_set_argument( pid, 3, PROT_READ|PROT_EXEC );
        ptlib_set_argument( pid, 4, MAP_SHARED );
        ptlib_set_argument( pid, 5, state->context_state[1] );
        ptlib_set_argument( pid, 6, 0 );

        ptlib_generate_syscall( pid, PREF_MMAP, state->mem->get_mem()+ptlib_prepare_memory_len() );
    } else {
        // open failed
        dlog( "handle_memory_allocation: " PID_F " process failed to open %s: %s\n", pid, state->mem->get_loc_c(),
                strerror(ptlib_get_error(pid, sc_num)) );
        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false;
    }

    return true;
}

static bool hma_state5( int sc_num, pid_t pid, pid_state *state )
{
    // mmap call return

    if( ptlib_success( pid, sc_num ) ) {
        // mmap succeeded
        state->mem->set_remote_shared(ptlib_get_retval( pid )+ptlib_prepare_memory_len());
        dlog("handle_memory_allocation: " PID_F " allocated for our use %lu shared bytes at %p\n", pid,
                (unsigned long)shared_mem_size, (void *)(state->mem->get_shared()-ptlib_prepare_memory_len()));

        // We now need to close the file descriptor
        ptlib_set_argument( pid, 1, state->context_state[1] );

        return ptlib_generate_syscall( pid, SYS_close, state->mem->get_shared() );
    } else {
        dlog( "handle_memory_allocation: " PID_F " process failed to mmap memory: %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );

        ptlib_continue( PTRACE_KILL, pid, 0 );
        return false;
    }
    return true;
}

static bool hma_state7( int sc_num, pid_t pid, pid_state *state )
{
    // Close done - we can revert to whatever we were previously doing
    if( !ptlib_success( pid, sc_num ) ) {
        // If close failed, we'll log the error and leak the file descriptor, but otherwise do nothing about it
        dlog( "handle_memory_allocation: " PID_F " procss close failed: %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
    }
    return ptlib_generate_syscall( pid, state->orig_sc , state->mem->get_shared() );
}

static bool hma_state8( int sc_num, pid_t pid, pid_state *state )
{
    // The syscall to restart is entering the kernel
    {
        ptlib_restore_state( pid, state->saved_state );
        state->state=pid_state::NONE;

        dlog("handle_memory_allocation: " PID_F " restore state and call handler for syscall %d\n", pid, sc_num );
    }
    return true;
}

static bool hma_state25( int sc_num, pid_t pid, pid_state *state )
{
    // Close done - we now need to deallocate the previous shared mem
    if( !ptlib_success( pid, sc_num ) ) {
        // If close failed, we'll log the error and leak the file descriptor, but otherwise do nothing about it
        dlog( "handle_memory_allocation: " PID_F " procss close failed: %s\n", pid, strerror(ptlib_get_error(pid, sc_num) ) );
    }

    ptlib_set_argument( pid, 1, state->context_state[2]-ptlib_prepare_memory_len() );
    ptlib_set_argument( pid, 2, shared_mem_size );

    ptlib_generate_syscall( pid, SYS_munmap, state->mem->get_shared() );
    return true;
}

static bool hma_state27( int sc_num, pid_t pid, pid_state *state )
{
    // Munmap done
    if( !ptlib_success( pid, sc_num ) ) {
        // Again, if the unmap failed, we'll log it but otherwise continue
        dlog( "handle_memory_allocation: " PID_F " process munmap failed: %s\n", pid, strerror( ptlib_get_error(pid, sc_num) ) );
    }

    // Restart the original system call
    state->context_state[0]=8; // Merge with the original code
    return ptlib_generate_syscall( pid, state->orig_sc, state->mem->get_shared() );
}

static bool handle_memory_allocation( int sc_num, pid_t pid, pid_state *state )
{
    bool ret=true;

    switch( state->context_state[0]++ ) {
    case 0:
        ret=hma_state0( sc_num, pid, state );
        break;
    case 1:
        return hma_state1( sc_num, pid, state );
    case 20:
        return hma_state20( sc_num, pid, state );
    case 2:
        // The entrance to the "open" syscall on the shared file
        break;
    case 3:
    case 21:
        ret=hma_state3( sc_num, pid, state );
        break;
    case 4:
    case 22:
        // The mmap call entry
        break;
    case 5:
    case 23:
        ret=hma_state5( sc_num, pid, state );
        break;
    case 6:
    case 24:
        // Close call entry
        break;
    // The first time and repeat allocations diverge again - case 25 is handled further on
    case 7:
        return hma_state7( sc_num, pid, state );
    case 8:
        ret=hma_state8( sc_num, pid, state );
        break;
    case 25:
        ret=hma_state25( sc_num, pid, state );
        break;
    case 26:
        // Syscall enter for munmap
        break;
    case 27:
        ret=hma_state27( sc_num, pid, state );
        break;
    }

    return ret;
}

bool sys_mmap( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        dlog("mmap: " PID_F " direct call\n", pid);
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        dlog("mmap: " PID_F " direct return\n", pid);
        state->state=pid_state::NONE;
    }

    return true;
}

pid_state *lookup_state( pid_t pid ) {
    std::unordered_map<pid_t, pid_state>::iterator process=state.find(pid);

    if( process!=state.end() ) {
        return &process->second;
    }

    return NULL;
}

void delete_state( pid_t pid )
{
    pid_state *proc_state=lookup_state(pid);
    assert(proc_state!=NULL);
    assert(proc_state->state==pid_state::ZOMBIE);

    if( (--proc_state->context_state[0])==0 )
        state.erase(pid);
}

void dump_states()
{
    // Print the header
    dlog("PID\tParent\tState\n");

    for( map_class<pid_t, pid_state>::const_iterator i=state.begin(); i!=state.end(); ++i ) {
        dlog(PID_F "\t" PID_F "\t%s", i->first, i->second.parent, state2str(i->second.state) );

        if( i->second.state==pid_state::ZOMBIE ) {
            dlog("(%d)", (int)i->second.context_state[0]);
        }

        dlog("\n");
    }

    dlog(NULL);
}
