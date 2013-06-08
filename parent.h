#ifndef PARENT_H
#define PARENT_H

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>

#include <list>
#include <set>

#include <stdio.h>
#include <string>
#include <assert.h>

#include "arch/platform.h"
#include "platform_specific.h"

#include "refcount.h"

extern size_t static_mem_size, shared_mem_size;

bool attach_debugger( pid_t child );
class daemonProcess;
int process_children( daemonProcess *daemon );
int process_sigchld( pid_t pid, enum PTLIB_WAIT_RET wait_state, int status, long ret );

// Called whenever a new process is created
void handle_new_process( pid_t parent_id, pid_t child_id );

#define NUM_SAVED_STATES 5

struct pid_state {
    /* The list of states a process can be in.
       As far as the syscall handler is concerned, each state has a "before" and "after" semantics.
       Before - between the point the process has sent us a SIGTRAP and the handler being called
       After - between the handler's return and the process receiving a continue command

       Handlers should check for the before state and should set the after state

       Terminology:
         Inbound - this is the SIGTRAP sent to us right before the kernel processes the syscall
         Outbound - this is the SIGTRAP sent to us right after the kernel processed the syscall
     */
    enum states {
        INIT,
        // Internal use - never set from a handler and will never be seen from a handler
        NONE,
        // Base state. Before - the process is inbound on a new syscall.
        // After - process is outbound from the last syscall in this sequence.
        RETURN,
        // After - process is inbound to an unmodified syscall. Before - process is outbound from an unmodified syscall.
        // The "unmodified" part is asserted by the main loop! Violating this constraint will crash the process in debug mode
        REDIRECT1,
        // After - Set in *Outbound* mode to indicate we initiated a new call with ptlib_generate_syscall
        // Before - handled internally by process_sigchld - handler will never be called with this state
        REDIRECT2,
        // Before - outbound on a modified syscall. May or may not be a result of ptlib_generate_syscall
        // After - Set when you want to change the original inbound syscall to something else.
        // Do not use RETURN under those circumstances, as it will violate the assertion.
        REDIRECT3,
        // This mode rarely makes sense.
        // After - handler generated a syscall, but would like to be notified when that syscall reaches inbound
        // Before - inbound on generated syscall
        ALLOCATE,
        ALLOC_RETURN,
        // The above two are used internally. The handler should never set them and will never see them set.
        WAITING,
        // After - the handler semantics needs to hold the process until some asynchronous operation is done.
        //      This state is somewhat special, as it is not tied to an outbound/inbound state.
        //      A handler setting this state should return false, to prevent process_sigchld from allowing the
        //      process to continue running.
        // Before - the handler is called from "notify_parent", not "process_sigchld". Inbound/outbound depends on
        //
        // NOTICE: Release of a waiting process should not be done into the NONE state, as that would mean that if a recursive
        // debugger is connected to the process, it will not see the syscall return!
        ZOMBIE,
        // As with real processes - the process has terminated, but has not yet been waited on.
    } state;
    int orig_sc; // Original system call

    class process_memory {
        int_ptr memory; // Where and how much mem do we have inside the process's address space
        int_ptr shared_memory; // Process address of shared memory
        void *shared_mem_local; // local pointers to the shared memory
        size_t shared_overhead; // Size of the overhead the shared memory has
        size_t shared_size; // Total size of mapping

        // Disable the implicit constructors
        process_memory( const process_memory &rhs );
        process_memory &operator=( const process_memory &rhs );
    public:

        process_memory() : memory(0), shared_memory(0), shared_mem_local(MAP_FAILED), shared_overhead(0), shared_size(0)
        {
        }

        ~process_memory();
        
        void set_local_addr(void *addr, size_t size, size_t overhead)
        {
            assert(shared_mem_local==MAP_FAILED);
            if( addr!=MAP_FAILED && addr!=NULL ) {
                shared_mem_local=(void *)(((int_ptr)addr)+overhead);
                shared_overhead=overhead;
                shared_size=size;
            }
        }
        void set_remote_static(int_ptr addr)
        {
            assert(memory==0);
            memory=addr;
        }
        void set_remote_shared(int_ptr addr)
        {
            shared_memory=addr;
        }

        // Accessors
        void *get_loc() const
        {
            return shared_mem_local!=MAP_FAILED ? shared_mem_local : NULL;
        }
        char *get_loc_c() const
        {
            return (char *)get_loc();
        }

        int_ptr get_mem() const
        {
            return memory;
        }

        int_ptr get_shared() const
        {
            return shared_memory;
        }
    };

    ref_count<process_memory> mem;

    int_ptr context_state[NUM_SAVED_STATES];
    void *saved_state[PTLIB_STATE_SIZE];

    // "wait" simulation and recursive debuggers support
    pid_t debugger, parent; // Which process thinks it's ptracing/parenting this one
    int num_children, num_debugees; // How many child/debugged processes we have
    int trace_mode; // Which ptrace mode was used to run the process
    pid_t session_id;

    ref_count<std::string> root;

    // The credentials (including the Linux specific file system UID)
    uid_t uid, euid, suid, fsuid;
    gid_t gid, egid, sgid, fsgid;
    std::set<gid_t> groups;

// Values for trace_mode
#define TRACE_DETACHED  0x0
#define TRACE_CONT      0x1
#define TRACE_SYSCALL   0x2
#define TRACE_SINGLSTEP 0x3
#define TRACE_MASK1     0x7
#define TRACE_STOPPED1  0x10
#define TRACE_STOPPED2  0x20
#define TRACE_MASK2     0x70

#define DEF_VAR(type, name) private: type _##name; \
    public: type &name() { return _##name; } const type &name() const { return _##name; }

    struct wait_state {
        DEF_VAR( pid_t, pid)
        DEF_VAR( int, status)
        DEF_VAR( struct rusage, usage)
        DEF_VAR( bool, debugonly) // Whether a parent that is not a debugger would have got this message

    public:
        wait_state() : _pid(0), _status(0), _debugonly(true)
        {
        }

        wait_state( pid_t pid, int status, const struct rusage *usage, bool debugonly ) : _pid(pid), _status(status), _usage(*usage),
            _debugonly(debugonly)
        {
        }
    };
#undef DEF_VAR
    std::list<wait_state> waiting_signals;

    pid_state() : state(INIT), mem(ref_count<process_memory>(new process_memory)), debugger(0),
        parent(0), num_children(0), num_debugees(0), trace_mode(TRACE_DETACHED), session_id(0), root(),
        uid(ROOT_UID), euid(ROOT_UID), suid(ROOT_UID), fsuid(ROOT_UID), gid(ROOT_GID), egid(ROOT_GID), sgid(ROOT_GID), fsgid(ROOT_GID)
    {
        groups.insert(ROOT_GID);
    }
};

// Look up a state by pid. Return NULL if the state does not exist
pid_state *lookup_state( pid_t pid );
// Delete a process. Must be called with state as ZOMBIE.
// Does reference counting, and will only perform actual delete when no more users.
void delete_state( pid_t pid );
// Dump all of the registered processes, including parent, state and zombie use count
void dump_states();

typedef bool (*sys_callback)( int sc_num, pid_t pid, pid_state *state );
struct syscall_hook {
    sys_callback func;
    const char *name;

    syscall_hook() : func(NULL), name(NULL)
    {
    }
    syscall_hook( sys_callback _func, const char *_name ) : func(_func), name(_name)
    {
    }
};

bool allocate_process_mem( pid_t pid, pid_state *state, int sc_num );

void dump_registers( pid_t pid );

#define PROC_MEM_LOCK()

#endif /* PARENT_H */
