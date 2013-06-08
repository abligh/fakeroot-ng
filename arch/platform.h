#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Platform specific definitinos go in a special file */
#include "platform_specific.h"

/* Functions for abstracting the details of registers and memory layout for interpreting ptrace stacks and memory */

/* Called once before any other call to ptlib functions */
void ptlib_init();

/* Continue (or detach) a halted process */
int ptlib_continue( int request, pid_t pid, int signal );

/* Called once per new process created */
void ptlib_prepare( pid_t pid );

/* Wait for next event. Returns some data about the event
 * "status" is the status returned by "wait"
 * "data" is extra data returned by wait (such as rusage)
 * "async" is a boolean telling whether to block if we have nothing to report
 * ptlib_parse_wait parses the info
 * Reports whether it was a signal delivered at the process (ret gets the signal number)
 * A process stopped due to signal (ret is the signal number)
 * A process terminated (ret is the return code)
 * A process terminated (ret is the signal that killed it)
 * A SYSCALL took place (ret is the syscall number)
 * A new process being created (only if PTLIB_SUPPORTS_{FORK,VFORK,CLONE} is defined for the platform) - ret is the new PID */
enum PTLIB_WAIT_RET { SIGNAL, EXIT, SIGEXIT, SYSCALL, NEWPROCESS };
int ptlib_wait( pid_t *pid, int *status, ptlib_extra_data *data, int async );
long ptlib_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type );

/* If we get a trace before we run ptlib_prepare, we might mis-interpret the signals */
int ptlib_reinterpret( enum PTLIB_WAIT_RET prestate, pid_t pid, int status, long *ret );

/* Returns/sets the Program Counter (EIP on Intel) for the traced program */
void *ptlib_get_pc( pid_t pid );
int ptlib_set_pc( pid_t pid, int_ptr location );

/* Syscall analysis functions - call only when stopped process just invoked a syscall */

/* Report the syscall number being invoked */
int ptlib_get_syscall( pid_t pid );
int ptlib_set_syscall( pid_t pid, int sc_num ); /* Change the meaning of a just started system call */
int ptlib_generate_syscall( pid_t pid, int sc_num, int_ptr base_memory ); /* Generate a new system call */

/* Return the nth argument passed */
int_ptr ptlib_get_argument( pid_t pid, int argnum );
int ptlib_set_argument( pid_t pid, int argnum, int_ptr value );

int_ptr ptlib_get_retval( pid_t pid );
int ptlib_success( pid_t pid, int sc_num ); /* Report whether the syscall succeeded */
void ptlib_set_retval( pid_t pid, int_ptr val );
void ptlib_set_error( pid_t pid, int sc_num, int error );
int ptlib_get_error( pid_t pid, int sc_num );

/* Copy memory in and out of the process
 * Return TRUE on success */
int ptlib_get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len );
int ptlib_set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len );

/* Copy a NULL terminated string. "get" returns the number of bytes copied, including the NULL */
int ptlib_get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen );
int ptlib_set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr );

/* Get a process' current directory and open fds */
/* Return value is as for "readlink" */
ssize_t ptlib_get_cwd( pid_t pid, char *buffer, size_t buff_size );
ssize_t ptlib_get_fd( pid_t pid, int fd, char *buffer, size_t buff_size );

/* Save/restore the process state */
void ptlib_save_state( pid_t pid, void *buffer );
void ptlib_restore_state( pid_t pid, const void *buffer );

/* Initialize debugger controled memory inside debuggee address space */
const void *ptlib_prepare_memory( ); /* Returns pointer to static buffer with the desired opcods, of ptlib_prepare_memory_len length */
size_t ptlib_prepare_memory_len(); /* How much memory does the platform need beyond how much the process needs */

/* Process relationship - return the parent of a process */
pid_t ptlib_get_parent( pid_t pid );

/* Process creation with debugger attached:
 * call the "enter" right before the function, "exit" right after it returns
 * ptlib_fork_enter returns true if it did not change the syscall, false if it did.
 * orig_sc is the original system call used by the process.

 * ptlib_fork_exit returns true if a new process was created, false if the call failed.
 *
 * Caller should make sure to call ptlib_fork_exit for both child AND parent process.
 * Keep in mind that child process might start running (traced) before the parent
 * process returns from the fork, or after. It is also possible that child or parent
 * will run to completion before the other one returns from the fork. Caller must be
 * prepared to handle them in arbitrary order.
 * 
 * The pid of the new process is returned in newpid as per fork's return code (or
 * whatever function it is that was called).
 *
 * ptlib_fork_exit makes sure that the return value from the kernel matches what the
 * called of fork (or whatever) would expect

 * process_mem is a pointer to the shared memory area in the process space (as per ptlib_generate_syscall)
 * our_mem is a pointer to the same memory in the debugger porcess space
 */

#define FORK_CONTEXT_SIZE 3
int ptlib_fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[PTLIB_STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] );
int ptlib_fork_exit( pid_t pid, pid_t *newpid, void *registers[PTLIB_STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] );

/* This is a function that must be provided by the user of the library */
void __dlog_( const char *format, ... ) COMPHINT_PRINTF( 1, 2);
extern int log_level;
#define dlog if( log_level>0 ) __dlog_

#ifdef __cplusplus
};
#endif

#endif /* PLATFORM_H */
