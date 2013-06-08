#ifndef ARCH_OS_H
#define ARCH_OS_H

int ptlib_linux_continue( int request, pid_t pid, int signal );
void ptlib_linux_prepare( pid_t pid );
int ptlib_linux_wait( pid_t *pid, int *status, ptlib_extra_data *data, int async );
long ptlib_linux_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type );
int ptlib_linux_reinterpret( enum PTLIB_WAIT_RET prevstate, pid_t pid, int status, long *ret );
int ptlib_linux_get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len );
int ptlib_linux_set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len );
int ptlib_linux_get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen );
int ptlib_linux_set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr );
ssize_t ptlib_linux_get_cwd( pid_t pid, char *buffer, size_t buff_size );
ssize_t ptlib_linux_get_fd( pid_t pid, int fd, char *buffer, size_t buff_size );
void ptlib_linux_save_state( pid_t pid, void *buffer );
void ptlib_linux_restore_state( pid_t pid, const void *buffer );
pid_t ptlib_linux_get_parent( pid_t pid );
int ptlib_linux_fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[PTLIB_STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] );
int ptlib_linux_fork_exit( pid_t pid, pid_t *newpid, void *registers[PTLIB_STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] );

#endif /* ARCH_OS_H */
