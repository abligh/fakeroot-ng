#ifndef CHROOT_H
#define CHROOT_H

#include <string>
#ifndef _FCNTL_H
#include <fcntl.h>
#endif

struct pid_state;

bool chroot_is_chrooted( const pid_state *state );

// translate a process relative path into a path that is correct outside of the process
// "path" must be in a writable buffer, and its content will be scratch by the function
// "wd" is the directory in relation to which relative paths should be interpreted
// "stat" is going to be filled in with the detail of the last element of the path returned
// If there is some error (say - file not found) stat->st_ino will be equal -1 and errno
// will be set
// If there was no error, but no stat was necessary, stat->st_ino will be equal -2
std::string chroot_parse_path( const pid_state *state, char *path, const std::string &wd, struct stat *stat, bool resolve_last_link );

// Same as above, only grab the work directory and file name from the process' state
std::string chroot_translate_addr( pid_t pid, const pid_state *state, struct stat *stat, int dirfd, int_ptr addr, bool resolve_last_link );
// If dirfd is CHROOT_PWD, everything is relative to the current work dir for the process

// Grab the original path from the process space, translate the path (if chrooted) write the
// new path into the shared memory and move the original param to point at the new path.
// param_num - the param number to translate
// abort_error - if true and an error occures, do not copy the partial string
// offset - offset into the shared memory to write buffer to
bool chroot_translate_param( pid_t pid, const pid_state *state, int param_num, bool resolve_last_link,
    bool abort_error=false, int_ptr offset=0 );
bool chroot_translate_paramat( pid_t pid, const pid_state *state, int dirfd, int param_num, bool resolve_last_link,
    bool abort_error=false, int_ptr offset=0 );

#ifdef AT_FDCWD
#define CHROOT_PWD AT_FDCWD
#else
#define CHROOT_PWD (-1)
#endif

#endif // CHROOT_H
