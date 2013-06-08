#ifndef DAEMON_H
#define DAEMON_H

#include "exceptions.h"
#include "unique_fd.h"

#include <list>
#include <string>

#include <sys/select.h>

class daemonProcess;
template <class T> class ipcMessage;

// Connect to the daemon, launching it if necessary, and return the connection fd
class daemonCtrl {
    daemonCtrl( const daemonCtrl & )=delete;
    daemonCtrl & operator=( const daemonCtrl & )=delete;

    friend class daemonProcess;

    enum commands {
        CMD_RESERVE,
        CMD_ATTACH
    };

    struct request {
        enum commands command;
    };

    struct response {
        enum commands command;
        int result;
    };
public:
    class terminal_error : public detailed_exception {
    public:
        terminal_error( const char * msg ) : detailed_exception(msg)
        {
        }
    };

    class remote_hangup_exception : public terminal_error {
    public:
        remote_hangup_exception() : terminal_error( "Remote hung up" )
        {}
    };

    class short_msg_exception : public terminal_error {
    public:
        short_msg_exception() : terminal_error( "Remote sent short message" )
        {}
    };

private:
    int daemon_socket;
    pid_t daemon_pid;

public:
    daemonCtrl(const char *state_file_path, bool nodetach);
    ~daemonCtrl();

    void cmd_attach();
private:
    void connect( const char * state_file_path );
    // Standard commands are commands with no reply other than "ACK"
    void send_std_cmd( commands command, ipcMessage<response> &response ) const;

    static void set_client_sock_options( int fd );

    void cmd_reserve();
};

class daemonProcess {
    daemonProcess( const daemonProcess & )=delete;
    daemonProcess & operator=( const daemonProcess & )=delete;

    std::list<unique_fd> session_fds;
    fd_set file_set;
    int max_fd;

    std::string state_path;
    unique_fd master_socket;
    unique_fd state_fd;

    static bool daemonize( bool nodetach, int skip_fd1=-1, int skip_fd2=-1 );

    explicit daemonProcess( int session_fd ); // Constructor for non-persistent daemon
    // Constructor for persistent daemon
    daemonProcess( const std::string &path, unique_fd &state_file, unique_fd &master_fd );

public:
    ~daemonProcess();

    // Create an anonymous daemon process, returning the connection file descriptor
    static int create( bool nodetach );
    static void create( const char *state_file_path, bool nodetach );

    bool handle_request( const sigset_t *sigmask, bool existing_children );
    static void set_client_sock_options( int fd );

private:
    void start();
    void register_session( unique_fd &fd );
    void unregister_Session( int fd );
    void handle_new_connection();
    void recalc_select_mask();
    void close_session( decltype(session_fds)::iterator & element );

    void handle_connection_request( decltype(session_fds)::iterator & element );
    void handle_cmd_reserve( decltype(session_fds)::iterator &element, const ipcMessage<daemonCtrl::request> &message );
    void handle_cmd_attach( decltype(session_fds)::iterator &element, const ipcMessage<daemonCtrl::request> &message );
};

#endif // DAEMON_H
