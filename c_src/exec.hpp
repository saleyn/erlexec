// vim:ts=4:sw=4:et
/*
Author: Serge Aleynikov
Date:   2016-11-14
*/
#pragma once

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#ifdef HAVE_CAP
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <map>
#include <list>
#include <deque>
#include <set>
#include <sstream>

#if defined(__CYGWIN__) || defined(__WIN32) || defined(__APPLE__) \
     || (defined(__sun) && defined(__SVR4))
#  define NO_SIGTIMEDWAIT
#  define sigtimedwait(a, b, c) 0
#  define sigisemptyset(s) \
    !(sigismember(s, SIGCHLD) || sigismember(s, SIGPIPE) || \
      sigismember(s, SIGTERM) || sigismember(s, SIGINT) || \
      sigismember(s, SIGHUP))
#endif

#if __OpenBSD__ || __APPLE__ || (__NetBSD__ && __NetBSD_Version__ < 600000000)
#   include <sys/event.h>
#endif

#include <ei.h>
#include "ei++.hpp"

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------
extern char **environ; // process environment
//-------------------------------------------------------------------------

namespace ei {

//-------------------------------------------------------------------------
// Enums and constants
//-------------------------------------------------------------------------

enum ConstsT {
    // Default file permissions
    DEF_MODE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,

    // Default read/write buffer
    BUF_SIZE                = 2048,

    // In the event we have tried to kill something, wait this many
    // seconds and then *really* kill it with SIGKILL if needs be
    KILL_TIMEOUT_SEC        = 5,

    // Max number of seconds to sleep in the select() call
    SLEEP_TIMEOUT_SEC       = 5,

    // Number of seconds allowed for cleanup before exit
    FINALIZE_DEADLINE_SEC   = 10,

    SIGCHLD_MAX_SIZE        = 4096
};

enum RedirectType {
    REDIRECT_STDOUT = -1,   // Redirect to stdout
    REDIRECT_STDERR = -2,   // Redirect to stderr
    REDIRECT_NONE   = -3,   // No output redirection
    REDIRECT_CLOSE  = -4,   // Close output file descriptor
    REDIRECT_ERL    = -5,   // Redirect output back to Erlang
    REDIRECT_FILE   = -6,   // Redirect output to file
    REDIRECT_NULL   = -7    // Redirect input/output to /dev/null
};

enum class FileOpenFlag {
    READ     = 0,
    APPEND   = O_APPEND,
    TRUNCATE = O_TRUNC
};

//-------------------------------------------------------------------------
// Forward declarations
//-------------------------------------------------------------------------
struct CmdInfo;
struct CmdOptions;

//-------------------------------------------------------------------------
// Types
//-------------------------------------------------------------------------

typedef unsigned char byte;
typedef int   exit_status_t;
typedef pid_t kill_cmd_pid_t;
typedef std::list<std::string>              CmdArgsList;
typedef std::pair<pid_t, exit_status_t>     PidStatusT;
typedef std::pair<pid_t, CmdInfo>           PidInfoT;
typedef std::map <pid_t, CmdInfo>           MapChildrenT;
typedef std::pair<kill_cmd_pid_t, pid_t>    KillPidStatusT;
typedef std::map <kill_cmd_pid_t, pid_t>    MapKillPidT;
typedef std::map<std::string, std::string>  MapEnv;
typedef MapEnv::iterator                    MapEnvIterator;
typedef std::map<pid_t, exit_status_t>      ExitedChildrenT;

static const char* CS_DEV_NULL  = "/dev/null";

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------
extern int             debug;
extern int             alarm_max_time;
extern int             dev_null;
extern bool            pipe_valid;
extern bool            terminated;
extern int             max_fds;
extern int             sigchld_pipe[2];
extern Serializer      eis;
extern MapChildrenT    children;       // Map containing all managed processes started by this port program.
extern MapKillPidT     transient_pids; // Map of pids of custom kill commands.
extern ExitedChildrenT exited_children;// Set of processed SIGCHLD events
extern pid_t           self_pid;

//-------------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------------

/// Convert file descriptor to a meaningful string
std::string fd_type(int tp);

/// Symbolic name of stdin/stdout/stderr fd stream
const char* stream_name(int i);

int     read_sigchld(pid_t& child);
void    check_child_exit(pid_t pid);
int     set_euid(int userid);
int     set_nice(pid_t pid,int nice, std::string& error);
bool    process_sigchld();
bool    set_pid_winsz(CmdInfo& ci, int rows, int cols);
bool    process_pid_input(CmdInfo& ci);
void    process_pid_output(CmdInfo& ci, int maxsize = 4096);
int     send_ok(int transId, long value = -1);
int     send_pid(int transId, pid_t pid);
int     send_pid_status_term(const PidStatusT& stat);
int     send_error_str(int transId, bool asAtom, const char* fmt, ...);
int     send_pid_list(int transId, const MapChildrenT& children);
int     send_ospid_output(int pid, const char* type, const char* data, int len);

pid_t   start_child(CmdOptions& op, std::string& err);
int     kill_child(pid_t pid, int sig, int transId, bool notify=true);
int     check_children(const TimeVal& now, bool& isTerminated, bool notify = true);
void    check_child(const TimeVal& now, pid_t pid, CmdInfo& cmd);
void    check_child_exit(pid_t pid);
void    close_stdin(CmdInfo& ci);
void    stop_child(pid_t pid, int transId, const TimeVal& now);
int     stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify = true);
void    erase_child(MapChildrenT::iterator& it);

int     set_nonblock_flag(pid_t pid, int fd, bool value);
int     erl_exec_kill(pid_t pid, int signal);
int     open_file(const char* file, FileOpenFlag flag, const char* stream,
                  ei::StringBuffer<128>& err, int mode = DEF_MODE);
int     open_pipe(int fds[2], const char* stream, ei::StringBuffer<128>& err);

inline void add_exited_child(pid_t pid, exit_status_t status) {
    // Note the following function doesn't insert anything if the element
    // with given key was already present in the map
    exited_children.insert(std::make_pair(pid, status));
}

// Write details of terminated child to pipe
inline int write_sigchld(pid_t child)
{
    if (terminated || write(sigchld_pipe[1], (char*)&child, sizeof(child)) <= 0)
        return -1;
    return 0;
}

inline void gotsigchild(int signal, siginfo_t* si, void* context)
{
    // If someone used kill() to send SIGCHLD ignore the event
    if (si->si_code == SI_USER || signal != SIGCHLD)
        return;

    pid_t child = si->si_pid;

    if (debug)
        fprintf(stderr, "Child process %d exited\r\n", child);

    write_sigchld(child);
}

inline void gotsignal(int signal)
{
    if (signal == SIGTERM || signal == SIGINT || signal == SIGPIPE)
        terminated = true;
    if (signal == SIGPIPE)
        pipe_valid = false;
    if (debug)
        fprintf(stderr, "Got signal: %d\r\n", signal);
}

//-------------------------------------------------------------------------
// Structs
//-------------------------------------------------------------------------
struct CmdOptions {
private:
    ei::StringBuffer<256>   m_tmp;
    std::stringstream       m_err;
    bool                    m_shell;
    bool                    m_pty;
    std::string             m_executable;
    CmdArgsList             m_cmd;
    std::string             m_cd;
    std::string             m_kill_cmd;
    int                     m_kill_timeout;
    bool                    m_kill_group;
    MapEnv                  m_env;
    const char**            m_cenv;
    long                    m_nice;     // niceness level
    int                     m_group;    // used in setgid()
    int                     m_user;     // run as
    int                     m_success_exit_code;
    std::string             m_std_stream[3];
    bool                    m_std_stream_append[3];
    int                     m_std_stream_fd[3];
    int                     m_std_stream_mode[3];

    void init_streams() {
        for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
            m_std_stream_append[i]  = false;
            m_std_stream_mode[i]    = DEF_MODE;
            m_std_stream_fd[i]      = REDIRECT_NULL;
            m_std_stream[i]         = CS_DEV_NULL;
        }
    }

public:
    CmdOptions(int def_user=INT_MAX)
        : m_tmp(0, 256), m_shell(true), m_pty(false)
        , m_kill_timeout(KILL_TIMEOUT_SEC)
        , m_kill_group(false)
        , m_cenv(NULL), m_nice(INT_MAX)
        , m_group(INT_MAX), m_user(def_user)
        , m_success_exit_code(0)
    {
        init_streams();
    }
    CmdOptions(const CmdArgsList& cmd, const char* cd = NULL, const char** env = NULL,
               int user = INT_MAX, int nice = INT_MAX, int group = INT_MAX)
        : m_shell(true), m_pty(false), m_cmd(cmd), m_cd(cd ? cd : "")
        , m_kill_timeout(KILL_TIMEOUT_SEC)
        , m_kill_group(false)
        , m_cenv(NULL), m_nice(INT_MAX)
        , m_group(group), m_user(user)
    {
        init_streams();
    }
    ~CmdOptions() {
        if (m_cenv != (const char**)environ) delete [] m_cenv;
        m_cenv = NULL;
    }

    const char*         strerror()      const { return m_err.str().c_str(); }
    const std::string&  executable()    const { return m_executable; }
    const CmdArgsList&  cmd()           const { return m_cmd; }
    bool                shell()         const { return m_shell; }
    bool                pty()           const { return m_pty; }
    const char*  cd()                   const { return m_cd.c_str(); }
    char* const* env()                  const { return (char* const*)m_cenv; }
    const char*  kill_cmd()             const { return m_kill_cmd.c_str(); }
    int          kill_timeout()         const { return m_kill_timeout; }
    bool         kill_group()           const { return m_kill_group; }
    int          group()                const { return m_group; }
    int          user()                 const { return m_user; }
    int          success_exit_code()    const { return m_success_exit_code; }
    int          nice()                 const { return m_nice; }
    const char*  stream_file(int i)     const { return m_std_stream[i].c_str(); }
    bool         stream_append(int i)   const { return m_std_stream_append[i]; }
    int          stream_mode(int i)     const { return m_std_stream_mode[i]; }
    int          stream_fd(int i)       const { return m_std_stream_fd[i]; }
    int&         stream_fd(int i)             { return m_std_stream_fd[i]; }
    std::string  stream_fd_type(int i)  const { return fd_type(stream_fd(i)); }

    void executable(const std::string& s) { m_executable = s; }

    void stream_file(int i, const std::string& file, bool append = false, int mode = DEF_MODE) {
        m_std_stream_fd[i]      = REDIRECT_FILE;
        m_std_stream_append[i]  = append;
        m_std_stream_mode[i]    = mode;
        m_std_stream[i]         = file;
    }

    void stream_null(int i) {
        m_std_stream_fd[i]      = REDIRECT_NULL;
        m_std_stream_append[i]  = false;
        m_std_stream[i]         = CS_DEV_NULL;
    }

    void stream_redirect(int i, RedirectType type) {
        m_std_stream_fd[i]      = type;
        m_std_stream_append[i]  = false;
        m_std_stream[i].clear();
    }

    int ei_decode(ei::Serializer& ei, bool getCmd = false);
    int init_cenv();
};

//-------------------------------------------------------------------------
/// Contains run-time info of a child OS process.
/// When a user provides a custom command to kill a process this
/// structure will contain its run-time information.
//-------------------------------------------------------------------------
struct CmdInfo {
    CmdArgsList     cmd;            // Executed command
    pid_t           cmd_pid;        // Pid of the custom kill command
    pid_t           cmd_gid;        // Command's group ID
    std::string     kill_cmd;       // Kill command to use (default: use SIGTERM)
    kill_cmd_pid_t  kill_cmd_pid;   // Pid of the command that <pid> is supposed to kill
    ei::TimeVal     deadline;       // Time when the <cmd_pid> is supposed to be killed using SIGTERM.
    bool            sigterm;        // <true> if sigterm was issued.
    bool            sigkill;        // <true> if sigkill was issued.
    int             kill_timeout;   // Pid shutdown interval in sec before it's killed with SIGKILL
    bool            kill_group;     // Indicates if at exit the whole group needs to be killed
    int             success_code;   // Exit code to use on success
    bool            managed;        // <true> if this pid is started externally, but managed by erlexec
    int             stream_fd[3];   // Pipe fd getting   process's stdin/stdout/stderr
    int             stdin_wr_pos;   // Offset of the unwritten portion of the head item of stdin_queue
    std::list<std::string> stdin_queue;

    CmdInfo() {
        new (this) CmdInfo(CmdArgsList(), "", 0, INT_MAX, 0);
    }
    CmdInfo(const CmdInfo& ci) {
        new (this) CmdInfo(ci.cmd, ci.kill_cmd.c_str(), ci.cmd_pid, ci.cmd_gid,
                           ci.success_code, ci.managed,
                           ci.stream_fd[STDIN_FILENO], ci.stream_fd[STDOUT_FILENO],
                           ci.stream_fd[STDERR_FILENO], ci.kill_timeout, ci.kill_group);
    }
    CmdInfo(bool managed, const char* _kill_cmd, pid_t _cmd_pid, int _ok_code,
            bool _kill_group = false) {
        new (this) CmdInfo(cmd, _kill_cmd, _cmd_pid, getpgid(_cmd_pid), _ok_code, managed);
        kill_group = _kill_group;
    }
    CmdInfo(const CmdArgsList& _cmd, const char* _kill_cmd, pid_t _cmd_pid, pid_t _cmd_gid,
            int  _success_code,
            bool _managed      = false,
            int  _stdin_fd     = REDIRECT_NULL,
            int  _stdout_fd    = REDIRECT_NONE,
            int  _stderr_fd    = REDIRECT_NONE,
            int  _kill_timeout = KILL_TIMEOUT_SEC,
            bool _kill_group   = false)
        : cmd(_cmd)
        , cmd_pid(_cmd_pid)
        , cmd_gid(_cmd_gid)
        , kill_cmd(_kill_cmd), kill_cmd_pid(-1)
        , sigterm(false), sigkill(false)
        , kill_timeout(_kill_timeout)
        , kill_group(_kill_group)
        , success_code(_success_code)
        , managed(_managed), stdin_wr_pos(0)
    {
        stream_fd[STDIN_FILENO]  = _stdin_fd;
        stream_fd[STDOUT_FILENO] = _stdout_fd;
        stream_fd[STDERR_FILENO] = _stderr_fd;
    }

    void include_stream_fd(int i, int& maxfd, fd_set* readfds, fd_set* writefds) {
        bool ok;
        fd_set* fds;

        if (i == STDIN_FILENO) {
            ok = stream_fd[i] >= 0 && stdin_wr_pos > 0;
            if (ok && debug > 2)
                fprintf(stderr, "Pid %d adding stdin available notification (fd=%d, pos=%d)\r\n",
                    cmd_pid, stream_fd[i], stdin_wr_pos);
            fds = writefds;
        } else {
            ok = stream_fd[i] >= 0;
            if (ok && debug > 2)
                fprintf(stderr, "Pid %d adding stdout checking (fd=%d)\r\n", cmd_pid, stream_fd[i]);
            fds = readfds;
        }

        if (ok) {
            FD_SET(stream_fd[i], fds);
            if (stream_fd[i] > maxfd) maxfd = stream_fd[i];
        }
    }

    void process_stream_data(int i, fd_set* readfds, fd_set* writefds) {
        int     fd  = stream_fd[i];
        fd_set* fds = i == STDIN_FILENO ? writefds : readfds;

        if (fd < 0 || !FD_ISSET(fd, fds)) return;

        if (i == STDIN_FILENO)
            process_pid_input(*this);
        else
            process_pid_output(*this);
    }
};

} // namespace ei
