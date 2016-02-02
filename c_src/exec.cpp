/*
    exec.cpp

    Author:   Serge Aleynikov
    Created:  2003/07/10

    Description:
    ============

    Erlang port program for spawning and controlling OS tasks.
    It listens for commands sent from Erlang and executes them until
    the pipe connecting it to Erlang VM is closed or the program
    receives SIGINT or SIGTERM. At that point it kills all processes
    it forked by issuing SIGTERM followed by SIGKILL in 6 seconds.

    Marshalling protocol:
        Erlang                                                  C++
          | ---- {TransId::integer(), Instruction::tuple()} ---> |
          | <----------- {TransId::integer(), Reply} ----------- |

    Instruction = {manage, OsPid::integer(), Options} |
                  {run,   Cmd::string(), Options}   |
                  {list}                            |
                  {stop, OsPid::integer()}          |
                  {kill, OsPid::integer(), Signal::integer()} |
                  {stdin, OsPid::integer(), Data::binary()}

    Options = [Option]
    Option  = {cd, Dir::string()} |
              {env, [string() | {string(), string()}]} |
              {kill, Cmd::string()} |
              {kill_timeout, Sec::integer()} |
              kill_group |
              {group, integer() | string()} |
              {user, User::string()} |
              {nice, Priority::integer()} |
              stdin  | {stdin, null | close | File::string()} |
              stdout | {stdout, Device::string()} |
              stderr | {stderr, Device::string()} |
              pty    | {success_exit_code, N::integer()}

    Device  = close | null | stderr | stdout | File::string() | {append, File::string()}

    Reply = ok                      |       // For kill/stop commands
            {ok, OsPid}             |       // For run command
            {ok, [OsPid]}           |       // For list command
            {error, Reason}         |
            {exit_status, OsPid, Status}    // OsPid terminated with Status

    Reason = atom() | string()
    OsPid  = integer()
    Status = integer()
*/

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
#include <setjmp.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <map>
#include <list>
#include <deque>
#include <set>
#include <sstream>

#include <ei.h>
#include "ei++.hpp"

#if defined(__CYGWIN__) || defined(__WIN32) || defined(__APPLE__) \
     || (defined(__sun) && defined(__SVR4))
#  define NO_SIGTIMEDWAIT
#  define sigtimedwait(a, b, c) 0
#  define sigisemptyset(s) \
    !(sigismember(s, SIGCHLD) || sigismember(s, SIGPIPE) || \
      sigismember(s, SIGTERM) || sigismember(s, SIGINT) || \
      sigismember(s, SIGHUP))
#endif

using namespace ei;

//-------------------------------------------------------------------------
// Defines
//-------------------------------------------------------------------------

#define BUF_SIZE 2048

// In the event we have tried to kill something, wait this many
// seconds and then *really* kill it with SIGKILL if needs be
#define KILL_TIMEOUT_SEC 5

// Max number of seconds to sleep in the select() call
#define SLEEP_TIMEOUT_SEC 5

// Number of seconds allowed for cleanup before exit
#define FINALIZE_DEADLINE_SEC 10

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------

extern char **environ; // process environment

ei::Serializer eis(/* packet header size */ 2);

sigjmp_buf  jbuf;
static int  alarm_max_time  = FINALIZE_DEADLINE_SEC + 2;
static int  debug           = 0;
static bool oktojump        = false;
static int  terminated      = 0;    // indicates that we got a SIGINT / SIGTERM event
static bool pipe_valid      = true;
static int  max_fds;
static int  dev_null;

static const int   DEF_MODE     = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
static const char* CS_DEV_NULL  = "/dev/null";

//-------------------------------------------------------------------------
// Types & variables
//-------------------------------------------------------------------------

struct CmdInfo;

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

MapChildrenT    children;       // Map containing all managed processes started by this port program.
MapKillPidT     transient_pids; // Map of pids of custom kill commands.
ExitedChildrenT exited_children;// Set of processed SIGCHLD events
pid_t           self_pid;

#define SIGCHLD_MAX_SIZE 4096

enum RedirectType {
    REDIRECT_STDOUT = -1,   // Redirect to stdout
    REDIRECT_STDERR = -2,   // Redirect to stderr
    REDIRECT_NONE   = -3,   // No output redirection
    REDIRECT_CLOSE  = -4,   // Close output file descriptor
    REDIRECT_ERL    = -5,   // Redirect output back to Erlang
    REDIRECT_FILE   = -6,   // Redirect output to file
    REDIRECT_NULL   = -7    // Redirect input/output to /dev/null
};

std::string fd_type(int tp) {
    switch (tp) {
        case REDIRECT_STDOUT:   return "stdout";
        case REDIRECT_STDERR:   return "stderr";
        case REDIRECT_NONE:     return "none";
        case REDIRECT_CLOSE:    return "close";
        case REDIRECT_ERL:      return "erlang";
        case REDIRECT_FILE:     return "file";
        case REDIRECT_NULL:     return "null";
        default: {
            std::stringstream s;
            if (tp == dev_null)
                s << "null(fd:" << tp << ')';
            else
                s << "fd:" << tp;
            return s.str();
        }
    }
    return std::string(); // Keep the compiler happy
}

struct CmdOptions;

//-------------------------------------------------------------------------
// Local Functions
//-------------------------------------------------------------------------

int     send_ok(int transId, pid_t pid = -1);
int     send_pid_status_term(const PidStatusT& stat);
int     send_error_str(int transId, bool asAtom, const char* fmt, ...);
int     send_pid_list(int transId, const MapChildrenT& children);
int     send_ospid_output(int pid, const char* type, const char* data, int len);

pid_t   start_child(CmdOptions& op, std::string& err);
int     kill_child(pid_t pid, int sig, int transId, bool notify=true);
int     check_children(const TimeVal& now, int& isTerminated, bool notify = true);
bool    process_pid_input(CmdInfo& ci);
void    process_pid_output(CmdInfo& ci, int maxsize = 4096);
void    stop_child(pid_t pid, int transId, const TimeVal& now);
int     stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify = true);
void    erase_child(MapChildrenT::iterator& it);

int     process_command();
void    initialize(int userid, bool use_alt_fds, bool run_as_root);
int     finalize();
int     set_nonblock_flag(pid_t pid, int fd, bool value);
int     erl_exec_kill(pid_t pid, int signal);
int     open_file(const char* file, bool append, const char* stream,
                  ei::StringBuffer<128>& err, int mode = DEF_MODE);
int     open_pipe(int fds[2], const char* stream, ei::StringBuffer<128>& err);

//-------------------------------------------------------------------------
// Types
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
    CmdOptions()
        : m_tmp(0, 256), m_shell(true), m_pty(false)
        , m_kill_timeout(KILL_TIMEOUT_SEC)
        , m_kill_group(false)
        , m_cenv(NULL), m_nice(INT_MAX)
        , m_group(INT_MAX), m_user(INT_MAX)
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

/// Contains run-time info of a child OS process.
/// When a user provides a custom command to kill a process this
/// structure will contain its run-time information.
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

//-------------------------------------------------------------------------
// Local Functions
//-------------------------------------------------------------------------

const char* stream_name(int i) {
    switch (i) {
        case STDIN_FILENO:  return "stdin";
        case STDOUT_FILENO: return "stdout";
        case STDERR_FILENO: return "stderr";
        default:            return "<unknown>";
    }
}

void gotsignal(int signal)
{
    if (signal == SIGTERM || signal == SIGINT || signal == SIGPIPE)
        terminated = 1;
    if (signal == SIGPIPE)
        pipe_valid = false;
    if (debug)
        fprintf(stderr, "Got signal: %d (oktojump=%d)\r\n", signal, oktojump);
    if (oktojump) siglongjmp(jbuf, 1);
}

void check_child(pid_t pid, int signal = -1)
{
    int status = 0;
    pid_t ret;

    if (pid == self_pid)    // Safety check. Never kill itself
        return;

    if (exited_children.find(pid) != exited_children.end())
        return;

    while ((ret = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

    if (debug)
        fprintf(stderr,
            "* Process %d (ret=%d, status=%d, sig=%d, "
            "oktojump=%d, exited_count=%ld%s%s)\r\n",
            pid, ret, status, signal, oktojump, exited_children.size(),
            ret > 0 && WIFEXITED(status) ? " [exited]":"",
            ret > 0 && WIFSIGNALED(status) ? " [signaled]":"");

    if (ret < 0 && errno == ECHILD) {
        if (erl_exec_kill(pid, 0) == 0) // process likely forked and is alive
            status = 0;
        if (status != 0)
            exited_children.insert(std::make_pair(pid <= 0 ? ret : pid, status));
    } else if (pid <= 0 && ret > 0) {
        exited_children.insert(std::make_pair(ret, status == 0 && signal == -1 ? 1 : status));
    } else if (ret == pid || WIFEXITED(status) || WIFSIGNALED(status)) {
        if (ret > 0)
            exited_children.insert(std::make_pair(pid, status));
    }

    if (oktojump) siglongjmp(jbuf, 1);
}

void gotsigchild(int signal, siginfo_t* si, void* context)
{
    // If someone used kill() to send SIGCHLD ignore the event
    if (si->si_code == SI_USER || signal != SIGCHLD)
        return;

    pid_t pid = si->si_pid;

    if (debug)
        fprintf(stderr, "Child process %d exited\r\n", pid);

    check_child(pid, signal);
}

void add_exited_child(pid_t pid, exit_status_t status) {
    std::pair<pid_t, exit_status_t> value = std::make_pair(pid, status);
    // Note the following function doesn't insert anything if the element
    // with given key was already present in the map
    exited_children.insert(value);
}

void check_pending()
{
    #if !defined(NO_SIGTIMEDWAIT)
    static const struct timespec timeout = {0, 0};
    #endif

    sigset_t  set;
    siginfo_t info;
    int sig;
    sigemptyset(&set);
    if (sigpending(&set) == 0 && !sigisemptyset(&set)) {
        if (debug > 1)
            fprintf(stderr, "Detected pending signals\r\n");

        while ((sig = sigtimedwait(&set, &info, &timeout)) > 0 || errno == EINTR)
            switch (sig) {
                case SIGCHLD:   gotsigchild(sig, &info, NULL); break;
                case SIGPIPE:   pipe_valid = false; /* intentionally follow through */
                case SIGTERM:
                case SIGINT:
                case SIGHUP:    gotsignal(sig); break;
                default:        break;
            }
    }
}

int set_nice(pid_t pid,int nice, std::string& error)
{
    ei::StringBuffer<128> err;

    if (nice != INT_MAX && setpriority(PRIO_PROCESS, pid, nice) < 0) {
        err.write("Cannot set priority of pid %d to %d", pid, nice);
        error = err.c_str();
        if (debug)
            fprintf(stderr, "%s\r\n", error.c_str());
        return -1;
    }
    return 0;
}

void usage(char* progname) {
    fprintf(stderr,
        "Usage:\n"
        "   %s [-n] [-root] [-alarm N] [-debug [Level]] [-user User]\n"
        "Options:\n"
        "   -n              - Use marshaling file descriptors 3&4 instead of default 0&1.\n"
        "   -root           - Allow running child processes as root.\n"
        "   -alarm N        - Allow up to <N> seconds to live after receiving SIGTERM/SIGINT (default %d)\n"
        "   -debug [Level]  - Turn on debug mode (default Level: 1)\n"
        "   -user User      - If started by root, run as User\n"
        "Description:\n"
        "   This is a port program intended to be started by an Erlang\n"
        "   virtual machine.  It can start/kill/list OS processes\n"
        "   as requested by the virtual machine.\n",
        progname, alarm_max_time);
    exit(1);
}

//-------------------------------------------------------------------------
// MAIN
//-------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    fd_set readfds, writefds;
    struct sigaction sact, sterm;
    int userid = 0;
    bool use_alt_fds = false;
    bool run_as_root = false;

    sterm.sa_handler = gotsignal;
    sigemptyset(&sterm.sa_mask);
    sigaddset(&sterm.sa_mask, SIGCHLD);
    sterm.sa_flags = 0;
    sigaction(SIGINT,  &sterm, NULL);
    sigaction(SIGTERM, &sterm, NULL);
    sigaction(SIGHUP,  &sterm, NULL);
    sigaction(SIGPIPE, &sterm, NULL);

    self_pid = getpid();

    sact.sa_handler = NULL;
    sact.sa_sigaction = gotsigchild;
    sigemptyset(&sact.sa_mask);
    sact.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP; // | SA_NODEFER;
    sigaction(SIGCHLD, &sact, NULL);

    if (argc > 1) {
        int res;
        for(res = 1; res < argc; res++) {
            if (strcmp(argv[res], "-h") == 0 || strcmp(argv[res], "--help") == 0) {
                usage(argv[0]);
            } else if (strcmp(argv[res], "-debug") == 0) {
                debug = (res+1 < argc && argv[res+1][0] != '-') ? atoi(argv[++res]) : 1;
                if (debug > 3)
                    eis.debug(true);
            } else if (strcmp(argv[res], "-alarm") == 0 && res+1 < argc) {
                if (argv[res+1][0] != '-')
                    alarm_max_time = atoi(argv[++res]);
                else
                    usage(argv[0]);
            } else if (strcmp(argv[res], "-n") == 0) {
                use_alt_fds = true;
            } else if (strcmp(argv[res], "-user") == 0 && res+1 < argc && argv[res+1][0] != '-') {
                char* run_as_user = argv[++res];
                struct passwd *pw = NULL;
                if ((pw = getpwnam(run_as_user)) == NULL) {
                    fprintf(stderr, "User %s not found!\r\n", run_as_user);
                    exit(3);
                }
                userid = pw->pw_uid;
            } else if (strcmp(argv[res], "-root") == 0) {
                run_as_root = true;
            }
        }
    }

    initialize(userid, use_alt_fds, run_as_root);

    while (!terminated) {

        sigsetjmp(jbuf, 1); oktojump = 0;

        FD_ZERO (&writefds);
        FD_ZERO (&readfds);

        FD_SET (eis.read_handle(), &readfds);

        int maxfd = eis.read_handle();

        TimeVal now(TimeVal::NOW);

        while (!terminated && !exited_children.empty()) {
            if (check_children(now, terminated) < 0)
                break;
        }

        double wakeup = SLEEP_TIMEOUT_SEC;

        // Set up all stdout/stderr input streams that we need to monitor and redirect to Erlang
        for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it)
            for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
                it->second.include_stream_fd(i, maxfd, &readfds, &writefds);
                if (!it->second.deadline.zero())
                    wakeup = std::max(0.0, std::min(wakeup, it->second.deadline.diff(now)));
            }

        check_pending(); // Check for pending signals arrived while we were in the signal handler

        if (terminated || wakeup < 0) break;

        oktojump = 1;
        ei::TimeVal timeout((int)wakeup, (wakeup - (int)wakeup) * 1000000);

        if (debug > 2)
            fprintf(stderr, "Selecting maxfd=%d (sleep={%ds,%dus})\r\n",
                maxfd, timeout.sec(), timeout.usec());

        int cnt = select (maxfd+1, &readfds, &writefds, (fd_set *) 0, &timeout.timeval());
        int interrupted = (cnt < 0 && errno == EINTR);
        oktojump = 0;

        if (debug > 2)
            fprintf(stderr, "Select got %d events (maxfd=%d)\r\n", cnt, maxfd);

        if (interrupted || cnt == 0) {
            now.now();
            if (check_children(now, terminated) < 0) {
                terminated = 11;
                break;
            }
        } else if (cnt < 0) {
            if (errno == EBADF) {
                if (debug)
                    fprintf(stderr, "Error EBADF(9) in select: %s (terminated=%d)\r\n",
                        strerror(errno), terminated);
                continue;
            }
            fprintf(stderr, "Error %d in select: %s\r\n", errno, strerror(errno));
            terminated = 12;
            break;
        } else if ( FD_ISSET (eis.read_handle(), &readfds) ) {
            /* Read from input stream a command sent by Erlang */
            if (process_command() < 0) {
                break;
            }
        } else {
            // Check if any stdout/stderr streams have data
            for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it)
                for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++)
                    it->second.process_stream_data(i, &readfds, &writefds);
        }
    }

    sigsetjmp(jbuf, 1); oktojump = 0;

    return finalize();

}

int process_command()
{
    int  err, arity;
    long transId;
    std::string command;

    // Note that if we were using non-blocking reads, we'd also need to check
    // for errno EWOULDBLOCK.
    if ((err = eis.read()) < 0) {
        if (debug)
            fprintf(stderr, "Broken Erlang command pipe (%d): %s\r\n",
                errno, strerror(errno));
        terminated = errno;
        return -1;
    }

    /* Our marshalling spec is that we are expecting a tuple
     * TransId, {Cmd::atom(), Arg1, Arg2, ...}} */
    if (eis.decodeTupleSize() != 2 ||
        (eis.decodeInt(transId)) < 0 ||
        (arity = eis.decodeTupleSize()) < 1)
    {
        terminated = 12;
        return -1;
    }

    enum CmdTypeT        {  MANAGE,  RUN,  STOP,  KILL,  LIST,  SHUTDOWN,  STDIN  } cmd;
    const char* cmds[] = { "manage","run","stop","kill","list","shutdown","stdin" };

    /* Determine the command */
    if ((int)(cmd = (CmdTypeT) eis.decodeAtomIndex(cmds, command)) < 0) {
        if (send_error_str(transId, false, "Unknown command: %s", command.c_str()) < 0) {
            terminated = 13;
            return -1;
        }
        return 0;
    }

    switch (cmd) {
        case SHUTDOWN: {
            terminated = 0;
            return -1;
        }
        case MANAGE: {
            // {manage, Cmd::string(), Options::list()}
            CmdOptions po;
            long       pid;
            pid_t      realpid;
            int        ret;

            if (arity != 3 || (eis.decodeInt(pid)) < 0 || po.ei_decode(eis) < 0 || pid <= 0) {
                send_error_str(transId, true, "badarg");
                return 0;
            }
            realpid = pid;

            while ((ret = kill(pid, 0)) < 0 && errno == EINTR);

            if (ret < 0) {
                send_error_str(transId, true, "not_found");
                return 0;
            }

            CmdInfo ci(true, po.kill_cmd(), realpid, po.success_exit_code(), po.kill_group());
            ci.kill_timeout = po.kill_timeout();
            children[realpid] = ci;

            // Set nice priority for managed process if option is present
            std::string error;
            set_nice(realpid,po.nice(),error);

            send_ok(transId, pid);
            break;
        }
        case RUN: {
            // {run, Cmd::string(), Options::list()}
            CmdOptions po;

            if (arity != 3 || po.ei_decode(eis, true) < 0) {
                send_error_str(transId, false, po.strerror());
                break;
            }

            pid_t pid;
            std::string err;
            if ((pid = start_child(po, err)) < 0)
                send_error_str(transId, false, "Couldn't start pid: %s", err.c_str());
            else {
                CmdInfo ci(po.cmd(), po.kill_cmd(), pid,
                           getpgid(pid),
                           po.success_exit_code(), false,
                           po.stream_fd(STDIN_FILENO),
                           po.stream_fd(STDOUT_FILENO),
                           po.stream_fd(STDERR_FILENO),
                           po.kill_timeout(),
                           po.kill_group());
                children[pid] = ci;
                send_ok(transId, pid);
            }
            break;
        }
        case STOP: {
            // {stop, OsPid::integer()}
            long pid;
            if (arity != 2 || eis.decodeInt(pid) < 0) {
                send_error_str(transId, true, "badarg");
                break;
            }
            stop_child(pid, transId, TimeVal(TimeVal::NOW));
            break;
        }
        case KILL: {
            // {kill, OsPid::integer(), Signal::integer()}
            long pid, sig;
            if (arity != 3 || eis.decodeInt(pid) < 0 || eis.decodeInt(sig) < 0 || pid == -1) {
                send_error_str(transId, true, "badarg");
                break;
            } else if (pid < 0) {
                send_error_str(transId, false, "Not allowed to send signal to all processes");
                break;
            } else if (children.find(pid) == children.end()) {
                send_error_str(transId, false, "Cannot kill a pid not managed by this application");
                break;
            }
            kill_child(pid, sig, transId);
            break;
        }
        case LIST: {
            // {list}
            if (arity != 1) {
                send_error_str(transId, true, "badarg");
                break;
            }
            send_pid_list(transId, children);
            break;
        }
        case STDIN: {
            // {stdin, OsPid::integer(), Data::binary()}
            long pid;
            std::string data;
            if (arity != 3 || eis.decodeInt(pid) < 0 || eis.decodeBinary(data) < 0) {
                send_error_str(transId, true, "badarg");
                break;
            }

            MapChildrenT::iterator it = children.find(pid);
            if (it == children.end()) {
                if (debug)
                    fprintf(stderr, "Stdin (%ld bytes) cannot be sent to non-existing pid %ld\r\n",
                        data.size(), pid);
                break;
            }
            it->second.stdin_queue.push_front(data);
            process_pid_input(it->second);
            break;
        }
    }
    return 0;
}

void initialize(int userid, bool use_alt_fds, bool run_as_root)
{
    // If we are root, switch to non-root user and set capabilities
    // to be able to adjust niceness and run commands as other users.
    // unless run_as_root is set
    if (getuid() == 0 && !run_as_root) {
        if (userid == 0) {
            fprintf(stderr, "When running as root, \"-user User\" or \"-root\" option must be provided!\r\n");
            exit(4);
        }

        #ifdef HAVE_CAP
        if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
            perror("Failed to call prctl to keep capabilities");
            exit(5);
        }
        #endif

        if (
            #ifdef HAVE_SETRESUID
            setresuid(-1, userid, geteuid()) // glibc, FreeBSD, OpenBSD, HP-UX
            #elif HAVE_SETREUID
            setreuid(-1, userid)             // MacOSX, NetBSD, AIX, IRIX, Solaris>=2.5, OSF/1, Cygwin
            #else
            #error setresuid(3) not supported!
            #endif
        < 0) {
            perror("Failed to set userid");
            exit(6);
        }

        struct passwd* pw;
        if (debug && (pw = getpwuid(geteuid())) != NULL)
            fprintf(stderr, "exec: running as: %s (euid=%d)\r\n", pw->pw_name, geteuid());

        if (geteuid() == 0) {
            fprintf(stderr, "exec: failed to set effective userid to a non-root user %s (uid=%d)\r\n",
                pw ? pw->pw_name : "", geteuid());
            exit(7);
        }

        #ifdef HAVE_CAP
        cap_t cur;
        if ((cur = cap_from_text("cap_setuid=eip cap_kill=eip cap_sys_nice=eip")) == 0) {
            fprintf(stderr, "exec: failed to convert cap_setuid & cap_sys_nice from text");
            exit(8);
        }
        if (cap_set_proc(cur) < 0) {
            fprintf(stderr, "exec: failed to set cap_setuid & cap_sys_nice");
            exit(9);
        }
        cap_free(cur);

        if (debug && (cur = cap_get_proc()) != NULL) {
            fprintf(stderr, "exec: current capabilities: %s\r\n",  cap_to_text(cur, NULL));
            cap_free(cur);
        }
        #else
        if (debug)
            fprintf(stderr, "exec: capability feature is not implemented for this plaform!\r\n");
        #endif

        if (!getenv("SHELL") || strncmp(getenv("SHELL"), "", 1) == 0) {
            fprintf(stderr, "exec: SHELL variable is not set!\r\n");
            exit(10);
        }

    }

    #if !defined(NO_SYSCONF)
    max_fds = sysconf(_SC_OPEN_MAX);
    #else
    max_fds = OPEN_MAX;
    #endif
    if (max_fds < 1024) max_fds = 1024;

    dev_null = open(CS_DEV_NULL, O_RDWR);

    if (dev_null < 0) {
        fprintf(stderr, "exec: cannot open %s: %s\r\n", CS_DEV_NULL, strerror(errno));
        exit(10);
    }

    if (use_alt_fds) {
        // TODO: when closing stdin/stdout we need to ensure that redirected
        // streams in the forked children have FDs different from 0,1,2 or else
        // wrong file handles get closed. Therefore for now just leave
        // stdin/stdout open even when not needed

        //eis.close_handles(); // Close stdin, stdout
        eis.set_handles(3, 4);
    }
}

int finalize()
{
    if (debug) fprintf(stderr, "Setting alarm to %d seconds\r\n", alarm_max_time);
    alarm(alarm_max_time);  // Die in <alarm_max_time> seconds if not done

    int old_terminated = terminated;
    terminated = 0;

    kill(0, SIGTERM); // Kill all children in our process group

    TimeVal now(TimeVal::NOW);
    TimeVal deadline(now, FINALIZE_DEADLINE_SEC, 0);

    while (children.size() > 0) {
        sigsetjmp(jbuf, 1);

        now.now();
        if (children.size() > 0 || !exited_children.empty()) {
            int term = 0;
            check_children(now, term, pipe_valid);
        }

        for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it)
            stop_child(it->second, 0, now, false);

        for(MapKillPidT::iterator it=transient_pids.begin(), end=transient_pids.end(); it != end; ++it) {
            erl_exec_kill(it->first, SIGKILL);
            transient_pids.erase(it);
        }

        if (children.size() == 0)
            break;

        TimeVal timeout(TimeVal::NOW);
        if (timeout < deadline) {
            timeout = deadline - timeout;

            oktojump = 1;
            while (select(0, (fd_set *)0, (fd_set *)0, (fd_set *)0, &timeout) < 0 && errno == EINTR);
            oktojump = 0;
        }
    }

    if (debug)
        fprintf(stderr, "Exiting (%d)\r\n", old_terminated);

    return old_terminated;
}

static int getpty(int& fdmp, int& fdsp, ei::StringBuffer<128>& err) {
    int fdm, fds;
    int rc;

    fdm = posix_openpt(O_RDWR);
    if (fdm < 0) {
        err.write("error %d on posix_openpt: %s\n", errno, strerror(errno));
        return -1;
    }

    rc = grantpt(fdm);
    if (rc != 0) {
        close(fdm);
        err.write("error %d on grantpt: %s\n", errno, strerror(errno));
        return -1;
    }

    rc = unlockpt(fdm);
    if (rc != 0) {
        close(fdm);
        err.write("error %d on unlockpt: %s\n", errno, strerror(errno));
        return -1;
    }

    fds = open(ptsname(fdm), O_RDWR);

    if (fds < 0) {
        close(fdm);
        err.write("error %d on open pty slave: %s\n", errno, strerror(errno));
        return -1;
    }

    fdmp = fdm;
    fdsp = fds;

    if (debug)
        fprintf(stderr, "  Opened PTY pair (master=%d, slave=%d)\r\n",
                fdm, fds);

    return 0;
}

pid_t start_child(CmdOptions& op, std::string& error)
{
    enum { RD = 0, WR = 1 };

    int stream_fd[][2] = {
        // ChildReadFD    ChildWriteFD
        { REDIRECT_NULL, REDIRECT_NONE },
        { REDIRECT_NONE, REDIRECT_NULL },
        { REDIRECT_NONE, REDIRECT_NULL }
    };

    ei::StringBuffer<128> err;

    // Optionally setup pseudoterminal
    int fdm, fds;

    if (op.pty()) {
        if (getpty(fdm, fds, err) < 0) {
            error = err.c_str();
            return -1;
        }
    }

    // Optionally setup stdin/stdout/stderr redirect
    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
        int  crw = i==0 ? RD : WR;
        int  cfd = op.stream_fd(i);
        int* sfd = stream_fd[i];

        // Optionally setup stdout redirect
        switch (cfd) {
            case REDIRECT_CLOSE:
                sfd[RD] = cfd;
                sfd[WR] = cfd;
                if (debug)
                    fprintf(stderr, "  Closing %s\r\n", stream_name(i));
                break;
            case REDIRECT_STDOUT:
            case REDIRECT_STDERR:
                sfd[crw] = cfd;
                if (debug)
                    fprintf(stderr, "  Redirecting [%s -> %s]\r\n", stream_name(i),
                            fd_type(cfd).c_str());
                break;
            case REDIRECT_ERL:
                if (op.pty()) {
                    if (i == STDIN_FILENO) {
                        sfd[RD] = fds;
                        sfd[WR] = fdm;
                    } else {
                        sfd[WR] = fds;
                        sfd[RD] = fdm;
                    }
                    if (debug)
                        fprintf(stderr, "  Redirecting [%s -> pipe:{r=%d,w=%d}] (PTY)\r\n",
                            stream_name(i), sfd[0], sfd[1]);
                } else if (open_pipe(sfd, stream_name(i), err) < 0) {
                    error = err.c_str();
                    return -1;
                }
                break;
            case REDIRECT_NULL:
                sfd[crw] = dev_null;
                if (debug)
                    fprintf(stderr, "  Redirecting [%s -> null]\r\n",
                            stream_name(i));
                break;
            case REDIRECT_FILE: {
                sfd[crw] = open_file(op.stream_file(i), op.stream_append(i),
                                     stream_name(i), err, op.stream_mode(i));
                if (sfd[crw] < 0) {
                    error = err.c_str();
                    return -1;
                }
                break;
            }
        }
    }

    if (debug) {
        fprintf(stderr, "Starting child: '%s'\r\n"
                        "  child  = (stdin=%s, stdout=%s, stderr=%s)\r\n"
                        "  parent = (stdin=%s, stdout=%s, stderr=%s)\r\n",
            op.cmd().front().c_str(),
            fd_type(stream_fd[STDIN_FILENO ][RD]).c_str(),
            fd_type(stream_fd[STDOUT_FILENO][WR]).c_str(),
            fd_type(stream_fd[STDERR_FILENO][WR]).c_str(),
            fd_type(stream_fd[STDIN_FILENO ][WR]).c_str(),
            fd_type(stream_fd[STDOUT_FILENO][RD]).c_str(),
            fd_type(stream_fd[STDERR_FILENO][RD]).c_str()
        );
        if (!op.executable().empty())
            fprintf(stderr, "  Executable: %s\r\n", op.executable().c_str());
        if (op.cmd().size() > 0) {
            int i = 0;
            if (op.shell()) {
                const char* s = getenv("SHELL");
                fprintf(stderr, "  Args[%d]: %s\r\n", i++, s ? s : "(null)");
                fprintf(stderr, "  Args[%d]: -c\r\n", i++);
            }
            typedef CmdArgsList::const_iterator const_iter;
            for(const_iter it = op.cmd().begin(), end = op.cmd().end(); it != end; ++it)
                fprintf(stderr, "  Args[%d]: %s\r\n", i++, it->c_str());
        }
    }

    pid_t pid = fork();

    if (pid < 0) {
        error = strerror(errno);
        return pid;
    } else if (pid == 0) {
        // I am the child

        // Setup stdin/stdout/stderr redirect
        for (int fd=STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
            int (&sfd)[2] = stream_fd[fd];
            int crw       = fd==STDIN_FILENO ? RD : WR;
            int prw       = fd==STDIN_FILENO ? WR : RD;

            if (sfd[prw] >= 0)
                close(sfd[prw]);            // Close parent end of child pipes

            if (sfd[crw] == REDIRECT_CLOSE)
                close(fd);
            else if (sfd[crw] >= 0) {       // Child end of the parent pipe
                dup2(sfd[crw], fd);
                // Don't close sfd[crw] here, since if the same fd is used for redirecting
                // stdout and stdin (e.g. /dev/null) if won't work correctly. Instead the loop
                // following this one will close all extra fds.

                //setlinebuf(stdout);                       // Set line buffering
            }
        }

        // See if we need to redirect STDOUT <-> STDERR
        if (stream_fd[STDOUT_FILENO][WR] == REDIRECT_STDERR)
            dup2(STDERR_FILENO, STDOUT_FILENO);
        if (stream_fd[STDERR_FILENO][WR] == REDIRECT_STDOUT)
            dup2(STDOUT_FILENO, STDERR_FILENO);

        for(int i=STDERR_FILENO+1; i < max_fds; i++)
            close(i);

        if (op.pty()) {
            struct termios ios;
            tcgetattr(STDIN_FILENO, &ios);
            // Disable the ECHO mode
            ios.c_lflag &= ~(ECHO | ECHONL | ECHOE | ECHOK);
            // We don't check if it succeeded because if the STDIN is not a terminal
            // it won't be able to disable the ECHO anyway.
            tcsetattr(STDIN_FILENO, TCSANOW, &ios);

            // Make the current process a new session leader
            setsid();

            // as a session leader, set the controlling terminal to be the 
            // slave side
            ioctl(STDIN_FILENO, TIOCSCTTY, 1);
        }

        #if !defined(__CYGWIN__) && !defined(__WIN32)
        if (op.user() != INT_MAX &&
            #ifdef HAVE_SETRESUID
                setresuid(op.user(), op.user(), op.user())
            #elif HAVE_SETREUID
                setreuid(op.user(), op.user())
            #else
                #error setresuid(3) not supported!
            #endif
        < 0) {
            err.write("Cannot set effective user to %d", op.user());
            perror(err.c_str());
            exit(EXIT_FAILURE);
        }
        #endif

        if (op.group() != INT_MAX && setpgid(0, op.group()) < 0) {
            err.write("Cannot set effective group to %d", op.group());
            perror(err.c_str());
            exit(EXIT_FAILURE);
        }

        // Build the command arguments list
        size_t sz = op.cmd().size() + 1 + (op.shell() ? 2 : 0);
        const char** argv = new const char*[sz];
        const char** p = argv;

        if (op.shell()) {
            *p++ = getenv("SHELL");
            *p++ = "-c";
        }

        for (CmdArgsList::const_iterator
                it = op.cmd().begin(), end = op.cmd().end(); it != end; ++it)
            *p++ = it->c_str();

        *p++ = (char*)NULL;

        if (op.cd() != NULL && op.cd()[0] != '\0' && chdir(op.cd()) < 0) {
            err.write("Cannot chdir to '%s'", op.cd());
            perror(err.c_str());
            exit(EXIT_FAILURE);
        }

        // Setup process environment
        if (op.init_cenv() < 0) {
            perror(err.c_str());
            exit(EXIT_FAILURE);
        }

        const char* executable = op.executable().empty()
            ? (const char*)argv[0] : op.executable().c_str();

        // Execute the process
        if (execve(executable, (char* const*)argv, op.env()) < 0) {
            err.write("Pid %d: cannot execute '%s'", getpid(), executable);
            perror(err.c_str());
            exit(EXIT_FAILURE);
        }
        // On success execve never returns
        exit(EXIT_FAILURE);
    }

    // I am the parent

    if (debug > 1)
        fprintf(stderr, "Spawned child pid %d\r\n", pid);

    // Either the parent or the child could use setpgid() to change
    // the process group ID of the child. However, because the scheduling
    // of the parent and child is indeterminate after a fork(), we can’t
    // rely on the parent changing the child’s process group ID before the
    // child does an exec(); nor can we rely on the child changing its
    // process group ID before the parent tries to send any job-control
    // signals to it (dependence on either one of these behaviors would
    // result in a race condition). Therefore, here the parent and the
    // child process both call setpgid() to change the child’s process
    // group ID to the same value immediately after a fork(), and the
    // parent ignores any occurrence of the EACCES error on the setpgid() call.

    if (op.group() != INT_MAX) {
        pid_t gid = op.group() ? op.group() : pid;
        if (setpgid(pid, gid) == -1 && errno != EACCES && debug)
            fprintf(stderr, "  Parent failed to set group of pid %d to %d: %s\r\n",
                    pid, gid, strerror(errno));
        else if (debug)
            fprintf(stderr, "  Set group of pid %d to %d\r\n", pid, gid);
    }

    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
        int  wr  = i==STDIN_FILENO ? WR : RD;
        int& cfd = op.stream_fd(i);
        int* sfd = stream_fd[i];

        int fd = sfd[i==0 ? RD : WR];
        if (fd >= 0 && fd != dev_null) {
            if (debug)
                fprintf(stderr, "  Parent closing pid %d pipe %s end (fd=%d)\r\n",
                    pid, i==STDIN_FILENO ? "reading" : "writing", fd);
            close(fd); // Close stdin/reading or stdout(err)/writing end of the child pipe
        }

        if (sfd[wr] >= 0 && sfd[wr] != dev_null) {
            cfd = sfd[wr];
            // Make sure the writing end is non-blocking
            set_nonblock_flag(pid, cfd, true);

            if (debug)
                fprintf(stderr, "  Setup %s end of pid %d %s redirection (fd=%d%s)\r\n",
                    i==STDIN_FILENO ? "writing" : "reading", pid, stream_name(i), cfd,
                    (fcntl(cfd, F_GETFL, 0) & O_NONBLOCK) == O_NONBLOCK ? " [non-block]" : "");
        }
    }

    set_nice(pid,op.nice(),error);

    return pid;
}

int stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify)
{
    bool use_kill = false;

    if (ci.sigkill)     // Kill signal already sent
        return 0;
    else if (ci.kill_cmd_pid > 0 || ci.sigterm) {
        // There was already an attempt to kill it.
        if (ci.sigterm && now.diff(ci.deadline) > 0) {
            // More than KILL_TIMEOUT_SEC secs elapsed since the last kill attempt
            erl_exec_kill(ci.kill_group ? -ci.cmd_gid : ci.cmd_pid, SIGKILL);
            if (ci.kill_cmd_pid > 0)
                erl_exec_kill(ci.kill_cmd_pid, SIGKILL);

            ci.sigkill = true;
        }
        if (notify) send_ok(transId);
        return 0;
    } else if (!ci.kill_cmd.empty()) {
        // This is the first attempt to kill this pid and kill command is provided.
        CmdArgsList kill_cmd;
        kill_cmd.push_front(ci.kill_cmd.c_str());
        CmdOptions co(kill_cmd);
        std::string err;
        ci.kill_cmd_pid = start_child(co, err);
        if (!err.empty() && debug)
            fprintf(stderr, "Error executing kill command '%s': %s\r\r",
                ci.kill_cmd.c_str(), err.c_str());

        if (ci.kill_cmd_pid > 0) {
            transient_pids[ci.kill_cmd_pid] = ci.cmd_pid;
            ci.deadline.set(now, ci.kill_timeout);
            if (notify) send_ok(transId);
            return 0;
        } else {
            if (notify) send_error_str(transId, false, "bad kill command - using SIGTERM");
            use_kill = true;
            notify = false;
        }
    } else {
        // This is the first attempt to kill this pid and no kill command is provided.
        use_kill = true;
    }

    if (use_kill) {
        // Use SIGTERM / SIGKILL to nuke the pid
        pid_t       pid  = ci.kill_group ? -ci.cmd_gid : ci.cmd_pid;
        const char* spid = ci.kill_group ? "gid" : "pid";
        int         n;
        if (!ci.sigterm && (n = kill_child(pid, SIGTERM, transId, notify)) == 0) {
            if (debug)
                fprintf(stderr, "Sent SIGTERM to %s %d (timeout=%ds)\r\n",
                        spid, abs(pid), ci.kill_timeout);
            ci.deadline.set(now, ci.kill_timeout);
        } else if (!ci.sigkill && (n = kill_child(pid, SIGKILL, 0, false)) == 0) {
            if (debug)
                fprintf(stderr, "Sent SIGKILL to %s %d\r\n", spid, abs(pid));
            ci.deadline.clear();
            ci.sigkill = true;
        } else {
            n = 0; // FIXME
            // Failed to send SIGTERM & SIGKILL to the process - give up
            ci.deadline.clear();
            ci.sigkill = true;
            if (debug)
                fprintf(stderr, "Failed to kill %s %d - leaving a zombie\r\n", spid, abs(pid));
            MapChildrenT::iterator it = children.find(ci.cmd_pid);
            if (it != children.end())
                erase_child(it);
        }
        ci.sigterm = true;
        return n;
    }
    return 0;
}

void stop_child(pid_t pid, int transId, const TimeVal& now)
{
    int n = 0;

    MapChildrenT::iterator it = children.find(pid);
    if (it == children.end()) {
        send_error_str(transId, false, "pid not alive");
        return;
    } else if ((n = erl_exec_kill(pid, 0)) < 0) {
        send_error_str(transId, false, "pid not alive (err: %d)", n);
        return;
    }
    stop_child(it->second, transId, now);
}

int send_std_error(int err, bool notify, int transId)
{
    if (err == 0) {
        if (notify) send_ok(transId);
        return 0;
    }

    switch (errno) {
        case EACCES:
            if (notify) send_error_str(transId, true, "eacces");
            break;
        case EINVAL:
            if (notify) send_error_str(transId, true, "einval");
            break;
        case ESRCH:
            if (notify) send_error_str(transId, true, "esrch");
            break;
        case EPERM:
            if (notify) send_error_str(transId, true, "eperm");
            break;
        default:
            if (notify) send_error_str(transId, false, strerror(errno));
            break;
    }
    return err;
}

int kill_child(pid_t pid, int signal, int transId, bool notify)
{
    // We can't use -pid here to kill the whole process group, because our process is
    // the group leader.
    int err = erl_exec_kill(pid, signal);
    switch (err) {
        case EINVAL:
            if (notify) send_error_str(transId, false, "Invalid signal: %d", signal);
            break;
        default:
            send_std_error(err, notify, transId);
            break;
    }
    return err;
}

bool process_pid_input(CmdInfo& ci)
{
    int& fd = ci.stream_fd[STDIN_FILENO];

    if (fd < 0) return true;

    while (!ci.stdin_queue.empty()) {
        std::string& s = ci.stdin_queue.back();

        const void* p = s.c_str() + ci.stdin_wr_pos;
        int n, len = s.size() - ci.stdin_wr_pos;

        while ((n = write(fd, p, len)) < 0 && errno == EINTR);

        if (debug) {
            if (n < 0)
                fprintf(stderr, "Error writing %d bytes to stdin (fd=%d) of pid %d: %s\r\n",
                    len, fd, ci.cmd_pid, strerror(errno));
            else
                fprintf(stderr, "Wrote %d/%d bytes to stdin (fd=%d) of pid %d\r\n",
                    n, len, fd, ci.cmd_pid);
        }

        if (n > 0 && n < len) {
            ci.stdin_wr_pos += n;
            return false;
        } else if (n < 0 && errno == EAGAIN) {
            break;
        } else if (n <= 0) {
            if (debug)
                fprintf(stderr, "Eof writing pid %d's stdin, closing fd=%d: %s\r\n",
                    ci.cmd_pid, fd, strerror(errno));
            ci.stdin_wr_pos = 0;
            close(fd);
            fd = REDIRECT_CLOSE;
            ci.stdin_queue.clear();
            return true;
        }

        ci.stdin_queue.pop_back();
        ci.stdin_wr_pos = 0;
    }

    return true;
}

void process_pid_output(CmdInfo& ci, int maxsize)
{
    char buf[4096];
    bool dead = false;

    for (int i=STDOUT_FILENO; i <= STDERR_FILENO; i++) {
        int& fd = ci.stream_fd[i];

        if (fd >= 0) {
            for(int got = 0, n = sizeof(buf); got < maxsize && n == sizeof(buf); got += n) {
                while ((n = read(fd, buf, sizeof(buf))) < 0 && errno == EINTR);
                if (debug > 1)
                    fprintf(stderr, "Read %d bytes from pid %d's %s (fd=%d): %s\r\n",
                        n, ci.cmd_pid, stream_name(i), fd, n > 0 ? "ok" : strerror(errno));
                if (n > 0) {
                    send_ospid_output(ci.cmd_pid, stream_name(i), buf, n);
                    if (n < (int)sizeof(buf))
                        break;
                } else if (n < 0 && errno == EAGAIN)
                    break;
                else if (n <= 0) {
                    if (debug)
                        fprintf(stderr, "Eof reading pid %d's %s, closing fd=%d: %s\r\n",
                            ci.cmd_pid, stream_name(i), fd, strerror(errno));
                    close(fd);
                    fd = REDIRECT_CLOSE;
                    dead = true;
                    break;
                }
            }
        }
    }

    if (dead)
        check_child(ci.cmd_pid);
}

void erase_child(MapChildrenT::iterator& it)
{
    for (int i=STDIN_FILENO; i<=STDERR_FILENO; i++)
        if (it->second.stream_fd[i] >= 0) {
            if (debug)
                fprintf(stderr, "Closing pid %d's %s\r\n", it->first, stream_name(i));
            close(it->second.stream_fd[i]);
        }

    children.erase(it);
}

int check_children(const TimeVal& now, int& isTerminated, bool notify)
{
    if (debug > 2)
        fprintf(stderr, "Checking %ld running children (exited count=%ld)\r\n",
            children.size(), exited_children.size());

    for (MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it) {
        int   status = ECHILD;
        pid_t pid = it->first;
        int n = erl_exec_kill(pid, 0);

        if (n == 0) { // process is alive
            /* If a deadline has been set, and we're over it, wack it. */
            if (!it->second.deadline.zero() && it->second.deadline.diff(now) <= 0) {
                stop_child(it->second, 0, now, false);
                it->second.deadline.clear();
            }

            while ((n = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

            if (n > 0) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    add_exited_child(pid <= 0 ? n : pid, status);
                } else if (WIFSTOPPED(status)) {
                    if (debug)
                        fprintf(stderr, "Pid %d %swas stopped by delivery of a signal %d\r\n",
                            pid, it->second.managed ? "(managed) " : "", WSTOPSIG(status));
                } else if (WIFCONTINUED(status)) {
                    if (debug)
                        fprintf(stderr, "Pid %d %swas resumed by delivery of SIGCONT\r\n",
                            pid, it->second.managed ? "(managed) " : "");
                }
            }
        } else if (n < 0 && errno == ESRCH) {
            add_exited_child(pid, -1);
        }
    }

    if (debug > 2)
        fprintf(stderr, "Checking %ld exited children (notify=%d)\r\n",
            exited_children.size(), notify);

    // For each process info in the <exited_children> queue deliver it to the Erlang VM
    // and remove it from the managed <children> map.
    for (ExitedChildrenT::iterator it=exited_children.begin(); !isTerminated && it!=exited_children.end();)
    {
        MapChildrenT::iterator i = children.find(it->first);
        MapKillPidT::iterator j;

        if (i != children.end()) {
            process_pid_output(i->second, INT_MAX);
            // Override status code if termination was requested by Erlang
            PidStatusT ps(it->first,
                i->second.sigterm
                ? 0 // Override status code if termination was requested by Erlang
                : i->second.success_code && !it->second
                    ? i->second.success_code // Override success status code
                    : it->second);
            // The process exited and it requires to kill all other processes in the group
            if (i->second.kill_group && i->second.cmd_gid != INT_MAX && i->second.cmd_gid)
                erl_exec_kill(-(i->second.cmd_gid), SIGTERM); // Kill all children in this group

            if (notify && send_pid_status_term(ps) < 0) {
                isTerminated = 1;
                return -1;
            }
            erase_child(i);
        } else if ((j = transient_pids.find(it->first)) != transient_pids.end()) {
            // the pid is one of the custom 'kill' commands started by us.
            transient_pids.erase(j);
        }

        exited_children.erase(it++);
    }

    return 0;
}

int send_pid_list(int transId, const MapChildrenT& children)
{
    // Reply: {TransId, [OsPid::integer()]}
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(transId);
    eis.encodeListSize(children.size());
    for(MapChildrenT::const_iterator it=children.begin(), end=children.end(); it != end; ++it)
        eis.encode(it->first);
    eis.encodeListEnd();
    return eis.write();
}

int send_error_str(int transId, bool asAtom, const char* fmt, ...)
{
    char str[MAXATOMLEN];
    va_list vargs;
    va_start (vargs, fmt);
    vsnprintf(str, sizeof(str), fmt, vargs);
    va_end   (vargs);

    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(transId);
    eis.encodeTupleSize(2);
    eis.encode(atom_t("error"));
    (asAtom) ? eis.encode(atom_t(str)) : eis.encode(str);
    return eis.write();
}

int send_ok(int transId, pid_t pid)
{
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(transId);
    if (pid < 0)
        eis.encode(atom_t("ok"));
    else {
        eis.encodeTupleSize(2);
        eis.encode(atom_t("ok"));
        eis.encode(pid);
    }
    return eis.write();
}

int send_pid_status_term(const PidStatusT& stat)
{
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(0);
    eis.encodeTupleSize(3);
    eis.encode(atom_t("exit_status"));
    eis.encode(stat.first);
    eis.encode(stat.second);
    return eis.write();
}

int send_ospid_output(int pid, const char* type, const char* data, int len)
{
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(0);
    eis.encodeTupleSize(3);
    eis.encode(atom_t(type));
    eis.encode(pid);
    eis.encode(data, len);
    return eis.write();
}

int open_file(const char* file, bool append, const char* stream,
              ei::StringBuffer<128>& err, int mode)
{
    int flags = O_RDWR | O_CREAT | (append ? O_APPEND : O_TRUNC);
    int fd    = open(file, flags, mode);
    if (fd < 0) {
        err.write("Failed to redirect %s to file: %s", stream, strerror(errno));
        return -1;
    }
    if (debug)
        fprintf(stderr, "  Redirecting [%s -> {file:%s, fd:%d}]\r\n",
            stream, file, fd);

    return fd;
}

int open_pipe(int fds[2], const char* stream, ei::StringBuffer<128>& err)
{
    if (pipe(fds) < 0) {
        err.write("Failed to create a pipe for %s: %s", stream, strerror(errno));
        return -1;
    }
    if (fds[1] > max_fds) {
        close(fds[0]);
        close(fds[1]);
        err.write("Exceeded number of available file descriptors (fd=%d)", fds[1]);
        return -1;
    }
    if (debug)
        fprintf(stderr, "  Redirecting [%s -> pipe:{r=%d,w=%d}]\r\n", stream, fds[0], fds[1]);

    return 0;
}

/* This exists just to make sure that we don't inadvertently do a
 * kill(-1, SIGKILL), which will cause all kinds of bad things to
 * happen. */

int erl_exec_kill(pid_t pid, int signal) {
    if (pid == -1 || pid == 0) {
        if (debug)
            fprintf(stderr, "kill(%d, %d) attempt prohibited!\r\n", pid, signal);
        return -1;
    }

    int r = kill(pid, signal);

    if (debug && signal > 0)
        fprintf(stderr, "Called kill(pid=%d, sig=%d) -> %d\r\n", pid, signal, r);

    return r;
}

int set_nonblock_flag(pid_t pid, int fd, bool value)
{
    int oldflags = fcntl(fd, F_GETFL, 0);
    if (oldflags < 0)
        return oldflags;
    if (value != 0)
        oldflags |= O_NONBLOCK;
    else
        oldflags &= ~O_NONBLOCK;

    int ret = fcntl(fd, F_SETFL, oldflags);
    if (debug > 3) {
        oldflags = fcntl(fd, F_GETFL, 0);
        fprintf(stderr, "  Set pid %d's fd=%d to non-blocking mode (flags=%x)\r\n",
            pid, fd, oldflags);
    }

    return ret;
}

int CmdOptions::ei_decode(ei::Serializer& ei, bool getCmd)
{
    // {Cmd::string(), [Option]}
    //      Option = {env, Strings} | {cd, Dir} | {kill, Cmd}
    int sz;
    std::string op, val;

    m_err.str("");
    m_cmd.clear();
    m_kill_cmd.clear();
    m_env.clear();

    m_nice = INT_MAX;

    if (getCmd) {
        std::string s;

        if (eis.decodeString(s) != -1) {
            m_cmd.push_front(s);
            m_shell=true;
        } else if ((sz = eis.decodeListSize()) > 0) {
            for (int i=0; i < sz; i++) {
                if (eis.decodeString(s) < 0) {
                    m_err << "badarg: invalid command argument #" << i;
                    return -1;
                }
                m_cmd.push_back(s);
            }
            eis.decodeListEnd();
            m_shell = false;
        } else {
            m_err << "badarg: cmd string or non-empty list is expected";
            return -1;
        }
    }

    if ((sz = eis.decodeListSize()) < 0) {
        m_err << "option list expected";
        return -1;
    }

    // Note: The STDIN, STDOUT, STDERR enums must occupy positions 0, 1, 2!!!
    enum OptionT {
        STDIN,      STDOUT,            STDERR,
        PTY,        SUCCESS_EXIT_CODE, CD,     ENV,
        EXECUTABLE, KILL,              KILL_TIMEOUT,
        KILL_GROUP, NICE,              USER,    GROUP
    } opt;
    const char* opts[] = {
        "stdin",      "stdout",            "stderr",
        "pty",        "success_exit_code", "cd", "env",
        "executable", "kill",              "kill_timeout",
        "kill_group", "nice",              "user",  "group"
    };

    bool seen_opt[sizeof(opts) / sizeof(char*)] = {false};

    for(int i=0; i < sz; i++) {
        int arity, type = eis.decodeType(arity);

        if (type == etAtom && (int)(opt = (OptionT)eis.decodeAtomIndex(opts, op)) >= 0)
            arity = 1;
        else if (type != etTuple || ((arity = eis.decodeTupleSize()) != 2 && arity != 3)) {
            m_err << "badarg: option must be {Cmd, Opt} or {Cmd, Opt, Args} or atom "
                     "(got tp=" << (char)type << ", arity=" << arity << ')';
            return -1;
        } else if ((int)(opt = (OptionT)eis.decodeAtomIndex(opts, op)) < 0) {
            m_err << "badarg: invalid cmd option tuple";
            return -1;
        }

        if (seen_opt[opt]) {
            m_err << "duplicate " << op << " option specified";
            return -1;
        }
        seen_opt[opt] = true;

        switch (opt) {
            case EXECUTABLE:
                if (eis.decodeString(m_executable) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case CD:
                // {cd, Dir::string()}
                if (eis.decodeString(m_cd) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case KILL:
                // {kill, Cmd::string()}
                if (eis.decodeString(m_kill_cmd) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case GROUP: {
                // {group, integer() | string()}
                type = eis.decodeType(arity);
                if (type == etString) {
                    if (eis.decodeString(val) < 0) {
                        m_err << op << " - bad group value"; return -1;
                    }
                    struct group g;
                    char buf[1024];
                    struct group* res;
                    if (getgrnam_r(val.c_str(), &g, buf, sizeof(buf), &res) < 0) {
                        m_err << op << " - invalid group name: " << val;
                        return -1;
                    }
                    m_group = g.gr_gid;
                } else if (eis.decodeInt(m_group) < 0) {
                    m_err << op << " - bad group value type (expected int or string)";
                    return -1;
                }
                break;
            }
            case USER:
                // {user, Dir::string()} | {kill, Cmd::string()}
                if (eis.decodeString(val) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                if      (opt == CD)     m_cd        = val;
                else if (opt == KILL)   m_kill_cmd  = val;
                else if (opt == USER) {
                    struct passwd *pw = getpwnam(val.c_str());
                    if (pw == NULL) {
                        m_err << "Invalid user " << val << ": " << ::strerror(errno);
                        return -1;
                    }
                    m_user = pw->pw_uid;
                }
                break;

            case KILL_TIMEOUT:
                // {kill_timeout, Timeout::int()}
                if (eis.decodeInt(m_kill_timeout) < 0) {
                    m_err << op << " - invalid value";
                    return -1;
                }
                break;

            case KILL_GROUP:
                m_kill_group = true;
                break;

            case NICE:
                // {nice, Level::int()}
                if (eis.decodeInt(m_nice) < 0 || m_nice < -20 || m_nice > 20) {
                    m_err << "nice option must be an integer between -20 and 20";
                    return -1;
                }
                break;

            case ENV: {
                // {env, [NameEqualsValue::string()]}
                // passed in env variables are appended to the existing ones
                // obtained from environ global var
                int opt_env_sz = eis.decodeListSize();
                if (opt_env_sz < 0) {
                    m_err << op << " - list expected";
                    return -1;
                }

                for (int i=0; i < opt_env_sz; i++) {
                    int sz, type = eis.decodeType(sz);
                    bool res = false;
                    std::string s, key;

                    if (type == ERL_STRING_EXT) {
                        res = !eis.decodeString(s);
                        if (res) {
                            size_t pos = s.find_first_of('=');
                            if (pos == std::string::npos)
                                res = false;
                            else
                                key = s.substr(0, pos);
                        }
                    } else if (type == ERL_SMALL_TUPLE_EXT && sz == 2) {
                        eis.decodeTupleSize();
                        std::string s2;
                        if (eis.decodeString(key) == 0 && eis.decodeString(s2) == 0) {
                            res = true;
                            s = key + "=" + s2;
                        }
                    }

                    if (!res) {
                        m_err << op << " - invalid argument #" << i;
                        return -1;
                    }
                    m_env[key] = s;
                }
                eis.decodeListEnd();
                break;
            }

            case PTY:
                m_pty = true;
                break;

            case SUCCESS_EXIT_CODE:
                if (eis.decodeInt(m_success_exit_code) < 0 ||
                    m_success_exit_code < 0 ||
                    m_success_exit_code > 255)
                {
                    m_err << "success exit code must be an integer between 0 and 255";
                    return -1;
                }
                break;

            case STDIN:
            case STDOUT:
            case STDERR: {
                int& fdr = stream_fd(opt);

                if (arity == 1)
                    stream_redirect(opt, REDIRECT_ERL);
                else if (arity == 2) {
                    int type = 0, sz;
                    std::string s, fop;
                    type = eis.decodeType(sz);

                    if (type == ERL_ATOM_EXT)
                        eis.decodeAtom(s);
                    else if (type == ERL_STRING_EXT)
                        eis.decodeString(s);
                    else {
                        m_err << op << " - atom or string value in tuple required";
                        return -1;
                    }

                    if (s == "null") {
                        stream_null(opt);
                        fdr = REDIRECT_NULL;
                    } else if (s == "close") {
                        stream_redirect(opt, REDIRECT_CLOSE);
                    } else if (s == "stderr" && opt == STDOUT)
                        stream_redirect(opt, REDIRECT_STDERR);
                    else if (s == "stdout" && opt == STDERR)
                        stream_redirect(opt, REDIRECT_STDOUT);
                    else if (!s.empty()) {
                        stream_file(opt, s);
                    }
                } else if (arity == 3) {
                    int n, sz, mode = DEF_MODE;
                    bool append = false;
                    std::string s, a, fop;
                    if (eis.decodeString(s) < 0) {
                        m_err << "filename must be a string for option " << op;
                        return -1;
                    }
                    if ((n = eis.decodeListSize()) < 0) {
                        m_err << "option " << op << " requires a list of file options" << op;
                        return -1;
                    }
                    for(int i=0; i < n; i++) {
                        int tp = eis.decodeType(sz);
                        if (eis.decodeAtom(a) >= 0) {
                            if (a == "append")
                                append = true;
                            else {
                                m_err << "option " << op << ": unsupported file option '" << a << "'";
                                return -1;
                            }
                        }
                        else if (tp != etTuple || eis.decodeTupleSize() != 2 ||
                                 eis.decodeAtom(a) < 0 || a != "mode" || eis.decodeInt(mode) < 0) {
                            m_err << "option " << op << ": unsupported file option '" << a << "'";
                            return -1;

                        }
                    }
                    eis.decodeListEnd();

                    stream_file(opt, s, append, mode);
                }

                if (opt == STDIN &&
                    !(fdr == REDIRECT_NONE  || fdr == REDIRECT_ERL ||
                      fdr == REDIRECT_CLOSE || fdr == REDIRECT_NULL || fdr == REDIRECT_FILE)) {
                    m_err << "invalid " << op << " redirection option: '" << op << "'";
                    return -1;
                }
                break;
            }
            default:
                m_err << "bad option: " << op; return -1;
        }
    }

    eis.decodeListEnd();

    for (int i=STDOUT_FILENO; i <= STDERR_FILENO; i++)
        if (stream_fd(i) == (i == STDOUT_FILENO ? REDIRECT_STDOUT : REDIRECT_STDERR)) {
            m_err << "self-reference of " << stream_fd_type(i);
            return -1;
        }

    if (stream_fd(STDOUT_FILENO) == REDIRECT_STDERR &&
        stream_fd(STDERR_FILENO) == REDIRECT_STDOUT)
    {
        m_err << "circular reference of stdout and stderr";
        return -1;
    }

    //if (cmd_is_list && m_shell)
    //    m_shell = false;

    if (debug > 1) {
        fprintf(stderr, "Parsed cmd '%s' options\r\n  (stdin=%s, stdout=%s, stderr=%s)\r\n",
            m_cmd.front().c_str(),
            stream_fd_type(0).c_str(), stream_fd_type(1).c_str(), stream_fd_type(2).c_str());
    }

    return 0;
}

int CmdOptions::init_cenv()
{
    if (m_env.empty()) {
        m_cenv = (const char**)environ;
        return 0;
    }

    // Copy environment of the caller process
    for (char **env_ptr = environ; *env_ptr; env_ptr++) {
        std::string s(*env_ptr), key(s.substr(0, s.find_first_of('=')));
        MapEnvIterator it = m_env.find(key);
        if (it == m_env.end())
            m_env[key] = s;
    }

    if ((m_cenv = (const char**) new char* [m_env.size()+1]) == NULL) {
        m_err << "Cannot allocate memory for " << m_env.size()+1 << " environment entries";
        return -1;
    }

    int i = 0;
    for (MapEnvIterator it = m_env.begin(), end = m_env.end(); it != end; ++it, ++i)
        m_cenv[i] = it->second.c_str();
    m_cenv[i] = NULL;

    return 0;
}
