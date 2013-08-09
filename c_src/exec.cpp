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
                  {shell, Cmd::string(), Options}   |
                  {list}                            |
                  {stop, OsPid::integer()}          |
                  {kill, OsPid::integer(), Signal::integer()} |
                  {stdin, OsPid::integer(), Data::binary()}

    Options = [Option]
    Option  = {cd, Dir::string()} |
              {env, [string() | {string(), string()}]} |
              {kill, Cmd::string()} |
              {kill_timeout, Sec::integer()} |
              {group, integer() | string()} |
              {user, User::string()} |
              {nice, Priority::integer()} |
              stdin  | {stdin, true | close | File::string()} |
              stdout | {stdout, Device::string()} |
              stderr | {stderr, Device::string()} |

    Device  = close | true | null | stderr | stdout | File::string() | {append, File::string()}

    Reply = ok                      |       // For kill/stop commands
            {ok, OsPid}             |       // For run/shell command
            {ok, [OsPid]}           |       // For list command
            {error, Reason}         |
            {exit_status, OsPid, Status}    // OsPid terminated with Status

    Reason = atom() | string()
    OsPid  = integer()
    Status = integer()
*/

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <signal.h>

#ifdef HAVE_CAP
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <setjmp.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <map>
#include <list>
#include <deque>
#include <sstream>

#include <ei.h>
#include "ei++.h"

#if defined(__CYGWIN__) || defined(__WIN32)
#  define sigtimedwait(a, b, c) 0
#endif

using namespace ei;

//-------------------------------------------------------------------------
// Defines
//-------------------------------------------------------------------------

#define BUF_SIZE 2048

/* In the event we have tried to kill something, wait this many
 * seconds and then *really* kill it with SIGKILL if needs be.  */
#define KILL_TIMEOUT_SEC 5

//-------------------------------------------------------------------------
// Types
//-------------------------------------------------------------------------

class CmdInfo;

typedef unsigned char byte;
typedef int   exit_status_t;
typedef pid_t kill_cmd_pid_t;
typedef std::pair<pid_t, exit_status_t>     PidStatusT;
typedef std::pair<pid_t, CmdInfo>           PidInfoT;
typedef std::map <pid_t, CmdInfo>           MapChildrenT;
typedef std::pair<kill_cmd_pid_t, pid_t>    KillPidStatusT;
typedef std::map <kill_cmd_pid_t, pid_t>    MapKillPidT;

enum RedirectType {
    REDIRECT_NONE = -1,     // No output redirection
    REDIRECT_NULL = -2,     // Redirect output to /dev/null
    REDIRECT_CLOSE= -3,     // Close output file descriptor
    REDIRECT_ERL  = -4,     // Redirect output back to Erlang
    REDIRECT_FILE = -5      // Redirect output to file
};

class CmdOptions {
    ei::StringBuffer<256>   m_tmp;
    std::stringstream       m_err;
    std::string             m_cmd;
    std::string             m_cd;
    std::string             m_stdin;
    std::string             m_stdout;
    std::string             m_stderr;
    std::string             m_kill_cmd;
    int                     m_kill_timeout;
    std::list<std::string>  m_env;
    long                    m_nice;     // niceness level
    size_t                  m_size;
    size_t                  m_count;
    int                     m_group;    // used in setgid()
    int                     m_user;     // run as
    const char**            m_cenv;
    int                     m_stdin_fd;
    int                     m_stdout_fd;
    int                     m_stderr_fd;
    bool                    m_stdout_append;
    bool                    m_stderr_append;

public:

    CmdOptions()
        : m_tmp(0, 256), m_kill_timeout(KILL_TIMEOUT_SEC)
        , m_nice(INT_MAX), m_size(0)
        , m_count(0), m_group(INT_MAX), m_user(INT_MAX), m_cenv(NULL)
        , m_stdin_fd(REDIRECT_NONE), m_stdout_fd(REDIRECT_NONE), m_stderr_fd(REDIRECT_NONE)
        , m_stdout_append(false), m_stderr_append(false)
    {}
    CmdOptions(const char* cmd, const char* cd = NULL, const char** env = NULL,
               int user = INT_MAX, int nice = INT_MAX, int group = INT_MAX)
        : m_cmd(cmd), m_cd(cd ? cd : ""), m_kill_timeout(KILL_TIMEOUT_SEC)
        , m_nice(nice), m_size(0), m_count(0)
        , m_group(group), m_user(user), m_cenv(env)
        , m_stdin_fd(REDIRECT_NONE), m_stdout_fd(REDIRECT_NONE), m_stderr_fd(REDIRECT_NONE)
        , m_stdout_append(false), m_stderr_append(false)
    {}
    ~CmdOptions() {
        delete [] m_cenv;
        m_cenv = NULL;
    }

    const char*  strerror()         const { return m_err.str().c_str(); }
    const char*  cmd()              const { return m_cmd.c_str(); }
    const char*  cd()               const { return m_cd.c_str(); }
    char* const* env()              const { return (char* const*)m_cenv; }
    const char*  kill_cmd()         const { return m_kill_cmd.c_str(); }
    int          kill_timeout()     const { return m_kill_timeout; }
    int          group()            const { return m_group; }
    int          user()             const { return m_user; }
    int          nice()             const { return m_nice; }
    const char*  stdin_file()       const { return m_stdin.c_str(); }
    const char*  stdout_file()      const { return m_stdout.c_str(); }
    const char*  stderr_file()      const { return m_stderr.c_str(); }
    bool         stdout_append()    const { return m_stdout_append; }
    bool         stderr_append()    const { return m_stderr_append; }
    int          stdin_fd()         const { return m_stdin_fd;  }
    int          stdout_fd()        const { return m_stdout_fd; }
    int          stderr_fd()        const { return m_stderr_fd; }

    void stdin_fd(int fd)  { m_stdin_fd  = fd; }
    void stdout_fd(int fd) { m_stdout_fd = fd; }
    void stderr_fd(int fd) { m_stderr_fd = fd; }

    void stdin_file(const std::string& file) {
        m_stdout_fd = REDIRECT_FILE; m_stdin = file;
    }

    void stdout_file(const std::string& file, bool append) {
        m_stdout_fd = REDIRECT_FILE; m_stdout = file; m_stdout_append = append;
    }

    void stderr_file(const std::string& file, bool append) {
        m_stderr_fd = REDIRECT_FILE; m_stderr = file; m_stderr_append = append;
    }

    void output_file(bool is_stdout, const std::string& file, bool append) {
        if (is_stdout)  stdout_file(file, append);
        else            stderr_file(file, append);
    }

    int ei_decode(ei::Serializer& ei, bool getCmd = false);
};

/// Contains run-time info of a child OS process.
/// When a user provides a custom command to kill a process this
/// structure will contain its run-time information.
struct CmdInfo {
    std::string     cmd;            // Executed command
    pid_t           cmd_pid;        // Pid of the custom kill command
    std::string     kill_cmd;       // Kill command to use (if provided - otherwise use SIGTERM)
    kill_cmd_pid_t  kill_cmd_pid;   // Pid of the command that <pid> is supposed to kill
    ei::TimeVal     deadline;       // Time when the <cmd_pid> is supposed to be killed using SIGTERM.
    bool            sigterm;        // <true> if sigterm was issued.
    bool            sigkill;        // <true> if sigkill was issued.
    int             kill_timeout;   // Pid shutdown interval in msec before it's killed with SIGKILL
    bool            managed;        // <true> if this pid is started externally, but managed by erlexec
    int             stdin_fd;       // Pipe fd getting   process's stdin
    int             stdout_fd;      // Pipe fd receiving process's stdout
    int             stderr_fd;      // Pipe fd receiving process's stderr
    int             stdin_wr_pos;   // Offset of the unwritten portion of the head item of stdin_queue 
    std::list<std::string> stdin_queue;

    CmdInfo() {
        new (this) CmdInfo("", "", 0);
    }
    CmdInfo(const CmdInfo& ci) {
        new (this) CmdInfo(ci.cmd.c_str(), ci.kill_cmd.c_str(), ci.cmd_pid, ci.managed,
                           ci.stdout_fd, ci.stderr_fd);
    }
    CmdInfo(const char* _cmd, const char* _kill_cmd, pid_t _cmd_pid, bool _managed = false,
            int _stdin_fd = REDIRECT_NONE, int _stdout_fd = REDIRECT_NONE, int _stderr_fd = REDIRECT_NONE,
            int _kill_timeout = KILL_TIMEOUT_SEC)
        : cmd(_cmd), cmd_pid(_cmd_pid), kill_cmd(_kill_cmd), kill_cmd_pid(-1)
        , sigterm(false), sigkill(false)
        , kill_timeout(_kill_timeout), managed(_managed)
        , stdin_fd(_stdin_fd), stdout_fd(_stdout_fd), stderr_fd(_stderr_fd)
        , stdin_wr_pos(0)
    {}
};

//-------------------------------------------------------------------------
// External definitions
//-------------------------------------------------------------------------
extern char **environ; // getting the whole environment

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------

ei::Serializer eis(/* packet header size */ 2);

sigjmp_buf  jbuf;
int alarm_max_time     = 12;
static int  debug      = 0;
static bool oktojump   = false;
static int  terminated = 0;         // indicates that we got a SIGINT / SIGTERM event
static bool superuser  = false;
static bool pipe_valid = true;

MapChildrenT children;              // Map containing all managed processes started by this port program.
MapKillPidT  transient_pids;        // Map of pids of custom kill commands.

#define SIGCHLD_MAX_SIZE 4096
std::list< PidStatusT > exited_children;  // deque of processed SIGCHLD events

//-------------------------------------------------------------------------
// Local Functions
//-------------------------------------------------------------------------

int   send_ok(int transId, pid_t pid = -1);
int   send_pid_status_term(const PidStatusT& stat);
int   send_error_str(int transId, bool asAtom, const char* fmt, ...);
int   send_pid_list(int transId, const MapChildrenT& children);
int   send_ospid_output(int pid, const char* type, const char* data, int len);

pid_t start_child(CmdOptions& op, std::string& err);
int   kill_child(pid_t pid, int sig, int transId, bool notify=true);
int   check_children(int& isTerminated, bool notify = true);
bool  process_pid_input(MapChildrenT::iterator& it);
void  process_pid_output(MapChildrenT::iterator& it, int maxsize = 4096);
void  stop_child(pid_t pid, int transId, const TimeVal& now);
int   stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify = true);

int set_nonblock_flag(pid_t pid, int fd, bool value);
int erl_exec_kill(pid_t pid, int signal);

int process_child_signal(pid_t pid)
{
    int status;
    pid_t ret;

    while ((ret = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

    if (ret < 0 && errno == ECHILD) {
        int status = ECHILD;
        if (erl_exec_kill(pid, 0) == 0) // process likely forked and is alive
            status = 0;
        if (status != 0)
            exited_children.push_back(std::make_pair(pid <= 0 ? ret : pid, status));
    } else if (pid <= 0)
        exited_children.push_back(std::make_pair(ret, status));
    else if (ret == pid)
        exited_children.push_back(std::make_pair(pid, status));
    else
        return -1;
    return 1;
}

void gotsignal(int signal)
{
    if (signal == SIGTERM || signal == SIGINT || signal == SIGPIPE)
        terminated = 1;
    if (signal == SIGPIPE)
        pipe_valid = false;
    if (debug)
        fprintf(stderr, "Got signal: %d\r\n", signal);
    if (oktojump) siglongjmp(jbuf, 1);
}

void gotsigchild(int signal, siginfo_t* si, void* context)
{
    // If someone used kill() to send SIGCHLD ignore the event
    if (si->si_code == SI_USER || signal != SIGCHLD)
        return;

    if (debug)
        fprintf(stderr, "Process %d exited (sig=%d, oktojump=%d)\r\n", si->si_pid, signal, oktojump);

    process_child_signal(si->si_pid);

    if (oktojump) siglongjmp(jbuf, 1);
}

void check_pending()
{
    static const struct timespec timeout = {0, 0};

    sigset_t  set;
    siginfo_t info;
    int sig;
    sigemptyset(&set);
    if (sigpending(&set) == 0) {
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

void usage(char* progname) {
    fprintf(stderr,
        "Usage:\n"
        "   %s [-n] [-alarm N] [-debug] [-user User]\n"
        "Options:\n"
        "   -n              - Use marshaling file descriptors 3&4 instead of default 0&1.\n"
        "   -alarm N        - Allow up to <N> seconds to live after receiving SIGTERM/SIGINT (default %d)\n"
        "   -debug          - Turn on debug mode\n"
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

    sterm.sa_handler = gotsignal;
    sigemptyset(&sterm.sa_mask);
    sigaddset(&sterm.sa_mask, SIGCHLD);
    sterm.sa_flags = 0;
    sigaction(SIGINT,  &sterm, NULL);
    sigaction(SIGTERM, &sterm, NULL);
    sigaction(SIGHUP,  &sterm, NULL);
    sigaction(SIGPIPE, &sterm, NULL);

    sact.sa_handler = NULL;
    sact.sa_sigaction = gotsigchild;
    sigemptyset(&sact.sa_mask);
    sact.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP | SA_NODEFER;
    sigaction(SIGCHLD, &sact, NULL);

    if (argc > 1) {
        int res;
        for(res = 1; res < argc; res++) {
            if (strcmp(argv[res], "-h") == 0 || strcmp(argv[res], "--help") == 0) {
                usage(argv[0]);
            } else if (strcmp(argv[res], "-debug") == 0) {
                debug = (res+1 < argc && argv[res+1][0] != '-') ? atoi(argv[++res]) : 1;
                if (debug > 2)
                    eis.debug(true);
            } else if (strcmp(argv[res], "-alarm") == 0 && res+1 < argc) {
                if (argv[res+1][0] != '-')
                    alarm_max_time = atoi(argv[++res]);
                else
                    usage(argv[0]);
            } else if (strcmp(argv[res], "-n") == 0) {
                eis.set_handles(3, 4);
            } else if (strcmp(argv[res], "-user") == 0 && res+1 < argc && argv[res+1][0] != '-') {
                char* run_as_user = argv[++res];
                struct passwd *pw = NULL;
                if ((pw = getpwnam(run_as_user)) == NULL) {
                    fprintf(stderr, "User %s not found!\r\n", run_as_user);
                    exit(3);
                }
                userid = pw->pw_uid;
            }
        }
    }

    // If we are root, switch to non-root user and set capabilities
    // to be able to adjust niceness and run commands as other users.
    if (getuid() == 0) {
        superuser = true;
        if (userid == 0) {
            fprintf(stderr, "When running as root, \"-user User\" option must be provided!\r\n");
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
            fprintf(stderr, "Failed to set effective userid to a non-root user %s (uid=%d)\r\n",
                pw ? pw->pw_name : "", geteuid());
            exit(7);
        }

        #ifdef HAVE_CAP
        cap_t cur;
        if ((cur = cap_from_text("cap_setuid=eip cap_kill=eip cap_sys_nice=eip")) == 0) {
            perror("Failed to convert cap_setuid & cap_sys_nice from text");
            exit(8);
        }
        if (cap_set_proc(cur) < 0) {
            perror("Failed to set cap_setuid & cap_sys_nice");
            exit(9);
        }
        cap_free(cur);

        if (debug && (cur = cap_get_proc()) != NULL) {
            fprintf(stderr, "exec: current capabilities: %s\r\n",  cap_to_text(cur, NULL));
            cap_free(cur);
        }
        #else
        if (debug)
            fprintf(stderr, "capability feature is not implemented for this plaform!\r\n");
        //exit(10);
        #endif
    }

    const int MAX_FD = eis.read_handle() + 1;

    while (!terminated) {

        FD_ZERO (&writefds);
        FD_ZERO (&readfds);

        FD_SET (eis.read_handle(), &readfds);

        int maxfd = MAX_FD;

        // Set up all stdout/stderr input streams that we need to monitor and redirect to Erlang
        for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it) {
            if (it->second.stdin_fd >= 0 && it->second.stdin_wr_pos > 0) {
                if (debug)
                    fprintf(stderr, "Pid %d adding stdin available notification\r\n", it->first);
                FD_SET(it->second.stdin_fd, &writefds);
                if (it->second.stdin_fd > maxfd) maxfd = it->second.stdin_fd;
            }
            if (it->second.stdout_fd >= 0) {
                if (debug)
                    fprintf(stderr, "Pid %d adding stdout checking\r\n", it->first);
                FD_SET(it->second.stdout_fd, &readfds);
                if (it->second.stdout_fd > maxfd) maxfd = it->second.stdout_fd;
            }
            if (it->second.stderr_fd >= 0) {
                if (debug)
                    fprintf(stderr, "Pid %d adding stderr checking\r\n", it->first);
                FD_SET(it->second.stderr_fd, &readfds);
                if (it->second.stderr_fd > maxfd) maxfd = it->second.stderr_fd;
            }
        }

        sigsetjmp(jbuf, 1); oktojump = 0;

        if (debug > 1)
            fprintf(stderr, "Checking %ld exited children\r\n", exited_children.size());

        while (!terminated && !exited_children.empty())
            check_children(terminated);

        check_pending(); // Check for pending signals arrived while we were in the signal handler

        if (terminated) break;

        oktojump = 1;
        ei::TimeVal timeout(KILL_TIMEOUT_SEC, 0);
        int cnt = select (maxfd, &readfds, &writefds, (fd_set *) 0, &timeout.timeval());
        int interrupted = (cnt < 0 && errno == EINTR);
        oktojump = 0;

        if (debug > 1)
            fprintf(stderr, "Select got %d events\r\n", cnt);

        if (interrupted || cnt == 0) {
            if (check_children(terminated) < 0)
                break;
        } else if (cnt < 0) {
            perror("select");
            exit(9);
        } else if ( FD_ISSET (eis.read_handle(), &readfds) ) {
            /* Read from fin a command sent by Erlang */
            int  err, arity;
            long transId;
            std::string command;

            // Note that if we were using non-blocking reads, we'd also need to check
            // for errno EWOULDBLOCK.
            if ((err = eis.read()) < 0) {
                terminated = 90-err;
                break;
            }

            /* Our marshalling spec is that we are expecting a tuple
             * TransId, {Cmd::atom(), Arg1, Arg2, ...}} */
            if (eis.decodeTupleSize() != 2 ||
                (eis.decodeInt(transId)) < 0 ||
                (arity = eis.decodeTupleSize()) < 1)
            {
                terminated = 10; break;
            }


            enum CmdTypeT        {  MANAGE,  RUN,  SHELL,  STOP,  KILL,  LIST,  SHUTDOWN,  STDIN  } cmd;
            const char* cmds[] = { "manage","run","shell","stop","kill","list","shutdown","stdin" };

            /* Determine the command */
            if ((int)(cmd = (CmdTypeT) eis.decodeAtomIndex(cmds, command)) < 0) {
                if (send_error_str(transId, false, "Unknown command: %s", command.c_str()) < 0) {
                    terminated = 11; break;
                } else
                    continue;
            }

            switch (cmd) {
                case SHUTDOWN: {
                    terminated = 126;
                    break;
                }
                case MANAGE: {
                    // {manage, Cmd::string(), Options::list()}
                    CmdOptions po;
                    long pid;
                    pid_t realpid;

                    if (arity != 3 || (eis.decodeInt(pid)) < 0 || po.ei_decode(eis) < 0) {
                        send_error_str(transId, true, "badarg");
                        continue;
                    }
                    realpid = pid;

                    CmdInfo ci("managed pid", po.kill_cmd(), realpid, true);
                    ci.kill_timeout = po.kill_timeout();
                    children[realpid] = ci;

                    send_ok(transId, pid);
                    break;
                }
                case RUN:
                case SHELL: {
                    // {shell, Cmd::string(), Options::list()}
                    CmdOptions po;

                    if (arity != 3 || po.ei_decode(eis, true) < 0) {
                        send_error_str(transId, false, po.strerror());
                        continue;
                    }

                    pid_t pid;
                    std::string err;
                    if ((pid = start_child(po, err)) < 0)
                        send_error_str(transId, false, "Couldn't start pid: %s", err.c_str());
                    else {
                        CmdInfo ci(po.cmd(), po.kill_cmd(), pid, false,
                                   po.stdin_fd(), po.stdout_fd(), po.stderr_fd(),
                                   po.kill_timeout());
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
                        continue;
                    }
                    stop_child(pid, transId, TimeVal(TimeVal::NOW));
                    break;
                }
                case KILL: {
                    // {kill, OsPid::integer(), Signal::integer()}
                    long pid, sig;
                    if (arity != 3 || eis.decodeInt(pid) < 0 || (eis.decodeInt(sig)) < 0) {
                        send_error_str(transId, true, "badarg");
                        continue;
                    } if (superuser && children.find(pid) == children.end()) {
                        send_error_str(transId, false, "Cannot kill a pid not managed by this application");
                        continue;
                    }
                    kill_child(pid, sig, transId);
                    break;
                }
                case LIST: {
                    // {list}
                    if (arity != 1) {
                        send_error_str(transId, true, "badarg");
                        continue;
                    }
                    send_pid_list(transId, children);
                    break;
                }
                case STDIN: {
                    long pid;
                    std::string data;
                    if (arity != 3 || eis.decodeInt(pid) < 0 || eis.decodeBinary(data) < 0) {
                        send_error_str(transId, true, "badarg");
                        continue;
                    }

                    MapChildrenT::iterator it = children.find(pid);
                    if (it == children.end()) {
                        if (debug)
                            fprintf(stderr, "Stdin (%ld bytes) cannot be sent to non-existing pid %ld\r\n",
                                data.size(), pid);
                        continue;
                    }
                    it->second.stdin_queue.push_front(data);
                    process_pid_input(it);
                    break;
                }
            }
        } else {
            // Check if any stdout/stderr streams have data
            for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it) {
                if (FD_ISSET(it->second.stdin_fd, &writefds))
                    process_pid_input(it);
                if (FD_ISSET(it->second.stdout_fd, &readfds) ||
                    FD_ISSET(it->second.stderr_fd, &readfds))
                    process_pid_output(it);
            }
        }
    }

    sigsetjmp(jbuf, 1); oktojump = 0;

    if (debug) fprintf(stderr, "Setting alarm to %d seconds\r\n", alarm_max_time);
    alarm(alarm_max_time);  // Die in <alarm_max_time> seconds if not done

    int old_terminated = terminated;
    terminated = 0;

    erl_exec_kill(0, SIGTERM); // Kill all children in our process group

    TimeVal now(TimeVal::NOW);
    TimeVal deadline(now, 6, 0);

    while (children.size() > 0) {
        sigsetjmp(jbuf, 1);

        if (children.size() > 0 || !exited_children.empty()) {
            int term = 0;
            check_children(term, pipe_valid);
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
            select (0, (fd_set *)0, (fd_set *)0, (fd_set *) 0, &timeout);
            oktojump = 0;
        }
    }

    if (debug)
        fprintf(stderr, "Exiting (%d)\r\n", old_terminated);

    return old_terminated;
}

int open_file(const char* file, bool append, const char* stream,
              const char* cmd, ei::StringBuffer<128>& err)
{
    int flags = O_RDWR | O_CREAT | (append ? O_APPEND : O_TRUNC);
    int fd    = open(file, flags);
    if (fd < 0) {
        err.write("Failed to redirect %s to file: %s", stream, strerror(errno));
        return -1;
    }
    if (debug)
        fprintf(stderr, "Redirecting %s of cmd '%s' to file: '%s' (fd=%d)\r\n",
            stream, cmd, file, fd);

    return fd;
}

int open_pipe(int fds[2], const char* stream, ei::StringBuffer<128>& err)
{
    if (pipe(fds) < 0) {
        err.write("Failed to create a pipe for %s: %s", stream, strerror(errno));
        return -1;
    }
    if (debug)
        fprintf(stderr, "Created %s pipe (readfd=%d, writefd=%d)\r\n", stream, fds[0], fds[1]);

    return 0;
}

pid_t start_child(CmdOptions& op, std::string& error)
{
    enum { RD = 0, WR = 1 };

    int stdin_fd [2] = { REDIRECT_NONE, REDIRECT_NONE };
    int stdout_fd[2] = { REDIRECT_NONE, REDIRECT_NONE };
    int stderr_fd[2] = { REDIRECT_NONE, REDIRECT_NONE };

    ei::StringBuffer<128> err;

    // Optionally setup stdin redirect
    switch (op.stdin_fd()) {
        case REDIRECT_CLOSE:
            stdin_fd[WR] = op.stdin_fd();
            break;
        case REDIRECT_ERL:
            if (open_pipe(stdin_fd, "stdin", err) < 0) {
                error = err.c_str();
                return -1;
            }
            break;
        case REDIRECT_FILE: {
            stdin_fd[RD] = open_file(op.stdin_file(), false, "stdin", op.cmd(), err);
            if (stdin_fd[RD] < 0) {
                error = err.c_str();
                return -1;
            }
            break;
        }
    }

    // Optionally setup stdout redirect
    switch (op.stdout_fd()) {
        case REDIRECT_CLOSE:
        case STDERR_FILENO:
            stdout_fd[WR] = op.stdout_fd();
            break;
        case REDIRECT_ERL:
            if (open_pipe(stdout_fd, "stdout", err) < 0) {
                error = err.c_str();
                return -1;
            }
            break;
        case REDIRECT_FILE: {
            stdout_fd[WR] = open_file(op.stdout_file(), op.stdout_append(), "stdout", op.cmd(), err);
            if (stdout_fd[WR] < 0) {
                error = err.c_str();
                return -1;
            }
            break;
        }
    }

    // Optionally setup stderr redirect
    switch (op.stderr_fd()) {
        case REDIRECT_CLOSE:
        case STDOUT_FILENO:
            stderr_fd[WR] = op.stderr_fd();
            break;
        case REDIRECT_ERL:
            if (open_pipe(stderr_fd, "stderr", err) < 0) {
                error = err.c_str();
                return -1;
            }
            break;
        case REDIRECT_FILE: {
            stderr_fd[WR] = open_file(op.stderr_file(), op.stderr_append(), "stderr", op.cmd(), err);
            if (stderr_fd[WR] < 0) {
                error = err.c_str();
                return -1;
            }
            break;
        }
    }

    if (debug)
        fprintf(stderr, "Starting child: %s\r\n", op.cmd());

    pid_t pid = fork();

    if (pid < 0) {
        error = strerror(errno);
        return pid;
    } else if (pid == 0) {
        // I am the child

        // Set up stdin redirect
        if (stdin_fd[WR] >= 0) close(stdin_fd[WR]);     // Close writing end of the child pipe
        if (stdin_fd[RD] == REDIRECT_CLOSE)
            close(STDOUT_FILENO);
        else if (stdin_fd[RD] >= 0) {
            dup2(stdin_fd[RD], STDIN_FILENO);           // Read stdin from the pipe/file
            close(stdin_fd[RD]);                        // This fd is no longer needed
        }

        // Set up stdout redirect
        if (stdout_fd[RD] >= 0) close(stdout_fd[RD]);   // Close reading end of the child pipe
        if (stdout_fd[WR] == REDIRECT_CLOSE)
            close(STDOUT_FILENO);
        else if (stdout_fd[WR] == STDERR_FILENO)
            dup2(STDERR_FILENO, STDOUT_FILENO);
        else if (stdout_fd[WR] >= 0) {
            dup2(stdout_fd[WR], STDOUT_FILENO);         // Send stdout to the pipe/file
            close(stdout_fd[WR]);                       // This fd is no longer needed
        }
        if (stdout_fd[WR] >= 0) setlinebuf(stdout);     // Set line buffering

        // Set up stderr redirect
        if (stderr_fd[RD] >= 0) close(stderr_fd[RD]);   // Close reading end of the child pipe
        if (stderr_fd[WR] == REDIRECT_CLOSE)
            close(STDERR_FILENO);
        else if (stderr_fd[WR] == STDOUT_FILENO)
            dup2(STDOUT_FILENO, STDERR_FILENO);
        else if (stderr_fd[WR] >= 0) {
            dup2(stderr_fd[WR], STDERR_FILENO);         // Send stderr to the pipe
            close(stderr_fd[WR]);                       // This fd is no longer needed
        }
        if (stderr_fd[WR] >= 0) setlinebuf(stderr);     // Set line buffering

        #if !defined(__CYGWIN__) && !defined(__WIN32)
        if (op.user() != INT_MAX && setresuid(op.user(), op.user(), op.user()) < 0) {
            err.write("Cannot set effective user to %d", op.user());
            perror(err.c_str());
            return EXIT_FAILURE;
        }
        #endif

        if (op.group() != INT_MAX && setgid(op.group()) < 0) {
            err.write("Cannot set effective group to %d", op.group());
            perror(err.c_str());
            return EXIT_FAILURE;
        }

        const char* const argv[] = { getenv("SHELL"), "-c", op.cmd(), (char*)NULL };
        if (op.cd() != NULL && op.cd()[0] != '\0' && chdir(op.cd()) < 0) {
            err.write("Cannot chdir to '%s'", op.cd());
            perror(err.c_str());
            return EXIT_FAILURE;
        }

        // TODO: move environment setup here

        if (execve((const char*)argv[0], (char* const*)argv, op.env()) < 0) {
            err.write("Cannot execute '%s'", op.cmd());
            perror(err.c_str());
            return EXIT_FAILURE;
        }
        // On success execve never returns
        return EXIT_FAILURE;
    }

    // I am the parent

    if (stdin_fd[RD] >= 0) close(stdin_fd[RD]);     // Close reading end of the child stdin pipe
    if (stdin_fd[WR] >= 0) {
        op.stdin_fd(stdin_fd[WR]);
        // Make sure the writing end is non-blocking
        set_nonblock_flag(pid, op.stdin_fd(), true);

        if (debug)
            fprintf(stderr, "Setup pid %d stdin redirection (fd=%d%s)\r\n", pid, op.stdin_fd(),
                (fcntl(op.stdin_fd(), F_GETFL, 0) & O_NONBLOCK) == O_NONBLOCK ? " [non-block]" : "");
    }

    if (stdout_fd[WR] >= 0) close(stdout_fd[WR]);   // Close writing end of the child stdout pipe
    if (stdout_fd[RD] >= 0) {
        op.stdout_fd(stdout_fd[RD]);
        // Make sure the reading end is non-blocking
        set_nonblock_flag(pid, op.stdout_fd(), true);

        if (debug)
            fprintf(stderr, "Setup pid %d stdout redirection (fd=%d%s)\r\n", pid, op.stdout_fd(),
                (fcntl(op.stdout_fd(), F_GETFL, 0) & O_NONBLOCK) == O_NONBLOCK ? " [non-block]" : "");
    }

    if (stderr_fd[WR] >= 0) close(stderr_fd[WR]);   // Close writing end of the child stderr pipe
    if (stderr_fd[RD] >= 0) {
        op.stderr_fd(stderr_fd[RD]);
        // Make sure the reading end is non-blocking
        set_nonblock_flag(pid, op.stderr_fd(), true);
        if (debug)
            fprintf(stderr, "Setup pid %d stderr redirection (fd=%d%s)\r\n", pid, op.stderr_fd(),
                (fcntl(op.stderr_fd(), F_GETFL, 0) & O_NONBLOCK) == O_NONBLOCK ? " [non-block]" : "");
    }

    if (op.nice() != INT_MAX && setpriority(PRIO_PROCESS, pid, op.nice()) < 0) {
        err.write("Cannot set priority of pid %d to %d", pid, op.nice());
        error = err.c_str();
        if (debug) perror(err.c_str());
    }
    return pid;
}

int stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify)
{
    bool use_kill = false;

    if (ci.kill_cmd_pid > 0 || ci.sigterm) {
        // There was already an attempt to kill it.
        if (ci.sigterm && now.diff(ci.deadline) > 0) {
            // More than KILL_TIMEOUT_SEC secs elapsed since the last kill attempt
            erl_exec_kill(ci.cmd_pid, SIGKILL);
            if (ci.kill_cmd_pid > 0)
                erl_exec_kill(ci.kill_cmd_pid, SIGKILL);

            ci.sigkill = true;
        }
        if (notify) send_ok(transId);
        return 0;
    } else if (!ci.kill_cmd.empty()) {
        // This is the first attempt to kill this pid and kill command is provided.
        CmdOptions co(ci.kill_cmd.c_str());
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
        int n;
        if (!ci.sigterm && (n = kill_child(ci.cmd_pid, SIGTERM, transId, notify)) == 0) {
            if (debug)
                fprintf(stderr, "Sent SIGTERM to pid %d (timeout=%dms)\r\n", ci.cmd_pid, ci.kill_timeout);
            ci.deadline.set(now, ci.kill_timeout);
        } else if (!ci.sigkill && (n = kill_child(ci.cmd_pid, SIGKILL, 0, false)) == 0) {
            if (debug)
                fprintf(stderr, "Sent SIGKILL to pid %d\r\n", ci.cmd_pid);
            ci.deadline = now;
            ci.sigkill  = true;
        } else {
            n = 0; // FIXME
            // Failed to send SIGTERM & SIGKILL to the process - give up
            ci.sigkill = true;
            if (debug)
                fprintf(stderr, "Failed to kill process %d - leaving a zombie\r\n", ci.cmd_pid);
            MapChildrenT::iterator it = children.find(ci.cmd_pid);
            if (it != children.end())
                children.erase(it);
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

int kill_child(pid_t pid, int signal, int transId, bool notify)
{
    // We can't use -pid here to kill the whole process group, because our process is
    // the group leader.
    int err = erl_exec_kill(pid, signal);
    switch (err) {
        case 0:
            if (notify) send_ok(transId);
            break;
        case EINVAL:
            if (notify) send_error_str(transId, false, "Invalid signal: %d", signal);
            break;
        case ESRCH:
            if (notify) send_error_str(transId, true, "esrch");
            break;
        case EPERM:
            if (notify) send_error_str(transId, true, "eperm");
            break;
        default:
            if (notify) send_error_str(transId, true, strerror(err));
            break;
    }
    return err;
}

bool process_pid_input(MapChildrenT::iterator& it)
{
    if (it->second.stdin_fd < 0)
        return true;

    while (!it->second.stdin_queue.empty()) {
        std::string& s = it->second.stdin_queue.back();

        const void* p = s.c_str() + it->second.stdin_wr_pos;
        int n, len = s.size() - it->second.stdin_wr_pos;

        while ((n = write(it->second.stdin_fd, p, len)) < 0 && errno == EINTR);

        if (debug) {
            if (n < 0)
                fprintf(stderr, "Error writing %d bytes to stdin (fd=%d) of pid %d: %s\r\n",
                    len, it->second.stdin_fd, it->first, strerror(errno));
            else
                fprintf(stderr, "Wrote %d/%d bytes to stdin (fd=%d) of pid %d\r\n",
                    n, len, it->second.stdin_fd, it->first);
        }

        if (n < len) {
            it->second.stdin_wr_pos += n;
            return false;
        }

        it->second.stdin_queue.pop_back();
        it->second.stdin_wr_pos = 0;
    }

    return true;
}

void process_pid_output(MapChildrenT::iterator& it, int maxsize)
{
    char buf[4096];

    if (it->second.stdout_fd >= 0) {
        for(int got = 0, n = sizeof(buf); got < maxsize && n == sizeof(buf); got += n) {
            n = read(it->second.stdout_fd, buf, sizeof(buf));
            if (debug > 1)
                fprintf(stderr, "Read %d bytes from pid %d's stdout\r\n", n, it->first);
            if (n > 0)
                send_ospid_output(it->first, "stdout", buf, n);
        }
    }
    if (it->second.stderr_fd >= 0) {
        for(int got = 0, n = sizeof(buf); got < maxsize && n == sizeof(buf); got += n) {
            n = read(it->second.stderr_fd, buf, sizeof(buf));
            if (debug > 1)
                fprintf(stderr, "Read %d bytes from pid %d's stderr\r\n", n, it->first);
            if (n > 0)
                send_ospid_output(it->first, "stderr", buf, n);
        }
    }
}

int check_children(int& isTerminated, bool notify)
{
    // For each process info in the <exited_children> queue deliver it to the Erlang VM
    // and removed it from the managed <children> map.
    while (!isTerminated && !exited_children.empty()) {
        PidStatusT& item = exited_children.front();

        MapChildrenT::iterator i = children.find(item.first);
        MapKillPidT::iterator j;
        if (i != children.end()) {
            process_pid_output(i, INT_MAX);
            // Override status code if termination was requested by Erlang
            PidStatusT ps(item.first, i->second.sigterm ? 0 : item.second);
            if (notify && send_pid_status_term(ps) < 0) {
                isTerminated = 1;
                return -1;
            }
            children.erase(i);
        } else if ((j = transient_pids.find(item.first)) != transient_pids.end()) {
            // the pid is one of the custom 'kill' commands started by us.
            transient_pids.erase(j);
        }

        exited_children.pop_front();
    }

    for (MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it) {
        TimeVal now(TimeVal::NOW);

        int   status = ECHILD;
        pid_t pid = it->first;
        int n = erl_exec_kill(pid, 0);

        if (n == 0) { // process is alive
            /* If a deadline has been set, and we're over it, wack it. */
            if (!it->second.deadline.zero() && now.diff(it->second.deadline) > 0)
                stop_child(it->second, 0, now, false);

            while ((n = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

            if (n > 0) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    exited_children.push_back(std::make_pair(pid <= 0 ? n : pid, status));
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
            continue;
        } else if (n < 0 && errno == ESRCH) {
            if (notify)
                send_pid_status_term(std::make_pair(it->first, status));
            children.erase(it);
        }
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

int CmdOptions::ei_decode(ei::Serializer& ei, bool getCmd)
{
    // {Cmd::string(), [Option]}
    //      Option = {env, Strings} | {cd, Dir} | {kill, Cmd}
    int sz;
    std::string op, val;

    m_err.str("");

    delete [] m_cenv;
    m_cenv = NULL;
    m_env.clear();

    // getting the environment of the caller process
    int orig_env_sz = 0;
    for (char **env_ptr = environ; *env_ptr; env_ptr++) {
        m_env.push_back(*env_ptr);
        orig_env_sz++;
    }

    m_nice = INT_MAX;

    if (getCmd && eis.decodeString(m_cmd) < 0) {
        m_err << "badarg: cmd string expected or string size too large";
        return -1;
    } else if ((sz = eis.decodeListSize()) < 0) {
        m_err << "option list expected";
        return -1;
    } else if (sz == 0) {
        m_cd  = "";
        m_kill_cmd = "";

        if ((m_cenv = (const char**) new char* [orig_env_sz+1]) == NULL) {
           m_err << "out of memory"; return -1;
        }
        else {
           for (int i=0; i < orig_env_sz; i++) {
                m_cenv[i] = m_env.front().c_str();
                m_env.pop_front();
            }
            m_cenv[orig_env_sz] = NULL;
        }
        return 0;
    }

    for(int i=0; i < sz; i++) {
        enum OptionT         { CD,  ENV,  KILL,  KILL_TIMEOUT,  NICE,  USER,  GROUP,  STDIN,  STDOUT,  STDERR } opt;
        const char* opts[] = {"cd","env","kill","kill_timeout","nice","user","group","stdin","stdout","stderr"};
        int arity, type = eis.decodeType(arity);

        if (type == ERL_ATOM_EXT && (int)(opt = (OptionT)eis.decodeAtomIndex(opts, op)) >= 0)
            arity = 1;
        else if (type != ERL_SMALL_TUPLE_EXT ||
                   eis.decodeTupleSize() != 2  ||
                   (int)(opt = (OptionT)eis.decodeAtomIndex(opts, op)) < 0) {
            m_err << "badarg: cmd option must be {Cmd, Opt} or atom"; return -1;
        }

        switch (opt) {
            case CD:
                // {cd, Dir::string()}
                if (eis.decodeString(val) < 0) { m_err << op << " bad option value"; return -1; }
                m_cd = val;
                break;

            case KILL:
                // {kill, Cmd::string()}
                if (eis.decodeString(val) < 0) { m_err << op << " bad option value"; return -1; }
                m_kill_cmd = val;
                break;

            case GROUP: {
                // {group, integer() | string()}
                type = eis.decodeType(arity);
                if (type == etString) {
                    if (eis.decodeString(val) < 0) { m_err << op << " bad group value"; return -1; }
                    struct group g;
                    char buf[1024];
                    struct group* res;
                    if (getgrnam_r(val.c_str(), &g, buf, sizeof(buf), &res) < 0) {
                        m_err << op << " invalid group name: " << val;
                        return -1;
                    }
                    m_group = g.gr_gid;
                } else if (eis.decodeInt(m_group) < 0) {
                    m_err << op << " bad group value type (expected int or string)";
                    return -1;
                }
                break;
            }
            case USER:
                // {user, Dir::string()} | {kill, Cmd::string()}
                if (eis.decodeString(val) < 0) {
                    m_err << op << " bad option value"; return -1;
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
                if (eis.decodeInt(m_kill_timeout) < 0) {
                    m_err << "invalid value of kill_timeout";
                    return -1;
                }
                break;

            case NICE:
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
                    m_err << "env list expected"; return -1;
                }

                for (int i=0; i < opt_env_sz; i++) {
                    int sz, type = eis.decodeType(sz);
                    bool res = false;
                    std::string s;

                    if (type == ERL_STRING_EXT) {
                        res = !eis.decodeString(s);
                    } else if (type == ERL_SMALL_TUPLE_EXT && sz == 2) {
                        eis.decodeTupleSize();
                        std::string s1, s2;
                        if (eis.decodeString(s1) == 0 && eis.decodeString(s2) == 0) {
                            res = true;
                            s = s1 + "=" + s2;
                        }
                    }

                    if (!res) {
                        m_err << "invalid env argument #" << i;
                        return -1;
                    }
                    m_env.push_back(s);
                }
                orig_env_sz += opt_env_sz;
                break;
            }

            case STDIN:
            case STDOUT:
            case STDERR: {
                int& fdr = opt == STDIN
                         ? m_stdin_fd
                         : (opt == STDOUT ? m_stdout_fd : m_stderr_fd);

                if (arity == 1)
                    fdr = REDIRECT_ERL;
                else {
                    int type = 0, sz;
                    std::string s, fop;
                    type = eis.decodeType(sz);

                    if (type == ERL_ATOM_EXT)
                        eis.decodeAtom(s);
                    else if (type == ERL_STRING_EXT)
                        eis.decodeString(s);
                    else if (! (type == ERL_SMALL_TUPLE_EXT && sz == 2 &&
                        eis.decodeTupleSize() == 2 &&
                        eis.decodeAtom(fop) == 0 &&
                        eis.decodeString(s) == 0 && fop == "append"))
                    {
                        m_err << "Atom, string or {append, Name} tuple required for option " << op;
                        return -1;
                    }

                    if (s == "null") {
                        output_file(opt == STDOUT, "/dev/null", false);
                    } else if (s == "true") {
                        fdr = REDIRECT_ERL;
                    } else if (s == "close") {
                        fdr = REDIRECT_CLOSE;
                    } else if (s == "stderr" && opt == STDOUT)
                        m_stderr_fd = STDOUT_FILENO;
                    else if (s == "stdout" && opt == STDERR)
                        m_stdout_fd = STDERR_FILENO;
                    else if (s != "") {
                        output_file(opt == STDOUT, s, fop == "append");
                    }
                }

                if (opt == STDIN &&
                    !(fdr == REDIRECT_NONE || fdr == REDIRECT_ERL || fdr == REDIRECT_CLOSE)) {
                    m_err << "Invalid " << op << " redirection option: '" << op << "'";
                    return -1;
                }
                break;
            }
            default:
                m_err << "bad option: " << op; return -1;
        }
    }

    if ((m_cenv = (const char**) new char* [orig_env_sz+1]) == NULL) {
        m_err << "out of memory"; return -1;
    }
    else {
      for (int i=0; i < orig_env_sz; i++) {
          m_cenv[i] = m_env.front().c_str();
          m_env.pop_front();
      }
      m_cenv[orig_env_sz] = NULL;
    }

    if (m_stdout_fd == STDERR_FILENO && m_stderr_fd == STDOUT_FILENO) {
        m_err << "circular reference of stdout and stderr";
        return -1;
    }

    return 0;
}

/* This exists just to make sure that we don't inadvertently do a
 * kill(-1, SIGKILL), which will cause all kinds of bad things to
 * happen. */

int erl_exec_kill(pid_t pid, int signal) {
    if (pid < 0) {
        if (debug)
            fprintf(stderr, "kill(-1, %d) attempt prohibited!\r\n", signal);

        return -1;
    }

    if (debug && signal > 0)
        fprintf(stderr, "Calling kill(pid=%d, sig=%d)\r\n", pid, signal);

    return kill(pid, signal);
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
    if (debug > 1) {
        oldflags = fcntl(fd, F_GETFL, 0);
        fprintf(stderr, "Set pid %d's fd=%d to non-blocking mode (flags=%x)\r\n",
            pid, fd, oldflags);
    }

    return ret;
}

/*
int CmdOptions::init(const std::list<std::string>& list)
{
    int i, size=0;
    for(std::list<std::string>::iterator it=list.begin(), end=list.end(); it != end; ++it)
        size += it->size() + 1;
    if (m_env.resize(m_size) == NULL)
        return -1;
    m_count = list.size() + 1;
    char *p = m_env.c_str();
    for(std::list<std::string>::iterator it=list.begin(), end=list.end(); it != end; ++it) {
        strcpy(p, it->c_str());
        m_cenv[i++] = p;
        p += it->size() + 1;
    }
    m_cenv[i] = NULL;
    return 0;
}
*/
