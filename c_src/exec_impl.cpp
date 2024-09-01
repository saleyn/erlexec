// vim:ts=4:sw=4:et
#include "exec.hpp"
#include <errno.h>

namespace ei {

//------------------------------------------------------------------------------
// DARWIN doesn't have ptsname_r()
//------------------------------------------------------------------------------
#if defined(__MACH__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
int ptsname_r(int fd, char* buf, size_t buflen) {
  char *name = ptsname(fd);
  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (strlen(name) + 1 > buflen) {
    errno = ERANGE;
    return -1;
  }
  strncpy(buf, name, buflen);
  return 0;
}
#endif

//------------------------------------------------------------------------------
// CmdInfo
//------------------------------------------------------------------------------
#if !defined(USE_POLL) || !USE_POLL
void CmdInfo::include_stream_fd(FdHandler &fdhandler)
{
    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
        if (stream_fd[i] < 0 || (i == STDIN_FILENO && stdin_wr_pos <= 0 && stdin_queue.empty()))
            continue;

        DEBUG(debug > 2, "Pid %d adding %s available notification (fd=%d, pos=%d)",
              cmd_pid, stream_name(i), stream_fd[i], i==STDIN_FILENO ? stdin_wr_pos : -1);

        if (i==STDIN_FILENO)
            fdhandler.append_write_fd(stream_fd[i]);
        else
            fdhandler.append_read_fd(stream_fd[i]);
    }
}

void CmdInfo::process_stream_data(FdHandler &fdhandler)
{
    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
        int fd  = stream_fd[i];

        if (fd < 0) continue;

        if ((i == STDIN_FILENO) && fdhandler.is_writable(fd)) {
            process_pid_input(*this);
        } else if ((i != STDIN_FILENO) && fdhandler.is_readable(FdType::CHILD_PROC, fd)) {
            process_pid_output(*this, i);
        }
    }
}
#endif /* !defined(USE_POLL) */

#if defined(USE_POLL) && USE_POLL
void CmdInfo::include_stream_fd(FdHandler &fdhandler)
{
    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
        poll_fd_idx[i] = -1;

        if (stream_fd[i] < 0 || (i == STDIN_FILENO && stdin_wr_pos <= 0 && stdin_queue.empty()))
            continue;

        DEBUG(debug > 2, "Pid %d adding %s available notification (fd=%d, pos=%d)",
              cmd_pid, stream_name(i), stream_fd[i], i==STDIN_FILENO ? stdin_wr_pos : -1);

        if (i==STDIN_FILENO)
            fdhandler.append_write_fd(stream_fd[i]);
        else
            fdhandler.append_read_fd(stream_fd[i]);

        poll_fd_idx[i] = fdhandler.size()-1;
    }
}

void CmdInfo::process_stream_data(FdHandler& fdhandler)
{
    for (int  i = STDIN_FILENO; i <= STDERR_FILENO; i++) {
        int idx = poll_fd_idx[i];
        if (idx < 0)
            continue;
        assert(idx < int(fdhandler.size()));
        if ((i == STDIN_FILENO) && fdhandler.is_writable(idx)) {
            process_pid_input(*this);
        } else if ((i != STDIN_FILENO) && fdhandler.is_readable(FdType::CHILD_PROC, idx)) {
            process_pid_output(*this, i);
        }
    }
}
#endif

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
const char* stream_name(int i) {
    switch (i) {
        case STDIN_FILENO:  return "stdin";
        case STDOUT_FILENO: return "stdout";
        case STDERR_FILENO: return "stderr";
        default:            return "<unknown>";
    }
}

//------------------------------------------------------------------------------
// Read details of terminated child from pipe
//------------------------------------------------------------------------------
int read_sigchld(pid_t& child)
{
    int         n = 0;
    char*       p = (char*)&child;
    const char* e = p + sizeof(pid_t);

    do    { n = read(sigchld_pipe[0], p, e-p); if (n > 0) p += n; }
    while ((n < 0 && errno == EINTR) || (n > 0 && p < e));

    if (n < 0 && errno != EAGAIN)
        DEBUG(debug, "Error reading from sigchld pipe descriptor: %s", strerror(errno));

    return n <= 0 ? n : p - (char*)&child;
}

//------------------------------------------------------------------------------
// Process queued SIGCHLD events
//------------------------------------------------------------------------------
bool process_sigchld()
{
    // Got SIGCHLD event
    pid_t child;
    int   n;
    while ((n = read_sigchld(child)) > 0)
        check_child_exit(child);
    return n > 0 || errno == EAGAIN;
}

//------------------------------------------------------------------------------
int set_nice(pid_t pid,int nice, std::string& error)
{
    ei::StringBuffer<128> err;

    if (nice != std::numeric_limits<int>::max() && setpriority(PRIO_PROCESS, pid, nice) < 0) {
        err.write("Cannot set priority of pid %d to %d", pid, nice);
        error = err.c_str();
        DEBUG(debug, "%s", error.c_str());
        return -1;
    }
    return 0;
}

//------------------------------------------------------------------------------
bool set_winsz(int fd, int rows, int cols) {
    struct winsize ws;
    ws.ws_row =  rows;
    ws.ws_col =  cols;

    int r = ioctl(fd, TIOCSWINSZ, &ws);

    if (r == -1 || ws.ws_row == 0 || ws.ws_col == 0) {
        int tty = open("/dev/tty", O_RDONLY);
        DEBUG(debug, "TIOCSWINSZ rows=%d cols=%d tty=%d ret=%d", ws.ws_row, ws.ws_col, r, tty);
        if (tty != -1) {
            r = ioctl(tty, TIOCGWINSZ, &ws);
            close(tty);
        }
    }

    DEBUG(debug, "TIOCSWINSZ rows=%d cols=%d ret=%d", rows, cols, r);

    return r == 0;
}

//------------------------------------------------------------------------------
bool set_pid_winsz(CmdInfo& ci, int rows, int cols)
{
    int&   fd = ci.stream_fd[STDIN_FILENO];
    return set_winsz(fd, rows, cols);
}

//------------------------------------------------------------------------------
bool set_pty_opt(struct termios* tio, const std::string& key, int value) {
#define TTYCHAR(NAME, STR_NAME)                                                \
    if (key == STR_NAME) {                                                     \
        DEBUG(debug, "set tty_char %s", #NAME);                                \
        if (tio) tio->c_cc[NAME] = value;                                      \
        return true;                                                           \
    }

#define TTYMODE(NAME, FIELD, STR_NAME)                                         \
    if (key == STR_NAME) {                                                     \
        DEBUG(debug, "tty mode %s %s", #NAME, value?"enabled":"disabled");     \
        if (tio) {                                                             \
            if (value)                                                         \
                tio->FIELD |=  NAME;                                           \
            else                                                               \
                tio->FIELD &= ~NAME;                                           \
        }                                                                      \
        return true;                                                           \
    }

#define TTYSPEED(VALUE)                                                        \
    if (key == "tty_op_ispeed" && value == VALUE) {                            \
        DEBUG(debug, "set tty_ispeed %d", value);                              \
        return !tio || cfsetispeed(tio, value) == 0;                           \
    }                                                                          \
    if (key == "tty_op_ospeed" && value == VALUE) {                            \
        DEBUG(debug, "set tty_ospeed %d", value);                              \
        return !tio || cfsetospeed(tio, value) == 0;                           \
    }

#include "ttymodes.hpp"

#undef TTYCHAR
#undef TTYMODE
#undef TTYSPEED

    // fallback for systems without pre-defined baud rates
    if (key == "tty_op_ispeed") {
        DEBUG(debug, "set tty_ispeed %d", value);
        return !tio || cfsetispeed(tio, value) == 0;
    }
    if (key == "tty_op_ospeed") {
        DEBUG(debug, "set tty_ospeed %d", value);
        return !tio || cfsetospeed(tio, value) == 0;
    }

    return false;
}

//------------------------------------------------------------------------------
bool process_pid_input(CmdInfo& ci)
{
    int& fd = ci.stream_fd[STDIN_FILENO];

    if (fd < 0) return true;

    while (!ci.stdin_queue.empty()) {
        std::string& s = ci.stdin_queue.back();
        const void*  p = s.c_str() + ci.stdin_wr_pos;
        int   n,   len = s.size()  - ci.stdin_wr_pos;

        while ((n = write(fd, p, len)) < 0 && errno == EINTR);

        auto err = errno;
      
        if (n < 0)
            DEBUG(debug, "Error writing %d bytes to stdin (fd=%d) of pid %d: %s",
                len, fd, ci.cmd_pid, strerror(err));
        else
            DEBUG(debug, "Wrote %d/%d bytes to stdin (fd=%d) of pid %d",
                n, len, fd, ci.cmd_pid);

        if (n > 0 && n < len) {
            ci.stdin_wr_pos += n;
            return false;
        } else if (n < 0 && err == EAGAIN) {
            break;
        } else if (n <= 0) {
            close_stdin(ci);
            return true;
        }

        ci.stdin_queue.pop_back();
        ci.stdin_wr_pos = 0;
    }

    if (ci.stdin_queue.empty() && ci.eof_arrived) {
        close_stdin(ci);
    }

    return true;
}

//------------------------------------------------------------------------------
void process_pid_output(CmdInfo& ci, int stream_id, int maxsize)
{
    char buf[4096];
    bool dead = false;

    assert(stream_id >= STDOUT_FILENO && stream_id <= STDERR_FILENO);
    int& fd = ci.stream_fd[stream_id];

    if (fd >= 0) {
        for(int got=0, n=sizeof(buf); got < maxsize && n == sizeof(buf); got += n) {
            while ((n = read(fd, buf, sizeof(buf))) < 0 && errno == EINTR);
            DEBUG(debug > 1, "Read %d bytes from pid %d's %s (fd=%d): %s",
                  n, ci.cmd_pid, stream_name(stream_id), fd, n > 0 ? "ok" : strerror(errno));
            if (n > 0) {
                send_ospid_output(ci.cmd_pid, stream_name(stream_id), buf, n);
                if (n < (int)sizeof(buf))
                    break;
            } else if (n < 0 && errno == EAGAIN)
                break;
            else if (n <= 0) {
                int fdc = fd;
                close(fd);
                fd = REDIRECT_CLOSE;
                DEBUG(debug, "Eof reading pid %d's %s, closing fd=%d (%d)",
                      ci.cmd_pid, stream_name(stream_id), fdc, ci.stream_fd[stream_id]);
                dead = true;
                break;
            }
        }
    }

    if (dead)
        check_child_exit(ci.cmd_pid);
}

//------------------------------------------------------------------------------
static int getpty(int& fdmp, ei::StringBuffer<128>& err) {
    int fdm;
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

    fdmp = fdm;

    DEBUG(debug, "  Opened PTY master=%d", fdm);

    return 0;
}

struct Caps {
    Caps() : m_caps(cap_get_proc()) {}
    ~Caps() { if (m_caps) cap_free(m_caps); }

    bool         valid()        const { return !!m_caps;           }
    cap_t        value()              { return m_caps;             }
    void         add(cap_value_t cap) { m_cap_list.push_back(cap); }
    cap_value_t* list()               { return m_cap_list.data();  }
    size_t       size()         const { return m_cap_list.size();  }
private:
    cap_t m_caps;
    std::vector<cap_value_t> m_cap_list;
};

//------------------------------------------------------------------------------
bool propagate_caps(ei::StringBuffer<128>& err)
{
#ifdef HAVE_CAP
    Caps caps;

    // Get the current process capabilities
    if (!caps.valid()) {
        err.write("error %d on cap_get_proc: %s\n", errno, strerror(errno));
        return false;
    }

    // Get the bounding set of capabilities
    cap_flag_value_t cap_value;
    for (cap_value_t i = 0; i <= CAP_LAST_CAP; ++i) {
        if (cap_get_flag(caps.value(), i, CAP_PERMITTED, &cap_value) < 0) {
            err.write("error %d on cap_get_flag: %s\n", errno, strerror(errno));
            return false;
        }
        if (cap_value == CAP_SET)
            cap_list.add(i);
    }

    // Set inheritable capabilities to all permitted capabilities
    if (cap_set_flag(caps.value(), CAP_INHERITABLE, caps.size(), caps.list(), CAP_SET) < 0) {
        err.write("error %d on cap_set_flag: %s\n", errno, strerror(errno));
        return false;
    }

    // Apply inheritable capabilities
    if (cap_set_proc(caps.value()) < 0) {
        err.write("error %d on cap_set_proc: %s\n", errno, strerror(errno));
        return false;
    }

    // Set ambient capabilities
    for (size_t i = 0; i < caps.size(); i++) {
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, caps.list()[i], 0, 0) < 0) {
            err.write("error %d on PR_CAP_AMBIENT_RAISE[%d]: %s\n", errno, i, strerror(errno));
            return false;
        }
    }
#endif
    return true;
}

//------------------------------------------------------------------------------
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
    int fdm = 0;

    if (op.pty()) {
        if (getpty(fdm, err) < 0) {
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
                DEBUG(debug, "  Closing %s", stream_name(i));
                break;
            case REDIRECT_STDOUT:
            case REDIRECT_STDERR:
                sfd[crw] = cfd;
                DEBUG(debug, "  Redirecting [%s -> %s]",
                      stream_name(i), fd_type(cfd).c_str());
                break;
            case REDIRECT_ERL:
                if (op.pty()) {
                    if (i == STDIN_FILENO) {
                        sfd[RD] = -1; // assign later in the child process when pty gets open
                        sfd[WR] = fdm;
                    } else {
                        sfd[WR] = -1;
                        sfd[RD] = fdm;
                    }
                    DEBUG(debug, "  Redirecting [%s -> pipe:{r=%d,w=%d}] (PTY)",
                          stream_name(i), sfd[0], sfd[1]);
                } else if (open_pipe(sfd, stream_name(i), err) < 0) {
                    error = err.c_str();
                    return -1;
                }
                break;
            case REDIRECT_NULL:
                sfd[crw] = dev_null;
                if (!op.is_kill_cmd())
                    DEBUG(debug, "  Redirecting [%s -> null]", stream_name(i));
                break;
            case REDIRECT_FILE: {
                FileOpenFlag flag = i == STDIN_FILENO   ? READ   :
                                    op.stream_append(i) ? APPEND :
                                    TRUNCATE;
                sfd[crw] = open_file(op.stream_file(i), flag,
                                     stream_name(i), err, op.stream_mode(i));
                if (sfd[crw] < 0) {
                    error = err.c_str();
                    return -1;
                }
                break;
            }
        }
    }

    if (debug || op.dbg()) {
        DEBUG(true, "Starting %s: '%s' (euid=%d)",
              op.is_kill_cmd() ? "custom kill command" : "child",
              op.cmd().front().c_str(), op.user() == std::numeric_limits<int>::max() ? -1 : op.user());
        if (!op.is_kill_cmd())
            fprintf(stderr,
                    "  child  = (stdin=%s, stdout=%s, stderr=%s)\r\n"
                    "  parent = (stdin=%s, stdout=%s, stderr=%s)\r\n",
                fd_type(stream_fd[STDIN_FILENO ][RD]).c_str(),
                fd_type(stream_fd[STDOUT_FILENO][WR]).c_str(),
                fd_type(stream_fd[STDERR_FILENO][WR]).c_str(),
                fd_type(stream_fd[STDIN_FILENO ][WR]).c_str(),
                fd_type(stream_fd[STDOUT_FILENO][RD]).c_str(),
                fd_type(stream_fd[STDERR_FILENO][RD]).c_str()
            );
        if (!op.executable().empty())
            fprintf(stderr, "  Executable: %s", op.executable().c_str());
        if (!op.cmd().empty()) {
            int i = 0;
            if (op.shell()) {
                const char* s = getenv("SHELL");
                fprintf(stderr, "  Args[%d]: %s\r\n"
                                "  Args[%d]: -c\r\n", i, s ? s : "(null)", i+1);
                i+=2;
            }
            typedef CmdArgsList::const_iterator const_iter;
            for(const_iter it = op.cmd().begin(), end = op.cmd().end(); it != end; ++it)
                fprintf(stderr, "  Args[%d]: %s\r\n", i++, it->c_str());
        } else {
            error = "cannot run empty command";
            return -1;
        }
        if (!op.mapenv().empty() && (debug || op.dbg()))
            for (auto& kv : op.mapenv())
                fprintf(stderr, "  Env[%s]: %s\r\n", kv.first.c_str(), kv.second.c_str());

    }

    pid_t pid = fork();

    if (pid < 0) {
        error = strerror(errno);
        return pid;
    } else if (pid == 0) {
        // I am the child
        int r;
        if (op.pty()) {
            int fds;
            char pts_name[256];
            
            // have to open the pty slave in the child, otherwise TIOCSCTTY will fail later
            r = ptsname_r(fdm, pts_name, sizeof(pts_name));
            if( r < 0 ) {
                DEBUG(true, "ptsname_r(%d) failed: %s", fdm, strerror(errno));
                exit(1);
            }
            fds = open(pts_name, O_RDWR);
            if (fds < 0) {
                DEBUG(true, "open slave pty %s failed: %s", pts_name, strerror(errno));
                exit(1);
            }
            for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
                int* sfd = stream_fd[i];
                int  cfd = op.stream_fd(i);
                if (cfd == REDIRECT_ERL) {
                    if (i == STDIN_FILENO)
                        sfd[RD] = fds;
                    else
                        sfd[WR] = fds;
                    DEBUG(debug, "  Redirecting [%s -> pipe:{r=%d,w=%d}] (PTY)",
                          stream_name(i), sfd[0], sfd[1]);
                }
            }
        }

        // Clear the child process signal mask
        sigset_t sig;
        sigemptyset(&sig);
        sigprocmask(SIG_SETMASK, &sig, NULL);

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

        // Note: we don't need to close fds inherited from parent
        // because they were open with O_CLOEXEC or FD_CLOEXEC and 
        // will be automatically closed in the execve(2) call below

        if (op.pty()) {
            if (!op.pty_echo()) {
                struct termios ios;
                tcgetattr(STDIN_FILENO, &ios);
                // Disable the ECHO mode
                // For the list of all modes see RFC4254:
                // https://datatracker.ietf.org/doc/html/rfc4254#section-8
                ios.c_lflag &= ~(ECHO | ECHONL | ECHOE | ECHOK);
                // We don't check if it succeeded because if the STDIN is not a terminal
                // it won't be able to disable the ECHO anyway.
                tcsetattr(STDIN_FILENO, TCSANOW, &ios);
            }
            if (!op.pty_opts().empty()) {
                MapPtyOpt pty_opts = op.pty_opts();
                struct termios ios;
                tcgetattr(STDIN_FILENO, &ios);
                for (auto it = pty_opts.begin(), end = pty_opts.end(); it != end; ++it)
                    set_pty_opt(&ios, it->first, it->second);
                tcsetattr(STDIN_FILENO, TCSANOW, &ios);
            }
            std::tuple<int, int> winsz = op.winsz();
            int rows = std::get<0>(winsz);
            int cols = std::get<1>(winsz);
            if (rows && cols)
                set_winsz(STDIN_FILENO, rows, cols);

            // Make the current process a new session leader
            setsid();

            // as a session leader, set the controlling terminal to be the
            // slave side
            ioctl(STDIN_FILENO, TIOCSCTTY, 1);
        }

        #if !defined(__CYGWIN__) && !defined(__WIN32)
        if (op.user() != std::numeric_limits<int>::max() &&
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

        if (op.group() != std::numeric_limits<int>::max() && setpgid(0, op.group()) < 0) {
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

        for (std::list<std::string>::const_iterator it = op.cmd().begin(), end = op.cmd().end();
             it != end; ++it)
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
        /*
        // Print the environment of the child
        if ((debug > 3 || op.dbg() > 3) && op.env()) {
            int i=0;
            for (auto p = op.env()[i]; p; p = op.env()[++i])
                fprintf(stderr, "  CEnv: %s\r\n", p);
        }
        */

        if (!propagate_caps(err)) {
	    perror(err.c_str());
	    exit(EXIT_FAILURE);
	}

        const char* executable = op.executable().empty()
            ? argv[0] : op.executable().c_str();

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

    DEBUG(debug > 1, "Spawned child pid %d", pid);

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

    if (op.group() != std::numeric_limits<int>::max()) {
        pid_t gid = op.group() ? op.group() : pid;
        if (setpgid(pid, gid) == -1 && errno != EACCES)
            DEBUG(debug, "  Parent failed to set group of pid %d to %d: %s",
                  pid, gid, strerror(errno));
        else
            DEBUG(debug, "  Set group of pid %d to %d", pid, gid);
    }

    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
        int  wr  = i==STDIN_FILENO ? WR : RD;
        int& cfd = op.stream_fd(i);
        int* sfd = stream_fd[i];

        int fd = sfd[i==0 ? RD : WR];
        if (fd >= 0 && fd != dev_null) {
            DEBUG(debug, "  Parent closing pid %d pipe %s end (fd=%d)",
                  pid, i==STDIN_FILENO ? "reading" : "writing", fd);
            close(fd); // Close stdin/reading or stdout(err)/writing end of the child pipe
        }

        if (sfd[wr] >= 0 && sfd[wr] != dev_null) {
            cfd = sfd[wr];
            // Make sure the writing end is non-blocking
            set_nonblock_flag(pid, cfd, true);

            DEBUG(debug, "  Setup %s end of pid %d %s redirection (fd=%d%s)",
                  i==STDIN_FILENO ? "writing" : "reading", pid, stream_name(i), cfd,
                  (fcntl(cfd, F_GETFL, 0) & O_NONBLOCK) == O_NONBLOCK ? " [non-block]" : "");
        }
    }

    set_nice(pid,op.nice(),error);

    return pid;
}

//------------------------------------------------------------------------------
int stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify)
{
    bool use_kill = false;

    if (ci.sigkill)     // Kill signal already sent
        return 0;

    if (ci.kill_cmd_pid > 0 || ci.sigterm) {
        // There was already an attempt to kill it.
        if (now.diff(ci.deadline) > 0) {
            DEBUG(debug,
                  "PID %d: more than %ds elapsed since the kill attempt by pid %d: executing SIGKILL",
                  ci.cmd_pid, KILL_TIMEOUT_SEC, ci.kill_cmd_pid);
            erl_exec_kill(ci.kill_group ? -ci.cmd_gid : ci.cmd_pid, SIGKILL, SRCLOC);
            if (ci.kill_cmd_pid > 0)
                erl_exec_kill(ci.kill_cmd_pid, SIGKILL, SRCLOC);

            ci.sigkill = true;
        }
        if (notify) send_ok(transId);
        return 0;
    }

    DEBUG(debug, "Request to stop pid %d", ci.cmd_pid);

    if (!ci.kill_cmd.empty()) {
        // This is the first attempt to kill this pid and kill command is provided.
        CmdArgsList kill_cmd;
        kill_cmd.push_front(ci.kill_cmd.c_str());
        MapEnv env{{"CHILD_PID", std::to_string(ci.cmd_pid)}};
        CmdOptions co(kill_cmd, NULL, env,
                      std::numeric_limits<int>::max(), // user
                      std::numeric_limits<int>::max(), // nice
                      std::numeric_limits<int>::max(), // group
                      true     // this is a custom kill command
                     );

        if (debug > 3 || co.dbg() > 3)
            co.stream_redirect(STDERR_FILENO, REDIRECT_NONE); // Don't redirect STDERR of the kill command

        std::string err;
        ci.kill_cmd_pid = start_child(co, err);
        if (!err.empty())
           DEBUG(debug, "Error executing kill command '%s': %s\r\r",
                 ci.kill_cmd.c_str(), err.c_str());

        if (ci.kill_cmd_pid > 0) {
            ci.deadline.set(now, ci.kill_timeout);
            DEBUG(debug, "Set kill deadline for pid %d of %ds (for being killed by custom command's pid %d)",
                  ci.cmd_pid, ci.kill_timeout, ci.kill_cmd_pid);
            transient_pids[ci.kill_cmd_pid] = std::make_pair(ci.cmd_pid, ci.deadline);
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
            DEBUG(debug, "Sent SIGTERM to %s %d (timeout=%ds)",
                  spid, abs(pid), ci.kill_timeout);
            ci.deadline.set(now, ci.kill_timeout);
        } else if (!ci.sigkill && (n = kill_child(pid, SIGKILL, 0, false)) == 0) {
            DEBUG(debug, "Sent SIGKILL to %s %d", spid, abs(pid));
            ci.deadline.clear();
            ci.sigkill = true;
        } else {
            n = 0; // FIXME
            // Failed to send SIGTERM & SIGKILL to the process - give up
            ci.deadline.clear();
            ci.sigkill = true;
            DEBUG(debug, "Failed to kill %s %d - leaving a zombie", spid, abs(pid));
            auto it = children.find(ci.cmd_pid);
            if (it != children.end())
                erase_child(it);
        }
        ci.sigterm = true;
        return n;
    }
    return 0;
}

//------------------------------------------------------------------------------
void stop_child(pid_t pid, int transId, const TimeVal& now)
{
    int n = 0;

    auto it = children.find(pid);
    if (it == children.end()) {
        send_error_str(transId, false, "pid not alive");
        return;
    } else if ((n = erl_exec_kill(pid, 0, SRCLOC)) < 0) {
        send_error_str(transId, false, "pid not alive (err: %d)", n);
        return;
    }
    stop_child(it->second, transId, now);
}

//------------------------------------------------------------------------------
static int send_std_error(int err, bool notify, int transId)
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

//------------------------------------------------------------------------------
int kill_child(pid_t pid, int signal, int transId, bool notify)
{
    // We can't use -pid here to kill the whole process group, because our process is
    // the group leader.
    int err = erl_exec_kill(pid, signal, SRCLOC);
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

//------------------------------------------------------------------------------
void close_stdin(CmdInfo& ci)
{
    int& fd = ci.stream_fd[STDIN_FILENO];

    if (fd < 0) return;
    DEBUG(debug, "Eof writing pid %d's stdin, closing fd=%d: %s",
          ci.cmd_pid, fd, strerror(errno));
    ci.stdin_wr_pos = 0;
    close(fd);
    fd = REDIRECT_CLOSE;
    ci.stdin_queue.clear();
}

//------------------------------------------------------------------------------
void erase_child(MapChildrenT::iterator& it)
{
    for (int i=STDIN_FILENO; i<=STDERR_FILENO; i++)
        if (it->second.stream_fd[i] >= 0) {
            DEBUG(debug, "Closing pid %d's %s", it->first, stream_name(i));
            close(it->second.stream_fd[i]);
        }

    children.erase(it);
}

//------------------------------------------------------------------------------
int check_children(const TimeVal& now, bool& isTerminated, bool notify)
{
    DEBUG(debug > 2, "Checking %ld running children (exited count=%ld)",
          children.size(), exited_children.size());

    for (auto it=children.begin(), end=children.end(); !isTerminated && it != end; ++it)
        check_child(now, it->first, it->second);

    DEBUG(debug > 2, "Checking %ld exited children (notify=%d)",
          exited_children.size(), notify);

    // For each process info in the <exited_children> queue deliver it to the Erlang VM
    // and remove it from the managed <children> map.
    for (auto it=exited_children.begin(); !isTerminated && it!=exited_children.end();)
    {
        auto i = children.find(it->first);
        MapKillPidT::iterator j;

        if (i != children.end()) {
            for(int stream_id=STDOUT_FILENO; stream_id <= STDERR_FILENO; ++stream_id)
                process_pid_output(i->second, stream_id, std::numeric_limits<int>::max());
            // Override status code if termination was requested by Erlang
            PidStatusT ps(it->first,
                i->second.sigterm
                ? 0 // Override status code if termination was requested by Erlang
                : i->second.success_code && !it->second
                    ? i->second.success_code // Override success status code
                    : it->second);
            // The process exited and it requires to kill all other processes in the group
            if (i->second.kill_group && i->second.cmd_gid != std::numeric_limits<int>::max() && i->second.cmd_gid)
                erl_exec_kill(-(i->second.cmd_gid), SIGTERM, SRCLOC); // Kill all children in this group

            if (notify && send_pid_status_term(ps) < 0) {
                isTerminated = 1;
                return -1;
            }
            erase_child(i);
        } else if ((j = transient_pids.find(it->first)) != transient_pids.end()) {
            // the pid is one of the custom 'kill' commands started by us.
            // If the cmd that was intended to be killed by this pid still exists
            // clear its kill_cmd_pid value
            auto cmd_pid = j->second.first;
            i = children.find(cmd_pid);
            if (i != children.end()) {
                i->second.kill_cmd_pid = 0;     // Since this command is no longer alive
                i->second.sigterm      = true;  // Since we already made an attempt to kill
            }
            // Erase the kill command's pid entry
            transient_pids.erase(j);
        }

        it = exited_children.erase(it);
    }

    return 0;
}

//------------------------------------------------------------------------------
void check_child(const TimeVal& now, pid_t pid, CmdInfo& cmd)
{
    if (pid == self_pid)    // Safety check. Never kill itself
        return;

    int n = erl_exec_kill(pid, 0, SRCLOC);

    if (n == 0) { // process is alive
        /* If a deadline has been set, and we're over it, wack it. */
        if (!cmd.deadline.zero() && cmd.deadline.diff(now) <= 0) {
            stop_child(cmd, 0, now, false);
            cmd.deadline.clear();
        }

        int status = ECHILD;
        while ((n  = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

        if (n > 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                add_exited_child(pid <= 0 ? n : pid, status);
            } else if (WIFSTOPPED(status)) {
                DEBUG(debug, "Pid %d %swas stopped by delivery of a signal %d",
                      pid, cmd.managed ? "(managed) " : "", WSTOPSIG(status));
            } else if (WIFCONTINUED(status)) {
                DEBUG(debug, "Pid %d %swas resumed by delivery of SIGCONT",
                      pid, cmd.managed ? "(managed) " : "");
            }
        }
    } else if (n < 0 && errno == ESRCH) {
        add_exited_child(pid, -1);
    }
}

//------------------------------------------------------------------------------
void check_child_exit(pid_t pid)
{
    int status = 0;
    pid_t ret;

    if (pid == self_pid)    // Safety check. Never kill itself
        return;

    if (exited_children.find(pid) != exited_children.end())
        return;

    // Read process's exit status
    while ((ret = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

    DEBUG(debug, "* Process %d (ret=%d, status=%d, exited_count=%ld%s%s)",
          pid, ret, status, exited_children.size(),
            ret > 0 && WIFEXITED(status) ? " [exited]":"",
            ret > 0 && WIFSIGNALED(status) ? " [signaled]":"");

    if (ret < 0 && errno == ECHILD) {
        if (erl_exec_kill(pid, 0, SRCLOC) == 0) // process likely forked and is alive
            status = 0;
        if (status != 0)
            exited_children.insert(std::make_pair(pid <= 0 ? ret : pid, status));
    } else if (pid <= 0 && ret > 0) {
        exited_children.insert(std::make_pair(ret, status == 0 ? 1 : status));
    } else if (ret == pid || WIFEXITED(status) || WIFSIGNALED(status)) {
        if (ret > 0)
            exited_children.insert(std::make_pair(pid, status));
    }
}

//------------------------------------------------------------------------------
int send_pid_list(int transId, const MapChildrenT& _children)
{
    // Reply: {TransId, [OsPid::integer()]}
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(transId);
    eis.encodeListSize(_children.size());
    for(const auto& it: _children)
        eis.encode(it.first);
    eis.encodeListEnd();
    return eis.write();
}

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
int send_pid(int transId, pid_t pid)
{
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(transId);
    eis.encodeTupleSize(2);
    eis.encode(atom_t("pid"));
    eis.encode(pid);
    return eis.write();
}

//------------------------------------------------------------------------------
int send_ok(int transId, long value)
{
    eis.reset();
    eis.encodeTupleSize(2);
    eis.encode(transId);
    if (value < 0)
        eis.encode(atom_t("ok"));
    else {
        eis.encodeTupleSize(2);
        eis.encode(atom_t("ok"));
        eis.encode(value);
    }
    return eis.write();
}

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
bool set_cloexec_flag(int fd, bool value)
{
  int oldflags = fcntl(fd, F_GETFD, 0);
  // If reading the flags failed, return error indication now
  if (oldflags < 0)
    return oldflags;
  // Set just the flag we want to set
  oldflags = value ? (oldflags |  FD_CLOEXEC)
                   : (oldflags & ~FD_CLOEXEC);
  // Store modified flag word in the descriptor
  auto res = fcntl(fd, F_SETFD, oldflags) != -1;
  DEBUG(debug && !res, "Failed to %s FD_CLOEXEC on fd=%d", value ? "set":"clear", fd);
  return res;
}

//------------------------------------------------------------------------------
int open_file(const char* file, FileOpenFlag flag, const char* stream,
              ei::StringBuffer<128>& err, int mode)
{
    int flags = O_RDWR | (flag == READ ? 0 : O_CREAT) | int(flag) | O_CLOEXEC;
    int fd    = open(file, flags, mode);
    if (fd < 0) {
        err.write("Failed to redirect %s to file: %s", stream, strerror(errno));
        return -1;
    }
    DEBUG(debug, "  Redirecting [%s -> {file:%s, fd:%d}%s]",
          stream, file, fd, flag == TRUNCATE ? " (truncate)" :
                            flag == APPEND   ? " (append)"   : "");

    return fd;
}

//------------------------------------------------------------------------------
int open_pipe(int fds[2], const char* stream, ei::StringBuffer<128>& err)
{
#ifdef HAVE_PIPE2
    auto res = pipe2(fds, O_CLOEXEC);
#else
    auto res = pipe(fds);
#endif
    if (res < 0) {
        err.write("Failed to create a pipe for %s: %s", stream, strerror(errno));
        return -1;
    }
    if (fds[1] > max_fds) {
        close(fds[0]);
        close(fds[1]);
        err.write("Exceeded number of available file descriptors (fd=%d)", fds[1]);
        return -1;
    }
    DEBUG(debug, "  Redirecting [%s -> pipe:{r=%d,w=%d}]", stream, fds[0], fds[1]);

#ifndef HAVE_PIPE2
    if (!set_cloexec_flag(fds[0], true) || !set_cloexec_flag(fds[1], true)) {
        err.write("Failed to set CLOEXEC on pipe fds for %s: %s", stream, strerror(errno));
        return -1;
    }
#endif
    return 0;
}

//------------------------------------------------------------------------------
// This exists just to make sure that we don't inadvertently do a
// kill(-1, SIGKILL), which will cause all kinds of bad things to
// happen.
//------------------------------------------------------------------------------
int erl_exec_kill(pid_t pid, int signal, const char* srcloc) {
    if (pid == -1 || pid == 0) {
        DEBUG(debug, "kill(%d, %d) attempt prohibited!%s", pid, signal, srcloc);
        return -1;
    }

    int r = kill(pid, signal);

    if (signal > 0)
        DEBUG(debug, "Called kill(pid=%d, sig=%d) -> %d%s", pid, signal, r, srcloc);

    return r;
}

//------------------------------------------------------------------------------
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
        DEBUG(true, "  Set pid %d's fd=%d to non-blocking mode (flags=%x)",
              pid, fd, oldflags);
    }

    return ret;
}

//------------------------------------------------------------------------------
int CmdOptions::ei_decode(bool getcmd)
{
    // {Cmd::string()|binary()|[string()|binary()], [Option]}
    //      Option = {env, Strings::[string()]} | {cd, Dir::string()|binary()}
    //                                          | {kill, Cmd::string()|binary()}
    int sz;
    std::string op, val;

    m_err.str("");
    m_cmd.clear();
    m_kill_cmd.clear();
    m_env.clear();

    m_nice = std::numeric_limits<int>::max();

    if (getcmd) {
        std::string s;

        if (eis.decodeStringOrBinary(s) == 0) {
            m_cmd.push_front(s);
            m_shell=true;
        } else if ((sz = eis.decodeListSize()) > 0) {
            for (int i=0; i < sz; i++) {
                if (eis.decodeStringOrBinary(s) < 0) {
                    m_err << "badarg: invalid command argument #" << i;
                    return -1;
                }
                m_cmd.push_back(s);
            }
            eis.decodeListEnd();
            m_shell = false;
        } else {
            int n;
            m_err << "badarg: cmd string, binary, or non-empty list is expected (type="
                  << eis.decodeType(n) << ')';
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
        KILL_GROUP, NICE,              USER,    GROUP,
        DEBUG_OPT,  PTY_ECHO,          WINSZ
    } opt;
    const char* opts[] = {
        "stdin",      "stdout",            "stderr",
        "pty",        "success_exit_code", "cd", "env",
        "executable", "kill",              "kill_timeout",
        "kill_group", "nice",              "user",  "group",
        "debug",      "pty_echo",          "winsz"
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
                if (eis.decodeStringOrBinary(m_executable) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case CD:
                // {cd, Dir::string()}
                if (eis.decodeStringOrBinary(m_cd) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case DEBUG_OPT:
                if (eis.decodeInt(m_debug) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case KILL:
                // {kill, Cmd::string()}
                if (eis.decodeStringOrBinary(m_kill_cmd) < 0) {
                    m_err << op << " - bad option value"; return -1;
                }
                break;

            case GROUP: {
                // {group, integer() | string()}
                type = eis.decodeType(arity);
                if (type == etString || type == etBinary) {
                    if (eis.decodeStringOrBinary(val) < 0) {
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
                // {user, Dir::string()|binary()} | {kill, Cmd::string()|binary()}
                if (eis.decodeStringOrBinary(val) < 0) {
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
                // {env, [clear | NameEqualsValue::string()]}
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

                    if (type == etString || type == etBinary) {
                        res = !eis.decodeStringOrBinary(s);
                        if (res) {
                            size_t pos = s.find_first_of('=');
                            if (pos == std::string::npos)
                                res = false;
                            else
                                key = s.substr(0, pos);
                        }
                    } else if (type == etAtom && !eis.decodeAtom(s)) {
                        if (s != "clear") {
                            m_err << op << " - invalid env option " << s;
                            return -1;
                        }
                        // Request to clear environment
                        m_env_clear = true;
                        continue;
                    } else if (type == etTuple && sz == 2) {
                        eis.decodeTupleSize();
                        std::string val;
                        if (!eis.decodeStringOrBinary(key) && !key.empty()) {
                            bool bval;
                            if (!eis.decodeStringOrBinary(val)) {
                                res = true;
                                s   = val;
                            } else if (!eis.decodeBool(bval) && !bval) {
                                // {"VAR", false}  - this means to unset the variable
                                res = true;
                                s   = "";
                            } else {
                                res = false;
                            }
                        }
                    }

                    if (!res) {
                        m_err << op << " - invalid env argument #" << i;
                        return -1;
                    }
                    m_env[key] = s;
                }
                eis.decodeListEnd();
                break;
            }

            case PTY: {
                m_pty = true;
                // pty | {pty, [{echo, 1}, ...]}
                // see https://www.erlang.org/doc/man/ssh_connection.html#type-term_mode
                int opt_env_sz = eis.decodeListSize();
                if (opt_env_sz < 0) {
                    // this is ok, we've got just the atom pty
                    break;
                }
                for (int i=0; i < opt_env_sz; i++) {
                    std::string key;
                    int         val;

                    if (eis.decodeTupleSize() != 2 || eis.decodeAtom(key) < 0 || key.empty() ||
                        !eis.decodeIntOrBool(val))
                    {
                        m_err << op << " - invalid pty argument or value ";
                        if (!key.empty()) m_err << "'" << key << "'";
                        else              m_err << "#" << i;
                        return -1;
                    }

                    m_pty_opts[key] = val;
                }
                eis.decodeListEnd();
                break;
            }

            case PTY_ECHO:
                m_pty_echo = true;
                break;

            case WINSZ:
                if (eis.decodeType(arity) != etTuple ||
                    eis.decodeTupleSize() != 2       ||
		    eis.decodeInt(m_winsz_rows) < 0  ||
		    eis.decodeInt(m_winsz_cols) < 0)
		{
                    m_err << op << " - invalid winsz";
                    return -1;
                }
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
                    else if (type == ERL_STRING_EXT || type == ERL_BINARY_EXT)
                        eis.decodeStringOrBinary(s);
                    else {
                        m_err << op << " - atom or string value in tuple required";
                        return -1;
                    }

                    if (s == "null") {
                        stream_null(opt);
                        fdr = REDIRECT_NULL;
                    } else if (s == "close") {
                        stream_redirect(opt, REDIRECT_CLOSE);
                    } else if (s == "stderr" && opt == STDOUT) // Redirect STDOUT to STDERR
                        stream_redirect(opt, REDIRECT_STDERR);
                    else if (s == "stdout" && opt == STDERR)   // Redirect STDERR to STDOUT
                        stream_redirect(opt, REDIRECT_STDOUT);
                    else if (!s.empty()) {
                        stream_file(opt, s);                   // Redirect to file
                    }
                } else if (arity == 3) {
                    int n, sz, mode = DEF_MODE;
                    bool append = false;
                    std::string s, a, fop;
                    if (eis.decodeStringOrBinary(s) < 0) {
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

    DEBUG(debug > 1, "Parsed cmd '%s' options\r\n  (stdin=%s, stdout=%s, stderr=%s)",
          m_cmd.empty() ? "" : m_cmd.front().c_str(),
          stream_fd_type(0).c_str(), stream_fd_type(1).c_str(), stream_fd_type(2).c_str());

    return 0;
}

//------------------------------------------------------------------------------
int CmdOptions::init_cenv()
{
    if (m_env.empty()) {
        m_cenv = m_env_clear ? NULL : (const char**)environ;
        return 0;
    }

    // Copy environment of the caller process
    if (!m_env_clear)
        for (char **env_ptr = environ; *env_ptr; env_ptr++) {
            std::string s(*env_ptr);
            auto pos = s.find_first_of('=');
            std::string key(s.substr(0, pos));
            auto it = m_env.find(key);
            if (it == m_env.end())
                m_env[key] = s.substr(pos+1);
        }

    if ((m_cenv = (const char**) new char* [m_env.size()+1]) == NULL) {
        m_err << "Cannot allocate memory for " << m_env.size()+1 << " environment entries";
        return -1;
    }

    int i = 0;
    for (auto it = m_env.begin(), end = m_env.end(); it != end; ++it)
        if (it->second.empty()) // Unset the env variable
            continue;
        else {
            // Reformat the environment in the form: KEY=VALUE
            it->second = it->first + "=" + it->second;
            m_cenv[i++] = it->second.c_str();
        }

    m_cenv[i] = NULL;

    return 0;
}

} // namespace ei

