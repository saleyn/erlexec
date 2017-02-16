// vim:ts=4:sw=4:et
#include "exec.hpp"
#include <errno.h>

namespace ei {

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

    if (debug && n < 0 && errno != EAGAIN)
        fprintf(stderr, "Error reading from sigchld pipe descriptor: %s\r\n", strerror(errno));

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

    if (nice != INT_MAX && setpriority(PRIO_PROCESS, pid, nice) < 0) {
        err.write("Cannot set priority of pid %d to %d", pid, nice);
        error = err.c_str();
        if (debug)
            fprintf(stderr, "%s\r\n", error.c_str());
        return -1;
    }
    return 0;
}

//------------------------------------------------------------------------------
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
            close_stdin(ci);
            return true;
        }

        ci.stdin_queue.pop_back();
        ci.stdin_wr_pos = 0;
    }

    return true;
}

//------------------------------------------------------------------------------
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
        check_child_exit(ci.cmd_pid);
}

//------------------------------------------------------------------------------
int getpty(int& fdmp, ei::StringBuffer<128>& err) {
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

    if (debug)
        fprintf(stderr, "  Opened PTY master=%d\r\n", fdm);

    return 0;
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
    int fdm;

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
                        sfd[RD] = -1; // fix these up later in the child process when I open my slave pty
                        sfd[WR] = fdm;
                    } else {
                        sfd[WR] = -1;
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
	int r;
	
	if (op.pty()) {
	    int fds;
	    char pts_name[256];
	    
	    // have to open the pty slave in the child, otherwise TIOCSCTTY will fail later
	    r = ptsname_r(fdm, pts_name, sizeof(pts_name));
	    if( r < 0 ) {
		fprintf(stderr, "ptsname_r(%d) failed: %s\n", fdm, strerror(errno));
		exit(1);
	    }
	    fds = open(pts_name, O_RDWR);
	    if (fds < 0) {
		fprintf(stderr, "open slave pty %s failed: %s\n", pts_name, strerror(errno));
		exit(1);
	    }
	    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
		int* sfd = stream_fd[i];
		int  cfd = op.stream_fd(i);
		if( cfd == REDIRECT_ERL ) {
		    if (i == STDIN_FILENO) {
			sfd[RD] = fds;
		    } else {
			sfd[WR] = fds;
		    }
                    if (debug)
                        fprintf(stderr, "  Redirecting [%s -> pipe:{r=%d,w=%d}] (PTY)\r\n",
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

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
void close_stdin(CmdInfo& ci)
{
    int& fd = ci.stream_fd[STDIN_FILENO];

    if (fd < 0) return;
    if (debug)
        fprintf(stderr, "Eof writing pid %d's stdin, closing fd=%d: %s\r\n",
                ci.cmd_pid, fd, strerror(errno));
    ci.stdin_wr_pos = 0;
    close(fd);
    fd = REDIRECT_CLOSE;
    ci.stdin_queue.clear();
    return;
}

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
int check_children(const TimeVal& now, bool& isTerminated, bool notify)
{
    if (debug > 2)
        fprintf(stderr, "Checking %ld running children (exited count=%ld)\r\n",
            children.size(), exited_children.size());

    for (auto it=children.begin(), end=children.end(); !isTerminated && it != end; ++it)
        check_child(now, it->first, it->second);

    if (debug > 2)
        fprintf(stderr, "Checking %ld exited children (notify=%d)\r\n",
            exited_children.size(), notify);

    // For each process info in the <exited_children> queue deliver it to the Erlang VM
    // and remove it from the managed <children> map.
    for (auto it=exited_children.begin(); !isTerminated && it!=exited_children.end();)
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

//------------------------------------------------------------------------------
void check_child(const TimeVal& now, pid_t pid, CmdInfo& cmd)
{
    if (pid == self_pid)    // Safety check. Never kill itself
        return;

    int n = erl_exec_kill(pid, 0);

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
                if (debug)
                    fprintf(stderr, "Pid %d %swas stopped by delivery of a signal %d\r\n",
                        pid, cmd.managed ? "(managed) " : "", WSTOPSIG(status));
            } else if (WIFCONTINUED(status)) {
                if (debug)
                    fprintf(stderr, "Pid %d %swas resumed by delivery of SIGCONT\r\n",
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

    while ((ret = waitpid(pid, &status, WNOHANG)) < 0 && errno == EINTR);

    if (debug)
        fprintf(stderr,
            "* Process %d (ret=%d, status=%d, exited_count=%ld%s%s)\r\n",
            pid, ret, status, exited_children.size(),
            ret > 0 && WIFEXITED(status) ? " [exited]":"",
            ret > 0 && WIFSIGNALED(status) ? " [signaled]":"");

    if (ret < 0 && errno == ECHILD) {
        if (erl_exec_kill(pid, 0) == 0) // process likely forked and is alive
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

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
// This exists just to make sure that we don't inadvertently do a
// kill(-1, SIGKILL), which will cause all kinds of bad things to
// happen.
//------------------------------------------------------------------------------
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
        fprintf(stderr, "  Set pid %d's fd=%d to non-blocking mode (flags=%x)\r\n",
            pid, fd, oldflags);
    }

    return ret;
}

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
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

} // namespace ei

