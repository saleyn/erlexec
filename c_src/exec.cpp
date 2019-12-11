// vim:ts=4:sw=4:et
/*
    exec.cpp

    Author:   Serge Aleynikov
    Created:  2003-07-10

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
                  {debug,Level::integer()}          |
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
            {pid, OsPid}            |       // For run command
            {ok, [OsPid]}           |       // For list command
            {ok, Int}               |       // For debug command
            {error, Reason}         |
            {exit_status, OsPid, Status}    // OsPid terminated with Status

    Reason = atom() | string()
    OsPid  = integer()
    Status = integer()
*/

#include "exec.hpp"

using namespace ei;

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------

ei::Serializer ei::eis(/* packet header size */ 2);

int   ei::debug           = 0;
int   ei::alarm_max_time  = FINALIZE_DEADLINE_SEC + 2;
bool  ei::terminated      = false; // indicates that we got a SIGINT / SIGTERM signal
bool  ei::pipe_valid      = true;
int   ei::max_fds;
int   ei::dev_null;
int   ei::sigchld_pipe[2] = { -1, -1 }; // Pipe for delivering sig child details
int   run_as_euid         = INT_MAX;

//-------------------------------------------------------------------------
// Types & variables
//-------------------------------------------------------------------------

MapChildrenT    ei::children;       // Map containing all managed processes
                                    // started by this port program.
MapKillPidT     ei::transient_pids; // Map of pids of custom kill commands.
ExitedChildrenT ei::exited_children;// Set of processed SIGCHLD events
pid_t           ei::self_pid;

//-------------------------------------------------------------------------
// Local Functions
//-------------------------------------------------------------------------
bool    process_command();
void    initialize(int userid, bool use_alt_fds, bool is_root,
                   bool requested_root);
int     finalize(fd_set& read_fds);

//-------------------------------------------------------------------------
// Local Functions
//-------------------------------------------------------------------------

void usage(char* progname) {
    fprintf(stderr,
        "Usage:\n"
        "   %s [-n] [-root] [-alarm N] [-debug [Level]] [-user User]\n"
        "Options:\n"
        "   -n              - Use marshaling file descriptors 3&4 instead of default 0&1.\n"
        "   --whoami        - Output the name of effective user and exit\n"
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
    int    userid         = 0;
    bool   use_alt_fds    = false;
    bool   is_root        = geteuid() == 0;
    bool   requested_root = false;

    self_pid = getpid();

    // Setup termination signal handlers
    sterm.sa_handler = gotsignal;
    sterm.sa_flags   = 0;
    sigemptyset(&sterm.sa_mask);
    sigaction(SIGINT,  &sterm, NULL);
    sigaction(SIGTERM, &sterm, NULL);
    sigaction(SIGHUP,  &sterm, NULL);
    sigaction(SIGPIPE, &sterm, NULL);

    // Process command arguments and do initialization
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
            } else if (strcmp(argv[res], "--whoami") == 0) {
                struct passwd* pws = getpwuid(geteuid());
                fprintf(stderr, "%s\n", pws->pw_name);
                exit(0);
            } else if (strcmp(argv[res], "-user") == 0 && res+1 < argc && argv[res+1][0] != '-') {
                char* run_as_user = argv[++res];
                struct stat    st;
                struct passwd *pw = NULL;
                requested_root    = strcmp(run_as_user, "root") == 0;
                if ((pw = getpwnam(run_as_user)) == NULL) {
                    fprintf(stderr, "User %s not found!\r\n", run_as_user);
                    exit(3);
                }
                run_as_euid = userid = pw->pw_uid;
                if (stat(argv[0], &st) < 0) {
                    fprintf(stderr, "Cannot stat the %s file: %s\r\n", argv[0],
                                    strerror(errno));
                    exit(3);
                }
                if (st.st_mode & S_ISUID && st.st_uid == 0)
                    is_root = true;
                if (debug > 2)
                    fprintf(stderr, "SUID bit %sset on %s owned by uid=%d\r\n",
                                    argv[0], (st.st_mode & S_ISUID) ? "" : " NOT", st.st_uid);
            }
        }
    }

    initialize(userid, use_alt_fds, is_root, requested_root);

    // Set up a pipe to deliver SIGCHLD details to pselect() and setup SIGCHLD handler
    if (pipe(sigchld_pipe) < 0) {
        fprintf(stderr, "Cannot create pipe: %s\r\n", strerror(errno));
        exit(3);
    }
    set_nonblock_flag(self_pid, sigchld_pipe[0], true);
    set_nonblock_flag(self_pid, sigchld_pipe[1], true);

    sact.sa_handler   = NULL;
    sact.sa_sigaction = gotsigchild;
    sact.sa_flags     = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP; // NOTE: use SA_RESTART (see sigaction(2))
    sigemptyset(&sact.sa_mask);
    sigaction(SIGCHLD, &sact, NULL);

    // Main processing loop
    while (!terminated) {

        FD_ZERO (&writefds);
        FD_ZERO (&readfds);

        FD_SET (eis.read_handle(), &readfds); // Erlang communication pipe
        FD_SET (sigchld_pipe[0],   &readfds); // pipe for delivering SIGCHLD signals

        int     maxfd  = std::max<int>(eis.read_handle(), sigchld_pipe[0]);
        double  wakeup = SLEEP_TIMEOUT_SEC;
        TimeVal now(TimeVal::NOW);

        // Set up all stdout/stderr input streams that we need to monitor and redirect to Erlang
        for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it)
            for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
                it->second.include_stream_fd(i, maxfd, &readfds, &writefds);
                if (!it->second.deadline.zero())
                    wakeup = std::max(0.1, std::min(wakeup, it->second.deadline.diff(now)));
            }

        if (terminated || wakeup < 0) break;

        int secs = int(wakeup);
        ei::TimeVal timeout(secs, int((wakeup - secs)*1000000.0 + 0.5));

        if (debug > 2)
            fprintf(stderr, "Selecting maxfd=%d (sleep={%ds,%dus})\r\n",
                    maxfd, timeout.sec(), timeout.usec());

        int cnt = select(maxfd+1, &readfds, &writefds, NULL, &timeout);
        int interrupted = (cnt < 0 && errno == EINTR);
        // Note that the process will not be interrupted while outside of pselectx()

        if (debug > 2)
            fprintf(stderr, "Select got %d events (maxfd=%d)%s\r\n",
                    cnt, maxfd, interrupted ?  " (interrupted)" : "");

        if (interrupted || cnt == 0) {
            now.now();
            if (check_children(now, terminated, pipe_valid) < 0) {
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
        } else if ( FD_ISSET (sigchld_pipe[0], &readfds) ) {
            if (!process_sigchld())
                break;
            now.now();
            if (check_children(now, terminated, pipe_valid) < 0) {
                terminated = 13;
                break;
            }
        } else if ( FD_ISSET (eis.read_handle(), &readfds) ) {
            // Read from input stream a command sent by Erlang
            if (!process_command())
                break;
        } else {
            // Check if any stdout/stderr streams have data
            for(MapChildrenT::iterator it=children.begin(), end=children.end(); it != end; ++it)
                for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++)
                    it->second.process_stream_data(i, &readfds, &writefds);
        }

    }

    return finalize(readfds);
}

bool process_command()
{
    int  err, arity;
    long transId;
    std::string command;

    // Note that if we were using non-blocking reads, we'd also need to check
    // for errno EWOULDBLOCK.
    if ((err = eis.read()) < 0) {
        if (debug)
            fprintf(stderr, "Broken Erlang command pipe (%d): %s [line:%d]\r\n",
                errno, strerror(errno), __LINE__);
        terminated = errno;
        return false;
    }

    /* Our marshalling spec is that we are expecting a tuple
     * TransId, {Cmd::atom(), Arg1, Arg2, ...}} */
    if (eis.decodeTupleSize() != 2 ||
        (eis.decodeInt(transId)) < 0 ||
        (arity = eis.decodeTupleSize()) < 1)
    {
        terminated = 12;
        return false;
    }

    enum CmdTypeT        {  MANAGE,  RUN,  STOP,  KILL,  LIST,  SHUTDOWN,  STDIN,  DEBUG, WINSZ  } cmd;
    const char* cmds[] = { "manage","run","stop","kill","list","shutdown","stdin","debug", "winsz" };

    /* Determine the command */
    if ((int)(cmd = (CmdTypeT) eis.decodeAtomIndex(cmds, command)) < 0) {
        if (send_error_str(transId, false, "Unknown command: %s", command.c_str()) < 0) {
            terminated = 13;
            return false;
        }
        return true;
    }

    switch (cmd) {
        case SHUTDOWN: {
            terminated = 0;
            return false;
        }
        case MANAGE: {
            // {manage, Cmd::string(), Options::list()}
            CmdOptions po;
            long       pid;
            pid_t      realpid;
            int        ret;

            if (arity != 3 || (eis.decodeInt(pid)) < 0 || po.ei_decode(eis) < 0 || pid <= 0) {
                send_error_str(transId, true, "badarg");
                return true;
            }
            realpid = pid;

            while ((ret = kill(pid, 0)) < 0 && errno == EINTR);

            if (ret < 0) {
                send_error_str(transId, true, "not_found");
                return true;
            }

            CmdInfo ci(true, po.kill_cmd(), realpid, po.success_exit_code(), po.kill_group());
            ci.kill_timeout = po.kill_timeout();
            children[realpid] = ci;

            // Set nice priority for managed process if option is present
            std::string error;
            set_nice(realpid,po.nice(),error);

            send_pid(transId, pid);
            break;
        }
        case RUN: {
            // {run, Cmd::string(), Options::list()}
            CmdOptions po(run_as_euid);

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
                send_pid(transId, pid);
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
        case WINSZ: {
            // {winsz, OsPid::integer(), rows::integer(), cols::integer()}
            long pid, rows, cols;
            if (arity != 4
                || eis.decodeInt(pid) < 0
                || eis.decodeInt(rows) < 0
                || eis.decodeInt(cols) < 0) {
                send_error_str(transId, true, "badarg");
                break;
            }
            MapChildrenT::iterator it = children.find(pid);
            if (it == children.end()) {
                if (debug)
                    fprintf(stderr, "pid %ld doesn't exist\r\n", pid);
                break;
            }
            set_pid_winsz(it->second, rows, cols);
            break;
        }
            
        case STDIN: {
            // {stdin, OsPid::integer(), Data::binary()}
            long pid;
            std::string data;
            std::string s;
            bool eof = false;
            if (arity != 3 || eis.decodeInt(pid) < 0 ||
                    (eis.decodeBinary(data) < 0 &&
                     (eis.decodeAtom(s) < 0 || !(eof = (s == "eof")))
                     )) {
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

            if (eof) {
                close_stdin(it->second);
                break;
            }

            if (!data.size()) {
                if (debug)
                    fprintf(stderr, "Warning: ignoring empty input on stdin of pid %ld.\r\n", pid);
                break;
            }

            it->second.stdin_queue.push_front(data);
            process_pid_input(it->second);
            break;
        }
        case DEBUG: {
            // {debug, Level::integer()}
            long level;
            if (arity != 2 || eis.decodeInt(level) < 0 || level < 0 || level > 10) {
                send_error_str(transId, true, "badarg");
                break;
            }
            int old = debug;
            debug   = level;
            send_ok(transId, old);
            break;
        }
    }
    return true;
}

int ei::set_euid(int userid)
{
    #ifdef HAVE_SETRESUID
    int res = setresuid(-1, userid, geteuid()); // glibc, FreeBSD, OpenBSD, HP-UX
    #elif HAVE_SETREUID
    int res = setreuid(-1,  userid);            // MacOSX, NetBSD, AIX, IRIX, Solaris>=2.5, OSF/1, Cygwin
    #else
    #error setresuid(3) not supported!
    #endif
    return res < 0 ? res : geteuid();
}

void initialize(int userid, bool use_alt_fds, bool is_root, bool requested_root)
{
    // In root mode, we are running exec-port as another effective
    // user `userid`, and the spawned child processes to be the
    // effective user `userid` by default, unless overriden in the
    // `{user, User}` option by the executed command (in which case
    // only users from the `{limit_users, Users}` list are permitted
    // to be effective users.

    if (is_root && userid == 0 && !requested_root) {
        fprintf(stderr, "Not allowed to run as root without setting effective user (-user option)!\r\n");
        exit(4);
    } else if (!is_root && userid == 0 && requested_root) {
        fprintf(stderr, "Requested to run as root (-user root), but effective user is not root!\r\n");
        exit(4);
    } else if (!is_root && userid > 0 && int(geteuid()) != userid) {
        fprintf(stderr, "Cannot switch effective user to euid=%d\r\n", userid);
        exit(4);
    } else if (!getenv("SHELL") || strcmp(getenv("SHELL"), "") == 0) {
        fprintf(stderr, "SHELL environment variable not set!\r\n");
        exit(4);
    }

    // (is_root && requested_root && userid > 0)
    // Make sure that we can switch effective user without issues
    if (userid > 0 && ei::set_euid(userid) < 0) {
        fprintf(stderr, "Failed to set effective userid: %s\r\n", strerror(errno));
        exit(4);
    }

    if (debug)
        fprintf(stderr, "Initializing: uid=%d, userid=%d%s%s\r\n",
            getuid(), userid, is_root ? " is-root":"",
            requested_root ? " requested-root":"");

    // If we were root, set capabilities
    // to be able to adjust niceness and run commands as other users.
    // unless run_as_root is set
    if (userid > 0 && is_root) {
        #ifdef HAVE_CAP
        if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
            perror("Failed to call prctl to keep capabilities");
            exit(5);
        }
        #endif

        struct passwd* pw;
        if (debug && (pw = getpwuid(geteuid())) != NULL)
            fprintf(stderr, "exec: running as: %s (euid=%d)\r\n", pw->pw_name, geteuid());

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

        if (debug) {
            cur = cap_get_proc();
            fprintf(stderr, "exec: current capabilities: %s\r\n", cur ? cap_to_text(cur, NULL) : "none");
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

int finalize(fd_set& readfds)
{
    if (debug) fprintf(stderr, "Setting alarm to %d seconds\r\n", alarm_max_time);
    alarm(alarm_max_time);  // Die in <alarm_max_time> seconds if not done

    int old_terminated = terminated;
    terminated = 0;

    kill(0, SIGTERM); // Kill all children in our process group

    TimeVal now(TimeVal::NOW);
    TimeVal deadline(now, FINALIZE_DEADLINE_SEC, 0);

    while (children.size() > 0) {
        now.now();
        if (children.size() > 0 || !exited_children.empty()) {
            bool term = false;
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

        while (true) {
            TimeVal timeout(TimeVal::NOW);
            if (deadline < timeout)
                break;

            timeval ts = (deadline - timeout).timeval();

            FD_ZERO(&readfds);
            FD_SET (sigchld_pipe[0], &readfds); // pipe for delivering SIGCHLD signals

            int maxfd = std::max<int>(eis.read_handle(), sigchld_pipe[0]);
            int cnt;
            while ((cnt = select(maxfd+1, &readfds, NULL, NULL, &ts)) < 0 && errno == EINTR);

            if (cnt < 0) {
                fprintf(stderr, "Error in finalizing pselect(2): %s\r\n", strerror(errno));
                break;
            } else if (cnt > 0 && FD_ISSET(sigchld_pipe[0], &readfds) ) {
                if (!process_sigchld())
                    break;
            }
        }
    }

    if (debug)
        fprintf(stderr, "Exiting (%d)\r\n", old_terminated);

    return old_terminated;
}
