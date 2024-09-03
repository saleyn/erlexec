%%% vim:ts=4:sw=4:et
-module(exec).
-moduledoc """
OS shell command runner.
It communicates with a separate C++ port process `exec-port`
spawned by this module, which is responsible
for starting, killing, listing, terminating, and notifying of
state changes.

The port program serves as a middle-man between
the OS and the virtual machine to carry out OS-specific low-level
process control.  The Erlang/C++ protocol is described in the
`exec.cpp` file.  The `exec` application can execute tasks by
impersonating as a different effective user.  This impersonation
can be accomplished in one of the following two ways (assuming
that the emulator is not running as `root`:

- Having the user account running the erlang emulator added to
  the `/etc/sudoers` file, so that it can execute `exec-port`
  task as `root`. (Preferred option)
- Setting `root` ownership on `exec-port`, and setting the
  SUID bit: `chown root:root exec-port; chmod 4755 exec-port`.
  (This option is discouraged as it's less secure).

In either of these two cases, `exec:start_link/2` must be started
with options `[root, {user, User}, {limit_users, Users}]`,
so that `exec-port` process will not actually run as
root but will switch to the effective `User`, and set the kernel
capabilities so that it's able to start processes as other
effective users given in the `Users` list and adjust process
priorities.

Though, in the initial design, `exec` prohibited such use, upon
user requests a feature was added (in order to support `docker`
deployment and CI testing) to be able to execute `exec-port` as
`root` without switching the effective user to anying other than
`root`. To accomplish this use the following options to start
`exec`: `[root, {user, "root"}, {limit_users, ["root"]}]`.

At exit the port program makes its best effort to perform
clean shutdown of all child OS processes.
Every started OS process is linked to a spawned light-weight
Erlang process returned by the run/2, run_link/2 command.
The application ensures that termination of spawned OsPid
leads to termination of the associated Erlang Pid, and vice
versa.
""".
-author('saleyn@gmail.com').

-behaviour(gen_server).

%% External exports
-export([
    start/0, start/1, start_link/1, run/2, run/3,
    run_link/2, run_link/3,
    manage/2, send/2, winsz/3, pty_opts/2,
    which_children/0, kill/2,       setpgid/2, stop/1, stop_and_wait/2,
    ospid/1, pid/1,   status/1,     signal/1,  signal_to_int/1, debug/1
]).

%% Internal exports
-export([default/0, default/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-include("exec.hrl").
-include_lib("kernel/include/file.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(TIMEOUT, 30000).

-record(state, {
    port,
    last_trans  = 0,            % Last transaction number sent to port
    trans       = queue:new(),  % Queue of outstanding transactions sent to port
    limit_users = [],           % Restricted list of users allowed to run commands
    registry,                   % Pids to notify when an OsPid exits
    debug       = false,
    root        = false
}).

-type exec_options() :: [exec_option()].
-doc """
Options passed to the exec process at startup. They can be specified in the
`sys.config` file for the `erlexec` application to customize application
startup.
- `debug`
  : Same as `{debug, 1}`
- `{debug, Level}`
  : Enable port-programs debug trace at `Level`.
- `verbose`
  : Enable verbose prints of the Erlang process.
- `root | {root, Boolean}`
  : Allow running child processes as root.
- `{args, Args}`
  : Append `Args` to the port command.
- `{alarm, Secs}`
  : Give `Secs` deadline for the port program to clean up
    child pids before exiting
- `{user, User}`
  : When the port program was compiled with capability (Linux)
    support enabled, and is owned by root with a a suid bit set,
    this option must be specified so that upon startup the port
    program is running under the effective user different from root.
    This is a security measure that will also prevent the port program
    to execute root commands.
- `{limit_users, LimitUsers}`
  : Limit execution of external commands to these set of users.
    This option is only valid when the port program is owned
    by root.
- `{portexe, Exe}`
  : Provide an alternative location of the port program.
    This option is useful when this application is stored
    on NFS and the port program needs to be copied locally
    so that root suid bit can be set.
- `{env, Env}`
  : Extend environment of the port program by using `Env` specification.
    `Env` should be a list of tuples `{Name, Val}`, where Name is the
    name of an environment variable, and Val is the value it is to have
    in the spawned port process. If Val is `false`, then the `Name`
    environment variable is unset.
""".
-type exec_option()  ::
      debug
    | {debug, integer()}
    | root | {root, boolean()}
    | verbose
    | {args, [string()|binary(), ...]}
    | {alarm, non_neg_integer()}
    | {user, string()|binary()}
    | {limit_users, [string()|binary(), ...]}
    | {portexe, string()|binary()}
    | {env, [{string()|binary(), string()|binary()|false}, ...]}.
-export_type([exec_option/0, exec_options/0]).

-doc """
Command to be executed. If specified as a string, the specified command
will be executed through the shell. The current shell is obtained
from environment variable `SHELL`. This can be useful if you
are using Erlang primarily for the enhanced control flow it
offers over most system shells and still want convenient
access to other shell features such as shell pipes, filename
wildcards, environment variable expansion, and expansion of
`~` to a user's home directory.  All command arguments must
be properly escaped including whitespace and shell
metacharacters.

Any part of the command string can contain unicode characters.

**Warning:** Executing shell commands that
incorporate unsanitized input from an untrusted source makes
a program vulnerable to
[shell injection](http://en.wikipedia.org/wiki/Shell_injection#Shell_injection),
a serious security flaw which can result in arbitrary command
execution. For this reason, the use of `shell` is strongly
discouraged in cases where the command string is constructed
from external input:

```
 1> {ok, Filename} = io:read("Enter filename: ").
 Enter filename: "non_existent; rm -rf / #".
 {ok, "non_existent; rm -rf / #"}
 2> exec(Filename, []) % Argh!!! This is not good!
```

When command is given in the form of a list of strings,
it is passed to `execve(3)` library call directly without
involving the shell process, so the list of strings
represents the program to be executed given with a full path,
followed by the list of arguments (e.g. `["/bin/echo", "ok"]`).
In this case all shell-based features are disabled
and there's no shell injection vulnerability.
""".
-type cmd() :: binary() | string() | [string()].
-export_type([cmd/0]).

-type cmd_options() :: [cmd_option()].
-doc """
Command options:
- `monitor`
  : Set up a monitor for the spawned process. The monitor is not
    a standard `erlang:montior/2` function call, but it's emulated
    by ensuring that the monitoring process receives notification
    in the form:
    `{'DOWN', OsPid::integer(), process, Pid::pid(), Reason}`.
    If the `Reason` is `normal`, then process exited with status `0`,
    otherwise there was an error. If the Reason is `{status, Status}`
    the returned `Status` can be decoded with `status/1` to determine
    the exit code of the process and if it was killed by signal.
- `sync`
  : Block the caller until the OS command exits
- `{executable, Executable::string()}`
  : Specifies a replacement program to execute. It is very seldom
    needed. When the port program executes a child process using
    `execve(3)` call, the call takes the following arguments:
    `(Executable, Args, Env)`. When `Cmd` argument passed to the
    `run/2` function is specified as the list of strings,
    the executable replaces the first parameter in the call, and
    the original args provided in the `Cmd` parameter are passed as
    as the second parameter. Most programs treat the program
    specified by args as the command name, which can then be different
    from the program actually executed. On Unix, the args name becomes
    the display name for the executable in utilities such as `ps`.

    If `Cmd` argument passed to the `run/2` function is given as a
    string, on Unix the `Executable` specifies a replacement shell
    for the default `/bin/sh`.
- `{cd, WorkDir}`
  : Working directory
- `{env, Env :: [{Name,Value}|string()|clear]}`
  : List of "VAR=VALUE" environment variables or
    list of {Name, Value} tuples or strings (like "NAME=VALUE") or `clear`.
    `clear` will clear environment of a spawned child OS process
    (so that it doesn't inherit parent's environment).
    If `Value` is `false` then the `Var` env variable is unset.
- `{kill, KillCmd}`
  : This command will be used for killing the process. After
    a 5-sec timeout if the process is still alive, it'll be
    killed with SIGKILL. The kill command will have a `CHILD_PID`
    environment variable set to the pid of the process it is
    expected to kill.  If the `kill` option is not specified,
    by default first the command is sent a `SIGTERM` signal,
    followed by `SIGKILL` after a default timeout.
- `{kill_timeout, Sec::integer()}`
  : Number of seconds to wait after issuing a SIGTERM or
    executing the custom `kill` command (if specified) before
    killing the process with the `SIGKILL` signal
- `kill_group`
  : At process exit kill the whole process group associated with this pid.
    The process group is obtained by the call to getpgid(3).
- `{group, GID}`
  : Sets the effective group ID of the spawned process. The value 0
    means to create a new group ID equal to the OS pid of the process.
- `{user, RunAsUser}`
  : When exec-port was compiled with capability (Linux) support
    enabled and has a suid bit set, it's capable of running
    commands with a different RunAsUser effective user. Passing
    "root" value of `RunAsUser` is prohibited.
- `{success_exit_code, IntExitCode}`
  : On success use `IntExitCode` return value instead of default 0.
- `{nice, Priority}`
  : Set process priority between -20 and 20. Note that
    negative values can be specified only when `exec-port`
    is started with a root suid bit set.
- `stdin | {stdin, null | close | Filename}`
  : Enable communication with an OS process via its `stdin`. The
    input to the process is sent by `exec:send(OsPid, Data)`.
    When specified as a tuple, `null` means redirection from `/dev/null`,
    `close` means to close `stdin` stream, and `Filename` means to
    take input from file.
- `stdout`
  : Same as `{stdout, self()}`.
- `stderr`
  : Same as `{stderr, self()}`.
- `{stdout, output_device()}`
  : Redirect process's standard output stream
- `{stderr, output_device()}`
  : Redirect process's standard error stream
- `{stdout | stderr, Filename::string(), [output_dev_opt()]}`
  : Redirect process's stdout/stderr stream to file
- `{winsz, {Rows, Cols}}`
  : Set the (psudo) terminal's dimensions of rows and columns
- `pty`
  : Use pseudo terminal for the process's stdin, stdout and stderr
- `pty_echo`
  : Allow the pty to run in echo mode, disabled by default
- `{capabilities, all | [capability()]}`
  : Capability names to inherit from the parent `exec-port` process.
    See [capability()](#t:capability/0).
- `debug`
  : Same as `{debug, 1}`
- `{debug, Level::integer()}`
  : Enable debug printing in port program for this command
""".
-type cmd_option()  ::
      monitor
    | sync
    | link
    | {executable, string()|binary()}
    | {cd, WorkDir::string()|binary()}
    | {env, [string() | clear | {Name::string()|binary(), Val::string()|binary()|false}, ...]}
    | {kill, KillCmd::string()|binary()}
    | {kill_timeout, Sec::non_neg_integer()}
    | kill_group
    | {group, GID :: string()|binary() | integer()}
    | {user, RunAsUser :: string()|binary()}
    | {nice, Priority :: integer()}
    | {success_exit_code, ExitCode :: integer() }
    | stdin  | {stdin, null | close | string()|binary()}
    | stdout | stderr
    | {stdout, stderr | output_dev_opt()}
    | {stderr, stdout | output_dev_opt()}
    | {stdout | stderr, string()|binary(), [output_file_opt()]}
    | {winsz, {Rows::non_neg_integer(), Cols::non_neg_integer()}}
    | pty | {pty, pty_opts()}
    | pty_echo
    | debug | {debug, integer()}.
-export_type([cmd_option/0, cmd_options/0]).

-doc """
Output device option:
- `null`
  : Suppress output.
- `close`
  : Close file descriptor for writing.
- `print`
  : A debugging convenience device that prints the output to the
    console shell
- `Filename`
  : Save output to file by overwriting it.
- `pid()`
  : Redirect output to this pid.
- `fun((Stream, OsPid, Data) -> none())`
  : Execute this callback on receiving output data
""".
-type output_dev_opt() :: null | close | print | string() | binary() | pid()
    | fun((stdout | stderr, integer(), binary()) -> none()).
-export_type([output_dev_opt/0]).

-doc """
Defines file opening attributes:
- `append`
  : Open the file in `append` mode
- `{mode, Mode}`
  : File creation access mode <b>specified in base 8</b> (e.g. 8#0644)
""".
-type output_file_opt() :: append | {mode, Mode::integer()}.
-export_type([output_file_opt/0]).

-doc "Representation of OS process ID".
-type ospid() :: integer().
-doc "Representation of OS group ID".
-type osgid() :: integer().
-export_type([ospid/0, osgid/0]).

-type tty_char() ::
    vintr  | vquit  | verase  | vkill  | veof     | veol    | veol2  |
    vstart | vstop  | vsusp   | vdsusp | vreprint | vwerase | vlnext |
    vflush | vswtch | vstatus | vdiscard.
-type tty_mode() ::
    ignpar | parmrk | inpck  | istrip | inlcr   | igncr  | icrnl  | xcase   |
    iuclc  | ixon   | ixany  | ixoff  | imaxbel | iutf8  | isig   | icanon  |
    echo   | echoe  | echok  | echonl | noflsh  | tostop | iexten | echoctl |
    echoke | pendin | opost  | olcuc  | onlcr   | ocrnl  | onocr  | onlret  |
    cs7    | cs8    | parenb | parodd.
-type tty_speed() :: tty_op_ispeed | tty_op_ospeed.

-doc """
For Linux platform that supports capabilities this type defines permissible
capability options.
* `chown`: Make arbitrary changes to file UIDs and GIDs.      
* `dac_override`: Bypass file read, write, and execute permission checks.
* `dac_read_search`: Bypass file read permission checks and directory read and
execute permission checks.
* `fowner`: Bypass permission checks on operations that normally require the file 
system UID of the process to match the UID of the file.
* `fsetid`: Don't clear set-user-ID and set-group-ID permission bits when a file is 
modified; set the set-group-ID bit for a file whose GID does not match the file 
system or any of the supplementary GIDs of the calling process.
* `ipc_lock`: Lock memory.                                    
* `ipc_owner`: Bypass permission checks for operations on System V IPC objects.
* `kill`: Bypass permission checks for sending signals.       
* `lease`: Establish leases on arbitrary files.               
* `linux_immutable`: Set the FS_APPEND_FL and FS_IMMUTABLE_FL i-node flags.
* `mac_admin`: Override Mandatory Access Control.             
* `mac_override`: Allow MAC configuration or state changes.   
* `mknod`: Create special files using.                        
* `net_admin`: Perform various network-related operations.    
* `net_bind_service`: Bind a socket to Internet domain privileged ports.
* `net_broadcast`: (Unused) Make socket broadcasts, and listen to multicasts.
* `net_raw`: Use RAW and PACKET sockets                   
* `setgid`: Make arbitrary manipulations of process GIDs and supplementary GID list;
forge GID when passing socket credentials via UNIX domain sockets.
* `setfcap`: Set file capabilities.                           
* `setpcap`: If file capabilities are not supported: grant or remove any capability
in the caller's permitted capability set to or from any other process.
* `setuid`: Make arbitrary manipulations of process UIDs; make forged UID when
passing socket credentials via UNIX domain sockets.
* `sys_admin`: Perform a range of system administration operations including:
`quotactl(2)`, `mount(2)`, `umount(2)`, `swapon(2)`, `swapoff(2)`, `sethostname(2)`,
and `setdomainname(2)`.
* `sys_boot`: Use `reboot(2)` and `kexec_load(2)`.            
* `sys_chroot`: Use `chroot(2)`.                              
* `sys_module`: Load and unload kernel modules; in kernels before 2.6.25: drop
capabilities from the system-wide capability bounding set.
* `sys_nice`: Raise process nice value (`nice(2)`, `setpriority(2)`) and change the
nice value for arbitrary processes.
* `sys_pacct`: Use `acct(2)`.                                 
* `sys_ptrace`: Trace arbitrary processes using `ptrace(2)`;
apply `get_robust_list(2)` to arbitrary processes; inspect processes using `kcmp(2)`.
* `sys_rawio`: Perform I/O port operations (`iopl(2)` and `ioperm(2)`).
* `sys_resource`: Use reserved space on ext2 file systems.    
* `sys_time`: Set system clock.                               
* `sys_tty_config`: Use `vhangup(2)`; employ various privileged `ioctl(2)` operations
on virtual terminals.
* `syslog`: Perform privileged `syslog(2)` operations. See `syslog(2)` for
information on which operations require privilege.
* `wake_alarm`: Trigger something that will wake up the system.

""".
-type capability() ::
    chown | dac_override | dac_read_search | fowner |
    fsetid | kill | setgid | setuid | setpcap | 
    linux_immutable | net_bind_service | net_broadcast |
    net_admin | net_raw | ipc_lock | ipc_owner | sys_module |
    sys_rawio | sys_chroot | sys_ptrace | sys_pacct | 
    sys_admin | sys_boot | sys_nice | sys_resource | sys_time | 
    sys_tty_config | mknod | lease | audit_write | audit_control |
    setfcap | mac_override | mac_admin | syslog | wake_alarm |
    block_suspend.
-export_type([capability/0]).

-doc """
Pty options.

See [termios(3)](https://man7.org/linux/man-pages/man3/termios.3.html).
See [RFC4254](https://datatracker.ietf.org/doc/html/rfc4254#section-8).

- `{tty_char(), Byte}`
  : A special character with value from 0 to 255
- `{tty_mode(), Enable}`
  : Enable/disable a tty mode
- `{tty_speed(), Speed}`
  : Specify input or output baud rate. Provided for
    completeness. Not useful for pseudo terminals.
""".
-type pty_opt()   :: {tty_char(), byte()}
    | {tty_mode(),  boolean()|0|1}
    | {tty_speed(), non_neg_integer()}.

-doc "List of pty options".
-type pty_opts() :: list(pty_opt()).

-export_type([pty_opt/0, pty_opts/0]).

%%-------------------------------------------------------------------------
-doc """
Supervised start an external program manager.

Note that the port program requires `SHELL` environment variable to be set.
""".
-spec start_link(exec_options()) -> {ok, pid()} | {error, any()}.
start_link(Options) when is_list(Options) ->
    % Debug = {debug, [trace, log, statistics, {log_to_file, "./execserver.log"}]},
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []). % , [Debug]).

%%-------------------------------------------------------------------------
-doc #{equiv => start_link/1}.
-doc """
Start of an external program manager without supervision.
Note that the port program requires `SHELL` environment variable to
be set.
""".
-spec start() -> {ok, pid()} | {error, any()}.
start() ->
    start([]).

-spec start(exec_options()) -> {ok, pid()} | {error, any()}.
start(Options) when is_list(Options) ->
    case check_options(Options) of
        ok ->
            gen_server:start({local, ?MODULE}, ?MODULE, [Options], []);
        {error, Reason} ->
            {error, Reason}
    end.

%%-------------------------------------------------------------------------
-doc """
Run an external program. `OsPid` is the OS process identifier of
the new process. If `sync` is specified in `Options` the return
value is `{ok, Status}` where `Status` is OS process exit status.
The `Status` can be decoded with `status/1` to determine the
process's exit code and if it was killed by signal.
""".
-spec run(cmd(), cmd_options(), integer()) ->
    {ok, pid(), ospid()} | {ok, [{stdout | stderr, [binary()]}]} | {error, any()}.
run(Exe, Options, Timeout) when (is_binary(Exe)  orelse  is_list(Exe))
                        andalso is_list(Options) andalso is_integer(Timeout) ->
    do_run({run, Exe, Options}, Options, Timeout).
run(Exe, Options) ->
    run(Exe, Options, ?TIMEOUT).

%%-------------------------------------------------------------------------
-doc #{equiv => run/2}.
-doc """
Run an external program and link to the OsPid. If OsPid exits,
the calling process will be killed or if it's trapping exits,
it'll get {'EXIT', OsPid, Status} message.  If the calling process
dies the OsPid will be killed.
The `Status` can be decoded with `status/1` to determine the
process's exit code and if it was killed by signal.
""".
-spec run_link(cmd(), cmd_options(), integer()) ->
    {ok, pid(), ospid()} | {ok, [{stdout | stderr, [binary()]}]} | {error, any()}.
run_link(Exe, Options, Timeout) when (is_binary(Exe)  orelse  is_list(Exe))
                             andalso is_list(Options) andalso is_integer(Timeout) ->
    do_run({run, Exe, Options}, [link | Options], Timeout).
run_link(Exe, Options) ->
    run_link(Exe, Options, ?TIMEOUT).

%%-------------------------------------------------------------------------
-doc """
Manage an existing external process. `OsPid` is the OS process
identifier of the external OS process or an Erlang `Port` that
would be managed by erlexec.
""".
-spec manage(ospid() | port(), Options::cmd_options(), Timeout::integer()) ->
    {ok, pid(), ospid()} | {error, any()}.
manage(Pid, Options, Timeout) when is_integer(Pid), is_integer(Timeout) ->
    do_run({manage, Pid, Options}, Options, Timeout);
manage(Port, Options, Timeout) when is_port(Port), is_integer(Timeout) ->
    {os_pid, OsPid} = erlang:port_info(Port, os_pid),
    manage(OsPid, Options, Timeout).
manage(Port, Options) ->
    manage(Port, Options, ?TIMEOUT).

%%-------------------------------------------------------------------------
-doc "Get a list of children managed by port program".
-spec which_children() -> [ospid(), ...].
which_children() ->
    gen_server:call(?MODULE, {port, {list}}).

%%-------------------------------------------------------------------------
-doc "Send a `Signal` to a child `Pid`, `OsPid` or an Erlang `Port`".
-spec kill(pid() | ospid(), atom()|integer()) -> ok | {error, any()}.
kill(Pid, Signal) when is_atom(Signal) ->
    kill(Pid, signal_to_int(Signal));
kill(Pid, Signal) when (is_pid(Pid) orelse is_integer(Pid))
                       andalso is_integer(Signal) ->
    gen_server:call(?MODULE, {port, {kill, Pid, Signal}});
kill(Port, Signal) when is_port(Port) ->
    {os_pid, Pid} = erlang:port_info(Port, os_pid),
    kill(Pid, Signal).

%%-------------------------------------------------------------------------
-doc "Change group ID of a given `OsPid` to `Gid`".
-spec setpgid(ospid(), osgid()) -> ok | {error, any()}.
setpgid(OsPid, Gid) when is_integer(OsPid), is_integer(Gid) ->
    gen_server:call(?MODULE, {port, {setpgid, OsPid, Gid}}).

%%-------------------------------------------------------------------------
-doc """
Terminate a managed `Pid`, `OsPid`, or `Port` process. The OS process is
terminated gracefully.  If it was given a `{kill, Cmd}` option at
startup, that command is executed and a timer is started.  If
the program doesn't exit, then the default termination is
performed.  Default termination implies sending a `SIGTERM` command
followed by `SIGKILL` in 5 seconds, if the program doesn't get
killed.
""".
-spec stop(pid() | ospid() | port()) -> ok | {error, any()}.
stop(Pid) when is_pid(Pid); is_integer(Pid) ->
    gen_server:call(?MODULE, {port, {stop, Pid}}, 30000);
stop(Port) when is_port(Port) ->
    {os_pid, Pid} = erlang:port_info(Port, os_pid),
    stop(Pid).

%%-------------------------------------------------------------------------
-doc """
Terminate a managed `Pid`, `OsPid`, or `Port` process, like
`stop/1`, and wait for it to exit.
""".
-spec stop_and_wait(pid() | ospid() | port(), integer()) -> term() | {error, any()}.
stop_and_wait(Port, Timeout) when is_port(Port) ->
    {os_pid, OsPid} = erlang:port_info(Port, os_pid),
    stop_and_wait(OsPid, Timeout);

stop_and_wait(OsPid, Timeout) when is_integer(OsPid) ->
    case ets:lookup(exec_mon, OsPid) of
    [{_, Pid}] ->
        stop_and_wait(Pid, Timeout);
    [] ->
        {error, not_found}
    end;

stop_and_wait(Pid, Timeout) when is_pid(Pid) ->
    gen_server:call(?MODULE, {port, {stop, Pid}}, Timeout),
    receive
    {'DOWN', _Ref, process, Pid, ExitStatus} -> ExitStatus
    after Timeout                            -> {error, timeout}
    end;

stop_and_wait(Port, Timeout) when is_port(Port) ->
    {os_pid, Pid} = erlang:port_info(Port, os_pid),
    stop_and_wait(Pid, Timeout).

%%-------------------------------------------------------------------------
-doc """
Get `OsPid` of the given Erlang `Pid`.  The `Pid` must be created
previously by running the run/2 or run_link/2 commands.
""".
-spec ospid(pid()) -> ospid() | {error, Reason::any()}.
ospid(Pid) when is_pid(Pid) ->
    Ref = make_ref(),
    Pid ! {{self(), Ref}, ospid},
    receive
    {Ref, Reply} -> Reply;
    Other        -> Other
    after 5000   -> {error, timeout}
    end.

%%-------------------------------------------------------------------------
-doc """
Get `Pid` of the given `OsPid`.  The `OsPid` must be created
previously by running the run/2 or run_link/2 commands.
""".
-spec pid(OsPid::ospid()) -> pid() | undefined | {error, timeout}.
pid(OsPid) when is_integer(OsPid) ->
    gen_server:call(?MODULE, {pid, OsPid}).

%%-------------------------------------------------------------------------
-doc """
Send `Data` to stdin of the OS process identified by `OsPid`.

Sending eof instead of binary Data causes close of stdin of the
corresponding process. Data sent to closed stdin is ignored.
""".
-spec send(OsPid :: ospid() | pid(), binary() | 'eof') -> ok.
send(OsPid, Data)
  when (is_integer(OsPid) orelse is_pid(OsPid)),
       (is_binary(Data)   orelse Data =:= eof) ->
    gen_server:call(?MODULE, {port, {send, OsPid, Data}}).

%%-------------------------------------------------------------------------
-doc """
Set the pty terminal `Rows` and `Cols` of the OS process identified by `OsPid`.

The process must have been created with the `pty` option.
""".
-spec winsz(OsPid :: ospid() | pid(), integer(), integer()) -> ok | {error, Reason::any()}.
winsz(OsPid, Rows, Cols)
  when (is_integer(OsPid) orelse is_pid(OsPid)),
       is_integer(Rows),
       is_integer(Cols) ->
    gen_server:call(?MODULE, {port, {winsz, OsPid, Rows, Cols}}).

%%-------------------------------------------------------------------------
-doc """
Set the pty terminal options of the OS process identified by `OsPid`.

The process must have been created with the `pty` option.
""".
-spec pty_opts(OsPid :: ospid() | pid(), pty_opts()) -> ok | {error, Reason::any()}.
pty_opts(OsPid, Opts)
  when (is_integer(OsPid) orelse is_pid(OsPid)),
       is_list(Opts) ->
    gen_server:call(?MODULE, {port, {pty_opts, OsPid, Opts}}).

%%-------------------------------------------------------------------------
-doc "Set debug level of the port process".
-spec debug(Level::integer()) -> {ok, OldLevel::integer()} | {error, timeout}.
debug(Level) when is_integer(Level), Level >= 0, Level =< 10 ->
    gen_server:call(?MODULE, {port, {debug, Level}}).

%%-------------------------------------------------------------------------
-doc """
Decode the program's exit_status.  If the program exited by signal
the function returns `{signal, Signal, Core}` where the `Signal`
is the signal number or atom, and `Core` indicates if the core file
was generated.
""".
-spec status(integer()) ->
        {status, ExitStatus :: integer()} |
        {signal, Signal :: integer() | atom(), Core :: boolean()}.
status(Status) when is_integer(Status) ->
    TermSignal = Status band 16#7F,
    IfSignaled = ((TermSignal + 1) bsr 1) > 0,
    ExitStatus = (Status band 16#FF00) bsr 8,
    case IfSignaled of
    true ->
        CoreDump = (Status band 16#80) =:= 16#80,
        {signal, signal(TermSignal), CoreDump};
    false ->
        {status, ExitStatus}
    end.

%%-------------------------------------------------------------------------
-doc "Convert a signal number to atom".
-spec signal(integer()) -> atom() | integer().
signal( 1) -> sighup;
signal( 2) -> sigint;
signal( 3) -> sigquit;
signal( 4) -> sigill;
signal( 5) -> sigtrap;
signal( 6) -> sigabrt;
signal( 7) -> sigbus;
signal( 8) -> sigfpe;
signal( 9) -> sigkill;
signal(11) -> sigsegv;
signal(13) -> sigpipe;
signal(14) -> sigalrm;
signal(15) -> sigterm;
signal(16) -> sigstkflt;
signal(17) -> sigchld;
signal(18) -> sigcont;
signal(19) -> sigstop;
signal(20) -> sigtstp;
signal(21) -> sigttin;
signal(22) -> sigttou;
signal(23) -> sigurg;
signal(24) -> sigxcpu;
signal(25) -> sigxfsz;
signal(26) -> sigvtalrm;
signal(27) -> sigprof;
signal(28) -> sigwinch;
signal(29) -> sigio;
signal(30) -> sigpwr;
signal(31) -> sigsys;
signal(34) -> sigrtmin;
signal(64) -> sigrtmax;
signal(Num) when is_integer(Num) -> Num.

signal_to_int(sighup)     ->  1;
signal_to_int(sigint)     ->  2;
signal_to_int(sigquit)    ->  3;
signal_to_int(sigill)     ->  4;
signal_to_int(sigtrap)    ->  5;
signal_to_int(sigabrt)    ->  6;
signal_to_int(sigbus)     ->  7;
signal_to_int(sigfpe)     ->  8;
signal_to_int(sigkill)    ->  9;
signal_to_int(sigsegv)    -> 11;
signal_to_int(sigpipe)    -> 13;
signal_to_int(sigalrm)    -> 14;
signal_to_int(sigterm)    -> 15;
signal_to_int(sigstkflt)  -> 16;
signal_to_int(sigchld)    -> 17;
signal_to_int(sigcont)    -> 18;
signal_to_int(sigstop)    -> 19;
signal_to_int(sigtstp)    -> 20;
signal_to_int(sigttin)    -> 21;
signal_to_int(sigttou)    -> 22;
signal_to_int(sigurg)     -> 23;
signal_to_int(sigxcpu)    -> 24;
signal_to_int(sigxfsz)    -> 25;
signal_to_int(sigvtalrm)  -> 26;
signal_to_int(sigprof)    -> 27;
signal_to_int(sigwinch)   -> 28;
signal_to_int(sigio)      -> 29;
signal_to_int(sigpwr)     -> 30;
signal_to_int(sigsys)     -> 31;
signal_to_int(sigrtmin)   -> 34;
signal_to_int(sigrtmax)   -> 64.

%%-------------------------------------------------------------------------
%% Provide default value of a given option.
%%-------------------------------------------------------------------------
-spec default() -> [{atom(), term()}].
default() ->
    [{debug, 0},        % Debug mode of the port program.
     {verbose, false},  % Verbose print of events on the Erlang side.
     {root, false},     % Allow running processes as root.
     {args, ""},        % Extra arguments that can be passed to port program
     {alarm, 12},
     {portexe, noportexe},
     {user, ""},        % Run port program as this user
     {limit_users, []}]. % Restricted list of users allowed to run commands
%% @private
default(portexe) ->
    % Retrieve the Priv directory
    case code:priv_dir(erlexec) of
    {error, _} ->
        error_logger:warning_msg("Priv directory not available", []),
        "";
    Priv ->
        % Find all ports using wildcard for resiliency
        Bin = case filelib:wildcard("*/exec-port", Priv) of
            [Port] -> Port;
            _      ->
                Arch = erlang:system_info(system_architecture),
                Tail = filename:join([Arch, "exec-port"]),
                os:find_executable(filename:join([Priv, Tail]))
        end,
        % Join the priv/port path
        filename:join([Priv, Bin])
    end;
default(Option) ->
    proplists:get_value(Option, default()).

%%%----------------------------------------------------------------------
%%% Callback functions from gen_server
%%%----------------------------------------------------------------------

%%-----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, State}          |
%%          {ok, State, Timeout} |
%%          ignore               |
%%          {stop, Reason}
%% @private
%%-----------------------------------------------------------------------
init([Options]) ->
    process_flag(trap_exit, true),
    Opts0 = proplists:expand([{debug,   [{debug, 1}]},
                              {root,    [{root, true}]},
                              {verbose, [{verbose, true}]}], Options),
    Opts1 = [T || T = {O,_} <- Opts0,
                lists:member(O, [debug, verbose, root, args, alarm, user])],
    Opts  = proplists:normalize(Opts1, [{aliases, [{args, ''}]}]),
    Args0 = lists:foldl(
        fun
           (Opt, Acc) when is_atom(Opt) ->
                [" -"++atom_to_list(Opt)++" " | Acc];
           ({Opt, I}, Acc) when is_atom(I) ->
                [" -"++atom_to_list(Opt)++" "++atom_to_list(I) | Acc];
           ({Opt, I}, Acc) when is_list(I), I /= ""; is_binary(I), I /= <<"">> ->
                [" -"++atom_to_list(Opt)++" "++to_list(I) | Acc];
           ({Opt, I}, Acc) when is_integer(I) ->
                [" -"++atom_to_list(Opt)++" "++integer_to_list(I) | Acc];
           (_, Acc) -> Acc
        end, [], Opts),
    Exe0  = case proplists:get_value(portexe, Options, noportexe) of
            noportexe -> default(portexe);
            UserExe   -> to_list(UserExe)
            end,
    Exe1  = ?FMT("~p", [Exe0]),
    Args  = lists:flatten(Args0),
    Users = case proplists:get_value(limit_users, Options, default(limit_users)) of
            [] -> [];
            L  -> [to_list(I) || I <- L]
            end,
    User  = to_list(proplists:get_value(user,Options)),
    Debug = proplists:get_value(verbose,     Options, default(verbose)),
    Root  = proplists:get_value(root,        Options, default(root)),
    Env   = case proplists:get_value(env, Options) of
            undefined -> [];
            Other     -> [{env, parse_env(Other)}]
            end,
    % When instructing to run as root, check that the port program has
    % the SUID bit set or else use "sudo"
    {SUID,NeedSudo} = is_suid_and_root_owner(Exe0),
    EffUsr= os:getenv("USER"),
    IsRoot= EffUsr =:= "root",
    Exe   = if not Root ->
                Exe1++Args;
            Root, IsRoot, User/=undefined, User/="", ((SUID     andalso Users/=[]) orelse
                                                      (not SUID andalso Users==[])) ->
                Exe1++Args;
            %Root, not IsRoot, NeedSudo, User/=undefined, User/="" ->
                % Asked to enable root, but running as non-root, and have no SUID: use sudo.
            %    lists:append(["/usr/bin/sudo -u ", to_list(User), " ", Exe1, Args]);
            Root, not IsRoot, NeedSudo, ((User/=undefined andalso User/="") orelse
                                         (EffUsr/=User andalso User/=undefined
                                                       andalso User/=root
                                                       andalso User/="root")) ->
                % Asked to enable root, but running as non-root, and have SUID: use sudo.
                lists:append(["/usr/bin/sudo ", Exe1, Args]);
            true ->
                Exe1++Args
            end,
    debug(Debug, "exec: ~s~sport program: ~s\n~s",
        [if SUID -> "[SUID] "; true -> "" end,
         if (Root orelse IsRoot) andalso User =:= [] -> "[ROOT] "; true -> "" end,
         Exe,
         if Env =/= [] -> "  env: "++?FMT("~p", Env)++"\n"; true -> "" end]),
    try
        PortOpts = Env ++ [binary, exit_status, {packet, 2}, hide],
        Port = erlang:open_port({spawn, Exe}, PortOpts),
        receive
            {Port, {exit_status, Status}} ->
                {stop, {port_exited_with_status, Status}}
        after 350 ->
            Tab = ets:new(exec_mon, [protected,named_table]),
            {ok, #state{port=Port, limit_users=Users, debug=Debug, registry=Tab, root=Root}}
        end
    catch
        ?EXCEPTION(_, Reason, Stacktrace) ->
            {stop, ?FMT("Error starting port '~s': ~200p\n  ~p\n",
                [Exe, Reason, ?GET_STACK(Stacktrace)])}
    end.

%%----------------------------------------------------------------------
%% Func: handle_call/3
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%% @private
%%----------------------------------------------------------------------
handle_call({port, Instruction}, From, #state{last_trans=Last} = State) ->
    try is_port_command(Instruction, element(1, From), State) of
    {ok, Term} ->
        erlang:port_command(State#state.port, term_to_binary({0, Term})),
        {reply, ok, State};
    {ok, Term, Link, Sync, PidOpts} ->
        Next = next_trans(Last),
        erlang:port_command(State#state.port, term_to_binary({Next, Term})),
        {noreply, State#state{trans = queue:in({Next, From, Link, Sync, PidOpts}, State#state.trans)}}
    catch _:{error, Why} ->
        {reply, {error, Why}, State}
    end;

handle_call({pid, OsPid}, _From, State) ->
    case ets:lookup(exec_mon, OsPid) of
    [{_, Pid}] -> {reply, Pid, State};
    _          -> {reply, undefined, State}
    end;

handle_call(Request, _From, _State) ->
    {stop, {not_implemented, Request}}.

%%----------------------------------------------------------------------
%% Func: handle_cast/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%% @private
%%----------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: handle_info/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%% @private
%%----------------------------------------------------------------------
handle_info({Port, {data, Bin}}, #state{port=Port, debug=Debug} = State) ->
    Msg = binary_to_term(Bin),
    debug(Debug, "~w got msg from port: ~p\n", [?MODULE, Msg]),
    case Msg of
    {N, Reply} when N =/= 0 ->
        case get_transaction(State#state.trans, N) of
        {true, {Pid,_} = From, MonType, Sync, PidOpts, Q} ->
            NewReply = maybe_add_monitor(Reply, Pid, MonType, Sync, PidOpts, Debug),
            gen_server:reply(From, NewReply);
        {false, Q} ->
            ok
        end,
        {noreply, State#state{trans=Q}};
    {0, {Stream, OsPid, Data}} when Stream =:= stdout; Stream =:= stderr ->
        send_to_ospid_owner(OsPid, {Stream, Data}),
        {noreply, State};
    {0, {exit_status, OsPid, Status}} ->
        debug(Debug, "Pid ~w exited with status: ~s{~w,~w}\n",
            [OsPid, if (((Status band 16#7F)+1) bsr 1) > 0 -> "signaled "; true -> "" end,
             (Status band 16#FF00 bsr 8), Status band 127]),
        notify_ospid_owner(OsPid, Status),
        {noreply, State};
    {0, ok} ->
        {noreply, State};
    {0, Ignore} ->
        error_logger:warning_msg("~w [~w] unknown msg: ~p\n", [self(), ?MODULE, Ignore]),
        {noreply, State}
    end;

handle_info({Port, {exit_status, 0}}, #state{port=Port} = State) ->
    {stop, normal, State};
handle_info({Port, {exit_status, Status}}, #state{port=Port} = State) ->
    {stop, {exit_status, Status}, State};
handle_info({'EXIT', Port, Reason}, #state{port=Port} = State) ->
    {stop, Reason, State};
handle_info({'EXIT', Pid, Reason}, State) ->
    % OsPid's Pid owner died. Kill linked OsPid.
    do_unlink_ospid(Pid, Reason, State),
    {noreply, State};
handle_info(_Info, State) ->
    error_logger:info_msg("~w - unhandled message: ~p\n", [?MODULE, _Info]),
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: code_change/3
%% Purpose: Convert process state when code is changed
%% Returns: {ok, NewState}
%% @private
%%----------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%----------------------------------------------------------------------
%% Func: terminate/2
%% Purpose: Shutdown the server
%% Returns: any (ignored by gen_server)
%% @private
%%----------------------------------------------------------------------
terminate(_Reason, State) ->
    try
        erlang:port_command(State#state.port, term_to_binary({0, {shutdown}})),
        case wait_port_exit(State#state.port) of
        0 -> ok;
        S -> error_logger:warning_msg("~w - exec process terminated (status: ~w)\n",
                [self(), S])
        end
    catch _:_ ->
        ok
    end.

to_list(undefined)           -> [];
to_list(A) when is_atom(A)   -> atom_to_list(A);
to_list(L) when is_list(L)   -> L;
to_list(B) when is_binary(B) -> binary_to_list(B).

wait_port_exit(Port) ->
    receive
    {Port,{exit_status,Status}} ->
        Status;
    _ ->
        wait_port_exit(Port)
    end.

%%%---------------------------------------------------------------------
%%% Internal functions
%%%---------------------------------------------------------------------

-spec do_run(Cmd::any(), Options::cmd_options(), Timeout::integer()) ->
    {ok, pid(), ospid()} | {ok, [{stdout | stderr, [binary()]}]} | {error, any()}.
do_run(Cmd, Options, Timeout) when is_integer(Timeout) ->
    Link = case {proplists:get_bool(link,    Options),
                 proplists:get_bool(monitor, Options)} of
           {true, _} -> link;
           {_, true} -> monitor;
           _         -> undefined
           end,
    Sync = proplists:get_value(sync, Options, false),
    Cmd2 = {port, {Cmd, Link, Sync}},
    case gen_server:call(?MODULE, Cmd2, Timeout) of
    {ok, Pid, OsPid, _Sync = true} ->
        wait_for_ospid_exit(OsPid, Pid, [], []);
    {ok, Pid, OsPid, _} ->
        {ok, Pid, OsPid};
    {error, Reason} ->
        {error, Reason}
    end.

wait_for_ospid_exit(OsPid, Pid, OutAcc, ErrAcc) ->
    % Note when a monitored process exits
    receive
    {stdout, OsPid, Data} ->
        wait_for_ospid_exit(OsPid, Pid, [Data | OutAcc], ErrAcc);
    {stderr, OsPid, Data} ->
        wait_for_ospid_exit(OsPid, Pid, OutAcc, [Data | ErrAcc]);
    {'DOWN', OsPid, process, Pid, normal} ->
        {ok, sync_res(OutAcc, ErrAcc)};
    {'DOWN', OsPid, process, Pid, noproc} ->
        {ok, sync_res(OutAcc, ErrAcc)};
    {'DOWN', OsPid, process, Pid, {exit_status,_}=R} ->
        {error, [R | sync_res(OutAcc, ErrAcc)]}
    end.

sync_res([], []) -> [];
sync_res([], L)  -> [{stderr, lists:reverse(L)}];
sync_res(LO, LE) -> [{stdout, lists:reverse(LO)} | sync_res([], LE)].

%% Add a link for Pid to OsPid if requested.
maybe_add_monitor({pid, OsPid}, Pid, MonType, Sync, PidOpts, Debug) when is_integer(OsPid) ->
    % This is a reply to a run/run_link command. The port program indicates
    % of creating a new OsPid process.
    % Spawn a light-weight process responsible for monitoring this OsPid
    Self = self(),
    LWP  = spawn_link(fun() -> ospid_init(Pid, OsPid, MonType, Sync, Self, PidOpts, Debug) end),
    debug(Debug, "~w added monitor ~p for OsPid ~w", [?MODULE, LWP, OsPid]),
    ets:insert(exec_mon, [{OsPid, LWP}, {LWP, OsPid}]),
    {ok, LWP, OsPid, Sync};
maybe_add_monitor(Reply, _Pid, _MonType, _Sync, _PidOpts, _Debug) ->
    Reply.

%%----------------------------------------------------------------------
%% Every OsPid is associated with an Erlang process started with
%% this function. The `Parent` is the ?MODULE port manager that
%% spawned this process and linked to it. `Pid` is the process
%% that ran an OS command associated with OsPid. If that process
%% requested a link (LinkType = 'link') we'll link to it.
%%----------------------------------------------------------------------
-spec ospid_init(Pid::pid(), OsPid::integer(), link | monitor | undefined,
                 Sync::boolean(), Parent::pid(), list(), Debug::boolean()) ->
        no_return().
ospid_init(Pid, OsPid, LinkType, Sync, Parent, PidOpts, Debug) ->
    process_flag(trap_exit, true),
    StdOut = proplists:get_value(stdout, PidOpts),
    StdErr = proplists:get_value(stderr, PidOpts),
    % The caller pid that requested to run the OsPid command & link to it.
    LinkType =:= link andalso link(Pid),
    % We need to emulate a monitor by sending the 'DOWN' message to the
    % caller's Pid if it requested to monitor or it's a synchronous call:
    IsMon  = LinkType =:= monitor orelse Sync =:= true,
    ospid_loop({Pid, OsPid, Parent, StdOut, StdErr, IsMon, Debug}).

ospid_loop({Pid, OsPid, Parent, StdOut, StdErr, IsMon, Debug} = State) ->
    receive
    {{From, Ref}, ospid} ->
        From ! {Ref, OsPid},
        ospid_loop(State);
    {stdout, Data} when is_binary(Data) ->
        ospid_deliver_output(StdOut, {stdout, OsPid, Data}),
        ospid_loop(State);
    {stderr, Data} when is_binary(Data) ->
        ospid_deliver_output(StdErr, {stderr, OsPid, Data}),
        ospid_loop(State);
    {'DOWN', OsPid, {exit_status, Status}} ->
        debug(Debug, "~w ~w got down message (~w) (ismon=~w)\n",
                     [self(), OsPid, status(Status), IsMon]),
        % OS process died
        case Status of
        0 -> notify_and_exit(IsMon, Pid, OsPid, normal);
        _ -> notify_and_exit(IsMon, Pid, OsPid, {exit_status, Status})
        end;
    {'EXIT', Pid, Reason} when Reason =:= normal; Reason =:= shutdown ->
        % orderly exit
        debug(Debug, "~w ~w got ~w exit from linked ~w\n", [self(), OsPid, Reason, Pid]),
        exit(Reason);
    {'EXIT', Pid, Reason} ->
        % Pid died
        debug(Debug, "~w ~w got exit from linked ~w: ~p\n", [self(), OsPid, Pid, Reason]),
        exit({owner_died, Pid, Reason});
    {'EXIT', Parent, Reason} ->
        % Port program died
        debug(Debug, "~w ~w got exit from parent ~w: ~p\n", [self(), OsPid, Parent, Reason]),
        notify_and_exit(IsMon, Pid, OsPid, port_closed);
    Other ->
        error_logger:warning_msg("~w - unknown msg: ~p\n", [self(), Other]),
        ospid_loop(State)
    end.

notify_and_exit(true, Pid, OsPid, Reason) ->
    Pid ! {'DOWN', OsPid, process, self(), Reason},
    exit(Reason);
notify_and_exit(_, _Pid, _OsPid, Reason) ->
    exit(Reason).

ospid_deliver_output(DestPid, Msg) when is_pid(DestPid) ->
    DestPid ! Msg;
ospid_deliver_output(DestFun, {Stream, OsPid, Data}) when is_function(DestFun) ->
    DestFun(Stream, OsPid, Data).

notify_ospid_owner(OsPid, Status) ->
    % See if there is a Pid owner of this OsPid. If so, sent the 'DOWN' message.
    case ets:lookup(exec_mon, OsPid) of
    [{_OsPid, Pid}] ->
        unlink(Pid),
        Pid ! {'DOWN', OsPid, {exit_status, Status}},
        ets:delete(exec_mon, Pid),
        ets:delete(exec_mon, OsPid);
    [] ->
        %error_logger:warning_msg("Owner ~w not found\n", [OsPid]),
        ok
    end.

send_to_ospid_owner(OsPid, Msg) ->
    case ets:lookup(exec_mon, OsPid) of
    [{_, Pid}] -> Pid ! Msg;
    _ -> ok
    end.

debug(false, _, _) ->
    ok;
debug(_, Fmt, Args) ->
    io:format(Fmt, Args).

is_suid_and_root_owner(File) ->
    case file:read_file_info(File) of
    {ok, Info} ->
        {(Info#file_info.mode band 8#4500) =:= 8#4500,
         (Info#file_info.uid =/= 0)};
    {error, Err} ->
        throw("Cannot find file " ++ File ++ ": " ++ file:format_error(Err))
    end.

check_options(Options) when is_list(Options) ->
    Users = proplists:get_value(limit_users, Options, default(limit_users)),
    User  = proplists:get_value(user,        Options),
    Root  = proplists:get_value(root,        Options, default(root)),
    % When instructing to run as root, check that the port program has
    % the SUID bit set or else use "sudo"
    Exe   = case proplists:get_value(portexe, Options, undefined) of
                undefined -> default(portexe);
                Other     -> Other
            end,
    {SUID,NeedSudo} = is_suid_and_root_owner(Exe),
    if Root, (User==undefined orelse User=="" orelse User == <<"">>) ->
        % Asked to enable root, but User is not set
        {error, "Not allowed to run without providing effective user {user,User}!"};
    Root, Users==[] ->
        % Asked to enable root, have SUID
        {error, "Not allowed to run without restricting effective users {limit_users,Users}!"};
    Root, User/=undefined, User/="", Users/=[] ->
        ok;
    not Root, SUID, not NeedSudo, Users==[] ->
        {error, "Not allowed to run as SUID root without restricting effective users {limit_users,Users}!"};
    not Root, User/=undefined ->
        {error, "Cannot specify effective user {user,User} in non-root mode!"};
        ok;
    not Root, Users/=[] ->
        {error, "Cannot restrict users {limit_users,Users} in non-root mode!"};
        ok;
    not Root ->
        ok;
    true ->
        {error, "Invalid root and user arguments"}
    end.

%%----------------------------------------------------------------------
%% Pid died or requested to unlink - remove linked Pid records and
%% optionally kill all OsPids linked to the Pid.
%%----------------------------------------------------------------------
-spec do_unlink_ospid(Pid::pid(), term(), State::#state{}) ->
        ok | true.
do_unlink_ospid(Pid, _Reason, State) ->
    case ets:lookup(exec_mon, Pid) of
    [{_Pid, OsPid}] when is_integer(OsPid) ->
        debug(State#state.debug, "Pid ~p died. Killing linked OsPid ~w\n", [Pid, OsPid]),
        ets:delete(exec_mon, Pid),
        ets:delete(exec_mon, OsPid),
        erlang:port_command(State#state.port, term_to_binary({0, {stop, OsPid}}));
    _ ->
        ok
    end.

get_transaction(Q, I) ->
    get_transaction(Q, I, Q).
get_transaction(Q, I, OldQ) ->
    case queue:out(Q) of
    {{value, {I, From, LinkType, Sync, PidOpts}}, Q2} ->
        {true, From, LinkType, Sync, PidOpts, Q2};
    {empty, _} ->
        {false, OldQ};
    {_, Q2} ->
        get_transaction(Q2, I, OldQ)
    end.

is_port_command({{run, Cmd, Options}, Link, Sync}, Pid, State) ->
    {PortOpts, Other} = check_cmd_options(Options, Pid, State, [], []),
    %% If Cmd is a printable string, handle it as a unicode binary string.
    %% Otherwise if it is a list of strings, convert them to list of unicode binaries.
    Exe = case io_lib:printable_unicode_list(Cmd) of
          true  -> unicode:characters_to_binary(Cmd);
          false ->
              F = fun(I) when is_binary(I) -> I;
                     (I) when is_list(I)   -> unicode:characters_to_binary(I)
                  end,
              case is_list(Cmd) of
              true  -> [F(I) || I <- Cmd];
              false -> Cmd
              end
          end,
    {ok, {run, Exe, PortOpts}, Link, Sync, Other};
is_port_command({list} = T, _Pid, _State) ->
    {ok, T, undefined, undefined, []};
is_port_command({stop, OsPid}=T, _Pid, _State) when is_integer(OsPid) ->
    {ok, T, undefined, undefined, []};
is_port_command({stop, Pid}, _Pid, _State) when is_pid(Pid) ->
    case ets:lookup(exec_mon, Pid) of
    [{_StoredPid, OsPid}] -> {ok, {stop, OsPid}, undefined, undefined, []};
    []              -> throw({error, no_process})
    end;
is_port_command({{manage, OsPid, Options}, Link, Sync}, Pid, State) when is_integer(OsPid) ->
    {PortOpts, _Other} = check_cmd_options(Options, Pid, State, [], []),
    {ok, {manage, OsPid, PortOpts}, Link, Sync, []};
is_port_command({send, Pid, Data}, _Pid, _State)
  when is_pid(Pid), is_binary(Data) orelse Data =:= eof ->
    case ets:lookup(exec_mon, Pid) of
    [{Pid, OsPid}]  -> {ok, {stdin, OsPid, Data}};
    []              -> throw({error, no_process})
    end;
is_port_command({send, OsPid, Data}, _Pid, _State)
  when is_integer(OsPid), is_binary(Data) orelse Data =:= eof ->
    {ok, {stdin, OsPid, Data}};
is_port_command({winsz, Pid, Rows, Cols}, _Pid, _State)
  when is_pid(Pid), is_integer(Rows), is_integer(Cols) ->
    case ets:lookup(exec_mon, Pid) of
    [{Pid, OsPid}]  -> {ok, {winsz, OsPid, Rows, Cols}, undefined, undefined, []};
    []              -> throw({error, no_process})
    end;
is_port_command({winsz, OsPid, Rows, Cols}, _Pid, _State)
  when is_integer(OsPid), is_integer(Rows), is_integer(Cols) ->
    {ok, {winsz, OsPid, Rows, Cols}, undefined, undefined, []};
is_port_command({pty_opts, Pid, Opts}, _Pid, _State)
  when is_pid(Pid), is_list(Opts) ->
    ok = check_pty_opts(Opts),
    case ets:lookup(exec_mon, Pid) of
    [{Pid, OsPid}]  -> {ok, {pty_opts, OsPid, Opts}, undefined, undefined, []};
    []              -> throw({error, no_process})
    end;
is_port_command({pty_opts, OsPid, Opts}, _Pid, _State)
  when is_integer(OsPid), is_list(Opts) ->
    ok = check_pty_opts(Opts),
    {ok, {pty_opts, OsPid, Opts}, undefined, undefined, []};
is_port_command({kill, OsPid, Sig}=T, _Pid, _State) when is_integer(OsPid),is_integer(Sig) ->
    {ok, T, undefined, undefined, []};
is_port_command({setpgid, OsPid, Gid}=T, _Pid, _State) when is_integer(OsPid),is_integer(Gid) ->
    {ok, T, undefined, undefined, []};
is_port_command({kill, Pid, Sig}, _Pid, _State) when is_pid(Pid),is_integer(Sig) ->
    case ets:lookup(exec_mon, Pid) of
    [{Pid, OsPid}]  -> {ok, {kill, OsPid, Sig}, undefined, undefined, []};
    []              -> throw({error, no_process})
    end;
is_port_command({debug, Level}=T, _Pid, _State) when is_integer(Level),Level >= 0,Level =< 10 ->
    {ok, T, undefined, undefined, []}.

parse_env([])            -> [];
parse_env([{K,false}|T]) -> [{to_list(K), false}     |parse_env(T)]; %% Remove the env var K
parse_env([{K,V}|T])     -> [{to_list(K), to_list(V)}|parse_env(T)];
parse_env([H|T])         -> [to_list(H)|parse_env(T)].

check_cmd_options([monitor|T], Pid, State, PortOpts, OtherOpts) ->
    check_cmd_options(T, Pid, State, PortOpts, OtherOpts);
check_cmd_options([sync|T], Pid, State, PortOpts, OtherOpts) ->
    check_cmd_options(T, Pid, State, PortOpts, OtherOpts);
check_cmd_options([link|T], Pid, State, PortOpts, OtherOpts) ->
    check_cmd_options(T, Pid, State, PortOpts, OtherOpts);
check_cmd_options([{executable,V}=H|T], Pid, State, PortOpts, OtherOpts) when is_list(V); is_binary(V) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{cd, Dir}=H|T], Pid, State, PortOpts, OtherOpts) when is_list(Dir); is_binary(Dir) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{env, Env}=H|T], Pid, State, PortOpts, OtherOpts) when is_list(Env) ->
    case lists:filter(fun(S) when is_list(S); is_binary(S) -> false;
                         ({S1,S2}) when (is_list(S1) orelse is_binary(S1)) andalso
                                        (is_list(S2) orelse is_binary(S2) orelse S2 == false) -> false;
                         (clear)   -> false;
                         (_)       -> true
                      end, Env) of
    [] -> check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
    L  -> throw({error, {invalid_env_value, L}})
    end;
check_cmd_options([{kill, Cmd}=H|T], Pid, State, PortOpts, OtherOpts) when is_list(Cmd); is_binary(Cmd) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{kill_timeout, I}=H|T], Pid, State, PortOpts, OtherOpts) when is_integer(I), I >= 0 ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([kill_group=H|T], Pid, State, PortOpts, OtherOpts) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{nice, I}=H|T], Pid, State, PortOpts, OtherOpts) when is_integer(I), I >= -20, I =< 20 ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([debug|T], Pid, State, PortOpts, OtherOpts) ->
    check_cmd_options(T, Pid, State, [{debug,1}|PortOpts], OtherOpts);
check_cmd_options([{debug, I}=H|T], Pid, State, PortOpts, OtherOpts) when is_integer(I), I >= 0, I =< 10 ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{success_exit_code, I}=H|T], Pid, State, PortOpts, OtherOpts)
  when is_integer(I), I >= 0, I < 256 ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([H|T], Pid, State, PortOpts, OtherOpts) when H=:=stdin; H=:=stdout; H=:=stderr ->
    check_cmd_options(T, Pid, State, [H|PortOpts], [{H, Pid}|OtherOpts]);
check_cmd_options([H|T], Pid, State, PortOpts, OtherOpts) when H=:=pty ->
    check_cmd_options(T, Pid, State, [H|PortOpts], [{H, Pid}|OtherOpts]);
check_cmd_options([H|T], Pid, State, PortOpts, OtherOpts) when H=:=pty_echo ->
    check_cmd_options(T, Pid, State, [H|PortOpts], [{H, Pid}|OtherOpts]);
check_cmd_options([{winsz, {Rows, Cols}}=H|T], Pid, State, PortOpts, OtherOpts)
        when is_integer(Rows), Rows >= 0, is_integer(Cols), Cols >= 0 ->
    check_cmd_options(T, Pid, State, [H|PortOpts], [{H, Pid}|OtherOpts]);
check_cmd_options([{pty, Pty}=H|T], Pid, State, PortOpts, OtherOpts) when is_list(Pty) ->
    ok = check_pty_opts(Pty),
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{capabilities, all}=H|T], Pid, State, PortOpts, OtherOpts) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{capabilities, Caps}=H|T], Pid, State, PortOpts, OtherOpts) when is_list(Caps) ->
    [check_capability(C) || C <- Caps],
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{stdin, I}=H|T], Pid, State, PortOpts, OtherOpts)
        when I=:=null; I=:=close; is_list(I); is_binary(I) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{Std, I, Opts}=H|T], Pid, State, PortOpts, OtherOpts)
        when (Std=:=stdout orelse Std=:=stderr) andalso (is_list(Opts) orelse is_binary(Opts)) ->
    io_lib:printable_list(I) orelse
        throw({error, ?FMT("Invalid ~w filename: ~200p", [Std, I])}),
    lists:foreach(fun
        (append) -> ok;
        ({mode, Mode}) when is_integer(Mode) -> ok;
        (Other) -> throw({error, ?FMT("Invalid ~w option: ~p", [Std, Other])})
    end, Opts),
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{Std, I}=H|T], Pid, State, PortOpts, OtherOpts)
        when Std=:=stderr, I=/=Std; Std=:=stdout, I=/=Std ->
    if
        I=:=null; I=:=close; I=:=stderr; I=:=stdout; is_list(I); is_binary(I) ->
            check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
        I=:=print ->
            check_cmd_options(T, Pid, State, [Std | PortOpts], [{Std, fun print/3} | OtherOpts]);
        is_pid(I) ->
            check_cmd_options(T, Pid, State, [Std | PortOpts], [H|OtherOpts]);
        is_function(I) ->
            {arity, 3} =:= erlang:fun_info(I, arity)
                orelse throw({error, ?FMT("Invalid ~w option ~p: expected Fun/3", [Std, I])}),
            check_cmd_options(T, Pid, State, [Std | PortOpts], [H|OtherOpts]);
        true ->
            throw({error, ?FMT("Invalid ~w option ~p", [Std, I])})
    end;
check_cmd_options([{group, I}=H|T], Pid, State, PortOpts, OtherOpts) when is_integer(I), I >= 0
                                                                        ; is_list(I); is_binary(I) ->
    check_cmd_options(T, Pid, State, [H|PortOpts], OtherOpts);
check_cmd_options([{user, U}|T], Pid, State, PortOpts, OtherOpts) when (is_list(U) andalso U =/= "")
                                                                     ; (is_binary(U) andalso U =/= <<"">>)
                                                                     ; is_atom(U) ->
    case lists:member(U, State#state.limit_users) of
    true  -> check_cmd_options(T, Pid, State, [{user,to_list(U)}|PortOpts], OtherOpts);
    false -> throw({error, ?FMT("User ~s is not allowed to run commands!", [U])})
    end;
check_cmd_options([Other|_], _Pid, _State, _PortOpts, _OtherOpts) ->
    throw({error, {invalid_option, Other}});
check_cmd_options([], _Pid, _State, PortOpts, OtherOpts) ->
    {PortOpts, OtherOpts}.

check_pty_opts(Pty) when is_list(Pty) ->
    case lists:filter(fun({K,V}) when is_atom(K), (is_integer(V) orelse is_boolean(V)) -> not check_pty_opt(K, V);
                         (_) -> true
                      end, Pty) of
    [] -> ok;
    L  -> throw({error, {invalid_pty_value, L}})
    end.

check_capability(chown)            -> ok;
check_capability(dac_override)     -> ok;
check_capability(dac_read_search)  -> ok;
check_capability(fowner)           -> ok;
check_capability(fsetid)           -> ok;
check_capability(kill)             -> ok;
check_capability(setgid)           -> ok;
check_capability(setuid)           -> ok;
check_capability(setpcap)          -> ok;
check_capability(linux_immutable)  -> ok;
check_capability(net_bind_service) -> ok;
check_capability(net_broadcast)    -> ok;
check_capability(net_admin)        -> ok;
check_capability(net_raw)          -> ok;
check_capability(ipc_lock)         -> ok;
check_capability(ipc_owner)        -> ok;
check_capability(sys_module)       -> ok;
check_capability(sys_rawio)        -> ok;
check_capability(sys_chroot)       -> ok;
check_capability(sys_ptrace)       -> ok;
check_capability(sys_pacct)        -> ok;
check_capability(sys_admin)        -> ok;
check_capability(sys_boot)         -> ok;
check_capability(sys_nice)         -> ok;
check_capability(sys_resource)     -> ok;
check_capability(sys_time)         -> ok;
check_capability(sys_tty_config)   -> ok;
check_capability(mknod)            -> ok;
check_capability(lease)            -> ok;
check_capability(audit_write)      -> ok;
check_capability(audit_control)    -> ok;
check_capability(setfcap)          -> ok;
check_capability(mac_override)     -> ok;
check_capability(mac_admin)        -> ok;
check_capability(syslog)           -> ok;
check_capability(wake_alarm)       -> ok;
check_capability(block_suspend)    -> ok;
check_capability(Other)            -> throw({error, ?FMT("Invalid capability: ~s", [Other])}).

%% special characters
check_pty_opt(vintr,    V) -> is_byte(V);
check_pty_opt(vquit,    V) -> is_byte(V);
check_pty_opt(verase,   V) -> is_byte(V);
check_pty_opt(vkill,    V) -> is_byte(V);
check_pty_opt(veof,     V) -> is_byte(V);
check_pty_opt(veol,     V) -> is_byte(V);
check_pty_opt(veol2,    V) -> is_byte(V);
check_pty_opt(vstart,   V) -> is_byte(V);
check_pty_opt(vstop,    V) -> is_byte(V);
check_pty_opt(vsusp,    V) -> is_byte(V);
check_pty_opt(vdsusp,   V) -> is_byte(V);
check_pty_opt(vreprint, V) -> is_byte(V);
check_pty_opt(vwerase,  V) -> is_byte(V);
check_pty_opt(vlnext,   V) -> is_byte(V);
check_pty_opt(vflush,   V) -> is_byte(V);
check_pty_opt(vswtch,   V) -> is_byte(V);
check_pty_opt(vstatus,  V) -> is_byte(V);
check_pty_opt(vdiscard, V) -> is_byte(V);
%% modes
check_pty_opt(ignpar,   V) -> is_mode(V);
check_pty_opt(parmrk,   V) -> is_mode(V);
check_pty_opt(inpck,    V) -> is_mode(V);
check_pty_opt(istrip,   V) -> is_mode(V);
check_pty_opt(inlcr,    V) -> is_mode(V);
check_pty_opt(igncr,    V) -> is_mode(V);
check_pty_opt(icrnl,    V) -> is_mode(V);
check_pty_opt(xcase,    V) -> is_mode(V);
check_pty_opt(iuclc,    V) -> is_mode(V);
check_pty_opt(ixon,     V) -> is_mode(V);
check_pty_opt(ixany,    V) -> is_mode(V);
check_pty_opt(ixoff,    V) -> is_mode(V);
check_pty_opt(imaxbel,  V) -> is_mode(V);
check_pty_opt(iutf8,    V) -> is_mode(V);
check_pty_opt(isig,     V) -> is_mode(V);
check_pty_opt(icanon,   V) -> is_mode(V);
check_pty_opt(echo,     V) -> is_mode(V);
check_pty_opt(echoe,    V) -> is_mode(V);
check_pty_opt(echok,    V) -> is_mode(V);
check_pty_opt(echonl,   V) -> is_mode(V);
check_pty_opt(noflsh,   V) -> is_mode(V);
check_pty_opt(tostop,   V) -> is_mode(V);
check_pty_opt(iexten,   V) -> is_mode(V);
check_pty_opt(echoctl,  V) -> is_mode(V);
check_pty_opt(echoke,   V) -> is_mode(V);
check_pty_opt(pendin,   V) -> is_mode(V);
check_pty_opt(opost,    V) -> is_mode(V);
check_pty_opt(olcuc,    V) -> is_mode(V);
check_pty_opt(onlcr,    V) -> is_mode(V);
check_pty_opt(ocrnl,    V) -> is_mode(V);
check_pty_opt(onocr,    V) -> is_mode(V);
check_pty_opt(onlret,   V) -> is_mode(V);
check_pty_opt(cs7,      V) -> is_mode(V);
check_pty_opt(cs8,      V) -> is_mode(V);
check_pty_opt(parenb,   V) -> is_mode(V);
check_pty_opt(parodd,   V) -> is_mode(V);
% speed
check_pty_opt(tty_op_ispeed, V) -> is_speed(V);
check_pty_opt(tty_op_ospeed, V) -> is_speed(V);
check_pty_opt(_,             _) -> false.

is_byte(V)  -> V >= 0 andalso V =< 255.
is_mode(V)  -> is_boolean(V) orelse V==0 orelse V==1.
is_speed(V) -> is_integer(V) andalso V >= 0.

next_trans(I) when I =< 134217727 ->
    I+1;
next_trans(_) ->
    1.

print(Stream, OsPid, Data) ->
    io:format("Got ~w from ~w: ~p\n", [Stream, OsPid, Data]).

%%%---------------------------------------------------------------------
%%% Unit testing
%%%---------------------------------------------------------------------

-ifdef(EUNIT).

-define(AssertMatch(A, B),
    (fun() ->
        case B of
            A -> ok;
            _ -> ?debugFmt("==> TEST ~s FAILED (line: ~w)!!!\n",
                           [?FUNCTION_NAME, ?LINE]),
                 ?assertMatch(A,B)
        end
    end)()).

-define(receiveBytes(A, Timeout),
    check_receive(A, A, [], Timeout, ?FUNCTION_NAME, ?LINE)).

-define(receivePattern(A, Timeout),
    (fun() ->
        receive
            A -> true
        after Timeout ->
            case flush() of
                [] -> ?AssertMatch(A, timeout);
                LL ->
                    ?debugFmt("==> TEST ~s FAILED!!!\n", [?FUNCTION_NAME]),
                    erlang:error(#{error => unexpected_messages,
                                   msgs  => lists:reverse(LL)}),
                    ?assert(false)
            end
        end
    end)()).

-define(tt(F), {timeout, 20, ?_test(F)}).

check_receive({Stream, Pid, Bin} = A, Orig, Got, Timeout, TestName, Line)
        when is_atom(Stream), is_integer(Pid), is_binary(Bin) ->
    receive
        A ->
            true;
        {Stream, Pid, B} when is_binary(B) ->
            Len = byte_size(B),
            case Bin of
                <<C:Len/binary, Rest/binary>> when C == B ->
                    check_receive({Stream, Pid, Rest}, Orig, [B|Got], Timeout, TestName, Line);
                Other ->
                    ?debugFmt("==> TEST ~s FAILED (line: ~w)!!!\n", [TestName, Line]),
                    erlang:error(#{error    => unexpected_bytes,
                                   expected => Orig,
                                   got      => lists:reverse([Other|Got]),
                                   test     => TestName,
                                   line     => Line})
                end
    after Timeout ->
        case flush() of
            [] ->
                ?debugFmt("==> TEST ~s FAILED (line: ~w)!!!\n", [TestName, Line]),
                erlang:error(#{error    => timeout,
                               expected => Orig,
                               got      => lists:reverse(Got),
                               test     => TestName,
                               line     => Line});
            LL ->
                R = lists:reverse(Got) ++ lists:reverse(LL),
                ?debugFmt("==> TEST ~s FAILED (line: ~w)!!!\n", [TestName, Line]),
                erlang:error(#{error    => unexpected_messages,
                               expected => Orig,
                               got      => R,
                               test     => TestName,
                               line     => Line})
        end
    end.

flush() ->
    receive
        B -> [B | flush()]
    after 0 ->
        []
    end.

temp_dir() ->
    case os:getenv("TEMP") of
    false -> "/tmp";
    Path  -> Path
    end.

temp_file() ->
    Dir = temp_dir(),
    {I1, I2, I3}  = erlang:timestamp(),
    filename:join(Dir, io_lib:format("exec_temp_~w_~w_~w", [I1, I2, I3])).

exec_test_() ->
    {setup,
        fun() ->
            Opts =
                case os:getenv("TEST_USER") of
                    false -> [];
                    User  -> 
                        [root, {limit_users, [User]}, {user, User}]
                end,
            Opts1 =
                case os:getenv("PORT_DEBUG") of
                    false -> Opts;
                    _     -> [{debug, 1}, verbose | Opts]
                end,
            {ok, Pid} = exec:start(Opts1),
            Pid
        end,

        fun(Pid) -> exit(Pid, kill) end,
        [
            ?tt(test_root()),
            ?tt(test_monitor()),
            ?tt(test_sync()),
            ?tt(test_winsz()),
            ?tt(test_stdin()),
            ?tt(test_stdin_eof()),
            ?tt(test_std(stdout)),
            ?tt(test_std(stderr)),
            ?tt(test_cmd()),
            ?tt(test_executable()),
            ?tt(test_redirect()),
            ?tt(test_redirect_stdin()),
            ?tt(test_env()),
            ?tt(test_kill_timeout()),
            ?tt(test_setpgid()),
            ?tt(test_pty()),
            ?tt(test_pty_echo()),
            ?tt(test_pty_opts()),
            ?tt(test_dynamic_pty_opts())
        ]
    }.

exec_run_many_test_() ->
    Level = case os:getenv("PORT_DEBUG") of
                false -> 0;
                _     -> 1
            end,
    Delay = case os:getenv("PID_SLEEP_SEC") of
                false  -> 1000;
                Y      -> list_to_integer(Y)*1000
            end,
    N     = case os:getenv("RUN_COUNT") of
                false  -> 900;
                X      -> list_to_integer(X)
            end,
    M     = N*2,
    {setup,
        fun()    -> {ok, Pid} = exec:start([{debug, Level}]), Pid end,
        fun(Pid) -> exit(Pid, kill) end,
        [
            {timeout, 200,
                ?_assertMatch({ok,[{io_ops,M},{success,N}]}, test_exec:run(N, 60000, Delay))}
        ]
    }.

test_root() ->
    case os:getenv("NO_ROOT_TESTS") of
        false ->
            ?AssertMatch({error, "Cannot specify effective user"++_},
                         exec:start([{user, "xxxx"}, {limit_users, [yyyy]}])),
            ?AssertMatch({error, "Cannot restrict users"++_},
                         exec:start([{limit_users, [yyyy]}])),
            ?AssertMatch({error, "Not allowed to run without restricting effective users"++_},
                         exec:start([root, {user, "xxxx"}])),
            ?AssertMatch({error, "Not allowed to run without providing effective user "++_},
                         exec:start([root, {limit_users, [yyyy]}]));
        _ ->
            ok
    end.

test_monitor() ->
    {ok, P, _} = exec:run("echo ok", [{stdout, null}, monitor]),
    ?receivePattern({'DOWN', _, process, P, normal}, 5000).

test_sync() ->
    ?AssertMatch({ok, [{stdout, [<<"Test\n">>]}, {stderr, [<<"ERR\n">>]}]},
        exec:run("echo Test; echo ERR 1>&2", [stdout, stderr, sync])),
    ?AssertMatch({ok,[{stdout,[<<"\n">>]}]},
         exec:run([<<"/bin/echo">>], [sync, stdout])),
    ?AssertMatch({ok,[{stdout,[<<"\n">>]}]},
         exec:run(["/bin/echo"], [sync, stdout])).


test_winsz() ->
    {ok, P, I} = exec:run(
        ["/bin/bash", "-i", "-c", "echo started; read x; echo LINES=$(tput lines) COLUMNS=$(tput cols)"],
        [stdin, stdout, {stderr, stdout}, monitor, pty, {env, [{"TERM", "xterm"}]}]),
    ?receiveBytes({stdout, I, <<"started\r\n">>}, 3000),
    ok = exec:winsz(I, 99, 88),
    ok = exec:send(I, <<"\n">>),
    ?receiveBytes({stdout, I, <<"LINES=99 COLUMNS=88\r\n">>}, 3000),
    ?receivePattern({'DOWN', _, process, P, normal}, 5000),
    % can set size on run
    {ok, P2, I2} = exec:run(
        ["/bin/bash", "-i", "-c", "echo LINES=$(tput lines) COLUMNS=$(tput cols)\n"],
        [stdin, stdout, {stderr, stdout}, monitor, pty, {env, [{"TERM", "xterm"}]}, {winsz, {99, 88}}]),
    ?receiveBytes({stdout, I2, <<"LINES=99 COLUMNS=88\r\n">>}, 5000),
    ?receivePattern({'DOWN', _, process, P2, normal}, 5000).

test_stdin() ->
    {ok, P, I} = exec:run("read x; echo \"Got: $x\"", [stdin, stdout, monitor]),
    ok = exec:send(I, <<"Test data\n">>),
    ?receiveBytes({stdout,I,<<"Got: Test data\n">>}, 3000),
    ?receivePattern({'DOWN', _, process, P, normal}, 5000).

test_stdin_eof() ->
    case os:find_executable("tac") of
    false ->
        ok;
    _ ->
        {ok, P, I} = exec:run("tac", [stdin, stdout, monitor]),
        [ok = exec:send(I, Data)
         || Data <- [<<"foo\n">>, <<"bar\n">>, <<"baz\n">>, eof]],
        ?receiveBytes({stdout,I,<<"baz\nbar\nfoo\n">>}, 3000),
        ?receivePattern({'DOWN', _, process, P, normal}, 5000)
    end.

test_std(Stream) ->
    Suffix = case Stream of
             stderr -> " 1>&2";
             stdout -> ""
             end,
    {ok, _, I} = exec:run("for i in 1 2; do echo TEST$i; sleep 0.05; done" ++ Suffix, [Stream]),
    ?receiveBytes({Stream,I,<<"TEST1\n">>}, 5000),
    ?receiveBytes({Stream,I,<<"TEST2\n">>}, 5000),

    Filename = temp_file(),
    try
        ?AssertMatch({ok, []}, exec:run("echo Test"++Suffix, [{Stream, Filename}, sync])),
        ?AssertMatch({ok, <<"Test\n">>}, file:read_file(Filename)),

        ?AssertMatch({ok, []}, exec:run("echo Test"++Suffix, [{Stream, Filename}, sync])),
        ?AssertMatch({ok, <<"Test\n">>}, file:read_file(Filename)),

        ?AssertMatch({ok, []}, exec:run("echo Test2"++Suffix, [{Stream, Filename, [append]}, sync])),
        ?AssertMatch({ok, <<"Test\nTest2\n">>}, file:read_file(Filename))

    after
        ?assertEqual(ok, file:delete(Filename))
    end.

test_cmd() ->
    % Cmd given as string
    ?AssertMatch(
        {ok, [{stdout, [<<"ok\n">>]}]},
        exec:run("/bin/echo ok", [sync, stdout])),
    ?AssertMatch(
        {ok, [{stdout, [<<"ok\n">>]}]},
        exec:run(<<"/bin/echo ok">>, [sync, stdout])),
    % Cmd given as list
    ?AssertMatch(
        {ok, [{stdout, [<<"ok\n">>]}]},
        exec:run(["/bin/bash", "-c", "echo ok"], [sync, stdout])),
    ?AssertMatch(
        {ok, [{stdout, [<<"ok\n">>]}]},
        exec:run([<<"/bin/bash">>, <<"-c">>, <<"echo ok">>], [sync, stdout])),
    ?AssertMatch(
        {ok, [{stdout, [<<"ok\n">>]}]},
        exec:run(["/bin/echo", "ok"], [sync, stdout])).

test_executable() ->
    % Cmd given as string
    ?AssertMatch(
        [<<"Pid ", _/binary>>, <<" cannot execute '00kuku00': No such file or directory\n">>],
        begin
            Res = exec:run("ls", [sync, {executable, "00kuku00"}, stdout, stderr]),
            {error,[{exit_status,256},{stderr, [E]}]} = Res,
            binary:split(E, <<":">>)
        end),

    ?AssertMatch(
        {ok, [{stdout,[<<"ok\n">>]}]},
        exec:run("echo ok", [sync, {executable, "/bin/sh"}, stdout, stderr])),

    ?AssertMatch(
        {ok, [{stdout,[<<"ok\n">>]}]},
        exec:run(<<"echo ok">>, [sync, {executable, <<"/bin/sh">>}, stdout, stderr])),

    % Cmd given as list
    ?AssertMatch(
        {ok, [{stdout,[<<"ok\n">>]}]},
        exec:run(["/bin/bash", "-c", "/bin/echo ok"],
                 [sync, {executable, "/bin/sh"}, stdout, stderr])),
    ?AssertMatch(
        {ok, [{stdout,[<<"XYZ\n">>]}]},
        exec:run(["/bin/echoXXXX abc", "XYZ"],
                 [sync, {executable, "/bin/echo"}, stdout, stderr])),
    
    % Cmd given as a unicode string
    File = unicode:characters_to_binary(filename:join(temp_dir(), "тест-эрл")),
    try
        ok = file:write_file(File, "#!/bin/bash\necho ok\n"),
        ok = file:change_mode(File, 8#755),
        ?AssertMatch(
           {ok, [{stdout,[<<"ok\n">>]}]},
           exec:run(File, [sync, stdout, stderr])),
        ?AssertMatch(
           {ok, [{stdout,[<<"ok\n">>]}]},
           exec:run([<<"/bin/bash">>, <<"-c">>, File], [sync, stdout, stderr]))
    after
        ok = file:delete(File)
    end.

test_redirect() ->
    ?AssertMatch({ok,[{stderr,[<<"TEST1\n">>]}]},
        exec:run("echo TEST1", [stderr, {stdout, stderr}, sync])),
    ?AssertMatch({ok,[{stdout,[<<"TEST2\n">>]}]},
        exec:run("echo TEST2 1>&2", [stdout, {stderr, stdout}, sync])),
    ok.

test_redirect_stdin() ->
    ?AssertMatch("ttt\n",
        os:cmd("echo ttt > /tmp/output.txt; cat /tmp/output.txt")),
    ?AssertMatch({ok,[{stdout,[<<"ttt\n">>]}]},
        exec:run("cat", [{stdin, "/tmp/output.txt"}, sync, stdout])),
    ?AssertMatch({ok,[{stdout,[<<"ttt\n">>]}]},
        exec:run("cat", [{stdin, <<"/tmp/output.txt">>}, sync, stdout])),
    file:delete("/tmp/output.txt").

test_env() ->
    ?AssertMatch({ok, [{stdout, [<<"X-Y\n">>]}]},
        exec:run("echo $XXX-$YYY", [stdout, {env, [{"XXX", "X"}, {<<"YYY">>, <<"Y">>}]}, sync])).

test_kill_timeout() ->
    %{ok, _OldDebug} = exec:debug(3),
    {ok, P2, I2} = exec:run("trap 'echo Got signal' SIGTERM; sleep 15", [{kill_timeout, 1}, stdout, monitor]),
    timer:sleep(200),
    exec:stop(I2),
    timer:sleep(50),
    %exec:debug(_OldDebug),
    ?receivePattern({'DOWN', I2, process, P2, normal}, 5000).

test_setpgid() ->
    % Cmd given as string
    {ok, P0, P} = exec:run("sleep  1", [{group, 0}, kill_group, monitor]),
    {ok, P1, _} = exec:run("sleep 15", [{group, P}, monitor]),
    {ok, P2, _} = exec:run("sleep 15", [{group, P}, monitor]),
    ?receivePattern({'DOWN',_,process, P0, normal}, 5000),
    ?receivePattern({'DOWN',_,process, P1, {exit_status, 15}}, 5000),
    ?receivePattern({'DOWN',_,process, P2, {exit_status, 15}}, 5000).

test_pty() ->
    ?AssertMatch({error,[{exit_status,256},{stdout,[<<"not a tty\n">>]}]},
        exec:run("tty", [stdin, stdout, sync])),
    ?assert(case exec:run("tty", [stdin, stdout, pty, sync]) of
        {ok,[{stdout,[<<"/dev/pts/", _/binary>>|_]}]} ->
            true;
        % on macos, the pty has the format /dev/ttysXXX
        {ok,[{stdout,[<<"/dev/ttys", _/binary>>|_]}]} ->
            true;
        _ -> false
    end),
    {ok, P, I} = exec:run("/bin/bash --norc -i", [stdin, stdout, pty, monitor]),
    ok = exec:send(I, <<"echo ok\n">>),
    receive
    {stdout, I, <<"echo ok\r\n">>} ->
        ?receiveBytes({stdout, I, <<"ok\r\n">>}, 1000);
    {stdout, I, <<"ok\r\n">>} ->
        ok
    after 1000 ->
        ?AssertMatch({stdout, I, <<"ok\r\n">>}, timeout)
    end,
    ok = exec:send(I, <<"exit\n">>),
    ?receivePattern({'DOWN', _, process, P, normal}, 1000).

test_pty_echo() ->
    % without echo
    {ok, _, I} = exec:run("echo started && cat", [
        stdin,
        stdout,
        {stderr, stdout},
        pty,
        monitor
    ]),
    ?receiveBytes({stdout, I, <<"started\r\n">>}, 5000),
    ok = exec:send(I, <<"test\n">>),
    ?receiveBytes({stdout, I, <<"test\r\n">>}, 5000),
    ok = exec:kill(I, 9),
    % with echo
    {ok, _, I2} = exec:run("echo started && cat", [
        stdin,
        stdout,
        {stderr, stdout},
        pty,
        pty_echo,
        monitor
    ]),
    ?receiveBytes({stdout, I2, <<"started\r\n">>}, 5000),
    ok = exec:send(I2, <<"test\n">>),
    ?receiveBytes({stdout, I2, <<"test\r\ntest\r\n">>}, 5000).

test_pty_opts() ->
    ?AssertMatch({error,[{exit_status,256},{stdout,[<<"not a tty\n">>]}]},
        exec:run("tty", [stdin, stdout, sync])),
    ?assert(case exec:run("tty", [stdin, stdout, {pty, []}, sync]) of
        {ok,[{stdout,[<<"/dev/pts/", _/binary>>|_]}]} ->
            true;
        {ok,[{stdout,[<<"/dev/ttys", _/binary>>|_]}]} ->
            true;
        _ -> false
    end),
    % without echo
    {ok, P, I} = exec:run("echo started && cat", [
        stdin,
        stdout,
        {stderr, stdout},
        {pty, [{echo, false}]},
        monitor
    ]),
    ?receiveBytes({stdout, I, <<"started\r\n">>}, 5000),
    ok = exec:send(I, <<"test\n">>),
    ?receiveBytes({stdout, I, <<"test\r\n">>}, 5000),
    ok = exec:kill(I, 9),
    ?receivePattern({'DOWN', I, process, P, {exit_status, 9}}, 5000),
    % with echo
    {ok, P2, I2} = exec:run("echo started && cat", [
        stdin,
        stdout,
        {stderr, stdout},
        {pty, [{echo, true}]},
        monitor
    ]),
    ?receiveBytes({stdout, I2, <<"started\r\n">>}, 5000),
    ok = exec:send(I2, <<"test\n">>),
    ?receiveBytes({stdout, I2, <<"test\r\ntest\r\n">>}, 5000),
    % send ^C
    ok = exec:send(I2, <<3>>),
    ?receiveBytes({stdout, I2, <<"^C">>}, 1000),
    ?receivePattern({'DOWN', I2, process, P2, {exit_status, 2}}, 5000),
    % vintr test
    {ok, P3, I3} = exec:run("echo started && cat", [
        stdin,
        stdout,
        {stderr, stdout},
        {pty, [{echo, true}, {vintr, 2}]},
        monitor
    ]),
    ?receiveBytes({stdout, I3, <<"started\r\n">>}, 5000),
    ok = exec:send(I3, <<"test">>),
    ?receiveBytes({stdout, I3, <<"test">>}, 5000),
    % send ^C (3), should not interrupt
    ok = exec:send(I3, <<3>>),
    ?receiveBytes({stdout, I3, <<"^C">>}, 5000),
    % send ^B (2), should interrupt
    ok = exec:send(I3, <<2>>),
    ?receiveBytes({stdout, I3, <<"^B">>}, 5000),
    ?receivePattern({'DOWN', I3, process, P3, {exit_status, 2}}, 5000),
    % opts validation
    ?AssertMatch(
        {error,{invalid_pty_value,[{vintr,false},
                                   {tty_op_ispeed,-1},
                                   {invalid,1}]}},
        exec:run("echo not ok", [
            sync,
            stdin,
            stdout,
            {pty, [
                {echo, true},
                {echoke, 0},
                {echoe, false},
                {vintr, false},
                {verase, 13},
                {tty_op_ispeed, -1},
                {invalid, 1}
            ]}])).

test_dynamic_pty_opts() ->
    % without echo
    {ok, P, I} = exec:run("echo started && cat", [
        stdin,
        stdout,
        {stderr, stdout},
        pty,
        monitor
    ]),
    ?receiveBytes({stdout, I, <<"started\r\n">>}, 5000),
    ok = exec:send(I, <<"test\n">>),
    ?receiveBytes({stdout, I, <<"test\r\n">>}, 5000),
    ok = exec:send(I, <<2>>),
    ok = exec:send(I, <<"\n">>),
    ?receiveBytes({stdout, I, <<2, 13, 10>>}, 5000),
    % change echo to 1, interrupt to ^B
    ok = exec:pty_opts(I, [{echo, 1}, {vintr, 2}]),
    % opts validation
    ?AssertMatch(
        {error,{invalid_pty_value,[{vintr,false},
                                   {tty_op_ispeed,-1},
                                   {invalid,1}]}},
        exec:pty_opts(I, [
            {echo, true},
            {echoke, 0},
            {echoe, false},
            {vintr, false},
            {verase, 13},
            {tty_op_ispeed, -1},
            {invalid, 1}
        ])),
    ok = exec:send(I, <<"test\n">>),
    ?receiveBytes({stdout, I, <<"test\r\ntest\r\n">>}, 5000),
    % send ^B
    ok = exec:send(I, <<2>>),
    ?receiveBytes({stdout, I, <<"^B">>}, 5000),
    ?receivePattern({'DOWN', I, process, P, {exit_status, 2}}, 5000).
-endif.
