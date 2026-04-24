# Erlexec - OS Process Manager for the Erlang VM

[![build](https://github.com/saleyn/erlexec/actions/workflows/erlang.yml/badge.svg)](https://github.com/saleyn/erlexec/actions/workflows/erlang.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/erlexec.svg)](https://hex.pm/packages/erlexec)
[![Hex.pm](https://img.shields.io/hexpm/dt/erlexec.svg)](https://hex.pm/packages/erlexec)

**Author** Serge Aleynikov <saleyn(at)gmail.com>

## Summary ##

Execute and control OS processes from Erlang/OTP.

This project implements an Erlang application with a C++ port program
that gives light-weight Erlang processes fine-grain control over
execution of OS processes.

The following features are supported:

* Start/stop OS commands and get their OS process IDs, and termination reason
  (exit code, signal number, core dump status).
* Support OS commands with unicode characters.
* Manage/monitor externally started OS processes.
* Execute OS processes synchronously and asynchronously.
* Set OS command's working directory, environment, process group, effective user, process priority.
* Provide custom termination command for killing a process or relying on
  default SIGTERM/SIGKILL behavior.
* Specify custom timeout for SIGKILL after the termination command or SIGTERM
  was executed and the running OS child process is still alive.
* Link Erlang processes to OS processes (via intermediate Erlang Pids that are linked
  to an associated OS process), so that the termination of an OS process results
  in termination of an Erlang Pid, and vice versa.
* Monitor termination of OS processes using `erlang:monitor/2`.
* Terminate all processes belonging to an OS process group.
* Kill processes belonging to an OS process group at process exit.
* Communicate with an OS process via its STDIN.
* Redirect STDOUT and STDERR of an OS process to a file, erlang process,
  or a custom function. When redirected to a file, the file can be open in
  append/truncate mode, and given at creation an access mask.
* Run interactive processes with psudo-terminal pty support.
* Support all RFC4254 pty psudo-terminal options defined in
  [section-8](https://datatracker.ietf.org/doc/html/rfc4254#section-8) of the spec.
  PTY commands use the session/process group created by `setsid()`, so
  `{group, 0}` remains the equivalent of "own process group" in PTY mode.
* Execute OS processes under different user credentials (using Linux capabilities).
* Perform proper cleanup of OS child processes at port program termination time.

This application provides significantly better control
over OS processes than built-in `erlang:open_port/2` command with a
`{spawn, Command}` option, and performs proper OS child process cleanup
when the emulator exits.

The `erlexec` application has been in production use by Erlang and Elixir systems,
and is considered stable.

## Donations ##
If you find this project useful, please donate to:
* Bitcoin: `12pt8TcoMWMkF6iY66VJQk95ntdN4pFihg`
* Ethereum: `0x268295486F258037CF53E504fcC1E67eba014218`

## Supported Platforms

Linux, Solaris, FreeBSD, DragonFly, OpenBSD, MacOS X

## DOCUMENTATION ##

See https://hexdocs.pm/erlexec/readme.html

## USAGE ##

### Erlang: import as a dependency ###

- Add dependency in `rebar.config`:
```erlang
{deps,
 [% ...
  {erlexec, "~> 2.0"}
  ]}.
```

- Include in your `*.app.src`:
```erlang
{applications,
   [kernel,
    stdlib,
    % ...
    erlexec
   ]}
```

### Elixir: import as a dependency ###

```elixir
defp deps do
  [
    # ...
    {:erlexec, "~> 2.0"}
  ]
end
```

## BUILDING FROM SOURCE ##

Make sure you have [rebar](http://github.com/basho/rebar) or
[rebar3](http://github.com/basho/rebar3) installed locally and the rebar script
is in the path.

If you are deploying the application on Linux and would like to
take advantage of exec-port running tasks using effective user IDs
different from the real user ID that started exec-port, then
either make sure that libcap-dev[el] library is installed or make
sure that the user running the port program has `sudo` rights.

OS-specific libcap-dev installation instructions:

* Fedora, CentOS: "yum install libcap-devel"
* Ubuntu:         "apt-get install libcap-dev"

```bash
$ git clone git@github.com:saleyn/erlexec.git
$ make

# NOTE: for disabling optimized build of exec-port, do the following instead:
$ OPTIMIZE=0 make
```

By default port program's implementation uses `poll(2)` call for event
demultiplexing. If you prefer to use `select(2)`, set the following environment
variable:
```bash
$ USE_POLL=0 make
```

## LICENSE ##

The program is distributed under BSD license.

Copyright (c) 2003 Serge Aleynikov

## Architecture

<pre>
┌───────────────────────────┐
│   ┌────┐ ┌────┐ ┌────┐    │
│   │Pid1│ │Pid2│ │PidN│    │   Erlang light-weight Pids associated
│   └────┘ └────┘ └────┘    │   one-to-one with managed OsPids
│         ╲   │   ╱         │
│          ╲  │  ╱          │
│           ╲ │ ╱ (links)   │
│         ┌──────┐          │
│         │ exec │          │   Exec application running in Erlang VM
│         └──────┘          │
│ Erlang VM   │             │
└─────────────┼─────────────┘
              │
        ┌───────────┐
        │ exec-port │           Port program (separate OS process)
        └───────────┘
         ╱    │    ╲
(optional stdin/stdout/stderr pipes)
       ╱      │      ╲
  ┌──────┐ ┌──────┐ ┌──────┐
  │OsPid1│ │OsPid2│ │OsPidN│    Managed Child OS processes
  └──────┘ └──────┘ └──────┘
</pre>

## Configuration Options

See description of types in {@link exec:exec_options()}.

The `exec-port` program requires the `SHELL` variable to be set. If you are
running Erlang inside a docker container, you might need to ensure that `SHELL`
is properly set prior to starting the emulator.

## Debugging

`exec` supports several debugging options passed to `exec:start/1`:

* `{debug, Level}` - turns on debug verbosity in the port program.
* `verbose`        - turns on verbosity in the Erlang code.
* `valgrind`       - runs exec under the Valgrind tool, which needs
  to be installed in the OS. This generates a local
  `valgrind.YYYYMMDDhhmmss.log` file containing Valgrind's output.
  If you need to customize the Valgrind command options, use
  `{valgrind, "/path/to/valgrind Args ..."}` option.

## Examples

### Starting/stopping an OS process
```erlang
1> exec:start().                                        % Start the port program.
{ok,<0.32.0>}
2> {ok, _, I} = exec:run_link("sleep 1000", []).        % Run a shell command to sleep for 1000s.
{ok,<0.34.0>,23584}
3> exec:stop(I).                                        % Kill the shell command.
ok                                                      % Note that this could also be accomplished
                                                        % by doing exec:stop(pid(0,34,0)).
```
In Elixir:
```elixir
iex(1)> :exec.start
{:ok, #PID<0.112.0>}
iex(2)> :exec.run("echo ok", [:sync, :stdout])
{:ok, [stdout: ["ok\n"]]}

iex(3)> :exec.run(["/bin/echo", "ok"], [:sync, :stdout])
{:ok, [stdout: ["ok\n"]]}
```

### Clearing environment or unsetting an env variable of the child process
```erlang
%% Clear environment with {env, [clear]} option:
10> f(Bin), {ok, [{stdout, [Bin]}]} = exec:run("env", [sync, stdout, {env, [clear]}]), io:format("~s\n", [re:split(Bin, <<"\n">>)]).
[<<"PWD=/home/...">>,<<"SHLVL=0">>, <<"_=/usr/bin/env">>,<<>>]
ok
%% Clear env and add a "TEST" env variable:
11> f(Bin), {ok, [{stdout, [Bin]}]} = exec:run("env", [sync, stdout, {env, [clear, {"TEST", "xxx"}]}]), io:format("~s\n", [re:split(Bin, <<"\n">>)]).
[<<"PWD=/home/...">>,<<"SHLVL=0">>, <<"_=/usr/bin/env">>,<<"TEST=xxx">>,<<>>]
%% Unset an "EMU" env variable:
11> f(Bin), {ok, [{stdout, [Bin]}]} = exec:run("env", [sync, stdout, {env, [{"EMU", false}]}]), io:format("~s\n", [re:split(Bin, <<"\n">>)]).
[...]
ok
%% Set an env variable to an empty string (use "" as the value, not false):
12> f(Bin), {ok, [{stdout, [Bin]}]} = exec:run("env", [sync, stdout, {env, [{"MY_VAR", ""}]}]), io:format("~s\n", [re:split(Bin, <<"\n">>)]).
[..., <<"MY_VAR=">>, ...]
ok
```

### Running exec-port as another effective user

In order to be able to use this feature the current user must either have `sudo`
rights or the `exec-port` file must be owned by `root` and have the SUID bit set
(use: `chown root:root exec-port; chmod 4555 exec-port`):

```bash
$ ll priv/x86_64-unknown-linux-gnu/exec-port
-rwsr-xr-x 1 root root 777336 Dec  8 10:02 ./priv/x86_64-unknown-linux-gnu/exec-port
```

If the effective user doesn't have rights to access the `exec-port`
program in the real user's directory, then the `exec-port` can be copied to some
shared location, which will be specified at startup using
`{portexe, "/path/to/exec-port"}`.

```erlang
$ cp $(find . -name exec-port) /tmp
$ chmod 755 /tmp/exec-port

$ whoami
serge

$ erl
1> exec:start([{user, "wheel"}, {portexe, "/tmp/exec-port"}]).  % Start the port program as effective user "wheel".
{ok,<0.32.0>}

$ ps haxo user,comm | grep exec-port
wheel      exec-port
```

### Allowing exec-port to run commands as other effective users

In order to be able to use this feature the current user must either have `sudo`
rights or the `exec-port` file must have the SUID bit set, and the `exec-port` file
must have the capabilities set as described in the "Build" section above.

The port program will initially be started as `root`, and then it will 
switch the effective user to `{user, User}` and set process capabilities to
`cap_setuid,cap_kill,cap_sys_nice`.  After that it'll allow to run child programs
under effective users listed in the `{limit_users, Users}` option.

```erlang
$ whoami
serge

$ erl
1> Opts = [root, {user, "wheel"}, {limit_users, ["alex","guest"]}],
2> exec:start(Opts).                                    % Start the port program as effective user "wheel"
                                                        % and allow it to execute commands as "alex" or "guest".
{ok,<0.32.0>}
3> exec:run("whoami", [sync, stdout, {user, "alex"}]).  % Command is executed under effective user "alex"
{ok,[{stdout,[<<"alex\n">>]}]}

$ ps haxo user,comm | grep exec-port
wheel      exec-port
```

### Linux Capabilities Support

The `erlexec` application on Linux supports setting Linux kernel capabilities on the port program.
This allows fine-grained control over what privileged operations the port program can perform
without requiring full root access. Capabilities are propagated to child processes automatically.

#### Available Capabilities

The following Linux capabilities can be specified (see `man 7 capabilities` for details):

- `cap_setuid` - Change UID/GID of processes
- `cap_kill` - Send signals to processes
- `cap_sys_nice` - Set process priority
- `cap_net_bind_service` - Bind to ports < 1024
- `cap_net_admin` - Network administration (configure interfaces, etc.)
- And 30+ others...

#### Using Specific Capabilities

You can start the port program with specific capabilities for your use case:

```erlang
$ whoami
serge

$ erl
1> Opts = [{capabilities, [setuid, kill, sys_nice]}],   % "cap_" prefix is optional
2> exec:start(Opts).                                    % Start with specific capabilities
{ok,<0.32.0>}
3> exec:run("whoami", [sync, stdout]).                  % Command inherits specified capabilities
{ok,[{stdout,[<<"serge\n">>]}]}
```

#### Using All Capabilities

To enable all available Linux capabilities, use the `all` keyword:

```erlang
1> exec:start([{capabilities, all}]).                   % Enable all capabilities
{ok,<0.32.0>}
2> exec:run("whoami", [sync, stdout]).                  % Command inherits all capabilities
{ok,[{stdout,[<<"serge\n">>]}]}
```

#### Using Default Capabilities

When no `capabilities` option is specified, the port program uses default capabilities
(`setuid`, `kill`, `sys_nice`):

```erlang
1> exec:start([]).                                       % Uses default capabilities
{ok,<0.32.0>}
```

#### Combining with User Switching

Capabilities work seamlessly with user switching. This allows the port program
to run as a non-root user while still having necessary capabilities:

```erlang
1> Opts = [root, {user, "nobody"}, 
           {limit_users, ["alex", "guest"]},
           {capabilities, [cap_setuid, cap_kill]}],
2> exec:start(Opts).                                    % Run as "nobody" with specific caps
{ok,<0.32.0>}
3> exec:run("whoami", [sync, stdout, {user, "alex"}]).  % Run command as "alex"
{ok,[{stdout,[<<"alex\n">>]}]}
```

#### Capability Propagation

When capabilities are set on the port program, they are automatically propagated
to child processes as inheritable capabilities. This means child processes can acquire additional capabilities beyond what they would normally have access to.
This is useful for:

- Container environments where the port program has specific capabilities
- Allowing child processes to perform privileged operations without SUID
- Fine-grained permission control in multi-tenant environments

Note: Capabilities are only supported on Linux systems and require the `libcap`
library. On other systems or when libcap is not available, capability options
are ignored gracefully.

### Running the port program as root

While running the port program as root is highly discouraged, since it opens a
security hole that gives users an ability to damage the system, for those who
might need such an option, here is how to get it done (PROCEED AT YOUR OWN
RISK!!!).

Note: in this case `exec` would use `sudo exec-port` to run it as `root` or the
`exec-port` must have the SUID bit set (4555) and be owned by `root`.  The other
(DANGEROUS and firmly DISCOURAGED!!!) alternative is to run `erl` as `root`:

```erlang
$ whoami
serge

# Make sure the exec-port can run as root:
$ sudo _build/default/lib/erlexec/priv/*/exec-port --whoami
root

$ erl
1> exec:start([root, {user, "root"}, {limit_users, ["root"]}]).
2> exec:run("whoami", [sync, stdout]).
{ok, [{stdout, [<<"root\n">>]}]}

$ ps haxo user,comm | grep exec-port
root       exec-port
```

### Killing an OS process

Note that killing a process can be accomplished by running kill(3) command
in an external shell, or by executing exec:kill/2.
```erlang
1> f(I), {ok, _, I} = exec:run_link("sleep 1000", []).
{ok,<0.37.0>,2350}
2> exec:kill(I, 15).
ok
** exception error: {exit_status,15}                    % Our shell died because we linked to the
                                                        % killed shell process via exec:run_link/2.

3> exec:status(15).                                     % Examine the exit status.
{signal,15,false}                                       % The program got SIGTERM signal and produced
                                                        % no core file.
```

### Using a custom success return code
```erlang
1> exec:start_link([]).
{ok,<0.35.0>}
2> exec:run_link("sleep 1", [{success_exit_code, 0}, sync]).
{ok,[]}
3> exec:run("sleep 1", [{success_exit_code, 1}, sync]).
{error,[{exit_status,1}]}                               % Note that the command returns exit code 1
```

### Redirecting OS process stdout to a file
```erlang
7> f(I), {ok, _, I} = exec:run_link("for i in 1 2 3; do echo \"Test$i\"; done",
    [{stdout, "/tmp/output"}]).
8> io:format("~s", [binary_to_list(element(2, file:read_file("/tmp/output")))]),
   file:delete("/tmp/output").
Test1
Test2
Test3
ok
```

### Redirecting OS process stdout to screen, an Erlang process or a custom function
```erlang
9> exec:run("echo Test", [{stdout, print}]).
{ok,<0.119.0>,29651}
Got stdout from 29651: <<"Test\n">>

10> exec:run("for i in 1 2 3; do sleep 1; echo \"Iter$i\"; done",
            [{stdout, fun(S,OsPid,D) -> io:format("Got ~w from ~w: ~p\n", [S,OsPid,D]) end}]).
{ok,<0.121.0>,29652}
Got stdout from 29652: <<"Iter1\n">>
Got stdout from 29652: <<"Iter2\n">>
Got stdout from 29652: <<"Iter3\n">>

% Note that stdout/stderr options are equivanet to {stdout, self()}, {stderr, self()} 
11> exec:run("echo Hello World!; echo ERR!! 1>&2", [stdout, stderr]).
{ok,<0.244.0>,18382}
12> flush().
Shell got {stdout,18382,<<"Hello World!\n">>}
Shell got {stderr,18382,<<"ERR!!\n">>}
ok
```

### Appending OS process stdout to a file
```erlang
13> exec:run("for i in 1 2 3; do echo TEST$i; done",
        [{stdout, "/tmp/out", [append, {mode, 8#600}]}, sync]),
    file:read_file("/tmp/out").
{ok,<<"TEST1\nTEST2\nTEST3\n">>}
14> exec:run("echo Test4; done", [{stdout, "/tmp/out", [append, {mode, 8#600}]}, sync]),
    file:read_file("/tmp/out").
{ok,<<"TEST1\nTEST2\nTEST3\nTest4\n">>}
15> file:delete("/tmp/out").
```

### Setting up a monitor for the OS process
```erlang
> f(I), f(P), {ok, P, I} = exec:run("echo ok", [{stdout, self()}, monitor]).
{ok,<0.263.0>,18950}
16> flush().
Shell got {stdout,18950,<<"ok\n">>}
Shell got {'DOWN',18950,process,<0.263.0>,normal}
ok
```

### Managing an externally started OS process
This command allows to instruct erlexec to begin monitoring given OS process
and notify Erlang when the process exits. It is also able to send signals to
the process and kill it.
```erlang
% Start an externally managed OS process and retrieve its OS PID:
17> spawn(fun() -> os:cmd("echo $$ > /tmp/pid; sleep 15") end).
<0.330.0>
18> f(P), P = list_to_integer(lists:reverse(tl(lists:reverse(binary_to_list(element(2,
file:read_file("/tmp/pid"))))))).
19355

% Manage the process and get notified by a monitor when it exits:
19> exec:manage(P, [monitor]).
{ok,<0.334.0>,19355}

% Wait for monitor notification
20> f(M), receive M -> M end.
{'DOWN',19355,process,<0.334.0>,{exit_status,10}}
ok
21> file:delete("/tmp/pid").
ok
```

### Specifying a custom process shutdown delay in seconds
```erlang
% Execute an OS process (script) that blocks SIGTERM with custom kill timeout, and monitor
22> f(I), {ok, _, I} = exec:run("trap '' SIGTERM; sleep 30", [{kill_timeout, 3}, monitor]).
{ok,<0.399.0>,26347}
% Attempt to stop the OS process
23> exec:stop(I).
ok
% Wait for its completion
24> f(M), receive M -> M after 10000 -> timeout end.
{'DOWN',26347,process,<0.403.0>,normal}
```

### Specifying a custom kill command for a process
```erlang
% Execute an OS process (script) that blocks SIGTERM, and uses a custom kill command,
% which kills it with a SIGINT. Add a monitor so that we can wait for process exit
% notification. Note the use of the special environment variable "CHILD_PID" by the
% kill command. This environment variable is set by the port program before invoking
% the kill command:
2> f(I), {ok, _, I} = exec:run("trap '' SIGTERM; sleep 30", [{kill, "kill -n 2 ${CHILD_PID}"},
                                                             {kill_timeout, 2}, monitor]).
{ok,<0.399.0>,26347}
% Try to kill by SIGTERM. This does nothing, since the process is blocking SIGTERM:
3> exec:kill(I, sigterm), f(M), receive M -> M after 0 -> timeout end.
timeout
% Attempt to stop the OS process
4> exec:stop(I).
ok
% Wait for its completion
5> f(M), receive M -> M after 1000 -> timeout end.
{'DOWN',26347,process,<0.403.0>,normal}
```

### Communicating with an OS process via STDIN
```erlang
% Execute an OS process (script) that reads STDIN and echoes it back to Erlang
25> f(I), {ok, _, I} = exec:run("read x; echo \"Got: $x\"", [stdin, stdout, monitor]).
{ok,<0.427.0>,26431}
% Send the OS process some data via its stdin
26> exec:send(I, <<"Test data\n">>).
ok
% Get the response written to processes stdout
27> f(M), receive M -> M after 10000 -> timeout end.
{stdout,26431,<<"Got: Test data\n">>}
% Confirm that the process exited
28> f(M), receive M -> M after 10000 -> timeout end.
{'DOWN',26431,process,<0.427.0>,normal}
```

### Communicating with an OS process via STDIN and sending end-of-file

Sometimes a spawned child OS process receiving stdin input needs to detect the
end of input in order to process incoming data. When piping commands (e.g.
`cat file | tac`) this is handled by detecting the EOF by the reading end of the
pipe when the writing end of the pipe is closed.  In `erlexec` this is handled
by explicitly sending the `eof` atom to the OS process that listens to STDIN:

```erlang
2> Watcher = spawn(fun F() -> receive Msg -> io:format("Got: ~p\n", [Msg]), F() after 60000 -> ok end end).
<0.112.0>
3> f(Pid), f(OsPid), {ok, Pid, OsPid} = exec:run("tac", [stdin, {stdout, Watcher}, {stderr, Watcher}]).
{ok,<0.114.0>,26143}
4> exec:send(Pid, <<"foo\n">>).
ok
5> exec:send(Pid, <<"bar\n">>).
ok
6> exec:send(Pid, <<"baz\n">>).
ok
7> exec:send(Pid, eof).   %% <--- sending the EOF command to the STDIN
ok
Got: {stdout,26143,<<"baz\nbar\nfoo\n">>}
```

### Running OS commands synchronously
```erlang
% Execute an shell script that blocks for 1 second and return its termination code
29> exec:run("sleep 1; echo Test", [sync]).
% By default all I/O is redirected to /dev/null, so no output is captured
{ok,[]}

% 'stdout' option instructs the port program to capture stdout and return it to caller
30> exec:run("sleep 1; echo Test", [stdout, sync]).
{ok,[{stdout, [<<"Test\n">>]}]}

% Execute a non-existing command
31> exec:run("echo1 Test", [sync, stdout, stderr]).
{error,[{exit_status,32512},
        {stderr,[<<"/bin/bash: echo1: command not found\n">>]}]}

% Capture stdout/stderr of the executed command
32> exec:run("echo Test; echo Err 1>&2", [sync, stdout, stderr]).
{ok,[{stdout,[<<"Test\n">>]},{stderr,[<<"Err\n">>]}]}

% Redirect stderr to stdout
33> exec:run("echo Test 1>&2", [{stderr, stdout}, stdout, sync]).
{ok, [{stdout, [<<"Test\n">>]}]}
```

### Running OS commands with/without shell
```erlang
% Execute a command by an OS shell interpreter
34> exec:run("echo ok", [sync, stdout]).
{ok, [{stdout, [<<"ok\n">>]}]}

% Execute an executable without a shell (note that in this case
% the full path to the executable is required):
35> exec:run(["/bin/echo", "ok"], [sync, stdout]).
{ok, [{stdout, [<<"ok\n">>]}]}

% Execute a shell with custom options
36> exec:run(["/bin/bash", "-c", "echo ok"], [sync, stdout]).
{ok, [{stdout, [<<"ok\n">>]}]}
```

### Running OS commands with pseudo terminal (pty)
```erlang
% Execute a command without a pty
37> exec:run("echo hello", [sync, stdout]).
{ok, [{stdout,[<<"hello\n">>]}]}

% Execute a command with a pty
38> exec:run("echo hello", [sync, stdout, pty]).
{ok,[{stdout,[<<"hello">>,<<"\r\n">>]}]}

% Execute a command with pty echo
39> {ok, P0, I0} = exec:run("cat", [stdin, stdout, {stderr, stdout}, pty, pty_echo]).
{ok,<0.162.0>,17086}
40> exec:send(I0, <<"hello">>).
ok
41> flush().
Shell got {stdout,17086,<<"hello">>}
ok
42> exec:send(I0, <<"\n">>).
ok
43> flush().
Shell got {stdout,17086,<<"\r\n">>}
Shell got {stdout,17086,<<"hello\r\n">>}
ok
44> exec:send(I, <<3>>).
ok
45> flush().
Shell got {stdout,17086,<<"^C">>}
Shell got {'DOWN',17086,process,<0.162.0>,{exit_status,2}}
ok

% Execute a command with custom pty options
46> {ok, P1, I1} = exec:run("cat", [stdin, stdout, {stderr, stdout}, {pty, [{vintr, 2}]}, monitor]).
{ok,<0.199.0>,16662}
47> exec:send(I1, <<3>>).
ok
48> flush().
ok
49> exec:send(I1, <<2>>).
ok
50> flush().
Shell got {'DOWN',16662,process,<0.199.0>,{exit_status,2}}
ok
```

#### Important Note: PTY stdout/stderr Separation

When using PTY mode, **stdout and stderr cannot be separated** because they are
both connected to the same PTY master file descriptor. This is a fundamental
characteristic of how pseudo-terminals work - they multiplex both streams into a
single data stream, similar to how SSH handles TTY connections.

If you use `pty` with both `stdout` and `stderr` options, **all output will appear
only in stdout, and stderr will receive nothing**:

```erlang
% With pty and both stdout/stderr: all data goes to stdout, stderr is empty
exec:run("echo Test\necho ERR 1>&2", [sync, stdout, stderr, pty]).
{ok,[{stdout,[<<"Test\r\nERR\r\n">>]}]}
```

**Recommended workaround for clarity**: Explicitly redirect stderr to stdout
using `{stderr, stdout}` when using `pty` mode:

```erlang
% All output flows through a single coherent stream in stdout
exec:run("echo Test\necho ERR 1>&2", [sync, stdout, {stderr, stdout}, pty]).
{ok,[{stdout,[<<"Test\r\nERR\r\n">>]}]}
```

If you need **clear separation** of stdout and stderr, **do not use PTY mode**:

```erlang
% Without pty: stdout and stderr are properly separated
exec:run("echo Test\necho ERR 1>&2", [sync, stdout, stderr]).
{ok,[{stdout,[<<"Test\n">>]}, {stderr,[<<"ERR\n">>]}]}
```
 
### Kill a process group at process exit
```erlang
% In the following scenario the process P0 will create a new process group
% equal to the OS pid of that process (value = GID). The next two commands
% are assigned to the same process group GID. As soon as the P0 process exits
% P1 and P2 will also get terminated by signal 15 (SIGTERM):
51> {ok, P2, GID} = exec:run("sleep 10",  [{group, 0},   kill_group]).
{ok,<0.37.0>,25306}
52> {ok, P3,   _} = exec:run("sleep 15",  [{group, GID}, monitor]).
{ok,<0.39.0>,25307}
53> {ok, P4,   _} = exec:run("sleep 15",  [{group, GID}, monitor]).
{ok,<0.41.0>,25308}
54> flush().
Shell got {'DOWN',25307,process,<0.39.0>,{exit_status,15}}
Shell got {'DOWN',25308,process,<0.41.0>,{exit_status,15}}
ok
```
