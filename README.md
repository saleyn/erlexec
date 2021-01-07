# erlexec #

[![Build Status](https://travis-ci.org/saleyn/erlexec.svg?branch=master)](https://travis-ci.org/saleyn/erlexec)
[![Hex.pm](https://img.shields.io/hexpm/v/erlexec.svg)](https://hex.pm/packages/erlexec)
[![Hex.pm](https://img.shields.io/hexpm/dt/erlexec.svg)](https://hex.pm/packages/erlexec)

Execute and control OS processes from Erlang/OTP.

This project implements an Erlang application with a C++ port program
that gives light-weight Erlang processes fine-grain control over
execution of OS processes.

The following features are supported:

* Start/stop OS commands and get their OS process IDs, and termination reason
  (exit code, signal number, core dump status).
* Manage/monitor externally started OS processes.
* Execute OS processes synchronously and asynchronously.
* Set OS command's working directory, environment, process group, effective user, process priority.
* Provide custom termination command for killing a process or relying on
  default SIGTERM/SIGKILL behavior.
* Specify custom timeout for SIGKILL after the termination command or SIGTERM
  was executed and the running OS child process is still alive.
* Link an Erlang processes to OS processes (via intermediate Erlang Pids that are linked
  to an associated OS process).
* Monitor termination of OS processes.
* Terminate all processes beloging to an OS process group.
* Kill processes belonging to an OS process group at process exit.
* Communicate with an OS process via its STDIN.
* Redirect STDOUT and STDERR of an OS process to a file, erlang process, or a custom function.
  When redirected to a file, the file can be open in append/truncate mode, and given creation
  access mask.
* Run interactive processes with psudo-terminal pty support.
* Execute OS processes under different user credentials (using Linux capabilities).
* Perform proper cleanup of OS child processes at port program termination time.

This application provides significantly better control
over OS processes than built-in `erlang:open_port/2` command with a
`{spawn, Command}` option, and performs proper OS child process cleanup
when the emulator exits. 

The `erlexec` application has been in production use by Erlang and Elixir systems,
and is stable.

See http://saleyn.github.com/erlexec for more information.

## SUPPORTED OS's ##
Linux, Solaris, FreeBSD, OpenBSD, MacOS X

## DOCUMENTATION ##
See http://saleyn.github.io/erlexec

## BUILDING ##
Make sure you have rebar (http://github.com/basho/rebar or
http://github.com/basho/rebar3) installed locally and the rebar script
is in the path.

If you are deploying the application on Linux and would like to
take advantage of exec-port running tasks using effective user IDs
different from the real user ID that started exec-port, then
either make sure that libcap-dev[el] library is installed or make
sure that the user running the port program has `sudo` rights.

OS-specific libcap-dev installation instructions:

* Fedora, CentOS: "yum install libcap-devel"
* Ubuntu:         "apt-get install libcap-dev"

```
$ git clone git@github.com:saleyn/erlexec.git
$ make

# NOTE: for disabling optimized build of exec-port, do the following instead:
$ OPTIMIZE=0 make
```

By default port program's implementation uses `poll(2)` call for event
demultiplexing. If you prefer to use `select(2)`, set the following environment
variable:
```
$ USE_POLL=0 make
```

## LICENSE ##
The program is distributed under BSD license.
Copyright (c) 2003 Serge Aleynikov <saleyn at gmail dot com>
