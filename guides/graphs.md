# Process Graphs

`exec:run_graph/2` executes a declarative graph of OS processes: each node is a command plus
a declaration of where its `stdout`/`stderr` goes (a sibling task's stdin, a file, or an
explicit Erlang sink). See the README's ["Running Process Graphs"](../README.md#running-process-graphs)
section for the quick-start examples. This guide focuses on **when `run_graph/2` is worth
reaching for over a plain shell pipe**, with runnable, verified examples for each point.

Internally, data flow between graph tasks runs natively: a producer's stdout is connected via
an OS pipe directly to a consumer's stdin, and the C++ port process reads each chunk once and
writes it to every destination (sibling pipes and/or files) in a tight native loop — the data
never enters the Erlang VM or crosses the Erlang/C++ port boundary. Erlang is only involved for
lifecycle (spawning, monitoring, reaping) and explicit sink delivery (`sink => erl`), which is
exactly the data a caller asked to see.

## `run_graph` vs. shell piping

If what you need is `cmd1 | cmd2 | cmd3`, use `exec:run("cmd1 | cmd2 | cmd3", [...])` — a plain
shell pipe is already native, zero-overhead, and simpler to read. `run_graph/2` earns its
complexity when your topology, observability, or safety needs go beyond what a linear shell
pipe can express. Five concrete cases follow.

### 1. Non-linear topologies (fan-out / fan-in)

A shell pipe is a straight line: one process reads the previous one's output. The moment you
need one producer's output to reach **multiple** consumers (or files, or sinks)
simultaneously, shell syntax runs out — `tee(1)` gets you partway, but doesn't compose cleanly
with further piping per branch, and gives you no structured way to know which branch failed.

```erlang
1> Graph = [
1>     #{id => src,   cmd => "printf 'x\n'", stdout => [left, right]},
1>     #{id => left,  cmd => "cat"},
1>     #{id => right, cmd => "cat >&2"}
1> ],
1> exec:run_graph(Graph, [sync, stdout, stderr]).
{ok,[{stdout,[<<"x\n">>]},{stderr,[<<"x\n">>]}]}
```

One `printf` fans out to two independent consumers (`left` reading via `stdout`, `right` via
`stdout`) — both backed by native OS pipes, no Erlang round-trip for the data itself.  Since
the Erlang caller requests `stdout` and `stderr` output, the `left` and `right`'s output
is delivered to the Erlang caller.

### 2. Per-stage observability

In a shell pipe, the only pid you get back is the whole pipeline's (or, with `$!` tricks, one
specific stage, inconsistently depending on shell/options). Every graph task is a full
`exec:run/2`-managed OS process with its own pid — you can monitor, signal, or inspect any
single stage without disturbing the others.

```erlang
1> Graph = [
1>     #{id => producer, cmd => "printf 'a\nb\nc\n'", stdout => middle},
1>     #{id => middle,   cmd => "sort", stdout => erl}
1> ],
1> {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [stdout, monitor]),
1> receive {stdout, GraphOsPid, Bin} -> Bin end.
<<"a\nb\nc\n">>
```

`stdout => erl` is shorthand for an Erlang sink: `middle`'s output is tapped and delivered
directly to the calling process via `{stdout, GraphOsPid, Bin}`, while `producer`'s output
feeds `middle`'s stdin natively. A shell pipe can't expose an intermediate stage's output
stream without rewriting the pipeline to add an explicit `tee`.

### 3. Structured failure attribution

With a shell pipe, `$?` reflects only the **last** command's exit status (you'd need
`set -o pipefail`, and even then only know *that* an earlier stage failed, not cleanly
*which* reason or exit code without extra plumbing). `run_graph/2` surfaces the first
non-trivial exit status it observes:

```erlang
1> Graph = [
1>     #{id => a, cmd => "echo start", stdout => b},
1>     #{id => b, cmd => "false", stdout => c},  % exits non-zero
1>     #{id => c, cmd => "cat"}
1> ],
1> exec:run_graph(Graph, [sync, stdout]).
{error,[{exit_status,256},{stdout,[]}]}
```

`{exit_status, 256}` is `256 = 1 bsl 8`, i.e. task `b`'s exit code 1 shifted per
`exec`'s [exit-status encoding](../README.md#killing-an-os-process). In async/monitor mode the
same reason arrives via `'DOWN'`:

```erlang
1> {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [monitor]),
1> receive {'DOWN', GraphOsPid, process, Pid, Reason} -> Reason end.
{exit_status,256}
```

This is a `exec`-wide exit-status encoding, not a task-identifying one — `run_graph/2` reports
the first abnormal exit it observes, but doesn't currently label *which* task id triggered it.
If your pipeline needs that distinction, tap each stage with its own sink (see point 2) and
compare which sink stopped receiving data.

Note the `{group, 0}`/`kill_group` mechanism described in the
[process-group section](../README.md#kill-a-process-group-at-process-exit) is deliberately
**not** what graph tasks use for this — `kill_group` tears down the whole group on *any* task's
exit (even a clean, successful one), which would be wrong for a pipeline where early stages are
expected to finish before later ones. Graph tasks instead share a process group purely for
abnormal-exit cleanup (a crash mid-pipeline tears down the rest; a normal finish doesn't).

### 4. Programmatic, injection-safe construction

Building a shell pipe from untrusted input means string-concatenating into a shell command —
classic injection risk unless you're careful with quoting. Graph task `cmd` accepts the same
argv-list form as `exec:run/2`, so user-controlled values never pass through a shell:

```erlang
1> UserPattern = "x; touch /tmp/pwned #",   % hostile input
1> Graph = [
1>     #{id => src, cmd => "printf 'a\nx\nb\n'", stdout => filter},
1>     #{id => filter, cmd => ["/usr/bin/grep", "-F", UserPattern]}
1> ],
1> exec:run_graph(Graph, [sync, stdout]).
{error,[{exit_status,256},{stdout,[]}]}
2> filelib:is_file("/tmp/pwned").
false
```

`UserPattern` is passed as a literal `argv[1]` to `grep -F` — never interpreted by a shell, so
the embedded `;` is just a character in the search string (no line matches that literal text,
hence the no-match exit status), not a command separator. The `touch` never runs. Contrast with
`exec:run("printf '...' | grep -F " ++ UserPattern, [...])`, which would execute the injected
`touch /tmp/pwned` as a second shell command.

(Note: the argv-list form calls `execve` directly, so the first element must resolve as a path
`execve` can run — e.g. `/usr/bin/grep`, not a bare `grep` that depends on `$PATH` lookup done
by a shell.)

### 5. Declarative mixed fan-out (sibling + file in one edge)

A single edge can target a mix of sibling tasks and files, so one line of graph declaration
captures what would otherwise be a `tee`-and-pipe shell construction:

```erlang
1> Graph = [
1>     #{id => src,
1>       cmd => "printf 's3\n'",
1>       stdout => [collector, "/tmp/erlexec-graph-example.log"]},
1>     #{id => collector, cmd => "cat"}
1> ],
1> exec:run_graph(Graph, [sync, stdout]).
{ok,[{stdout,[<<"s3\n">>]}]}
2> file:read_file("/tmp/erlexec-graph-example.log").
{ok,<<"s3\n">>}
```

One `stdout => [collector, Path]` edge both pipes to `collector` and tees to a file —
equivalent to `printf 's3\n' | tee /tmp/erlexec-graph-example.log | cat` in shell terms, but
declared as graph structure rather than imperative piping.

### 6. Per-task and whole-graph wall-clock budgets

A shell pipeline has no built-in way to bound how long any one stage, or the pipeline as a
whole, is allowed to run — you'd reach for `timeout(1)` wrapping the whole command, which only
bounds the *entire* pipe, not an individual stage. Graph tasks support both scopes
independently:

```erlang
1> Graph = [
1>     #{id => slow_stage, cmd => "sleep 10", timeout => 200},  % kills ONLY this task at 200ms
1>     #{id => independent, cmd => "sleep 1"}                   % unaffected by slow_stage's timeout
1> ],
1> exec:run_graph(Graph, [sync, stdout]).
{error,[{exit_status,15},{stdout,[]}]}
```

The per-task `timeout` field only kills that one task (SIGTERM, same escalation `exec:stop/1`
uses) — `independent` keeps running to its own completion regardless. For a budget on the
**whole graph** instead, use the `timeout` key in `run_graph/2`'s `GraphOpts` map (requires the
map form, not the plain options list):

```erlang
1> Graph = [
1>     #{id => a, cmd => "sleep 10"},
1>     #{id => b, cmd => "sleep 10"}
1> ],
1> exec:run_graph(Graph, #{run_options => [sync, stdout], timeout => 300}).
{error,[{timeout,graph},{stdout,[]}]}
```

Here, exceeding the graph-level budget kills **every** task, not just one. The two scopes
compose: give a fast-but-sometimes-hanging task its own tight `timeout`, and still bound the
whole pipeline with a generous outer `timeout` as a backstop.

### 7. Per-stage completion events (`task_monitor`)

Point 2 showed tapping one intermediate stage with an `erl` sink. For visibility into **every**
stage's completion — without wiring up a sink per task — use the `task_monitor` run option in
async mode:

```erlang
1> Graph = [
1>   #{id => a, cmd => "echo a", stdout => b},
1>   #{id => b, cmd => "cat",    stdout => c},
1>   #{id => c, cmd => "cat"}
1> ],
1> {ok,<0.339.0>,-1218} = exec:run_graph(Graph, [monitor, task_monitor]),
1> flush().
Shell got {'DOWN',-1218,task,a,normal}
Shell got {'DOWN',-1218,task,b,normal}
Shell got {'DOWN',-1218,task,c,normal}
Shell got {'DOWN',-1218,process,<0.339.0>,normal}
```

Each task fires its own `{'DOWN', GraphOsPid, task, TaskId, Reason}` as it completes, in
completion order, followed by the usual whole-graph `'DOWN'` once every task has finished.
`task_monitor` composes with `monitor` (shown above) but also works on its own if you only
want per-task events and don't care about a final graph-level notification.

### 8. Resource usage per task (`stats`)

`stats` is a plain `exec:run/2` option (works for any process, graph task or not) that folds
wall-clock duration and `rusage` metrics directly into the exit reason — not a separate
message:

```erlang
1> {ok, Pid, OsPid} = exec:run("sleep 0.1", [stats, monitor]),
1> flush().
Shell got {'DOWN',OsPid,process,Pid,
                  {normal,#{maxrss_kb => 3780,stime_us => 0,utime_us => 1528,
                            wall_time_ms => 101}}}
```

A clean exit's reason becomes `{normal, StatsMap}` instead of plain `normal`; a failure's
becomes `{{exit_status, Status}, StatsMap}`. `utime_us`/`stime_us`/`maxrss_kb` require
`wait4(2)` support (present on Linux/macOS/BSD; absent on Cygwin/Solaris/Windows, where
`StatsMap` only contains `wall_time_ms`). This isn't graph-specific — any `exec:run/2` call can
request it — but it's often most useful on a graph task to see which stage of a pipeline is
actually consuming CPU/memory.

For a graph task specifically, set `stats => true` on that task's own node map (rather than
the graph-wide `stats` run option) to scope it to just that one task; combine with
`task_monitor` (point 7) to see it, since the whole-graph `'DOWN'` never carries any
individual task's stats:

```erlang
1> Graph = [#{id => a, cmd => "sleep 0.1", stats => true}],
1> {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [monitor, task_monitor]),
1> flush().
Shell got {'DOWN',GraphOsPid,task,a,
                  {normal,#{maxrss_kb => 3780,stime_us => 0,utime_us => 1528,
                            wall_time_ms => 101}}}
Shell got {'DOWN',GraphOsPid,process,Pid,normal}
```

## When *not* to use `run_graph`

For a straight `cmd1 | cmd2 | cmd3` with no fan-out, no per-stage tapping, and no untrusted
input to isolate, `exec:run("cmd1 | cmd2 | cmd3", [...])` is simpler and just as fast — the
shell's own pipe implementation is exactly as native as what `run_graph/2` sets up internally
for a linear chain. Reach for `run_graph/2` when the topology, observability, or safety
requirements above actually apply.
