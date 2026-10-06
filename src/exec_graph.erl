%%% vim:ts=2:sw=2:et
-module(exec_graph).

-moduledoc """
Graph execution helpers for `exec:run_graph/2`.

This module contains parsing, validation, planning, and runtime execution
logic for process graphs.

Supported edge forms:
- `stdout => RecipientId`
- `stdout => {to, RecipientId}`
- `stdout => [RecipientId1, RecipientId2]`
- `stdout => "/path/to/file"`
- `stderr => RecipientId`
- `stderr => [RecipientId1, RecipientId2]`

Current execution limitation:
- native runtime supports sync and async graph runs.

## Examples

Tuple-form edge:
```erlang
Graph = [
  #{id     => producer,
    cmd    => "printf 'a\\nb\\nc\\n'",
    stdout => {to, filter, stdin}},

  #{id     => filter,
    cmd    => "grep '^b$'"}
],
exec:run_graph(Graph, [sync, stdout]).
%% -> {ok, [{stdout, [<<"b\\n">>]}]}
```

Shorthand edge form (`stdout => Id`):
```erlang
Graph = [
  #{id     => producer,
    cmd    => "printf 'x\\ny\\n'",
    stdout => filter},

  #{id     => filter,
    cmd    => "grep '^y$'"}
],
exec:run_graph(Graph, [sync, stdout]).
%% -> {ok, [{stdout, [<<"y\\n">>]}]}
```

Options map form:
```erlang
GraphOpts = #{
  run_options => [sync, stdout, stderr],
},
exec:run_graph(Graph, GraphOpts).
```
""".

-export([run_graph/2]).

-export_type([
  task_id/0,
  stream_kind/0,
  target_port/0,
  graph_edge/0,
  edge/0,
  sink_fun/0,
  process_task/0,
  erl_sink_task/0,
  graph_task/0,
  graph_run_opts/0,
  runtime_plan/0
]).

-doc "Identifier for a graph task/stage.".
-type task_id() :: atom() | binary() | string().

-doc "Supported stream names on process nodes.".
-type stream_kind() :: stdout | stderr.

-doc "Supported destination port kinds for graph edges.".
-type target_port() :: stdin | sink.

-doc """
Normalized graph edge representation used by internal validators/planners.

Attributes:
- `from`: source task identifier.
- `stream`: source stream on `from` (`stdout` or `stderr`).
- `to`: destination task identifier or file path.
- `to_port`: destination port on `to` (currently `stdin`, `sink`, or `file`).
""".
-type graph_edge() :: #{
  from    := task_id(),
  stream  := stream_kind(),
  to      := task_id(),
  to_port := target_port()
}.

-doc "Edge declaration syntax accepted on node `stdout`/`stderr` fields.".
-type edge() :: task_id() | {to, task_id(), target_port()}.

-doc "Callback target for Erlang sink nodes.".
-type sink_fun() :: fun((stream_kind(), task_id(), binary()) -> any()).

-doc """
Executable process task in a graph.

Attributes:
- `id`: unique task identifier.
- `cmd`: command to execute (shell string or argv form accepted by `exec:run/2`).
- `stdout`: outbound edge declaration from stdout. Accepts one `edge()` or a non-empty list.
- `stderr`: outbound edge declaration from stderr. Accepts one `edge()` or a non-empty list.
- Bare string/binary targets are treated as file destinations when they do not match a graph node.
- `stdin`: optional inbound declaration used for consistency checks.
- `timeout`: optional per-task wall-clock watchdog in milliseconds -- kills ONLY this task
  if it runs longer than `Ms`. For a whole-graph wall-clock budget instead, use the
  `timeout` key in `run_graph/2`'s `GraphOpts` map (see `run_graph/2`'s doc).
- `stats`: when `true`, this task's rusage/wall-time stats are attached to its
  `task_monitor` notification (if `task_monitor` is also enabled) as
  `{'DOWN', GraphOsPid, task, TaskId, {PlainReason, StatsMap}}`. Does not affect
  normal/abnormal exit classification -- a task with `stats` enabled that exits cleanly
  is still treated as a normal completion for the graph's own overall result, which
  does NOT carry per-task stats (only the plain reason).
""".
-type process_task() :: #{
  id      := task_id(),
  cmd     := exec:cmd(),
  stdout  => edge() | [edge(), ...],
  stderr  => edge() | [edge(), ...],
  stdin   => {from, task_id(), stream_kind()},
  timeout => non_neg_integer(),
  stats   => boolean()
}.

-doc """
Erlang sink task that receives data from process-task streams.

Attributes:
- `id`: unique task identifier.
- `sink`: fixed marker atom (`erl`) identifying sink tasks.
- `stream`: stream expected by this sink task (`stdout` or `stderr`).
- `target`: sink destination (`self`, another pid, or callback function).
""".
-type erl_sink_task() :: #{
  id     := task_id(),
  sink   := erl,
  stream := stream_kind(),
  target := self | pid() | {'fun', sink_fun()}
}.

-doc "Any graph node supported by this module.".
-type graph_task() :: process_task() | erl_sink_task().

-doc """
Graph-specific runtime options map accepted by `run_graph/2`.

Attributes:
- `run_options`: options passed through to the underlying `exec:run/2` call.
- `sink_tagging`: sink tagging mode for native routing (`by_sink` or `by_source`).
  - `by_sink`: tag payload metadata by destination sink identity so each sink
    can disambiguate records by sink channel.
  - `by_source`: tag payload metadata by originating task/stream identity so
    sinks can attribute records to their upstream producer.
- `max_buffer`: per-branch buffering budget hint for fan-out paths.
- `timeout`: whole-graph wall-clock budget in milliseconds. If the graph is still running
  after `Ms` milliseconds (from graph start, not from any individual task's start), every
  task in the graph is killed (SIGTERM) and the graph's result/`'DOWN'` reason becomes
  `{timeout, graph}`. Only available via the map form of `GraphOpts` (the list form, e.g.
  `[sync, stdout]`, has no slot for this key). Distinct from a per-task `timeout` field in
  an individual `process_task()` node map, which only kills that one task.
""".
-type graph_run_opts() :: # {
  run_options  => exec:cmd_options(),
  sink_tagging => by_sink | by_source,
  max_buffer => non_neg_integer(),
  timeout => non_neg_integer()
}.

-doc """
Internal planning result produced by phase-2 validation/planning stubs.

Attributes:
- `node_map`: canonical task map used by validators/planners.
- `edges`: normalized graph edges.
""".
-type runtime_plan() :: #{
  node_map := map(),
  edges    := [graph_edge()]
}.

-doc """
Run a process graph through the current graph execution path.

The graph runtime is native-only.

## Graph-level run options (`run_options`)

These control the graph's own lifecycle/notification behavior and are consumed by
`exec_graph` itself (filtered out of what's passed to each task's own `exec:run/2` call --
see `is_controlled_native_option/1`):
- `sync` / `stdout` / `stderr`: as in plain `exec:run/2` -- `sync` makes `run_graph/2` block
  and return the collected result directly; `stdout`/`stderr` select which exposed streams
  get collected (sync) or forwarded to the caller (async).
- `link`: link the calling process to the graph worker (async mode).
- `monitor` (async mode only): send `{'DOWN', GraphOsPid, process, WorkerPid, Reason}` to the
  caller when the *whole graph* completes.
- `task_monitor` (async mode only): additionally send
  `{'DOWN', GraphOsPid, task, TaskId, Reason}` to the caller as *each individual task*
  completes, before the graph as a whole finishes. Useful for observing per-stage progress in
  a long pipeline without tapping every stage with its own `erl` sink.

## Per-task run options (everything else in `run_options`)

Any other option in `run_options` is NOT graph-specific -- it's passed straight through to
**every** task's own `exec:run/2` spawn call, same as a plain `exec:run/2` option would behave
in isolation. Two are worth calling out because they interact with graph-level notification:
- `{timeout, Ms}`: wall-clock watchdog killing a task if it's still running `Ms` ms after
  spawn. Setting it in `run_options` applies the SAME `Ms` to every task (SIGTERM->SIGKILL
  escalation, same as `exec:stop/1`); for a per-task value instead, use the `timeout` field
  on that task's own node map (see `process_task()`). For a budget on the WHOLE graph
  (independent of any single task), use the `timeout` key in `GraphOpts` (see
  `graph_run_opts()`) instead -- that one is enforced in Erlang, not per-task.
- `stats`: every task gets its rusage/wall-time stats folded into its exit reason as
  `{PlainReason, StatsMap}` (see `exec:cmd_option()`'s `stats` doc). With `task_monitor` also
  enabled, each task's `'DOWN'` carries this wrapped reason; without it, stats are captured
  but never surfaced anywhere by the graph layer itself. The graph's own overall `'DOWN'`/
  result reason never carries any task's stats (only the plain reason) -- for per-task
  stats visibility, use the `timeout` field equivalent: a per-task `stats => true` node map
  field instead of a graph-wide `run_options` entry, if you only want it on specific tasks.

Example:
```erlang
Graph = [
  #{id     => producer,
    cmd    => "printf 'ok\\n'",
    stdout => consumer},

  #{id     => consumer,
    cmd    => "cat"}
],
exec_graph:run_graph(Graph, [sync, stdout]).
%% -> {ok, [{stdout, [<<"ok\\n">>]}]}
```
""".
-spec run_graph([graph_task()], exec:cmd_options() | map()) ->
  {ok, pid(), exec:ospid()} | {ok, [{stdout | stderr, [binary()]}]} | {error, any()}.
run_graph(Graph, GraphOpts) when is_list(Graph) ->
  maybe
    {ok, GraphOpts2} ?= normalize_graph_run_options(GraphOpts),
    {ok, NodeMap2}   ?= graph_node_map_checked(Graph),
    {ok, Edges2}     ?= graph_edges_checked(NodeMap2),
    ok               ?= validate_graph_outbound_checked(NodeMap2, Edges2),
    ok               ?= validate_graph_stdin_checked(NodeMap2, Edges2),
    ok               ?= validate_no_cycles_checked(NodeMap2, Edges2),
    ok               ?= validate_sink_nodes_checked(NodeMap2, Edges2),
    {ok, Plan}       ?= graph_runtime_plan(NodeMap2, Edges2, GraphOpts2),
    run_graph_plan(Plan, GraphOpts2)
  else
    {error, _} = Error -> Error;
    Reason -> {error, {graph_validation, Reason}}
  end.

run_graph_plan(#{node_map := NodeMap, edges := Edges}, GraphOpts) ->
  run_graph_native(NodeMap, Edges, GraphOpts).

run_graph_native(NodeMap, Edges, GraphOpts) ->
  RunOptions = maps:get(run_options, GraphOpts, []),
  case lists:member(sync, RunOptions) of
    true ->
      run_graph_native_sync(NodeMap, Edges, GraphOpts);
    false ->
      run_graph_native_async(NodeMap, Edges, GraphOpts)
  end.

run_graph_native_sync(NodeMap, Edges, GraphOpts) ->
  RunOptions = maps:get(run_options, GraphOpts, []),
  case build_graph_io_plan(NodeMap, Edges, RunOptions) of
    {ok, IOPlan} ->
      case start_native_processes(NodeMap, Edges, IOPlan) of
        {ok, ProcMap, PidToId} ->
          State = init_native_state(NodeMap, Edges, GraphOpts, ProcMap, PidToId,
            sync, self(), 0, false),
          native_loop(State);
        {error, _} = Error ->
          Error
      end;
    {error, _} = Error ->
      Error
  end.

run_graph_native_async(NodeMap, Edges, GraphOpts) ->
  Owner         = self(),
  RunOptions    = maps:get(run_options, GraphOpts, []),
  GraphOsPid    = -erlang:unique_integer([positive]),
  NotifyMonitor = lists:member(monitor, RunOptions),
  %% task_monitor: in addition to the whole-graph 'DOWN' (controlled by `monitor`
  %% above), also notify Owner as each individual task completes:
  %% {'DOWN', GraphOsPid, task, TaskId, Reason}. Lets a caller observe per-stage
  %% completion/failure without tapping every stage with its own erl sink.
  NotifyTaskMonitor = lists:member(task_monitor, RunOptions),
  Worker = spawn(fun() ->
    run_graph_native_async_worker(Owner, GraphOsPid, NotifyMonitor, NotifyTaskMonitor,
      NodeMap, Edges, GraphOpts)
  end),
  case lists:member(link, RunOptions) of
    true  -> link(Worker);
    false -> ok
  end,
  receive
    {graph_started, GraphOsPid, Worker} ->
      {ok, Worker, GraphOsPid};
    {graph_start_failed, GraphOsPid, Reason} ->
      {error, Reason}
  end.

run_graph_native_async_worker(Owner, GraphOsPid, NotifyMonitor, NotifyTaskMonitor, NodeMap, Edges, GraphOpts) ->
  RunOptions = maps:get(run_options, GraphOpts, []),
  maybe
    {ok, IOPlan} ?= build_graph_io_plan(NodeMap, Edges, RunOptions),
    {ok, ProcMap, PidToId} ?= start_native_processes(NodeMap, Edges, IOPlan),
    Owner ! {graph_started, GraphOsPid, self()},
    State = init_native_state(NodeMap, Edges, GraphOpts, ProcMap, PidToId,
      async, Owner, GraphOsPid, NotifyMonitor, NotifyTaskMonitor),
    _ = native_loop(State),
    ok
  else
    {error, Reason} ->
      notify_error(NotifyMonitor, Owner, GraphOsPid, Reason),
      exit(Reason)
  end.

% Helper to avoid duplication
notify_error(true, Owner, GraphOsPid, Reason) ->
  Owner ! {'DOWN', GraphOsPid, process, self(), Reason};
notify_error(false, _Owner, _GraphOsPid, _Reason) ->
  ok.

init_native_state(NodeMap, Edges, GraphOpts, ProcMap, PidToId,
    Mode, Owner, GraphOsPid, NotifyMonitor) ->
  init_native_state(NodeMap, Edges, GraphOpts, ProcMap, PidToId,
    Mode, Owner, GraphOsPid, NotifyMonitor, false).

init_native_state(NodeMap, Edges, GraphOpts, ProcMap, PidToId,
    Mode, Owner, GraphOsPid, NotifyMonitor, NotifyTaskMonitor) ->
  EdgesBySource = build_edges_by_source(Edges),
  SinkNodes = maps:filter(fun(_, N) -> maps:get(sink, N, undefined) =:= erl end, NodeMap),
  Exposed = exposed_process_streams(NodeMap, EdgesBySource),
  InboundOpen = inbound_stdin_counts(Edges),
  #{
    node_map             => NodeMap,
    proc_map             => ProcMap,
    pid_to_id            => PidToId,
    edges_by_source      => EdgesBySource,
    sink_nodes           => SinkNodes,
    exposed              => Exposed,
    inbound_open         => InboundOpen,
    sink_tagging         => maps:get(sink_tagging, GraphOpts, by_source),
    collect_stdout       => lists:member(stdout, maps:get(run_options, GraphOpts, [])),
    collect_stderr       => lists:member(stderr, maps:get(run_options, GraphOpts, [])),
    collected_stdout     => [],
    collected_stderr     => [],
    remaining            => map_size(ProcMap),
    exit_reason          => undefined,
    mode                 => Mode,
    owner                => Owner,
    graph_ospid          => GraphOsPid,
    notify_monitor       => NotifyMonitor,
    notify_task_monitor  => NotifyTaskMonitor,
    %% Graph-level wall-clock budget (distinct from any per-task {timeout, Ms} option):
    %% absolute monotonic-clock deadline computed once at graph start, or `undefined` if
    %% no graph-level `timeout` key was given in GraphOpts. Enforced in native_loop/1 via
    %% a dynamic `after` clause -- if it fires, every task in the graph is killed and the
    %% graph's result/'DOWN' reason becomes {timeout, graph}.
    graph_deadline       => case maps:get(timeout, GraphOpts, undefined) of
      undefined -> undefined;
      Ms        -> erlang:monotonic_time(millisecond) + Ms
    end
  }.

native_loop(State = #{remaining := 0}) ->
  finalize_native_result(State);
native_loop(State0 = #{graph_deadline := undefined}) ->
  receive
    Msg -> native_loop(native_loop_dispatch(Msg, State0))
  end;
native_loop(State0 = #{graph_deadline := Deadline}) ->
  RemainingMs = max(0, Deadline - erlang:monotonic_time(millisecond)),
  receive
    Msg -> native_loop(native_loop_dispatch(Msg, State0))
  after RemainingMs ->
    kill_all_graph_tasks(State0),
    native_loop(State0#{exit_reason := {timeout, graph}, remaining := 0})
  end.

%% Shared message-dispatch body for native_loop/1's two clauses above (plain `receive` when
%% no graph-level timeout is set, vs. `receive ... after RemainingMs` when one is) -- kept as
%% a single function so the message-matching logic itself never needs to be duplicated.
native_loop_dispatch(Msg, State0) ->
  case Msg of
    {stdout, OsPid, Data} when is_integer(OsPid), is_binary(Data) ->
      handle_native_stream(stdout, OsPid, Data, State0);
    {stderr, OsPid, Data} when is_integer(OsPid), is_binary(Data) ->
      handle_native_stream(stderr, OsPid, Data, State0);
    {'DOWN', OsPid, process, _Pid, Reason} when is_integer(OsPid) ->
      handle_native_down(OsPid, Reason, State0);
    {'DOWN', OsPid, {exit_status, Status}} when is_integer(OsPid) ->
      handle_native_down(OsPid, {exit_status, Status}, State0);
    {'DOWN', _Ref, process, _Pid, _Reason} ->
      State0
  end.

%% Kill every still-running task in the graph (SIGTERM; same first-attempt signal used by
%% stop_child's escalation for ordinary exec:stop/1 requests). Mirrors the existing
%% spawn-failure cleanup loop in start_native_processes/7, just SIGTERM instead of SIGKILL.
kill_all_graph_tasks(#{proc_map := ProcMap}) ->
  lists:foreach(
    fun(#{ospid := OsPid}) -> _ = exec:kill(OsPid, 15) end,
    maps:values(ProcMap)).

handle_native_stream(Stream, OsPid, Data, State0) ->
  case maps:get(OsPid, maps:get(pid_to_id, State0), undefined) of
    undefined ->
      State0;
    FromId ->
      State1 = maybe_collect_exposed(Stream, FromId, Data, State0),
      route_native_stream(FromId, Stream, Data, State1)
  end.

maybe_collect_exposed(stdout, FromId, Data,
    State = #{collect_stdout := true, exposed := Exposed, collected_stdout := Stdout, mode := Mode}) ->
  case maps:get({FromId, stdout}, Exposed, false) of
    true when Mode =:= sync ->
      State#{collected_stdout := [Data | Stdout]};
    true ->
      forward_native_output(stdout, Data, State),
      State;
    false -> State
  end;
maybe_collect_exposed(stderr, FromId, Data,
    State = #{collect_stderr := true, exposed := Exposed, collected_stderr := Stderr, mode := Mode}) ->
  case maps:get({FromId, stderr}, Exposed, false) of
    true when Mode =:= sync ->
      State#{collected_stderr := [Data | Stderr]};
    true ->
      forward_native_output(stderr, Data, State),
      State;
    false -> State
  end;
maybe_collect_exposed(_, _, _, State) ->
  State.

forward_native_output(Stream, Data, #{owner := Owner, graph_ospid := GraphOsPid}) ->
  Owner ! {Stream, GraphOsPid, Data},
  ok.

route_native_stream(FromId, Stream, Data, State0) ->
  %% File redirects for PURE-FILE cases are now handled natively by C++ (via {stdout_files,...} option).
  %% But MIXED cases (file + sink/task destinations) still need file routing here.
  %% Task-to-task piping still flows through Erlang until native sibling pipes are implemented (TODO Phase 10).
  %% Sink delivery is always handled here (Erlang-side message dispatch).
  Targets = maps:get({FromId, Stream}, maps:get(edges_by_source, State0), []),
  lists:foldl(
    fun(#{to := ToPath, to_port := file}, StateAcc) ->
      %% File routing for MIXED cases (pure-file cases are already handled natively by C++).
      exec:write_file(ToPath, Data),
      StateAcc;
       (#{to := ToId, to_port := stdin}, StateAcc) ->
      %% Route to sibling task's stdin (until native sibling pipes are implemented).
      case maps:get(ToId, maps:get(proc_map, StateAcc), undefined) of
        #{ospid := ToOsPid} ->
          _ = exec:send(ToOsPid, Data),
          StateAcc;
        _ ->
          StateAcc
      end;
       (#{to := ToId, to_port := sink}, StateAcc) ->
      deliver_sink(ToId, Stream, FromId, Data, StateAcc);
       (_, StateAcc) ->
      StateAcc
    end,
    State0,
    Targets).

deliver_sink(SinkId, Stream, FromId, Data, State = #{sink_nodes := SinkNodes, sink_tagging := SinkTagging}) ->
  case maps:get(SinkId, SinkNodes, undefined) of
    undefined when SinkId =:= erl ->
      collect_or_forward_erl_sink(Stream, Data, State);
    #{target := self} ->
      maps:get(owner, State) ! sink_payload(SinkTagging, SinkId, Stream, FromId, Data),
      State;
    #{target := Pid} when is_pid(Pid) ->
      Pid ! sink_payload(SinkTagging, SinkId, Stream, FromId, Data),
      State;
    #{target := {'fun', Fun}} when is_function(Fun, 3) ->
      Fun(Stream, FromId, Data),
      State;
    _ ->
      State
  end.

collect_or_forward_erl_sink(stdout, Data, State = #{mode := sync, collected_stdout := Stdout}) ->
  State#{collected_stdout := [Data | Stdout]};
collect_or_forward_erl_sink(stderr, Data, State = #{mode := sync, collected_stderr := Stderr}) ->
  State#{collected_stderr := [Data | Stderr]};
collect_or_forward_erl_sink(Stream, Data, State = #{mode := async, owner := Owner, graph_ospid := GraphOsPid}) ->
  Owner ! {Stream, GraphOsPid, Data},
  State;
collect_or_forward_erl_sink(_, _, State) ->
  State.

sink_payload(by_sink, SinkId, Stream, _FromId, Data) ->
  {graph_sink, SinkId, Stream, Data};
sink_payload(by_source, _SinkId, Stream, FromId, Data) ->
  {graph_source, FromId, Stream, Data}.

handle_native_down(OsPid, Reason, State0 = #{pid_to_id := PidToId, edges_by_source := EdgesBySource}) ->
  case maps:get(OsPid, PidToId, undefined) of
    undefined ->
      State0;
    FromId ->
      %% If this task was spawned with the `stats` option, exec.erl's ospid_loop folds
      %% rusage/wall-time into the 'DOWN' reason as {PlainReason, StatsMap} (see
      %% exec:notify_and_exit/5). Unwrap it ONCE here so every downstream consumer
      %% (task_monitor notification, exit_reason capture/classification) keeps working
      %% on the plain reason shape it already expects -- a task having `stats` enabled
      %% must not change whether the graph considers its exit normal or abnormal.
      {PlainReason, Stats} = unwrap_stats_reason(Reason),
      maybe_notify_task_down(FromId, PlainReason, Stats, State0),
      State1 = close_downstream_stdin(FromId, EdgesBySource, State0),
      State2 = maybe_capture_exit_reason(PlainReason, State1),
      State2#{remaining := maps:get(remaining, State1) - 1}
  end.

%% {PlainReason, StatsMap} is only ever produced by exec.erl's ospid_loop when `stats`
%% was requested on this specific task; is_map/1 safely disambiguates it from a
%% same-shape ordinary reason like {exit_status, Status} (Status is always an integer,
%% never a map), so no graph task failure mode can be mistaken for a stats wrapper.
unwrap_stats_reason({PlainReason, StatsMap}) when is_map(StatsMap) ->
  {PlainReason, StatsMap};
unwrap_stats_reason(Reason) ->
  {Reason, undefined}.

%% Per-task completion notification (task_monitor run option): fires for every
%% graph task as it individually exits, independent of (and in addition to) the
%% whole-graph 'DOWN' sent at the end (controlled by `monitor`). Only active in
%% async mode -- sync callers get the final collected result/error directly as
%% the return value of run_graph/2, so there's no Owner process to notify mid-run.
%% If this task had `stats` enabled, Stats (a map) is re-attached to the reported
%% reason here -- {Reason, Stats} -- so a task_monitor caller still sees it; this is
%% the only place the stats wrapper survives past handle_native_down/3's unwrap.
maybe_notify_task_down(TaskId, Reason, Stats,
    #{mode := async, notify_task_monitor := true, owner := Owner, graph_ospid := GraphOsPid}) ->
  ReportedReason = case Stats of
    undefined -> Reason;
    _         -> {Reason, Stats}
  end,
  Owner ! {'DOWN', GraphOsPid, task, TaskId, ReportedReason},
  ok;
maybe_notify_task_down(_TaskId, _Reason, _Stats, _State) ->
  ok.

maybe_capture_exit_reason(normal, State) ->
  State;
maybe_capture_exit_reason(noproc, State) ->
  State;
maybe_capture_exit_reason({exit_status, 0}, State) ->
  State;
maybe_capture_exit_reason(Reason, State = #{exit_reason := undefined}) ->
  State#{exit_reason := Reason};
maybe_capture_exit_reason(_Reason, State) ->
  State.

close_downstream_stdin(FromId, EdgesBySource, State0 = #{proc_map := ProcMap}) ->
  SenderTargets =
    maps:get({FromId, stdout}, EdgesBySource, []) ++
    maps:get({FromId, stderr}, EdgesBySource, []),
  RecipientIds = lists:usort([ToId || #{to := ToId, to_port := stdin} <- SenderTargets]),
  lists:foldl(
    fun(ToId, StateAcc = #{inbound_open := InOpenAcc}) ->
      Count0 = maps:get(ToId, InOpenAcc, 0),
      Count = erlang:max(Count0 - 1, 0),
      InOpen = maps:put(ToId, Count, InOpenAcc),
      case {Count =:= 0, maps:get(ToId, ProcMap, undefined)} of
        {true, #{ospid := ToOsPid}} ->
          _ = exec:send(ToOsPid, eof),
          StateAcc#{inbound_open := InOpen};
        _ ->
          StateAcc#{inbound_open := InOpen}
      end
    end,
    State0,
    RecipientIds).

finalize_native_result(State) ->
  Mode = maps:get(mode, State),
  Out = native_collected_outputs(State),
  ExitReason = maps:get(exit_reason, State, undefined),
  case Mode of
    sync ->
      case ExitReason of
        undefined -> {ok, Out};
        Reason -> {error, [Reason | Out]}
      end;
    async ->
      maybe_notify_native_async_down(State, ExitReason),
      ok
  end.

maybe_notify_native_async_down(#{notify_monitor := true, owner := Owner, graph_ospid := GraphOsPid}, undefined) ->
  Owner ! {'DOWN', GraphOsPid, process, self(), normal},
  ok;
maybe_notify_native_async_down(#{notify_monitor := true, owner := Owner, graph_ospid := GraphOsPid}, Reason) ->
  Owner ! {'DOWN', GraphOsPid, process, self(), Reason},
  ok;
maybe_notify_native_async_down(_State, _Reason) ->
  ok.

native_collected_outputs(State) ->
  Stdout = lists:reverse(maps:get(collected_stdout, State, [])),
  Stderr = lists:reverse(maps:get(collected_stderr, State, [])),
  Acc0 = [],
  Acc1 = case maps:get(collect_stdout, State, false) of
    true -> [{stdout, Stdout} | Acc0];
    false -> Acc0
  end,
  Acc2 = case maps:get(collect_stderr, State, false) of
    true -> [{stderr, Stderr} | Acc1];
    false -> Acc1
  end,
  lists:reverse(Acc2).

%% Pre-allocate all sibling-stdin pipes before any task spawning.
%% Returns a map: #{{ProducerId, Stream} => [{ConsumerId, WriteFd}, ...], {ConsumerId, stdin} => ReadFd}
%% Each sibling-stdin edge gets its own pipe (one per {producer_stream, consumer} pair) --
%% multi-producer fan-in into one consumer's stdin would need N pipes dup2'd onto the
%% same fd, which the kernel doesn't support; today's graph validation only allows a
%% single stdin source per task, so this one-pipe-per-edge model is sufficient.
allocate_sibling_pipes(Edges) ->
  %% Find all {ProducerId, Stream} -> {ConsumerId, stdin} edge pairs.
  SiblingEdges = [E || E <- Edges, maps:get(to_port, E) =:= stdin],

  lists:foldl(
    fun(#{from := ProducerId, stream := Stream, to := ConsumerId}, Acc0) ->
      case exec:open_pipe() of
        {ok, ReadFd, WriteFd} ->
          %% Store write-end for producer (folded into its stdout fanout list at spawn time).
          ProducerKey = {ProducerId, Stream},
          ProducerEntry = maps:get(ProducerKey, Acc0, []),
          Acc1 = maps:put(ProducerKey, [{ConsumerId, WriteFd} | ProducerEntry], Acc0),
          %% Store read-end for consumer (used directly as its stdin fd at spawn time).
          maps:put({ConsumerId, stdin}, ReadFd, Acc1);
        {error, Reason} ->
          %% Pipe allocation failures are rare (fd exhaustion); propagate as an
          %% exception since this runs before any task has been spawned yet --
          %% there's nothing to roll back, we just abort the whole graph run.
          throw({error, {sibling_pipe_alloc_failed, Reason}})
      end
    end,
    #{},
    SiblingEdges).

start_native_processes(NodeMap, Edges, IOPlan) ->
  RunOptions = maps:get(run_options, IOPlan, []),
  ProcNodes = maps:to_list(maps:filter(fun(_, N) -> maps:is_key(cmd, N) end, NodeMap)),
  StartOpts = native_process_run_options(RunOptions),
  %% Index task plans by id for O(1) lookup during spawn.
  TaskPlansById = maps:from_list(
    [{maps:get(id, TP), TP} || TP <- maps:get(tasks, IOPlan, [])]),
  %% Pre-allocate all sibling-stdin pipes before spawning any tasks. This can throw if
  %% pipe allocation fails (e.g. fd exhaustion) -- catch and convert to {error, _} since
  %% nothing has been spawned yet, there's nothing to roll back.
  try allocate_sibling_pipes(Edges) of
    SiblingPipeAllocs ->
      start_native_processes_1(ProcNodes, StartOpts, TaskPlansById, SiblingPipeAllocs)
  catch
    throw:{error, _} = Error -> Error
  end.

start_native_processes_1(ProcNodes, StartOpts, TaskPlansById, SiblingPipeAllocs) ->
  %% Process group sequencing: there is no synthetic/pre-generated GID -- the kernel assigns
  %% the group's GID as the first member's own OS pid (via {group, 0}). The first task spawns
  %% with {group, 0}; its OsPid becomes GroupGid. Every subsequent task spawns with
  %% {group, GroupGid} to join that same group. kill_group is intentionally NOT set here:
  %% it fires killpg on *that task's own* exit (normal or abnormal), which would kill every
  %% sibling the instant the first task of a pipeline finishes normally. Group membership is
  %% for bookkeeping / future abnormal-exit cleanup only.
  start_native_processes(ProcNodes, StartOpts, TaskPlansById, SiblingPipeAllocs, #{}, #{}, undefined).

start_native_processes([{Id, Node} | T], StartOpts, TaskPlansById, SiblingPipeAllocs, ProcMap0, PidToId0, GroupGid0) ->
  GroupOpts = case GroupGid0 of
    undefined -> [{group, 0} | StartOpts];
    _         -> [{group, GroupGid0} | StartOpts]
  end,
  %% Pure-file streams are redirected natively at spawn time (bypassing Erlang entirely for
  %% that stream's data). Sibling-pipe destinations are also connected natively.
  %% Mixed/pure-task/exposed streams keep the default stream-to-self behavior from StartOpts
  %% and are routed in route_native_stream/4 (for sink delivery).
  TaskPlan = maps:get(Id, TaskPlansById, #{}),
  TaskOpts1 = add_file_redirect_opts(TaskPlan, GroupOpts),
  %% Add sibling pipe options for this task's outputs and inputs.
  TaskOpts2 = add_sibling_pipe_opts(Id, TaskOpts1, SiblingPipeAllocs),
  %% Add this task's own per-task {timeout, Ms} watchdog, if specified in its node map.
  TaskOpts3 = add_task_timeout_opt(Node, TaskOpts2),
  %% Add this task's own `stats` request, if specified in its node map.
  TaskOpts = add_task_stats_opt(Node, TaskOpts3),
  case exec:run(maps:get(cmd, Node), TaskOpts) of
    {ok, Pid, OsPid} ->
      ProcMap = maps:put(Id, #{pid => Pid, ospid => OsPid}, ProcMap0),
      PidToId = maps:put(OsPid, Id, PidToId0),
      %% First successfully-spawned task's OsPid becomes the group GID for the rest.
      GroupGid = case GroupGid0 of
        undefined -> OsPid;
        _         -> GroupGid0
      end,
      start_native_processes(T, StartOpts, TaskPlansById, SiblingPipeAllocs, ProcMap, PidToId, GroupGid);
    {error, _} = Error ->
      %% Kill tasks already started (manual loop -- no group kill primitive available yet
      %% since kill_group isn't set; see note above).
      lists:foreach(
        fun(#{ospid := Existing}) -> _ = exec:kill(Existing, 9) end,
        maps:values(ProcMap0)),
      Error
  end;
start_native_processes([], _StartOpts, _TaskPlansById, _SiblingPipeAllocs, ProcMap, PidToId, _GroupGid) ->
  {ok, ProcMap, PidToId}.

%% Add sibling pipe spawn options for task inputs and outputs.
%% Extracts write-ends for producer destinations and read-ends for consumer sources.
add_sibling_pipe_opts(TaskId, BaseOpts, SiblingPipeAllocs) ->
  %% Check if this task produces output to sibling inputs (as a producer), per-stream.
  ProducerStdout = maps:get({TaskId, stdout}, SiblingPipeAllocs, []),
  ProducerStderr = maps:get({TaskId, stderr}, SiblingPipeAllocs, []),
  %% Check if this task consumes input from a sibling output (as a consumer).
  ConsumerStdin = maps:get({TaskId, stdin}, SiblingPipeAllocs, undefined),

  Opts1 = case ProducerStdout of
    [] -> BaseOpts;
    _  -> [{stdout_sibling_pipes, ProducerStdout} | BaseOpts]
  end,

  Opts2 = case ProducerStderr of
    [] -> Opts1;
    _  -> [{stderr_sibling_pipes, ProducerStderr} | Opts1]
  end,

  Opts3 = case ConsumerStdin of
    undefined -> Opts2;
    ReadFd    -> [{stdin_from_sibling, ReadFd} | Opts2]
  end,

  Opts3.

%% Add spawn-time file redirect options for pure-file streams (stdout/stderr).
%% Pure-task/mixed/exposed streams are left untouched (keep stream-to-self from BaseOpts),
%% so their data flows through Erlang for sink delivery (route_native_stream/4).
add_file_redirect_opts(TaskPlan, BaseOpts) ->
  Opts1 = add_stream_file_redirect(stdout, maps:get(stdout, TaskPlan, exposed), BaseOpts),
  add_stream_file_redirect(stderr, maps:get(stderr, TaskPlan, exposed), Opts1).

%% Translate a graph node's optional `timeout => Ms` field into a per-task {timeout, Ms}
%% exec:run/2 option -- a wall-clock watchdog scoped to just this one task (kills only this
%% process, SIGTERM->SIGKILL escalation, same as exec:stop/1). Distinct from the graph-level
%% `timeout` key in run_graph/2's GraphOpts map, which bounds the whole graph's wall-clock
%% budget and is enforced purely in Erlang (native_loop/1), not here.
add_task_timeout_opt(Node, Opts) ->
  case maps:get(timeout, Node, undefined) of
    undefined -> Opts;
    Ms when is_integer(Ms), Ms >= 0 -> [{timeout, Ms} | Opts]
  end.

%% Translate a graph node's optional `stats => true` field into the per-task `stats`
%% exec:run/2 option. The resulting {stats, OsPid, StatsMap} reason-wrapper (see
%% exec:notify_and_exit/5) is unwrapped once in handle_native_down/3 before any
%% normal/abnormal exit classification happens, and re-attached only for task_monitor
%% notifications -- see unwrap_stats_reason/1 and maybe_notify_task_down/4.
add_task_stats_opt(Node, Opts) ->
  case maps:get(stats, Node, false) of
    true  -> [stats | Opts];
    false -> Opts
  end.

add_stream_file_redirect(Stream, {pure_file, [{file, Path, Options}]}, Opts) ->
  %% Single pure-file destination: redirect natively at spawn time.
  %% Remove the stream-to-self option (if any) and add the file redirect instead.
  StreamOpt = case Options of
    [] -> {Stream, Path};
    _  -> {Stream, Path, Options}
  end,
  Opts2 = lists:filter(fun({S, _}) when S =:= Stream -> false; (_) -> true end, Opts),
  [StreamOpt | Opts2];
add_stream_file_redirect(_Stream, _Classification, Opts) ->
  %% exposed, pure_task, or mixed: keep stream-to-self so data flows to Erlang for sink delivery.
  %% Multi-file pure_file: TODO for future Phase 4 completion (will use C++ fanout_fds).
  Opts.

native_process_run_options(RunOptions) ->
  Filtered = [Opt || Opt <- RunOptions, not is_controlled_native_option(Opt)],
  [stdin, monitor, {stdout, self()}, {stderr, self()} | Filtered].

is_controlled_native_option(sync) -> true;
is_controlled_native_option(stdin) -> true;
is_controlled_native_option(stdout) -> true;
is_controlled_native_option(stderr) -> true;
is_controlled_native_option(monitor) -> true;
is_controlled_native_option(task_monitor) -> true;  % graph-level only, not a real exec:run/2 option
is_controlled_native_option({stdin, _}) -> true;
is_controlled_native_option({stdout, _}) -> true;
is_controlled_native_option({stderr, _}) -> true;
is_controlled_native_option(_) -> false.

%% Build the I/O routing plan for C++ execution.
%% For each task, classify stdout/stderr destinations and determine if they need native fanout.
%% Returns: {ok, GraphIOPlan} or {error, Reason}
%% GraphIOPlan is passed to C++ as {graph_plan, Plan} option.
build_graph_io_plan(NodeMap, Edges, RunOptions) ->
  ProcNodes = maps:filter(fun(_, N) -> maps:is_key(cmd, N) end, NodeMap),
  SinkNodes = maps:filter(fun(_, N) -> maps:get(sink, N, undefined) =:= erl end, NodeMap),

  TaskPlans = maps:fold(
    fun(TaskId, _Node, Acc) ->
      case build_task_io_plan(TaskId, Edges, NodeMap) of
        {ok, TaskPlan} -> [TaskPlan | Acc];
        {error, _} = Error -> Error
      end
    end,
    [],
    ProcNodes),

  case TaskPlans of
    {error, _} = Error -> Error;
    Plans ->
      %% Build sink targets map: SinkId => self|Pid|{'fun', Fun}
      SinkTargets = maps:fold(
        fun(SinkId, SinkNode, Acc) ->
          Target = maps:get(target, SinkNode, self),
          maps:put(SinkId, Target, Acc)
        end,
        #{},
        SinkNodes),
      {ok, #{
        tasks => lists:reverse(Plans),
        sinks => SinkTargets,
        run_options => RunOptions
      }}
  end.

%% Build I/O plan for a single task: which streams connect where.
build_task_io_plan(TaskId, Edges, NodeMap) ->
  StdoutEdges = [E || E <- Edges, maps:get(from, E) =:= TaskId, maps:get(stream, E) =:= stdout],
  StderrEdges = [E || E <- Edges, maps:get(from, E) =:= TaskId, maps:get(stream, E) =:= stderr],
  {ok, #{
    id => TaskId,
    stdout => classify_stream_destinations(StdoutEdges, NodeMap),
    stderr => classify_stream_destinations(StderrEdges, NodeMap)
  }}.

%% Classify a stream's destinations: pure_file, pure_task, mixed, or exposed.
%% Returns specifications suitable for C++ decoding:
%% - exposed: bare atom
%% - {pure_file, [{file, Path, Options}, ...]}: only file destinations
%% - {pure_task, [{task, TaskId}, {sink, SinkId}, ...]}: only task/sink destinations
%% - {mixed, FileList, TaskList}: both files and tasks/sinks
classify_stream_destinations(Edges, _NodeMap) ->
  FileEdges = [E || E <- Edges, maps:get(to_port, E) =:= file],
  TaskEdges = [E || E <- Edges, maps:get(to_port, E) =:= stdin],
  SinkEdges = [E || E <- Edges, maps:get(to_port, E) =:= sink],

  FileSpecs = [edge_to_file_spec(E) || E <- FileEdges],
  TaskSpecs = [{task, maps:get(to, E)} || E <- TaskEdges],
  SinkSpecs = [{sink, maps:get(to, E)} || E <- SinkEdges],
  AllTaskSpecs = TaskSpecs ++ SinkSpecs,

  case {FileSpecs, AllTaskSpecs} of
    {[], []} ->
      exposed;
    {[], TaskList} ->
      {pure_task, TaskList};
    {FileList, []} ->
      {pure_file, FileList};
    {FileList, TaskList} ->
      {mixed, FileList, TaskList}
  end.

%% Convert a file edge to a file specification: {file, Path, [Options]}
edge_to_file_spec(#{to := Path} = _Edge) ->
  %% For now, append flag is implicit. Future: extract from edge if present.
  {file, Path, []}.  %% Empty options list = truncate (default)

build_edges_by_source(Edges) ->
  lists:foldl(
    fun(#{from := From, stream := Stream} = E, Acc) ->
      maps:update_with({From, Stream}, fun(L) -> [E | L] end, [E], Acc)
    end,
    #{},
    Edges).

exposed_process_streams(NodeMap, EdgesBySource) ->
  maps:fold(
    fun(Id, Node, Acc0) ->
      case maps:is_key(cmd, Node) of
        false -> Acc0;
        true ->
          Acc1 = maps:put({Id, stdout}, not maps:is_key({Id, stdout}, EdgesBySource), Acc0),
          maps:put({Id, stderr}, not maps:is_key({Id, stderr}, EdgesBySource), Acc1)
      end
    end,
    #{},
    NodeMap).

inbound_stdin_counts(Edges) ->
  lists:foldl(
    fun(#{to := To, to_port := stdin}, Acc) ->
      maps:update_with(To, fun(N) -> N + 1 end, 1, Acc);
       (_, Acc) ->
      Acc
    end,
    #{},
    Edges).

-spec normalize_graph_run_options(exec:cmd_options() | map()) ->
  {ok, graph_run_opts()} | {error, any()}.
normalize_graph_run_options(Opts) when is_list(Opts) ->
  %% List form has no slot for a graph-level timeout -- use the map form
  %% (#{run_options => [...], timeout => Ms}) if a whole-graph wall-clock budget is needed.
  {ok, #{run_options  => Opts,
         sink_tagging => by_source,
         max_buffer   => 0,
         timeout      => undefined}};
normalize_graph_run_options(Opts) when is_map(Opts) ->
  RunOptions = maps:get(run_options, Opts, []),
  SinkTagging = maps:get(sink_tagging, Opts, by_source),
  MaxBuf = maps:get(max_buffer, Opts, 0),
  Timeout = maps:get(timeout, Opts, undefined),
  maybe
    true ?= is_list(RunOptions) orelse {invalid_run_options, RunOptions},
    true ?= (SinkTagging =:= by_sink orelse SinkTagging =:= by_source) orelse
        {invalid_sink_tagging, SinkTagging},
    true ?= (is_integer(MaxBuf) andalso MaxBuf >= 0) orelse {invalid_max_buffer, MaxBuf},
    true ?= (Timeout =:= undefined orelse (is_integer(Timeout) andalso Timeout >= 0)) orelse
        {invalid_timeout, Timeout},
    {ok, #{run_options => RunOptions,
         sink_tagging => SinkTagging,
         max_buffer => MaxBuf,
         timeout => Timeout}}
  else
    {error, _} = Error -> Error;
    Reason -> {error, {graph_validation, Reason}}
  end;
normalize_graph_run_options(Other) ->
  {error, {graph_validation, {invalid_graph_options, Other}}}.

-spec graph_node_map_checked([graph_task()]) -> {ok, map()} | {error, any()}.
graph_node_map_checked(Graph) ->
  graph_node_map(Graph).

-spec graph_edges_checked(map()) -> {ok, [graph_edge()]} | {error, any()}.
graph_edges_checked(NodeMap) ->
  case graph_edges(NodeMap) of
    {ok, Legacy} -> {ok, [legacy_edge_to_graph_edge(L) || L <- Legacy]};
    {error, _} = Error -> Error
  end.

legacy_edge_to_graph_edge({From, Stream, To}) ->
  #{from    => From,
    stream  => Stream,
    to      => To,
    to_port => case To of erl -> sink; _ -> stdin end};
legacy_edge_to_graph_edge({From, Stream, To, file}) ->
  #{from    => From,
    stream  => Stream,
    to      => To,
    to_port => file}.

-spec validate_graph_stdin_checked(map(), [graph_edge()]) -> ok | {error, any()}.
validate_graph_stdin_checked(NodeMap, GraphEdges) ->
  validate_graph_stdin(NodeMap, graph_edges_to_legacy(GraphEdges)).

graph_edges_to_legacy(GraphEdges) ->
  [{maps:get(from, E), maps:get(stream, E), maps:get(to, E)} ||
    E <- GraphEdges,
    maps:get(to_port, E) =:= stdin].

-spec validate_graph_outbound_checked(map(), [graph_edge()]) -> ok | {error, any()}.
validate_graph_outbound_checked(NodeMap, GraphEdges) ->
  validate_graph_outbound_checked(NodeMap, GraphEdges, #{}).

validate_graph_outbound_checked(_NodeMap, [], _Counts) ->
  ok;
validate_graph_outbound_checked(NodeMap, [E | T], Counts0) ->
  From = maps:get(from, E),
  To = maps:get(to, E),
  Stream = maps:get(stream, E),
  ToPort = maps:get(to_port, E),
  case validate_edge_target_checked(From, Stream, {to, To, ToPort}, NodeMap) of
    ok ->
      Key = {From, Stream},
      Cnt = maps:get(Key, Counts0, 0),
      Counts = maps:put(Key, Cnt + 1, Counts0),
      validate_graph_outbound_checked(NodeMap, T, Counts);
    {error, _} = Error ->
      Error
  end.

-spec validate_edge_target_checked(task_id(), stream_kind(), edge(), map()) -> ok | {error, any()}.
validate_edge_target_checked(From, Stream, Edge, NodeMap) ->
  case normalize_edge_target(NodeMap, Edge) of
    {to, erl, sink} ->
      ok;
    {to, _Path, file} ->
      ok;
    {to, To, ToPort} ->
      case maps:is_key(To, NodeMap) of
        false ->
          {error, {graph_validation, {unknown_task_id, To}}};
        true ->
          TargetNode = maps:get(To, NodeMap),
          validate_edge_target_node_checked(From, Stream, To, ToPort, TargetNode)
      end;
    _ ->
      {error, {graph_validation, {invalid_edge_target, From, Stream, Edge}}}
  end.

validate_edge_target_node_checked(_From, _Stream, _To, stdin, #{cmd := _}) ->
  ok;
validate_edge_target_node_checked(_From, _Stream, erl, sink, _) ->
  ok;
validate_edge_target_node_checked(_From, _Stream, _To, file, _) ->
  ok;
validate_edge_target_node_checked(_From, _Stream, _To, sink, #{sink := erl}) ->
  ok;
validate_edge_target_node_checked(From, Stream, To, ToPort, _Node) ->
  {error, {graph_validation, {invalid_edge_target_port, From, Stream, To, ToPort}}}.

-spec validate_no_cycles_checked(map(), [graph_edge()]) -> ok | {error, any()}.
validate_no_cycles_checked(NodeMap, GraphEdges) ->
  Adjacency = adjacency_map(GraphEdges),
  case dag_has_cycle(maps:keys(NodeMap), Adjacency) of
    false -> ok;
    {true, NodeId} -> {error, {graph_validation, {cycle_detected, NodeId}}}
  end.

adjacency_map(GraphEdges) ->
  lists:foldl(
    fun(#{from := From, to := To}, Acc) ->
      maps:update_with(From, fun(L) -> [To | L] end, [To], Acc)
    end,
    #{},
    GraphEdges).

dag_has_cycle(NodeIds, Adjacency) ->
  dag_has_cycle(NodeIds, Adjacency, #{}).

dag_has_cycle([Id | T], Adjacency, Colors) ->
  case maps:get(Id, Colors, white) of
    white ->
      case dfs_cycle(Id, Adjacency, Colors) of
        {ok, Colors2} -> dag_has_cycle(T, Adjacency, Colors2);
        {cycle, NodeId} -> {true, NodeId}
      end;
    _ ->
      dag_has_cycle(T, Adjacency, Colors)
  end;
dag_has_cycle([], _Adjacency, _Colors) ->
  false.

dfs_cycle(Id, Adjacency, Colors0) ->
  Colors1 = maps:put(Id, gray, Colors0),
  Children = maps:get(Id, Adjacency, []),
  case dfs_children(Children, Adjacency, Colors1) of
    {ok, Colors2} -> {ok, maps:put(Id, black, Colors2)};
    {cycle, _} = Cycle -> Cycle
  end.

dfs_children([Child | T], Adjacency, Colors0) ->
  case maps:get(Child, Colors0, white) of
    gray ->
      {cycle, Child};
    black ->
      dfs_children(T, Adjacency, Colors0);
    white ->
      case dfs_cycle(Child, Adjacency, Colors0) of
        {ok, Colors1} -> dfs_children(T, Adjacency, Colors1);
        {cycle, _} = Cycle -> Cycle
      end
  end;
dfs_children([], _Adjacency, Colors) ->
  {ok, Colors}.

-spec validate_sink_nodes_checked(map(), [graph_edge()]) -> ok | {error, any()}.
validate_sink_nodes_checked(NodeMap, GraphEdges) ->
  SinkInbound = lists:foldl(
    fun(#{to := To, to_port := sink}, Acc) ->
        maps:update_with(To, fun(N) -> N + 1 end, 1, Acc);
       (_, Acc) ->
        Acc
    end,
    #{},
    GraphEdges),
  maps:fold(
    fun(Id, Node, ok) ->
      case Node of
        #{sink := erl} ->
          case maps:get(Id, SinkInbound, 0) > 0 of
            true -> ok;
            false -> {error, {graph_validation, {orphan_sink_node, Id}}}
          end;
        _ ->
          ok
      end;
       (_, _, Error) ->
      Error
    end,
    ok,
    NodeMap).

-spec graph_runtime_plan(map(), [graph_edge()], graph_run_opts()) ->
  {ok, runtime_plan()} | {error, any()}.
graph_runtime_plan(NodeMap, GraphEdges, _GraphOpts) ->
  {ok, #{node_map => NodeMap, edges => GraphEdges}}.

graph_node_map(Graph) ->
  graph_node_map(Graph, #{}, []).

graph_node_map([Node | T], Map, Seen) when is_map(Node) ->
  maybe
    {ok, Id} ?= maps:find(id, Node),
    false    ?= maps:is_key(Id, Map) andalso {duplicate_node_id, Id},
    graph_node_map(T, maps:put(Id, Node, Map), [Id | Seen])
  else
    error ->
      {error, {graph_validation, {missing_node_id, Node}}};
    {duplicate_node_id, _} = DupId ->
      {error, {graph_validation, DupId}}
  end;
graph_node_map([Other | _], _Map, _Seen) ->
  {error, {graph_validation, {invalid_node, Other}}};
graph_node_map([], Map, _) when map_size(Map) > 0 ->
  {ok, Map};
graph_node_map([], _Map, _) ->
  {error, {graph_validation, empty_graph}}.

graph_edges(NodeMap) ->
  maps:fold(
    fun(Id, Node, {ok, Edges}) ->
      case graph_node_edge(Id, Node, NodeMap) of
        {ok, NodeEdges} -> {ok, NodeEdges ++ Edges};
        {error, _} = Error -> Error
      end;
       (_, _, Error) ->
      Error
    end,
    {ok, []},
    NodeMap).

graph_node_edge(Id, Node, NodeMap) ->
  maybe
    {ok, _Cmd} ?= maps:find(cmd, Node),
    {ok, StdoutEdges} ?= graph_node_stream_edges(Id, stdout, Node, NodeMap),
    {ok, StderrEdges} ?= graph_node_stream_edges(Id, stderr, Node, NodeMap),
    {ok, StdoutEdges ++ StderrEdges}
  else
    error ->
      {error, {graph_validation, {missing_cmd, Id}}}
  end.

graph_node_stream_edges(Id, Stream, Node, NodeMap) when Stream =:= stdout; Stream =:= stderr ->
  maybe
    {ok, StreamValue} ?= maps:find(Stream, Node),
    {ok, OutEdges} ?= graph_node_stream_edges_from_value(Id, Stream, StreamValue, NodeMap),
    {ok, OutEdges}
  else
    error ->
      {ok, []};
    {error, _} = Error ->
      Error
  end.

graph_node_stream_edges_from_value(Id, Stream, erl, _NodeMap) ->
  {ok, [{Id, Stream, erl}]};
graph_node_stream_edges_from_value(Id, Stream, StreamValue, NodeMap) ->
  maybe
    {ok, StreamEdges} ?= normalize_edge_targets(NodeMap, StreamValue),
    {ok, OutEdges} ?= collect_stream_edges(Id, Stream, StreamEdges, NodeMap),
    {ok, OutEdges}
  else
    error ->
      {ok, []};
    {error, _} = Error ->
      Error
  end.

normalize_edge_target(_NodeMap, {to, _ToId, _ToPort} = Edge) ->
  Edge;
normalize_edge_target(_NodeMap, erl) ->
  {to, erl, sink};
normalize_edge_target(_NodeMap, {file, Path}) when is_binary(Path); is_list(Path) ->
  {to, Path, file};
normalize_edge_target(_NodeMap, ToId) when is_atom(ToId) ->
  {to, ToId, stdin};
normalize_edge_target(NodeMap, ToId) when is_binary(ToId); is_list(ToId) ->
  case maps:is_key(ToId, NodeMap) of
    true -> {to, ToId, stdin};
    false -> {to, ToId, file}
  end;
normalize_edge_target(_NodeMap, Other) ->
  Other.

normalize_edge_targets(NodeMap, Edges) when is_list(Edges) ->
  case io_lib:printable_unicode_list(Edges) of
    true ->
      normalize_edge_targets_scalar(NodeMap, Edges);
    false ->
      collect_edge_targets(NodeMap, Edges, [])
  end;
normalize_edge_targets(NodeMap, Edge) ->
  normalize_edge_targets_scalar(NodeMap, Edge).

normalize_edge_targets_scalar(NodeMap, Edge) ->
  case normalize_edge_target(NodeMap, Edge) of
    {to, _ToId, _ToPort} = Normalized -> {ok, [Normalized]};
    Other -> {error, {graph_validation, {invalid_edge_target, Other}}}
  end.

collect_edge_targets(NodeMap, [Edge | T], Acc) ->
  case normalize_edge_target(NodeMap, Edge) of
    {to, _ToId, _ToPort} = Normalized ->
      collect_edge_targets(NodeMap, T, [Normalized | Acc]);
    Other ->
      {error, {graph_validation, {invalid_edge_target, Other}}}
  end;
collect_edge_targets(_NodeMap, [], Acc) when Acc =:= [] ->
  {error, {graph_validation, empty_edge_list}};
collect_edge_targets(_NodeMap, [], Acc) ->
  {ok, lists:reverse(Acc)}.

collect_stream_edges(Id, Stream, [{to, ToId, stdin} | T], NodeMap) ->
  maybe
    true ?= maps:is_key(ToId, NodeMap) orelse {unknown_task_id, ToId},
    {ok, Tail} ?= collect_stream_edges(Id, Stream, T, NodeMap),
    {ok, [{Id, Stream, ToId} | Tail]}
  else
    {unknown_task_id, _} = Unknown ->
      {error, {graph_validation, Unknown}};
    {error, _} = Error ->
      Error
  end;
collect_stream_edges(Id, Stream, [{to, ToPath, file} | T], NodeMap) ->
  maybe
    {ok, Tail} ?= collect_stream_edges(Id, Stream, T, NodeMap),
    {ok, [{Id, Stream, ToPath, file} | Tail]}
  else
    {error, _} = Error ->
      Error
  end;
collect_stream_edges(Id, Stream, [{to, erl, sink} | T], NodeMap) ->
  maybe
    {ok, Tail} ?= collect_stream_edges(Id, Stream, T, NodeMap),
    {ok, [{Id, Stream, erl} | Tail]}
  else
    {error, _} = Error ->
      Error
  end;
collect_stream_edges(Id, Stream, [{to, ToId, ToPort} | _], _NodeMap) ->
  {error, {graph_validation, {invalid_edge_target_port, Id, Stream, ToId, ToPort}}};
collect_stream_edges(_Id, _Stream, [], _NodeMap) ->
  {ok, []}.

validate_graph_stdin(NodeMap, Edges) ->
  Inbound = graph_inbound_map(Edges),
  maps:fold(
    fun(Id, Node, ok) ->
      NodeInbound = maps:get(Id, Inbound, []),
      validate_node_stdin(Id, maps:get(stdin, Node, undefined), NodeInbound);
       (_, _, Error) ->
      Error
    end,
    ok,
    NodeMap).

validate_node_stdin(Id, {from, Sender, Stream}, NodeInbound)
  when Stream =:= stdout; Stream =:= stderr ->
  maybe
    true ?= lists:member({Sender, Stream}, NodeInbound) orelse
        {missing_sender_edge, Id, Sender, Stream},
    [{Sender, Stream}] ?= exact_stdin_edge(NodeInbound, Id, Sender, Stream),
    ok
  else
    {missing_sender_edge, _Id, _Sender, _Stream} ->
      case NodeInbound of
        [] ->
          {error, {graph_validation, {dangling_from, Id, {from, Sender, Stream}}}};
        [Only] ->
          {error, {graph_validation, {edge_conflict, Id, {from, Sender, Stream}, {from, element(1, Only), element(2, Only)}}}};
        _ ->
          {error, {graph_validation, {ambiguous_stdin, Id, NodeInbound}}}
      end;
    {ambiguous_stdin, _Id, _Inbound} = Ambiguous ->
      {error, {graph_validation, Ambiguous}}
  end;
validate_node_stdin(Id, undefined, NodeInbound) ->
  maybe
    true ?= is_zero_or_one_inbound(NodeInbound) orelse {ambiguous_stdin, Id, NodeInbound},
    ok
  else
    {ambiguous_stdin, _Id, _Inbound} = Ambiguous ->
      {error, {graph_validation, Ambiguous}}
  end;
validate_node_stdin(Id, Other, _NodeInbound) ->
  {error, {graph_validation, {invalid_stdin_binding, Id, Other}}}.

exact_stdin_edge(NodeInbound, Id, Sender, Stream) ->
  case NodeInbound of
    [{Sender, Stream}] = Match -> Match;
    _ -> {ambiguous_stdin, Id, NodeInbound}
  end.

is_zero_or_one_inbound([]) -> true;
is_zero_or_one_inbound([_]) -> true;
is_zero_or_one_inbound(_) -> false.

graph_inbound_map(Edges) ->
  lists:foldl(
    fun({From, Stream, To}, Acc) ->
      Existing = maps:get(To, Acc, []),
      maps:put(To, [{From, Stream} | Existing], Acc)
    end,
    #{},
    Edges).

