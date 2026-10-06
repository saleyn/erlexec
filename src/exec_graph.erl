%%% vim:ts=2:sw=2:et
-module(exec_graph).

-moduledoc """
Graph execution helpers for `exec:run_graph/2`.

This module contains parsing, validation, planning, and runtime execution
logic for process graphs.

Supported edge forms:
- `stdout => RecipientId`
- `stdout => {to, RecipientId, stdin}`
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
	run_options  => [sync, stdout, stderr],
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
""".
-type process_task() :: #{
	id     := task_id(),
	cmd    := exec:cmd(),
	stdout => edge() | [edge(), ...],
	stderr => edge() | [edge(), ...],
	stdin  => {from, task_id(), stream_kind()}
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
- `max_branch_buffer_bytes`: per-branch buffering budget hint for fan-out paths.
""".
-type graph_run_opts() :: # {
	run_options  => exec:cmd_options(),
	sink_tagging => by_sink | by_source,
	max_branch_buffer_bytes => non_neg_integer()
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

run_graph_plan(#{node_map := NodeMap, edges := V2Edges}, GraphOpts) ->
	run_graph_native(NodeMap, V2Edges, GraphOpts).

run_graph_native(NodeMap, V2Edges, GraphOpts) ->
	RunOptions = maps:get(run_options, GraphOpts, []),
	case lists:member(sync, RunOptions) of
		true ->
			run_graph_native_sync(NodeMap, V2Edges, GraphOpts);
		false ->
			run_graph_native_async(NodeMap, V2Edges, GraphOpts)
	end.

run_graph_native_sync(NodeMap, V2Edges, GraphOpts) ->
	RunOptions = maps:get(run_options, GraphOpts, []),
	case start_native_processes(NodeMap, RunOptions) of
		{ok, ProcMap, PidToId} ->
			State = init_native_state(NodeMap, V2Edges, GraphOpts, ProcMap, PidToId,
				sync, self(), 0, false),
			native_loop(State);
		{error, _} = Error ->
			Error
	end.

run_graph_native_async(NodeMap, V2Edges, GraphOpts) ->
	Owner         = self(),
	RunOptions    = maps:get(run_options, GraphOpts, []),
	GraphOsPid    = -erlang:unique_integer([positive]),
	NotifyMonitor = lists:member(monitor, RunOptions),
	Worker = spawn(fun() ->
		run_graph_native_async_worker(Owner, GraphOsPid, NotifyMonitor, NodeMap, V2Edges, GraphOpts)
	end),
	case lists:member(link, RunOptions) of
		true -> link(Worker);
		false -> ok
	end,
	receive
		{graph_started, GraphOsPid, Worker} ->
			{ok, Worker, GraphOsPid};
		{graph_start_failed, GraphOsPid, Reason} ->
			{error, Reason}
	end.

run_graph_native_async_worker(Owner, GraphOsPid, NotifyMonitor, NodeMap, V2Edges, GraphOpts) ->
	case start_native_processes(NodeMap, maps:get(run_options, GraphOpts, [])) of
		{ok, ProcMap, PidToId} ->
			Owner ! {graph_started, GraphOsPid, self()},
			State = init_native_state(NodeMap, V2Edges, GraphOpts, ProcMap, PidToId,
				async, Owner, GraphOsPid, NotifyMonitor),
			_ = native_loop(State),
			ok;
		{error, Reason} ->
			case NotifyMonitor of
				true -> Owner ! {'DOWN', GraphOsPid, process, self(), Reason};
				false -> ok
			end,
			exit(Reason)
	end.

init_native_state(NodeMap, V2Edges, GraphOpts, ProcMap, PidToId,
		Mode, Owner, GraphOsPid, NotifyMonitor) ->
	EdgesBySource = build_edges_by_source(V2Edges),
	SinkNodes = maps:filter(fun(_, N) -> maps:get(sink, N, undefined) =:= erl end, NodeMap),
	Exposed = exposed_process_streams(NodeMap, EdgesBySource),
	InboundOpen = inbound_stdin_counts(V2Edges),
	#{
		node_map         => NodeMap,
		proc_map         => ProcMap,
		pid_to_id        => PidToId,
		edges_by_source  => EdgesBySource,
		sink_nodes       => SinkNodes,
		exposed          => Exposed,
		inbound_open     => InboundOpen,
		sink_tagging     => maps:get(sink_tagging, GraphOpts, by_source),
		collect_stdout   => lists:member(stdout, maps:get(run_options, GraphOpts, [])),
		collect_stderr   => lists:member(stderr, maps:get(run_options, GraphOpts, [])),
		collected_stdout => [],
		collected_stderr => [],
		remaining        => map_size(ProcMap),
		exit_reason      => undefined,
		mode             => Mode,
		owner            => Owner,
		graph_ospid      => GraphOsPid,
		notify_monitor   => NotifyMonitor
	}.

native_loop(State = #{remaining := 0}) ->
	finalize_native_result(State);
native_loop(State0) ->
	receive
		{stdout, OsPid, Data} when is_integer(OsPid), is_binary(Data) ->
			native_loop(handle_native_stream(stdout, OsPid, Data, State0));
		{stderr, OsPid, Data} when is_integer(OsPid), is_binary(Data) ->
			native_loop(handle_native_stream(stderr, OsPid, Data, State0));
		{'DOWN', OsPid, process, _Pid, Reason} when is_integer(OsPid) ->
			native_loop(handle_native_down(OsPid, Reason, State0));
		{'DOWN', OsPid, {exit_status, Status}} when is_integer(OsPid) ->
			native_loop(handle_native_down(OsPid, {exit_status, Status}, State0));
		{'DOWN', _Ref, process, _Pid, _Reason} ->
			native_loop(State0)
	end.

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
	Targets = maps:get({FromId, Stream}, maps:get(edges_by_source, State0), []),
	lists:foldl(
		fun(#{to := ToPath, to_port := file}, StateAcc) ->
			write_graph_file(ToPath, Data),
			StateAcc;
		   (#{to := ToId, to_port := stdin}, StateAcc) ->
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

write_graph_file(Path, Data) ->
	ok = exec:write_file(Path, Data).

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
			State1 = close_downstream_stdin(FromId, EdgesBySource, State0),
			State2 = maybe_capture_exit_reason(Reason, State1),
			State2#{remaining := maps:get(remaining, State1) - 1}
	end.

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

start_native_processes(NodeMap, RunOptions) ->
	ProcNodes = maps:to_list(maps:filter(fun(_, N) -> maps:is_key(cmd, N) end, NodeMap)),
	StartOpts = native_process_run_options(RunOptions),
	start_native_processes(ProcNodes, StartOpts, #{}, #{}).

start_native_processes([{Id, Node} | T], StartOpts, ProcMap0, PidToId0) ->
	case exec:run(maps:get(cmd, Node), StartOpts) of
		{ok, Pid, OsPid} ->
			ProcMap = maps:put(Id, #{pid => Pid, ospid => OsPid}, ProcMap0),
			PidToId = maps:put(OsPid, Id, PidToId0),
			start_native_processes(T, StartOpts, ProcMap, PidToId);
		{error, _} = Error ->
			lists:foreach(
				fun(#{ospid := Existing}) -> _ = exec:kill(Existing, 9) end,
				maps:values(ProcMap0)),
			Error
	end;
start_native_processes([], _StartOpts, ProcMap, PidToId) ->
	{ok, ProcMap, PidToId}.

native_process_run_options(RunOptions) ->
	Filtered = [Opt || Opt <- RunOptions, not is_controlled_native_option(Opt)],
	[stdin, monitor, {stdout, self()}, {stderr, self()} | Filtered].

is_controlled_native_option(sync) -> true;
is_controlled_native_option(stdin) -> true;
is_controlled_native_option(stdout) -> true;
is_controlled_native_option(stderr) -> true;
is_controlled_native_option(monitor) -> true;
is_controlled_native_option({stdin, _}) -> true;
is_controlled_native_option({stdout, _}) -> true;
is_controlled_native_option({stderr, _}) -> true;
is_controlled_native_option(_) -> false.

build_edges_by_source(V2Edges) ->
	lists:foldl(
		fun(#{from := From, stream := Stream} = E, Acc) ->
			maps:update_with({From, Stream}, fun(L) -> [E | L] end, [E], Acc)
		end,
		#{},
		V2Edges).

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

inbound_stdin_counts(V2Edges) ->
	lists:foldl(
		fun(#{to := To, to_port := stdin}, Acc) ->
			maps:update_with(To, fun(N) -> N + 1 end, 1, Acc);
		   (_, Acc) ->
			Acc
		end,
		#{},
		V2Edges).

-spec normalize_graph_run_options(exec:cmd_options() | map()) ->
	{ok, graph_run_opts()} | {error, any()}.
normalize_graph_run_options(Opts) when is_list(Opts) ->
	{ok, #{run_options => Opts,
		   sink_tagging => by_source,
		   max_branch_buffer_bytes => 0}};
normalize_graph_run_options(Opts) when is_map(Opts) ->
	RunOptions = maps:get(run_options, Opts, []),
	SinkTagging = maps:get(sink_tagging, Opts, by_source),
	MaxBuf = maps:get(max_branch_buffer_bytes, Opts, 0),
	maybe
		true ?= is_list(RunOptions) orelse {invalid_run_options, RunOptions},
		true ?= (SinkTagging =:= by_sink orelse SinkTagging =:= by_source) orelse
				{invalid_sink_tagging, SinkTagging},
		true ?= (is_integer(MaxBuf) andalso MaxBuf >= 0) orelse {invalid_max_branch_buffer_bytes, MaxBuf},
		{ok, #{run_options => RunOptions,
			   sink_tagging => SinkTagging,
			   max_branch_buffer_bytes => MaxBuf}}
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
		{ok, Legacy} -> {ok, legacy_edges_to_graph_edges(Legacy)};
		{error, _} = Error -> Error
	end.

legacy_edges_to_graph_edges(Edges) ->
	[case Edge of
		{From, Stream, To} ->
			#{from => From,
			  stream => Stream,
			  to => To,
			  to_port => case To of erl -> sink; _ -> stdin end};
		{From, Stream, To, file} ->
			#{from => From,
			  stream => Stream,
			  to => To,
			  to_port => file}
	 end || Edge <- Edges].

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

