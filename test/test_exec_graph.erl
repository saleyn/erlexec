%%%-------------------------------------------------------------------
%%% @doc Tests for exec:run_graph/2 (process graph execution).
%%%
%%% Migrated out of test_exec.erl to keep graph-specific coverage in its own
%%% module. Includes:
%%% - Core run_graph/2 behavior tests (pipelines, fanout, sinks, file
%%%   destinations, validation errors).
%%% - Regression test for the sibling-pipe-fanout SIGPIPE crash (fixed:
%%%   see memory/sibling-pipe-sigpipe-bug-fixed.md).
%%% - Doc-validation tests exercising examples from guides/graphs.md,
%%%   so the guide can't silently drift from actual behavior.
%%% @end
%%%-------------------------------------------------------------------
-module(test_exec_graph).

-include_lib("eunit/include/eunit.hrl").

graph_test_() ->
    {setup,
     fun() -> application:ensure_all_started(erlexec), ok end,
     fun(_) -> ok end,
     case os:type() of
         {unix, _} ->
             [
                 {"Run graph pipeline", ?_test(test_run_graph_pipeline())},
                 {"Run graph pipeline with shorthand edge", ?_test(test_run_graph_pipeline_shorthand_edge())},
                 {"Run graph with optional stdin annotation", ?_test(test_run_graph_optional_stdin_annotation())},
                 {"Run graph async native monitor", ?_test(test_run_graph_async_native_monitor())},
                 {"Run graph async fanout monitor", ?_test(test_run_graph_async_fanout_monitor())},
                 {"Run graph async erl sink shorthand", ?_test(test_run_graph_async_erl_sink_shorthand())},
                 {"Graph stdin mismatch returns error", ?_test(test_run_graph_stdin_mismatch())},
                 {"Graph stdout list targets accepted", ?_test(test_run_graph_stdout_list_targets())},
                 {"Graph stdout file destination accepts string path", ?_test(test_run_graph_stdout_file_destination_string())},
                 {"Graph stdout file destination accepts binary path", ?_test(test_run_graph_stdout_file_destination_binary())},
                 {"Graph stderr edge routes through graph", ?_test(test_run_graph_stderr_edge_routes_through_graph())},
                 {"Graph erl sink shorthand receives payload", ?_test(test_run_graph_erl_sink_shorthand())},
                 {"Graph stderr list targets accepted", ?_test(test_run_graph_stderr_list_targets())},
                 {"Sibling-pipe fanout survives early-exiting consumer (SIGPIPE regression)",
                     ?_test(test_run_graph_sibling_pipe_early_exit_consumer())},
                 {"Doc: per-stage observability via erl sink on intermediate stage",
                     ?_test(test_run_graph_doc_per_stage_observability())},
                 {"Doc: structured failure attribution surfaces exit status",
                     ?_test(test_run_graph_doc_structured_failure_attribution())},
                 {"Doc: injection-safe construction via argv-list cmd",
                     ?_test(test_run_graph_doc_injection_safe_construction())},
                 {"Reap-race regression: sequential fast-failing middle stage",
                     {timeout, 60, ?_test(test_reap_race_sequential_fast_fail())}},
                 {"Reap-race regression: concurrent fast-failing middle stage",
                     {timeout, 60, ?_test(test_reap_race_concurrent_fast_fail())}},
                 {"task_monitor delivers per-task completion events in order",
                     ?_test(test_run_graph_task_monitor_per_task_events())},
                 {"task_monitor is independent of monitor (task events without graph monitor)",
                     ?_test(test_run_graph_task_monitor_without_graph_monitor())},
                 {"per-task timeout kills only that task, siblings unaffected",
                     {timeout, 10, ?_test(test_run_graph_per_task_timeout_scoped())}},
                 {"graph-level timeout kills every task in the graph",
                     {timeout, 10, ?_test(test_run_graph_level_timeout_kills_all())}},
                 {"graph-level timeout does not fire when graph finishes in time",
                     ?_test(test_run_graph_level_timeout_no_premature_fire())},
                 {"stats + task_monitor together do not crash the graph worker (regression)",
                     ?_test(test_run_graph_stats_with_task_monitor_no_crash())},
                 {"per-task stats field attaches StatsMap to task_monitor reason only",
                     ?_test(test_run_graph_per_task_stats_scoped_to_task_monitor())}
             ];
         _ ->
             []
     end
    }.

test_run_graph_pipeline() ->
    Graph = [
        #{id => producer,
          cmd => "printf 'a\\nb\\nc\\n'",
          stdout => {to, filter, stdin}},
        #{id => filter,
          cmd => "grep '^b$'"}
    ],
    case exec:run_graph(Graph, [sync, stdout]) of
        {ok, [{stdout, [<<"b\n">>]}]} ->
            ok;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_pipeline_shorthand_edge() ->
    Graph = [
        #{id => producer,
          cmd => "printf 'a\\nb\\nc\\n'",
          stdout => filter},
        #{id => filter,
          cmd => "grep '^b$'"}
    ],
    case exec:run_graph(Graph, [sync, stdout]) of
        {ok, [{stdout, [<<"b\n">>]}]} ->
            ok;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_optional_stdin_annotation() ->
    Graph = [
        #{id => producer,
          cmd => "printf 'x\\ny\\n'",
          stdout => {to, filter, stdin}},
        #{id => filter,
          cmd => "grep '^y$'",
          stdin => {from, producer, stdout}}
    ],
    case exec:run_graph(Graph, [sync, stdout]) of
        {ok, [{stdout, [<<"y\n">>]}]} ->
            ok;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_async_native_monitor() ->
    Graph = [
        #{id => producer,
          cmd => "printf 'ok\\n'",
          stdout => consumer},
        #{id => consumer,
          cmd => "cat"}
    ],
    case exec:run_graph(Graph, [stdout, monitor]) of
        {ok, Pid, GraphOsPid} when is_pid(Pid), is_integer(GraphOsPid) ->
            receive
                {stdout, GraphOsPid, <<"ok\n">>} -> ok
            after 5000 ->
                ?assert(false, {missing_stdout, GraphOsPid})
            end,
            receive
                {'DOWN', GraphOsPid, process, Pid, normal} -> ok
            after 5000 ->
                ?assert(false, {missing_down, GraphOsPid})
            end;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_async_fanout_monitor() ->
    Graph = [
        #{id => producer,
          cmd => "printf 'x\\n'",
          stdout => [left, right]},
        #{id => left,
          cmd => "cat"},
        #{id => right,
          cmd => "cat"}
    ],
    case exec:run_graph(Graph, [monitor]) of
        {ok, Pid, GraphOsPid} when is_pid(Pid), is_integer(GraphOsPid) ->
            receive
                {'DOWN', GraphOsPid, process, Pid, normal} -> ok
            after 5000 ->
                ?assert(false, {missing_down, GraphOsPid})
            end;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_async_erl_sink_shorthand() ->
    Graph = [
        #{id => producer,
          cmd => "printf 's1\\n'",
          stdout => erl}
    ],
    case exec:run_graph(Graph, [stdout, monitor]) of
        {ok, Pid, GraphOsPid} when is_pid(Pid), is_integer(GraphOsPid) ->
            receive
                {stdout, GraphOsPid, <<"s1\n">>} -> ok
            after 5000 ->
                ?assert(false, {missing_stdout, GraphOsPid})
            end,
            receive
                {'DOWN', GraphOsPid, process, Pid, normal} -> ok
            after 5000 ->
                ?assert(false, {missing_down, GraphOsPid})
            end;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_stdin_mismatch() ->
    Graph = [
        #{id => producer,
          cmd => "echo ok",
          stdout => {to, filter, stdin}},
        #{id => filter,
          cmd => "cat",
          stdin => {from, wrong_sender, stdout}}
    ],
    ?assertMatch(
        {error, {graph_validation, {edge_conflict, filter, _, _}}},
        exec:run_graph(Graph, [sync, stdout])
    ).

test_run_graph_stdout_list_targets() ->
        Graph = [
                #{id => producer,
                    cmd => "printf 'a\\nb\\n'",
                    stdout => [left, right]},
                #{id => left,
                    cmd => "cat"},
                #{id => right,
                    cmd => "cat"}
        ],
        case exec:run_graph(Graph, [sync, stdout]) of
            {ok, [{stdout, Chunks}]} ->
                Joined = iolist_to_binary(Chunks),
                ?assertEqual(2, length(binary:matches(Joined, <<"a\n">>))),
                ?assertEqual(2, length(binary:matches(Joined, <<"b\n">>)));
            Other ->
                ?assert(false, {unexpected_result, Other})
        end.

test_run_graph_stdout_file_destination_string() ->
    FilePath = graph_temp_file("stdout-string"),
    Graph = [
        #{id => producer,
          cmd => "printf 'file-string\\n'",
          stdout => [collector, FilePath]},
        #{id => collector,
          cmd => "cat"}
    ],
    try
        case exec:run_graph(Graph, [sync, stdout]) of
            {ok, [{stdout, [<<"file-string\n">>]}]} ->
                {ok, FileBin} = file:read_file(FilePath),
                ?assertEqual(<<"file-string\n">>, FileBin);
            Other ->
                ?assert(false, {unexpected_result, Other})
        end
    after
        _ = file:delete(FilePath)
    end.

test_run_graph_stdout_file_destination_binary() ->
    FilePath = graph_temp_file("stdout-binary"),
    FilePathBin = list_to_binary(FilePath),
    Graph = [
        #{id => producer,
          cmd => "printf 'file-binary\\n'",
          stdout => [collector, FilePathBin]},
        #{id => collector,
          cmd => "cat"}
    ],
    try
        case exec:run_graph(Graph, [sync, stdout]) of
            {ok, [{stdout, [<<"file-binary\n">>]}]} ->
                {ok, FileBin} = file:read_file(FilePath),
                ?assertEqual(<<"file-binary\n">>, FileBin);
            Other ->
                ?assert(false, {unexpected_result, Other})
        end
    after
        _ = file:delete(FilePath)
    end.

test_run_graph_stderr_edge_routes_through_graph() ->
    Graph = [
        #{id => src,
            cmd => "echo err 1>&2",
            stderr => collector},
        #{id => collector,
            cmd => "cat"}
    ],
    case exec:run_graph(Graph, [sync, stdout]) of
        {ok, [{stdout, [<<"err\n">>]}]} ->
            ok;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_erl_sink_shorthand() ->
    Graph = [
        #{id => src,
            cmd => "printf 's1\\n'",
            stdout => erl}
    ],
    case exec:run_graph(Graph, [sync, stdout]) of
        {ok, [{stdout, [<<"s1\n">>]}]} ->
            ok;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end.

test_run_graph_stderr_list_targets() ->
        Graph = [
                #{id => producer,
                    cmd => "echo ok",
                    stderr => [consumer]},
                #{id => consumer,
                    cmd => "cat"}
        ],
        ?assertMatch(
                {ok, [{stdout, [<<"ok\n">>]}]},
                exec:run_graph(Graph, [sync, stdout])
        ).

%% Regression test for the sibling-pipe-fanout SIGPIPE crash: a producer fans
%% out (natively, via a sibling stdin pipe) to a consumer that exits early
%% (after reading only its first line), closing its stdin read-end while the
%% producer is still writing. Before the fix, process_pid_output's fanout
%% write() to the now-closed pipe raised SIGPIPE, which the port's global
%% signal handler treated as a reason to terminate the ENTIRE exec-port
%% process (not just this task). See memory/sibling-pipe-sigpipe-bug-fixed.md.
%%
%% Verifies both: (a) the graph itself completes with the expected partial
%% result, and (b) the exec-port (and thus the whole erlexec application)
%% survives and can still manage new processes afterward.
test_run_graph_sibling_pipe_early_exit_consumer() ->
    Graph = [
        #{id => producer,
          cmd => "for i in 1 2 3 4 5; do echo line$i; sleep 0.05; done",
          stdout => consumer},
        #{id => consumer,
          cmd => "head -n 1"}
    ],
    case exec:run_graph(Graph, [sync, stdout]) of
        {ok, [{stdout, [<<"line1\n">>]}]} ->
            ok;
        Other ->
            ?assert(false, {unexpected_result, Other})
    end,
    %% Give the producer's remaining fanout writes (to the now-closed pipe) a
    %% chance to execute and potentially crash the port, if the bug regresses.
    timer:sleep(500),
    %% If the port survived, this call succeeds; if it crashed, the gen_server
    %% would be down and this would throw/exit.
    ?assertEqual([], exec:which_children()).

%% Doc example (guides/graphs.md, "Per-stage observability"): tap an
%% intermediate stage's output via the `erl` sink shorthand without
%% disturbing the rest of the pipeline.
test_run_graph_doc_per_stage_observability() ->
    Graph = [
        #{id => producer, cmd => "printf 'a\\nb\\nc\\n'", stdout => middle},
        #{id => middle,   cmd => "sort", stdout => erl}
    ],
    {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [stdout, monitor]),
    receive
        {stdout, GraphOsPid, Bin} ->
            ?assertEqual(<<"a\nb\nc\n">>, Bin)
    after 5000 ->
        ?assert(false, missing_stdout)
    end,
    receive
        {'DOWN', GraphOsPid, process, Pid, normal} -> ok
    after 5000 ->
        ?assert(false, missing_down)
    end.

%% Doc example (guides/graphs.md, "Structured failure attribution"): a
%% middle-stage failure surfaces via the sync error tuple and via the async
%% 'DOWN' reason, both carrying the specific {exit_status, Code}.
test_run_graph_doc_structured_failure_attribution() ->
    Graph = [
        #{id => a, cmd => "echo start", stdout => b},
        #{id => b, cmd => "false", stdout => c},
        #{id => c, cmd => "cat"}
    ],
    ?assertEqual(
        {error, [{exit_status, 256}, {stdout, []}]},
        exec:run_graph(Graph, [sync, stdout])
    ),
    {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [monitor]),
    receive
        {'DOWN', GraphOsPid, process, Pid, Reason} ->
            ?assertEqual({exit_status, 256}, Reason)
    after 5000 ->
        ?assert(false, missing_down)
    end.

%% Doc example (guides/graphs.md, "Programmatic, injection-safe
%% construction"): a hostile pattern passed via the argv-list cmd form is
%% treated as a literal grep argument, never interpreted by a shell.
test_run_graph_doc_injection_safe_construction() ->
    MarkerFile = graph_temp_file("injection-marker"),
    UserPattern = "x; touch " ++ MarkerFile ++ " #",
    %% The argv-list cmd form calls execve() directly (no shell), so the
    %% executable must be a resolvable path -- resolve "grep" via $PATH here
    %% since the test environment's path may vary.
    GrepPath = os:find_executable("grep"),
    Graph = [
        #{id => src, cmd => "printf 'a\\nx\\nb\\n'", stdout => filter},
        #{id => filter, cmd => [GrepPath, "-F", UserPattern]}
    ],
    try
        case exec:run_graph(Graph, [sync, stdout]) of
            {error, [{exit_status, _}, {stdout, []}]} ->
                %% No line matches the literal pattern -- grep found nothing,
                %% exits non-zero. The important assertion is below: the
                %% embedded `touch` was never executed by a shell.
                ok;
            Other ->
                ?assert(false, {unexpected_result, Other})
        end,
        ?assertNot(filelib:is_file(MarkerFile))
    after
        _ = file:delete(MarkerFile)
    end.

graph_temp_file(Suffix) ->
    Name = lists:flatten(io_lib:format("/tmp/erlexec-graph-~s-~p", [Suffix, erlang:unique_integer([positive])])),
    _ = file:delete(Name),
    Name.

%% --------------------------------------------------------------------------
%% Reap-race regression tests (CI early-warning tripwire)
%% --------------------------------------------------------------------------
%% Historically (see memory/graph-reap-race-bug.md), a 3-stage graph whose
%% middle stage exits quickly with a non-zero status could intermittently
%% hang: `check_child`'s liveness-probe-then-waitpid path and
%% `check_child_exit`'s EOF/SIGCHLD-driven path could both attempt
%% waitpid(2) for the same fast-exiting pid; the loser got ECHILD and (absent
%% a dedup guard) could silently drop the exit notification, leaving
%% `native_loop/1` waiting forever for a 'DOWN' that never arrives.
%%
%% A hardening fix added a dedup guard to `check_child` (mirroring the one
%% already in `check_child_exit`) so a pid already recorded in
%% `exited_children` is never re-probed/re-waited. Exhaustive manual testing
%% (1000+ sequential and concurrent trials) could not reproduce the hang even
%% before this hardening fix, suggesting an earlier, unrelated SIGCHLD
%% signal-handler rewrite had already closed the practical timing window.
%% These two tests exist as a tripwire: if the race ever resurfaces (e.g. a
%% future refactor reintroduces an un-deduplicated waitpid call site), CI
%% will start timing out here instead of only in the field.
-define(REAP_RACE_ITERATIONS, 60).
-define(REAP_RACE_PER_RUN_TIMEOUT, 2000).

reap_race_graph() ->
    [
        #{id => a, cmd => "true", stdout => b},
        #{id => b, cmd => "false", stdout => c},
        #{id => c, cmd => "true"}
    ].

reap_race_run_once() ->
    {ok, Pid, GraphOsPid} = exec:run_graph(reap_race_graph(), [monitor]),
    receive
        {'DOWN', GraphOsPid, process, Pid, _Reason} -> ok
    after ?REAP_RACE_PER_RUN_TIMEOUT ->
        timeout
    end.

test_reap_race_sequential_fast_fail() ->
    Results = [reap_race_run_once() || _ <- lists:seq(1, ?REAP_RACE_ITERATIONS)],
    Hangs = length([ok || timeout <- Results]),
    ?assertEqual(0, Hangs).

test_reap_race_concurrent_fast_fail() ->
    Parent = self(),
    Pids = [spawn(fun() -> Parent ! {self(), reap_race_run_once()} end)
            || _ <- lists:seq(1, ?REAP_RACE_ITERATIONS)],
    Results = [receive {P, R} -> R after ?REAP_RACE_PER_RUN_TIMEOUT + 3000 -> timeout end
               || P <- Pids],
    Hangs = length([ok || timeout <- Results]),
    ?assertEqual(0, Hangs).

%% --------------------------------------------------------------------------
%% task_monitor tests
%% --------------------------------------------------------------------------

%% Each task in a 3-stage pipeline should produce its own
%% {'DOWN', GraphOsPid, task, TaskId, normal} event, in completion order,
%% followed by the whole-graph {'DOWN', GraphOsPid, process, Pid, normal}.
test_run_graph_task_monitor_per_task_events() ->
    Graph = [
        #{id => a, cmd => "echo a", stdout => b},
        #{id => b, cmd => "cat",    stdout => c},
        #{id => c, cmd => "cat"}
    ],
    {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [monitor, task_monitor]),
    TaskEvents = collect_task_monitor_events(GraphOsPid, Pid, []),
    ?assertEqual([{a, normal}, {b, normal}, {c, normal}], TaskEvents).

%% task_monitor can be used without the whole-graph `monitor` option -- the
%% caller still gets per-task events, just not a final graph-level 'DOWN'.
%% Since there's then no reliable terminal signal to synchronize on, this
%% test just asserts the first task's event arrives correctly.
test_run_graph_task_monitor_without_graph_monitor() ->
    Graph = [
        #{id => a, cmd => "echo a"}
    ],
    {ok, _Pid, GraphOsPid} = exec:run_graph(Graph, [task_monitor]),
    receive
        {'DOWN', GraphOsPid, task, a, normal} -> ok
    after 5000 ->
        ?assert(false, missing_task_down)
    end.

collect_task_monitor_events(GraphOsPid, Pid, Acc) ->
    receive
        {'DOWN', GraphOsPid, task, TaskId, Reason} ->
            collect_task_monitor_events(GraphOsPid, Pid, [{TaskId, Reason} | Acc]);
        {'DOWN', GraphOsPid, process, Pid, _Reason} ->
            lists:reverse(Acc)
    after 5000 ->
        lists:reverse(Acc)
    end.

%% --------------------------------------------------------------------------
%% timeout tests (per-task node field vs. graph-level GraphOpts key)
%% --------------------------------------------------------------------------

%% A `timeout => Ms` field on one graph task's node map kills ONLY that task.
%% An independent sibling task (no edge to/from the timed-out one) is unaffected
%% and keeps running to its own natural completion -- confirms task-level scope
%% does NOT cascade to the rest of the graph, unlike the graph-level `timeout` key.
test_run_graph_per_task_timeout_scoped() ->
    Graph = [
        #{id => a, cmd => "sleep 10", timeout => 200},
        #{id => b, cmd => "sleep 1"}
    ],
    T0 = erlang:monotonic_time(millisecond),
    R = exec:run_graph(Graph, [sync, stdout]),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    %% Graph waits for B's full `sleep 1` (~1000ms), unaffected by A's 200ms task timeout.
    ?assert(Elapsed >= 900, {graph_finished_too_early, Elapsed}),
    ?assertMatch({error, [{exit_status, _} | _]}, R).

%% A graph-level `timeout` key in GraphOpts bounds the WHOLE graph's wall-clock budget.
%% When it fires, every task is killed and the result/'DOWN' reason is {timeout, graph}.
test_run_graph_level_timeout_kills_all() ->
    Graph = [
        #{id => a, cmd => "sleep 10"},
        #{id => b, cmd => "sleep 10"}
    ],
    T0 = erlang:monotonic_time(millisecond),
    R = exec:run_graph(Graph, #{run_options => [sync, stdout], timeout => 300}),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assert(Elapsed < 2000, {graph_timeout_did_not_fire_promptly, Elapsed}),
    ?assertMatch({error, [{timeout, graph} | _]}, R).

%% A graph-level timeout generous enough to cover the graph's actual run time must
%% not fire -- the graph should complete normally.
test_run_graph_level_timeout_no_premature_fire() ->
    Graph = [#{id => a, cmd => "echo done"}],
    R = exec:run_graph(Graph, #{run_options => [sync, stdout], timeout => 5000}),
    ?assertEqual({ok, [{stdout, [<<"done\n">>]}]}, R).

%% --------------------------------------------------------------------------
%% stats tests (run_options pass-through + per-task node field)
%% --------------------------------------------------------------------------

%% Regression: before stats/'DOWN' were redesigned (per [[stats-task-monitor-crash-fixed]]),
%% `exec:run_graph(Graph, [stats, monitor, task_monitor])` crashed the graph's async
%% worker process with a case_clause error in native_loop_dispatch/2, because that
%% function had no clause for the (then-standalone) {stats, OsPid, StatsMap} message.
%% Verifies the worker survives and both notification channels still work.
test_run_graph_stats_with_task_monitor_no_crash() ->
    Graph = [#{id => a, cmd => "echo a"}],
    {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [stats, monitor, task_monitor]),
    {TaskReason, GraphReason} = collect_task_and_graph_down(GraphOsPid, Pid, undefined, undefined),
    ?assertMatch({normal, #{wall_time_ms := Ms}} when is_integer(Ms), TaskReason),
    ?assertEqual(normal, GraphReason),
    %% The exec gen_server itself must still be alive -- the original bug crashed only
    %% the graph worker, but confirms the whole app wasn't destabilized either.
    ?assert(is_process_alive(whereis(exec))).

%% A per-task `stats => true` node field attaches StatsMap to that task's
%% task_monitor notification, but the graph's own whole-graph 'DOWN'/result reason
%% stays plain (stats never silently expands to graph-level visibility).
test_run_graph_per_task_stats_scoped_to_task_monitor() ->
    Graph = [#{id => a, cmd => "sleep 0.1", stats => true}],
    {ok, Pid, GraphOsPid} = exec:run_graph(Graph, [monitor, task_monitor]),
    {TaskReason, GraphReason} = collect_task_and_graph_down(GraphOsPid, Pid, undefined, undefined),
    ?assertMatch({normal, #{wall_time_ms := _}}, TaskReason),
    ?assertEqual(normal, GraphReason).

collect_task_and_graph_down(_GraphOsPid, _Pid, TaskReason, GraphReason)
        when TaskReason =/= undefined, GraphReason =/= undefined ->
    {TaskReason, GraphReason};
collect_task_and_graph_down(GraphOsPid, Pid, TaskReason, GraphReason) ->
    receive
        {'DOWN', GraphOsPid, task, _TaskId, R} ->
            collect_task_and_graph_down(GraphOsPid, Pid, R, GraphReason);
        {'DOWN', GraphOsPid, process, Pid, R} ->
            collect_task_and_graph_down(GraphOsPid, Pid, TaskReason, R)
    after 5000 ->
        {TaskReason, GraphReason}
    end.
