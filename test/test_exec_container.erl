%%%-------------------------------------------------------------------
%%% Tests for exec_container
%%%-------------------------------------------------------------------
-module(test_exec_container).

-include_lib("eunit/include/eunit.hrl").

all_options_build_test() ->
  Finder = fun
    ("podman") -> "/usr/bin/podman";
    ("docker") -> "/usr/bin/docker";
    (_) -> false
  end,
  Spec = #{
    image => "alpine:3.20",
    command => ["/bin/echo", "hello"],
    args => ["world"],
    env => [{"A", "B"}, {"N", 42}],
    volumes => [
      {"/data", "/mnt/data", read_only},
      {"/cache", "/mnt/cache", read_write}
    ],
    networks => ["bridge", "host"],
    ports => [
      8080,
      {18080, 8080},
      {"127.0.0.1", 18081, 8081},
      {udp, 5353, 5353},
      {"127.0.0.1", tcp, 18443, 8443}
    ],
    memory_limit => "512M",
    cpu_limit => "1000m",
    timeout => 5000,
    exec_options => [monitor, {timeout, 999}, stdout],
    start_timeout => 12000,
    remove => true
  },
  {ok, Cmd, ExecOpts, StartTimeout} = exec_container:build_container_run(Spec, Finder),
  ?assertEqual(12000, StartTimeout),
  ?assert(lists:member(monitor, ExecOpts)),
  ?assert(lists:member(stdout, ExecOpts)),
  ?assertEqual(1, length([T || T = {timeout, _} <- ExecOpts])),
  ?assert(lists:member({timeout, 5000}, ExecOpts)),
  ?assertEqual("/usr/bin/podman", hd(Cmd)),
  ?assert(lists:member("--rm", Cmd)),
  ?assert(lists:member("-e", Cmd)),
  ?assert(lists:member("A=B", Cmd)),
  ?assert(lists:member("N=42", Cmd)),
  ?assert(lists:member("-v", Cmd)),
  ?assert(lists:member("/data:/mnt/data:ro", Cmd)),
  ?assert(lists:member("/cache:/mnt/cache:rw", Cmd)),
  ?assert(lists:member("--network", Cmd)),
  ?assert(lists:member("bridge", Cmd)),
  ?assert(lists:member("host", Cmd)),
  ?assert(lists:member("-p", Cmd)),
  ?assert(lists:member("8080", Cmd)),
  ?assert(lists:member("18080:8080", Cmd)),
  ?assert(lists:member("127.0.0.1:18081:8081", Cmd)),
  ?assert(lists:member("5353:5353/udp", Cmd)),
  ?assert(lists:member("127.0.0.1:18443:8443/tcp", Cmd)),
  ?assert(lists:member("--memory", Cmd)),
  ?assert(lists:member("512M", Cmd)),
  ?assert(lists:member("--cpus", Cmd)),
  ?assert(lists:member("1", Cmd)),
  ?assert(lists:suffix(["alpine:3.20", "/bin/echo", "hello", "world"], Cmd)).

string_command_with_args_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{
    image => "alpine",
    command => "echo hi",
    args => ["x", "y z"]
  },
  {ok, Cmd, _ExecOpts, _StartTimeout} = exec_container:build_container_run(Spec, Finder),
  ?assert(lists:suffix(["alpine", "sh", "-lc", "echo hi 'x' 'y z'"], Cmd)).

argv_command_appends_args_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{
    image => "alpine",
    command => ["python", "-c", "print('ok')"],
    args => ["--flag"]
  },
  {ok, Cmd, _ExecOpts, _StartTimeout} = exec_container:build_container_run(Spec, Finder),
  ?assert(lists:suffix(["alpine", "python", "-c", "print('ok')", "--flag"], Cmd)).

auto_runtime_falls_back_to_docker_test() ->
  Finder = fun
    ("podman") -> false;
    ("docker") -> "/usr/bin/docker";
    (_) -> false
  end,
  Spec = #{image => "alpine", command => ["echo", "ok"]},
  {ok, Cmd, _ExecOpts, _StartTimeout} = exec_container:build_container_run(Spec, Finder),
  ?assertEqual("/usr/bin/docker", hd(Cmd)).

runtime_missing_test() ->
  Finder = fun(_) -> false end,
  Spec = #{image => "alpine", command => ["echo", "ok"]},
  ?assertEqual(
    {error, {container_runtime_not_found, [podman, docker]}},
    exec_container:build_container_run(Spec, Finder)
  ).

explicit_runtime_name_missing_test() ->
  Finder = fun(_) -> false end,
  Spec = #{image => "alpine", runtime => podman, command => ["echo", "ok"]},
  ?assertEqual(
    {error, {container_runtime_not_found, "podman"}},
    exec_container:build_container_run(Spec, Finder)
  ).

explicit_runtime_path_missing_test() ->
  Finder = fun(_) -> false end,
  Spec = #{image => "alpine", runtime => "/no/such/runtime", command => ["echo", "ok"]},
  ?assertEqual(
    {error, {container_runtime_not_found, "/no/such/runtime"}},
    exec_container:build_container_run(Spec, Finder)
  ).

invalid_ports_value_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{image => "alpine", command => ["echo", "ok"], ports => [70000]},
  ?assertMatch(
    {error, {invalid_container_spec, {ports, _}}},
    exec_container:build_container_run(Spec, Finder)
  ).

invalid_volume_mode_type_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{image => "alpine", command => ["echo", "ok"], volumes => [{"/a", "/b", 99}]},
  ?assertMatch(
    {error, {invalid_container_spec, {volume_mode, 99}}},
    exec_container:build_container_run(Spec, Finder)
  ).

invalid_on_timeout_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{image => "alpine", command => ["echo", "ok"], on_timeout => stop},
  ?assertEqual(
    {error, {invalid_container_spec, {on_timeout, stop}}},
    exec_container:build_container_run(Spec, Finder)
  ).

invalid_timeout_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{image => "alpine", command => ["echo", "ok"], timeout => -1},
  ?assertEqual(
    {error, {invalid_container_spec, {timeout, -1}}},
    exec_container:build_container_run(Spec, Finder)
  ).

remove_false_omits_rm_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{image => "alpine", command => ["echo", "ok"], remove => false},
  {ok, Cmd, _ExecOpts, _StartTimeout} = exec_container:build_container_run(Spec, Finder),
  ?assert(not lists:member("--rm", Cmd)).

missing_image_test() ->
  Finder = fun("podman") -> "/usr/bin/podman"; (_) -> false end,
  Spec = #{command => ["echo", "ok"]},
  ?assertEqual(
    {error, {invalid_container_spec, missing_image}},
    exec_container:build_container_run(Spec, Finder)
  ).

run_container_executes_echo_test() ->
  case os:getenv("ERLEXEC_RUN_CONTAINER_TESTS") of
    V when V=="0"; V=="N"; V=="NO" ->
      ok;
    _ ->
      run_container_executes_echo_enabled()
  end.

run_container_executes_echo_enabled() ->
  case {os:find_executable("podman"), os:find_executable("docker")} of
    {false, false} ->
      ok;
    _ ->
      with_exec_server(fun() ->
        Spec = #{
          image => "alpine:3.20",
          command => ["sh", "-lc", "echo erlexec-container-ok"],
          exec_options => [sync, stdout, stderr],
          timeout => 20000,
          start_timeout => 30000
        },
        case exec:run_container(Spec) of
          {ok, Result} ->
            Stdout = proplists:get_value(stdout, Result, []),
            ?assert(lists:member(<<"erlexec-container-ok\n">>, Stdout));
          {error, Reason} ->
            ?assert(false, {container_run_failed, Reason})
        end
      end)
  end.

with_exec_server(Fun) ->
  case whereis(exec) of
    undefined ->
      {ok, Pid} = exec:start([]),
      try
        Fun()
      after
        exit(Pid, kill)
      end;
    _Existing ->
      Fun()
  end.
