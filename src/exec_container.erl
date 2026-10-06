%%% vim:ts=2:sw=2:et
-module(exec_container).
-moduledoc """
Container command helper for `exec`.

This module translates a container specification map into an argv form suitable
for `exec:run_link/3`, choosing a container runtime and mapping high-level keys
to runtime flags.

## Runtime Selection

- Default behavior (`runtime => auto`) prefers `podman`, then falls back to
  `docker`.
- Explicit runtime names (`podman`, `docker`) are also supported.
- A custom executable path can be provided via `runtime` as string or binary.

## Runtime Cache

When called through `exec_container:run_link/1`, runtime executable paths are
cached in `persistent_term` for faster subsequent calls.

- The cache stores discovered paths for `auto`, `podman`, and/or `docker`.
- Before use, cached paths are validated with `filelib:is_file/1`.
- Missing stale paths are evicted and re-discovered.

## Supported Spec Keys

- `image` (required)
- `command` (string/binary shell form or argv list)
- `args` (argv list)
- `env` (map or list of `{Key, Value}`)
- `volumes` (`[{Host, Container}]` or `[{Host, Container, Mode :: text() | ro | rw | read_only | read_write}]`)
- `networks` (list)
- `ports` (list; mapped to `-p` / `--publish`)
- `memory_limit` (mapped to `--memory`)
- `cpu_limit` (mapped to `--cpus`, supports milli CPU strings like `"500m"`)
- `runtime` (`auto | podman | docker | path`)
- `remove` (`true` by default, adds `--rm`)
- `timeout` (mapped to `exec` option `{timeout, Ms}`)
- `on_timeout` (currently only `kill`)
- `exec_options` (extra `exec:run_link/2` options)
- `start_timeout` (timeout used for `exec:run_link/3` call)

## Example

```erlang
exec_container:run_link(#{
  image        => "alpine:3.20",
  command      => "echo hello",
  env          => #{"FOO" => "bar"},
  volumes      => [{"/tmp", "/work", "ro"}],
  ports        => [{"127.0.0.1", 8080, 80}, {udp, 5353, 5353}],
  cpu_limit    => "500m",
  memory_limit => "256M",
  timeout      => 5000
}).
```
""".

-export([run_link/1]).
-export_type([container_spec/0]).

-ifdef(EUNIT).
-export([build_container_run/2]).
-endif.

-define(TIMEOUT, 30000).
-define(CONTAINER_RUNTIME_CACHE_KEY, {?MODULE, container_runtime_cache}).

-doc "Text value accepted in container spec fields (string or binary).".
-type text()   :: string() | binary().

-doc "Environment key/value pair used by the `env` field.".
-type env_kv() :: {text(), text() | integer() | float()}.

-doc "Volume mapping used by the `volumes` field.".
-type volume_spec() ::
  {HostPath :: text(), ContainerPath :: text()} |
  {HostPath :: text(), ContainerPath :: text(), Mode :: text() | ro | rw | read_only | read_write}.

-doc "Transport protocol qualifier used in `port_spec()` tuples.".
-type proto()     :: tcp | udp.

-doc "Valid TCP/UDP port range.".
-type port_num()  :: 1..65535.

-doc "Supported forms for one entry in the `ports` field.".
-type port_spec() ::
  port_num() |
  {HostPort :: port_num() | text(), ContainerPort :: port_num() | text()} |
  {HostIp   :: text(),  HostPort :: port_num() | text(), ContainerPort :: port_num() | text()} |
  {Proto    :: proto(), HostPort :: port_num() | text(), ContainerPort :: port_num() | text()} |
  {HostIp   :: text(),  Proto    :: proto(), HostPort :: port_num() | text(), ContainerPort :: port_num() | text()}.

-doc """
Specification map consumed by `run_link/1`.

Required key:
- `image`

Optional keys:
- `command`: string/binary shell command or argv list
- `args`: extra argv list
- `env`: map or list of `{Key, Value}` tuples
- `volumes`: list of `volume_spec()`
  : mode supports standard values (for example `"ro"`, `"rw"`) and aliases
    `read_only` -> `"ro"`, `read_write` -> `"rw"`
- `networks`: list of network names
- `ports`: list of `port_spec()`
- `memory_limit`: value for `--memory`
- `cpu_limit`: value for `--cpus` (milli values like `"500m"` are accepted)
- `runtime`: `auto` (default), `podman`, `docker`, or explicit executable
- `remove`: whether to add `--rm` (default `true`)
- `timeout`: mapped to `exec` watchdog option `{timeout, Ms}`
- `on_timeout`: currently only `kill`
- `exec_options`: additional options passed through to `exec:run_link/3`
- `start_timeout`: timeout for the `exec:run_link/3` call itself
""".
-type container_spec() :: #{
  image         := text(),
  command       => text() | [text()],
  args          => [text()],
  env           => map() | [env_kv()],
  volumes       => [volume_spec()],
  networks      => [text()],
  ports         => [port_spec()],
  memory_limit  => text() | integer(),
  cpu_limit     => text() | integer() | float(),
  runtime       => auto | podman | docker | text(),
  remove        => boolean(),
  timeout       => non_neg_integer(),
  on_timeout    => kill,
  exec_options  => list(),
  start_timeout => pos_integer()
}.

-spec run_link(container_spec()) ->
    {ok, pid(), integer()} | {ok, [{stdout | stderr, [binary()]}]} | {error, any()}.
-doc """
Run a container command using `exec:run_link/3` through `exec_container:run_link/1`.

The specification map is transformed into a runtime command line. On success,
returns the same shape as `exec:run_link/3`.
""".
run_link(Spec) when is_map(Spec) ->
  case build_container_run(Spec, fun os:find_executable/1, true) of
    {ok, Cmd, RunOpts, StartTimeout} ->
      exec:run_link(Cmd, RunOpts, StartTimeout);
    {error, _}=Err ->
      Err
  end.

-ifdef(EUNIT).
%% Finder-based builder keeps caching disabled so unit tests that inject
%% custom finders remain deterministic.
-spec build_container_run(container_spec(), fun((string()) -> string() | false)) ->
    {ok, [string() | binary()], list(), integer()} | {error, any()}.
build_container_run(Spec, Finder) when is_map(Spec), is_function(Finder, 1) ->
  build_container_run(Spec, Finder, false).
-endif.

-spec build_container_run(container_spec(), fun((string()) -> string() | false), boolean()) ->
    {ok, [string() | binary()], list(), integer()} | {error, any()}.
-doc false.
build_container_run(Spec, Finder, UseCache)
  when is_map(Spec), is_function(Finder, 1), is_boolean(UseCache) ->
  try
    RuntimePref  = maps:get(runtime, Spec, auto),
    Runtime      = select_container_runtime(RuntimePref, Finder, UseCache),
    Image        = ensure_text(image, maps:get(image, Spec)),
    RunArgs      = container_run_args(Spec),
    CmdArgs      = container_command_args(Spec),
    OnTimeout    = maps:get(on_timeout, Spec, kill),
    ok           = validate_on_timeout(OnTimeout),
    Opts0        = maps:get(exec_options, Spec, []),
    is_list(Opts0) orelse throw({error, {invalid_container_spec, {exec_options, Opts0}}}),
    Opts         = maybe_set_exec_timeout(Opts0, maps:get(timeout, Spec, undefined)),
    StartTimeout = maps:get(start_timeout, Spec, ?TIMEOUT),
    is_integer(StartTimeout) andalso StartTimeout > 0
      orelse throw({error, {invalid_container_spec, {start_timeout, StartTimeout}}}),
    Cmd = [Runtime, "run" | RunArgs] ++ [Image | CmdArgs],
    {ok, Cmd, Opts, StartTimeout}
  catch
    throw:{error, _}=Err ->
      Err;
    error:{badkey, image} ->
      {error, {invalid_container_spec, missing_image}}
  end.

validate_on_timeout(kill) ->
  ok;
validate_on_timeout(Other) ->
  throw({error, {invalid_container_spec, {on_timeout, Other}}}).

maybe_set_exec_timeout(ExecOpts, undefined) ->
  ExecOpts;
maybe_set_exec_timeout(ExecOpts, Ms) when is_integer(Ms), Ms >= 0 ->
  [{timeout, Ms} | [Opt || Opt <- ExecOpts, not is_timeout_opt(Opt)]];
maybe_set_exec_timeout(_ExecOpts, Other) ->
  throw({error, {invalid_container_spec, {timeout, Other}}}).

is_timeout_opt({timeout, _}) -> true;
is_timeout_opt(_) -> false.

container_run_args(Spec) ->
  Remove   = maps:get(remove, Spec, true),
  is_boolean(Remove) orelse throw({error, {invalid_container_spec, {remove, Remove}}}),
  Base     = case Remove of true -> ["--rm"]; false -> [] end,
  EnvArgs  = container_env_args(maps:get(env, Spec, #{})),
  VolArgs  = container_volume_args(maps:get(volumes, Spec, [])),
  NetArgs  = container_network_args(maps:get(networks, Spec, [])),
  PortArgs = container_port_args(maps:get(ports, Spec, [])),
  MemArgs  = case maps:find(memory_limit, Spec) of
    {ok, MemLimit} -> ["--memory", ensure_text(memory_limit, MemLimit)];
    error          -> []
  end,
  CpuArgs = case maps:find(cpu_limit, Spec) of
    {ok, CpuLimit} -> ["--cpus", normalize_cpu_limit(CpuLimit)];
    error          -> []
  end,
  Base ++ EnvArgs ++ VolArgs ++ NetArgs ++ PortArgs ++ MemArgs ++ CpuArgs.

container_env_args(Env) when is_map(Env) ->
  container_env_args(maps:to_list(Env));
container_env_args(Env) when is_list(Env) ->
  lists:foldl(fun
    ({K, V}, Acc) ->
      Key = ensure_text(env_key, K),
      Val = ensure_text(env_value, V),
      Acc ++ ["-e", Key ++ "=" ++ Val];
    (Other, _Acc) ->
      throw({error, {invalid_container_spec, {env, Other}}})
  end, [], Env);
container_env_args(Other) ->
  throw({error, {invalid_container_spec, {env, Other}}}).

container_volume_args(Volumes) when is_list(Volumes) ->
  lists:foldl(fun
    ({Host, Container}, Acc) ->
      H = ensure_text(volume_host, Host),
      C = ensure_text(volume_container, Container),
      Acc ++ ["-v", H ++ ":" ++ C];
    ({Host, Container, Mode}, Acc) ->
      H = ensure_text(volume_host, Host),
      C = ensure_text(volume_container, Container),
      M = ensure_volume_mode(Mode),
      Acc ++ ["-v", H ++ ":" ++ C ++ ":" ++ M];
    (Other, _Acc) ->
      throw({error, {invalid_container_spec, {volumes, Other}}})
  end, [], Volumes);
container_volume_args(Other) ->
  throw({error, {invalid_container_spec, {volumes, Other}}}).

ensure_volume_mode(read_only)  -> "ro";
ensure_volume_mode(read_write) -> "rw";
ensure_volume_mode(ro)         -> "ro";
ensure_volume_mode(rw)         -> "rw";
ensure_volume_mode(Mode) when is_binary(Mode); is_list(Mode) ->
  ensure_text(volume_mode, Mode);
ensure_volume_mode(Mode) ->
  throw({error, {invalid_container_spec, {volume_mode, Mode}}}).

container_network_args(Networks) when is_list(Networks) ->
  lists:foldl(fun(Net, Acc) ->
    Acc ++ ["--network", ensure_text(network, Net)]
  end, [], Networks);
container_network_args(Other) ->
  throw({error, {invalid_container_spec, {networks, Other}}}).

container_port_args(Ports) when is_list(Ports) ->
  lists:foldl(fun(PortSpec, Acc) ->
    Acc ++ ["-p", format_port_spec(PortSpec)]
  end, [], Ports);
container_port_args(Other) ->
  throw({error, {invalid_container_spec, {ports, Other}}}).

format_port_spec(Port) when is_integer(Port), Port > 0, Port =< 65535 ->
  integer_to_list(Port);
format_port_spec({Proto, Host, Container}) when Proto =:= tcp; Proto =:= udp ->
  HostPort = ensure_port_value(host_port, Host),
  ContainerPort = ensure_port_value(container_port, Container),
  HostPort ++ ":" ++ ContainerPort ++ "/" ++ atom_to_list(Proto);
format_port_spec({Host, Container}) ->
  HostPort = ensure_port_value(host_port, Host),
  ContainerPort = ensure_port_value(container_port, Container),
  HostPort ++ ":" ++ ContainerPort;
format_port_spec({HostIp, Host, Container}) ->
  HostIpStr = ensure_text(host_ip, HostIp),
  HostPort = ensure_port_value(host_port, Host),
  ContainerPort = ensure_port_value(container_port, Container),
  HostIpStr ++ ":" ++ HostPort ++ ":" ++ ContainerPort;
format_port_spec({HostIp, Proto, Host, Container}) when Proto =:= tcp; Proto =:= udp ->
  HostIpStr = ensure_text(host_ip, HostIp),
  HostPort = ensure_port_value(host_port, Host),
  ContainerPort = ensure_port_value(container_port, Container),
  HostIpStr ++ ":" ++ HostPort ++ ":" ++ ContainerPort ++ "/" ++ atom_to_list(Proto);
format_port_spec(Other) ->
  throw({error, {invalid_container_spec, {ports, Other}}}).

ensure_port_value(_Key, Port) when is_integer(Port), Port > 0, Port =< 65535 ->
  integer_to_list(Port);
ensure_port_value(Key, Port) when is_binary(Port); is_list(Port) ->
  PortStr = ensure_text(Key, Port),
  case re:run(PortStr, "^[0-9]+$", [unicode]) of
    {match, _} ->
      case list_to_integer(PortStr) of
        N when N > 0, N =< 65535 -> PortStr;
        _ -> throw({error, {invalid_container_spec, {Key, Port}}})
      end;
    nomatch ->
      throw({error, {invalid_container_spec, {Key, Port}}})
  end;
ensure_port_value(Key, Port) ->
  throw({error, {invalid_container_spec, {Key, Port}}}).

container_command_args(Spec) ->
  Args = normalize_argv(args, maps:get(args, Spec, [])),
  case maps:find(command, Spec) of
    error ->
      Args;
    {ok, Command} when is_binary(Command) ->
      ["sh", "-lc", shell_compose(Command, Args)];
    {ok, Command} when is_list(Command) ->
      case io_lib:printable_unicode_list(Command) of
        true ->
          ["sh", "-lc", shell_compose(Command, Args)];
        false ->
          normalize_argv(command, Command) ++ Args
      end;
    {ok, Other} ->
      throw({error, {invalid_container_spec, {command, Other}}})
  end.

shell_compose(Command, []) ->
  ensure_text(command, Command);
shell_compose(Command, Args) ->
  ensure_text(command, Command) ++ " " ++ string:join([container_shell_quote(A) || A <- Args], " ").

container_shell_quote(Arg0) ->
  Arg = ensure_text(arg, Arg0),
  "'" ++ re:replace(Arg, "'", "'\\\\''", [global, {return, list}]) ++ "'".

normalize_argv(_Key, []) ->
  [];
normalize_argv(Key, Value) when is_list(Value) ->
  case io_lib:printable_unicode_list(Value) of
    true ->
      throw({error, {invalid_container_spec, {Key, Value}}});
    false ->
      [ensure_text(Key, V) || V <- Value]
  end;
normalize_argv(Key, Value) ->
  throw({error, {invalid_container_spec, {Key, Value}}}).

normalize_cpu_limit(V) ->
  S = ensure_text(cpu_limit, V),
  case re:run(S, "^([0-9]+)m$", [{capture, [1], list}]) of
    {match, [MilliStr]} ->
      format_cpu_decimal(list_to_integer(MilliStr) / 1000);
    nomatch ->
      S
  end.

format_cpu_decimal(FloatVal) ->
  Raw = lists:flatten(io_lib:format("~.6f", [FloatVal])),
  strip_trailing_zeros(Raw).

strip_trailing_zeros(Str) ->
  Rev = lists:reverse(Str),
  Rev1 = lists:dropwhile(fun(C) -> C =:= $0 end, Rev),
  Rev2 = case Rev1 of
    [$. | T] -> T;
    _ -> Rev1
  end,
  case Rev2 of
    [] -> "0";
    _ -> lists:reverse(Rev2)
  end.

select_container_runtime(auto, Finder, true) ->
  case get_cached_runtime(auto) of
    {ok, RuntimePath} -> RuntimePath;
    not_found -> select_container_runtime(auto, Finder, false)
  end;
select_container_runtime(auto, Finder, false) ->
  case find_runtime(["podman", "docker"], Finder) of
    {ok, RuntimeName, RuntimePath} ->
      maybe_cache_runtime(auto, RuntimePath, true),
      maybe_cache_runtime(RuntimeName, RuntimePath, true),
      RuntimePath;
    {error, _} -> throw({error, {container_runtime_not_found, [podman, docker]}})
  end;
select_container_runtime(podman, Finder, UseCache) ->
  require_runtime("podman", Finder, UseCache);
select_container_runtime(docker, Finder, UseCache) ->
  require_runtime("docker", Finder, UseCache);
select_container_runtime(Runtime, Finder, _UseCache) when is_binary(Runtime); is_list(Runtime) ->
  RuntimePath = ensure_text(runtime, Runtime),
  case Finder(RuntimePath) of
    false -> throw({error, {container_runtime_not_found, RuntimePath}});
    Path  -> Path
  end;
select_container_runtime(Other, _Finder, _UseCache) ->
  throw({error, {invalid_container_spec, {runtime, Other}}}).

find_runtime([], _Finder) ->
  {error, not_found};
find_runtime([H | T], Finder) ->
  case Finder(H) of
    false -> find_runtime(T, Finder);
    Path -> {ok, H, Path}
  end.

require_runtime(Name, Finder, true) ->
  case get_cached_runtime(Name) of
    {ok, RuntimePath} -> RuntimePath;
    not_found -> require_runtime(Name, Finder, false)
  end;
require_runtime(Name, Finder, false) ->
  case Finder(Name) of
    false -> throw({error, {container_runtime_not_found, Name}});
    Path  ->
      maybe_cache_runtime(Name, Path, true),
      Path
  end.

maybe_cache_runtime(_Name, _Path, false) ->
  ok;
maybe_cache_runtime(Name, Path, true) ->
  Cache0 = persistent_term:get(?CONTAINER_RUNTIME_CACHE_KEY, #{}),
  Cache1 = Cache0#{Name => Path},
  persistent_term:put(?CONTAINER_RUNTIME_CACHE_KEY, Cache1),
  ok.

get_cached_runtime(Name) ->
  Cache = persistent_term:get(?CONTAINER_RUNTIME_CACHE_KEY, #{}),
  case maps:get(Name, Cache, undefined) of
    undefined ->
      not_found;
    Path when is_list(Path) ->
      case filelib:is_file(Path) of
        true -> {ok, Path};
        false ->
          evict_cached_runtime(Name),
          not_found
      end
  end.

evict_cached_runtime(Name) ->
  Cache0 = persistent_term:get(?CONTAINER_RUNTIME_CACHE_KEY, #{}),
  Cache1 = maps:remove(Name, Cache0),
  persistent_term:put(?CONTAINER_RUNTIME_CACHE_KEY, Cache1),
  ok.

ensure_text(_Key, V) when is_binary(V) ->
  unicode:characters_to_list(V);
ensure_text(_Key, V) when is_list(V) ->
  V;
ensure_text(_Key, V) when is_integer(V) ->
  integer_to_list(V);
ensure_text(_Key, V) when is_float(V) ->
  lists:flatten(io_lib:format("~p", [V]));
ensure_text(Key, V) ->
  throw({error, {invalid_container_spec, {Key, V}}}).
