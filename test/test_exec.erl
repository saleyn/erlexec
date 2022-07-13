%%%-------------------------------------------------------------------
%%% @author Serge Aleynikov
%%% @see https://github.com/saleyn/erlexec/issues/90
%%%-------------------------------------------------------------------
-module(test_exec).

-behaviour(gen_server).

-export([run/0, run/1, run/2, run/3, stats/0]).
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SCRIPT, "/tmp/test_script.sh").

-record(state, {
    owner       :: pid(),
    delay       :: integer(),
    count       :: integer(),
    active  = 0 :: integer(),
    success = 0 :: integer(),
    ios     = 0 :: integer(),
    fderr   = 0 :: integer(),
    cmd         :: binary(),
    pids        :: sets:set()
}).


%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
run() ->
    run(1000).

run(Count) ->
    run(Count, 30000).

run(Count, Timeout) ->
    run(Count, Timeout, 1000).

run(0, _Timeout, _DelayMS) ->
  {ok,[{io_ops,0},{success,0}]};
run(Count, Timeout, DelayMS) when is_integer(Count), is_integer(Timeout), is_integer(DelayMS) ->
    %application:ensure_started(erlexec),
    io:format(standard_error, "\n==> Test Concurrency: ~w\n", [Count]),
    {ok, Pid} = gen_server:start_link({local, ?MODULE}, ?MODULE, [self(),Count,DelayMS], []),
    receive
        {completed, Pid, IOs, Success, 0} when IOs =:= Success*2 ->
            {ok, [{io_ops, IOs}, {success, Success}]};
        {completed, Pid, IOs, Success, FdErr} when FdErr > 0 ->
            {error, hit_limit_of_max_open_files, [{io_ops, IOs}, {success, Success}, {fd_err, FdErr}]};
        {completed, Pid, IOs, Success, FdErr} ->
            {error, wrong_num_of_ios, [{io_ops, IOs}, {success, Success}, {fd_err, FdErr}]}
    after Timeout ->
        timeout
    end.

stats() ->
    State = sys:get_state(?MODULE),
    [{count,  State#state.count},
     {active, State#state.active},
     {ios,    State#state.ios}].

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Owner, Count, DelayMS]) ->
    process_flag(trap_exit, true),
    Delay = integer_to_binary(DelayMS),
    Cmd   = <<"echo \"Test stdout $$\"; echo \"Test stderr $$\" 1>&2; "
              "sleep $[ ((($RANDOM % ", Delay/binary, ") + 1)/1000) ]; "
              "exit 12\n">>,
    self() ! start_child,
    {ok, #state{owner=Owner, delay=DelayMS, count=Count, cmd=Cmd, pids=sets:new()}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(Msg, _From, State) ->
    {stop, {unhandled_call, Msg}, badarg, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(Msg, State) ->
    {stop, {unknown_cast, Msg}, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(start_child, #state{count=Count, active=Active, cmd=Cmd, fderr=Err, pids=Pids} = State0) ->
    {I, State} =
        case exec:run(Cmd, [stdout, stderr, monitor]) of
            {ok, _Pid, OsPid} ->
                {10, State0#state{count=Count-1, active=Active+1, pids = sets:add_element(OsPid, Pids)}};
            {error, "Couldn't start pid: Failed to create a pipe for stdout: Too many open files"} ->
                {0, State0#state{count=Count-1, fderr=Err+1}};
            {error, "Couldn't start pid: Failed to create a pipe for stderr: Too many open files"} ->
                {0, State0#state{count=Count-1, fderr=Err+1}}
        end,
    State#state.count > 0 andalso
        erlang:send_after(I, self(), start_child),
    {noreply, State};
            

handle_info({stdout, _OsPid, <<"Test stdout ", _Rest/binary>>}, State) ->
    {noreply, State#state{ios = State#state.ios + 1}};
handle_info({stderr, _OsPid, <<"Test stderr ", _Rest/binary>>}, State) ->
    {noreply, State#state{ios = State#state.ios + 1}};

handle_info({'DOWN', OsPid, process, _Pid, {exit_status, ExitStatus}}, #state{pids = Pids, success=N} = State) ->
    case sets:is_element(OsPid, Pids) of
        true ->
            Active   = State#state.active - 1,
            FdErr    = State#state.fderr,
            Success  = case exec:status(ExitStatus) of {status, 12} -> N+1; _ -> N end,
            NewPids  = sets:del_element(OsPid, Pids),
            NewState = State#state{pids=NewPids, active=Active, success=Success},
            case {Active, State#state.count} of
                {0, 0} ->
                    State#state.owner ! {completed, self(), State#state.ios, Success, FdErr},
                    {stop, normal, NewState};
                _ ->
                    {noreply, NewState}
            end;
        false ->
            io:format("DOWN from unmanaged pid ~w: ~p\n", [OsPid, ExitStatus]),
            {noreply, State}
    end;

handle_info(_Msg, State) ->
    io:format("Unhandled message: ~p\n", [_Msg]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
