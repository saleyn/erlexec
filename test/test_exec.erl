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

-define(SERVER, ?MODULE).
-define(SCRIPT, "/tmp/test_script.sh").

-record(state, {
    owner       :: pid(),
    delay       :: integer(),
    count       :: integer(),
    active  = 0 :: integer(),
    success = 0 :: integer(),
    ios     = 0 :: integer(),
    pids        :: sets:set()
}).


%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
run() ->
    run(1000).

run(Count) ->
    run(Count, 25000).

run(Count, Timeout) ->
    run(Count, Timeout, 1).

run(Count, Timeout, DelayMS) when is_integer(Count), is_integer(Timeout), is_integer(DelayMS) ->
    ok = application:ensure_started(erlexec),
    {ok, Pid} = gen_server:start_link({local,?SERVER}, ?MODULE, [self(),Count,DelayMS], []),
    receive
        {completed, Pid, IOs, Success} ->
            {ok, [{io_ops, IOs}, {success, Success}]}
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
    ok = file:write_file(?SCRIPT,
        <<"#!/bin/bash\n"
          "echo 'This is a test script $$'\n"
          "sleep $[ ( $RANDOM % ", Delay/binary, " ) + 1 ]s\n"
          "exit 12\n">>),
    file:change_mode(?SCRIPT, 8#755),
    self() ! start_child,
    {ok, #state{owner=Owner, delay=DelayMS, count=Count, pids = sets:new()}}.

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
handle_info(start_child, #state{count=Count, active=Active, pids = Pids} = State0) ->
    {ok, _Pid, OsPid} = exec:run(?SCRIPT, [stdout, stderr, monitor]),
    State = State0#state{count=Count-1, active=Active+1, pids = sets:add_element(OsPid, Pids)},
    State#state.count > 0 andalso
        erlang:send_after(10, self(), start_child),
    {noreply, State};

handle_info({Channel, _OsPid, _Data}, State) when Channel == stdout;
                                                  Channel == stderr ->
    {noreply, State#state{ios = State#state.ios + 1}};

handle_info({'DOWN', OsPid, process, _Pid, {exit_status, ExitStatus}}, #state{pids = Pids, success=N} = State) ->
    case sets:is_element(OsPid, Pids) of
        true ->
            Active   = State#state.active - 1,
            Success  = case exec:status(ExitStatus) of {status, 12} -> N+1; _ -> N end,
            NewPids  = sets:del_element(OsPid, Pids),
            NewState = State#state{pids=NewPids, active=Active, success=Success},
            case {Active, State#state.count} of
                {0, 0} ->
                    State#state.owner ! {completed, self(), State#state.ios, Success},
                    {stop, normal, NewState};
                _ ->
                    {noreply, NewState}
            end;
        false ->
            io:format("DOWN from unmanaged pid ~w: ~p\n", [OsPid, ExitStatus]),
            {noreply, State}
    end;

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    file:delete(?SCRIPT),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
