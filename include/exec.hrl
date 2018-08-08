-define(SIGHUP,   -1).
-define(SIGINT,   -2).
-define(SIGKILL,  -9).
-define(SIGTERM, -15).
-define(SIGUSR1, -10).
-define(SIGUSR2, -12).

-define(FMT(Fmt, Args), lists:flatten(io_lib:format(Fmt, Args))).

%% compatibility
-ifdef(OTP_RELEASE). %% this implies 21 or higher
-define(EXCEPTION(Class, Reason, Stacktrace), Class:Reason:Stacktrace).
-define(GET_STACK(Stacktrace), Stacktrace).
-else.
-define(EXCEPTION(Class, Reason, _), Class:Reason).
-define(GET_STACK(_), erlang:get_stacktrace()).
-endif.
