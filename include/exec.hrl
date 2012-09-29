-define(SIGHUP,   -1).
-define(SIGINT,   -2).
-define(SIGKILL,  -9).
-define(SIGTERM, -15).
-define(SIGUSR1, -10).
-define(SIGUSR2, -12).

-define(FMT(Fmt, Args), lists:flatten(io_lib:format(Fmt, Args))).
