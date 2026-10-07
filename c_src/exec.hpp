// vim:ts=2:sw=2:et
/*
Author: Serge Aleynikov
Date:   2016-11-14
*/
#pragma once

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#ifdef HAVE_CAP
#include <sys/prctl.h>
#include <sys/capability.h>
#include <unordered_map>
#include <set>
#endif

enum class FdType {
  COMMAND,
  SIGCHILD,
  CHILD_PROC
};

#if defined(USE_POLL) && USE_POLL > 0
#include "poll_handler.hpp"
#else
#include "select_handler.hpp"
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <map>
#include <list>
#include <deque>
#include <set>
#include <optional>
#include <sstream>

#if defined(USE_POLL) && USE_POLL > 0
#include <vector>
#endif

#if defined(__CYGWIN__) || defined(__WIN32) || defined(__APPLE__) \
   || (defined(__sun) && defined(__SVR4))
#  define NO_SIGTIMEDWAIT
#  define sigtimedwait(a, b, c) 0
#  define sigisemptyset(s) \
  !(sigismember(s, SIGCHLD) || sigismember(s, SIGPIPE) || \
    sigismember(s, SIGTERM) || sigismember(s, SIGINT) || \
    sigismember(s, SIGHUP))
#endif

#if __OpenBSD__ || __APPLE__ || (__NetBSD__ && __NetBSD_Version__ < 600000000)
#   include <sys/event.h>
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define SRCLOC " [" __FILE__ ":" STR(__LINE__) "]"

#define DEBUG(Cond, Fmt, ...) \
  do { \
    if (Cond) \
      fprintf(stderr, Fmt SRCLOC "\r\n", ##__VA_ARGS__); \
  } while(0)

#include <ei.h>
#include "ei++.hpp"

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------
extern char **environ; // process environment
//-------------------------------------------------------------------------

namespace ei {

//-------------------------------------------------------------------------
// Enums and constants
//-------------------------------------------------------------------------

enum ConstsT {
  // Default file permissions
  DEF_MODE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,

  // Default read/write buffer
  BUF_SIZE                = 2048,

  // In the event we have tried to kill something, wait this many
  // seconds and then *really* kill it with SIGKILL if needs be
  KILL_TIMEOUT_SEC        = 5,

  // Max number of seconds to sleep in the select() call
  SLEEP_TIMEOUT_SEC       = 5,

  // Number of seconds allowed for cleanup before exit
  FINALIZE_DEADLINE_SEC   = 10,

  SIGCHLD_MAX_SIZE        = 4096
};

enum RedirectType {
  REDIRECT_STDOUT = -1,   // Redirect to stdout
  REDIRECT_STDERR = -2,   // Redirect to stderr
  REDIRECT_NONE   = -3,   // No output redirection
  REDIRECT_CLOSE  = -4,   // Close output file descriptor
  REDIRECT_ERL    = -5,   // Redirect output back to Erlang
  REDIRECT_FILE   = -6,   // Redirect output to file
  REDIRECT_NULL   = -7    // Redirect input/output to /dev/null
};

enum FileOpenFlag {
  READ     = 0,
  APPEND   = O_APPEND,
  TRUNCATE = O_TRUNC
};

//-------------------------------------------------------------------------
// Forward declarations
//-------------------------------------------------------------------------
struct CmdInfo;
class  CmdOptions;

//-------------------------------------------------------------------------
// Types
//-------------------------------------------------------------------------

typedef unsigned char byte;
typedef int   exit_status_t;
typedef pid_t kill_cmd_pid_t;
typedef std::list<std::string>                  CmdArgsList;
typedef std::pair<pid_t, exit_status_t>         PidStatusT;
typedef std::pair<pid_t, CmdInfo>               PidInfoT;
typedef std::map <pid_t, CmdInfo>               MapChildrenT;
typedef std::pair<kill_cmd_pid_t, pid_t>        KillPidStatusT;
typedef std::pair<pid_t, ei::TimeVal>           KillPidInfoT;
typedef std::map <kill_cmd_pid_t, KillPidInfoT> MapKillPidT;
typedef std::map<std::string, std::optional<std::string>> MapEnv;
typedef MapEnv::iterator                        MapEnvIterator;
typedef std::map<std::string, int>              MapPtyOpt;
typedef std::map<pid_t, exit_status_t>          ExitedChildrenT;

static const char* CS_DEV_NULL  = "/dev/null";

//-------------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------------
extern int             debug;
extern int             alarm_max_time;
extern int             dev_null;
extern bool            pipe_valid;
extern bool            terminated;
extern int             max_fds;
extern int             sigchld_pipe[2];
extern Serializer      eis;
extern MapChildrenT    children;       // Map containing all managed processes started by this port program.
extern MapKillPidT     transient_pids; // Map of pids of custom kill commands.
extern ExitedChildrenT exited_children;// Set of processed SIGCHLD events
extern pid_t           self_pid;
extern sigset_t        sigchld_mask;   // Signal mask for SIGCHLD synchronization

/// Convert file descriptor to a meaningful string
std::string fd_type(int tp);

//-------------------------------------------------------------------------
// Graph Execution Plan Structures
//-------------------------------------------------------------------------
struct GraphFileDestination {
  std::string path;
  bool append = false;      // "append" atom
  int  mode   = DEF_MODE;   // {mode, Value} tuple
};

struct GraphTaskDestination {
  enum class Type { TASK, SINK };

  // For TASK: sibling task id, used to look up its stdin pipe fd.
  // For SINK: informational only (debug/logging) — all sinks fan out to the
  // same Erlang-facing fd; resolving the delivery target (self/Pid/Fun) is
  // done in Erlang's deliver_sink/5, not here.
  std::string id;
  Type type;
};

struct GraphStreamRedirect {
  enum class Type {
    EXPOSED,      // no destinations
    PURE_FILE,    // [{file, Path, [Options]}, ...]
    PURE_TASK,    // [{task, TaskId}, {sink, SinkId}, ...]
    MIXED         // both files and tasks
  } type;
  std::vector<GraphFileDestination> files;
  std::vector<GraphTaskDestination> tasks;
};

struct GraphTaskPlan {
  std::string id;
  GraphStreamRedirect stdout_redirect;
  GraphStreamRedirect stderr_redirect;
};

struct GraphIOPlan {
  std::vector<GraphTaskPlan> tasks;
  // Note: sink delivery targets (self/Pid/{'fun', Fun}) are resolved entirely
  // in Erlang (exec_graph:deliver_sink/5) and never decoded here. C++ only
  // needs to know *that* a stream has a sink destination (to include the
  // Erlang-facing fd in its fanout set), not *who* receives it.
};

//-------------------------------------------------------------------------
// Structs
//-------------------------------------------------------------------------
class CmdOptions {
  using StrSet          = std::set<std::string>;
  using StrMap          = std::map<std::string, std::string>;
  using StrIntVec       = std::vector<std::pair<std::string, int>>;
  using GraphFileVec    = std::vector<GraphFileDestination>;

  ei::StringBuffer<256>   m_tmp;
  std::stringstream       m_err;
  bool                    m_shell = true;
  bool                    m_pty = false;
  bool                    m_pty_echo = false;
  MapPtyOpt               m_pty_opts;
  std::string             m_executable;
  CmdArgsList             m_cmd;
  std::string             m_cd;
  std::string             m_kill_cmd;
  int                     m_kill_timeout = KILL_TIMEOUT_SEC;
  int                     m_timeout_ms = -1; // wall-clock watchdog: kill if still running after
                                              // this many ms since spawn; -1 = disabled. Distinct
                                              // from m_kill_timeout, which only governs the
                                              // SIGTERM->SIGKILL escalation *after* a stop/kill
                                              // was already requested.
  bool                    m_want_stats = false; // deliver {stats, OsPid, StatsMap} (rusage +
                                              // wall time) to the owner just before the final
                                              // exit notification.
  bool                    m_kill_group = false;
  bool                    m_graph_group = false; // kill group on *abnormal* exit only (graph pipelines)
  bool                    m_is_kill_cmd; // true if this represents a custom kill command
  MapEnv                  m_env;
  const char**            m_cenv = NULL;
  bool                    m_env_clear = false;
  long                    m_nice;     // niceness level
  int                     m_group;    // used in setgid()
  int                     m_user;     // run as
  std::string             m_cgroup;
  bool                    m_cgroup_create = false;
  bool                    m_cgroup_clear = false;
  StrMap                  m_cgroup_limits;
  int                     m_success_exit_code = 0;
  std::string             m_std_stream[3];
  bool                    m_std_stream_append[3];
  int                     m_std_stream_fd[3];
  int                     m_std_stream_mode[3];
  // Multi-destination file fanout (e.g. {stdout_files, [{Path, [Options]}, ...]}).
  // Index 0 (stdin) unused. m_std_stream_extra_files is the requested spec (pre-spawn);
  // m_std_stream_extra_fds is populated by start_child() with the opened fds, in the
  // same order, for the RUN case in exec.cpp to thread into CmdInfo.
  GraphFileVec            m_std_stream_extra_files[3];
  std::vector<int>        m_std_stream_extra_fds[3];
  bool                    m_fanout_forced[3] = {false, false, false};  // For each stream,
                          // true if we forced a pipe into existence for fanout purposes,
                          // but the user did NOT explicitly request that stream (e.g.,
                          // stdout_files without stdout). Passed to CmdInfo so that
                          // process_pid_output knows not to send data to Erlang.
  // Sibling-to-sibling piping (graph tasks only; see exec_graph:allocate_sibling_pipes/1).
  // m_sibling_stdin_writes[3]: per-stream (index 0/stdin unused), write-ends of downstream
  // siblings' stdin pipes that this task's stdout/stderr should be fanned out to (consumer
  // id is informational, only the fd is used). These get folded into
  // m_std_stream_extra_fds[i] at spawn time (start_child), so process_pid_output's existing
  // fanout loop handles them with zero extra code.
  StrIntVec               m_sibling_stdin_writes[3];
  // m_stdin_from_sibling: read-end of this task's own stdin pipe, already connected to an
  // upstream sibling's fanout list by Erlang. When >= 0, start_child uses this fd directly
  // instead of creating a new REDIRECT_ERL pipe for stdin.
  int                     m_stdin_from_sibling = -1;
  int                     m_debug = 0;
  int                     m_winsz_rows;
  int                     m_winsz_cols;
  #ifdef HAVE_CAP
  bool                    m_caps_all; // Inherit all capabilities
  std::set<cap_value_t>   m_caps;
  #endif

  std::optional<GraphIOPlan>  m_graph_plan;  // I/O routing plan for graph execution (if present)

  void init_streams() {
    for (int i=STDIN_FILENO; i <= STDERR_FILENO; i++) {
      m_std_stream_append[i] = false;
      m_std_stream_mode[i]   = DEF_MODE;
      m_std_stream_fd[i]     = REDIRECT_NULL;
      m_std_stream[i]        = CS_DEV_NULL;
      m_std_stream_extra_files[i].clear();
      m_std_stream_extra_fds[i].clear();
      m_fanout_forced[i] = false;
    }
  }

public:
  explicit CmdOptions(int def_user=std::numeric_limits<int>::max())
    : m_tmp(0, 256)
    , m_is_kill_cmd(false)
    , m_nice(std::numeric_limits<int>::max())
    , m_group(std::numeric_limits<int>::max()), m_user(def_user)
    #ifdef HAVE_CAP
    , m_caps_all(false)
    #endif
  {
    init_streams();
  }
  CmdOptions(const CmdArgsList& cmd, const char* cd, const MapEnv& env,
         int user, int nice, int group, bool is_kill_cmd)
    : m_cmd(cmd), m_cd(cd ? cd : "")
    , m_is_kill_cmd(is_kill_cmd)
    , m_env(env)
    , m_nice(nice)
    , m_group(group), m_user(user)
    #ifdef HAVE_CAP
    , m_caps_all(false)
    #endif
  {
    init_streams();
  }

  // prevent copying
  CmdOptions(const CmdOptions&) = delete;
  CmdOptions& operator=(const CmdOptions&) = delete;

  ~CmdOptions() {
    // Fix memory management - check if m_cenv was allocated with new[]
    // and use proper deallocation method
    if (m_cenv && m_cenv != (const char**)environ)
      free((void*)m_cenv);  // Use free() since it's allocated with malloc() family
    m_cenv = NULL;
  }

  std::string          error()        const { return m_err.str();  }
  const std::string&   executable()   const { return m_executable; }
  const CmdArgsList&   cmd()          const { return m_cmd;        }
  bool                 shell()        const { return m_shell;      }
  bool                 pty()          const { return m_pty;        }
  bool                 pty_owns_group() const {
    return m_pty && (m_group == std::numeric_limits<int>::max() || m_group == 0);
  }
  bool                 pty_echo()     const { return m_pty_echo;   }
  MapPtyOpt const&     pty_opts()     const { return m_pty_opts;   }
  std::tuple<int, int> winsz()        const { return std::make_tuple(m_winsz_rows, m_winsz_cols); }
  const char*   cd()                  const { return m_cd.c_str();            }
  MapEnv const& mapenv()              const { return m_env;                   }
  char* const*  env()                 const { return (char* const*)m_cenv;    }
  int           dbg()                 const { return m_debug;                 }
  const char*   kill_cmd()            const { return m_kill_cmd.c_str();      }
  int           kill_timeout()        const { return m_kill_timeout;          }
  int           timeout_ms()          const { return m_timeout_ms;            }
  bool          want_stats()          const { return m_want_stats;            }
  bool          kill_group()          const { return m_kill_group;            }
  bool          graph_group()         const { return m_graph_group;           }
  bool          is_kill_cmd()         const { return m_is_kill_cmd;           }
  int           group()               const { return m_group;                 }
  int           user()                const { return m_user;                  }
  const std::string& cgroup()         const { return m_cgroup;                }
  bool          cgroup_create()       const { return m_cgroup_create;         }
  bool          cgroup_clear()        const { return m_cgroup_clear;          }
  const StrMap& cgroup_limits()       const { return m_cgroup_limits;         }
  int           success_exit_code()   const { return m_success_exit_code;     }
  int           nice()                const { return m_nice;                  }
  const char*   stream_file(int i)    const { return m_std_stream[i].c_str(); }
  bool          stream_append(int i)  const { return m_std_stream_append[i];  }
  int           stream_mode(int i)    const { return m_std_stream_mode[i];    }
  int           stream_fd(int i)      const { return m_std_stream_fd[i];      }
  int&          stream_fd(int i)            { return m_std_stream_fd[i];      }
  std::string   stream_fd_type(int i) const { return fd_type(stream_fd(i));   }

  // Multi-destination file fanout (stdout_files/stderr_files option).
  const std::vector<GraphFileDestination>& stream_extra_files(int i) const {
    return m_std_stream_extra_files[i];
  }
  void add_stream_extra_file(int i, const std::string& path, bool append = false, int mode = DEF_MODE) {
    m_std_stream_extra_files[i].push_back(GraphFileDestination{path, append, mode});
  }
  // Opened fds (populated by start_child(), same order as stream_extra_files(i));
  // read back by the RUN case in exec.cpp to thread into CmdInfo::fanout_fds.
  const std::vector<int>& opened_fanout_fds(int i) const { return m_std_stream_extra_fds[i]; }
  void add_opened_fanout_fd(int i, int fd) { m_std_stream_extra_fds[i].push_back(fd); }

  // Flag: for each stream, true if we forced a pipe for fanout purposes only
  // (user didn't explicitly request that stream, so don't send to Erlang).
  bool fanout_forced(int i) const { return m_fanout_forced[i]; }
  void set_fanout_forced(int i, bool forced) { m_fanout_forced[i] = forced; }

  // Sibling-to-sibling piping (graph tasks only). i is STDOUT_FILENO or STDERR_FILENO.
  const std::vector<std::pair<std::string, int>>& sibling_stdin_writes(int i) const {
    return m_sibling_stdin_writes[i];
  }
  void add_sibling_stdin_write(int i, const std::string& consumer_id, int write_fd) {
    m_sibling_stdin_writes[i].emplace_back(consumer_id, write_fd);
  }
  int  stdin_from_sibling() const { return m_stdin_from_sibling; }
  void stdin_from_sibling(int fd) { m_stdin_from_sibling = fd; }

  #ifdef HAVE_CAP
  bool                         caps_all() const { return m_caps_all; }
  std::set<cap_value_t> const& caps()     const { return m_caps;     }
  bool                         has_caps() const { return m_caps_all || m_caps.size() > 0; }
  std::string                  caps_to_string() const;

  bool has_cap(cap_value_t v) const { return m_caps_all || m_caps.find(v) != m_caps.end(); }
  #endif

  const std::optional<GraphIOPlan>& graph_plan() const { return m_graph_plan; }
  void graph_plan(const GraphIOPlan& plan) { m_graph_plan = plan; }

  void executable(const std::string& s) { m_executable = s; }

  void stream_file(int i, const std::string& file, bool append = false, int mode = DEF_MODE) {
    m_std_stream_fd[i]      = REDIRECT_FILE;
    m_std_stream_append[i]  = append;
    m_std_stream_mode[i]    = mode;
    m_std_stream[i]         = file;
  }

  void stream_null(int i) {
    m_std_stream_fd[i]      = REDIRECT_NULL;
    m_std_stream_append[i]  = false;
    m_std_stream[i]         = CS_DEV_NULL;
  }

  void stream_redirect(int i, RedirectType type) {
    m_std_stream_fd[i]      = type;
    m_std_stream_append[i]  = false;
    m_std_stream[i].clear();
  }

  // @param getcmd  - when managing existing PID, pass "false", otherwise "true"
  int ei_decode(bool getcmd);
  int init_cenv();
};

//-------------------------------------------------------------------------
/// Contains run-time info of a child OS process.
/// When a user provides a custom command to kill a process this
/// structure will contain its run-time information.
//-------------------------------------------------------------------------
struct CmdInfo {
  using Queue = std::list<std::string>;

  CmdArgsList     cmd;                // Executed command
  pid_t           cmd_pid;            // Pid of the custom kill command
  pid_t           cmd_gid;            // Command's group ID
  std::string     kill_cmd;           // Kill command to use (default: use SIGTERM)
  kill_cmd_pid_t  kill_cmd_pid   = -1;// Pid of the command that <pid> is supposed to kill
  ei::TimeVal     deadline;           // Time when the <cmd_pid> is supposed to be killed using SIGTERM.
  bool            sigterm = false;    // <true> if sigterm was issued.
  bool            sigkill = false;    // <true> if sigkill was issued.
  bool            timed_out = false;  // <true> if the kill was triggered by the {timeout, Ms}
                                       // watchdog (run_deadline), as opposed to an explicit
                                       // exec:stop/1 or exec:kill/2 request. Used to avoid the
                                       // exit-status-override-to-0 logic below (meant for
                                       // explicit user-requested stops) misreporting a timeout
                                       // kill as a normal/clean exit.
  int             kill_timeout;       // Pid shutdown interval in sec before it's killed with SIGKILL
  bool            kill_group;         // Indicates if at exit (any exit) the whole group needs to be killed
  bool            graph_group = false;// Indicates this pid is part of a graph's process group:
                                       // on *abnormal* exit only (signaled, or non-zero exit code),
                                       // kill the rest of the group. Unlike kill_group, does NOT
                                       // fire on normal (zero-exit-code) completion -- a graph
                                       // pipeline's early stages are expected to finish before
                                       // later ones.
  int             success_code;       // Exit code to use on success
  bool            managed;            // <true> if this pid is started externally, but managed by erlexec
  int             stream_fd[3];       // Pipe fd getting   process's stdin/stdout/stderr
  std::vector<int> fanout_fds[3];     // Extra destination fds for stdout/stderr fanout (index 0 unused).
                                       // Opened at spawn time, written on every chunk alongside
                                       // stream_fd (via ei::tee_buffer_to_many), closed once at reap.
                                       // Independent of stream_fd's EOF/REDIRECT_CLOSE lifecycle.
  bool            fanout_forced[3] = {false, false, false};  // For each stream, true if we
                                       // forced a pipe into existence for fanout purposes, but the user
                                       // did NOT explicitly request that stream (e.g., stdout_files without stdout).
                                       // When true, don't send data to Erlang via send_ospid_output.
  ei::TimeVal     run_deadline;       // Wall-clock watchdog deadline (zero = disabled). Set once
                                       // at spawn time from the {timeout, Ms} option; independent
                                       // of `deadline` above, which only tracks the post-stop
                                       // SIGTERM->SIGKILL escalation window.
  bool            want_stats = false; // Deliver {stats, OsPid, StatsMap} to the owner just
                                       // before the final exit notification.
  ei::TimeVal     start_time;         // Spawn time; used to compute wall-clock duration for
                                       // the stats message regardless of rusage portability.
  struct rusage   last_rusage{};      // Captured at reap time via wait4() when available and
                                       // want_stats is set; see HAVE_WAIT4 in exec_impl.cpp.
  bool            have_rusage = false;// True if last_rusage was actually populated (wait4()
                                       // succeeded on a platform that has it).
  int             stdin_wr_pos   = 0; // Offset of the unwritten portion of the head item of stdin_queue
  int             dbg            = 0; // Debug flag
  Queue           stdin_queue;
  bool            eof_arrived    = false;
#if defined(USE_POLL) && USE_POLL  > 0
  int             poll_fd_idx[3] = {-1,-1,-1}; // Indexes to the pollfd structure in the poll array
#endif

  // delete default constructor, copy-ctor and assignment operator
  CmdInfo() = delete;
  CmdInfo(const CmdInfo&) = delete;
  CmdInfo& operator=(const CmdInfo&) = delete;

  // enable default move constructor to be able to put it into a map via emplace
  CmdInfo(CmdInfo&& ci) = default;

  CmdInfo(bool _managed, const char* _kill_cmd, pid_t _cmd_pid, int _ok_code,
      bool _kill_group, int _debug, int _kill_timeout, bool _graph_group = false)
    : CmdInfo(cmd, _kill_cmd, _cmd_pid, getpgid(_cmd_pid), _ok_code, _managed,
          REDIRECT_NULL, REDIRECT_NONE, REDIRECT_NONE, _kill_timeout,
          _kill_group, _debug, _graph_group)
  {}

  CmdInfo(const CmdArgsList& _cmd, const char* _kill_cmd, pid_t _cmd_pid, pid_t _cmd_gid,
      int _success_code, bool _managed, int _stdin_fd, int _stdout_fd, int _stderr_fd,
      int _kill_timeout, bool _kill_group, int _debug, bool _graph_group = false,
      std::vector<int> _stdout_fanout_fds = {}, std::vector<int> _stderr_fanout_fds = {},
      bool _stdout_forced_for_fanout = false, bool _stderr_forced_for_fanout = false,
      int _timeout_ms = -1, bool _want_stats = false)
    : cmd(_cmd)
    , cmd_pid(_cmd_pid)
    , cmd_gid(_cmd_gid)
    , kill_cmd(_kill_cmd)
    , kill_timeout(_kill_timeout)
    , kill_group(_kill_group)
    , graph_group(_graph_group)
    , success_code(_success_code)
    , managed(_managed)
    , want_stats(_want_stats)
    , dbg(_debug)
  {
    stream_fd[STDIN_FILENO]      = _stdin_fd;
    stream_fd[STDOUT_FILENO]     = _stdout_fd;
    stream_fd[STDERR_FILENO]     = _stderr_fd;
    fanout_fds[STDOUT_FILENO]    = std::move(_stdout_fanout_fds);
    fanout_fds[STDERR_FILENO]    = std::move(_stderr_fanout_fds);
    fanout_forced[STDOUT_FILENO] = _stdout_forced_for_fanout;
    fanout_forced[STDERR_FILENO] = _stderr_forced_for_fanout;
    start_time.now();
    if (_timeout_ms >= 0)
      run_deadline.set(start_time, _timeout_ms/1000, (_timeout_ms%1000)*1000);
  }

  void include_stream_fd(FdHandler &fdhandler);
  void process_stream_data(FdHandler &fdhandler);
};

#ifdef HAVE_CAP
struct Caps {
  Caps() : m_caps(cap_get_proc()) {}
  ~Caps() { if (m_caps) cap_free(m_caps); }

  bool         valid() const          { return !!m_caps;           }
  cap_t        value()                { return m_caps;             }
  void         add(cap_value_t cap)   { m_cap_list.push_back(cap); }
  cap_value_t* list()                 { return m_cap_list.data();  }
  size_t       size() const           { return m_cap_list.size();  }

  static const std::string& value_to_string(cap_value_t v) {
    static const std::string s_empty;
    auto   it =  s_cap_i2s.find(v);
    return it == s_cap_i2s.end() ? s_empty : it->second;
  }

  static const cap_value_t string_to_value(const std::string& cap) {
    auto   it =  s_cap_s2i.find(cap);
    return it == s_cap_s2i.end() ? -1 : it->second;
  }

  std::string to_string() {
    std::string s;
    for (auto c : m_cap_list) {
      if (s.length() > 0) s += "|";
      s += value_to_string(c);
    }
    return s;
  }

  static void init_maps() {
    for (cap_value_t i = 0; i < TOTAL_CAP_COUNT; ++i) {
      s_cap_s2i.emplace(std::make_pair(s_cap_name[i], i));
      s_cap_i2s.emplace(std::make_pair(i, s_cap_name[i]));
    }
  }

  // In case on some platform the last capability name is less than CAP_BLOCK_SUSPEND,
  // use that max cap name. If it is greater than, we'd need to add them to the list above.
  static constexpr const int TOTAL_CAP_COUNT = (CAP_LAST_CAP < CAP_CHECKPOINT_RESTORE ? CAP_LAST_CAP : CAP_CHECKPOINT_RESTORE) + 1;

private:
  std::vector<cap_value_t> m_cap_list;
  cap_t m_caps;

  // Placeholder for decoding capability names passed in the "run child" command
  // awk '/^#define +CAP_LAST_CAP/{exit} /^#define +CAP_.*/{gsub("CAP_", "", $2); printf("\"%-20s // %d\n", tolower($2)",", $3)}' /usr/include/linux/capability.h
  //
  static const char* s_cap_name[];

  static std::unordered_map<std::string, cap_value_t> s_cap_s2i;
  static std::unordered_map<cap_value_t, std::string> s_cap_i2s;
};

#if CAP_LAST_CAP > CAP_CHECKPOINT_RESTORE
#warning Capability names above CAP_BLOCK_SUSPEND are not supported!
#endif

#endif

//-------------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------------

/// Symbolic name of stdin/stdout/stderr fd stream
const char* stream_name(int i);

int     read_sigchld(pid_t& child);
void    check_child_exit(pid_t pid);
int     set_euid(int userid);
int     set_nice(pid_t pid,int nice, std::string& error);
bool    process_sigchld();
bool    set_pid_winsz(CmdInfo& ci, int rows, int cols);
bool    set_pty_opt(struct termios* tio, const std::string& key, int value);
bool    set_cloexec_flag(int fd, bool value);
bool    process_pid_input(CmdInfo& ci);
void    process_pid_output(CmdInfo& ci, int stream_id, int maxsize = 4096);
int     send_ok(int transId, long value = -1);
int     send_pid(int transId, pid_t pid);
int     send_pid_status_term(const PidStatusT& stat);
int     send_pid_stats_term(pid_t pid, int64_t wall_ms, bool have_rusage, const struct rusage& ru);
int     send_error_str(int transId, bool asAtom, const char* fmt, ...);
int     send_pid_list(int transId, const MapChildrenT& children);
int     send_ospid_output(int pid, const char* type, const char* data, int len);

pid_t   start_child(CmdOptions& op, std::string& err);
int     kill_child(pid_t pid, int sig, int transId, bool notify=true);
int     check_children(const TimeVal& now, bool& isTerminated, bool notify = true);
void    check_child(const TimeVal& now, pid_t pid, CmdInfo& cmd);
void    close_stdin(CmdInfo& ci);
void    stop_child(pid_t pid, int transId, const TimeVal& now);
int     stop_child(CmdInfo& ci, int transId, const TimeVal& now, bool notify = true);
void    erase_child(MapChildrenT::iterator& it);

int     set_nonblock_flag(pid_t pid, int fd, bool value);
int     erl_exec_kill(pid_t pid, int signal, const char* srcloc="");
int     open_file(const char* file, FileOpenFlag flag, const char* stream,
          ei::StringBuffer<128>& err, int mode = DEF_MODE);
int     open_pipe(int fds[2], const char* stream, ei::StringBuffer<128>& err);

// Safe file descriptor management functions to prevent double-close bugs
void    safe_close_fd(int& fd);
bool    is_valid_fd(int fd);

inline bool child_exists(pid_t pid) { return children.find(pid) != children.end(); }
inline void add_exited_child(pid_t pid, exit_status_t status) {
  // Note the following function doesn't insert anything if the element
  // with given key was already present in the map
  exited_children.insert(std::make_pair(pid, status));
}

// This function is now integrated into gotsigchild() for better error handling
// and async-signal-safety. The old write_sigchld() function had race conditions.

inline void gotsigchild(int signal, siginfo_t* si, void* /*context*/)
{
  // If someone used kill() to send SIGCHLD ignore the event
  if (si->si_code == SI_USER || signal != SIGCHLD)
    return;

  pid_t child = si->si_pid;

  // Only use async-signal-safe operations in signal handlers
  // Removed DEBUG() call as fprintf() is not async-signal-safe

  // Use write() with retry loop to handle EINTR
  // This is async-signal-safe unlike the previous version
  const char* data = (const char*)&child;
  size_t remaining = sizeof(child);
  ssize_t written;

  while (remaining > 0) {
    written = write(sigchld_pipe[1], data, remaining);
    if (written > 0) {
      data += written;
      remaining -= written;
    } else if (written < 0) {
      if (errno == EINTR) {
        continue; // Retry on interrupt
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Pipe buffer full - signal will be lost but we can't block in signal handler
        // This is logged later in the main thread when pipe is readable
        break;
      } else {
        // Other errors (EPIPE, etc.) - pipe is broken, can't recover in signal handler
        break;
      }
    }
  }
}

inline void gotsignal(int signal)
{
  if (signal == SIGTERM || signal == SIGINT || signal == SIGPIPE)
    terminated = true;
  if (signal == SIGPIPE)
    pipe_valid = false;
  DEBUG(debug, "Got signal: %d", signal);
}


} // namespace ei
