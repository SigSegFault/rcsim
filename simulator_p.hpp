/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Copyright (C) 2013 Paul Letnyanko                                       *
 *                                                                         *
 * Permission is hereby granted, free of charge, to any person obtaining a *
 * copy of this software and associated documentation files (the           *
 * "Software"), to deal in the Software without restriction, including     *
 * without limitation the rights to use, copy, modify, merge, publish,     *
 * distribute, sublicense, and/or sell copies of the Software, and to      *
 * permit persons to whom the Software is furnished to do so, subject to   *
 * the following conditions:                                               *
 *                                                                         *
 * The above copyright notice and this permission notice shall be included *
 * in all copies or substantial portions of the Software.                  *
 *                                                                         *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS *
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF              *
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  *
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY    *
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR   *
 * CLAIM, OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        *
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                  *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef SIMULATOR_P_HPP
#define SIMULATOR_P_HPP

#include "simulator.hpp"

#include <string>
#include <map>
#include <vector>
#include <poll.h>
#include <sys/types.h>

namespace rcs
{

namespace impl
{

/// Entropy source based on '/dev/urandom'.
struct Urandom
{
    Urandom();
    ~Urandom();

    /// Open entropy source.
    void open();

    /// Close entropy source.
    void close();

    /// Get random numeric value.
    /// Entropy source must be opened.
    template <typename T>
    T get_numeric()
    {
        T numeric;

        _read_raw_bytes(&numeric, sizeof(numeric));
        return numeric;
    }

private:
    /// Read raw bytes from entropy source.
    void _read_raw_bytes(void * ptr, size_t size);

    int _urand_fd;
};

/// Cross-process mutex based on locking shared file descriptor.
struct ProcessMutex
{
    ProcessMutex();
    ~ProcessMutex();

    /// Lock mutex for reading.
    void lock_read();

    /// Lock mutex for writing.
    void lock_write();

    /// Unlock mutex.
    void unlock();

    /// Init mubex, this effectively opens file descriptor.
    /// You must init mutex before fork()-ing to make it shared!
    void init();

    /// Release mutex resources, also releasing any locks.
    void release();

private:
    enum LockMode { LockNone, LockRead, LockWrite };

    /// Open file descriptor.
    void _open_fd();

    /// Close file descriptor.
    void _close_fd();

    /// Check if this pid is a lock owner.
    void _check_lock_owner();

    /// Lock file descriptor.
    bool _lock_fd(int type);

    LockMode    _lock_mode;
    pid_t       _lock_owner;
    int         _fd;
};

/// Generic process data.
struct LoneProcessInfo
{
    LoneProcessInfo(RaceSuspect * handler, const Config & config)
        :handler(handler),
          config(config),
          spawns_performed(0)
    { }

    void reset()
    {
        is_running = false;
        spawns_performed = 0;
    }

    bool need_more_spawns()
    {
        return spawns_performed < config.respawns + 1;
    }

    size_t expected_count() const
    {
        return config.respawns + 1;
    }

    RaceSuspect *   handler;
    Config          config;
    bool            is_running;
    size_t          spawns_performed;
};

/// Generic process data.
struct ProcessGroupInfo
{
    ProcessGroupInfo(RaceSuspect * handler, const Config & config, size_t group_size)
        :handler(handler),
          config(config),
          group_size(group_size),
          running_count(0),
          spawns_performed(0)
    { }

    void reset()
    {
        running_count = 0;
        spawns_performed = 0;
    }

    size_t need_more_spawns()
    {
        if (spawns_performed >= config.respawns + group_size)
            return 0;

        size_t spawns_left = config.respawns + group_size - spawns_performed;
        size_t missing = group_size - running_count;

        return missing > spawns_left ? spawns_left : missing;
    }


    size_t expected_count() const
    {
        return config.respawns + group_size;
    }


    RaceSuspect *   handler;
    Config          config;
    size_t          group_size;
    size_t          running_count;
    size_t          spawns_performed;
};

typedef size_t process_type_id;

struct SimulatedProcessData
{
    SimulatedProcessData()
        :pid(0),
          is_loner(false),
          stdin_bytes_fed(0),
          type(0),
          stdin_fd(-1),
          stdout_fd(-1),
          stderr_fd(-1)
    { }

    /// OS's process identifier.
    pid_t           pid;
    /// true indicates that process belongs to the lone processes list.
    /// Otherwise it's a member of group of processes.
    bool            is_loner;
    /// Size of the stdin data fed to process.
    size_t          stdin_bytes_fed;
    /// Proces type identifier.
    process_type_id type;
    /// The other side of the process's stdin pipe.
    int             stdin_fd;
    /// The other side of the process's stdout pipe.
    int             stdout_fd;
    /// The other side of the process's stderr pipe.
    int             stderr_fd;
};

/// Descriptor events.
enum DescriptorEvent
{
    DescriptorEventTalks    = 0x1,
    DescriptorEventListens  = 0x2
};

typedef size_t descriptor_events_t;

struct DescriptorWatchData
{
    DescriptorWatchData(pid_t pid = 0, descriptor_events_t events = 0)
        :pid(pid),
          events(events)
    { }

    pid_t               pid;
    descriptor_events_t events;
};


/// Race condition simulator implementation.
struct Simulator
{
public:
    Simulator();
    ~Simulator();

    /// Every process is either a lone process, or belongs to process group.
    /// This is judjed by it's woerker_type_id value.
    ///
    /// Lone processes templates.
    typedef std::map<process_type_id, LoneProcessInfo>  LoneProcesses;
    /// Groups of processes templates.
    typedef std::map<process_type_id, ProcessGroupInfo> ProcessGroups;

    /// Per process data.
    typedef std::map<pid_t, SimulatedProcessData>       RunningProcesses;
    /// File descriptor to pid mapping.
    typedef std::map<int, DescriptorWatchData>          DescriptorMap;


    /// /////////////////// ///
    ///                     ///
    ///  Sumulation makeup  ///
    ///                     ///
    /// /////////////////// ///
    ///
    ///
    /// Add race suspect to simulation as a lone process.
    void _add_process(RaceSuspect * handler, const Config & conf);

    /// Add race suspect to simulation as a process group.
    void _add_process_group(RaceSuspect * handler, size_t group_size, const Config & conf);

    /// Perform simulation initialization.
    void _init_simulation();

    /// Perform simulation cleanup.
    void _shutdown_simulation();

    /// Clear internal state, abandoning all the added processes.
    void _clear();

    /// Init all the stuff, perform simulation and cleanup aftermath.
    bool _run_simulation();

    /// Enter the mail simulation loop.
    void _simulation_loop();



    /// ////////////////// ///
    ///                    ///
    ///  Process handling  ///
    ///                    ///
    /// ////////////////// ///
    ///
    ///
    /// Check if there are any processes either done or failed their duty.
    void _check_for_zombies();

    /// Run through templates and see whether there are processes need to be spawned.
    void _spawn_missing_processes();

    /// Spawn process of specific kind.
    void _spawn_process(process_type_id process_type);

    /// Spawn lone process.
    void _spawn_process(process_type_id process_type, LoneProcessInfo & process_info);

    /// Spawn group member process.
    void _spawn_process(process_type_id process_type, ProcessGroupInfo & group_info);

    /// Spawn abstract process.
    void _spawn_process(RaceSuspect * handler, SimulatedProcessData & process_data);

    void _process_handler(RaceSuspect * handler);

    /// Brutally kill all the processes.
    void _kill_all_processes();

    /// Kill individual process, performing cleanup after it.
    void _kill_process(pid_t pid);

    /// Abandon all the processes.
    void _abandon_all_processes();

    /// Claenup process aftermath.
    void _remove_process(pid_t pid);



    /// //////////////////// ///
    ///                      ///
    ///  Descriptor polling  ///
    ///                      ///
    /// //////////////////// ///
    ///
    ///
    /// Watch specific descriptor events.
    void _watch_descriptor(int fd, pid_t pid, descriptor_events_t event);

    /// Stop watching specific descriptor events.
    void _stop_watching_descriptor(int fd, descriptor_events_t event = DescriptorEventTalks | DescriptorEventListens);

    /// Make poll buffer up to date with the running processes.
    void _update_poll_buffer();

    /// Poll descriptor events.
    void _poll_descriptors();



    /// //////// ///
    ///          ///
    ///  Events  ///
    ///          ///
    /// //////// ///
    ///
    ///
    /// One of descriptors being polled has some data pending.
    void _on_descriptor_talks(int fd, pid_t pid);

    /// One of descriptors being polled ready to read some data.
    void _on_descriptor_listens(int fd, pid_t pid);

    /// One of descriptors being polled experienced error.
    void _on_descriptor_error(int fd, pid_t pid);

    /// Child exited via return either via exit() functions family.
    void _on_child_exited(pid_t pid, int exit_status);

    /// Child was terminated by a signal.
    void _on_child_terminated(pid_t pid, int signal);



    /// //////////// ///
    ///              ///
    ///  Misc stuff  ///
    ///              ///
    /// //////////// ///
    ///
    ///
    /// Generate unique process type id.
    process_type_id _new_process_type_id();

    /// Get process data by pid.
    SimulatedProcessData & _get_process_data(pid_t pid);

    /// Get process info by process type.
    LoneProcessInfo & _get_process_info(process_type_id process_type);

    /// Get process group info by process type.
    ProcessGroupInfo & _get_process_group_info(process_type_id process_type);

    /// Run through templates and count expected number of processes.
    size_t _get_expected_process_count();

    /// Map descriptor to pid.
    pid_t _descriptor_to_pid(int fd);

    /// Get prefix to be prepended to the child logging messages.
    std::string _get_child_name(pid_t pid);

    /// Get timestamp string.
    std::string _get_timestamp();

    /// Send message to both stdout and message collector.
    /// Log to stdout may be disabled though.
    void _log(const char * message = "", ...);

    /// Send error message to both stderr and error message collector.
    /// Log to stderr may be disabled though.
    void _log_error(const char * message = "", ...);

    /// Read pending data from the file descriptor and append result to string.
    /// Return true if soemthing's being read.
    bool _read_pending(int fd, std::string & str);

    /// Try to write max possible chunk of data to the file descroptor,
    /// ignoring signal interruptions.
    ssize_t _write(int fd, const void * data, size_t size);

    /// Write whole string, ignoring signal interruptions.
    /// Does not expect descriptor to be in non-blocking mode!
    void _write_all(int fd, const std::string & str);
    void _write_all(int fd, const void * buf, size_t size);

    /// Make IO operations on descriptor non-blocking.
    void _set_descriptor_non_blocking(int fd);

    /// Sleep for arbitrary milliseconds, ignoring all interrupting signals.
    void _sleep_ms(int ms);


    /// Flag indiacating need to spawn more processes.
    bool                _spawn_more_processes;
    /// Whether to log output to stdout/stderr.
    bool                _log_to_std;
    /// Whether redirection of stdin is enabled.
    bool                _redirect_stdin;
    /// stdin data to be fed to simualted processes.
    std::string         _stdin_data;
    /// Statistics
    ///
    /// Number of processes that have failed to perform jib correctly.
    size_t              _failed_count;
    /// Number of processes successfully done thir duty.
    size_t              _successful_count;
    /// Number of spawned processes
    size_t              _spawned_count;
    /// Expected number of spawned processes.
    size_t              _expected_count;
    /// Buffer for stdout log messages.
    std::string         _log_messages;
    /// Buffer stderr log messages.
    std::string         _error_log_messages;
    /// Entropy provider.
    Urandom             _urandom;
    /// Initialization mutex.
    /// Used by a master process to determine moment when the last
    /// process of the first generation finished initialization stage.
    ProcessMutex        _init_mutex;
    /// Sync mutex, used to synchronize the execution of critical section
    /// of the first generation of processes.
    ProcessMutex        _sync_mutex;
    /// Las process type id.
    process_type_id     _process_type_last;
    /// Individual data of each lone process.
    LoneProcesses       _lone_processes;
    /// Individual data of each group of processes.
    ProcessGroups       _process_groups;
    /// Abstract data of each simulated running proccess.
    RunningProcesses    _running_processes;
    /// Descriptor map, used for watching descriptor events.
    DescriptorMap       _descriptor_map;
    /// Poll buffer.
    std::vector<pollfd> _poll_buffer;
    /// Flag indicating need to update above poll buffer.
    bool                _poll_buffer_needs_update;
};

} /// namespace impl

} /// namespace rcs

#endif // SIMULATOR_P_HPP
