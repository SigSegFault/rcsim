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

#include "simulator_p.hpp"

#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <wait.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <algorithm>

namespace rcs
{

Simulator::Simulator()
    :_p(new impl::Simulator)
{ }

Simulator::~Simulator()
{
    delete _p;
}

void Simulator::add_process(RaceSuspect * job, const Config & config)
{
    _p->_add_process(job, config);
}

void Simulator::add_process(RaceSuspect * job, const std::string & name, size_t respawns)
{
    _p->_add_process(job, Config(name, respawns));
}

void Simulator::add_process_group(RaceSuspect * job, size_t group_size, const Config & config)
{
    if (!group_size)
        return;

    _p->_add_process_group(job, group_size, config);
}

void Simulator::add_process_group(RaceSuspect * job, size_t group_size, const std::string & name, size_t respawns)
{
    if (!group_size)
        return;

    _p->_add_process_group(job, group_size, Config(name, respawns));
}

bool Simulator::run_simulation()
{
    try
    {
        return _p->_run_simulation();
    }
    catch(const std::exception & e)
    {
        _p->_log_error("Exception caught: %s.\n", e.what());
    }
    catch(...)
    {
        _p->_log_error("Unknown exception caught.\n");
    }
    return false;
}

void Simulator::clear()
{
    _p->_clear();
}

bool Simulator::redirect_stdin()
{
    return _p->_redirect_stdin;
}

void Simulator::set_redirect_stdin(bool enabled)
{
    _p->_redirect_stdin = enabled;
}

bool Simulator::log_to_std() const
{
    return _p->_log_to_std;
}

void Simulator::set_log_to_std(bool enabled)
{
    _p->_log_to_std = enabled;
}

const std::string &Simulator::log_messages() const
{
    return _p->_log_messages;
}

void Simulator::clear_log_messages()
{
    _p->_log_messages.clear();
}

const std::string &Simulator::error_log_messages() const
{
    return _p->_error_log_messages;
}

void Simulator::clear_error_log_messages()
{
    _p->_error_log_messages.clear();
}


namespace impl
{

struct Exception : public std::exception
{
    Exception(const char * message = "", ...)
    {
        va_list arg_list;

        va_start(arg_list, message);
        vsnprintf(_what, sizeof(_what), message, arg_list);
        va_end(arg_list);
    }

    const char * what() const throw()
    {
        return _what;
    }

private:
    char _what[512];
};



template <int Signal, bool ignore = false>
struct SignalTrap
{
    SignalTrap()
        :_trap_is_set(false)
    { }

    ~SignalTrap()
    { disarm(); }

    void set_trap()
    {
        if (_trap_is_set)
            return;

        memset(&_sigaction, 0, sizeof(_sigaction));
        memset(&_sigaction_old, 0, sizeof(_sigaction_old));

        sigemptyset(&_sigaction.sa_mask);
        if (ignore)
            _sigaction.sa_handler = SIG_IGN;
        else
            _sigaction.sa_handler = _on_signal;
        sigaction(Signal, &_sigaction, &_sigaction_old);
        _trap_is_set = true;
    }

    void disarm()
    {
        if (!_trap_is_set)
            return;

        sigaction(Signal, &_sigaction_old, 0);
        _trap_is_set = false;
    }

    static sig_atomic_t signal_caught;

private:
    static void _on_signal(int sig)
    {
        signal_caught = 1;
    }

    bool                _trap_is_set;
    struct sigaction    _sigaction;
    struct sigaction    _sigaction_old;
};

template <int Signal, bool ignore>
sig_atomic_t SignalTrap<Signal, ignore>::signal_caught = 0;






Urandom::Urandom()
    :_urand_fd(-1)
{ }

Urandom::~Urandom()
{
    close();
}

void Urandom::open()
{
    if (_urand_fd != -1)
        return;

    if ((_urand_fd = ::open("/dev/urandom", O_RDONLY)) == -1)
        throw Exception("failed to open '/dev/urandom', and the reason is: %s.", strerror(errno));
}

void Urandom::close()
{
    if (_urand_fd != -1)
    {
        ::close(_urand_fd);
        _urand_fd = -1;
    }
}

void Urandom::_read_raw_bytes(void * ptr, size_t size)
{
    if (::read(_urand_fd, ptr, size) != (ssize_t)size)
        throw Exception("failed to read random bytes, and the reason is: %s.", strerror(errno));
}






ProcessMutex::ProcessMutex()
    :_lock_mode(LockNone),
      _fd(-1)
{ }

ProcessMutex::~ProcessMutex()
{ release(); }

void ProcessMutex::lock_read()
{
    _check_lock_owner();

    if (_lock_mode == LockRead)
        return;

    _open_fd();
    if (!_lock_fd(F_RDLCK))
        throw Exception("failed to lock process mutex for reading, and the reason is: %s.", strerror(errno));
    _lock_mode = LockRead;
    _lock_owner = getpid();
}

void ProcessMutex::lock_write()
{
    _check_lock_owner();

    if (_lock_mode == LockWrite)
        return;

    _open_fd();
    if (!_lock_fd(F_WRLCK))
        throw Exception("failed to lock process mutex for writing, and the reason is: %s.", strerror(errno));
    _lock_mode = LockWrite;
    _lock_owner = getpid();
}

void ProcessMutex::unlock()
{
    _check_lock_owner();

    if (_lock_mode == LockNone)
        return;

    _open_fd();
    if (!_lock_fd(F_UNLCK))
        throw Exception("failed to unlock process mutex, and the reason is: %s.", strerror(errno));
    _lock_mode = LockNone;
    _lock_owner = getpid();
}

void ProcessMutex::init()
{
    _open_fd();
}

void ProcessMutex::release()
{
    unlock();
    _close_fd();
}

void ProcessMutex::_open_fd()
{
    if (_fd != -1)
        return;

    if ((_fd = ::open("/dev/null", O_RDWR)) < 0)
        throw Exception("failed to open '/dev/null', and the reason is: %s.", strerror(errno));
}

void ProcessMutex::_close_fd()
{
    if (_fd == -1)
        return;

    ::close(_fd);
    _fd = -1;
}

void ProcessMutex::_check_lock_owner()
{
    if (_lock_mode == LockNone)
        return;

    pid_t pid = getpid();
    if (_lock_owner == pid)
        return;

    _lock_mode = LockNone;
    _lock_owner = pid;
}

bool ProcessMutex::_lock_fd(int type)
{
    struct flock file_lock;

    file_lock.l_type = type;
    file_lock.l_len = 1;
    file_lock.l_whence = SEEK_SET;
    file_lock.l_start = 0;
    file_lock.l_len = 1;
    file_lock.l_pid = 0;
    return !fcntl(_fd, F_SETLKW, &file_lock);
}









Simulator::Simulator()
    :_spawn_more_processes(false),
      _log_to_std(false),
      _failed_count(0),
      _successful_count(0),
      _spawned_count(0),
      _expected_count(0),
      _process_type_last(0),
      _poll_buffer_needs_update(false)
{ }

Simulator::~Simulator()
{ _clear(); }

void Simulator::_add_process(RaceSuspect * handler, const Config & conf)
{
    _lone_processes.insert(LoneProcesses::value_type(_new_process_type_id(), impl::LoneProcessInfo(handler, conf)));
}

void Simulator::_add_process_group(RaceSuspect * handler, size_t group_size, const Config & conf)
{
    _process_groups.insert(ProcessGroups::value_type(_new_process_type_id(), impl::ProcessGroupInfo(handler, conf, group_size)));
}

void Simulator::_init_simulation()
{
    /// Reset counters.
    _failed_count = 0;
    _successful_count = 0;
    _spawned_count = 0;
    _expected_count = _get_expected_process_count();
    /// Abandon old logs.
    _log_messages.clear();
    _error_log_messages.clear();
    /// Open enpropy provider.
    _urandom.open();
    srand(_urandom.get_numeric<int>());
    /// Read stdin data.
    if (_redirect_stdin)
        _read_pending(STDIN_FILENO, _stdin_data);
}

void Simulator::_shutdown_simulation()
{
    /// Get rid of stdin data.
    _stdin_data.clear();
    /// Kill all processes.
    _kill_all_processes();
    /// Reset process data.
    for (LoneProcesses::iterator it = _lone_processes.begin(); it != _lone_processes.end(); ++it)
        it->second.reset();
    for (ProcessGroups::iterator it = _process_groups.begin(); it != _process_groups.end(); ++it)
        it->second.reset();
}

void Simulator::_clear()
{
    /// Get rid of stdin data.
    _stdin_data.clear();
    /// Clear the logs.
    _log_messages.clear();
    _error_log_messages.clear();
    /// Kill all processes.
    _kill_all_processes();
    /// Clear process templates.
    for (LoneProcesses::iterator it = _lone_processes.begin(); it != _lone_processes.end(); ++it)
        delete it->second.handler;
    _lone_processes.clear();
    for (ProcessGroups::iterator it = _process_groups.begin(); it != _process_groups.end(); ++it)
        delete it->second.handler;
    _process_groups.clear();
    /// Close all monitored descriptors.
}

bool Simulator::_run_simulation()
{
    /// Automatically perform shutdown when scope is left.
    struct SimulationWatcher
    {
        SimulationWatcher(Simulator & ref)
            :_ref(ref)
        { }

        void start()
        { _ref._init_simulation(); }

        void stop()
        { _ref._shutdown_simulation(); }

        ~SimulationWatcher()
        { stop(); }

        Simulator & _ref;
    } reset_watcher(*this);
    reset_watcher.start();

    /// Set SIGCHLD trap.
    impl::SignalTrap<SIGCHLD> sigchild_trap;
    sigchild_trap.set_trap();

    /// Set SIGTERM trap.
    impl::SignalTrap<SIGTERM> sigterm_trap;
    sigterm_trap.set_trap();

    /// Set SIGPIPE trap.
    impl::SignalTrap<SIGPIPE, true> sigpipe_trap;
    sigpipe_trap.set_trap();

    /// Open init mutex.
    _init_mutex.init();
    /// Lock sync mutex.
    _sync_mutex.lock_write();
    /// Spawn first generation of processes.
    _spawn_more_processes = true;
    _spawn_missing_processes();
    /// Give some time for childs to start doing stuff.
    _sleep_ms(25);
    /// Wait for every last process to finish initialization.
    _init_mutex.lock_write();
    /// Release lock, to run whole bunch of processes synchronously.
    _sync_mutex.unlock();
    /// Release lock to not interfere with the future born childs.
    _init_mutex.unlock();
    /// Enter the loop.
    _simulation_loop();
    /// Dump statistics.
    _log("Simulation is over.");
    _log("Spawned processes:        %u.", _spawned_count);
    _log("Successfully finished:    %u.", _successful_count);
    _log("Abnormally finished:      %u.", _failed_count);
    return _failed_count == 0;
}

void Simulator::_simulation_loop()
{
    while (!impl::SignalTrap<SIGTERM>::signal_caught) {
        /// Check dead processes.
        _check_for_zombies();
        /// Spawn missing processes.
        _spawn_missing_processes();
        /// If we have no running processes it means we're done, yay!
        if (_running_processes.empty())
            break;
        /// Poll events from processes.
        _poll_descriptors();
    }
}

void Simulator::_check_for_zombies()
{
    /// Bailout if no signal occured.
    if (!impl::SignalTrap<SIGCHLD>::signal_caught)
        return;

    /// We must reset signal status in advance, but not afterwards.
    impl::SignalTrap<SIGCHLD>::signal_caught = 0;

    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /// Child may either exit.
        if (WIFEXITED(status))
            _on_child_exited(pid, WEXITSTATUS(status));
        /// Or be terminated by a signal.
        else if (WIFSIGNALED(status))
            _on_child_terminated(pid, WTERMSIG(status));
    }
}

void Simulator::_spawn_missing_processes()
{
    /// If there is no need to spawn anything
    if (!_spawn_more_processes || _expected_count <= _spawned_count)
    {
        _spawn_more_processes = false;
        return;
    }
    _spawn_more_processes = false;

    /// To spawn processes fairly we must shuffle candidates.
    std::vector<process_type_id> candidates;

    /// Run through lone processes, looking for spawn candidates.
    for (LoneProcesses::iterator it = _lone_processes.begin(); it != _lone_processes.end(); ++it) {
        impl::LoneProcessInfo & process_info = it->second;

        if (!process_info.need_more_spawns())
            continue;

        candidates.push_back(it->first);
    }

    /// Run through processe groups, looking for spawn candidates.
    for (ProcessGroups::iterator it = _process_groups.begin(); it != _process_groups.end(); ++it) {
        impl::ProcessGroupInfo & group_info = it->second;

        size_t spawns = group_info.need_more_spawns();
        if (!spawns)
            continue;

        candidates.insert(candidates.end(), spawns, it->first);
    }

    std::random_shuffle(candidates.begin(), candidates.end());
    for (size_t i = 0; i < candidates.size(); ++i)
        _spawn_process(candidates.at(i));
}

void Simulator::_spawn_process(process_type_id process_type)
{
    /// Look in lone processes.
    {
        LoneProcesses::iterator it = _lone_processes.find(process_type);

        if (it != _lone_processes.end())
            return _spawn_process(process_type, it->second);
    }
    /// Look in process groups.
    {
        ProcessGroups::iterator it = _process_groups.find(process_type);

        if (it != _process_groups.end())
            return _spawn_process(process_type, it->second);
    }

    throw impl::Exception("process type not found.");
}

void Simulator::_spawn_process(process_type_id process_type, LoneProcessInfo & process_info)
{
    impl::SimulatedProcessData process_data;
    process_data.is_loner = true;
    process_data.type = process_type;
    _spawn_process(process_info.handler, process_data);
    /// Put descriptors on watch.
    if (!_stdin_data.empty())
        _watch_descriptor(process_data.stdin_fd, process_data.pid, DescriptorEventListens);
    _watch_descriptor(process_data.stdout_fd, process_data.pid, DescriptorEventTalks);
    _watch_descriptor(process_data.stderr_fd, process_data.pid, DescriptorEventTalks);
    /// Save to running processes map.
    _running_processes.insert(RunningProcesses::value_type(process_data.pid, process_data));
    process_info.is_running = true;
    ++process_info.spawns_performed;

}

void Simulator::_spawn_process(process_type_id process_type, ProcessGroupInfo & group_info)
{
    impl::SimulatedProcessData process_data;
    process_data.is_loner = false;
    process_data.type = process_type;
    _spawn_process(group_info.handler, process_data);
    /// Put descriptors on watch.
    if (!_stdin_data.empty())
        _watch_descriptor(process_data.stdin_fd, process_data.pid, DescriptorEventListens);
    _watch_descriptor(process_data.stdout_fd, process_data.pid, DescriptorEventTalks);
    _watch_descriptor(process_data.stderr_fd, process_data.pid, DescriptorEventTalks);
    /// Save to running processes map.
    _running_processes.insert(RunningProcesses::value_type(process_data.pid, process_data));
    ++group_info.running_count;
    ++group_info.spawns_performed;
}

void Simulator::_spawn_process(RaceSuspect * handler, SimulatedProcessData & process_data)
{
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];

    if (pipe(stdin_pipe) == -1)
        throw impl::Exception("failed to create pipe, and the reason is: %s.", strerror(errno));

    if (pipe(stdout_pipe) == -1) {
        ::close(stdin_pipe[0]);
        ::close(stdin_pipe[1]);
        throw impl::Exception("failed to create pipe, and the reason is: %s.", strerror(errno));
    }

    if (pipe(stderr_pipe) == -1) {
        ::close(stdin_pipe[0]);
        ::close(stdin_pipe[1]);
        ::close(stdout_pipe[0]);
        ::close(stdout_pipe[1]);
        throw impl::Exception("failed to create pipe, and the reason is: %s.", strerror(errno));
    }

    pid_t pid = fork();
    if (pid == -1) {
        ::close(stdout_pipe[0]);
        ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]);
        ::close(stderr_pipe[1]);
        throw impl::Exception("failed to fork, and the reason is: %s.", strerror(errno));
    }

    /// Child process.
    if (!pid) {
        /// Close writing side.
        ::close(stdin_pipe[1]);
        /// Close reading side.
        ::close(stdout_pipe[0]);
        ::close(stderr_pipe[0]);

        _log_to_std = false;
        try
        {
            /// Those are not ours...
            _abandon_all_processes();
            /// Link stdin.
            if (dup2(stdin_pipe[0], STDIN_FILENO) == -1)
                throw impl::Exception("failed to dup2, and the reason is: %s.", strerror(errno));
            ::close(stdin_pipe[0]);
            /// Link stdout.
            if (dup2(stdout_pipe[1], STDOUT_FILENO) == -1)
                throw impl::Exception("failed to dup2, and the reason is: %s.", strerror(errno));
            ::close(stdout_pipe[1]);
            /// Link stderr.
            if (dup2(stderr_pipe[1], STDERR_FILENO) == -1)
                throw impl::Exception("failed to dup2, and the reason is: %s.", strerror(errno));
            ::close(stderr_pipe[1]);
            /// Run process handler.
            _process_handler(handler);
            _exit(0);
        }
        catch(const std::exception & e)
        {
            _log_error("Exception caught: %s.\n", e.what());
            _exit(1);
        }
        catch(...)
        {
            _log_error("Unknown exception caught.\n");
            _exit(1);
        }
    }

    /// Parent process
    ///
    /// Close reading side.
    ::close(stdin_pipe[0]);
    /// Close writing side.
    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[1]);
    /// Make descriptors non-blocking.
    _set_descriptor_non_blocking(stdout_pipe[0]);
    _set_descriptor_non_blocking(stderr_pipe[0]);
    /// Save descriptors.
    process_data.stdin_fd = stdin_pipe[1];
    process_data.stdout_fd = stdout_pipe[0];
    process_data.stderr_fd = stderr_pipe[0];
    process_data.pid = pid;
    ++_spawned_count;
}

void Simulator::_process_handler(RaceSuspect * handler)
{
    /// Introduce some real randomness.
    srand(_urandom.get_numeric<int>());
    /// On first run, all the processes lock init mutex before init
    /// And unlock after init is completed, so that master may know
    /// when every last process is ready to go.
    _init_mutex.lock_read();
    /// Init asynchronously.
    if (!handler->init())
        throw impl::Exception("handler initialization failed.");
    /// Release lock, for we are ready to go.
    _init_mutex.unlock();
    /// Synchronize at run point.
    _sync_mutex.lock_read();
    if (!handler->run())
        throw impl::Exception("handler returned false.");
    /// Flush output.
    fflush(stdout);
    fflush(stderr);
    /// Cleanup aftermath.
    if (!handler->shutdown())
        throw impl::Exception("handler shutdown failed.");
}

void Simulator::_kill_all_processes()
{
    if (_running_processes.empty())
        return;

    std::vector<pid_t> pids;

    /// Collect pids first.
    pids.reserve(_running_processes.size());
    for (RunningProcesses::const_iterator it = _running_processes.begin();
         it != _running_processes.end();
         ++it)
        pids.push_back(it->first);

    /// Now kill them.
    for (size_t i = 0; i < pids.size(); ++i)
        _kill_process(pids[i]);
}

void Simulator::_kill_process(pid_t pid)
{
    /// Brutally kill.
    kill(pid, SIGKILL);
    /// Cleanup.
    _remove_process(pid);
}

void Simulator::_abandon_all_processes()
{
    if (_running_processes.empty())
        return;

    std::vector<pid_t> pids;

    /// Collect pids first.
    pids.reserve(_running_processes.size());
    for (RunningProcesses::const_iterator it = _running_processes.begin();
         it != _running_processes.end();
         ++it)
        pids.push_back(it->first);

    /// Now kill them.
    for (size_t i = 0; i < pids.size(); ++i)
        _remove_process(pids[i]);
}

void Simulator::_remove_process(pid_t pid)
{
    /// It is dangerous to have reference to non-existent object so I make new block here.
    {
        impl::SimulatedProcessData & process_data = _get_process_data(pid);
        /// Close associated descriptors.
        ::close(process_data.stdin_fd);
        ::close(process_data.stdout_fd);
        ::close(process_data.stderr_fd);
        /// Erace descriptors from queue.
        _stop_watching_descriptor(process_data.stdin_fd);
        _stop_watching_descriptor(process_data.stdout_fd);
        _stop_watching_descriptor(process_data.stderr_fd);
        /// Find in lone process list, and if found - update data.
        if (process_data.is_loner) {
            impl::LoneProcessInfo & process_info = _get_process_info(process_data.type);

            process_info.is_running = false;
            /// Request respawn if we have some more process spwans in a pocket.
            if (process_info.need_more_spawns())
                _spawn_more_processes = true;
            /// Do the same for process groups.
        } else {
            impl::ProcessGroupInfo & group_info = _get_process_group_info(process_data.type);

            --group_info.running_count;
            /// Request respawn if we have some more process spwans in a pocket.
            if (group_info.need_more_spawns())
                _spawn_more_processes = true;
        }
    }
    /// Remove from running processes.
    _running_processes.erase(pid);
}

void Simulator::_watch_descriptor(int fd, pid_t pid, descriptor_events_t events)
{
    DescriptorMap::iterator it = _descriptor_map.find(fd);

    /// Unknown descriptor.
    if (it == _descriptor_map.end()) {
        _descriptor_map.insert(it, DescriptorMap::value_type(fd, DescriptorWatchData(pid, events)));
        _poll_buffer_needs_update = true;
        return;
    }

    /// We're already watching this event.
    if (it->second.events == events)
        return;

    /// New event type.
    it->second.events = events;
    _poll_buffer_needs_update = true;
}

void Simulator::_stop_watching_descriptor(int fd, descriptor_events_t events)
{
    DescriptorMap::iterator it = _descriptor_map.find(fd);

    /// Unknown descriptor.
    if (it == _descriptor_map.end())
        return;

    /// We aren't watching that event.
    if (!(it->second.events & events))
        return;

    it->second.events &= ~events;
    /// No event to be listened, we have to remove descriptor.
    if (!it->second.events)
        _descriptor_map.erase(it);
    _poll_buffer_needs_update = true;
}

void Simulator::_update_poll_buffer()
{
    if (!_poll_buffer_needs_update)
        return;

    /// We need to hold all the descriptors.
    _poll_buffer.resize(_descriptor_map.size());
    pollfd * _pfd = &_poll_buffer[0];

    DescriptorMap::const_iterator it = _descriptor_map.begin();
    for (; it != _descriptor_map.end(); ++it, ++_pfd) {
        _pfd->revents = 0;
        _pfd->events = 0;
        if (it->second.events & DescriptorEventTalks)
            _pfd->events |= POLLIN;
        if (it->second.events & DescriptorEventListens)
            _pfd->events |= POLLOUT;
        _pfd->fd = it->first;
    }
}

void Simulator::_poll_descriptors()
{
    _update_poll_buffer();

    int events = poll(&_poll_buffer[0], _poll_buffer.size(), -1);
    if (events > 0) {
        for (size_t i = 0; i < _poll_buffer.size(); ++i) {
            if (_poll_buffer.at(i).revents & POLLIN)
                _on_descriptor_talks(_poll_buffer.at(i).fd, _descriptor_to_pid(_poll_buffer.at(i).fd));
            if (_poll_buffer.at(i).revents & POLLERR)
                _on_descriptor_error(_poll_buffer.at(i).fd, _descriptor_to_pid(_poll_buffer.at(i).fd));
            else if (_poll_buffer.at(i).revents & POLLOUT)
                _on_descriptor_listens(_poll_buffer.at(i).fd, _descriptor_to_pid(_poll_buffer.at(i).fd));
        }
    } else if (events < 0 && errno != EINTR) {
        throw impl::Exception("failed to poll, and the reason is: %s.", strerror(errno));
    }
}

void Simulator::_on_descriptor_talks(int fd, pid_t pid)
{
    std::string message;

    /// Nothing to be read means, the other side just closed.
    if (!_read_pending(fd, message))
        return;

    if (*message.rbegin() == '\n')
        message.resize(message.size() - 1);

    impl::SimulatedProcessData & process_data = _get_process_data(pid);
    /// stdout message.
    if (fd == process_data.stdout_fd)
        _log("%s said: %s", _get_child_name(pid).c_str(), message.c_str());
    /// stderror message.
    else
        _log_error("%s cried: %s", _get_child_name(pid).c_str(), message.c_str());
}

void Simulator::_on_descriptor_listens(int fd, pid_t pid)
{
    impl::SimulatedProcessData & process_data = _get_process_data(pid);

    /// Bailout, if we had fed all the data.
    if (process_data.stdin_bytes_fed >= _stdin_data.size()) {
        _stop_watching_descriptor(fd, DescriptorEventListens);
        return;
    }

    const void * data_ptr = _stdin_data.c_str() + process_data.stdin_bytes_fed;
    size_t bytes_left = _stdin_data.size() - process_data.stdin_bytes_fed;
    ssize_t fed_bytes = _write(fd, data_ptr, bytes_left);

    /// The other side doesn't want input any more.
    if (fed_bytes <= 0) {
        _stop_watching_descriptor(fd, DescriptorEventListens);
        return;
    }

    process_data.stdin_bytes_fed += fed_bytes;
}

void Simulator::_on_descriptor_error(int fd, pid_t pid)
{
    /// Descriptor is closed on the other side, we ough to stop watching it.
    _stop_watching_descriptor(fd);
}

void Simulator::_on_child_exited(pid_t pid, int exit_status)
{
    if (exit_status) {
        ++_failed_count;
        _log_error("%s exited with code: %d.", _get_child_name(pid).c_str(), exit_status);
    } else {
        ++_successful_count;
    }
    /// There might be something pending on stdout/stderr of a process.
    /// It is dangerous to have reference to non-existent object so I make new block here.
    {
        impl::SimulatedProcessData & process_data = _get_process_data(pid);
        _on_descriptor_talks(process_data.stdout_fd, pid);
        _on_descriptor_talks(process_data.stderr_fd, pid);
    }
    /// Now we have no use of the process.
    _remove_process(pid);
}

void Simulator::_on_child_terminated(pid_t pid, int signal)
{
    ++_failed_count;
    _log_error("%s was terminated by signal: %d.", _get_child_name(pid).c_str(), signal);
    /// There might be something pending on stdout/stderr of a process.
    /// It is dangerous to have reference to non-existent object so I make new block here.
    {
        impl::SimulatedProcessData & process_data = _get_process_data(pid);
        _on_descriptor_talks(process_data.stderr_fd, pid);
        _on_descriptor_talks(process_data.stdout_fd, pid);
    }
    /// Now we have no use of the process.
    _remove_process(pid);
}

process_type_id Simulator::_new_process_type_id()
{
    return ++_process_type_last;
}

SimulatedProcessData &Simulator::_get_process_data(pid_t pid)
{
    RunningProcesses::iterator it = _running_processes.find(pid);
    if (it == _running_processes.end())
        throw impl::Exception("process was not found in running process list.");

    return it->second;
}

LoneProcessInfo &Simulator::_get_process_info(process_type_id process_type)
{
    LoneProcesses::iterator it = _lone_processes.find(process_type);

    if (it == _lone_processes.end())
        throw impl::Exception("process type was not found in a lone process list.");

    return it->second;
}

ProcessGroupInfo &Simulator::_get_process_group_info(process_type_id process_type)
{
    ProcessGroups::iterator it = _process_groups.find(process_type);

    if (it == _process_groups.end())
        throw impl::Exception("process of type was not found in a process group list.");

    return it->second;
}

size_t Simulator::_get_expected_process_count()
{
    size_t count = 0;

    /// Run through lone processes.
    for (LoneProcesses::iterator it = _lone_processes.begin(); it != _lone_processes.end(); ++it) {
        impl::LoneProcessInfo & process_info = it->second;

        count += process_info.expected_count();
    }

    /// Run through processe groups.
    for (ProcessGroups::iterator it = _process_groups.begin(); it != _process_groups.end(); ++it) {
        impl::ProcessGroupInfo & group_info = it->second;

        count += group_info.expected_count();
    }

    return count;
}

pid_t Simulator::_descriptor_to_pid(int fd)
{
    DescriptorMap::const_iterator it = _descriptor_map.find(fd);

    if (it == _descriptor_map.end())
        throw impl::Exception("file descriptor was not found in descriptor map.");

    return it->second.pid;
}

std::string Simulator::_get_child_name(pid_t pid)
{
    char prefix_buf[512];

    impl::SimulatedProcessData & process_data = _get_process_data(pid);
    /// Process is a loner.
    if (process_data.is_loner) {
        impl::LoneProcessInfo & process_info = _get_process_info(process_data.type);

        snprintf(prefix_buf, sizeof(prefix_buf), "'%s' [%u]", process_info.config.name.c_str(), pid);
        /// Process acting on behalf of a group.
    } else {
        impl::ProcessGroupInfo & group_info = _get_process_group_info(process_data.type);

        snprintf(prefix_buf, sizeof(prefix_buf), "Member of '%s' [%u]", group_info.config.name.c_str(), pid);
    }
    return prefix_buf;
}

std::string Simulator::_get_timestamp()
{
    char time_buf[64];
    char nanosec_buf[32];
    struct timespec hires_time;

    clock_gettime(CLOCK_REALTIME, &hires_time);

    time_t rawtime = time(0);
    struct tm * timeinfo = localtime(&rawtime);
    strftime(time_buf, sizeof(time_buf), "[%H:%M:%S", timeinfo);
    snprintf(nanosec_buf, sizeof(nanosec_buf), ":%u] ", (size_t)hires_time.tv_nsec);
    return std::string(time_buf) + nanosec_buf;
}

void Simulator::_log(const char * message, ...)
{
    char log_buffer[1 << 19];
    std::string timestamp = _get_timestamp();
    va_list arg_list;

    va_start(arg_list, message);
    /// Log to buffer.
    size_t size = vsnprintf(log_buffer, sizeof(log_buffer), message, arg_list);
    _log_messages.append(timestamp).append(log_buffer, size).append("\n");
    /// Log to stdout.
    if (_log_to_std) {
        _write_all(STDOUT_FILENO, timestamp);
        _write_all(STDOUT_FILENO, log_buffer, size);
        _write_all(STDOUT_FILENO, "\n", 1);
    }
    va_end(arg_list);
}

void Simulator::_log_error(const char * message, ...)
{
    char log_buffer[1 << 19];
    std::string timestamp = _get_timestamp();
    va_list arg_list;

    va_start(arg_list, message);
    /// Log to buffer.
    size_t size = vsnprintf(log_buffer, sizeof(log_buffer), message, arg_list);
    _error_log_messages.append(timestamp).append(log_buffer, size).append("\n");
    /// Log to stderr.
    if (_log_to_std) {
        _write_all(STDERR_FILENO, timestamp);
        _write_all(STDERR_FILENO, log_buffer, size);
        _write_all(STDERR_FILENO, "\n", 1);
    }
    va_end(arg_list);
}

bool Simulator::_read_pending(int fd, std::string & str)
{
    char buf[1 < 12];
    size_t size_before = str.size();
    ssize_t read_bytes;

    /// Descriptor is guaranteed to be in non-blocking IO mode.
    while (true) {
        read_bytes = ::read(fd, buf, sizeof(buf));
        if (read_bytes < 0) {
            if (errno == EINTR)
                continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else
                throw impl::Exception("failed to read data from descriptor, and the reason is: %s.", strerror(errno));
        } else if (!read_bytes)
            break;

        str.append(buf, read_bytes);
    }

    return str.size() != size_before;
}

ssize_t Simulator::_write(int fd, const void * data, size_t size)
{
    size_t offset = 0;
    ssize_t written_bytes;

    while (offset < size) {
        written_bytes = ::write(fd, static_cast<const char*>(data) + offset, size - offset);
        if (written_bytes < 0) {
            if (errno == EINTR)
                continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else if (errno == EPIPE)
                return -1;
            else
                throw impl::Exception("failed to write data to descriptor, and the reason is: %s.", strerror(errno));
        } else if (!written_bytes)
            break;

        offset += written_bytes;
    }
    return offset;
}

void Simulator::_write_all(int fd, const std::string & str)
{
    size_t offset = 0;
    size_t size = str.size();
    ssize_t written_bytes;

    while (offset < size) {
        written_bytes = ::write(fd, str.c_str() + offset, size - offset);
        if (written_bytes < 0) {
            if (errno == EINTR)
                continue;
            else
                throw impl::Exception("failed to write data to descriptor, and the reason is: %s.", strerror(errno));
        }

        offset += written_bytes;
    }
}

void Simulator::_write_all(int fd, const void * buf, size_t size)
{
    size_t offset = 0;
    ssize_t written_bytes;

    while (offset < size) {
        written_bytes = ::write(fd, static_cast<const char*>(buf) + offset, size);
        if (written_bytes < 0) {
            if (errno == EINTR)
                continue;
            else
                throw impl::Exception("failed to write data to descriptor, and the reason is: %s.", strerror(errno));
        }

        offset += written_bytes;
    }
}

void Simulator::_set_descriptor_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags == -1)
        throw impl::Exception("failed to get descriptor flags, and the reason is: %s.", strerror(errno));

    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags) < 0)
        throw impl::Exception("failed to set descriptor flags, and the reason is: %s.", strerror(errno));
}

void Simulator::_sleep_ms(int ms)
{
    struct timespec time;
    struct timespec time_left;

    time.tv_sec = ms / 1000;
    time.tv_nsec = (ms - time.tv_sec * 1000) * 1000000;
    while (nanosleep(&time, &time_left) < 0 && errno == EINTR)
        time = time_left;
}

} /// namespace impl

} /// namespace rcs
