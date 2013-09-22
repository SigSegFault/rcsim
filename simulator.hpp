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

#ifndef SIMULATOR_HPP
#define SIMULATOR_HPP

#include <string>

namespace rcs
{

/// One of the ways to simulate race condition is by synchronizing suspected piece of code.
/// This way, init routines won't make noise and interfere with the actual suspect.
struct RaceSuspect
{
    virtual ~RaceSuspect()
    { }

    /// If init returns false operation will be aborted.
    virtual bool init() = 0;

    /// This piece of code is what will be actually synchronized with
    /// the other suspects on the first spawn.
    /// This way we can cast away time, needed for init and put critical
    /// suspected piece of code here.
    virtual bool run() = 0;

    /// Aftermath cleaner.
    virtual bool shutdown() = 0;
};

typedef bool (*race_suspect_function_t)();


/// Per prosess/process group config.
struct Config
{
    Config(const std::string & name = std::string(), size_t concurrent = 1, size_t respawns = 0)
        :name(name),
          concurrent(concurrent),
          respawns(respawns)
    { }

    /// Name of the proces or a group of processes.
    std::string name;
    /// Number of concurrently running processes.
    size_t      concurrent;
    /// Number of process respawns.
    size_t      respawns;
};

namespace impl
{
struct Simulator;
}

/// A simple framework for Race Conditions simulation.
///
/// Entropy source is used to initalize standard random generator
/// (srand()) for each spawned child using providing seed.
class Simulator
{
public:
    Simulator();
    ~Simulator();


    /// ////////////////////////////////////// ///
    ///                                        ///
    ///  Add single process to the simulation  ///
    ///                                        ///
    /// ////////////////////////////////////// ///
    ///
    ///
    /// Job as a RaceSuspect derived object.
    /// Simulator takes ownership of the @param job object, so it must be allocated on heap.
    void add_process(RaceSuspect * job, const std::string & name, size_t respawns = 0);

    /// Job as a function.
    inline void add_process(race_suspect_function_t job, const std::string & name, size_t respawns = 0);

    /// Job as a functor.
    /// Functor must have overloaded function operator taking no arguments, as well as available copy constructor.
    template <typename F>
    inline void add_process(F & job, const std::string & name, size_t respawns = 0);


    /// ///////////////////////////////////// ///
    ///                                       ///
    ///  Add process group to the simulation  ///
    ///                                       ///
    /// ///////////////////////////////////// ///
    ///
    ///
    /// Processes of group run simultaneously.
    ///
    /// Job as a RaceSuspect derived object.
    /// Simulator takes ownership of the @param job object, so it must be allocated on heap.
    void add_process_group(RaceSuspect * job, size_t group_size, const std::string & name, size_t respawns = 0);

    /// Job as a function.
    inline void add_process_group(race_suspect_function_t job, size_t group_size, const std::string & name, size_t respawns = 0);

    /// Job as a functor.
    /// Functor must have overloaded function operator taking no arguments, as well as available copy constructor.
    template <typename F>
    inline void add_process_group(F & job, size_t group_size, const std::string & name, size_t respawns = 0);


    /// //////////////////////////////////////////// ///
    ///                                              ///
    ///  Add process to the simulation using config  ///
    ///                                              ///
    /// //////////////////////////////////////////// ///
    ///
    ///
    /// Job as a RaceSuspect derived object.
    /// Simulator takes ownership of the @param job object, so it must be allocated on heap.
    void add_process(RaceSuspect * job, const Config & config);

    /// Job as a function.
    inline void add_process(race_suspect_function_t job, const Config & config);

    /// Job as a functor.
    /// Functor must have overloaded function operator taking no arguments, as well as available copy constructor.
    template <typename F>
    inline void add_process(F & job, const Config & config);


    /// ///////////////////////// ///
    ///                           ///
    ///  Add pressure generators  ///
    ///                           ///
    /// ///////////////////////// ///
    ///
    ///
    /// Side note: you must not worry about specifying incorrect values for pressure
    ///            generatots; those will run in separate processes and will be
    ///            respawned, if crashed, having 0 influence on simulation outcome;
    ///            moreover, in real-life scenarious, unexpected behaviour is
    ///            the pie, when it comes to race conditions. So, be brave! =)
    ///
    /// Add I/O pressure generator at the specific file system location.
    /// Directory path is expected, and if process does not have permission
    /// to create/unlink file there, false will be returned.
    bool add_io_pressure(const std::string & where);

    /// Add CPU pressure generator.
    /// Pressure is generated by constantly copying data from one place to another.
    /// You can adjust block size and that will basically reflect CPU cache pollution.
    /// Block size is specified in kilobytes, with minimum size of 2 kilobytes.
    void add_cpu_pressure(size_t kilobytes = 2);

    /// Add RAM pressure generator.
    /// Pressure is generated by allocating block of memory and keeping it resident
    /// in RAM by first making pages dirty and then just sleeping.
    /// So yeah, you should probably disable swap, unless you want your system dead =)
    /// Block size is specified in megabytes, with minimum size of 1 megabyte.
    void add_ram_pressure(size_t magabytes = 1);


    /// ///////////////// ///
    ///                   ///
    ///  Adjust settings  ///
    ///                   ///
    /// ///////////////// ///
    ///
    ///
    /// Check whether simulation will abort upon encountering first failure.
    bool abort_on_first_failure() const;

    /// Check whether simulation will abort upon encountering first failure.
    void set_abort_on_first_failure(bool enabled = true);

    /// Check if redirection of stdin is enabled.
    /// If true, all data from stdin will be redirected to each simulated process.
    bool redirect_stdin() const;

    /// Enable or disable redirection of stdin.
    /// By default, input redirection is disabled.
    void set_redirect_stdin(bool enabled = true);

    /// Check if logging to stdout/stderr enabled.
    bool log_to_std() const;

    /// Enable or disable logging to stdout/stderr.
    /// Logging is disabled by default.
    /// In any case, enabled logging to std or not, all logs
    /// will be saved to corresponding buffers.
    /// By default logging to stdout/stderr is disabled.
    void set_log_to_std(bool enabled = true);

    /// Get stdout log buffer content.
    /// Simulator's own messages, as well as output from all childs'
    /// stdout, will be sent to this buffer.
    const std::string & log_messages() const;

    /// Clear stdout log buffer.
    void clear_log_messages();

    /// Get stderr log buffer content.
    /// Simulator's own error messages, as well as output from all childs'
    ///  stderr, will be sent to this buffer.
    const std::string & error_log_messages() const;

    /// Clear stderr log buffer.
    void clear_error_log_messages();


    /// ////////////////////// ///
    ///                        ///
    ///  Begin the simulation  ///
    ///                        ///
    /// ////////////////////// ///
    ///
    ///
    /// Returns true if everything gone smooth.
    /// If false is returned you can check out log messages.
    /// False will be returned in such cases:
    ///  * internal error;
    ///  * at least one child process abnormally (by a signal) terminated;
    ///  * at least one child process's exit code is not 0;
    ///  * at least one child process's job handler returns false;
    ///  * at least one child process's job handler throws exception.
    bool run_simulation();

    /// Clear internal state, abandoning:
    ///  * added process templates;
    ///  * added process group templates;
    ///  * stdout/stderr log messages.
    void clear();


private:
    impl::Simulator * _p;
};


namespace impl
{

template <typename F>
struct FunctorWrapper : public RaceSuspect
{
    FunctorWrapper(const F & functor)
        :_functor(functor)
    { }

    bool init()
    { return true; }

    bool run()
    { return _functor(); }

    bool shutdown()
    { return true; }

private:
    F       _functor;
};

struct FunctionWrapper : public RaceSuspect
{
    FunctionWrapper(race_suspect_function_t function)
        :_function(function)
    { }

    bool init()
    { return true; }

    bool run()
    { return _function(); }

    bool shutdown()
    { return true; }

private:
    race_suspect_function_t _function;
};

} /// namespace impl



inline void Simulator::add_process(race_suspect_function_t job, const std::string & name, size_t respawns)
{ add_process(new impl::FunctionWrapper(job), Config(name, 1, respawns)); }

template <typename F>
inline void Simulator::add_process(F & job, const std::string & name, size_t respawns)
{ add_process(new impl::FunctorWrapper<F>(job), Config(name, 1, respawns)); }

inline void Simulator::add_process_group(race_suspect_function_t job, size_t group_size, const std::string & name, size_t respawns)
{ add_process(new impl::FunctionWrapper(job), Config(name, group_size, respawns)); }

template <typename F>
inline void Simulator::add_process_group(F & job, size_t group_size, const std::string & name, size_t respawns)
{ add_process(new impl::FunctorWrapper<F>(job), Config(name, group_size, respawns)); }

inline void Simulator::add_process(race_suspect_function_t job, const Config & config)
{ add_process(new impl::FunctionWrapper(job), config); }

template <typename F>
inline void Simulator::add_process(F & job, const Config & config)
{ add_process(new impl::FunctorWrapper<F>(job), config); }

} /// namespace rcs

#endif // SIMULATOR_HPP
