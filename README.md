Simple framework for race condition testing. Simulates environment to make your life easier, when it comes to their reproduction.

What it basically provides is:
 * ability to run a piece of code in several processes simultaneously
 * ability to add single process to simulation
 * ability to add group of processes to simulation (processes of group run simultaneously)
 * ability to assign name to process/group of processes
 * ability to provide number of process instances to be respawned after member of group/lone process exits
 * ability to feed input from stdin to every spawned process
 * ability to add arbitrary number of I/O pressure generators for specific path on File System
 * ability to add arbitrary number of CPU pressure generators
 * ability to add arbitrary number of RAM pressure generators
 * synchronization of execution of piece of code in question for the first generation of processes
 * bunching of stdout/stderr from all simulated processes to buffer, prepending nice timestamp, with the ability to send output to stdout/stderr of the former process


TODO
=====
 * more real-life examples


Examples
=====

In this simple example we spawn 4 kinds of processes running simultaneously.
There will be spawned 100 instances of each kind in total.
```c++
#include <stdio.h>
#include <iostream>
#include "simulator.hpp"

using namespace std;

bool foo()
{
    printf("hello bar!\n");
    return true;
}

bool bar()
{
    std::cout << "hello foo!" << std::endl;
    return true;
}

bool baz()
{
    std::cerr << "what about baz, guys!?" << std::endl;
    return true;
}

bool qux()
{
    fprintf(stderr, "sup buz!\n");
    return true;
}

int main()
{
    rcs::Simulator sim;

    /// 20 instances of foo will run simultaneously.
    sim.add_process_group(foo, 20, "foo", 80);
    /// 10 instances of foo will run simultaneously.
    sim.add_process_group(bar, 10, "bar", 90);
    /// 5 instances of baz will run simultaneously.
    sim.add_process_group(baz, 5, "baz", 95);
    /// 1 instances of qux will run simultaneously.
    sim.add_process(qux, "qux", 99);
    /// Enable logging to std.
    sim.set_log_to_std(true);
    /// Abort upon encountering first failed process.
    sim.set_abort_on_first_failure(true);
    /// Add two I/O pressure generators at '/tmp'.
    /// Path specification is useful in real-life scenarious,
    /// when you have server with multiple file systems mounted.
    /// In that case you can pressure each file system individually.
    sim.add_io_pressure("/tmp");
    sim.add_io_pressure("/tmp");
    /// Add four CPU pressure generators.
    sim.add_cpu_pressure(2048);
    sim.add_cpu_pressure(2048);
    sim.add_cpu_pressure(2048);
    sim.add_cpu_pressure(2048);
    /// Add single ram pressure generator.
    sim.add_ram_pressure(512);
    sim.run_simulation();
    return 0;
}
```
