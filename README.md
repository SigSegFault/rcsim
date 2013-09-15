rcsim
=====

Simple framework for race condition simulations

What it basically provides is:
 * ability to run a piece of code in several processes simultaneously
 * ability to add single process to simulation
 * ability to add group of processes to simulation (processes of group run simultaneously)
 * ability to assign name to process/group of processes
 * ability to provide number of process instances to be respawned after member of group/lone process exits
 * ability to feed input from stdin to every spawned process.
 * synchronization of execution of piece of code in question for the first generation of processes
 * bunching of stdout/stderr from all the processes to buffer, prepending nice timestamp, with the ability to send output to stdout/stderr of the former process


TODOs
=====
 * add I/O pressure generators
 * add CPU pressure generators
 * add RAM pressure generators


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
    /// only 1 instances of qux will run at each moment of time.
    sim.add_process(qux, "qux", 99);
    sim.set_log_to_std(true);
    sim.run_simulation();
    return 0;
}
```
