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
    sim.set_log_to_std(true);
    sim.run_simulation();
    return 0;
}
