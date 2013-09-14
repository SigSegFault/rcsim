#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <wait.h>
#include <sys/fcntl.h>
#include <map>
#include <vector>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <poll.h>

#include "simulator.hpp"

using namespace std;

bool foo()
{
    printf("hello_world!\n");
    sleep(1);
    fflush(stdout);
    return true;
}

int main()
{
    rcs::Simulator sim;

    sim.add_process_group(foo, 20, "foo", 1000);
    sim.set_log_to_std(true);
    sim.run_simulation();
    return 0;
}
