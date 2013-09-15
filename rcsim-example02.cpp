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

#include <stdio.h>
#include <iostream>
#include <iterator>
#include "simulator.hpp"

using namespace std;

bool foo()
{
    std::cin >> std::noskipws;
    std::string message(std::istream_iterator<char>(std::cin), std::istream_iterator<char>());
    printf("Sgt foo reports: '%s'\n", message.c_str());
    return true;
}

bool bar()
{
    std::cin >> std::noskipws;
    std::string message(std::istream_iterator<char>(std::cin), std::istream_iterator<char>());
    std::cout << "Colonel bar confirms: '" << message << "'!" << std::endl;
    return true;
}

bool baz()
{
    std::cout << "baz is just too high!" << std::endl;
    return true;
}

bool qux()
{
    fprintf(stderr, "cmon buz!\n");
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
    /// All input from stdin will be fed to simulated processes.
    /// So you can use something like:
    /// ~# echo "message" | ./rcsim-example02
    sim.set_redirect_stdin(true);
    sim.run_simulation();
    return 0;
}
