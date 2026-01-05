#include "tracer.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options] <target_binary> [args...]\n"
              << "Options:\n"
              << "  --pid <pid>    Attach to existing process ID\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    Tracer tracer;
    std::string first_arg = argv[1];

    if (first_arg == "--pid") {
        if (argc < 3) {
            std::cerr << "Error: PID required" << std::endl;
            return 1;
        }
        pid_t pid = std::atoi(argv[2]);
        tracer.attach_and_trace(pid);
    } else {
        // Treat as command execution
        std::string command = argv[1];
        std::vector<std::string> args;
        for (int i = 2; i < argc; ++i) {
            args.push_back(argv[i]);
        }
        tracer.spawn_and_trace(command, args);
    }

    return 0;
}
