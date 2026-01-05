#ifndef TRACER_H
#define TRACER_H

#include <sys/types.h>
#include <string>
#include <vector>

class Tracer {
public:
    Tracer();
    ~Tracer();

    // Start a new process and trace it
    void spawn_and_trace(const std::string& command, const std::vector<std::string>& args);

    // Attach to an existing process
    void attach_and_trace(pid_t pid);

private:
    void run_debugger(pid_t pid);
    void dump_registers(pid_t pid);
    
    bool is_attached;
};

#endif // TRACER_H
