#include "tracer.h"
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

Tracer::Tracer() : is_attached(false) {}

Tracer::~Tracer() {
  // Ensure we detach if we are destroyed cleanly? Default OS cleanup might be
  // enough but good practice.
}

void Tracer::spawn_and_trace(const std::string &command,
                             const std::vector<std::string> &args) {
  pid_t pid = fork();

  if (pid < 0) {
    perror("fork");
    return;
  }

  if (pid == 0) {
    // Child process
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);

    // Prepare args for execvp
    std::vector<char *> c_args;
    c_args.push_back(const_cast<char *>(command.c_str()));
    for (const auto &arg : args) {
      c_args.push_back(const_cast<char *>(arg.c_str()));
    }
    c_args.push_back(nullptr);

    execvp(command.c_str(), c_args.data());
    perror("execvp");
    exit(1);
  } else {
    // Parent process
    std::cout << "[+] Spawned target process with PID: " << pid << std::endl;
    run_debugger(pid);
  }
}

void Tracer::attach_and_trace(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
    perror("ptrace attach");
    return;
  }
  std::cout << "[+] Attached to process " << pid << std::endl;
  run_debugger(pid);
}

void Tracer::run_debugger(pid_t pid) {
  int wait_status;

  // Wait for the child to stop on its first signal (SIGTRAP after exec or
  // attach)
  waitpid(pid, &wait_status, 0);

  // Initial setup options: PTRACE_O_EXITKILL ensures child dies if we die
  ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

  bool running = true;
  while (running) {
    // Continue execution
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
      perror("ptrace cont");
      break;
    }

    // Wait for next signal
    pid_t wpid = waitpid(pid, &wait_status, 0);

    if (WIFEXITED(wait_status)) {
      std::cout << "[*] Target process exited with code "
                << WEXITSTATUS(wait_status) << std::endl;
      running = false;
    } else if (WIFSIGNALED(wait_status)) {
      std::cout << "[!] Target process killed by signal "
                << WTERMSIG(wait_status) << std::endl;
      running = false;
    } else if (WIFSTOPPED(wait_status)) {
      int sig = WSTOPSIG(wait_status);

      // Handle critical signals
      if (sig == SIGSEGV || sig == SIGABRT || sig == SIGILL || sig == SIGFPE) {
        std::cout << "\n[!] CRASH DETECTED! Signal: " << sig << " ("
                  << strsignal(sig) << ")" << std::endl;
        dump_registers(pid);

        // We are done after a crash
        running = false;
        // Detach or kill? Usually kill if we found a crash.
        kill(pid, SIGKILL);
      } else if (sig == SIGTRAP) {
        // Just a trap (maybe breakpoint or attach), continue.
      } else {
        // Pass the signal to the child? For now, we just swallow or continue.
        // To pass it: ptrace(PTRACE_CONT, pid, 0, sig);
        // But simpler loop first:
        std::cout << "[*] Signal received: " << sig << std::endl;
        // ptrace(PTRACE_CONT, pid, 0, sig); // if we wanted to pass it
      }
    }
  }
}

void Tracer::dump_registers(pid_t pid) {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
    perror("ptrace getregs");
    return;
  }

  std::cout << "\n=== REGISTER DUMP (x64) ===" << std::endl;
  std::cout << std::hex << std::uppercase << std::setfill('0');
  std::cout << "RIP: 0x" << std::setw(16) << regs.rip << std::endl;
  std::cout << "RSP: 0x" << std::setw(16) << regs.rsp << std::endl;
  std::cout << "RBP: 0x" << std::setw(16) << regs.rbp << std::endl;
  std::cout << "RAX: 0x" << std::setw(16) << regs.rax << std::endl;
  std::cout << "RBX: 0x" << std::setw(16) << regs.rbx << std::endl;
  std::cout << "RCX: 0x" << std::setw(16) << regs.rcx << std::endl;
  std::cout << "RDX: 0x" << std::setw(16) << regs.rdx << std::endl;
  std::cout << "RSI: 0x" << std::setw(16) << regs.rsi << std::endl;
  std::cout << "RDI: 0x" << std::setw(16) << regs.rdi << std::endl;
  std::cout << "R8 : 0x" << std::setw(16) << regs.r8 << std::endl;
  std::cout << "R9 : 0x" << std::setw(16) << regs.r9 << std::endl;
  std::cout << "R10: 0x" << std::setw(16) << regs.r10 << std::endl;
  std::cout << "R11: 0x" << std::setw(16) << regs.r11 << std::endl;
  std::cout << "R12: 0x" << std::setw(16) << regs.r12 << std::endl;
  std::cout << "R13: 0x" << std::setw(16) << regs.r13 << std::endl;
  std::cout << "R14: 0x" << std::setw(16) << regs.r14 << std::endl;
  std::cout << "R15: 0x" << std::setw(16) << regs.r15 << std::endl;
  std::cout << "EFLAGS: 0x" << std::setw(16) << regs.eflags << std::endl;
  std::cout << std::dec;
}
