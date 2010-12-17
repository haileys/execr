#ifndef HOOKS_HPP
#define HOOKS_HPP

#include <cstdio>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

typedef bool (*hook_t)(pid_t, long);

bool trigger_hook(pid_t, long);

// this macro allows us to read registers from a syscall.
// syscalls use the following registers for arguments, from left to right
// EBX - arg0
// ECX - arg1
// EDX - arg2
// ESI - arg3
// EDI - arg4
#define REG(p,r) ptrace(PTRACE_PEEKUSER, (p), 4 * (r), NULL)

#define ARG0(p) REG(p, ORIG_EBX)
#define ARG1(p) REG(p, ORIG_ECX)
#define ARG2(p) REG(p, ORIG_EDX)
#define ARG3(p) REG(p, ORIG_ESI)
#define ARG4(p) REG(p, ORIG_EDI)

#endif