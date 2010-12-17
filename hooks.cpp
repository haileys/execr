#include <map>
#include <algorithm>
#include <sys/syscall.h>
#include "hooks.hpp"

#define BLOCKED ((hook_t)0)
#define ALLOWED ((hook_t)1)

using namespace std;

long allowed[] = { SYS_access, SYS_brk, SYS_mmap2 };
const int nallowed = sizeof(allowed)/sizeof(long);

long blocked[] = {};
const int nblocked = sizeof(blocked)/sizeof(long);

map<long,hook_t> hooked;

/// hooks

bool _open(pid_t,long);

/// end hooks

bool initialized = false;
void open_hooks()
{
	sort(allowed, allowed + nallowed);
	sort(blocked, blocked + nblocked);
	initialized = true;
}

bool trigger_hook(pid_t proc, long syscall)
{
	if(!initialized)
		open_hooks();
	
	if(binary_search(blocked, blocked + nblocked, syscall))
		return false;
	
	if(binary_search(allowed, allowed + nallowed, syscall))
		return true;
	
	hook_t hook = hooked[syscall];
	if(hook == NULL)
		return false;
		
	return hook(proc, syscall);
}

// hooks definitions

bool _open(pid_t p, long eax)
{
	fprintf(stderr, "child attempted to open %s\n", ARG0(p));
	return true;
}