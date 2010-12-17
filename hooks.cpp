#include <cstdlib>
#include <map>
#include <algorithm>
#include <sys/syscall.h>
#include <sys/reg.h>
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
	
	hooked[SYS_open] = _open;
	
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

char* read_str(pid_t p, void* addr)
{
	char* buff = (char*)malloc(32);
	long offset = 0;
	long sz = 32;
	
	do
	{
		if(offset == sz)
			buff = (char*)realloc(buff, sz *= 2);
			
		buff[offset] = ptrace(PTRACE_PEEKDATA, p, (char*)addr + offset, NULL) & 0xFF;
	} 
	while(buff[offset++] != 0);
	
	return buff;
}

// hooks definitions

bool _open(pid_t p, long eax)
{
	char* str = read_str(p, (void*)ARG0(p));
	fprintf(stderr, "child attempted to open %s\n", str);
	free(str);
	return true;
}