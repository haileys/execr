#include <cstdlib>
#include <map>
#include <algorithm>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "hooks.hpp"

#define BLOCKED ((hook_t)0)
#define ALLOWED ((hook_t)1)

using namespace std;

long allowed[] = { 	SYS_access, SYS_mmap2, SYS_stat64,
					SYS_read, SYS_fstat64, SYS_close, SYS_mprotect,
					SYS_io_setup, SYS_ioctl, SYS_munmap, SYS_time,
					SYS_exit, 
					243, // io_setup
					258, // timer_delete
					311, // getcpu
					240, // sched_getaffinity
					174, // rt_sigaction
					175, // rt_sigprocmask
					191, // getrlimit
					122, // newuname
					268, // mbind
					221, // fcntl64
					220, // getdents64
					252, // set_tid_address
					199, // getuid
					200, // getgid
					201, // geteuid
					202, // getegid
				 };
const int nallowed = sizeof(allowed)/sizeof(long);

long blocked[] = {};
const int nblocked = sizeof(blocked)/sizeof(long);

map<long,hook_t> hooked;

/// hooks

bool _open(pid_t,long);
bool _write(pid_t,long);
bool _brk(pid_t,long);

/// end hooks

bool initialized = false;
void open_hooks()
{
	sort(allowed, allowed + nallowed);
	sort(blocked, blocked + nblocked);
	
	hooked[SYS_open] = _open;
	hooked[SYS_write] = _write;
	hooked[SYS_brk] = _brk;
	
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
#ifdef EBUG
	char* str = read_str(p, (void*)ARG0(p));
	fprintf(stderr, "child attempted to open %s\n", str);
	free(str);
#endif
	return true;
}

bool _write(pid_t p, long eax)
{
	if(ARG0(p) > 2)
		return false;
	return true;
}

bool _brk(pid_t p, long eax)
{
	return true;
}