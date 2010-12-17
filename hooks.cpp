#include <map>
#include <algorithm>
#include <sys/syscall.h>
#include "hooks.hpp"

#define BLOCKED ((hook_t)0)
#define ALLOWED ((hook_t)1)

using namespace std;

long allowed[] = { SYS_access, SYS_brk };
const int nallowed = 2;

long blocked[] = {};
const int nblocked = 0;

map<long,hook_t> hooked;

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