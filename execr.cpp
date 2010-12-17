#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <cerrno>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>

#include "hooks.hpp"

#define SETUID_TO 1002
#define CPY_BLOCK_SZ 2048

#define TRY(fn,args...) \
	if(fn(args)) { \
		fprintf(stderr, "couldn't " #fn ": %s\n", strerror(errno)); \
		return 1; \
	}

int chroot(const char*);
int kill(pid_t, int);

int main(int argc, char** argv)
{
	if(argc < 3)
	{
		printf("execr <temp dir> <bin>\n");
		return 1;
	}

	char* bin = (char*)malloc(strlen(argv[1]) + 10);
	strcpy(bin, argv[1]);
	strcat(bin, "/prog");
	
	unlink(bin);
	link(argv[2], bin);
	
	chmod(bin, S_IXUSR | S_IRUSR | S_IXGRP | S_IRGRP | S_IXOTH | S_IROTH); // allow rx to all
	
	TRY(chroot, argv[1]);
	TRY(setuid, SETUID_TO);
	TRY(chdir, "/");

	pid_t parent = getpid();
	pid_t child = fork();
	
	if(child == 0)
	{
		rlimit tm;
		tm.rlim_cur = 1;
		tm.rlim_max = 1;
		setrlimit(RLIMIT_CPU, &tm);
		
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl("/prog", "prog", NULL);
		return 1; // if exec is unsuccessful, bail out
	}
	
	// do one cycle of ptrace trapping to let the child exec the target process
	wait(NULL);
	assert(ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL) == 11);
	ptrace(PTRACE_SYSCALL, child, NULL, NULL); // skip the return value, we don't care
	ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		
	while(1)
	{
		int status;
		wait(&status);
		
		if(WIFEXITED(status))
			return 0;
			
		if(WIFSIGNALED(status))
		{
			fprintf(stderr, "child reached time limit, or was terminated by a signal\n");
			return 1;
		}
			
		long syscall_num = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);
		
		if(!trigger_hook(child, syscall_num))
		{
			fprintf(stderr, "Child attempted blocked syscall: %ld\n", syscall_num);
			kill(child, SIGKILL);
			return 1;
		}
		
		ptrace(PTRACE_SYSCALL, child, NULL, NULL); // skip the return value, we don't care
		ptrace(PTRACE_SYSCALL, child, NULL, NULL);
	}	
}