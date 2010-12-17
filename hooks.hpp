#include <stdbool.h>
#include <sys/types.h>

typedef bool (*hook_t)(pid_t, long);

bool trigger_hook(pid_t, long);